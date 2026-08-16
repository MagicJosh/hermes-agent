#!/usr/bin/env python3
"""Path-confined file tools for architecture-council worker profiles.

These tools enforce a controller-issued capability that binds:
- workspace root (read boundary)
- exact draft paths (write boundary)
- task identity (decision_id, stage, owner, task_key)
- expiry and one-time nonce

The tools are registered under the 'architecture-council-scoped' toolset.
They appear only for profiles that list that toolset, and their check_fn
additionally gates on HERMES_COUNCIL_WORKSPACE being set (or a capability
file being reachable from the cwd).
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.path_security import has_traversal_component, validate_within_dir
from tools.registry import registry, tool_error

# Deny patterns for reads — even inside the workspace, these are off-limits.
DENY_READ_PATTERNS = [
    ".env",
    ".env.",
    ".git/",
    ".git\\",
    ".hermes/",
    "auth.json",
    ".pem",
    ".key",
    ".p12",
    "credentials",
]


class CapabilityError(Exception):
    """Raised when a capability is missing, stale, or invalid."""


def _workspace_root() -> Path:
    """Get the council workspace root from env or cwd."""
    ws = os.environ.get("HERMES_COUNCIL_WORKSPACE")
    if ws:
        return Path(ws).resolve()
    # Fallback: assume cwd is the workspace (Kanban --workspace dir: sets it)
    return Path.cwd().resolve()


def _capability_path() -> Path:
    """Path to the controller-issued capability file."""
    return _workspace_root() / "state" / "council-worker-capability.json"


def _load_capability() -> dict[str, Any]:
    """Load and validate the controller-issued capability."""
    cap_path = _capability_path()
    if not cap_path.is_file():
        raise CapabilityError(
            f"No council worker capability at {cap_path}. "
            "The controller must issue a capability before dispatch."
        )
    # Read and parse the capability
    content = cap_path.read_bytes()
    try:
        cap = json.loads(content.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CapabilityError(f"Capability is not valid JSON: {exc}") from exc
    if not isinstance(cap, dict):
        raise CapabilityError("Capability must be a JSON object")

    # Validate capability structure
    required_fields = {
        "schema_version", "workspace", "decision_id", "stage",
        "owner", "task_key", "allowed_read_root", "allowed_write_paths",
        "issued_at", "expires_at", "nonce", "sha256",
    }
    missing = required_fields - set(cap)
    if missing:
        raise CapabilityError(f"Capability missing fields: {sorted(missing)}")

    if cap["schema_version"] != "1.0":
        raise CapabilityError("Capability schema_version must be 1.0")

    # Validate expiry
    try:
        expires_at = float(cap["expires_at"])
    except (TypeError, ValueError) as exc:
        raise CapabilityError("Capability expires_at is not a number") from exc
    now = time.time()
    if now > expires_at:
        raise CapabilityError(
            f"Capability expired at {cap['expires_at']} (now={now:.0f})"
        )

    # Validate workspace binding
    ws_root = _workspace_root()
    if not isinstance(cap["workspace"], str):
        raise CapabilityError("Capability workspace must be a string")
    cap_workspace = Path(cap["workspace"]).resolve()
    if cap_workspace != ws_root:
        raise CapabilityError(
            f"Capability workspace {cap_workspace} does not match "
            f"actual workspace {ws_root}"
        )

    # Validate task binding (if HERMES_KANBAN_TASK is set, it must match)
    kanban_task = os.environ.get("HERMES_KANBAN_TASK", "")
    if kanban_task and cap["task_key"] != kanban_task:
        raise CapabilityError(
            f"Capability task_key {cap['task_key']!r} does not match "
            f"Kanban task {kanban_task!r}"
        )

    # Validate capability hash (integrity)
    cap_without_hash = {k: v for k, v in cap.items() if k != "sha256"}
    recomputed = hashlib.sha256(
        json.dumps(cap_without_hash, sort_keys=True).encode("utf-8")
    ).hexdigest()
    if recomputed != cap["sha256"]:
        raise CapabilityError("Capability sha256 mismatch — tampered or corrupted")

    return cap


def _validate_read_path(path_str: str, cap: dict) -> Path:
    """Validate that a read path is within the allowed root and not denied."""
    if has_traversal_component(path_str):
        raise CapabilityError(f"Path contains '..' traversal: {path_str}")

    root = Path(cap["allowed_read_root"]).resolve()
    candidate = (
        (root / path_str).resolve()
        if not Path(path_str).is_absolute()
        else Path(path_str).resolve()
    )

    # Containment check (resolve() follows symlinks, so a symlink that
    # points outside the workspace is rejected here)
    error = validate_within_dir(candidate, root)
    if error:
        raise CapabilityError(f"Read path escapes workspace: {path_str}: {error}")

    # Deny pattern check (on the resolved path string)
    resolved_str = str(candidate)
    for pattern in DENY_READ_PATTERNS:
        if pattern in resolved_str:
            raise CapabilityError(
                f"Read path matches denied pattern {pattern!r}: {resolved_str}"
            )

    # Reject non-regular files (FIFOs, devices, sockets)
    if candidate.exists() and not candidate.is_file():
        raise CapabilityError(f"Path is not a regular file: {candidate}")

    return candidate


def _validate_write_path(path_str: str, cap: dict) -> Path:
    """Validate that a write path is one of the exact assigned draft paths."""
    if has_traversal_component(path_str):
        raise CapabilityError(f"Path contains '..' traversal: {path_str}")

    root = Path(cap["allowed_read_root"]).resolve()
    candidate = (
        (root / path_str).resolve()
        if not Path(path_str).is_absolute()
        else Path(path_str).resolve()
    )

    # Must match one of the allowed write paths exactly (after resolution)
    allowed_resolved = [
        (root / p).resolve() for p in cap["allowed_write_paths"]
    ]
    if candidate not in allowed_resolved:
        raise CapabilityError(
            f"Write path {path_str} is not in the assigned draft paths. "
            f"Allowed: {cap['allowed_write_paths']}"
        )

    # Containment check (belt-and-suspenders)
    error = validate_within_dir(candidate, root)
    if error:
        raise CapabilityError(f"Write path escapes workspace: {path_str}: {error}")

    # Reject symlinks: the final path component must not be a symlink,
    # even one that resolves inside the workspace.
    unresolved = (
        (root / path_str) if not Path(path_str).is_absolute() else Path(path_str)
    )
    if unresolved.is_symlink():
        raise CapabilityError(f"Write path is a symlink: {unresolved}")

    return candidate


def _audit_operation(
    workspace: Path, operation: str, path: str, success: bool, detail: str = ""
) -> None:
    """Append an audit event for a scoped tool operation.

    Best-effort: audit failures must never break the tool call.
    """
    try:
        event = {
            "event_id": f"CSE-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "operation": operation,
            "path": path,
            "success": success,
            "detail": detail,
        }
        audit_path = workspace / "audit" / "council-scoped-operations.jsonl"
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        with audit_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, sort_keys=True) + "\n")
            f.flush()
    except OSError:
        pass


def _check_council_worker() -> bool:
    """check_fn: tools appear only in council worker contexts."""
    if os.environ.get("HERMES_COUNCIL_WORKSPACE"):
        return True
    # Fallback: the Kanban dispatcher sets the worker's cwd to the workspace
    # via --workspace dir:, so a reachable capability file also counts.
    cap = Path.cwd() / "state" / "council-worker-capability.json"
    return cap.is_file()


def _issue_capability(
    *,
    workspace: Path,
    decision_id: str,
    stage: str,
    owner: str,
    task_key: str,
    allowed_write_paths: list[str],
    ttl_seconds: int = 3600,
) -> dict[str, Any]:
    """Issue a controller capability for a council worker task.

    Called by the council kernel before Kanban dispatch. Writes the
    capability to state/council-worker-capability.json and returns it.
    """
    workspace = workspace.resolve()
    now = time.time()
    cap_without_hash = {
        "schema_version": "1.0",
        "workspace": str(workspace),
        "decision_id": decision_id,
        "stage": stage,
        "owner": owner,
        "task_key": task_key,
        "allowed_read_root": str(workspace),
        "allowed_write_paths": list(allowed_write_paths),
        "issued_at": now,
        "expires_at": now + ttl_seconds,
        "nonce": secrets.token_hex(16),
    }
    cap = dict(cap_without_hash)
    cap["sha256"] = hashlib.sha256(
        json.dumps(cap_without_hash, sort_keys=True).encode("utf-8")
    ).hexdigest()
    cap_path = workspace / "state" / "council-worker-capability.json"
    cap_path.parent.mkdir(parents=True, exist_ok=True)
    cap_path.write_text(
        json.dumps(cap, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return cap


# --- Tool handlers ---

COUNCIL_READ_SCHEMA = {
    "name": "council_read",
    "description": (
        "Read a file within the architecture-council workspace. "
        "The path must be relative to the workspace root. "
        "Denied: .env, credentials, .git, profile homes, files outside the workspace."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": (
                    "Relative path within the council workspace "
                    "(e.g., '00-intake.json', 'drafts/analysis.md')"
                ),
            },
            "offset": {
                "type": "integer",
                "description": "Line number to start reading from (1-indexed)",
                "default": 1,
                "minimum": 1,
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of lines to read (default: 2000)",
                "default": 2000,
                "maximum": 2000,
            },
        },
        "required": ["path"],
    },
}


def _handle_council_read(args, **kw):
    try:
        cap = _load_capability()
        ws = _workspace_root()
        path_str = args.get("path", "")
        if not path_str or not isinstance(path_str, str):
            return tool_error("Missing required field 'path'")
        try:
            offset = max(1, int(args.get("offset", 1)))
        except (TypeError, ValueError):
            offset = 1
        try:
            limit = min(2000, max(1, int(args.get("limit", 2000))))
        except (TypeError, ValueError):
            limit = 2000
        resolved = _validate_read_path(path_str, cap)
        if not resolved.is_file():
            _audit_operation(ws, "read", path_str, False, "file not found")
            return tool_error(f"File not found: {path_str}")
        text = resolved.read_text(encoding="utf-8")
        lines = text.splitlines()
        start = min(offset - 1, len(lines))
        if not lines:
            _audit_operation(ws, "read", path_str, True, "empty file")
            return "[empty file]"
        if start >= len(lines):
            _audit_operation(
                ws, "read", path_str, True, f"offset {offset} beyond EOF"
            )
            return f"[offset {offset} beyond end of file ({len(lines)} lines)]"
        end = min(len(lines), start + limit)
        result_lines = [
            f"{start + i + 1:6d}| {lines[start + i]}" for i in range(end - start)
        ]
        _audit_operation(ws, "read", path_str, True)
        out = "\n".join(result_lines)
        if end < len(lines):
            out += f"\n\n[next_offset: {end + 1}]"
        return out
    except CapabilityError as e:
        return tool_error(str(e))
    except Exception as e:
        return tool_error(f"Read failed: {e}")


registry.register(
    name="council_read",
    toolset="architecture-council-scoped",
    schema=COUNCIL_READ_SCHEMA,
    handler=_handle_council_read,
    check_fn=_check_council_worker,
    emoji="📋",
    max_result_size_chars=100_000,
)
