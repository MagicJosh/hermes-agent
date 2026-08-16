"""Tests for the architecture-council scoped file tools."""

import json
from pathlib import Path

import pytest

from tools.council_scoped_tool import (
    CapabilityError,
    _check_council_worker,
    _handle_council_read,
    _handle_council_write,
    _issue_capability,
    _load_capability,
    _validate_read_path,
    _validate_write_path,
)


@pytest.fixture
def council_workspace(tmp_path, monkeypatch):
    """Create a minimal council workspace with an issued capability.

    Sets HERMES_COUNCIL_WORKSPACE so capability loading and handlers
    resolve the workspace the way a dispatched worker would.
    """
    ws = tmp_path / "DEC-TEST"
    for d in ["state", "drafts", "audit", "registry", "artifacts"]:
        (ws / d).mkdir(parents=True)
    # Write some readable files
    (ws / "00-intake.json").write_text('{"decision_id": "DEC-TEST"}')
    (ws / "drafts" / "analysis.md").write_text("# Analysis\nDraft content")
    # Issue a capability
    _issue_capability(
        workspace=ws,
        decision_id="DEC-TEST",
        stage="analyze",
        owner="archanalyst",
        task_key="DEC-TEST:1:analyze:0:style-0",
        allowed_write_paths=["drafts/analysis.md"],
        ttl_seconds=3600,
    )
    monkeypatch.setenv("HERMES_COUNCIL_WORKSPACE", str(ws))
    return ws


# --- Capability loading ---


def test_council_capability_roundtrip(council_workspace):
    cap = _load_capability()
    assert cap["schema_version"] == "1.0"
    assert cap["decision_id"] == "DEC-TEST"
    assert cap["stage"] == "analyze"
    assert cap["owner"] == "archanalyst"
    assert cap["task_key"] == "DEC-TEST:1:analyze:0:style-0"
    assert Path(cap["workspace"]).resolve() == council_workspace.resolve()
    assert cap["allowed_write_paths"] == ["drafts/analysis.md"]


def test_council_capability_expired(council_workspace, monkeypatch):
    _issue_capability(
        workspace=council_workspace,
        decision_id="DEC-TEST",
        stage="analyze",
        owner="archanalyst",
        task_key="DEC-TEST:1:analyze:0:style-0",
        allowed_write_paths=["drafts/analysis.md"],
        ttl_seconds=-10,
    )
    with pytest.raises(CapabilityError, match="expired"):
        _load_capability()


def test_council_capability_tampered(council_workspace):
    cap_file = council_workspace / "state" / "council-worker-capability.json"
    content = cap_file.read_text(encoding="utf-8")
    cap_file.write_text(
        content.replace('"analyze"', '"review"', 1), encoding="utf-8"
    )
    with pytest.raises(CapabilityError, match="sha256 mismatch"):
        _load_capability()


def test_council_capability_workspace_mismatch(council_workspace, tmp_path, monkeypatch):
    # Copy the capability into another workspace and point the env at it:
    # the workspace binding check must reject it.
    other = tmp_path / "OTHER-WS"
    (other / "state").mkdir(parents=True)
    cap_file = council_workspace / "state" / "council-worker-capability.json"
    (other / "state" / "council-worker-capability.json").write_bytes(
        cap_file.read_bytes()
    )
    monkeypatch.setenv("HERMES_COUNCIL_WORKSPACE", str(other))
    with pytest.raises(CapabilityError, match="does not match"):
        _load_capability()


def test_council_capability_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_COUNCIL_WORKSPACE", str(tmp_path))
    with pytest.raises(CapabilityError, match="No council worker capability"):
        _load_capability()


def test_council_check_fn_env(council_workspace, monkeypatch):
    assert _check_council_worker() is True
    monkeypatch.delenv("HERMES_COUNCIL_WORKSPACE", raising=False)
    monkeypatch.chdir(Path("/"))
    assert _check_council_worker() is False


def test_council_check_fn_cwd_fallback(council_workspace, monkeypatch):
    monkeypatch.delenv("HERMES_COUNCIL_WORKSPACE", raising=False)
    monkeypatch.chdir(council_workspace)
    assert _check_council_worker() is True


# --- Read path validation ---


def test_council_read_allowed_file(council_workspace):
    cap = _load_capability()
    path = _validate_read_path("00-intake.json", cap)
    assert path == (council_workspace / "00-intake.json").resolve()


def test_council_read_denied_env_file(council_workspace):
    (council_workspace / ".env").write_text("SECRET=hello")
    cap = _load_capability()
    with pytest.raises(CapabilityError, match="denied pattern"):
        _validate_read_path(".env", cap)


def test_council_read_denied_traversal(council_workspace):
    cap = _load_capability()
    with pytest.raises(CapabilityError, match="traversal"):
        _validate_read_path("../../../etc/passwd", cap)


def test_council_read_denied_outside_workspace(council_workspace, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    cap = _load_capability()
    with pytest.raises(CapabilityError, match="escapes workspace"):
        _validate_read_path(str(outside), cap)


# --- council_read handler ---


def test_council_handler_read_line_numbers(council_workspace):
    result = _handle_council_read({"path": "drafts/analysis.md"})
    assert "1| # Analysis" in result
    assert "2| Draft content" in result
    assert "[next_offset" not in result


def test_council_handler_read_pagination(council_workspace):
    (council_workspace / "drafts" / "lines.md").write_text(
        "line1\nline2\nline3\nline4\nline5\n"
    )
    result = _handle_council_read({"path": "drafts/lines.md", "offset": 2, "limit": 2})
    assert "2| line2" in result
    assert "3| line3" in result
    assert "1| line1" not in result
    assert "4| line4" not in result
    assert "[next_offset: 4]" in result


def test_council_handler_read_offset_beyond_eof(council_workspace):
    result = _handle_council_read(
        {"path": "drafts/analysis.md", "offset": 100, "limit": 10}
    )
    assert "beyond end of file" in result


def test_council_handler_read_not_found(council_workspace):
    result = _handle_council_read({"path": "drafts/nope.md"})
    assert "not found" in result


def test_council_handler_read_missing_capability(tmp_path, monkeypatch):
    monkeypatch.delenv("HERMES_COUNCIL_WORKSPACE", raising=False)
    monkeypatch.chdir(tmp_path)
    result = _handle_council_read({"path": "00-intake.json"})
    assert "No council worker capability" in result


def test_council_handler_read_denied_path(council_workspace):
    (council_workspace / ".env").write_text("SECRET=hello")
    result = _handle_council_read({"path": ".env"})
    assert "denied pattern" in result


# --- Write path validation ---


def test_council_write_allowed_draft(council_workspace):
    cap = _load_capability()
    path = _validate_write_path("drafts/analysis.md", cap)
    assert path == (council_workspace / "drafts" / "analysis.md").resolve()


def test_council_write_denied_unassigned_path(council_workspace):
    cap = _load_capability()
    with pytest.raises(CapabilityError, match="not in the assigned draft paths"):
        _validate_write_path("drafts/unauthorized.md", cap)


def test_council_write_denied_registry(council_workspace):
    cap = _load_capability()
    with pytest.raises(CapabilityError, match="not in the assigned draft paths"):
        _validate_write_path("registry/claim-registry.json", cap)


def test_council_write_denied_state(council_workspace):
    cap = _load_capability()
    with pytest.raises(CapabilityError, match="not in the assigned draft paths"):
        _validate_write_path("state/workflow-state.json", cap)


def test_council_write_denied_traversal(council_workspace):
    cap = _load_capability()
    with pytest.raises(CapabilityError, match="traversal"):
        _validate_write_path("../other.md", cap)


def test_council_write_denied_symlink(council_workspace):
    # A symlink at the assigned draft path must be rejected, even if the
    # capability lists it.
    target = council_workspace / "drafts" / "analysis.md"
    target.unlink()
    (council_workspace / "drafts" / "real.md").write_text("real")
    target.symlink_to(council_workspace / "drafts" / "real.md")
    cap = _load_capability()
    with pytest.raises(CapabilityError, match="symlink"):
        _validate_write_path("drafts/analysis.md", cap)


def test_council_read_denied_symlink_escape(council_workspace, tmp_path):
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("stolen")
    symlink = council_workspace / "drafts" / "escape.md"
    symlink.symlink_to(outside)
    cap = _load_capability()
    with pytest.raises(CapabilityError, match="escapes workspace"):
        _validate_read_path("drafts/escape.md", cap)


# --- council_write handler ---


def test_council_handler_write_allowed(council_workspace):
    result = _handle_council_write(
        {"path": "drafts/analysis.md", "content": "# Analysis\nRewritten"}
    )
    assert '"success": true' in result
    written = (council_workspace / "drafts" / "analysis.md").read_text(
        encoding="utf-8"
    )
    assert written == "# Analysis\nRewritten"


def test_council_handler_write_denied_path(council_workspace):
    result = _handle_council_write(
        {"path": "registry/claim-registry.json", "content": "{}"}
    )
    assert "not in the assigned draft paths" in result
    assert not (council_workspace / "registry" / "claim-registry.json").exists()


def test_council_handler_write_missing_content(council_workspace):
    result = _handle_council_write({"path": "drafts/analysis.md"})
    assert "Missing required field 'content'" in result


def test_council_handler_write_non_string_content(council_workspace):
    result = _handle_council_write(
        {"path": "drafts/analysis.md", "content": 42}
    )
    assert "'content' must be a string" in result


def test_council_handler_write_audits(council_workspace):
    _handle_council_write(
        {"path": "drafts/analysis.md", "content": "# Analysis\nAudited"}
    )
    audit_file = council_workspace / "audit" / "council-scoped-operations.jsonl"
    assert audit_file.is_file()
    events = [
        json.loads(line)
        for line in audit_file.read_text(encoding="utf-8").splitlines()
    ]
    assert any(
        e["operation"] == "write"
        and e["path"] == "drafts/analysis.md"
        and e["success"] is True
        for e in events
    )
