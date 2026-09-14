"""Tests for the SPA smoke/audit seeding, especially the stored security scan."""

from __future__ import annotations

import contextlib
from pathlib import Path

import pytest

from reportal import engines, store
from tools import smoke_spa


def _require_engine() -> None:
    """Skip when the rebrew package is not importable."""
    if not engines.get_engine().available():
        pytest.skip("rebrew is not importable")


def _prerequisites() -> tuple[Path, Path, Path, Path]:
    """Return the sibling project, binary, function list and rebrew executable."""
    project_dir = smoke_spa.sibling(str(smoke_spa.NOTEPAD_PROJECT_RELATIVE))
    return (
        project_dir,
        project_dir / "original" / "notepad.exe",
        smoke_spa.function_seed_file(project_dir),
        smoke_spa.sibling(str(smoke_spa.REBREW_RELATIVE)),
    )


def test_seeded_workspace_holds_a_security_scan_with_severities(tmp_path: Path) -> None:
    project_dir, binary_path, functions_file, rebrew_bin = _prerequisites()
    for required in (binary_path, functions_file, rebrew_bin):
        if not required.is_file():
            pytest.skip(f"missing prerequisite: {required}")
    _require_engine()

    workspace = tmp_path / "e2e-web"
    ids = smoke_spa.build_workspace(workspace, project_dir, binary_path, functions_file)

    with contextlib.closing(store.connect(workspace / "reportal.db")) as conn:
        analysis_id = store.latest_analysis_for_binary(conn, ids["binary_id"])
    assert analysis_id is not None
    with contextlib.closing(store.connect(workspace / "reportal.db")) as conn:
        stored = store.get_scan(conn, analysis_id, store.SCAN_KIND_SECURITY)

    assert stored is not None, "the seeded workspace has no stored security scan"
    findings = stored["findings"]
    severities = {str(finding["severity"]) for finding in findings}
    assert len(severities) > 1, f"the seeded scan carries one severity: {severities}"
    assert stored["by_severity"] == {
        severity: sum(1 for finding in findings if finding["severity"] == severity)
        for severity in ("high", "medium", "low")
    }
    assert any(str(finding["rule"]) == smoke_spa.SECURITY_HIGH_RULE for finding in findings)
    assert any(str(finding["rule"]) == smoke_spa.SECURITY_LOW_RULE for finding in findings)
    assert any(str(finding["cwe"]) == smoke_spa.SECURITY_HIGH_CWE for finding in findings)
    assert any(str(finding["cwe"]) == smoke_spa.SECURITY_LOW_CWE for finding in findings)


def test_the_seeded_scan_reaches_the_stored_only_route(tmp_path: Path) -> None:
    project_dir, binary_path, functions_file, rebrew_bin = _prerequisites()
    for required in (binary_path, functions_file, rebrew_bin):
        if not required.is_file():
            pytest.skip(f"missing prerequisite: {required}")
    _require_engine()

    workspace = tmp_path / "e2e-web"
    smoke_spa.build_workspace(workspace, project_dir, binary_path, functions_file)

    with contextlib.closing(store.connect(workspace / "reportal.db")) as conn:
        binary_id = int(
            conn.execute("SELECT id FROM binaries ORDER BY id LIMIT 1").fetchone()["id"]
        )
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        stored = store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_SECURITY)
    assert stored is not None
    assert stored["count"] == len(stored["findings"])
    assert stored["count"] > 0
