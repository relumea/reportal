"""Tests for the `reportal diff` command."""

from __future__ import annotations

import contextlib
import json
from pathlib import Path

import pytest
from conftest import FakeEngine
from typer.testing import CliRunner

from reportal import cli, engines, similarity, store
from reportal._paths import DB_ENV

runner = CliRunner()

LEFT_CODE = "void sub_1000(void)\n{\n  return;\n}\n"
RIGHT_CODE = "void sub_2000(void)\n{\n  int x = 1;\n  return;\n}\n"


def _seed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    context: bool = True,
    match: bool = True,
    decomp: bool = False,
) -> dict[str, int]:
    db = tmp_path / "portal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    with contextlib.closing(store.connect(db)) as conn:
        binary_id = store.add_binary(
            conn, sha256="ab" * 32, name="demo.exe", path=str(tmp_path / "demo.exe")
        )
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        left = store.add_function(
            conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", size=16
        )
        right = store.add_function(
            conn, analysis_id=analysis_id, va=0x2000, name="sub_2000", size=16
        )
        if context:
            store.set_rebrew_context(conn, binary_id, str(tmp_path))
        if match:
            store.record_match(
                conn,
                function_id=left,
                candidate_function_id=right,
                similarity=77.0,
                confidence=0.5,
            )
        if decomp:
            store.set_decompilation(conn, left, LEFT_CODE, "kuna")
            store.set_decompilation(conn, right, RIGHT_CODE, "kuna")
    return {"binary": binary_id, "analysis": analysis_id, "left": left, "right": right}


class TestDiffCommand:
    def test_json_output(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, decomp=True)
        result = runner.invoke(cli.app, ["diff", str(ids["left"]), str(ids["right"]), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["kind"] == "decomp"
        assert payload["normalized"] is True
        assert payload["similarity"] == 77.0
        assert payload["summary"]["insert"] > 0
        assert fake_engine.calls == []

    def test_human_output_marks_changed_lines_and_summary(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, decomp=True)
        result = runner.invoke(cli.app, ["diff", str(ids["left"]), str(ids["right"])])
        assert result.exit_code == 0, result.output
        assert "diff decomp" in result.output
        assert "similarity 77.0" in result.output
        assert "- " in result.output
        assert "+ " in result.output
        assert "changed" in result.output
        assert "int x = 1;" in result.output

    def test_no_normalize_flag(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, decomp=True)
        result = runner.invoke(
            cli.app, ["diff", str(ids["left"]), str(ids["right"]), "--no-normalize", "--json"]
        )
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["normalized"] is False

    def test_disasm_kind_reaches_the_engine(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app, ["diff", str(ids["left"]), str(ids["right"]), "--kind", "disasm", "--json"]
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["kind"] == "disasm"
        assert fake_engine.calls == ["disassemble", "disassemble"]

    def test_unknown_function_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, decomp=True)
        result = runner.invoke(cli.app, ["diff", "4242", str(ids["right"]), "--json"])
        assert result.exit_code == 1
        assert "no function with id 4242" in result.stdout

    def test_invalid_kind_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, decomp=True)
        result = runner.invoke(
            cli.app, ["diff", str(ids["left"]), str(ids["right"]), "--kind", "bytes", "--json"]
        )
        assert result.exit_code == 1
        assert "unsupported diff kind" in result.stdout

    def test_without_engine_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        result = runner.invoke(cli.app, ["diff", str(ids["left"]), str(ids["right"]), "--json"])
        assert result.exit_code == 1
        assert "analysis engine unavailable" in result.stdout

    def test_similarity_null_without_a_recorded_match_or_the_extra(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, match=False, decomp=True)
        monkeypatch.setattr(similarity, "available", lambda: False)
        result = runner.invoke(cli.app, ["diff", str(ids["left"]), str(ids["right"]), "--json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["similarity"] is None
