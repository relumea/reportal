"""Tests for the pipeline CLI commands."""

from __future__ import annotations

import contextlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from conftest import FakeEngine
from pipeline_helpers import ScriptedLlmClient, seed_portal, seed_unstrip_proposal
from typer.testing import CliRunner

from reportal import cli, components, engines, llm, pipeline, store

runner = CliRunner()


@pytest.fixture(autouse=True)
def _isolate_components() -> Iterator[None]:
    """Reload the registry and drop the live host around each test."""
    components.refresh_components()
    pipeline.reset_live_state()
    yield
    pipeline.reset_live_state()
    components.refresh_components()


def _seed_unstrip(tmp_path: Path, ids: dict[str, int]) -> None:
    """Store an auto-unstrip proposal through its own connection."""
    with contextlib.closing(store.connect(tmp_path / "reportal.db")) as conn:
        seed_unstrip_proposal(conn, analysis_id=ids["analysis"], function_id=ids["function"])


def _run_pipeline(tmp_path: Path, ids: dict[str, int]) -> int:
    """Run the pipeline through the CLI and return the stored run id."""
    result = runner.invoke(cli.app, ["pipeline", str(ids["function"]), "--json"])
    assert result.exit_code == 0, result.output
    return int(json.loads(result.stdout)["id"])


class TestPipelineCommand:
    def test_json_prints_the_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        llm.set_client(ScriptedLlmClient())
        result = runner.invoke(cli.app, ["pipeline", str(ids["function"]), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["function_id"] == ids["function"]
        assert payload["status"] == "done"
        assert [step["name"] for step in payload["steps"]][0] == "prepare"
        assert all(step["status"] == "done" for step in payload["steps"])
        assert payload["artifacts"]["summary"]["summary"].startswith("Reads a file")

    def test_human_prints_steps_and_artifacts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        _seed_unstrip(tmp_path, ids)
        llm.set_client(ScriptedLlmClient())
        result = runner.invoke(cli.app, ["pipeline", str(ids["function"])])
        assert result.exit_code == 0, result.output
        assert "prepare" in result.output
        assert "done" in result.output
        assert "predicted name: ChooseFontW" in result.output
        assert "Reads a file into a buffer" in result.output
        assert "comment count: 2" in result.output

    def test_human_without_llm_shows_skipped_steps(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["pipeline", str(ids["function"])])
        assert result.exit_code == 0, result.output
        assert "name-variables" in result.output
        assert "llm-unavailable" in result.output
        assert "predicted name: none" in result.output
        assert "comment count: 0" in result.output

    def test_without_an_engine_the_run_still_reports_its_steps(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        result = runner.invoke(cli.app, ["pipeline", str(ids["function"]), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["status"] == "failed"
        steps = {step["name"]: step for step in payload["steps"]}
        assert steps["prepare"]["reason"] == "engine-unavailable"

    def test_unknown_function_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["pipeline", "4242", "--json"])
        assert result.exit_code == 1
        assert "no function with id 4242" in result.stdout

    def test_disabled_config_is_honoured(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        (tmp_path / "reportal.toml").write_text(
            '[pipeline]\ndisabled = ["prepare"]\n', encoding="utf-8"
        )
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cli.app, ["pipeline", str(ids["function"]), "--json"])
        assert result.exit_code == 0, result.output
        steps = {step["name"]: step for step in json.loads(result.stdout)["steps"]}
        assert steps["prepare"]["reason"] == "disabled"


class TestPipelineRevertCommand:
    def test_json_reverts_and_prints_what_was_undone(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        llm.set_client(ScriptedLlmClient())
        run_id = _run_pipeline(tmp_path, ids)
        result = runner.invoke(cli.app, ["pipeline-revert", str(run_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["run_id"] == run_id
        assert payload["reverted"]
        descriptions = [entry["description"] for entry in payload["reverted"]]
        assert any("stored decompilation" in description for description in descriptions)
        with contextlib.closing(store.connect(tmp_path / "reportal.db")) as conn:
            assert store.get_decompilation(conn, ids["function"]) is None

    def test_human_lists_the_artifact_descriptions(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        llm.set_client(ScriptedLlmClient())
        run_id = _run_pipeline(tmp_path, ids)
        result = runner.invoke(cli.app, ["pipeline-revert", str(run_id)])
        assert result.exit_code == 0, result.output
        assert "reverted" in result.output
        assert "stored decompilation" in result.output

    def test_a_second_revert_reports_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        llm.set_client(ScriptedLlmClient())
        run_id = _run_pipeline(tmp_path, ids)
        runner.invoke(cli.app, ["pipeline-revert", str(run_id)])
        result = runner.invoke(cli.app, ["pipeline-revert", str(run_id)])
        assert result.exit_code == 0, result.output
        assert "Nothing to revert." in result.output

    def test_unknown_run_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["pipeline-revert", "4242", "--json"])
        assert result.exit_code == 1
        assert "no pipeline run with id 4242" in result.stdout


class TestComponentsCommands:
    def test_components_json_lists_the_registry(self) -> None:
        result = runner.invoke(cli.app, ["components", "--json"])
        assert result.exit_code == 0, result.output
        rows = json.loads(result.stdout)
        entry = next(row for row in rows if row["name"] == "prepare")
        assert entry["origin"] == "builtin"
        assert entry["reloadable"] is True
        assert entry["requires"] == ["conn", "engine", "function"]

    def test_components_human_prints_a_table(self) -> None:
        result = runner.invoke(cli.app, ["components"])
        assert result.exit_code == 0, result.output
        assert "prepare" in result.output
        assert "builtin" in result.output

    def test_components_reload_one_json(self) -> None:
        result = runner.invoke(cli.app, ["components-reload", "prepare", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["name"] == "prepare"
        assert payload["changed"] is False
        assert payload["module"] == "reportal.pipeline"

    def test_components_reload_all_json(self) -> None:
        result = runner.invoke(cli.app, ["components-reload", "--all", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["count"] == len(components.components())
        assert payload["skipped"] == []

    def test_components_reload_all_human(self) -> None:
        result = runner.invoke(cli.app, ["components-reload", "--all"])
        assert result.exit_code == 0, result.output
        assert "reloaded" in result.output
        assert "prepare" in result.output

    def test_components_reload_unknown_name_fails(self) -> None:
        result = runner.invoke(cli.app, ["components-reload", "no-such-component"])
        assert result.exit_code == 1
        assert "no component named no-such-component" in result.output

    def test_components_reload_without_a_name_or_all_fails(self) -> None:
        result = runner.invoke(cli.app, ["components-reload"])
        assert result.exit_code == 1
        assert "provide a component name or --all" in result.output

    def test_components_reload_json_error_for_a_non_reloadable_component(self) -> None:
        components.register_component(
            components.Component("probe", frozenset(), frozenset(), lambda ctx: None)
        )
        result = runner.invoke(cli.app, ["components-reload", "probe", "--json"])
        assert result.exit_code == 1
        assert "not-reloadable" in json.loads(result.stdout)["error"]

    def test_components_deactivate_withdraws_one(self, portal_db: Path) -> None:
        result = runner.invoke(cli.app, ["components-deactivate", "prepare", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["name"] == "prepare"
        assert [entry["name"] for entry in payload["deactivated"]] == ["prepare"]
        assert payload["journaled"] is False

    def test_components_deactivate_refuses_a_second_withdrawal(self, portal_db: Path) -> None:
        runner.invoke(cli.app, ["components-deactivate", "prepare", "--json"])
        result = runner.invoke(cli.app, ["components-deactivate", "prepare", "--json"])
        assert result.exit_code == 1
        assert "already withdrawn" in json.loads(result.stdout)["error"]

    def test_components_deactivate_unknown_name_fails(self, portal_db: Path) -> None:
        result = runner.invoke(cli.app, ["components-deactivate", "no-such-component"])
        assert result.exit_code == 1
        assert "no component named no-such-component" in result.output

    def test_components_deactivate_refuses_nothing_to_withdraw(self, portal_db: Path) -> None:
        result = runner.invoke(cli.app, ["components-deactivate", "store", "--json"])
        assert result.exit_code == 1
        assert "not-withdrawable" in json.loads(result.stdout)["error"]

    def test_components_deactivate_without_a_name_fails(self, portal_db: Path) -> None:
        result = runner.invoke(cli.app, ["components-deactivate"])
        assert result.exit_code == 1
        assert "provide a component name" in result.output

    def test_components_deactivate_calls_the_withdraw_helper(
        self, portal_db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[str] = []

        def spy(conn: Any, name: str) -> dict[str, Any]:
            calls.append(name)
            return {
                "name": name,
                "deactivated": [],
                "context_changes": [],
                "active": [],
                "journaled": False,
            }

        monkeypatch.setattr(pipeline, "withdraw_component", spy)
        result = runner.invoke(cli.app, ["components-deactivate", "prepare", "--json"])
        assert result.exit_code == 0, result.output
        assert calls == ["prepare"]
