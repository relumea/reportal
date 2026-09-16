"""Tests for the AI decompilation pipeline API routes."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest
from conftest import FakeEngine, FakeLlmClient, json_body, wsgi_request
from pipeline_helpers import ScriptedLlmClient, seed_portal, seed_unstrip_proposal

from reportal import auth, components, effects, journal, llm, pipeline, store


@pytest.fixture(autouse=True)
def _isolate_components() -> Iterator[None]:
    """Reload the registry and drop the live host around each test."""
    components.refresh_components()
    pipeline.reset_live_state()
    yield
    pipeline.reset_live_state()
    components.refresh_components()


def _steps(payload: dict[str, object]) -> dict[str, dict[str, object]]:
    steps = payload["steps"]
    assert isinstance(steps, list)
    return {str(step["name"]): step for step in steps}


def _scratch_component() -> components.Component:
    """A component whose revert deletes a row and journals how to put it back."""

    def effect(ctx: components.Context) -> None:
        ctx.provide("scratch-out", 1)

    def revert(ctx: components.Context) -> None:
        conn = ctx.require("conn")
        conn.execute("DELETE FROM scratch WHERE id = 1")
        conn.commit()
        descriptor = journal.row_restore_descriptor("scratch", [{"id": 1, "value": "kept"}])
        ctx.record(
            "deleted scratch row 1",
            lambda: effects.apply_descriptor(conn, descriptor),
            descriptor,
        )

    return components.Component("scratch", frozenset(), frozenset({"scratch-out"}), effect, revert)


class TestRunRoute:
    def test_post_runs_and_stores_the_run(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        llm.set_client(ScriptedLlmClient())
        status, headers, body = wsgi_request("POST", f"/api/functions/{ids['function']}/pipeline")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["function_id"] == ids["function"]
        assert payload["status"] == pipeline.RUN_DONE
        assert payload["model"] == "scripted-model"
        assert [step["name"] for step in payload["steps"]][:3] == [
            "prepare",
            "read-trace",
            "decompile",
        ]
        assert payload["artifacts"]["summary"]["summary"].startswith("Reads a file")
        stored = store.latest_pipeline_run(conn, ids["function"])
        assert stored is not None and stored["id"] == payload["id"]

    def test_post_without_llm_skips_the_llm_steps(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        status, headers, body = wsgi_request("POST", f"/api/functions/{ids['function']}/pipeline")
        assert status.startswith("200")
        payload = json_body(body, headers)
        steps = _steps(payload)
        assert steps["name-variables"]["status"] == pipeline.STEP_SKIPPED
        assert steps["name-variables"]["reason"] == pipeline.REASON_LLM_UNAVAILABLE
        assert steps["summarize"]["reason"] == pipeline.REASON_LLM_UNAVAILABLE
        assert payload["model"] == ""
        assert payload["artifacts"]["summary"] is None

    def test_post_404_unknown_function(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("POST", "/api/functions/999/pipeline")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "function not found"

    def test_post_body_disables_a_component(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/functions/{ids['function']}/pipeline",
            body=json.dumps({"disabled": ["prepare"]}),
        )
        assert status.startswith("200")
        steps = _steps(json_body(body, headers))
        assert steps["prepare"]["reason"] == pipeline.REASON_DISABLED

    def test_post_400_for_a_malformed_disabled_body(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/functions/{ids['function']}/pipeline",
            body=json.dumps({"disabled": "prepare"}),
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid disabled"

    def test_post_503_when_the_pipeline_cannot_run(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)

        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise pipeline.PipelineUnavailable("two components named prepare")

        monkeypatch.setattr(pipeline, "run_pipeline", boom)
        status, headers, body = wsgi_request("POST", f"/api/functions/{ids['function']}/pipeline")
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "pipeline-unavailable"


class TestLatestRoute:
    def test_get_404_no_run(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        status, headers, body = wsgi_request("GET", f"/api/functions/{ids['function']}/pipeline")
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["error"] == "no-run"
        assert f"reportal pipeline {ids['function']}" in payload["detail"]

    def test_get_404_unknown_function(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("GET", "/api/functions/999/pipeline")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "function not found"

    def test_get_returns_the_latest_run_with_artifacts(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        seed_unstrip_proposal(conn, analysis_id=ids["analysis"], function_id=ids["function"])
        llm.set_client(ScriptedLlmClient())
        _, _, created = wsgi_request("POST", f"/api/functions/{ids['function']}/pipeline")
        run_id = json.loads(created)["id"]

        status, headers, body = wsgi_request("GET", f"/api/functions/{ids['function']}/pipeline")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["id"] == run_id
        assert _steps(payload)["store"]["status"] == pipeline.STEP_DONE
        assert payload["artifacts"]["predicted_name"]["name"] == "ChooseFontW"
        assert payload["artifacts"]["inline_comments"]["comments"][0]["line"] == 3

    def test_get_run_by_id(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        run_id = store.create_pipeline_run(conn, function_id=ids["function"], model="m")
        status, headers, body = wsgi_request("GET", f"/api/pipeline/runs/{run_id}")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["id"] == run_id
        assert payload["model"] == "m"
        assert payload["steps"] == []

    def test_get_run_by_id_404(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("GET", "/api/pipeline/runs/999")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "run not found"

    def test_a_non_member_does_not_read_a_team_run(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        run_id = store.create_pipeline_run(conn, function_id=ids["function"], model="m")
        owner, _token = auth.add_user(conn, name="owner", role="admin")
        team_id = int(auth.create_team(conn, name="blue")["id"])
        auth.add_member(conn, team_id, int(owner["id"]))
        _member, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        ana = auth.find_user(conn, "ana")
        assert ana is not None
        auth.add_member(conn, team_id, int(ana["id"]))
        _outsider, outsider = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        store.set_binary_scope(conn, ids["binary"], visibility="team", owner_team_id=team_id)

        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        stranger_status, headers, body = wsgi_request(
            "GET",
            f"/api/pipeline/runs/{run_id}",
            headers={"Authorization": f"Bearer {outsider}"},
        )
        assert stranger_status.startswith("404"), body
        assert json_body(body, headers)["error"] == "run not found"

        member_status, headers, body = wsgi_request(
            "GET",
            f"/api/pipeline/runs/{run_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert member_status.startswith("200"), body


class TestRevertRoute:
    def _run(self, conn: sqlite3.Connection, ids: dict[str, int]) -> int:
        llm.set_client(ScriptedLlmClient())
        _, headers, body = wsgi_request("POST", f"/api/functions/{ids['function']}/pipeline")
        return int(json_body(body, headers)["id"])

    def test_revert_undoes_the_run(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        run_id = self._run(conn, ids)
        assert store.get_decompilation(conn, ids["function"]) is not None
        status, headers, body = wsgi_request("POST", f"/api/pipeline/runs/{run_id}/revert")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["run_id"] == run_id
        assert payload["reverted"]
        assert all(entry["status"] == pipeline.EFFECT_REVERTED for entry in payload["reverted"])
        assert store.get_decompilation(conn, ids["function"]) is None
        assert store.get_ai_artifact(conn, ids["function"], "summary") is None

    def test_revert_404_unknown_run(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("POST", "/api/pipeline/runs/999/revert")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "run not found"


class TestExistingAiRoutes:
    def test_stored_pipeline_artifacts_are_served_by_the_ai_routes(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        llm.set_client(ScriptedLlmClient())
        wsgi_request("POST", f"/api/functions/{ids['function']}/pipeline")
        status, headers, body = wsgi_request("GET", f"/api/functions/{ids['function']}/summary")
        assert status.startswith("200")
        assert json_body(body, headers)["payload"]["summary"].startswith("Reads a file")
        status, headers, body = wsgi_request("GET", f"/api/functions/{ids['function']}/ai-comments")
        assert status.startswith("200")
        assert len(json_body(body, headers)["payload"]["comments"]) == 2
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{ids['function']}/type-suggestions"
        )
        assert status.startswith("200")
        assert json_body(body, headers)["payload"]["suggestions"][0]["type"] == "const char *"

    def test_ai_post_route_still_works(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        store.set_decompilation(conn, ids["function"], "int f(void);\n", "kuna")
        llm.set_client(FakeLlmClient())
        status, headers, body = wsgi_request("POST", f"/api/functions/{ids['function']}/summary")
        assert status.startswith("200")
        assert json_body(body, headers)["kind"] == "summary"

    def test_ai_post_route_503_without_a_client(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        store.set_decompilation(conn, ids["function"], "int f(void);\n", "kuna")
        status, headers, body = wsgi_request("POST", f"/api/functions/{ids['function']}/summary")
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "llm-unavailable"

    def test_health_and_counts_still_work(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("GET", "/api/health")
        assert status.startswith("200")
        assert json_body(body, headers)["status"] == "ok"


class TestEngineStages:
    def test_pipeline_uses_the_injected_engine(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        status, headers, body = wsgi_request("POST", f"/api/functions/{ids['function']}/pipeline")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["status"] == pipeline.RUN_DONE
        assert "disassemble" in fake_engine.calls
        assert "decompile" in fake_engine.calls


class TestComponentsRoutes:
    def test_get_lists_the_registry(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("GET", "/api/components")
        assert status.startswith("200")
        payload = json_body(body, headers)
        entry = next(
            item for item in payload["components"] if item["name"] == pipeline.COMPONENT_PREPARE
        )
        assert entry == {
            "name": "prepare",
            "requires": ["conn", "engine", "function"],
            "provides": ["disassembly", "function_meta"],
            "origin": "builtin",
            "reloadable": True,
            "withdrawable": True,
            "withdraw_reason": "",
        }
        assert payload["count"] == len(payload["components"])

    def test_get_marks_a_component_with_nothing_to_withdraw(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("GET", "/api/components")
        assert status.startswith("200")
        payload = json_body(body, headers)
        store_entry = next(
            item for item in payload["components"] if item["name"] == pipeline.COMPONENT_STORE
        )
        assert store_entry["withdrawable"] is False
        assert "nothing" in store_entry["withdraw_reason"]

    def test_post_reloads_one_component(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request(
            "POST",
            "/api/components/reload",
            body=json.dumps({"name": pipeline.COMPONENT_PREPARE}),
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["name"] == "prepare"
        assert payload["reloaded"] is True
        assert payload["changed"] is False
        assert payload["module"] == components.BUILTIN_MODULE

    def test_post_reloads_every_reloadable_component(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request(
            "POST", "/api/components/reload", body=json.dumps({"all": True})
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["count"] == len(pipeline.builtin_components())
        assert payload["changed"] == []
        assert payload["skipped"] == []

    def test_post_404_for_an_unknown_component(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request(
            "POST", "/api/components/reload", body=json.dumps({"name": "no-such-component"})
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "component not found"

    def test_post_400_without_a_name_or_all(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("POST", "/api/components/reload", body="{}")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "provide a component name or all"

    def test_post_400_with_a_name_and_all(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request(
            "POST",
            "/api/components/reload",
            body=json.dumps({"name": "prepare", "all": True}),
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "provide a name or all, not both"

    def test_post_400_for_a_malformed_all_flag(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request(
            "POST", "/api/components/reload", body=json.dumps({"all": "yes"})
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "all must be a boolean"

    def test_post_409_for_an_in_process_component(self, portal_db: Path) -> None:
        components.register_component(
            components.Component("probe", frozenset(), frozenset(), lambda ctx: None)
        )
        status, headers, body = wsgi_request(
            "POST", "/api/components/reload", body=json.dumps({"name": "probe"})
        )
        assert status.startswith("409")
        payload = json_body(body, headers)
        assert payload["error"] == "not-reloadable"
        assert "no declaring module" in payload["detail"]


class TestDeactivateRoute:
    def test_post_withdraws_a_component(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("POST", "/api/components/prepare/deactivate")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["name"] == "prepare"
        assert [entry["name"] for entry in payload["deactivated"]] == ["prepare"]
        assert payload["journaled"] is False
        assert "journal_action" not in payload

    def test_post_refuses_a_second_withdrawal(self, portal_db: Path) -> None:
        wsgi_request("POST", "/api/components/prepare/deactivate")
        status, headers, body = wsgi_request("POST", "/api/components/prepare/deactivate")
        assert status.startswith("409")
        payload = json_body(body, headers)
        assert payload["error"] == "not-withdrawable"
        assert "already withdrawn" in payload["detail"]

    def test_post_404_for_an_unknown_component(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("POST", "/api/components/no-such/deactivate")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "component not found"

    def test_post_409_for_a_component_with_nothing_to_withdraw(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("POST", "/api/components/store/deactivate")
        assert status.startswith("409")
        payload = json_body(body, headers)
        assert payload["error"] == "not-withdrawable"
        assert "nothing" in payload["detail"]

    def test_post_journals_a_durable_revert_and_its_action_reverts(
        self, conn: sqlite3.Connection
    ) -> None:
        conn.execute("CREATE TABLE scratch (id INTEGER PRIMARY KEY, value TEXT)")
        conn.execute("INSERT INTO scratch (id, value) VALUES (1, 'kept')")
        conn.commit()
        components.register_component(_scratch_component())
        status, headers, body = wsgi_request("POST", "/api/components/scratch/deactivate")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["deactivated"][0]["reverted"] is True
        assert payload["journaled"] is True
        assert conn.execute("SELECT COUNT(*) FROM scratch").fetchone()[0] == 0

        action = payload["journal_action"]
        status, headers, body = wsgi_request(
            "POST", "/api/journal/revert", body=json.dumps({"action": action})
        )
        assert status.startswith("200")
        assert conn.execute("SELECT COUNT(*) FROM scratch").fetchone()[0] == 1

    def test_an_analyst_cannot_reload_or_deactivate_components(
        self, portal_db: Path, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        _analyst, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        conn.commit()
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        }
        reload = wsgi_request(
            "POST",
            "/api/components/reload",
            body=json.dumps({"name": pipeline.COMPONENT_PREPARE}),
            headers=headers,
        )
        assert reload[0].startswith("403"), reload[2]
        assert json_body(reload[2], reload[1])["error"] == auth.ERROR_FORBIDDEN

        deactivate = wsgi_request(
            "POST",
            f"/api/components/{pipeline.COMPONENT_PREPARE}/deactivate",
            headers=headers,
        )
        assert deactivate[0].startswith("403"), deactivate[2]
        assert json_body(deactivate[2], deactivate[1])["error"] == auth.ERROR_FORBIDDEN
