"""Tests for the model registry and the analysis-model upgrade.

The bridge is always a typed stub, never a network call.  The registry is
exercised both as it is (an unconfigured install) and with an injected client,
the upgrade is asserted against the artifacts it rewrites, and every failure the
error vocabulary names has a case.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from conftest import FakeLlmClient, json_body, wsgi_request
from plugin_helpers import EntryPoint as _EntryPoint
from plugin_helpers import patch_entry_points as _patch_entry_points
from typer.testing import CliRunner

from reportal import cli, journal, llm, mcp_server, models, plugins, renames, store
from reportal._paths import DB_ENV

runner = CliRunner()

SUMMARY = '{"summary": "reads a file"}'
COMMENTS = '[{"line": 3, "comment": "open it"}]'
TYPES = '[{"name": "path", "kind": "parameter", "type": "const char *"}]'
RENAMES = '[{"from": "local_8", "to": "handle", "kind": "variable", "reason": "clearer"}]'

# The stored decompilation every upgrade test reads.  It carries the identifier
# the canned rename suggestion targets, because renames drops a suggestion whose
# `from` no longer occurs in the code.
CODE = "int sub_1000(int param_1)\n{\n  int local_8 = param_1;\n  return local_8;\n}\n"


@pytest.fixture(autouse=True)
def _isolate_models() -> Iterator[None]:
    """Reload the registry around each test, whatever a test registered."""
    models.refresh_models()
    yield
    models.refresh_models()


def _seed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, functions: int = 1) -> dict[str, Any]:
    """Create a portal DB with one analysis, its functions and a decompilation."""
    db = tmp_path / "portal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    with contextlib.closing(store.connect(db)) as conn:
        binary_id = store.add_binary(conn, sha256="ef" * 32, name="demo.exe")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        ids = [
            store.add_function(
                conn, analysis_id=analysis_id, va=0x1000 + index * 0x100, name=f"sub_{index}"
            )
            for index in range(functions)
        ]
        for function_id in ids:
            store.set_decompilation(conn, function_id, code=CODE, backend="kuna")
    return {"binary": binary_id, "analysis": analysis_id, "functions": ids, "db": db}


def _install_llm(response: str, model: str = "new-model") -> FakeLlmClient:
    """Install a fake bridge and refresh the registry so it names the model."""
    client = FakeLlmClient(response=response, model=model)
    llm.set_client(client)
    models.refresh_models()
    return client


@contextlib.contextmanager
def _journaled(db: Path) -> Iterator[tuple[sqlite3.Connection, journal.Journal]]:
    """A store connection opened inside one flushed journaled action."""
    with (
        contextlib.closing(store.connect(db)) as conn,
        journal.journaled(conn, journal.new_action()) as log,
    ):
        yield conn, log


def _store_summary(conn: sqlite3.Connection, function_id: int, payload: str) -> None:
    """Store one summary artifact with an old model, as a previous run would."""
    store.set_ai_artifact(conn, function_id, llm.AI_KIND_SUMMARY, json.loads(payload), "old-model")


class TestRegistry:
    def test_builtins_are_registered_with_their_kinds(self) -> None:
        found = {model.name: model.kind for model in models.models()}
        assert found[models.ENGINE_PACKAGE] == models.KIND_ENGINE
        assert found["kuna"] == models.KIND_DECOMPILER
        assert found[models.UNCONFIGURED_MODEL] == models.KIND_LLM
        assert found[models.SIMILARITY_PACKAGE] == models.KIND_SIMILARITY

    def test_every_decompiler_backend_has_an_entry(self) -> None:
        from reportal import engines

        names = {model.name for model in models.models() if model.kind == models.KIND_DECOMPILER}
        assert names == set(engines.DECOMPILER_BACKENDS)

    def test_the_engine_entry_reports_its_availability(self) -> None:
        from reportal import engines

        model = models.get_model(models.ENGINE_PACKAGE)
        assert model.available() == engines.get_engine().available()

    def test_the_unconfigured_bridge_is_listed_but_unavailable(self) -> None:
        llm.set_client(None)
        model = models.get_model(models.UNCONFIGURED_MODEL)
        assert model.kind == models.KIND_LLM
        assert not model.available()
        assert model.unavailable_reason()
        assert model.describe()["unavailable_reason"]

    def test_a_configured_bridge_is_named_by_its_model(self) -> None:
        llm.set_client(FakeLlmClient(model="upgrade-target"))
        assert "upgrade-target" in [model.name for model in models.refresh_models()]
        assert models.get_model("upgrade-target").available()

    def test_an_unavailable_entry_reports_no_reason_when_it_works(self) -> None:
        model = models.get_model(models.ENGINE_PACKAGE)
        assert model.describe()["unavailable_reason"] == (
            "" if model.available() else model.unavailable_reason()
        )

    def test_get_model_unknown_name_names_the_known_ones(self) -> None:
        with pytest.raises(models.UnknownModelError) as excinfo:
            models.get_model("nope")
        assert "kuna" in str(excinfo.value)

    def test_describe_reports_the_counts_and_the_note(self) -> None:
        payload = models.describe()
        assert payload["count"] == len(payload["models"])
        assert payload["kinds"] == list(models.KINDS)
        assert renames.RENAMES_KIND in payload["upgrade_kinds"]
        assert payload["note"]

    def test_a_duplicate_name_is_a_registry_error(self) -> None:
        impostor = models.Model(name=models.ENGINE_PACKAGE, kind=models.KIND_ENGINE)
        with pytest.raises(plugins.RegistryError):
            models.register_model(impostor, origin="test")

    def test_a_registered_model_is_replaced_by_a_refresh(self) -> None:
        models.register_model(models.Model(name="probe", kind=models.KIND_LLM), origin="test")
        assert "probe" in [model.name for model in models.models()]
        assert "probe" not in [model.name for model in models.refresh_models()]

    def test_unregister_withdraws_one_entry(self) -> None:
        models.register_model(models.Model(name="probe", kind=models.KIND_LLM), origin="test")
        models.unregister_model("probe")
        names = [model.name for model in models.models()]
        assert "probe" not in names
        assert models.ENGINE_PACKAGE in names

    def test_unregister_unknown_name_raises(self) -> None:
        with pytest.raises(plugins.RegistryError):
            models.unregister_model("nope")

    def test_an_unknown_kind_is_a_registry_error(self) -> None:
        with pytest.raises(plugins.RegistryError):
            models.register_model(models.Model(name="probe", kind="nonsense"), origin="test")

    def test_an_empty_name_is_a_registry_error(self) -> None:
        with pytest.raises(plugins.RegistryError):
            models.register_model(models.Model(name="  ", kind=models.KIND_LLM), origin="test")

    def test_a_non_model_is_a_registry_error(self) -> None:
        with pytest.raises(plugins.RegistryError):
            models.register_model(42, origin="test")  # type: ignore[arg-type]

    def test_entry_point_models_are_registered(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("plugin-probe", "model_plugins:PROBE_MODEL"))
        assert "plugin-probe" in [model.name for model in models.refresh_models()]

    def test_an_entry_point_factory_is_called(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("probe", "model_plugins:PROBE_FACTORY"))
        assert "plugin-probe" in [model.name for model in models.refresh_models()]

    def test_a_broken_entry_point_is_skipped_with_a_warning(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("bad", "model_plugins:NOT_A_MODEL"))
        with caplog.at_level(logging.WARNING):
            names = [model.name for model in models.refresh_models()]
        assert "skipping bad reportal.models registration" in caplog.text
        assert models.ENGINE_PACKAGE in names

    def test_an_entry_point_without_a_module_is_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("bad", ""))
        assert models.ENGINE_PACKAGE in [model.name for model in models.refresh_models()]

    def test_an_entry_point_duplicating_a_builtin_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("dup", "model_plugins:IMPOSTOR_MODEL"))
        with pytest.raises(plugins.RegistryError):
            models.refresh_models()

    def test_refresh_picks_up_a_newly_registered_entry_point(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        assert "plugin-probe" not in [model.name for model in models.models()]
        _patch_entry_points(monkeypatch, _EntryPoint("probe", "model_plugins:PROBE_MODEL"))
        assert "plugin-probe" in [model.name for model in models.refresh_models()]


class TestValidation:
    def test_a_model_name_must_be_a_non_empty_string(self) -> None:
        for bad in (None, "", "   ", 5):
            with pytest.raises(models.InvalidModelError):
                models.normalize_model_name(bad)

    def test_a_name_past_the_cap_is_refused(self) -> None:
        with pytest.raises(models.InvalidModelError):
            models.normalize_model_name("m" * (models.MAX_MODEL_NAME + 1))

    def test_a_name_is_trimmed(self) -> None:
        assert models.normalize_model_name("  gpt-4o-mini ") == "gpt-4o-mini"

    def test_functions_must_be_a_list_of_ids(self) -> None:
        assert models.normalize_function_ids(None) is None
        assert models.normalize_function_ids([1, 2]) == [1, 2]
        for bad in ("3", [True], ["x"], {"a": 1}):
            with pytest.raises(models.InvalidModelError):
                models.normalize_function_ids(bad)

    def test_the_limit_defaults_and_is_bounded(self) -> None:
        assert models.normalize_limit(None) == models.DEFAULT_UPGRADE_LIMIT
        assert models.normalize_limit(3) == 3
        for bad in (0, -1, models.MAX_UPGRADE_LIMIT + 1, True, "3"):
            with pytest.raises(models.InvalidModelError):
                models.normalize_limit(bad)

    def test_a_non_llm_model_cannot_be_upgraded_to(self) -> None:
        with pytest.raises(models.NotUpgradeableError):
            models.upgradeable_model(models.ENGINE_PACKAGE)

    def test_an_unknown_upgrade_model_is_404(self) -> None:
        with pytest.raises(models.UnknownModelError):
            models.upgradeable_model("nope")

    def test_an_unconfigured_bridge_is_unavailable(self) -> None:
        llm.set_client(None)
        models.refresh_models()
        with pytest.raises(llm.LlmUnavailable):
            models.upgradeable_model(models.UNCONFIGURED_MODEL)


class TestCandidates:
    def test_only_functions_with_a_stored_artifact_are_candidates(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, functions=2)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            _store_summary(conn, ids["functions"][0], SUMMARY)
            rows = models.candidate_functions(conn, ids["analysis"])
        assert [row["id"] for row in rows] == [ids["functions"][0]]

    def test_the_limit_bounds_the_candidates(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, functions=3)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            for function_id in ids["functions"]:
                _store_summary(conn, function_id, SUMMARY)
            rows = models.candidate_functions(conn, ids["analysis"], limit=2)
        assert len(rows) == 2

    def test_an_explicit_list_keeps_its_order_and_ignores_the_limit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, functions=3)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            for function_id in ids["functions"]:
                _store_summary(conn, function_id, SUMMARY)
            reversed_ids = list(reversed(ids["functions"]))
            rows = models.candidate_functions(
                conn, ids["analysis"], functions=reversed_ids, limit=1
            )
        assert [row["id"] for row in rows] == reversed_ids

    def test_a_function_of_another_analysis_is_not_a_candidate(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            other_analysis = store.create_analysis(conn, binary_id=ids["binary"], engine="manual")
            other = store.add_function(conn, analysis_id=other_analysis, va=0x9000, name="other")
            _store_summary(conn, other, SUMMARY)
            rows = models.candidate_functions(conn, ids["analysis"], functions=[other])
        assert rows == []

    def test_a_function_with_no_stored_kind_is_not_a_candidate(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            rows = models.candidate_functions(conn, ids["analysis"])
        assert rows == []


class TestUpgrade:
    def test_it_reruns_every_stored_kind_and_records_the_model(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, functions=2)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            _store_summary(conn, ids["functions"][0], SUMMARY)
            _store_summary(conn, ids["functions"][1], SUMMARY)
        _install_llm(SUMMARY)
        with _journaled(ids["db"]) as (conn, log):
            result = models.upgrade_analysis(
                conn, log, analysis_id=ids["analysis"], model="new-model"
            )
            assert result["from"] == ""
            assert result["to"] == "new-model"
            assert result["upgraded"] == 2
            assert result["candidates"] == 2
            assert result["note"]
            analysis = store.get_analysis(conn, ids["analysis"])
            assert analysis is not None
            assert analysis["model"] == "new-model"
            artifact = store.get_ai_artifact(conn, ids["functions"][0], llm.AI_KIND_SUMMARY)
        assert artifact is not None
        assert artifact["model"] == "new-model"

    def test_every_stored_kind_is_rerun(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            _store_summary(conn, ids["functions"][0], SUMMARY)
            store.set_ai_artifact(
                conn,
                ids["functions"][0],
                llm.AI_KIND_COMMENTS,
                {"comments": json.loads(COMMENTS)},
                "old",
            )
            store.set_ai_artifact(
                conn,
                ids["functions"][0],
                llm.AI_KIND_TYPES,
                {"suggestions": json.loads(TYPES)},
                "old",
            )
        _install_llm(SUMMARY)

        class _PerKind(FakeLlmClient):
            """A stub that answers each artifact kind with its own canned response."""

            def complete(
                self,
                messages: list[dict[str, str]],
                *,
                temperature: float = llm.DEFAULT_TEMPERATURE,
                json_object: bool = False,
                max_tokens: int = llm.MAX_COMPLETION_TOKENS,
            ) -> str:
                self.calls.append(messages)
                prompt = messages[-1]["content"]
                if "inline comment" in prompt:
                    return COMMENTS
                if "Suggest types" in prompt:
                    return TYPES
                return SUMMARY

        with _journaled(ids["db"]) as (conn, log):
            result = models.upgrade_analysis(
                conn,
                log,
                analysis_id=ids["analysis"],
                model="new-model",
                client=_PerKind(response=SUMMARY, model="new-model"),
            )
            comments = store.get_ai_artifact(conn, ids["functions"][0], llm.AI_KIND_COMMENTS)
        assert result["applied"][0]["kinds"] == list(models.UPGRADE_KINDS[:3])
        assert comments is not None
        assert comments["payload"]["comments"][0]["comment"] == "open it"

    def test_every_artifact_replaced_is_journaled(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            _store_summary(conn, ids["functions"][0], SUMMARY)
        _install_llm(SUMMARY)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            action = journal.new_action()
            with journal.journaled(conn, action) as log:
                models.upgrade_analysis(conn, log, analysis_id=ids["analysis"], model="new-model")
            assert journal.revert_action(conn, action)["reverted"] > 0
            artifact = store.get_ai_artifact(conn, ids["functions"][0], llm.AI_KIND_SUMMARY)
            reverted = store.get_analysis(conn, ids["analysis"])
            assert reverted is not None
            assert reverted["model"] == ""
        assert artifact is not None
        assert artifact["model"] == "old-model"

    def test_the_renames_kind_goes_through_the_renames_module(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            store.set_ai_artifact(
                conn,
                ids["functions"][0],
                renames.RENAMES_KIND,
                {"suggestions": [{"from": "old", "to": "new"}]},
                "old-model",
            )
        _install_llm(RENAMES)
        with _journaled(ids["db"]) as (conn, log):
            result = models.upgrade_analysis(
                conn, log, analysis_id=ids["analysis"], model="new-model"
            )
            artifact = store.get_ai_artifact(conn, ids["functions"][0], renames.RENAMES_KIND)
        assert result["applied"][0]["kinds"] == [renames.RENAMES_KIND]
        assert artifact is not None
        assert artifact["payload"]["suggestions"][0]["to"] == "handle"

    def test_a_function_whose_rerun_fails_is_skipped_and_keeps_its_artifact(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            _store_summary(conn, ids["functions"][0], SUMMARY)
        _install_llm("not json at all")
        with _journaled(ids["db"]) as (conn, log):
            result = models.upgrade_analysis(
                conn, log, analysis_id=ids["analysis"], model="new-model"
            )
            artifact = store.get_ai_artifact(conn, ids["functions"][0], llm.AI_KIND_SUMMARY)
        assert result["upgraded"] == 0
        assert result["skipped"][0]["function_id"] == ids["functions"][0]
        assert artifact is not None
        assert artifact["model"] == "old-model"

    def test_an_analysis_with_nothing_to_rerun_reports_no_candidates(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        _install_llm(SUMMARY)
        with _journaled(ids["db"]) as (conn, log):
            result = models.upgrade_analysis(
                conn, log, analysis_id=ids["analysis"], model="new-model"
            )
        assert result["candidates"] == 0
        assert result["applied"] == []

    def test_an_explicit_function_list_scopes_the_rerun(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, functions=2)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            for function_id in ids["functions"]:
                _store_summary(conn, function_id, SUMMARY)
        _install_llm(SUMMARY)
        with _journaled(ids["db"]) as (conn, log):
            result = models.upgrade_analysis(
                conn,
                log,
                analysis_id=ids["analysis"],
                model="new-model",
                functions=[ids["functions"][1]],
            )
        assert [entry["function_id"] for entry in result["applied"]] == [ids["functions"][1]]

    def test_the_from_model_is_the_one_the_analysis_recorded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            store.update_analysis(conn, ids["analysis"], model="old-model")
            _store_summary(conn, ids["functions"][0], SUMMARY)
        _install_llm(SUMMARY)
        with _journaled(ids["db"]) as (conn, log):
            result = models.upgrade_analysis(
                conn, log, analysis_id=ids["analysis"], model="new-model"
            )
        assert result["from"] == "old-model"

    def test_an_unknown_model_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        _install_llm(SUMMARY)
        with (
            _journaled(ids["db"]) as (conn, log),
            pytest.raises(models.UnknownModelError),
        ):
            models.upgrade_analysis(conn, log, analysis_id=ids["analysis"], model="x")

    def test_a_non_llm_model_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with (
            _journaled(ids["db"]) as (conn, log),
            pytest.raises(models.NotUpgradeableError),
        ):
            models.upgrade_analysis(
                conn, log, analysis_id=ids["analysis"], model=models.ENGINE_PACKAGE
            )

    def test_an_injected_client_is_used_as_it_is(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            _store_summary(conn, ids["functions"][0], SUMMARY)
        _install_llm(SUMMARY)
        client = FakeLlmClient(response=SUMMARY, model="new-model")
        with _journaled(ids["db"]) as (conn, log):
            result = models.upgrade_analysis(
                conn,
                log,
                analysis_id=ids["analysis"],
                model="new-model",
                client=client,
            )
        assert result["upgraded"] == 1
        assert client.calls, "the injected client is the one that ran"


class TestLlmWithModel:
    def test_it_keeps_the_endpoint_and_changes_the_model(self) -> None:
        client = FakeLlmClient(model="old-model")
        other = llm.with_model(client, "new-model")
        assert other.model == "new-model"
        assert other.available()
        assert other.config is not None
        assert client.config is not None
        assert other.config.endpoint == client.config.endpoint

    def test_an_unconfigured_client_is_unavailable(self) -> None:
        with pytest.raises(llm.LlmUnavailable):
            llm.with_model(llm.LlmClient(None), "new-model")


class TestRoutes:
    def test_the_models_route_lists_the_registry(self) -> None:
        status, headers, body = wsgi_request("GET", "/api/models")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["count"] == len(payload["models"])
        assert models.ENGINE_PACKAGE in [entry["name"] for entry in payload["models"]]

    def test_the_upgrade_route_reruns_and_journals(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            _store_summary(conn, ids["functions"][0], SUMMARY)
        _install_llm(SUMMARY)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/analyses/{ids['analysis']}/upgrade",
            body=json.dumps({"model": "new-model"}),
        )
        assert status.startswith("200"), body
        payload = json_body(body, headers)
        assert payload["to"] == "new-model"
        assert payload["upgraded"] == 1
        assert payload["journal_action"]

    def test_an_unknown_analysis_is_404(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(tmp_path, monkeypatch)
        _install_llm(SUMMARY)
        status, headers, body = wsgi_request(
            "POST", "/api/analyses/999/upgrade", body=json.dumps({"model": "new-model"})
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "analysis not found"

    def test_an_unknown_model_is_404(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        _install_llm(SUMMARY)
        status, headers, body = wsgi_request(
            "POST", f"/api/analyses/{ids['analysis']}/upgrade", body=json.dumps({"model": "nope"})
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "model not found"

    def test_a_non_llm_model_is_400(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/analyses/{ids['analysis']}/upgrade",
            body=json.dumps({"model": models.ENGINE_PACKAGE}),
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid model"

    def test_a_bad_limit_is_400(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        _install_llm(SUMMARY)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/analyses/{ids['analysis']}/upgrade",
            body=json.dumps({"model": "new-model", "limit": 0}),
        )
        assert status.startswith("400")
        payload = json_body(body, headers)
        assert payload["error"] == "invalid model"
        assert payload["detail"] == "limit must be between 1 and 200"

    def test_an_unconfigured_bridge_is_503(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        llm.set_client(None)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/analyses/{ids['analysis']}/upgrade",
            body=json.dumps({"model": models.UNCONFIGURED_MODEL}),
        )
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "llm-unavailable"

    def test_a_missing_model_field_is_400(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        status, headers, body = wsgi_request(
            "POST", f"/api/analyses/{ids['analysis']}/upgrade", body=json.dumps({})
        )
        assert status.startswith("400")


class TestCli:
    def test_models_lists_the_registry(self) -> None:
        result = runner.invoke(cli.app, ["models", "--json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["count"] > 0

    def test_models_human_output(self) -> None:
        result = runner.invoke(cli.app, ["models"])
        assert result.exit_code == 0, result.output
        assert "kuna" in result.output

    def test_the_upgrade_reruns_and_reports(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            _store_summary(conn, ids["functions"][0], SUMMARY)
        _install_llm(SUMMARY)
        result = runner.invoke(
            cli.app, ["analysis-upgrade", str(ids["analysis"]), "--model", "new-model", "--json"]
        )
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["upgraded"] == 1

    def test_the_upgrade_human_output(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            _store_summary(conn, ids["functions"][0], SUMMARY)
        _install_llm("not json")
        result = runner.invoke(
            cli.app, ["analysis-upgrade", str(ids["analysis"]), "--model", "new-model"]
        )
        assert result.exit_code == 0, result.output
        assert "skipped function" in result.output

    def test_an_explicit_function_and_limit_are_accepted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            _store_summary(conn, ids["functions"][0], SUMMARY)
        _install_llm(SUMMARY)
        result = runner.invoke(
            cli.app,
            [
                "analysis-upgrade",
                str(ids["analysis"]),
                "--model",
                "new-model",
                "--function",
                str(ids["functions"][0]),
                "--limit",
                "5",
                "--json",
            ],
        )
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["upgraded"] == 1

    def test_an_unknown_model_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app, ["analysis-upgrade", str(ids["analysis"]), "--model", "nope"]
        )
        assert result.exit_code == 1
        assert "unknown model" in result.output

    def test_a_non_llm_model_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app, ["analysis-upgrade", str(ids["analysis"]), "--model", models.ENGINE_PACKAGE]
        )
        assert result.exit_code == 1
        assert "only an llm model" in result.output

    def test_an_unknown_analysis_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(tmp_path, monkeypatch)
        _install_llm(SUMMARY)
        result = runner.invoke(cli.app, ["analysis-upgrade", "999", "--model", "new-model"])
        assert result.exit_code == 1
        assert "no analysis with id 999" in result.output

    def test_an_unconfigured_bridge_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        llm.set_client(None)
        result = runner.invoke(
            cli.app,
            ["analysis-upgrade", str(ids["analysis"]), "--model", models.UNCONFIGURED_MODEL],
        )
        assert result.exit_code == 1
        assert "llm-unavailable" in result.output

    def test_the_upgrade_fails_without_a_database(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "missing" / "portal.db"))
        _install_llm(SUMMARY)
        result = runner.invoke(cli.app, ["analysis-upgrade", "1", "--model", "new-model"])
        assert result.exit_code == 1
        assert "no reportal database" in result.output


class TestMcp:
    def test_list_models_reads_the_registry(self) -> None:
        payload, failed = mcp_server.call_tool("list_models", {})
        assert not failed
        assert payload["count"] > 0

    def test_the_upgrade_tool_reruns_and_journals(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            _store_summary(conn, ids["functions"][0], SUMMARY)
        _install_llm(SUMMARY)
        payload, failed = mcp_server.call_tool(
            "upgrade_analysis_model",
            {"analysis_id": ids["analysis"], "model": "new-model", "limit": 5},
        )
        assert not failed, payload
        assert payload["upgraded"] == 1
        assert payload["journal_action"]

    def test_the_upgrade_tool_reports_its_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        _install_llm(SUMMARY)
        payload, failed = mcp_server.call_tool(
            "upgrade_analysis_model", {"analysis_id": 999, "model": "new-model"}
        )
        assert failed
        assert payload["error"] == "analysis not found"

        payload, failed = mcp_server.call_tool(
            "upgrade_analysis_model", {"analysis_id": ids["analysis"], "model": "nope"}
        )
        assert failed
        assert payload["error"] == "model not found"

        payload, failed = mcp_server.call_tool(
            "upgrade_analysis_model",
            {"analysis_id": ids["analysis"], "model": models.ENGINE_PACKAGE},
        )
        assert failed
        assert payload["error"] == "invalid model"

        payload, failed = mcp_server.call_tool(
            "upgrade_analysis_model",
            {"analysis_id": ids["analysis"], "model": "new-model", "functions": "no"},
        )
        assert failed
        assert payload["error"] == "invalid params"

    def test_the_upgrade_tool_without_a_bridge_is_a_tool_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        llm.set_client(None)
        payload, failed = mcp_server.call_tool(
            "upgrade_analysis_model",
            {"analysis_id": ids["analysis"], "model": models.UNCONFIGURED_MODEL},
        )
        assert failed
        assert payload["error"] == "llm-unavailable"

    def test_a_bad_limit_is_an_invalid_model_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        _install_llm(SUMMARY)
        payload, failed = mcp_server.call_tool(
            "upgrade_analysis_model",
            {"analysis_id": ids["analysis"], "model": "new-model", "limit": 0},
        )
        assert failed
        assert payload["error"] == "invalid model"


def test_the_environment_db_constant_is_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The helpers above rely on DB_ENV; a missing one would silently use the real DB."""
    ids = _seed(tmp_path, monkeypatch)
    assert os.environ[DB_ENV] == str(ids["db"])
