"""Tests for the AI decompilation pipeline: ordering, stages, run and revert."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, cast

import pytest
from conftest import AI_SUMMARY_RESPONSE, FailingLlmClient, FakeEngine
from pipeline_helpers import LISTING, ScriptedLlmClient, seed_portal, seed_unstrip_proposal, spy

from reportal import (
    ai_decomp,
    components,
    effects,
    engines,
    journal,
    llm,
    pipeline,
    similarity,
    store,
    symbols,
)
from reportal.components import Component, Context


@pytest.fixture(autouse=True)
def _isolate_components() -> Iterator[None]:
    """Reload the registry and drop the live host around each test."""
    components.refresh_components()
    pipeline.reset_live_state()
    yield
    pipeline.reset_live_state()
    components.refresh_components()


def _component(
    name: str,
    *,
    requires: set[str] | None = None,
    provides: set[str] | None = None,
    effect: Any = None,
) -> Component:
    """A component with no behaviour, for registration in a test."""
    return Component(
        name=name,
        requires=frozenset(requires or ()),
        provides=frozenset(provides or ()),
        effect=effect if effect is not None else (lambda ctx: None),
    )


def _run(
    conn: sqlite3.Connection,
    ids: dict[str, int],
    *,
    engine: engines.RebrewEngine | None = None,
    llm_client: llm.LlmClient | None = None,
    disabled: frozenset[str] | None = None,
) -> dict[str, Any]:
    """Run the pipeline over the seeded function and return the run."""
    return pipeline.run_pipeline(
        conn,
        function_id=ids["function"],
        engine=engine,
        llm_client=llm_client,
        disabled=disabled,
    )


def _ingest_symbols(
    conn: sqlite3.Connection, *, binary_id: int, data: bytes, parsed: dict[str, Any]
) -> None:
    """Store a hand-built symbol parse for one binary, without applying it."""
    with journal.journaled(conn, journal.new_action()) as log:
        symbols.import_symbols(
            conn, log, binary_id=binary_id, data=data, parsed=parsed, apply=False
        )


def _steps(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """The run's steps keyed by component name."""
    return {str(step["name"]): step for step in run["steps"]}


class TestDependencyOrder:
    def test_provider_precedes_its_dependents(self) -> None:
        late = _component("late", requires={"thing"})
        provider = _component("provider", provides={"thing"})
        order = [component.name for component in pipeline.dependency_order([late, provider])]
        assert order == ["provider", "late"]

    def test_ties_keep_declaration_order(self) -> None:
        first = _component("first", requires={"thing"})
        second = _component("second", requires={"thing"})
        provider = _component("provider", provides={"thing"})
        order = [
            component.name for component in pipeline.dependency_order([second, first, provider])
        ]
        assert order == ["provider", "second", "first"]

    def test_builtin_order_matches_the_reported_step_sequence(self) -> None:
        order = [
            component.name for component in pipeline.dependency_order(pipeline.builtin_components())
        ]
        # The enrich chain is ordered by real edges, not by luck:
        # `name-variables` and `summarize` require `renamed_code`, so they cannot
        # run before the rename pass, and `store` persists what the whole chain
        # produced so it comes last.  A declaration shuffle that broke any of
        # that would show up here.
        assert order == [
            "prepare",
            "read-trace",
            "decompile",
            "search-functionality",
            "resolve-names",
            "retrieve-knowledge",
            "rewrite",
            "rename-variables",
            "name-variables",
            "summarize",
            "store",
        ]
        assert order.index("rewrite") < order.index("rename-variables")
        assert order.index("rename-variables") < order.index("name-variables")
        assert order.index("rename-variables") < order.index("summarize")
        assert order.index("summarize") < order.index("store")


class TestRun:
    def test_records_every_step_with_duration_and_provides(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        client = ScriptedLlmClient()
        run = _run(conn, ids, engine=fake_engine, llm_client=client)
        assert run["status"] == pipeline.RUN_DONE
        assert run["model"] == "scripted-model"
        steps = run["steps"]
        assert [step["name"] for step in steps] == [
            "prepare",
            "read-trace",
            "decompile",
            "search-functionality",
            "resolve-names",
            "retrieve-knowledge",
            "rewrite",
            "rename-variables",
            "name-variables",
            "summarize",
            "store",
        ]
        assert all(step["status"] == pipeline.STEP_DONE for step in steps)
        assert all(step["duration_ms"] >= 0 for step in steps)
        assert all(step["started_at"] and step["finished_at"] for step in steps)
        assert _steps(run)["decompile"]["provides"] == ["decompilation"]
        assert run["started_at"] and run["finished_at"]

    def test_step_duration_comes_from_the_clock_seam(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        """The recorded duration is pinned by ``pipeline._monotonic``, not wall time."""
        ids = seed_portal(tmp_path, monkeypatch)
        clock = [0.0]

        def tick() -> float:
            clock[0] += 1.0
            return clock[0]

        monkeypatch.setattr(pipeline, "_monotonic", tick)
        run = _run(conn, ids, engine=fake_engine, llm_client=ScriptedLlmClient())
        assert run["status"] == pipeline.RUN_DONE
        assert all(step["duration_ms"] == 1000 for step in run["steps"])

    def test_persists_run_and_steps(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        run = _run(conn, ids, engine=fake_engine, llm_client=ScriptedLlmClient())
        stored = store.get_pipeline_run(conn, int(run["id"]))
        assert stored is not None
        assert stored["function_id"] == ids["function"]
        assert stored["status"] == store.PIPELINE_RUN_DONE
        assert len(stored["steps"]) == len(run["steps"])
        assert (
            cast(dict[str, Any], store.latest_pipeline_run(conn, ids["function"]))["id"]
            == run["id"]
        )

    def test_unknown_function_raises_key_error(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(KeyError):
            pipeline.run_pipeline(conn, function_id=4242)

    def test_without_an_engine_prepare_fails_and_dependents_skip(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        run = _run(conn, ids)
        steps = _steps(run)
        assert steps["prepare"]["status"] == pipeline.STEP_FAILED
        assert steps["prepare"]["reason"] == pipeline.REASON_ENGINE_UNAVAILABLE
        assert steps["read-trace"]["status"] == pipeline.STEP_SKIPPED
        assert steps["read-trace"]["reason"] == "dependency-failed:prepare"
        assert steps["decompile"]["status"] == pipeline.STEP_FAILED
        assert run["status"] == pipeline.RUN_FAILED

    def test_without_a_project_decompile_skips_with_no_engine_context(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch, project=False)
        run = _run(conn, ids, engine=FakeEngine(), llm_client=ScriptedLlmClient())
        steps = _steps(run)
        assert steps["decompile"]["status"] == pipeline.STEP_SKIPPED
        assert steps["decompile"]["reason"] == pipeline.REASON_NO_ENGINE_CONTEXT
        # Each step names the requirement that went, so the reason reads as a
        # chain back to the root: summarize waits on the rename pass, which
        # waits on the decompilation, which had no project to read.
        for name in ("rewrite", "rename-variables"):
            assert steps[name]["status"] == pipeline.STEP_SKIPPED
            assert steps[name]["reason"] == "dependency-skipped:decompile"
        for name in ("name-variables", "summarize"):
            assert steps[name]["status"] == pipeline.STEP_SKIPPED
            assert steps[name]["reason"] == "dependency-skipped:rename-variables"

    def test_without_llm_skips_the_llm_stages(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        run = _run(conn, ids, engine=FakeEngine())
        steps = _steps(run)
        assert steps["name-variables"]["status"] == pipeline.STEP_SKIPPED
        assert steps["name-variables"]["reason"] == pipeline.REASON_LLM_UNAVAILABLE
        assert steps["summarize"]["status"] == pipeline.STEP_SKIPPED
        assert steps["summarize"]["reason"] == pipeline.REASON_LLM_UNAVAILABLE
        assert run["model"] == ""
        assert run["artifacts"]["summary"] is None

    def test_disabled_argument_skips_a_component_and_its_dependents(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        run = _run(conn, ids, engine=FakeEngine(), disabled=frozenset({"prepare"}))
        steps = _steps(run)
        assert steps["prepare"]["status"] == pipeline.STEP_SKIPPED
        assert steps["prepare"]["reason"] == pipeline.REASON_DISABLED
        assert steps["read-trace"]["reason"] == "dependency-skipped:prepare"

    def test_config_disables_a_component(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        (tmp_path / "reportal.toml").write_text(
            '[pipeline]\ndisabled = ["prepare"]\n', encoding="utf-8"
        )
        monkeypatch.setattr(pipeline, "project_root", lambda: tmp_path)
        run = _run(conn, ids, engine=FakeEngine())
        assert _steps(run)["prepare"]["reason"] == pipeline.REASON_DISABLED

    def test_explicit_disabled_overrides_the_config(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        (tmp_path / "reportal.toml").write_text(
            '[pipeline]\ndisabled = ["prepare"]\n', encoding="utf-8"
        )
        monkeypatch.setattr(pipeline, "project_root", lambda: tmp_path)
        run = _run(conn, ids, engine=FakeEngine(), disabled=frozenset())
        assert _steps(run)["prepare"]["status"] == pipeline.STEP_DONE

    def test_an_unsatisfiable_requirement_names_itself(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        components.register_component(_component("needs-nothing-in-particular", requires={"nope"}))
        run = _run(conn, ids, engine=FakeEngine())
        step = _steps(run)["needs-nothing-in-particular"]
        assert step["status"] == pipeline.STEP_SKIPPED
        assert step["reason"] == "requires-nope"

    def test_failed_component_calls_its_revert_hook(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        reverted: list[str] = []

        def explode(ctx: Context) -> None:
            raise pipeline.StepFailure("boom")

        def cleanup(ctx: Context) -> None:
            reverted.append("cleaned")

        components.register_component(
            Component(
                name="exploding",
                requires=frozenset(),
                provides=frozenset(),
                effect=explode,
                revert=cleanup,
            )
        )
        run = _run(conn, ids, engine=FakeEngine())
        assert _steps(run)["exploding"]["reason"] == "boom"
        assert reverted == ["cleaned"]
        assert run["status"] == pipeline.RUN_FAILED

    def test_registry_error_becomes_pipeline_unavailable(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)

        def boom() -> tuple[Component, ...]:
            raise components.RegistryError("two components named prepare")

        monkeypatch.setattr(components, "components", boom)
        with pytest.raises(pipeline.PipelineUnavailable):
            _run(conn, ids)


class TestUniqueProviders:
    """One writer per context name, checked before any effect runs."""

    def _two_providers(self) -> tuple[Component, Component]:
        return (
            _provider("first", provides={"shared"}),
            _provider("second", provides={"shared"}),
        )

    def test_a_run_refuses_a_duplicate_provider(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        composition = self._two_providers()
        monkeypatch.setattr(components, "components", lambda: composition)

        with pytest.raises(pipeline.PipelineUnavailable) as failure:
            _run(conn, ids)

        assert "shared" in str(failure.value)

    def test_a_disabled_provider_is_not_a_writer(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        composition = self._two_providers()
        monkeypatch.setattr(components, "components", lambda: composition)

        # Disabling the second one leaves a single writer, so the run is valid
        # and the disabled component is recorded as a skipped step rather than
        # an error.
        run = _run(conn, ids, disabled=frozenset({"second"}))

        assert run["status"] == pipeline.RUN_DONE
        steps = {step["name"]: step["status"] for step in run["steps"]}
        assert steps == {"first": pipeline.STEP_DONE, "second": pipeline.STEP_SKIPPED}

    def test_the_host_refuses_a_duplicate_provider(self) -> None:
        composition = self._two_providers()
        with pytest.raises(components.RegistryError) as failure:
            pipeline.ComponentHost({}, registered=list(composition))
        assert "shared" in str(failure.value)

    def test_the_host_checks_the_composition_a_reload_brings_in(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        first = _provider("first", provides={"shared"})
        host = pipeline.ComponentHost({}, registered=[first])
        monkeypatch.setattr(
            components, "components", lambda: (first, _provider("second", provides={"shared"}))
        )

        with pytest.raises(components.RegistryError):
            host.sync()

        # The live composition is untouched by a refused reload.
        assert [component.name for component in host.registered()] == ["first"]


class TestReactiveActivation:
    def test_a_component_activates_when_its_requirement_appears_mid_run(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        captured: dict[str, Any] = {}
        components.register_component(
            _component(
                "late-provider",
                provides={"late_value"},
                effect=lambda ctx: ctx.provide("late_value", 7),
            )
        )
        components.register_component(spy("late-consumer", {"late_value"}, captured))
        run = _run(conn, ids, engine=FakeEngine())
        assert captured["late_value"] == 7
        assert _steps(run)["late-consumer"]["status"] == pipeline.STEP_DONE

    def test_a_component_deactivates_when_a_requirement_is_revoked(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        reached: list[str] = []

        def flip(ctx: Context) -> None:
            ctx.provide("flip_value", 1)
            ctx.revoke("flip_value")

        components.register_component(_component("flipper", provides={"flip_value"}, effect=flip))
        components.register_component(
            _component(
                "needs-flip",
                requires={"flip_value"},
                effect=lambda ctx: reached.append("ran"),
            )
        )
        run = _run(conn, ids, engine=FakeEngine())
        step = _steps(run)["needs-flip"]
        assert step["status"] == pipeline.STEP_DEACTIVATED
        assert step["reason"] == f"{pipeline.REASON_REQUIREMENT_REVOKED}:flip_value"
        assert reached == []
        assert run["status"] == pipeline.RUN_DONE

    def test_a_component_waiting_on_a_deactivated_provider_is_skipped(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)

        def gate(ctx: Context) -> None:
            ctx.provide("gate", 1)
            ctx.revoke("gate")

        components.register_component(_component("gatekeeper", provides={"gate"}, effect=gate))
        components.register_component(_component("flipper", requires={"gate"}, provides={"flip"}))
        components.register_component(_component("needs-flip", requires={"flip"}))
        run = _run(conn, ids, engine=FakeEngine())
        assert _steps(run)["flipper"]["status"] == pipeline.STEP_DEACTIVATED
        step = _steps(run)["needs-flip"]
        assert step["status"] == pipeline.STEP_SKIPPED
        assert step["reason"] == f"{pipeline.REASON_DEPENDENCY_DEACTIVATED}:flipper"

    def test_a_component_revoking_its_own_requirement_still_completes(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        components.register_component(
            _component(
                "seeder",
                provides={"handoff"},
                effect=lambda ctx: ctx.provide("handoff", 1),
            )
        )
        components.register_component(
            _component(
                "self-revoker",
                requires={"handoff"},
                effect=lambda ctx: ctx.revoke("handoff"),
            )
        )
        run = _run(conn, ids, engine=FakeEngine())
        assert _steps(run)["self-revoker"]["status"] == pipeline.STEP_DONE
        assert _steps(run)["seeder"]["status"] == pipeline.STEP_DONE

    def test_a_revert_that_revokes_a_requirement_deactivates_the_consumer(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        builtin_names = frozenset(component.name for component in pipeline.builtin_components())
        components.register_component(
            _component(
                "seeder",
                provides={"shared"},
                effect=lambda ctx: ctx.provide("shared", 1),
            )
        )
        components.register_component(_component("reverter", effect=lambda ctx: ctx.revert()))
        components.register_component(_component("consumer", requires={"shared"}))
        run = _run(conn, ids, engine=FakeEngine(), disabled=builtin_names)
        assert _steps(run)["seeder"]["status"] == pipeline.STEP_DONE
        step = _steps(run)["consumer"]
        assert step["status"] == pipeline.STEP_DEACTIVATED
        assert step["reason"] == f"{pipeline.REASON_REQUIREMENT_REVOKED}:shared"

    def test_a_disabled_provider_skips_its_dependent_without_deactivation(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)

        def flip(ctx: Context) -> None:
            ctx.provide("flip_value", 1)
            ctx.revoke("flip_value")

        components.register_component(_component("flipper", provides={"flip_value"}, effect=flip))
        components.register_component(_component("needs-flip", requires={"flip_value"}))
        run = _run(conn, ids, engine=FakeEngine(), disabled=frozenset({"flipper"}))
        # A disabled provider is skipped, so its dependent is skipped too, and
        # neither ever becomes ready to be deactivated.
        assert _steps(run)["flipper"]["reason"] == pipeline.REASON_DISABLED
        assert _steps(run)["needs-flip"]["reason"] == "dependency-skipped:flipper"


class TestBuiltinStages:
    def test_prepare_reuses_the_disasm_cache(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        store.set_disasm(conn, ids["function"], LISTING)
        engine = FakeEngine()
        _run(conn, ids, engine=engine)
        assert "disassemble" not in engine.calls

    def test_prepare_caches_a_live_disassembly(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        engine = FakeEngine()

        def disassemble(*args: Any, **kwargs: Any) -> str:
            engine.calls.append("disassemble")
            return LISTING

        monkeypatch.setattr(engine, "disassemble", disassemble)
        run = _run(conn, ids, engine=engine)
        assert engine.calls == ["disassemble", "decompile"]
        assert store.get_disasm(conn, ids["function"]) == LISTING
        assert any(descriptor["kind"] == pipeline.EFFECT_DISASM for descriptor in run["effects"])

    def test_read_trace_provides_control_flow_and_call_trace(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        captured: dict[str, Any] = {}
        components.register_component(spy("trace-spy", {"control_flow", "call_trace"}, captured))
        engine = FakeEngine()
        monkeypatch.setattr(engine, "disassemble", lambda *args, **kwargs: LISTING)
        _run(conn, ids, engine=engine)
        flow = captured["control_flow"]
        assert flow["instruction_count"] == 7
        assert flow["block_count"] == 3
        assert {"kind": "call", "va": 0x1005, "target": 0x2000} in flow["branches"]
        assert captured["call_trace"]["callees"] == [{"va": 0x2000, "name": "DoThing"}]

    def test_decompile_reuses_a_stored_decompilation(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        store.set_decompilation(conn, ids["function"], "int f(void) { return 1; }\n", "kuna")
        captured: dict[str, Any] = {}
        components.register_component(spy("decompile-spy", {"decompilation"}, captured))
        engine = FakeEngine()
        run = _run(conn, ids, engine=engine)
        assert "decompile" not in engine.calls
        assert captured["decompilation"]["reused"] is True
        assert not any(
            descriptor["kind"] == pipeline.EFFECT_DECOMPILATION for descriptor in run["effects"]
        )

    def test_decompile_stores_and_journals_a_new_one(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        captured: dict[str, Any] = {}
        components.register_component(spy("decompile-spy", {"decompilation"}, captured))
        engine = FakeEngine()
        run = _run(conn, ids, engine=engine)
        stored = store.get_decompilation(conn, ids["function"])
        assert stored is not None and "return;" in stored["code"]
        assert captured["decompilation"]["reused"] is False
        assert any(
            descriptor["kind"] == pipeline.EFFECT_DECOMPILATION and descriptor["previous"] is None
            for descriptor in run["effects"]
        )

    def test_search_functionality_reads_stored_matches(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        store.record_match(
            conn,
            function_id=ids["function"],
            candidate_function_id=ids["second"],
            similarity=88.0,
            confidence=0.7,
        )
        captured: dict[str, Any] = {}
        components.register_component(spy("similar-spy", {"similar_functions"}, captured))
        monkeypatch.setattr(similarity, "available", lambda: False)
        _run(conn, ids, engine=FakeEngine())
        payload = captured["similar_functions"]
        assert payload["count"] == 1
        assert payload["scored"] is False
        assert payload["candidates"][0]["name"] == "DoThing"
        assert payload["candidates"][0]["similarity"] == 88.0

    def test_search_functionality_reports_scoring_availability(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        captured: dict[str, Any] = {}
        components.register_component(spy("similar-spy", {"similar_functions"}, captured))
        monkeypatch.setattr(similarity, "available", lambda: True)
        _run(conn, ids, engine=FakeEngine())
        assert captured["similar_functions"]["scored"] is True

    def test_resolve_names_prefers_an_unstrip_proposal(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        store.record_match(
            conn,
            function_id=ids["function"],
            candidate_function_id=ids["second"],
            similarity=99.0,
            confidence=0.9,
        )
        seed_unstrip_proposal(conn, analysis_id=ids["analysis"], function_id=ids["function"])
        captured: dict[str, Any] = {}
        components.register_component(spy("name-spy", {"predicted_name"}, captured))
        _run(conn, ids, engine=FakeEngine())
        predicted = captured["predicted_name"]
        assert predicted["name"] == "ChooseFontW"
        assert predicted["source"] == pipeline.PREDICTED_NAME_SOURCE_UNSTRIP
        assert predicted["confidence"] == 0.3
        assert predicted["evidence"]["module"] == "COMDLG32"

    def test_resolve_names_falls_back_to_a_match_candidate(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        store.record_match(
            conn,
            function_id=ids["function"],
            candidate_function_id=ids["second"],
            similarity=91.5,
            confidence=0.8,
        )
        captured: dict[str, Any] = {}
        components.register_component(spy("name-spy", {"predicted_name"}, captured))
        _run(conn, ids, engine=FakeEngine())
        predicted = captured["predicted_name"]
        assert predicted["name"] == "DoThing"
        assert predicted["source"] == pipeline.PREDICTED_NAME_SOURCE_MATCH
        assert predicted["evidence"]["similarity"] == 91.5

    def test_resolve_names_without_evidence_predicts_nothing(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        captured: dict[str, Any] = {}
        components.register_component(spy("name-spy", {"predicted_name"}, captured))
        _run(conn, ids, engine=FakeEngine())
        assert captured["predicted_name"]["name"] is None
        assert captured["predicted_name"]["confidence"] == 0.0

    def test_name_variables_provides_comments_and_types(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        captured: dict[str, Any] = {}
        components.register_component(
            spy("variables-spy", {"inline_comments", "type_suggestions"}, captured)
        )
        _run(conn, ids, engine=FakeEngine(), llm_client=ScriptedLlmClient())
        assert captured["inline_comments"]["comments"][0]["comment"] == "open the target file"
        assert captured["type_suggestions"]["suggestions"][0]["type"] == "const char *"

    def test_summarize_provides_the_summary(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        captured: dict[str, Any] = {}
        components.register_component(spy("summary-spy", {"summary"}, captured))
        _run(conn, ids, engine=FakeEngine(), llm_client=ScriptedLlmClient())
        assert captured["summary"] == json.loads(AI_SUMMARY_RESPONSE)

    def test_llm_error_fails_the_step_with_its_reason(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        run = _run(conn, ids, engine=FakeEngine(), llm_client=FailingLlmClient("model exploded"))
        steps = _steps(run)
        assert steps["name-variables"]["status"] == pipeline.STEP_FAILED
        assert steps["name-variables"]["reason"].startswith("llm-error: ")
        assert steps["summarize"]["status"] == pipeline.STEP_FAILED
        assert run["status"] == pipeline.RUN_FAILED

    def test_store_persists_the_ai_artifacts(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        seed_unstrip_proposal(conn, analysis_id=ids["analysis"], function_id=ids["function"])
        _run(conn, ids, engine=FakeEngine(), llm_client=ScriptedLlmClient())
        function_id = ids["function"]
        summary = store.get_ai_artifact(conn, function_id, llm.AI_KIND_SUMMARY)
        comments = store.get_ai_artifact(conn, function_id, llm.AI_KIND_COMMENTS)
        types = store.get_ai_artifact(conn, function_id, llm.AI_KIND_TYPES)
        predicted = store.get_ai_artifact(conn, function_id, pipeline.PREDICTED_NAME_KIND)
        assert summary is not None and summary["model"] == "scripted-model"
        assert summary["payload"] == json.loads(AI_SUMMARY_RESPONSE)
        assert comments is not None and len(comments["payload"]["comments"]) == 2
        assert types is not None and types["payload"]["suggestions"][0]["name"] == "path"
        assert predicted is not None and predicted["payload"]["name"] == "ChooseFontW"

    def test_store_skips_a_predicted_name_it_did_not_resolve(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        _run(conn, ids, engine=FakeEngine(), llm_client=ScriptedLlmClient())
        assert store.get_ai_artifact(conn, ids["function"], pipeline.PREDICTED_NAME_KIND) is None


class _EmptyRenameClient(ScriptedLlmClient):
    """A scripted client whose rename answer carries no usable suggestion."""

    def complete(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float = llm.DEFAULT_TEMPERATURE,
        json_object: bool = False,
        max_tokens: int = llm.MAX_COMPLETION_TOKENS,
    ) -> str:
        prompt = messages[-1]["content"] if messages else ""
        if "unclear identifiers" in prompt:
            self.calls.append(messages)
            return '{"suggestions": []}'
        return super().complete(
            messages, temperature=temperature, json_object=json_object, max_tokens=max_tokens
        )


class TestEnrichChain:
    """The composed chain: rewrite, then rename, then summarize the renamed text."""

    def test_the_chain_renames_the_stored_text_and_the_store_stage_keeps_it(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The regression the store stage's guard exists for.

        `_persist_decompilation` holds the pre-rename text in the run's context.
        Comparing it against the stored row after the rename pass always reads
        as "changed", so without the guard the store stage would put the
        identifiers back and silently undo the whole rename.
        """
        ids = seed_portal(tmp_path, monkeypatch)
        run = _run(conn, ids, engine=FakeEngine(), llm_client=ScriptedLlmClient())
        assert _steps(run)["rename-variables"]["status"] == pipeline.STEP_DONE
        stored = store.get_decompilation(conn, ids["function"])
        assert stored is not None
        assert "read_file" in stored["code"]
        assert "sub_1000" not in stored["code"]
        assert run["artifacts"]["decompilation"]["code"] == stored["code"]
        # The rewrite the chain asked for is a stored artifact of its own.
        rewrite = store.get_ai_artifact(conn, ids["function"], ai_decomp.KIND)
        assert rewrite is not None
        assert rewrite["model"] == "scripted-model"
        assert "read_file" in run["artifacts"]["rewrite"]["rewritten_code"]

    def test_the_summary_reads_the_renamed_text(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        client = ScriptedLlmClient()
        _run(conn, ids, engine=FakeEngine(), llm_client=client)
        summary_prompts = [
            call[-1]["content"] for call in client.calls if "Summarize" in call[-1]["content"]
        ]
        assert summary_prompts, "the summary stage must have asked the model"
        assert "read_file" in summary_prompts[0]
        assert "sub_1000" not in summary_prompts[0]

    def test_the_naming_prompt_carries_the_workspace_names(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The evidence is the workspace's, not the model's: a real match name."""
        ids = seed_portal(tmp_path, monkeypatch)
        store.record_match(
            conn,
            function_id=ids["function"],
            candidate_function_id=ids["second"],
            similarity=91.5,
            confidence=0.8,
        )
        client = ScriptedLlmClient()
        _run(conn, ids, engine=FakeEngine(), llm_client=client)
        rename_prompts = [
            call[-1]["content"]
            for call in client.calls
            if "unclear identifiers" in call[-1]["content"]
        ]
        assert rename_prompts, "the rename stage must have asked the model"
        assert "Names this workspace already knows" in rename_prompts[0]
        assert "DoThing" in rename_prompts[0]
        # Both the resolved prediction and the recorded match reach the prompt:
        # the match list is a named block, not a bare list of rows.
        assert "DoThing (match at 91.50 similarity)" in rename_prompts[0]

    def test_the_naming_prompt_carries_the_symbol_names(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A debug symbol file is the one source of names nothing can derive."""
        ids = seed_portal(tmp_path, monkeypatch)
        store.set_decompilation(
            conn,
            ids["function"],
            "void sub_1000(void)\n{\n  count = DAT_0040a1c;\n  return;\n}\n",
            "kuna",
        )
        _ingest_symbols(
            conn,
            binary_id=ids["binary"],
            data=b"pipeline-symbol-file",
            parsed={
                "kind": "elf",
                "symbols": [
                    {"name": "read_file", "va": 0x1000, "kind": "function", "source": "elf"},
                    {"name": "g_count", "va": 0x40A1C, "kind": "object", "source": "elf"},
                ],
                "types": [],
            },
        )
        client = ScriptedLlmClient()
        _run(conn, ids, engine=FakeEngine(), llm_client=client)
        rename_prompts = [
            call[-1]["content"]
            for call in client.calls
            if "unclear identifiers" in call[-1]["content"]
        ]
        assert rename_prompts, "the rename stage must have asked the model"
        # The symbol at the function's own VA and the one behind the DAT_
        # placeholder in its code, so a global can be named too.
        assert "read_file (ingested symbols)" in rename_prompts[0]
        assert "g_count (ingested symbols at 0x40a1c)" in rename_prompts[0]

    def test_symbol_names_are_bounded_and_skip_an_unusable_index(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The block is bounded, and a symbol file with nothing usable adds none."""
        ids = seed_portal(tmp_path, monkeypatch)
        _ingest_symbols(
            conn,
            binary_id=ids["binary"],
            data=b"pipeline-unusable-symbols",
            parsed={
                "kind": "elf",
                "symbols": ["junk", {"name": "", "va": 0x1000}, {"name": "no-va", "va": None}],
                "types": [],
            },
        )
        function = store.get_function(conn, ids["function"])
        assert function is not None
        ctx = Context(
            {
                pipeline.SEED_CONN: conn,
                pipeline.SEED_FUNCTION: function,
                pipeline.NAME_DECOMPILATION: {"code": "void sub_1000(void) {}"},
            }
        )
        assert pipeline.symbol_names(ctx) == []
        # A caller with no run seeds at all gets no names rather than an error.
        assert pipeline.symbol_names(Context({})) == []

        _ingest_symbols(
            conn,
            binary_id=ids["binary"],
            data=b"pipeline-many-symbols",
            parsed={
                "kind": "elf",
                "symbols": [
                    {"name": f"g_{index}", "va": 0x4000 + index, "kind": "object", "source": "elf"}
                    for index in range(30)
                ],
                "types": [],
            },
        )
        code = (
            "void sub_1000(void)\n{\n"
            + "\n".join(f"  x = DAT_{0x4000 + i:x};" for i in range(30))
            + "\n}\n"
        )
        ctx.provide(pipeline.NAME_DECOMPILATION, {"code": code})
        names = pipeline.symbol_names(ctx)
        assert len(names) == pipeline.KNOWN_SYMBOL_LIMIT

        # The index cache is bounded, so a long-lived server cannot pin every
        # symbol file it ever ingested.
        for index in range(pipeline.MAX_SYMBOL_INDEXES + 1):
            pipeline._symbol_index(f"hash-{index}", {"symbols": []})
        assert len(pipeline._symbol_indexes) <= pipeline.MAX_SYMBOL_INDEXES

    def test_a_model_with_nothing_to_rename_does_not_cancel_the_chain(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No applicable suggestion is a pass-through, not a failed step.

        A whole-binary batch would otherwise report a failure for every function
        whose identifiers the model left alone, and the stages after the rename
        pass would be skipped with the text they need already bound.
        """
        ids = seed_portal(tmp_path, monkeypatch)
        run = _run(conn, ids, engine=FakeEngine(), llm_client=_EmptyRenameClient())
        steps = _steps(run)
        assert steps["rename-variables"]["status"] == pipeline.STEP_DONE
        assert steps["summarize"]["status"] == pipeline.STEP_DONE
        assert run["status"] == pipeline.RUN_DONE
        stored = store.get_decompilation(conn, ids["function"])
        assert stored is not None and "sub_1000" in stored["code"]


class TestBatch:
    """The whole-binary form: one composition per function, one run each."""

    def _seed(self, conn: sqlite3.Connection, ids: dict[str, Any]) -> list[int]:
        """Three extra functions of distinct sizes, largest last."""
        return [
            store.add_function(
                conn,
                analysis_id=ids["analysis"],
                va=0x3000 + index * 0x10,
                name=f"extra_{index}",
                size=size,
            )
            for index, size in enumerate((0x40, 0x80, 0x20))
        ]

    def test_the_batch_takes_the_largest_functions_by_default(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        extra = self._seed(conn, ids)
        payload = pipeline.run_pipeline_batch(
            conn,
            binary_id=ids["binary"],
            limit=2,
            engine=FakeEngine(),
            llm_client=ScriptedLlmClient(),
        )
        assert payload["total"] == 2
        # The seeded sub_1000 is 0x20 and extra_0 is 0x40, extra_1 0x80, so the
        # two largest are the ones a model call returns something for.
        assert [row["function_id"] for row in payload["runs"]] == [extra[1], extra[0]]
        assert payload["done"] == 2
        assert payload["failed"] == 0

    def test_named_function_ids_are_run_whatever_their_size(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        payload = pipeline.run_pipeline_batch(
            conn,
            binary_id=ids["binary"],
            function_ids=[ids["second"]],
            engine=FakeEngine(),
            llm_client=ScriptedLlmClient(),
        )
        assert [row["function_id"] for row in payload["runs"]] == [ids["second"]]
        assert payload["total"] == 1
        assert store.get_pipeline_run(conn, int(payload["runs"][0]["run_id"])) is not None

    def test_each_function_gets_its_own_run_and_the_progress_sink_sees_each_one(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        seen: list[tuple[int, int]] = []
        payload = pipeline.run_pipeline_batch(
            conn,
            binary_id=ids["binary"],
            function_ids=[ids["function"], ids["second"]],
            engine=FakeEngine(),
            llm_client=ScriptedLlmClient(),
            progress=lambda done, total: seen.append((done, total)),
        )
        assert seen == [(1, 2), (2, 2)]
        assert len({row["run_id"] for row in payload["runs"]}) == 2
        # One run per function is what makes one function's artifacts separately
        # revertible; a batch sharing a run would be all-or-nothing.
        assert store.latest_pipeline_run(conn, ids["function"]) is not None
        assert store.latest_pipeline_run(conn, ids["second"]) is not None

    def test_one_function_failing_leaves_the_others_run(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        real = pipeline.run_pipeline

        def flaky(conn: sqlite3.Connection, *, function_id: int, **kwargs: Any) -> dict[str, Any]:
            if function_id == ids["function"]:
                raise KeyError(f"no function with id {function_id}")
            return real(conn, function_id=function_id, **kwargs)

        monkeypatch.setattr(pipeline, "run_pipeline", flaky)
        payload = pipeline.run_pipeline_batch(
            conn,
            binary_id=ids["binary"],
            function_ids=[ids["function"], ids["second"]],
            engine=FakeEngine(),
            llm_client=ScriptedLlmClient(),
        )
        assert payload["failed"] == 1
        assert payload["done"] == 1
        assert payload["runs"][0]["status"] == pipeline.RUN_FAILED
        assert payload["runs"][0]["error"]
        assert payload["runs"][1]["function_id"] == ids["second"]

    def test_an_out_of_range_limit_is_refused(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        for limit in (0, pipeline.MAX_BATCH_LIMIT + 1):
            with pytest.raises(ValueError):
                pipeline.run_pipeline_batch(conn, binary_id=ids["binary"], limit=limit)

    def test_an_unknown_function_id_is_refused_before_any_run(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        with pytest.raises(KeyError):
            pipeline.run_pipeline_batch(conn, binary_id=ids["binary"], function_ids=[4242])

    def test_a_binary_with_no_functions_is_an_empty_batch(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        other = store.add_binary(conn, sha256="ef" * 32, name="empty.exe", path="/nonexistent")
        payload = pipeline.run_pipeline_batch(conn, binary_id=other)
        assert payload == {"binary_id": other, "runs": [], "done": 0, "failed": 0, "total": 0}
        assert ids["binary"] != other


class TestRevert:
    def test_a_finished_run_leaves_no_subscriber_on_its_context(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The loader's subscription is undone when the run ends.

        A revert notifies the context's subscribers, and a run's context outlives
        the run in ``_run_contexts``; a watcher still attached would re-decide a
        composition whose run is over.
        """
        ids = seed_portal(tmp_path, monkeypatch)
        run = _run(conn, ids, engine=FakeEngine(), llm_client=ScriptedLlmClient())
        ctx = pipeline._run_contexts[int(run["id"])]
        assert ctx._subscribers == []

    def test_revert_removes_the_artifacts_the_run_stored(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        run = _run(conn, ids, engine=FakeEngine(), llm_client=ScriptedLlmClient())
        function_id = ids["function"]
        assert store.get_decompilation(conn, function_id) is not None
        assert store.get_disasm(conn, function_id) is not None
        assert store.get_ai_artifact(conn, function_id, llm.AI_KIND_SUMMARY) is not None
        result = pipeline.revert_run(conn, int(run["id"]))
        assert result["run_id"] == run["id"]
        assert all(entry["status"] == pipeline.EFFECT_REVERTED for entry in result["reverted"])
        assert store.get_decompilation(conn, function_id) is None
        assert store.get_disasm(conn, function_id) is None
        assert store.get_ai_artifact(conn, function_id, llm.AI_KIND_SUMMARY) is None
        assert store.get_ai_artifact(conn, function_id, pipeline.PREDICTED_NAME_KIND) is None

    def test_revert_restores_a_previous_artifact(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        function_id = ids["function"]
        store.set_decompilation(conn, function_id, "int old(void);\n", "r2dec")
        old_summary = {"summary": "an earlier summary"}
        store.set_ai_artifact(conn, function_id, llm.AI_KIND_SUMMARY, old_summary, "old-model")
        run = _run(conn, ids, engine=FakeEngine(), llm_client=ScriptedLlmClient())
        pipeline.revert_run(conn, int(run["id"]))
        restored = store.get_decompilation(conn, function_id)
        assert restored is not None and restored["code"] == "int old(void);\n"
        assert restored["backend"] == "r2dec"
        stored_summary = store.get_ai_artifact(conn, function_id, llm.AI_KIND_SUMMARY)
        assert stored_summary is not None
        assert stored_summary["payload"] == old_summary
        assert stored_summary["model"] == "old-model"

    def test_revert_consumes_the_undo_plan(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        run = _run(conn, ids, engine=FakeEngine(), llm_client=ScriptedLlmClient())
        first = pipeline.revert_run(conn, int(run["id"]))
        assert first["reverted"]
        second = pipeline.revert_run(conn, int(run["id"]))
        assert second["reverted"] == []
        assert cast(dict[str, Any], store.get_pipeline_run(conn, int(run["id"])))["effects"] == []

    def test_revert_unknown_run_raises(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(KeyError):
            pipeline.revert_run(conn, 4242)

    def test_revert_walks_the_stored_plan_newest_first(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        run = _run(conn, ids, engine=FakeEngine(), llm_client=ScriptedLlmClient())
        durable = [
            item for item in run["effects"] if item["kind"] != pipeline.EFFECT_CONTEXT_CHANGE
        ]
        result = pipeline.revert_run(conn, int(run["id"]))
        assert [entry["description"] for entry in result["reverted"]] == [
            effects.describe(descriptor) for descriptor in reversed(durable)
        ]

    def test_revert_entries_carry_their_descriptor_kind(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        run = _run(conn, ids, engine=FakeEngine(), llm_client=ScriptedLlmClient())
        result = pipeline.revert_run(conn, int(run["id"]))
        kinds = {entry["kind"] for entry in result["reverted"]}
        assert pipeline.EFFECT_AI_ARTIFACT in kinds
        assert result["applied"] == len(result["reverted"])
        assert result["failed"] == 0

    def test_revert_reports_the_context_changes_the_run_made(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        run = _run(conn, ids, engine=FakeEngine(), llm_client=ScriptedLlmClient())
        result = pipeline.revert_run(conn, int(run["id"]))
        assert result["context_changes"], "the run provided bindings"
        assert all(change["applied"] for change in result["context_changes"])
        names = {change["name"] for change in result["context_changes"]}
        assert {"disassembly", "decompilation"} <= names
        assert any(change["change"] == "provide" for change in result["context_changes"])

    def test_revert_reports_bindings_a_later_process_cannot_apply(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        run = _run(conn, ids, engine=FakeEngine(), llm_client=ScriptedLlmClient())
        # A run stored before the change has no binding descriptors; one stored
        # now is replayed by whatever process reads it, which may not be the one
        # that made the bindings.
        pipeline.reset_live_state()
        result = pipeline.revert_run(conn, int(run["id"]))
        assert result["context_changes"]
        assert all(change["applied"] is False for change in result["context_changes"])
        assert all(change["detail"] for change in result["context_changes"])

    def test_revert_of_a_legacy_plan_reports_no_context_changes(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        run_id = store.create_pipeline_run(conn, function_id=ids["function"], model="m")
        store.finish_pipeline_run(
            conn,
            run_id,
            status=store.PIPELINE_RUN_DONE,
            effects=[{"kind": pipeline.EFFECT_DISASM, "function_id": ids["function"]}],
        )
        result = pipeline.revert_run(conn, run_id)
        assert result["context_changes"] == []
        assert [entry["kind"] for entry in result["reverted"]] == [pipeline.EFFECT_DISASM]

    def test_revert_payload_stays_json_serializable(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        run = _run(conn, ids, engine=FakeEngine(), llm_client=ScriptedLlmClient())
        result = pipeline.revert_run(conn, int(run["id"]))
        assert json.loads(json.dumps(result)) == result

    def test_the_stored_plan_records_the_bindings_the_run_made(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        run = _run(conn, ids, engine=FakeEngine())
        changes = [
            item for item in run["effects"] if item["kind"] == pipeline.EFFECT_CONTEXT_CHANGE
        ]
        assert {
            "kind": pipeline.EFFECT_CONTEXT_CHANGE,
            "change": "provide",
            "name": "disassembly",
        } in changes


class TestRunStore:
    def test_run_and_step_crud(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        run_id = store.create_pipeline_run(conn, function_id=ids["function"], model="m")
        created = store.get_pipeline_run(conn, run_id)
        assert created is not None
        assert created["status"] == store.PIPELINE_RUN_RUNNING
        assert created["finished_at"] is None
        assert created["steps"] == []
        store.add_pipeline_step(
            conn,
            run_id=run_id,
            name="prepare",
            status=store.PIPELINE_STEP_DONE,
            duration_ms=7,
            provides=["function_meta", "disassembly"],
        )
        store.add_pipeline_step(
            conn, run_id=run_id, name="store", status=store.PIPELINE_STEP_SKIPPED, reason="disabled"
        )
        done = store.finish_pipeline_run(
            conn,
            run_id,
            status=store.PIPELINE_RUN_DONE,
            effects=[{"kind": pipeline.EFFECT_DISASM, "function_id": ids["function"]}],
        )
        assert done
        run = store.get_pipeline_run(conn, run_id)
        assert run is not None
        assert run["finished_at"]
        assert run["effects"] == [{"kind": pipeline.EFFECT_DISASM, "function_id": ids["function"]}]
        assert [step["name"] for step in run["steps"]] == ["prepare", "store"]
        assert run["steps"][0]["provides"] == ["function_meta", "disassembly"]
        assert run["steps"][1]["reason"] == "disabled"
        assert (
            cast(dict[str, Any], store.latest_pipeline_run(conn, ids["function"]))["id"] == run_id
        )
        assert store.set_pipeline_effects(conn, run_id, [])
        assert cast(dict[str, Any], store.get_pipeline_run(conn, run_id))["effects"] == []
        assert store.delete_pipeline_run(conn, run_id)
        assert store.get_pipeline_run(conn, run_id) is None
        assert store.list_pipeline_steps(conn, run_id) == []

    def test_latest_run_is_the_newest(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        first = store.create_pipeline_run(conn, function_id=ids["function"])
        second = store.create_pipeline_run(conn, function_id=ids["function"])
        latest = store.latest_pipeline_run(conn, ids["function"])
        assert latest is not None and latest["id"] == second
        assert store.latest_pipeline_run(conn, ids["second"]) is None
        assert cast(dict[str, Any], store.get_pipeline_run(conn, first))["id"] == first

    def test_run_creation_stamps_started_and_created(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        run_id = store.create_pipeline_run(conn, function_id=ids["function"])
        run = store.get_pipeline_run(conn, run_id)
        assert run is not None and run["started_at"] and run["created_at"]


class TestConfiguredDisabled:
    def test_absent_table_is_empty(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seed_portal(tmp_path, monkeypatch)
        (tmp_path / "reportal.toml").write_text("[portal]\ndb = 'x'\n", encoding="utf-8")
        monkeypatch.setattr(pipeline, "project_root", lambda: tmp_path)
        assert pipeline.configured_disabled() == frozenset()

    def test_outside_a_workspace_is_empty(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seed_portal(tmp_path, monkeypatch)
        monkeypatch.setattr(pipeline, "project_root", lambda: tmp_path / "nowhere")
        assert pipeline.configured_disabled() == frozenset()

    def test_a_non_list_value_is_ignored(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seed_portal(tmp_path, monkeypatch)
        (tmp_path / "reportal.toml").write_text(
            '[pipeline]\ndisabled = "prepare"\n', encoding="utf-8"
        )
        monkeypatch.setattr(pipeline, "project_root", lambda: tmp_path)
        assert pipeline.configured_disabled() == frozenset()

    def test_an_unreadable_config_logs_before_falling_back(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        seed_portal(tmp_path, monkeypatch)
        (tmp_path / "reportal.toml").write_text("this is not [toml\n", encoding="utf-8")
        monkeypatch.setattr(pipeline, "project_root", lambda: tmp_path)
        with caplog.at_level("WARNING", logger="reportal.pipeline"):
            assert pipeline.configured_disabled() == frozenset()
        assert any(
            "disabled components fall back to none" in record.message for record in caplog.records
        )


def _provider(name: str, *, requires: set[str] | None = None, provides: set[str]) -> Component:
    """A component whose effect binds every name it provides."""

    def effect(ctx: Context) -> None:
        for provided in sorted(provides):
            ctx.provide(provided, name)

    return Component(name, frozenset(requires or ()), frozenset(provides), effect)


def _chain() -> tuple[Component, Component, Component]:
    """A provider, a consumer of its output and a consumer of the consumer."""
    return (
        _provider("alpha", provides={"alpha-out"}),
        _provider("beta", requires={"alpha-out"}, provides={"beta-out"}),
        _provider("gamma", requires={"beta-out"}, provides=set()),
    )


class TestComponentHost:
    def test_activate_runs_the_component_and_records_it(self) -> None:
        host = pipeline.ComponentHost({}, registered=[_chain()[0]])
        payload = host.activate("alpha")
        assert [entry["name"] for entry in payload["activated"]] == ["alpha"]
        assert payload["activated"][0]["status"] == pipeline.STEP_DONE
        assert payload["skipped"] == []
        assert host.active() == ("alpha",)
        assert host.decisions() == {"alpha": pipeline.STEP_DONE}
        assert host.journal()[-1]["name"] == "alpha"

    def test_activate_is_idempotent(self) -> None:
        host = pipeline.ComponentHost({}, registered=[_chain()[0]])
        host.activate("alpha")
        payload = host.activate("alpha")
        assert payload["activated"] == []
        assert host.active() == ("alpha",)

    def test_activate_runs_dependents_in_dependency_order(self) -> None:
        host = pipeline.ComponentHost({}, registered=list(_chain()))
        payload = host.activate("alpha")
        assert [entry["name"] for entry in payload["activated"]] == ["alpha", "beta", "gamma"]
        assert host.active() == ("alpha", "beta", "gamma")

    def test_activate_skips_a_dependent_with_a_missing_requirement(self) -> None:
        alpha = _provider("alpha", provides={"alpha-out"})
        beta = _provider("beta", requires={"alpha-out", "seed"}, provides={"beta-out"})
        gamma = _provider("gamma", requires={"beta-out"}, provides=set())
        host = pipeline.ComponentHost({}, registered=[alpha, beta, gamma])
        payload = host.activate("alpha")
        assert [entry["name"] for entry in payload["activated"]] == ["alpha"]
        reasons = {entry["name"]: entry["reason"] for entry in payload["skipped"]}
        assert reasons == {"beta": "requires-seed", "gamma": "dependency-skipped:beta"}
        assert host.active() == ("alpha",)

    def test_activate_reports_a_disabled_component(self) -> None:
        host = pipeline.ComponentHost({}, registered=[_chain()[0]], disabled=frozenset({"alpha"}))
        payload = host.activate("alpha")
        assert payload["activated"] == []
        assert payload["skipped"] == [
            {"name": "alpha", "status": pipeline.STEP_SKIPPED, "reason": pipeline.REASON_DISABLED}
        ]

    def test_activate_records_a_failed_effect_and_calls_revert(self) -> None:
        reverted: list[str] = []

        def boom(ctx: Context) -> None:
            raise RuntimeError("effect exploded")

        alpha = Component(
            "alpha",
            frozenset(),
            frozenset({"alpha-out"}),
            boom,
            revert=lambda ctx: reverted.append("alpha"),
        )
        host = pipeline.ComponentHost({}, registered=[alpha])
        payload = host.activate("alpha")
        assert payload["activated"][0]["status"] == pipeline.STEP_FAILED
        assert "effect exploded" in payload["activated"][0]["reason"]
        assert reverted == ["alpha"]
        assert host.active() == ()

    def test_deactivate_calls_revert_and_records_the_decision(self) -> None:
        calls: list[str] = []
        alpha = Component(
            "alpha",
            frozenset(),
            frozenset({"alpha-out"}),
            lambda ctx: ctx.provide("alpha-out", 1),
            revert=lambda ctx: calls.append("alpha"),
        )
        host = pipeline.ComponentHost({}, registered=[alpha])
        host.activate("alpha")
        payload = host.deactivate("alpha")
        assert calls == ["alpha"]
        assert payload["deactivated"] == [
            {
                "name": "alpha",
                "status": pipeline.STEP_DEACTIVATED,
                "reason": pipeline.REASON_WITHDRAWN,
                "reverted": True,
                "detail": "",
            }
        ]
        assert payload["context_changes"] == ["alpha-out"]
        assert host.active() == ()
        assert not host.context.has("alpha-out")
        assert host.decisions() == {"alpha": pipeline.STEP_DEACTIVATED}

    def test_deactivate_withdraws_dependents_first(self) -> None:
        order: list[str] = []

        def revert(name: str) -> Callable[[Context], None]:
            def run(ctx: Context) -> None:
                order.append(name)

            return run

        alpha = Component(
            "alpha",
            frozenset(),
            frozenset({"alpha-out"}),
            lambda ctx: ctx.provide("alpha-out", 1),
            revert=revert("alpha"),
        )
        beta = Component(
            "beta",
            frozenset({"alpha-out"}),
            frozenset({"beta-out"}),
            lambda ctx: ctx.provide("beta-out", 2),
            revert=revert("beta"),
        )
        gamma = Component(
            "gamma",
            frozenset({"beta-out"}),
            frozenset(),
            lambda ctx: None,
            revert=revert("gamma"),
        )
        host = pipeline.ComponentHost({}, registered=[alpha, beta, gamma])
        host.activate("alpha")
        payload = host.deactivate("alpha")
        assert order == ["gamma", "beta", "alpha"]
        assert [entry["name"] for entry in payload["deactivated"]] == ["gamma", "beta", "alpha"]
        assert host.active() == ()
        assert not host.context.has("alpha-out")
        assert not host.context.has("beta-out")

    def test_deactivate_records_a_failing_revert_and_still_withdraws(self) -> None:
        def boom(ctx: Context) -> None:
            raise RuntimeError("cannot undo")

        alpha = Component(
            "alpha",
            frozenset(),
            frozenset({"alpha-out"}),
            lambda ctx: ctx.provide("alpha-out", 1),
            revert=boom,
        )
        host = pipeline.ComponentHost({}, registered=[alpha])
        host.activate("alpha")
        entry = host.deactivate("alpha")["deactivated"][0]
        assert entry["reverted"] is False
        assert "cannot undo" in entry["detail"]
        assert host.active() == ()

    def test_deactivate_withdraws_a_component_the_host_never_activated(self) -> None:
        host = pipeline.ComponentHost({}, registered=[_chain()[0]])
        payload = host.deactivate("alpha")
        assert [entry["name"] for entry in payload["deactivated"]] == ["alpha"]
        assert payload["deactivated"][0]["reverted"] is None
        assert payload["deactivated"][0]["reason"] == pipeline.REASON_WITHDRAWN
        assert payload["context_changes"] == []
        assert payload["active"] == []
        assert host.decisions() == {"alpha": pipeline.STEP_DEACTIVATED}

    def test_deactivate_refuses_a_second_withdrawal(self) -> None:
        host = pipeline.ComponentHost({}, registered=[_chain()[0]])
        host.deactivate("alpha")
        with pytest.raises(pipeline.NotWithdrawableError) as excinfo:
            host.deactivate("alpha")
        assert excinfo.value.name == "alpha"
        assert excinfo.value.reason == pipeline.REASON_ALREADY_WITHDRAWN

    def test_deactivate_refuses_a_component_with_nothing_to_withdraw(self) -> None:
        host = pipeline.ComponentHost({}, registered=[_component("bare")])
        with pytest.raises(pipeline.NotWithdrawableError) as excinfo:
            host.deactivate("bare")
        assert excinfo.value.reason == pipeline.REASON_NOTHING_TO_WITHDRAW

    def test_unknown_names_raise_key_error(self) -> None:
        host = pipeline.ComponentHost({}, registered=[_chain()[0]])
        with pytest.raises(KeyError):
            host.activate("absent")
        with pytest.raises(KeyError):
            host.deactivate("absent")

    def test_sync_picks_up_a_new_registration(self) -> None:
        host = pipeline.ComponentHost({}, registered=[])
        assert host.registered() == ()
        components.register_component(
            _component("late", provides={"late-out"}, effect=lambda ctx: ctx.provide("late-out", 1))
        )
        names = [component.name for component in host.sync()]
        assert "late" in names
        assert pipeline.COMPONENT_PREPARE in names
        assert host.activate("late")["activated"][0]["status"] == pipeline.STEP_DONE

    def test_deactivate_then_activate_runs_a_swapped_implementation(self) -> None:
        seen: list[str] = []

        def first(ctx: Context) -> None:
            seen.append("first")
            ctx.provide("value", "first")

        def second(ctx: Context) -> None:
            seen.append("second")
            ctx.provide("value", "second")

        components.register_component(_component("alpha", provides={"value"}, effect=first))
        host = pipeline.ComponentHost({}, registered=components.components())
        host.activate("alpha")
        assert host.context.require("value") == "first"

        components.refresh_components()
        components.register_component(_component("alpha", provides={"value"}, effect=second))
        host.sync()
        host.deactivate("alpha")
        host.activate("alpha")
        assert host.context.require("value") == "second"
        assert seen == ["first", "second"]


def _scratch_component() -> Component:
    """A component whose revert deletes a row and journals how to put it back."""

    def effect(ctx: Context) -> None:
        ctx.provide("scratch-out", 1)

    def revert(ctx: Context) -> None:
        conn = ctx.require("conn")
        conn.execute("DELETE FROM scratch WHERE id = 1")
        conn.commit()
        descriptor = journal.row_restore_descriptor("scratch", [{"id": 1, "value": "kept"}])
        ctx.record(
            "deleted scratch row 1",
            lambda: effects.apply_descriptor(conn, descriptor),
            descriptor,
        )

    return Component("scratch", frozenset(), frozenset({"scratch-out"}), effect, revert)


class TestWithdrawComponent:
    def _seed_component(self, conn: sqlite3.Connection) -> None:
        conn.execute("CREATE TABLE IF NOT EXISTS scratch (id INTEGER PRIMARY KEY, value TEXT)")
        conn.execute("DELETE FROM scratch")
        conn.execute("INSERT INTO scratch (id, value) VALUES (1, 'kept')")
        conn.commit()

    def test_withdrawal_runs_revert_revokes_names_and_journals(
        self, conn: sqlite3.Connection
    ) -> None:
        self._seed_component(conn)
        components.register_component(_scratch_component())
        host = pipeline.live_host()
        host.activate("scratch")
        assert host.context.has("scratch-out")

        payload = pipeline.withdraw_component(conn, "scratch")
        assert payload["name"] == "scratch"
        assert [entry["name"] for entry in payload["deactivated"]] == ["scratch"]
        assert payload["deactivated"][0]["reverted"] is True
        assert payload["context_changes"] == ["scratch-out"]
        assert payload["journaled"] is True
        assert conn.execute("SELECT COUNT(*) FROM scratch").fetchone()[0] == 0

        action = str(payload["journal_action"])
        assert journal.revert_action(conn, action)["reverted"] == 1
        assert conn.execute("SELECT COUNT(*) FROM scratch").fetchone()[0] == 1

    def test_a_binding_only_withdrawal_is_not_journaled(self, conn: sqlite3.Connection) -> None:
        components.register_component(_component("pure", provides={"pure-out"}))
        pipeline.live_host().activate("pure")
        payload = pipeline.withdraw_component(conn, "pure")
        assert payload["journaled"] is False
        assert "journal_action" not in payload

    def test_withdrawal_twice_is_refused(self, conn: sqlite3.Connection) -> None:
        components.register_component(_component("pure", provides={"pure-out"}))
        pipeline.withdraw_component(conn, "pure")
        with pytest.raises(pipeline.NotWithdrawableError) as excinfo:
            pipeline.withdraw_component(conn, "pure")
        assert excinfo.value.reason == pipeline.REASON_ALREADY_WITHDRAWN

    def test_withdrawal_of_an_unknown_component_raises(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(KeyError):
            pipeline.withdraw_component(conn, "no-such-component")

    def test_withdrawal_of_a_component_with_nothing_to_withdraw_is_refused(
        self, conn: sqlite3.Connection
    ) -> None:
        components.register_component(_component("bare"))
        with pytest.raises(pipeline.NotWithdrawableError) as excinfo:
            pipeline.withdraw_component(conn, "bare")
        assert excinfo.value.reason == pipeline.REASON_NOTHING_TO_WITHDRAW
