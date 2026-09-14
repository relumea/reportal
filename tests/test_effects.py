"""Tests for the shared undo dispatcher: one inverse per descriptor kind."""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from pipeline_helpers import seed_portal

from reportal import auto_store, effects, plugins, store
from reportal.components import EFFECT_FAILED, EFFECT_REVERTED


class _EntryPoint:
    """Minimal stand-in for importlib.metadata.EntryPoint."""

    def __init__(self, name: str, value: str) -> None:
        self.name = name
        self.value = value


class _EntryPoints:
    """Minimal stand-in for the EntryPoints collection."""

    def __init__(self, entries: list[_EntryPoint]) -> None:
        self._entries = entries

    def select(self, *, group: str) -> list[_EntryPoint]:
        return list(self._entries)


def _patch_entry_points(monkeypatch: pytest.MonkeyPatch, *entries: _EntryPoint) -> None:
    monkeypatch.setattr(plugins, "entry_points", lambda: _EntryPoints(list(entries)))


@pytest.fixture(autouse=True)
def _isolate_effect_handlers() -> Iterator[None]:
    """Reload the registry around each test, whatever a test registered."""
    effects.refresh_effect_handlers()
    yield
    effects.refresh_effect_handlers()


class TestApplyDescriptor:
    def test_disasm_inverse_drops_the_cache(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        store.set_disasm(conn, ids["function"], "listing")
        entry = effects.apply_descriptor(
            conn, {"kind": effects.EFFECT_DISASM, "function_id": ids["function"]}
        )
        assert store.get_disasm(conn, ids["function"]) is None
        assert entry["status"] == EFFECT_REVERTED
        assert entry["function_id"] == ids["function"]

    def test_decompilation_inverse_restores_the_previous_one(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        store.set_decompilation(conn, ids["function"], "int new(void);\n", "kuna")
        effects.apply_descriptor(
            conn,
            {
                "kind": effects.EFFECT_DECOMPILATION,
                "function_id": ids["function"],
                "previous": {"code": "int old(void);\n", "backend": "r2dec"},
            },
        )
        restored = store.get_decompilation(conn, ids["function"])
        assert restored is not None
        assert restored["code"] == "int old(void);\n"
        assert restored["backend"] == "r2dec"

    def test_decompilation_inverse_clears_without_a_previous_one(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        store.set_decompilation(conn, ids["function"], "int new(void);\n", "kuna")
        effects.apply_descriptor(
            conn,
            {
                "kind": effects.EFFECT_DECOMPILATION,
                "function_id": ids["function"],
                "previous": None,
            },
        )
        assert store.get_decompilation(conn, ids["function"]) is None

    def test_ai_artifact_inverse_restores_the_previous_payload(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        store.set_ai_artifact(conn, ids["function"], "summary", {"summary": "new"}, "new-model")
        effects.apply_descriptor(
            conn,
            {
                "kind": effects.EFFECT_AI_ARTIFACT,
                "function_id": ids["function"],
                "artifact_kind": "summary",
                "previous": {"payload": {"summary": "old"}, "model": "old-model"},
            },
        )
        restored = store.get_ai_artifact(conn, ids["function"], "summary")
        assert restored is not None
        assert restored["payload"] == {"summary": "old"}
        assert restored["model"] == "old-model"

    def test_file_write_inverse_removes_the_file(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        written = tmp_path / "Written.c"
        written.write_text("void f(void) {}\n", encoding="utf-8")
        entry = effects.apply_descriptor(
            conn, {"kind": effects.EFFECT_FILE_WRITE, "path": str(written)}
        )
        assert not written.exists()
        assert entry == {"path": str(written), "status": "removed"}

    def test_file_write_inverse_reports_a_missing_file(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        absent = tmp_path / "Absent.c"
        entry = effects.apply_descriptor(
            conn, {"kind": effects.EFFECT_FILE_WRITE, "path": str(absent)}
        )
        assert entry == {"path": str(absent), "status": "missing"}

    def test_the_written_file_descriptor_carries_its_digest(self, tmp_path: Path) -> None:
        written = tmp_path / "Written.c"
        written.write_text("void f(void) {}\n", encoding="utf-8")

        descriptor = effects.file_write_descriptor(written)

        assert descriptor["kind"] == effects.EFFECT_FILE_WRITE
        assert descriptor["path"] == str(written)
        assert descriptor["sha256"] == effects.file_digest(written)
        # A path that cannot be read claims no bytes rather than inventing them.
        assert "sha256" not in effects.file_write_descriptor(tmp_path / "absent.c")

    def test_a_verified_descriptor_removes_the_file_it_wrote(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        written = tmp_path / "Written.c"
        written.write_text("void f(void) {}\n", encoding="utf-8")

        entry = effects.apply_descriptor(conn, effects.file_write_descriptor(written))

        assert not written.exists()
        assert entry == {"path": str(written), "status": effects.EFFECT_REMOVED}

    def test_the_inverse_refuses_a_path_another_writer_replaced(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        written = tmp_path / "Written.c"
        written.write_text("void f(void) {}\n", encoding="utf-8")
        descriptor = effects.file_write_descriptor(written)
        written.write_text("void g(void) {}\n", encoding="utf-8")

        entry = effects.apply_descriptor(conn, descriptor)

        assert written.exists()
        assert entry == {"path": str(written), "status": effects.EFFECT_DIVERGED}

    def test_a_descriptor_without_a_digest_still_removes_the_path(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        written = tmp_path / "Written.c"
        written.write_text("void f(void) {}\n", encoding="utf-8")

        # A plan persisted before the field existed claims no bytes, so a revert
        # keeps the behaviour it always had rather than refusing to act.
        entry = effects.apply_descriptor(
            conn, {"kind": effects.EFFECT_FILE_WRITE, "path": str(written)}
        )

        assert not written.exists()
        assert entry == {"path": str(written), "status": effects.EFFECT_REMOVED}

    def test_status_change_inverse_restores_the_status(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        auto_store.set_function_status(conn, ids["function"], "EXACT")
        entry = effects.apply_descriptor(
            conn,
            {
                "kind": effects.EFFECT_STATUS_CHANGE,
                "function_id": ids["function"],
                "before": "STUB",
            },
        )
        row = store.get_function(conn, ids["function"])
        assert row is not None and row["status"] == "STUB"
        assert entry == {"function_id": ids["function"], "status": "STUB"}

    def test_unknown_kind_raises(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(effects.UnknownEffectError, match="unknown effect kind"):
            effects.apply_descriptor(conn, {"kind": "no-such-kind", "function_id": 1})


class TestApplyUndoPlan:
    def test_replays_newest_first(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        plan: list[dict[str, Any]] = [
            {"kind": effects.EFFECT_DISASM, "function_id": ids["function"]},
            {
                "kind": effects.EFFECT_AI_ARTIFACT,
                "function_id": ids["function"],
                "artifact_kind": "summary",
                "previous": None,
            },
        ]
        undone = effects.apply_undo_plan(conn, plan)
        assert [entry["kind"] for entry in undone] == [
            effects.EFFECT_AI_ARTIFACT,
            effects.EFFECT_DISASM,
        ]

    def test_a_bad_descriptor_does_not_strand_the_rest(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        store.set_disasm(conn, ids["function"], "listing")
        plan: list[dict[str, Any]] = [
            {"kind": "no-such-kind", "function_id": ids["function"]},
            {"kind": effects.EFFECT_DISASM, "function_id": ids["function"]},
        ]
        undone = effects.apply_undo_plan(conn, plan)
        assert [entry["status"] for entry in undone] == [EFFECT_REVERTED, EFFECT_FAILED]
        assert store.get_disasm(conn, ids["function"]) is None


class TestPlanContext:
    def test_undo_plan_round_trips_the_descriptors(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        plan: list[dict[str, Any]] = [
            {"kind": effects.EFFECT_DISASM, "function_id": 1},
            {"kind": effects.EFFECT_FILE_WRITE, "path": str(tmp_path / "Written.c")},
        ]
        assert effects.plan_context(conn, plan).undo_plan() == plan

    def test_revert_walks_the_plan_newest_first(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        written = tmp_path / "Written.c"
        written.write_text("void f(void) {}\n", encoding="utf-8")
        store.set_disasm(conn, ids["function"], "listing")
        plan: list[dict[str, Any]] = [
            {"kind": effects.EFFECT_DISASM, "function_id": ids["function"]},
            {"kind": effects.EFFECT_FILE_WRITE, "path": str(written)},
        ]
        undone = effects.plan_context(conn, plan).revert()
        assert [entry["kind"] for entry in undone] == [
            effects.EFFECT_FILE_WRITE,
            effects.EFFECT_DISASM,
        ]
        assert not written.exists()
        assert store.get_disasm(conn, ids["function"]) is None


def _custom_handler(conn: sqlite3.Connection, descriptor: dict[str, Any]) -> dict[str, Any]:
    """A custom inverse the registry tests register directly."""
    return {"kind": str(descriptor.get("kind", "")), "custom": True}


class TestRegistry:
    def test_builtin_kinds_register_in_tree(self) -> None:
        assert set(effects.effect_handlers()) == {
            effects.EFFECT_DISASM,
            effects.EFFECT_DECOMPILATION,
            effects.EFFECT_AI_ARTIFACT,
            effects.EFFECT_FILE_WRITE,
            effects.EFFECT_STATUS_CHANGE,
            effects.EFFECT_ROW_RESTORE,
            effects.EFFECT_ROW_DELETE,
            effects.EFFECT_FILE_DELETE,
            effects.EFFECT_FILE_RESTORE,
            effects.EFFECT_CONTEXT_CHANGE,
        }

    def test_register_effect_handler_adds_it(self) -> None:
        effects.register_effect_handler("probe", _custom_handler)
        assert effects.effect_handlers()["probe"] is _custom_handler

    def test_duplicate_kind_raises_naming_both_origins(self) -> None:
        effects.register_effect_handler("probe", _custom_handler, origin="probe-plugin")
        with pytest.raises(effects.RegistryError) as excinfo:
            effects.register_effect_handler("probe", _custom_handler, origin="rival-plugin")
        message = str(excinfo.value)
        assert "probe" in message
        assert "probe-plugin" in message
        assert "rival-plugin" in message

    def test_registering_a_non_callable_handler_raises(self) -> None:
        with pytest.raises(effects.RegistryError):
            effects.register_effect_handler("probe", "nope")  # type: ignore[arg-type]

    def test_registering_an_empty_kind_raises(self) -> None:
        with pytest.raises(effects.RegistryError):
            effects.register_effect_handler("", _custom_handler)

    def test_registering_a_malformed_kind_raises(self) -> None:
        with pytest.raises(effects.RegistryError):
            effects.register_effect_handler("bad kind!", _custom_handler)

    def test_effect_handlers_returns_a_copy(self) -> None:
        handlers = effects.effect_handlers()
        handlers.clear()
        assert effects.EFFECT_DISASM in effects.effect_handlers()

    def test_apply_descriptor_dispatches_a_custom_kind(self, conn: sqlite3.Connection) -> None:
        effects.register_effect_handler("probe", _custom_handler)
        entry = effects.apply_descriptor(conn, {"kind": "probe", "function_id": 1})
        assert entry == {"kind": "probe", "custom": True}

    def test_unknown_effect_error_names_the_kind_and_known_kinds(
        self, conn: sqlite3.Connection
    ) -> None:
        with pytest.raises(effects.UnknownEffectError) as excinfo:
            effects.apply_descriptor(conn, {"kind": "no-such-kind", "function_id": 1})
        error = excinfo.value
        assert isinstance(error, LookupError)
        assert error.kind == "no-such-kind"
        assert effects.EFFECT_DISASM in error.known_kinds
        assert "no-such-kind" in str(error)
        assert effects.EFFECT_DISASM in str(error)

    def test_apply_undo_plan_reports_an_unknown_kind_as_failed(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        store.set_disasm(conn, ids["function"], "listing")
        plan: list[dict[str, Any]] = [
            {"kind": "no-such-kind", "function_id": ids["function"]},
            {"kind": effects.EFFECT_DISASM, "function_id": ids["function"]},
        ]
        undone = effects.apply_undo_plan(conn, plan)
        assert undone[1]["status"] == EFFECT_FAILED
        assert undone[1]["kind"] == "no-such-kind"
        assert "no-such-kind" in undone[1]["detail"]
        assert undone[0]["status"] == EFFECT_REVERTED
        assert store.get_disasm(conn, ids["function"]) is None

    def test_entry_point_single_handler_registers_under_its_name(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_entry_points(
            monkeypatch, _EntryPoint("plugin-mark", "effects_plugins:mark_function")
        )
        assert "plugin-mark" in effects.refresh_effect_handlers()

    def test_entry_point_mapping_registers_every_kind(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_entry_points(
            monkeypatch, _EntryPoint("plugin-bundle", "effects_plugins:HANDLER_MAPPING")
        )
        handlers = effects.refresh_effect_handlers()
        assert "plugin-note" in handlers
        assert "plugin-tag" in handlers

    def test_entry_point_broken_registration_is_skipped_with_a_warning(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("bad", "effects_plugins:NOT_A_HANDLER"))
        with caplog.at_level(logging.WARNING):
            handlers = effects.refresh_effect_handlers()
        assert "skipping bad reportal.effect_handlers registration" in caplog.text
        assert effects.EFFECT_DISASM in handlers

    def test_entry_point_without_a_module_is_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("bad", ""))
        assert effects.EFFECT_DISASM in effects.refresh_effect_handlers()

    def test_entry_point_with_an_unimportable_module_is_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("bad", "no_such_plugin_module:thing"))
        assert effects.EFFECT_DISASM in effects.refresh_effect_handlers()

    def test_entry_point_with_a_missing_attribute_is_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("bad", "effects_plugins:absent_attr"))
        assert effects.EFFECT_DISASM in effects.refresh_effect_handlers()

    def test_entry_point_with_a_bad_mapping_is_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("bad", "effects_plugins:BAD_MAPPING"))
        assert effects.EFFECT_DISASM in effects.refresh_effect_handlers()

    def test_entry_point_duplicating_a_builtin_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("dup", "effects_plugins:BUILTIN_MAPPING"))
        with pytest.raises(effects.RegistryError):
            effects.refresh_effect_handlers()

    def test_refresh_picks_up_a_newly_registered_entry_point_kind(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        assert "plugin-mark" not in effects.effect_handlers()
        _patch_entry_points(
            monkeypatch, _EntryPoint("plugin-mark", "effects_plugins:mark_function")
        )
        assert "plugin-mark" in effects.refresh_effect_handlers()

    def test_refresh_drops_a_directly_registered_kind(self) -> None:
        effects.register_effect_handler("probe", _custom_handler)
        assert "probe" in effects.effect_handlers()
        assert "probe" not in effects.refresh_effect_handlers()
