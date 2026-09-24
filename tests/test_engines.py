"""Tests for reportal.engines: in-process engine calls and the degraded path.

rebrew is a base dependency, and its modules are imported lazily inside each
method, so a test that wants a live engine installs a stub rebrew submodule in
``sys.modules`` and the adapter's ``from rebrew.<module> import`` resolves to
it.  The degraded path is exercised by hiding the package, which is what an
install with a broken engine looks like.

``disassemble``, ``control_flow_graph`` and ``test_source`` import the
engine's own entry points lazily; their tests stub those modules.
"""

from __future__ import annotations

import importlib.machinery
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest
import typer

from reportal import engines


def _target(tmp_path: Path) -> Path:
    path = tmp_path / "demo.exe"
    path.write_bytes(b"MZ" + b"\x00" * 30)
    return path


def _rebrew_project(tmp_path: Path) -> Path:
    project = tmp_path / "rebrew-project"
    project.mkdir()
    (project / "rebrew-project.toml").write_text('[project]\nname = "demo"\n', encoding="utf-8")
    return project


def _stub(monkeypatch: pytest.MonkeyPatch, name: str, **attributes: Any) -> None:
    """Put a stub ``rebrew.<name>`` in ``sys.modules`` so a lazy import resolves."""
    module = ModuleType(f"rebrew.{name}")
    for attribute, value in attributes.items():
        setattr(module, attribute, value)
    monkeypatch.setitem(sys.modules, f"rebrew.{name}", module)


def _spec(origin: str = "/opt/rebrew/__init__.py") -> importlib.machinery.ModuleSpec:
    return importlib.machinery.ModuleSpec("rebrew", loader=None, origin=origin)


def _config(project: Path) -> SimpleNamespace:
    """A stand-in project config, shaped like rebrew's ProjectConfig."""
    return SimpleNamespace(
        root=project,
        arch="x86_32",
        target_binary=project / "original" / "demo.exe",
        reversed_dir=project / "src",
        metadata_dir=None,
        pointer_size=4,
        library_modules=[],
        crt_sources={},
        marker="",
        source_ext=".c",
    )


# Every public call, as (engine, project_dir, binary) -> result.  Used by the
# degraded-path test so one engine's whole surface is exercised.
_CALLS: dict[str, Callable[[engines.RebrewEngine, Path, Path], Any]] = {
    "fingerprint": lambda engine, project, target: engine.fingerprint(target),
    "imports": lambda engine, project, target: engine.imports(target),
    "strings": lambda engine, project, target: engine.strings(target),
    "analyze": lambda engine, project, target: engine.analyze(target),
    "crypto_scan": lambda engine, project, target: engine.crypto_scan(target),
    "pe_info": lambda engine, project, target: engine.pe_info(target),
    "read_memory": lambda engine, project, target: engine.read_memory(target, address=0x401000),
    "read_memory_page": lambda engine, project, target: engine.read_memory_page(target),
    "identify_library": lambda engine, project, target: engine.identify_library(project),
    "report": lambda engine, project, target: engine.report(project, project / "out"),
    "disassemble": lambda engine, project, target: engine.disassemble(project, 0x1000, 16),
    "control_flow_graph": lambda engine, project, target: engine.control_flow_graph(
        project, 0x1000
    ),
    "decompile": lambda engine, project, target: engine.decompile(project, 0x1000),
    "xrefs": lambda engine, project, target: engine.xrefs(project, 0x1000),
    "describe": lambda engine, project, target: engine.describe(project, 0x1000),
    "structs": lambda engine, project, target: engine.structs(project),
    "security_scan": lambda engine, project, target: engine.security_scan(project),
    "test_source": lambda engine, project, target: engine.test_source(project, "FN.c"),
    "intake": lambda engine, project, target: engine.intake(target, project / "new", target="demo"),
    "build_coverage_db": lambda engine, project, target: engine.build_coverage_db(project),
    "library_functions": lambda engine, project, target: engine.library_functions(target),
}


class TestAvailability:
    def test_probes_the_installed_package(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(engines, "_rebrew_spec", lambda: _spec())
        assert engines.RebrewEngine().available() is True

    def test_a_missing_package_is_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(engines, "_rebrew_spec", lambda: None)
        assert engines.RebrewEngine().available() is False

    def test_enabled_pins_either_side(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(engines, "_rebrew_spec", lambda: None)
        assert engines.RebrewEngine(enabled=True).available() is True
        monkeypatch.setattr(engines, "_rebrew_spec", lambda: _spec())
        assert engines.RebrewEngine(enabled=False).available() is False

    def test_origin_names_the_installed_package(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(engines, "_rebrew_spec", lambda: _spec("/x/rebrew/__init__.py"))
        assert engines.RebrewEngine().origin == "/x/rebrew/__init__.py"

    def test_origin_is_none_without_the_package(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(engines, "_rebrew_spec", lambda: None)
        assert engines.RebrewEngine().origin is None

    def test_get_engine_resolves_once(self) -> None:
        engines.set_engine(None)
        engine = engines.get_engine()
        assert isinstance(engine, engines.RebrewEngine)
        assert engines.get_engine() is engine

    def test_injected_engine_wins(self) -> None:
        fake = engines.RebrewEngine(enabled=True)
        engines.set_engine(fake)
        assert engines.get_engine() is fake

    def test_set_engine_none_restores_default(self) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=True))
        engines.set_engine(None)
        assert isinstance(engines.get_engine(), engines.RebrewEngine)


class TestUnavailable:
    @pytest.mark.parametrize("name", sorted(_CALLS))
    def test_every_call_raises_engine_unavailable(
        self, name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The package is hidden, so this is the import failure a broken install
        # would produce, not a second venv.
        monkeypatch.setattr(engines, "_rebrew_spec", lambda: None)
        engine = engines.RebrewEngine()
        with pytest.raises(engines.EngineUnavailable, match="analysis engine unavailable"):
            _CALLS[name](engine, _rebrew_project(tmp_path), _target(tmp_path))

    def test_unavailable_subclasses_engine_error(self) -> None:
        assert issubclass(engines.EngineUnavailable, engines.EngineError)

    def test_a_missing_binary_is_reported_before_availability(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(engines, "_rebrew_spec", lambda: None)
        engine = engines.RebrewEngine()
        with pytest.raises(engines.EngineError, match="binary not found"):
            engine.fingerprint(tmp_path / "absent.exe")


class TestErrors:
    def test_a_raising_engine_becomes_an_engine_error(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        def boom(path: str) -> dict[str, Any]:
            raise ValueError("bad header")

        _stub(monkeypatch, "pe_info", pe_info=boom)
        engine = engines.RebrewEngine(enabled=True)
        with pytest.raises(engines.EngineError, match="rebrew pe-info failed: bad header"):
            engine.pe_info(_target(tmp_path))

    def test_an_exiting_engine_reports_its_code(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        def boom(path: str) -> dict[str, Any]:
            raise typer.Exit(code=2)

        _stub(monkeypatch, "pe_info", pe_info=boom)
        engine = engines.RebrewEngine(enabled=True)
        with pytest.raises(engines.EngineError, match="rebrew pe-info exited with code 2"):
            engine.pe_info(_target(tmp_path))

    def test_the_message_is_bounded(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        def boom(path: str) -> dict[str, Any]:
            raise ValueError("y" * 5000)

        _stub(monkeypatch, "pe_info", pe_info=boom)
        engine = engines.RebrewEngine(enabled=True)
        with pytest.raises(engines.EngineError) as excinfo:
            engine.pe_info(_target(tmp_path))
        assert str(excinfo.value).count("y") == engines.ERROR_MESSAGE_CHARS

    def test_an_importable_but_incomplete_engine_is_unavailable(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _stub(monkeypatch, "pe_info")  # the module exists, the name does not
        engine = engines.RebrewEngine(enabled=True)
        with pytest.raises(engines.EngineUnavailable, match="failed to import"):
            engine.pe_info(_target(tmp_path))

    def test_a_missing_binary_never_reaches_the_engine(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        calls: list[str] = []

        def bundle(path: str) -> dict[str, Any]:
            calls.append(path)
            return {}

        _stub(monkeypatch, "fingerprints", fingerprint_bundle=bundle)
        engine = engines.RebrewEngine(enabled=True)
        with pytest.raises(engines.EngineError, match="binary not found"):
            engine.fingerprint(tmp_path / "absent.exe")
        assert calls == []


class TestBinaryCalls:
    def test_fingerprint_returns_the_bundle(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        seen: dict[str, str] = {}

        def bundle(path: str) -> dict[str, Any]:
            seen["path"] = path
            return {"format": "pe", "md5": "ab"}

        _stub(monkeypatch, "fingerprints", fingerprint_bundle=bundle)
        target = _target(tmp_path)
        assert engines.RebrewEngine(enabled=True).fingerprint(target) == {
            "format": "pe",
            "md5": "ab",
        }
        assert seen["path"] == str(target)

    def test_imports_passes_the_binary_path(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        seen: dict[str, Path] = {}

        def payload(path: Path) -> dict[str, Any]:
            seen["path"] = path
            return {"imports": [], "stubs": []}

        _stub(monkeypatch, "imports", imports_payload=payload)
        target = _target(tmp_path)
        assert engines.RebrewEngine(enabled=True).imports(target) == {"imports": [], "stubs": []}
        assert seen["path"] == target

    def test_strings_asks_for_the_json_payload(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        seen: dict[str, Any] = {}

        def collect(path: Path, *, json_output: bool = False) -> dict[str, Any]:
            seen["path"] = path
            seen["json_output"] = json_output
            return {"binary": str(path), "count": 1, "strings": []}

        _stub(monkeypatch, "strings", collect_strings=collect)
        target = _target(tmp_path)
        result = engines.RebrewEngine(enabled=True).strings(target)
        assert result["count"] == 1
        assert seen == {"path": target, "json_output": True}

    def test_pe_info_returns_the_metadata(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _stub(monkeypatch, "pe_info", pe_info=lambda path: {"format": "pe", "sections": []})
        assert engines.RebrewEngine(enabled=True).pe_info(_target(tmp_path)) == {
            "format": "pe",
            "sections": [],
        }

    def test_analyze_uses_the_standalone_config_outside_a_project(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        seen: dict[str, Any] = {}

        def load_config(*args: Any, **kwargs: Any) -> Any:
            raise FileNotFoundError("no rebrew-project.toml")

        def build(cfg: Any, binary: Path, **kwargs: Any) -> dict[str, Any]:
            seen["cfg"] = cfg
            seen["binary"] = binary
            return {"meta": {"format": "pe"}}

        _stub(monkeypatch, "config", load_config=load_config)
        _stub(monkeypatch, "analyze", build_dossier=build)
        target = _target(tmp_path)
        assert engines.RebrewEngine(enabled=True).analyze(target) == {"meta": {"format": "pe"}}
        assert seen["binary"] == target
        assert seen["cfg"].root is None
        assert seen["cfg"].target_binary == target

    def test_analyze_uses_the_cwd_project_when_there_is_one(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        cfg = _config(tmp_path)
        seen: dict[str, Any] = {}

        _stub(monkeypatch, "config", load_config=lambda *args, **kwargs: cfg)
        _stub(
            monkeypatch,
            "analyze",
            build_dossier=lambda config, binary, **kwargs: seen.update(config=config) or {},
        )
        target = _target(tmp_path)
        assert engines.RebrewEngine(enabled=True).analyze(target) == {}
        assert seen["config"] is cfg

    def test_crypto_scan_contributes_the_project_function_names(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        cfg = _config(tmp_path)
        seen: dict[str, Any] = {}

        def scan(path: str, names: list[str] | None = None) -> dict[str, Any]:
            seen["path"] = path
            seen["names"] = names
            return {"findings": [], "count": 0, "by_confidence": {}}

        _stub(monkeypatch, "config", load_config=lambda *args, **kwargs: cfg)
        _stub(
            monkeypatch,
            "crypto_scan",
            crypto_scan=scan,
            _project_function_names=lambda config: ["sub_1000"],
        )
        target = _target(tmp_path)
        assert engines.RebrewEngine(enabled=True).crypto_scan(target)["count"] == 0
        assert seen == {"path": str(target), "names": ["sub_1000"]}

    def test_crypto_scan_without_a_project_passes_no_names(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        seen: dict[str, Any] = {}

        def load_config(*args: Any, **kwargs: Any) -> Any:
            raise FileNotFoundError("no rebrew-project.toml")

        def scan(path: str, names: list[str] | None = None) -> dict[str, Any]:
            seen["names"] = names
            return {"findings": [], "count": 0}

        _stub(monkeypatch, "config", load_config=load_config)
        _stub(
            monkeypatch,
            "crypto_scan",
            crypto_scan=scan,
            _project_function_names=lambda config: ["must not be used"],
        )
        engines.RebrewEngine(enabled=True).crypto_scan(_target(tmp_path))
        assert seen["names"] == []


class TestProjectCalls:
    def test_identify_library_previews_without_writing(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        project = _rebrew_project(tmp_path)
        candidates = [
            SimpleNamespace(
                va=0x1000,
                name="ChooseFontW",
                module="COMDLG32",
                kind="import",
                confidence=0.30000001,
            ),
            SimpleNamespace(
                va=0x2000, name="GetOpenFileNameW", module="COMDLG32", kind="import", confidence=0.5
            ),
        ]
        _stub(monkeypatch, "config", load_config=lambda root: _config(project))
        _stub(
            monkeypatch,
            "identify_library",
            collect_candidates=lambda cfg, default_module=None: candidates,
            _existing_vas=lambda cfg: {0x2000},
        )
        payload = engines.RebrewEngine(enabled=True).identify_library(project)
        assert payload == {
            "sigs_written": 0,
            "identified": 2,
            "already_annotated": 1,
            "to_write": 1,
            "written": 0,
            "candidates": [
                {
                    "va": "0x00001000",
                    "name": "ChooseFontW",
                    "module": "COMDLG32",
                    "kind": "import",
                    "confidence": 0.3,
                },
                {
                    "va": "0x00002000",
                    "name": "GetOpenFileNameW",
                    "module": "COMDLG32",
                    "kind": "import",
                    "confidence": 0.5,
                },
            ],
        }

    def test_report_writes_into_the_named_output_directory(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        project = _rebrew_project(tmp_path)
        output = tmp_path / "reports" / "1"
        seen: dict[str, Any] = {}

        def generate(cfg: Any, out: Path) -> dict[str, Any]:
            seen["out"] = out
            return {"out": str(out), "pages": ["index.html"], "summary": {}}

        _stub(monkeypatch, "config", load_config=lambda root: _config(project))
        _stub(monkeypatch, "report", generate_report=generate)
        result = engines.RebrewEngine(enabled=True).report(project, output)
        assert result["pages"] == ["index.html"]
        assert seen["out"] == output

    def test_decompile_returns_the_engine_payload(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        project = _rebrew_project(tmp_path)
        _stub(monkeypatch, "config", load_config=lambda root: _config(project))
        _stub(
            monkeypatch,
            "decompiler",
            fetch_decompilation=lambda backend, binary, va, root: ("void f(void);", "kuna"),
        )
        result = engines.RebrewEngine(enabled=True).decompile(project, 0x1000)
        assert result == {
            "va": "0x1000",
            "backend": "kuna",
            "named": False,
            "applied": [],
            "code": "void f(void);",
        }

    def test_decompile_named_applies_known_names(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        project = _rebrew_project(tmp_path)
        applied = [{"var": "a0", "struct": "PlayerInfo", "offsets": ["0x0"]}]
        _stub(monkeypatch, "config", load_config=lambda root: _config(project))
        _stub(
            monkeypatch,
            "decompiler",
            fetch_decompilation=lambda backend, binary, va, root: ("void f(void);", "kuna"),
        )
        _stub(
            monkeypatch,
            "sources",
            iter_sources=lambda d, cfg: [],
            iter_library_headers=lambda d, cfg: [],
        )
        _stub(monkeypatch, "struct_recover", existing_structs=lambda sources: {"PlayerInfo": "..."})
        _stub(
            monkeypatch,
            "name_decomp",
            apply_known_names=lambda code, definitions, pointer_width=4: SimpleNamespace(
                code="void f(PlayerInfo *a0);", applied=applied
            ),
        )
        result = engines.RebrewEngine(enabled=True).decompile(project, 0x1000, named=True)
        assert result["named"] is True
        assert result["applied"] == applied
        assert result["code"] == "void f(PlayerInfo *a0);"

    def test_decompile_without_code_raises(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        project = _rebrew_project(tmp_path)
        _stub(monkeypatch, "config", load_config=lambda root: _config(project))
        _stub(
            monkeypatch,
            "decompiler",
            fetch_decompilation=lambda backend, binary, va, root: (None, "kuna"),
        )
        engine = engines.RebrewEngine(enabled=True)
        with pytest.raises(engines.EngineError, match="decompilation failed"):
            engine.decompile(project, 0x1000)

    def test_decompile_rejects_an_unknown_backend_before_the_engine(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        project = _rebrew_project(tmp_path)
        _stub(monkeypatch, "config", load_config=lambda root: _config(project))
        engine = engines.RebrewEngine(enabled=True)
        with pytest.raises(engines.EngineError, match="unsupported decompiler backend"):
            engine.decompile(project, 0x1000, "ida")

    def test_xrefs_forwards_the_kind_filter(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        project = _rebrew_project(tmp_path)
        seen: dict[str, Any] = {}

        def build(binary: Path, va: int, kinds: list[str]) -> dict[str, Any]:
            seen.update(binary=binary, va=va, kinds=kinds)
            return {"target": va, "import_name": None, "count": 0, "refs": []}

        _stub(monkeypatch, "config", load_config=lambda root: _config(project))
        _stub(monkeypatch, "xrefs", build_xrefs_payload=build)
        result = engines.RebrewEngine(enabled=True).xrefs(project, 0x1000, ["call", "data"])
        assert result == {"target": 0x1000, "import_name": None, "count": 0, "refs": []}
        assert seen == {
            "binary": project / "original" / "demo.exe",
            "va": 0x1000,
            "kinds": ["call", "data"],
        }

    def test_describe_returns_the_json_contract_only(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        project = _rebrew_project(tmp_path)
        keys = ("va", "name", "status", "size", "cflags", "pattern", "convention")
        dossier = dict.fromkeys(keys)
        dossier["va"] = 0x1000
        dossier["note"] = "terminal only"
        _stub(monkeypatch, "config", load_config=lambda root: _config(project))
        _stub(monkeypatch, "analysis", is_inside=lambda info, va: True)
        _stub(monkeypatch, "binary_loader", load_binary=lambda path: object())
        _stub(monkeypatch, "describe", _JSON_KEYS=keys, build_dossier=lambda cfg, info, va: dossier)
        result = engines.RebrewEngine(enabled=True).describe(project, 0x1000)
        assert result["va"] == 0x1000
        assert "note" not in result

    def test_describe_rejects_an_address_outside_the_image(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        project = _rebrew_project(tmp_path)
        _stub(monkeypatch, "config", load_config=lambda root: _config(project))
        _stub(monkeypatch, "analysis", is_inside=lambda info, va: False)
        _stub(monkeypatch, "binary_loader", load_binary=lambda path: object())
        _stub(monkeypatch, "describe", _JSON_KEYS=(), build_dossier=lambda cfg, info, va: {})
        engine = engines.RebrewEngine(enabled=True)
        with pytest.raises(engines.EngineError, match="outside the binary image"):
            engine.describe(project, 0x1000)

    def test_structs_forwards_the_backend_and_limit(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        project = _rebrew_project(tmp_path)
        seen: dict[str, Any] = {}

        def recover(cfg: Any, **kwargs: Any) -> dict[str, Any]:
            seen.update(kwargs)
            return {"decompiled": 12, "skipped": 1, "structs": []}

        _stub(monkeypatch, "config", load_config=lambda root: _config(project))
        _stub(monkeypatch, "struct_recover", recover_project_structs=recover)
        result = engines.RebrewEngine(enabled=True).structs(project, decompiler="r2ghidra", limit=7)
        assert result == {"decompiled": 12, "skipped": 1, "structs": []}
        assert seen == {"decompiler": "r2ghidra", "limit": 7, "json_output": True}

    def test_structs_rejects_a_negative_limit(self, tmp_path: Path) -> None:
        engine = engines.RebrewEngine(enabled=True)
        with pytest.raises(engines.EngineError, match="must not be negative"):
            engine.structs(_rebrew_project(tmp_path), limit=-1)

    def test_security_scan_filters_to_the_severity_floor(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        project = _rebrew_project(tmp_path)
        seen: dict[str, Any] = {}
        raw = {"root": str(project), "files_scanned": 2, "findings": [], "count": 0}

        def scan(directory: Path, *, recursive: bool = True) -> dict[str, Any]:
            seen["directory"] = directory
            return raw

        def filtered(result: dict[str, Any], min_severity: str) -> dict[str, Any]:
            seen["min_severity"] = min_severity
            return {**result, "filtered": True}

        _stub(monkeypatch, "config", load_config=lambda root: _config(project))
        _stub(monkeypatch, "security_scan", security_scan=scan, _filter_result=filtered)
        result = engines.RebrewEngine(enabled=True).security_scan(project, "high")
        assert result["filtered"] is True
        assert seen == {"directory": project / "src", "min_severity": "high"}

    def test_security_scan_rejects_an_unknown_severity(self, tmp_path: Path) -> None:
        engine = engines.RebrewEngine(enabled=True)
        with pytest.raises(engines.EngineError, match="unsupported security severity"):
            engine.security_scan(_rebrew_project(tmp_path), "critical")

    def test_a_missing_project_directory_is_rejected(self, tmp_path: Path) -> None:
        engine = engines.RebrewEngine(enabled=True)
        with pytest.raises(engines.EngineError, match="project directory not found"):
            engine.report(tmp_path / "absent", tmp_path / "out")

    def test_a_directory_without_the_marker_is_rejected(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        engine = engines.RebrewEngine(enabled=True)
        with pytest.raises(engines.EngineError, match="not a rebrew project"):
            engine.xrefs(empty, 0x1000)


class TestInProcessEngineCalls:
    """disassemble, control_flow_graph and test_source call rebrew directly."""

    def _load(self, monkeypatch: pytest.MonkeyPatch, project: Path) -> None:
        _stub(monkeypatch, "config", load_config=lambda root: _config(project))

    def test_disassemble_returns_the_nasm_entry_point_text(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        project = _rebrew_project(tmp_path)
        seen: dict[str, Any] = {}

        def to_nasm(
            code: bytes, base_va: int, label: str | None = None
        ) -> tuple[str, dict[str, Any]]:
            seen.update(code=code, base_va=base_va, label=label)
            return "bits 32\norg 0x1000", {}

        self._load(monkeypatch, project)
        _stub(monkeypatch, "binary_loader", extract_raw_bytes=lambda path, va, size: b"\x90\x90")
        _stub(monkeypatch, "asm", disassemble_to_nasm=to_nasm)

        listing = engines.RebrewEngine(enabled=True).disassemble(project, 0x1000, 48, "nasm")
        assert listing == "bits 32\norg 0x1000\n"
        assert seen == {"code": b"\x90\x90", "base_va": 0x1000, "label": "func_00001000"}

    def test_library_functions_lists_each_object_s_functions(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        library = tmp_path / "LIBC.LIB"
        library.write_bytes(b"!<arch>\n")
        members = [
            ("coff.obj", b"L\x01coff"),
            ("elf.o", b"\x7fELFelf"),
            ("x64.o", b"\x7fELFx64"),
            ("omf.obj", b"\x80omf"),
        ]
        arches = {
            b"L\x01coff": ("x86_32", "little"),
            b"\x7fELFelf": ("x86_32", "little"),
            b"\x7fELFx64": ("x86_64", "little"),
        }
        parsed: list[str] = []

        def coff(obj: bytes) -> list[tuple[str, bytes, set[int]]]:
            parsed.append("coff")
            return [("_strlen", b"\x55\xc3", set()), ("_empty", b"", set())]

        def elf(obj: bytes, *, include_local: bool) -> list[tuple[str, bytes, set[int]]]:
            assert include_local, "a library pack wants file-static functions too"
            parsed.append("elf")
            if obj.endswith(b"x64"):
                # push rbp; mov rbp, rsp; ret
                return [("memset", b"\x55\x48\x89\xe5\xc3", set())]
            return [("memcpy", b"\xc3", set())]

        def nasm(code: bytes, va: int, label: str | None) -> tuple[str, dict[str, Any]]:
            return ("" if not code else f"; {len(code)} bytes at {va}\n"), {}

        _stub(
            monkeypatch,
            "gen_flirt_pat",
            parse_archive=lambda path: iter(members),
            parse_coff_obj=coff,
            parse_elf_obj=elf,
        )
        _stub(monkeypatch, "asm", disassemble_to_nasm=nasm)
        monkeypatch.setattr("rebrew.binary_loader.object_arch", arches.get)
        functions = engines.RebrewEngine(enabled=True).library_functions(library)
        # The OMF object is an unknown machine and never parsed.
        assert parsed == ["coff", "elf", "elf"]
        assert functions == [
            {"name": "_strlen", "size": 2, "arch": "x86_32", "listing": "; 2 bytes at 0\n"},
            {"name": "memcpy", "size": 1, "arch": "x86_32", "listing": "; 1 bytes at 0\n"},
            {
                "name": "memset",
                "size": 5,
                "arch": "x86_64",
                "listing": "push rbp\nmov rbp, rsp\nret\n",
            },
        ]

    def test_build_coverage_db_regenerates_and_replaces(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        project = _rebrew_project(tmp_path)
        seen: dict[str, Any] = {}

        def build_db(root: Path, **kwargs: Any) -> None:
            seen.update(kwargs, root=root)

        _stub(monkeypatch, "build_db", build_db=build_db)
        engines.RebrewEngine(enabled=True).build_coverage_db(project)
        assert seen == {"root": project.resolve(), "regen": True, "force": True}

    def test_disassemble_refuses_nasm_for_a_target_it_cannot_decode(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        project = _rebrew_project(tmp_path)
        sixteen_bit = _config(project)
        sixteen_bit.arch = "x86_16"
        _stub(monkeypatch, "config", load_config=lambda root: sixteen_bit)
        refusal = "covers x86_32 only and this target is x86_16"
        with pytest.raises(engines.EngineError, match=refusal):
            engines.RebrewEngine(enabled=True).disassemble(project, 0x10, 8)

    def test_disassemble_defaults_to_nasm(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        project = _rebrew_project(tmp_path)
        seen: dict[str, Any] = {}

        def to_nasm(
            code: bytes, base_va: int, label: str | None = None
        ) -> tuple[str, dict[str, Any]]:
            seen["label"] = label
            return "nop", {}

        self._load(monkeypatch, project)
        _stub(monkeypatch, "binary_loader", extract_raw_bytes=lambda *args, **kwargs: b"\x90")
        _stub(monkeypatch, "asm", disassemble_to_nasm=to_nasm)
        engines.RebrewEngine(enabled=True).disassemble(project, 0x10, 8)
        assert seen["label"] == "func_00000010"

    @pytest.mark.parametrize(
        ("arch", "code", "expected"),
        [
            ("x86_64", b"\x55\x48\x89\xe5\xc3", "push rbp\nmov rbp, rsp\nret\n"),
            ("arm64", b"\xc0\x03\x5f\xd6", "ret\n"),
        ],
    )
    def test_disassemble_lists_any_isa_as_asm(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, arch: str, code: bytes, expected: str
    ) -> None:
        from rebrew.analysis import resolve_capstone
        from rebrew.config import _ARCH_PRESETS

        project = _rebrew_project(tmp_path)
        cfg = _config(project)
        cfg.arch = arch
        cfg.capstone_arch = resolve_capstone(_ARCH_PRESETS[arch]["capstone_arch"])
        cfg.capstone_mode = resolve_capstone(_ARCH_PRESETS[arch]["capstone_mode"])
        _stub(monkeypatch, "config", load_config=lambda root: cfg)
        monkeypatch.setattr(
            "rebrew.binary_loader.extract_raw_bytes", lambda path, va, size: code[:size]
        )
        listing = engines.RebrewEngine(enabled=True).disassemble(project, 0x1000, len(code), "asm")
        assert listing == expected

    def test_listing_format_is_nasm_only_for_its_isa(self) -> None:
        assert [engines.listing_format(arch) for arch in ("x86_32", "", "x86_64", "mips32")] == [
            "nasm",
            "nasm",
            "asm",
            "asm",
        ]

    def test_disassemble_returns_the_hex_text(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        project = _rebrew_project(tmp_path)
        seen: dict[str, Any] = {}

        def hex_listing(cfg: Any, va: int, size: int) -> str:
            seen.update(va=va, size=size)
            return "  0x00001000:  90  nop\n"

        self._load(monkeypatch, project)
        _stub(monkeypatch, "asm", hex_disassembly=hex_listing)

        listing = engines.RebrewEngine(enabled=True).disassemble(project, 0x1000, 16, "hex")
        assert listing == "  0x00001000:  90  nop\n"
        assert seen == {"va": 0x1000, "size": 16}

    def test_disassemble_rejects_bad_format(self, tmp_path: Path) -> None:
        engine = engines.RebrewEngine(enabled=True)
        with pytest.raises(engines.EngineError, match="unsupported disassembly format"):
            engine.disassemble(_rebrew_project(tmp_path), 0x1000, 16, "json")

    def test_disassemble_rejects_non_positive_size(self, tmp_path: Path) -> None:
        engine = engines.RebrewEngine(enabled=True)
        with pytest.raises(engines.EngineError, match="must be positive"):
            engine.disassemble(_rebrew_project(tmp_path), 0x1000, 0)

    def test_disassemble_maps_an_engine_failure(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        project = _rebrew_project(tmp_path)

        def extract(path: Any, va: int, size: int) -> bytes:
            raise OSError("bad va")

        self._load(monkeypatch, project)
        _stub(monkeypatch, "binary_loader", extract_raw_bytes=extract)
        _stub(monkeypatch, "asm", disassemble_to_nasm=lambda *args, **kwargs: ("", {}))
        engine = engines.RebrewEngine(enabled=True)
        with pytest.raises(engines.EngineError, match="rebrew asm failed: bad va"):
            engine.disassemble(project, 0x1000, 16)

    def test_control_flow_graph_passes_the_size(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        project = _rebrew_project(tmp_path)
        seen: dict[str, Any] = {}

        def build(cfg: Any, va: int, size: int = 0) -> dict[str, Any]:
            seen.update(va=va, size=size)
            return {"va": "0x1000", "blocks": [], "edges": []}

        self._load(monkeypatch, project)
        _stub(monkeypatch, "asm", build_cfg_payload=build)

        payload = engines.RebrewEngine(enabled=True).control_flow_graph(project, 0x1000, 48)
        assert payload["va"] == "0x1000"
        assert seen == {"va": 0x1000, "size": 48}

    def test_control_flow_graph_passes_zero_size(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        project = _rebrew_project(tmp_path)
        seen: dict[str, Any] = {}

        def build(cfg: Any, va: int, size: int = 0) -> dict[str, Any]:
            seen["size"] = size
            return {"va": "0x1000", "note": "no extent", "blocks": []}

        self._load(monkeypatch, project)
        _stub(monkeypatch, "asm", build_cfg_payload=build)

        payload = engines.RebrewEngine(enabled=True).control_flow_graph(project, 0x1000, 0)
        assert seen["size"] == 0
        assert payload["note"] == "no extent"

    def test_control_flow_graph_maps_an_engine_failure(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        project = _rebrew_project(tmp_path)

        def build(cfg: Any, va: int, size: int = 0) -> dict[str, Any]:
            raise ValueError("not x86")

        self._load(monkeypatch, project)
        _stub(monkeypatch, "asm", build_cfg_payload=build)
        engine = engines.RebrewEngine(enabled=True)
        with pytest.raises(engines.EngineError, match="rebrew asm failed: not x86"):
            engine.control_flow_graph(project, 0x1000)

    def test_test_source_returns_the_mismatch_object(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        project = _rebrew_project(tmp_path)
        seen: dict[str, Any] = {}

        def run(
            cfg: Any, source: Any, *, no_promote: bool = False, json_output: bool = False
        ) -> dict[str, Any]:
            seen.update(source=source, no_promote=no_promote, json_output=json_output)
            return {"status": "NEAR_MATCHING", "match_count": 1}

        self._load(monkeypatch, project)
        _stub(monkeypatch, "test", run_test=run)

        result = engines.RebrewEngine(enabled=True).test_source(project, "src/FN.c")
        assert result == {"status": "NEAR_MATCHING", "match_count": 1}
        # json_output=True keeps the engine from painting the human compare
        # result into the server's stderr; the returned object is the same.
        assert seen == {"source": "src/FN.c", "no_promote": True, "json_output": True}

    def test_test_source_maps_an_engine_exit(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        project = _rebrew_project(tmp_path)

        def run(
            cfg: Any, source: Any, *, no_promote: bool = False, json_output: bool = False
        ) -> dict[str, Any]:
            raise typer.Exit(code=2)

        self._load(monkeypatch, project)
        _stub(monkeypatch, "test", run_test=run)
        engine = engines.RebrewEngine(enabled=True)
        with pytest.raises(engines.EngineError, match="rebrew test exited with code 2"):
            engine.test_source(project, "src/FN.c")

    def test_test_source_maps_an_engine_failure(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        project = _rebrew_project(tmp_path)

        def run(
            cfg: Any, source: Any, *, no_promote: bool = False, json_output: bool = False
        ) -> dict[str, Any]:
            raise ValueError("compile failed")

        self._load(monkeypatch, project)
        _stub(monkeypatch, "test", run_test=run)
        engine = engines.RebrewEngine(enabled=True)
        with pytest.raises(engines.EngineError, match="rebrew test failed: compile failed"):
            engine.test_source(project, "src/FN.c")
