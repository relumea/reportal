"""Wheel content checks: SPA assets, packaged manual, no stale modules."""

from __future__ import annotations

import importlib.util
import sys
import time
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_wheel.py"


def _load() -> object:
    spec = importlib.util.spec_from_file_location("check_wheel", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_missing_manual_lists_required_paths() -> None:
    mod = _load()
    required = list(mod.MANUAL_REQUIRED)  # type: ignore[attr-defined]
    assert len(required) >= 15
    assert any(path.endswith("ERRORS.md") for path in required)
    assert any(path.endswith("CHANGELOG.md") for path in required)
    assert any(path.endswith("ARCHITECTURE.md") for path in required)
    assert mod.missing_manual(set()) == required  # type: ignore[attr-defined]
    assert mod.missing_manual(set(required)) == []  # type: ignore[attr-defined]


def test_packaged_pages_walks_one_subdirectory_level(tmp_path: Path) -> None:
    mod = _load()
    docs_dir = tmp_path / "docs"
    (docs_dir / "subsystems").mkdir(parents=True)
    (docs_dir / "subsystems" / "store.md").write_text("# Store\n", encoding="utf-8")
    (docs_dir / "subsystems" / "README.md").write_text("# Subsystems\n", encoding="utf-8")
    (docs_dir / "ERRORS.md").write_text("# Errors\n", encoding="utf-8")
    (docs_dir / "subsystems" / "note.txt").write_text("ignored\n", encoding="utf-8")
    pages = mod.packaged_pages(docs_dir)  # type: ignore[attr-defined]
    assert pages == (
        "reportal/manual/ERRORS.md",
        "reportal/manual/subsystems/README.md",
        "reportal/manual/subsystems/store.md",
    )
    missing = mod.missing_manual(  # type: ignore[attr-defined]
        {"reportal/manual/subsystems/store.md"}, pages
    )
    assert missing == ["reportal/manual/ERRORS.md", "reportal/manual/subsystems/README.md"]


def test_stale_modules_ignores_nested_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = _load()
    source = tmp_path / "src" / "reportal"
    source.mkdir(parents=True)
    (source / "cli.py").write_text("", encoding="utf-8")
    monkeypatch.setattr(mod, "SOURCE_DIR", source)
    names = {
        "reportal/cli.py",
        "reportal/gone.py",
        "reportal/assets/dist/index.html",
        "reportal/manual/ERRORS.md",
    }
    assert mod.stale_modules(names) == ["reportal/gone.py"]  # type: ignore[attr-defined]


def test_newest_wheel_prefers_mtime(tmp_path: Path) -> None:
    mod = _load()
    older = tmp_path / "reportal-9.0.0-py3-none-any.whl"
    newer = tmp_path / "reportal-1.0.0-py3-none-any.whl"
    older.write_bytes(b"old")
    time.sleep(0.02)
    newer.write_bytes(b"new")
    assert mod.newest_wheel(tmp_path) == newer  # type: ignore[attr-defined]
