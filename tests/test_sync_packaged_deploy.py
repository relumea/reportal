"""Packaged-deploy sync mirrors deploy/ into src/reportal/deploy for the wheel."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "sync_packaged_deploy.py"


def _load() -> object:
    spec = importlib.util.spec_from_file_location("sync_packaged_deploy", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _populate(source: Path) -> None:
    source.mkdir(parents=True, exist_ok=True)
    mod = _load()
    for name in mod.REQUIRED:  # type: ignore[attr-defined]
        (source / name).write_text(f"# {name}\n", encoding="utf-8")


def test_sync_copies_required_units(tmp_path: Path) -> None:
    mod = _load()
    source = tmp_path / "deploy"
    dest = tmp_path / "packaged"
    _populate(source)
    written = mod.sync(dest=dest, source=source)  # type: ignore[attr-defined]
    assert written == len(mod.REQUIRED)  # type: ignore[attr-defined]
    assert (dest / "reportal.service").read_text(encoding="utf-8") == "# reportal.service\n"
    assert mod.sync(dest=dest, source=source) == 0  # type: ignore[attr-defined]


def test_sync_removes_stale_units(tmp_path: Path) -> None:
    mod = _load()
    source = tmp_path / "deploy"
    dest = tmp_path / "packaged"
    _populate(source)
    dest.mkdir()
    (dest / "gone.service").write_text("# Gone\n", encoding="utf-8")
    mod.sync(dest=dest, source=source)  # type: ignore[attr-defined]
    assert (dest / "reportal.service").is_file()
    assert not (dest / "gone.service").exists()


def test_sync_refuses_incomplete_source(tmp_path: Path) -> None:
    mod = _load()
    source = tmp_path / "deploy"
    source.mkdir()
    (source / "reportal.service").write_text("# only one\n", encoding="utf-8")
    dest = tmp_path / "packaged"
    assert mod.sync(dest=dest, source=source) == -1  # type: ignore[attr-defined]
    assert not dest.exists()
