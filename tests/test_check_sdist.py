"""Sdist content checks: deploy templates present, no egg-info or SPA junk."""

from __future__ import annotations

import importlib.util
import sys
import tarfile
import time
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_sdist.py"


def _load() -> object:
    spec = importlib.util.spec_from_file_location("check_sdist", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_contamination_flags_host_assets_not_egg_info() -> None:
    mod = _load()
    names = {
        "src/reportal/cli.py",
        "src/reportal.egg-info/SOURCES.txt",
        "src/reportal/assets/dist/assets/app.js.br",
        "src/reportal/assets/dist/assets/app.js.map",
        "src/reportal/__pycache__/cli.cpython-313.pyc",
        "deploy/reportal.service",
    }
    assert mod.contamination(names) == [  # type: ignore[attr-defined]
        "src/reportal/__pycache__/cli.cpython-313.pyc",
        "src/reportal/assets/dist/assets/app.js.br",
        "src/reportal/assets/dist/assets/app.js.map",
    ]


def test_missing_required_lists_root_and_deploy() -> None:
    mod = _load()
    assert mod.missing_required(set()) == list(mod.ROOT_REQUIRED) + list(  # type: ignore[attr-defined]
        mod.DEPLOY_REQUIRED  # type: ignore[attr-defined]
    )
    present = set(mod.ROOT_REQUIRED) | set(mod.DEPLOY_REQUIRED)  # type: ignore[attr-defined]
    assert mod.missing_required(present) == []  # type: ignore[attr-defined]


def test_newest_sdist_prefers_mtime(tmp_path: Path) -> None:
    mod = _load()
    older = tmp_path / "reportal-9.0.0.tar.gz"
    newer = tmp_path / "reportal-1.0.0.tar.gz"
    older.write_bytes(b"old")
    time.sleep(0.02)
    newer.write_bytes(b"new")
    assert mod.newest_sdist(tmp_path) == newer  # type: ignore[attr-defined]


def test_member_relpaths_strips_version_prefix(tmp_path: Path) -> None:
    mod = _load()
    archive_path = tmp_path / "sample.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        info = tarfile.TarInfo(name="reportal-2.1.0/deploy/reportal.service")
        payload = b"# unit\n"
        info.size = len(payload)
        import io

        archive.addfile(info, io.BytesIO(payload))
    with tarfile.open(archive_path, "r:gz") as archive:
        names = mod.member_relpaths(archive)  # type: ignore[attr-defined]
    assert names == {"deploy/reportal.service"}
