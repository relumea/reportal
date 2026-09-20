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


def test_source_maps_lists_dist_maps_only() -> None:
    mod = _load()
    names = {
        "reportal/assets/dist/assets/app.js.map",
        "reportal/assets/dist/index.html",
        "other/place.js.map",
    }
    assert mod.source_maps(names) == [  # type: ignore[attr-defined]
        "reportal/assets/dist/assets/app.js.map"
    ]


def test_brotli_siblings_lists_dist_br_only() -> None:
    mod = _load()
    names = {
        "reportal/assets/dist/assets/app.js.br",
        "reportal/assets/dist/index.html",
        "other/place.js.br",
    }
    assert mod.brotli_siblings(names) == [  # type: ignore[attr-defined]
        "reportal/assets/dist/assets/app.js.br"
    ]


def test_expected_zip_date_time_honours_source_date_epoch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mod = _load()
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1789921172")
    assert mod.expected_zip_date_time() == (2026, 9, 20, 16, 19, 32)  # type: ignore[attr-defined]
    monkeypatch.delenv("SOURCE_DATE_EPOCH")
    assert mod.expected_zip_date_time() == (1980, 1, 1, 0, 0, 0)  # type: ignore[attr-defined]
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "100")  # pre-1980
    assert mod.expected_zip_date_time() == (1980, 1, 1, 0, 0, 0)  # type: ignore[attr-defined]


def test_nondeterministic_zip_dates_flags_wall_clock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import zipfile

    mod = _load()
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    expected = mod.expected_zip_date_time()  # type: ignore[attr-defined]
    wheel = tmp_path / "sample.zip"
    with zipfile.ZipFile(wheel, "w") as archive:
        good = zipfile.ZipInfo("reportal/cli.py")
        good.date_time = expected
        archive.writestr(good, b"")
        bad = zipfile.ZipInfo("reportal/other.py")
        bad.date_time = (2024, 1, 2, 3, 4, 6)
        archive.writestr(bad, b"")
    with zipfile.ZipFile(wheel) as archive:
        flagged = mod.nondeterministic_zip_dates(  # type: ignore[attr-defined]
            archive, expected=expected
        )
    assert flagged == ["reportal/other.py"]


def test_missing_deploy_lists_required_unit_paths() -> None:
    mod = _load()
    required = list(mod.DEPLOY_REQUIRED)  # type: ignore[attr-defined]
    assert len(required) == 3
    assert any(path.endswith("reportal.service") for path in required)
    assert any(path.endswith("reportal-backup.timer") for path in required)
    assert mod.missing_deploy(set()) == required  # type: ignore[attr-defined]
    assert mod.missing_deploy(set(required)) == []  # type: ignore[attr-defined]


def test_missing_requires_dist_flags_absent_runtime_deps() -> None:
    mod = _load()
    metadata = (
        "Requires-Dist: fastapi==0.141.1\n"
        "Requires-Dist: rebrew\n"
        'Requires-Dist: pytest==9.1.1; extra == "dev"\n'
    )
    gaps = mod.missing_requires_dist(metadata)  # type: ignore[attr-defined]
    assert "python-flirt" in gaps
    assert "httpx2" in gaps
    assert "fastapi" not in gaps
    assert "rebrew" not in gaps
    complete = metadata + "\n".join(
        f"Requires-Dist: {name}"
        for name in mod.REQUIRED_DIST_NAMES  # type: ignore[attr-defined]
    )
    assert mod.missing_requires_dist(complete) == []  # type: ignore[attr-defined]


def test_expected_gzip_mtime_honours_source_date_epoch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mod = _load()
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    assert mod.expected_gzip_mtime() == 1700000000  # type: ignore[attr-defined]
    monkeypatch.delenv("SOURCE_DATE_EPOCH")
    assert mod.expected_gzip_mtime() == 0  # type: ignore[attr-defined]


def test_nondeterministic_gzip_flags_wall_clock_mtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import gzip
    import zipfile

    mod = _load()
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    body = b"x" * 300
    good = gzip.compress(body, compresslevel=9, mtime=0)
    bad = gzip.compress(body, compresslevel=9, mtime=1_700_000_000)
    wheel = tmp_path / "sample.zip"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("reportal/assets/dist/assets/app.js.gz", good)
        archive.writestr("reportal/assets/dist/assets/other.js.gz", bad)
        archive.writestr("reportal/cli.py", b"")
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        flagged = mod.nondeterministic_gzip(  # type: ignore[attr-defined]
            archive, names, expected_mtime=0
        )
    assert flagged == ["reportal/assets/dist/assets/other.js.gz"]
