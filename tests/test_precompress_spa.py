"""Build-time SPA precompression writes ``.gz`` siblings ``ui.py`` prefers."""

from __future__ import annotations

import gzip
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "precompress_spa.py"


@pytest.fixture(scope="module")
def precompress_mod() -> object:
    """Load ``scripts/precompress_spa.py`` without making ``scripts`` a package."""
    spec = importlib.util.spec_from_file_location("precompress_spa", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_precompress_writes_gzip_siblings(tmp_path: Path, precompress_mod: object) -> None:
    min_bytes = int(precompress_mod.MIN_BYTES)  # type: ignore[attr-defined]
    root = tmp_path / "dist"
    assets = root / "assets"
    assets.mkdir(parents=True)
    big = "x" * (min_bytes + 50)
    (assets / "app.js").write_text(big, encoding="utf-8")
    (assets / "tiny.js").write_text("ok", encoding="utf-8")
    (assets / "photo.png").write_bytes(b"\x89PNG" + b"\x00" * min_bytes)
    written = precompress_mod.precompress(root)  # type: ignore[attr-defined]
    gz = assets / "app.js.gz"
    assert gz.is_file()
    assert gzip.decompress(gz.read_bytes()) == big.encode("utf-8")
    assert not (assets / "tiny.js.gz").exists()
    assert not (assets / "photo.png.gz").exists()
    br = assets / "app.js.br"
    if precompress_mod.brotli_bin() is not None:  # type: ignore[attr-defined]
        assert written >= 2
        assert br.is_file()
        assert len(br.read_bytes()) < len(big.encode("utf-8"))
    else:
        assert written == 1
        assert not br.exists()


def test_precompress_skips_fresh_siblings(tmp_path: Path, precompress_mod: object) -> None:
    min_bytes = int(precompress_mod.MIN_BYTES)  # type: ignore[attr-defined]
    root = tmp_path / "dist"
    root.mkdir()
    path = root / "shell.html"
    path.write_text("<html>" + ("y" * min_bytes) + "</html>", encoding="utf-8")
    first = precompress_mod.precompress(root)  # type: ignore[attr-defined]
    assert first >= 1
    assert precompress_mod.precompress(root) == 0  # type: ignore[attr-defined]


def test_precompress_rewrites_nondeterministic_gzip(
    tmp_path: Path, precompress_mod: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A sibling whose gzip header still carries wall-clock mtime is refreshed."""
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    min_bytes = int(precompress_mod.MIN_BYTES)  # type: ignore[attr-defined]
    root = tmp_path / "dist"
    root.mkdir()
    path = root / "app.js"
    body = ("x" * (min_bytes + 10)).encode("utf-8")
    path.write_bytes(body)
    stale = gzip.compress(body, compresslevel=int(precompress_mod.GZIP_LEVEL))  # type: ignore[attr-defined]
    assert stale[4:8] != b"\x00\x00\x00\x00"
    (root / "app.js.gz").write_bytes(stale)
    assert precompress_mod.precompress(root) >= 1  # type: ignore[attr-defined]
    assert (root / "app.js.gz").read_bytes()[4:8] == b"\x00\x00\x00\x00"


def test_precompress_gzip_header_is_deterministic(
    tmp_path: Path, precompress_mod: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Gzip siblings must not embed the wall clock (reproducible builds)."""
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    min_bytes = int(precompress_mod.MIN_BYTES)  # type: ignore[attr-defined]
    root = tmp_path / "dist"
    root.mkdir()
    path = root / "app.js"
    path.write_text("x" * (min_bytes + 10), encoding="utf-8")
    assert precompress_mod.precompress(root) >= 1  # type: ignore[attr-defined]
    first = (root / "app.js.gz").read_bytes()
    (root / "app.js.gz").unlink()
    br = root / "app.js.br"
    if br.is_file():
        br.unlink()
    assert precompress_mod.precompress(root) >= 1  # type: ignore[attr-defined]
    second = (root / "app.js.gz").read_bytes()
    assert first == second
    # Bytes 4-7 of a gzip member are the little-endian mtime; 0 is reproducible.
    assert first[4:8] == b"\x00\x00\x00\x00"


def test_gzip_mtime_honours_source_date_epoch(
    precompress_mod: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    assert precompress_mod.gzip_mtime() == 1700000000  # type: ignore[attr-defined]
    monkeypatch.delenv("SOURCE_DATE_EPOCH")
    assert precompress_mod.gzip_mtime() == 0  # type: ignore[attr-defined]


def test_gzip_mtime_rejects_invalid_source_date_epoch(
    precompress_mod: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "not-a-number")
    assert precompress_mod.gzip_mtime() == 0  # type: ignore[attr-defined]
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "-1")
    assert precompress_mod.gzip_mtime() == 0  # type: ignore[attr-defined]


def test_precompress_removes_stale_brotli_when_unavailable(
    tmp_path: Path, precompress_mod: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A leftover ``.br`` from a host that had brotli must not survive without it."""
    monkeypatch.setattr(precompress_mod, "brotli_bin", lambda: None)
    min_bytes = int(precompress_mod.MIN_BYTES)  # type: ignore[attr-defined]
    root = tmp_path / "dist"
    root.mkdir()
    path = root / "app.js"
    path.write_text("x" * (min_bytes + 10), encoding="utf-8")
    stale = root / "app.js.br"
    stale.write_bytes(b"stale-brotli")
    assert precompress_mod.precompress(root) >= 1  # type: ignore[attr-defined]
    assert (root / "app.js.gz").is_file()
    assert not stale.exists()


def test_reportal_brotli_zero_disables_cli(
    precompress_mod: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``REPORTAL_BROTLI=0`` forces gzip-only even when a brotli binary exists."""
    monkeypatch.setenv("REPORTAL_BROTLI", "0")
    monkeypatch.setattr(precompress_mod.shutil, "which", lambda _name: "/usr/bin/brotli")
    assert precompress_mod.brotli_bin() is None  # type: ignore[attr-defined]
    monkeypatch.delenv("REPORTAL_BROTLI")
    assert precompress_mod.brotli_bin() == "/usr/bin/brotli"  # type: ignore[attr-defined]
