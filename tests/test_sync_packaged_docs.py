"""Packaged-manual sync mirrors docs/ into src/reportal/manual for the wheel."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from reportal.docs import CHANGELOG_FILE, PAGE_ORDER

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "sync_packaged_docs.py"


def _load() -> object:
    spec = importlib.util.spec_from_file_location("sync_packaged_docs", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _populate_required(docs_src: Path, changelog: Path) -> None:
    docs_src.mkdir(parents=True, exist_ok=True)
    for stem in PAGE_ORDER:
        (docs_src / f"{stem}.md").write_text(f"# {stem}\n", encoding="utf-8")
    changelog.write_text("# Changelog\n", encoding="utf-8")


def test_sync_copies_docs_and_changelog(tmp_path: Path) -> None:
    mod = _load()
    docs_src = tmp_path / "docs"
    changelog = tmp_path / "CHANGELOG.md"
    _populate_required(docs_src, changelog)
    dest = tmp_path / "manual"
    written = mod.sync(dest=dest, docs_src=docs_src, changelog=changelog)  # type: ignore[attr-defined]
    assert written == len(PAGE_ORDER) + 1
    assert (dest / "ERRORS.md").read_text(encoding="utf-8") == "# ERRORS\n"
    assert (dest / CHANGELOG_FILE).read_text(encoding="utf-8") == "# Changelog\n"
    assert mod.sync(dest=dest, docs_src=docs_src, changelog=changelog) == 0  # type: ignore[attr-defined]


def test_sync_removes_stale_pages(tmp_path: Path) -> None:
    mod = _load()
    docs_src = tmp_path / "docs"
    changelog = tmp_path / "CHANGELOG.md"
    _populate_required(docs_src, changelog)
    dest = tmp_path / "manual"
    dest.mkdir()
    (dest / "gone.md").write_text("# Gone\n", encoding="utf-8")
    mod.sync(dest=dest, docs_src=docs_src, changelog=changelog)  # type: ignore[attr-defined]
    assert (dest / "ERRORS.md").is_file()
    assert not (dest / "gone.md").exists()


def test_sync_refuses_incomplete_page_order(tmp_path: Path) -> None:
    mod = _load()
    docs_src = tmp_path / "docs"
    docs_src.mkdir()
    (docs_src / "ERRORS.md").write_text("# Errors\n", encoding="utf-8")
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text("# Changelog\n", encoding="utf-8")
    dest = tmp_path / "manual"
    assert mod.sync(dest=dest, docs_src=docs_src, changelog=changelog) == -1  # type: ignore[attr-defined]
    assert not dest.exists()
