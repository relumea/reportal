"""Unit tests for the SPA serving helpers: MIME types, path resolution."""

from __future__ import annotations

from pathlib import Path

import pytest

from reportal import ui
from reportal.server import JsonError


class TestMediaType:
    def test_known_suffixes(self) -> None:
        assert ui._media_type(Path("app.js")) == "text/javascript"
        assert ui._media_type(Path("app.mjs")) == "text/javascript"
        assert ui._media_type(Path("app.css")) == "text/css"
        assert ui._media_type(Path("icon.svg")) == "image/svg+xml"

    def test_unknown_suffix_is_octet_stream(self) -> None:
        assert ui._media_type(Path("blob.unknownext")) == "application/octet-stream"


class TestResolveUnder:
    def test_file_under_root_resolves(self, tmp_path: Path) -> None:
        target = tmp_path / "index.html"
        target.write_text("<html></html>", encoding="utf-8")
        assert ui._resolve_under(tmp_path, "index.html") == target.resolve()

    def test_escape_is_a_404(self, tmp_path: Path) -> None:
        (tmp_path / "index.html").write_text("x", encoding="utf-8")
        with pytest.raises(JsonError):
            ui._resolve_under(tmp_path, "../outside.txt")

    def test_missing_file_is_a_404(self, tmp_path: Path) -> None:
        with pytest.raises(JsonError):
            ui._resolve_under(tmp_path, "gone.html")

    def test_symlink_escape_is_a_404(self, tmp_path: Path) -> None:
        import os

        outside = tmp_path / "outside.txt"
        outside.write_text("x", encoding="utf-8")
        link = tmp_path / "sub"
        link.mkdir()
        target = link / "evil.html"
        try:
            os.symlink(outside, target)
        except OSError:
            pytest.skip("symlinks are not permitted here")
        with pytest.raises(JsonError):
            ui._resolve_under(link, "evil.html")
