"""Tests for the in-app documentation browser: the reader, the routes and the tools.

The reader is the interesting part: it turns a document into blocks, and the
tests pin the subset it claims (headings, paragraphs, fenced code, lists with
their depth, quotes and tables) plus the two refusals that keep a page honest
(no directory, no such slug).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import cli, docs, mcp_server, mcp_tools
from reportal._paths import DB_ENV

runner = CliRunner()

SAMPLE = """# A page

Intro paragraph that
wraps over two lines.

## Section one

- first
  - nested
- second

1. one
2. two

```python
print("hi")
```

> a quote
> over two lines

| Name | Value |
| ---- | ----- |
| a | 1 |

### Closing
"""


def _workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A workspace whose docs/ directory holds two pages and a changelog."""
    root = tmp_path / "ws"
    (root / "docs").mkdir(parents=True)
    (root / "docs" / "alpha.md").write_text(SAMPLE, encoding="utf-8")
    (root / "docs" / "beta.md").write_text("# Beta\n\nBody.\n", encoding="utf-8")
    (root / "CHANGELOG.md").write_text("# Changelog\n\n## 9.9.9\n\nA note.\n", encoding="utf-8")
    (root / "reportal.toml").write_text("", encoding="utf-8")
    monkeypatch.chdir(root)
    monkeypatch.delenv(docs.DOCS_ENV, raising=False)
    return root


class TestDirectory:
    def test_the_workspace_docs_directory_resolves(self, tmp_path: Path, monkeypatch: Any) -> None:
        root = _workspace(tmp_path, monkeypatch)
        assert docs.documents_dir() == root / "docs"
        assert docs.changelog_path() == root / "CHANGELOG.md"

    def test_an_explicit_override_wins(self, tmp_path: Path, monkeypatch: Any) -> None:
        _workspace(tmp_path, monkeypatch)
        other = tmp_path / "elsewhere"
        other.mkdir()
        monkeypatch.setenv(docs.DOCS_ENV, str(other))
        assert docs.documents_dir() == other
        # No docs/ inside the override, so there is no changelog beside it either.
        assert docs.changelog_path() is None

    def test_an_override_that_is_not_a_directory_resolves_to_nothing(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        monkeypatch.setenv(docs.DOCS_ENV, str(tmp_path / "missing"))
        assert docs.documents_dir() is None
        with pytest.raises(docs.NoDocsError):
            docs.pages()

    def test_the_packaged_manual_is_the_last_fallback(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """A wheel install has no checkout docs/; package-data `manual/` still serves."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv(docs.DOCS_ENV, raising=False)
        packaged = tmp_path / "site-packages" / "reportal" / docs.PACKAGED_MANUAL
        packaged.mkdir(parents=True)
        (packaged / "guide.md").write_text("# Guide\n\nBody.\n", encoding="utf-8")
        (packaged / "CHANGELOG.md").write_text("# Changelog\n\n## 1.0\n", encoding="utf-8")
        docs_py = tmp_path / "site-packages" / "reportal" / "docs.py"
        monkeypatch.setattr(docs, "__file__", str(docs_py))
        assert docs.documents_dir() == packaged
        assert [page["slug"] for page in docs.pages()] == ["guide", "changelog"]

    def test_the_changelog_is_the_last_page(self, tmp_path: Path, monkeypatch: Any) -> None:
        _workspace(tmp_path, monkeypatch)
        listing = docs.pages()
        assert [page["slug"] for page in listing] == ["alpha", "beta", "changelog"]
        assert listing[1]["title"] == "Beta"
        assert listing[2]["title"] == "Changelog"


class TestBlocks:
    def test_every_claimed_block_kind_is_parsed(self) -> None:
        parsed = docs.blocks(SAMPLE)
        kinds = [block["kind"] for block in parsed]
        assert kinds.count("code") == 1
        assert kinds.count("table") == 1
        assert kinds.count("quote") == 1
        assert kinds.count("list") == 2
        assert kinds.count("heading") == 2

    def test_the_title_heading_is_not_repeated_as_a_block(self) -> None:
        parsed = docs.blocks(SAMPLE)
        assert all(block.get("text") != "A page" for block in parsed)

    def test_a_paragraph_keeps_its_wrapped_lines(self) -> None:
        paragraph = docs.blocks(SAMPLE)[0]
        assert paragraph["text"] == "Intro paragraph that\nwraps over two lines."

    def test_a_fence_closes_on_its_own_marker(self) -> None:
        text = "```python\n~~~\nnot closed\n```\nafter\n"
        parsed = docs.blocks(text)
        assert parsed[0] == {"kind": "code", "lang": "python", "text": "~~~\nnot closed"}

    def test_a_list_keeps_each_items_depth(self) -> None:
        lists = [block for block in docs.blocks(SAMPLE) if block["kind"] == "list"]
        unordered = lists[0]
        assert unordered["ordered"] is False
        assert [item["depth"] for item in unordered["items"]] == [0, 1, 0]
        assert lists[1]["ordered"] is True

    def test_a_table_needs_its_separator_row(self) -> None:
        parsed = docs.blocks("| a | b |\n| c | d |\n")
        assert parsed[0]["kind"] == "paragraph"

    def test_a_table_keeps_its_header_and_rows(self) -> None:
        table = [block for block in docs.blocks(SAMPLE) if block["kind"] == "table"][0]
        assert table["header"] == ["Name", "Value"]
        assert table["rows"] == [["a", "1"]]

    def test_a_quote_is_one_run(self) -> None:
        quote = [block for block in docs.blocks(SAMPLE) if block["kind"] == "quote"][0]
        assert quote["text"] == "a quote over two lines"

    def test_an_unknown_construct_becomes_a_paragraph(self) -> None:
        parsed = docs.blocks("<!-- a comment -->\n")
        assert parsed == [{"kind": "paragraph", "text": "<!-- a comment -->"}]

    def test_headings_carry_unique_anchors(self) -> None:
        parsed = docs.blocks("## Same\n\n## Same\n")
        found = docs.headings(parsed)
        assert [entry["id"] for entry in found] == ["same", "same-1"]
        assert found[0]["level"] == "2"


class TestPage:
    def test_a_page_carries_its_title_headings_and_blocks(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        page = docs.page("alpha")
        assert page["title"] == "A page"
        assert page["source"] == "alpha.md"
        assert [entry["text"] for entry in page["headings"]] == ["Section one", "Closing"]

    def test_the_slug_is_case_insensitive(self, tmp_path: Path, monkeypatch: Any) -> None:
        _workspace(tmp_path, monkeypatch)
        assert docs.page("ALPHA")["title"] == "A page"

    def test_the_changelog_is_reachable_by_slug(self, tmp_path: Path, monkeypatch: Any) -> None:
        _workspace(tmp_path, monkeypatch)
        assert docs.page("changelog")["title"] == "Changelog"

    @pytest.mark.parametrize("slug", ["nope", "", "  ", "../alpha", ".hidden", "docs/alpha"])
    def test_a_slug_that_is_not_a_page_is_refused(
        self, tmp_path: Path, monkeypatch: Any, slug: str
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        with pytest.raises(docs.DocsError) as failure:
            docs.page(slug)
        assert failure.value.code in (docs.ERROR_NO_DOC, docs.ERROR_NO_DOCS)

    def test_a_missing_directory_is_no_docs(self, tmp_path: Path, monkeypatch: Any) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv(docs.DOCS_ENV, str(tmp_path / "missing"))
        with pytest.raises(docs.NoDocsError) as failure:
            docs.page("alpha")
        assert failure.value.code == docs.ERROR_NO_DOCS


class TestRoutes:
    def _seed(self, tmp_path: Path, monkeypatch: Any) -> None:
        _workspace(tmp_path, monkeypatch)
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))

    def test_the_index_lists_the_pages(self, tmp_path: Path, monkeypatch: Any) -> None:
        self._seed(tmp_path, monkeypatch)
        status, headers, body = wsgi_request("GET", "/api/docs")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["count"] == 3
        assert {page["slug"] for page in payload["pages"]} == {"alpha", "beta", "changelog"}

    def test_one_page_is_blocks_not_markup(self, tmp_path: Path, monkeypatch: Any) -> None:
        self._seed(tmp_path, monkeypatch)
        status, headers, body = wsgi_request("GET", "/api/docs/alpha")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["title"] == "A page"
        assert payload["headings"][0]["text"] == "Section one"
        assert all("html" not in block for block in payload["blocks"])

    def test_an_unknown_slug_is_404(self, tmp_path: Path, monkeypatch: Any) -> None:
        self._seed(tmp_path, monkeypatch)
        status, headers, body = wsgi_request("GET", "/api/docs/nope")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == docs.ERROR_NO_DOC

    def test_no_directory_is_404_no_docs(self, tmp_path: Path, monkeypatch: Any) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        monkeypatch.setenv(docs.DOCS_ENV, str(tmp_path / "missing"))
        status, _headers, body = wsgi_request("GET", "/api/docs")
        assert status.startswith("404")
        assert json.loads(body)["error"] == docs.ERROR_NO_DOCS


class TestMcp:
    def test_the_two_reads_answer(self, tmp_path: Path, monkeypatch: Any) -> None:
        _workspace(tmp_path, monkeypatch)
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        listing, failed = mcp_server.call_tool("list_docs", {})
        assert failed is False
        assert listing["count"] == 3
        page, failed = mcp_server.call_tool("get_doc", {"slug": "alpha"})
        assert failed is False
        assert page["title"] == "A page"

    def test_an_unknown_slug_is_a_tool_error(self, tmp_path: Path, monkeypatch: Any) -> None:
        _workspace(tmp_path, monkeypatch)
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        payload, failed = mcp_server.call_tool("get_doc", {"slug": "nope"})
        assert failed is True
        assert payload["error"] == docs.ERROR_NO_DOC

    def test_both_are_read_only(self) -> None:
        by_name = {tool.name: tool for tool in mcp_tools.tools()}
        for name in ("list_docs", "get_doc"):
            assert by_name[name].annotations.read_only_hint is True


class TestCli:
    def test_the_index_prints_a_table(self, tmp_path: Path, monkeypatch: Any) -> None:
        _workspace(tmp_path, monkeypatch)
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        result = runner.invoke(cli.app, ["docs"])
        assert result.exit_code == 0
        assert "alpha" in result.output
        assert "A page" in result.output

    def test_the_index_answers_json(self, tmp_path: Path, monkeypatch: Any) -> None:
        _workspace(tmp_path, monkeypatch)
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        result = runner.invoke(cli.app, ["docs", "--json"])
        assert result.exit_code == 0
        assert json.loads(result.stdout)["count"] == 3

    def test_one_page_prints_its_blocks(self, tmp_path: Path, monkeypatch: Any) -> None:
        _workspace(tmp_path, monkeypatch)
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        result = runner.invoke(cli.app, ["docs", "alpha"])
        assert result.exit_code == 0
        assert "Section one" in result.output
        assert 'print("hi")' in result.output
        assert "Name | Value" in result.output

    def test_the_changelog_command_prints_it(self, tmp_path: Path, monkeypatch: Any) -> None:
        _workspace(tmp_path, monkeypatch)
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        result = runner.invoke(cli.app, ["changelog"])
        assert result.exit_code == 0
        assert "9.9.9" in result.output

    def test_an_unknown_slug_fails_loud(self, tmp_path: Path, monkeypatch: Any) -> None:
        _workspace(tmp_path, monkeypatch)
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        result = runner.invoke(cli.app, ["docs", "nope"])
        assert result.exit_code == 1
        assert docs.ERROR_NO_DOC in result.output


class TestNeighbours:
    """The reading-order pair a page carries, which the pager renders."""

    def test_the_first_page_has_no_previous(self, tmp_path: Path, monkeypatch: Any) -> None:
        _workspace(tmp_path, monkeypatch)

        page = docs.page("alpha")

        assert page["previous"] is None
        assert page["next"] == {"slug": "beta", "title": "Beta"}

    def test_a_middle_page_has_both(self, tmp_path: Path, monkeypatch: Any) -> None:
        _workspace(tmp_path, monkeypatch)

        page = docs.page("beta")

        assert page["previous"] == {"slug": "alpha", "title": "A page"}
        assert page["next"] == {"slug": "changelog", "title": "Changelog"}

    def test_the_last_page_is_the_changelog_with_no_next(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        _workspace(tmp_path, monkeypatch)

        page = docs.page("changelog")

        assert page["next"] is None
        assert page["previous"] == {"slug": "beta", "title": "Beta"}

    def test_the_slug_is_case_insensitive(self, tmp_path: Path, monkeypatch: Any) -> None:
        _workspace(tmp_path, monkeypatch)

        assert docs.page("ALPHA")["next"] == {"slug": "beta", "title": "Beta"}

    def test_a_lone_page_has_neither(self, tmp_path: Path, monkeypatch: Any) -> None:
        monkeypatch.chdir(tmp_path)
        root = tmp_path / "only"
        root.mkdir()
        (root / "solo.md").write_text("# Solo\n", encoding="utf-8")
        monkeypatch.setenv(docs.DOCS_ENV, str(root))

        page = docs.page("solo")

        assert page["previous"] is None
        assert page["next"] is None


class TestPagerSurfaces:
    def _seed(self, tmp_path: Path, monkeypatch: Any) -> None:
        _workspace(tmp_path, monkeypatch)
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))

    def test_the_route_carries_the_pair(self, tmp_path: Path, monkeypatch: Any) -> None:
        self._seed(tmp_path, monkeypatch)

        status, headers, body = wsgi_request("GET", "/api/docs/beta")
        payload = json_body(body, headers)

        assert status.startswith("200")
        assert payload["previous"]["slug"] == "alpha"
        assert payload["next"]["slug"] == "changelog"

    def test_the_mcp_tool_carries_the_pair(self, tmp_path: Path, monkeypatch: Any) -> None:
        self._seed(tmp_path, monkeypatch)

        page, failed = mcp_server.call_tool("get_doc", {"slug": "alpha"})

        assert failed is False
        assert page["next"]["slug"] == "beta"
        assert page["previous"] is None

    def test_the_command_names_the_next_page(self, tmp_path: Path, monkeypatch: Any) -> None:
        self._seed(tmp_path, monkeypatch)

        result = runner.invoke(cli.app, ["docs", "alpha"])

        assert result.exit_code == 0
        assert "Next: Beta (beta)" in result.output
