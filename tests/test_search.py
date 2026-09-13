"""Tests for the typed search backend and ``GET /api/search``."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import api, cli, store
from reportal._paths import DB_ENV

runner = CliRunner()

# Two binaries whose hashes share an eight-character prefix, so the hash query
# has a genuinely ambiguous prefix to refuse.
SHARED_PREFIX = "abababab"
HASH_A = "ab" * 32
HASH_B = "ab" * 31 + "cd"
HASH_C = "cd" * 32


def _seed(conn: sqlite3.Connection) -> dict[str, int]:
    """Store one binary of every kind, two sharing a hash prefix."""
    alpha = store.add_binary(
        conn,
        sha256=HASH_A,
        name="alpha.dll",
        path="/samples/alpha.dll",
        size=2048,
        fmt="PE",
        arch="x86_32",
    )
    beta = store.add_binary(
        conn, sha256=HASH_B, name="beta.exe", path="/samples/beta.exe", size=4096
    )
    store.add_binary(conn, sha256=HASH_C, name="gamma.sys", path="/elsewhere/gamma.sys", size=512)
    analysis = store.create_analysis(conn, binary_id=alpha, engine="manual")
    store.add_function(conn, analysis_id=analysis, va=0x1000, name="parse_alpha")
    collection = store.create_collection(conn, name="alpha collection", description="alpha samples")
    store.add_collection_binary(conn, collection, alpha)
    tag = store.create_tag(conn, "alpha-tag")
    store.add_binary_tag(conn, alpha, tag)
    return {"alpha": alpha, "beta": beta, "collection": collection, "tag": tag}


class TestSearchKinds:
    def test_default_substring_spans_entities(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        results = store.search(conn, "alpha")
        assert [row["name"] for row in results["binaries"]] == ["alpha.dll"]
        assert [row["name"] for row in results["functions"]] == ["parse_alpha"]
        assert [row["name"] for row in results["collections"]] == ["alpha collection"]
        assert [row["name"] for row in results["tags"]] == ["alpha-tag"]

    def test_default_matches_a_path(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        results = store.search(conn, "elsewhere")
        assert [row["name"] for row in results["binaries"]] == ["gamma.sys"]
        assert results["binaries"][0]["match"] == "path"

    def test_default_matches_a_hash_substring(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        results = store.search(conn, HASH_C)
        assert [row["name"] for row in results["binaries"]] == ["gamma.sys"]
        assert results["binaries"][0]["match"] == "sha256"

    def test_binary_kind_matches_the_name_only(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        results = store.search(conn, "alpha", kind=store.SEARCH_KIND_BINARY)
        assert [row["name"] for row in results["binaries"]] == ["alpha.dll"]
        assert results["functions"] == []
        assert results["collections"] == []

    def test_collection_kind_matches_the_name(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        results = store.search(conn, "alpha", kind=store.SEARCH_KIND_COLLECTION)
        assert [row["name"] for row in results["collections"]] == ["alpha collection"]
        assert results["binaries"] == []

    def test_collection_kind_ignores_the_description(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        results = store.search(conn, "samples", kind=store.SEARCH_KIND_COLLECTION)
        assert results["collections"] == []

    def test_tag_kind_returns_the_tag_and_its_binaries(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        results = store.search(conn, "alpha-tag", kind=store.SEARCH_KIND_TAG)
        assert [row["name"] for row in results["tags"]] == ["alpha-tag"]
        assert [row["name"] for row in results["binaries"]] == ["alpha.dll"]
        assert results["binaries"][0]["match"] == "tag"
        assert results["tags"][0]["binary_count"] == 1

    def test_sha256_kind_accepts_a_full_hash(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        results = store.search(conn, HASH_C, kind=store.SEARCH_KIND_SHA256)
        assert [row["name"] for row in results["binaries"]] == ["gamma.sys"]
        assert results["binaries"][0]["match"] == "sha256"

    def test_sha256_kind_accepts_an_unambiguous_prefix(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        results = store.search(conn, "cdcdcdcd", kind=store.SEARCH_KIND_SHA256)
        assert [row["name"] for row in results["binaries"]] == ["gamma.sys"]

    def test_sha256_kind_is_case_insensitive(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        results = store.search(conn, "CDCDCDCD", kind=store.SEARCH_KIND_SHA256)
        assert [row["name"] for row in results["binaries"]] == ["gamma.sys"]


class TestSearchRefusals:
    def test_short_hash_prefix_is_refused(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        with pytest.raises(store.SearchError) as caught:
            store.search(conn, "ababab", kind=store.SEARCH_KIND_SHA256)
        assert caught.value.code == "short-hash"

    def test_ambiguous_hash_prefix_is_refused(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        with pytest.raises(store.SearchError) as caught:
            store.search(conn, SHARED_PREFIX, kind=store.SEARCH_KIND_SHA256)
        assert caught.value.code == "ambiguous-hash"
        assert "2 binaries" in caught.value.detail

    def test_non_hex_hash_is_refused(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        with pytest.raises(store.SearchError) as caught:
            store.search(conn, "nothexatall", kind=store.SEARCH_KIND_SHA256)
        assert caught.value.code == "invalid-hash"

    def test_overlong_hash_is_refused(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        with pytest.raises(store.SearchError) as caught:
            store.search(conn, "a" * 65, kind=store.SEARCH_KIND_SHA256)
        assert caught.value.code == "invalid-hash"

    def test_unknown_kind_is_refused(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(store.SearchError) as caught:
            store.search(conn, "x", kind="nonsense")
        assert caught.value.code == "invalid-kind"


class TestSearchMetadata:
    def test_binary_rows_carry_size_format_arch_and_tags(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        row = store.search(conn, "alpha.dll")["binaries"][0]
        assert row["size"] == 2048
        assert row["format"] == "PE"
        assert row["arch"] == "x86_32"
        assert row["created_at"]
        assert row["tags"] == ["alpha-tag"]

    def test_collection_rows_carry_the_member_count(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        row = store.search(conn, "alpha", kind=store.SEARCH_KIND_COLLECTION)["collections"][0]
        assert row["binary_count"] == 1

    def test_counts_are_exact_under_a_limit(self, conn: sqlite3.Connection) -> None:
        for index in range(3):
            store.add_binary(conn, sha256=f"{index:02x}" * 32, name=f"shared-{index}.bin")
        results = store.search(conn, "shared", limit=1)
        assert len(results["binaries"]) == 1
        assert results["counts"]["binaries"] == {"count": 1, "total": 3}

    def test_empty_query_answers_every_group_empty(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        results = store.search(conn, "   ")
        assert results["binaries"] == []
        assert results["tags"] == []
        assert results["counts"]["binaries"] == {"count": 0, "total": 0}


class TestSearchRoute:
    def test_default_route_still_finds_entities(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        _, headers, body = wsgi_request("GET", "/api/search?q=alpha")
        payload = json_body(body, headers)
        assert payload["kind"] == store.SEARCH_KIND_ALL
        assert [row["name"] for row in payload["binaries"]] == ["alpha.dll"]
        assert [row["name"] for row in payload["tags"]] == ["alpha-tag"]

    def test_hash_kind_route(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        _, headers, body = wsgi_request("GET", f"/api/search?q={HASH_C}&kind=sha256")
        payload = json_body(body, headers)
        assert [row["name"] for row in payload["binaries"]] == ["gamma.sys"]

    def test_ambiguous_prefix_route_is_400(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        status, headers, body = wsgi_request("GET", f"/api/search?q={SHARED_PREFIX}&kind=sha256")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "ambiguous-hash"

    def test_unknown_kind_route_is_400(self, conn: sqlite3.Connection) -> None:
        status, headers, body = wsgi_request("GET", "/api/search?q=x&kind=nonsense")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid-kind"

    def test_limit_is_bounded(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        status, headers, body = wsgi_request("GET", "/api/search?q=alpha&limit=0")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid limit"
        _, headers, body = wsgi_request("GET", "/api/search?q=alpha&limit=1")
        assert json_body(body, headers)["counts"]["binaries"] == {"count": 1, "total": 1}

    def test_no_query_answers_empty_groups(self, portal_db: Path) -> None:
        _, headers, body = wsgi_request("GET", "/api/search")
        payload = json_body(body, headers)
        assert payload["binaries"] == [] and payload["tags"] == []

    def test_response_body_is_json_serializable(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        _, headers, body = wsgi_request("GET", "/api/search?q=alpha")
        assert json.loads(json.dumps(json_body(body, headers)))["query"] == "alpha"


# ── The regular-expression search and the any-of string filter ─────


class TestRegexSearch:
    def test_a_pattern_matches_where_a_substring_would_not(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        literal = store.search(conn, "alpha.dll")
        assert [row["name"] for row in literal["binaries"]] == ["alpha.dll"]
        patterned = store.search(conn, r"^(alpha|gamma)\..*$", regex=True)
        assert [row["name"] for row in patterned["binaries"]] == ["alpha.dll", "gamma.sys"]
        assert patterned["functions"] == []

    def test_a_function_name_is_matched_and_labeled(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        results = store.search(conn, r"parse_.*", kind=store.SEARCH_KIND_ALL, regex=True)
        assert [row["name"] for row in results["functions"]] == ["parse_alpha"]

    def test_every_typed_kind_takes_a_pattern(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        for kind, key in (
            (store.SEARCH_KIND_BINARY, "binaries"),
            (store.SEARCH_KIND_COLLECTION, "collections"),
            (store.SEARCH_KIND_TAG, "tags"),
        ):
            results = store.search(conn, "alpha", kind=kind, regex=True)
            assert results[key], kind

    def test_a_bad_pattern_is_refused(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(store.SearchError) as caught:
            store.search(conn, "(", regex=True)
        assert caught.value.code == "invalid regex"
        assert store.search(conn, "", regex=True)["functions"] == []
        with pytest.raises(store.SearchError):
            store.search(conn, "x" * (store.MAX_REGEX_CHARS + 1), regex=True)

    def test_a_hash_prefix_is_never_a_pattern(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(store.SearchError) as caught:
            store.search(conn, HASH_A, kind=store.SEARCH_KIND_SHA256, regex=True)
        assert caught.value.code == "invalid regex"

    def test_the_compiled_pattern_is_cached(self) -> None:
        first = store.compile_regex("alpha.*")
        assert store.compile_regex("alpha.*") is first
        for index in range(store.REGEX_CACHE_SIZE + 2):
            store.compile_regex(f"pattern-{index}")
        assert len(store._REGEX_CACHE) <= store.REGEX_CACHE_SIZE

    def test_the_route_takes_the_pattern_flag(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        status, headers, body = wsgi_request("GET", "/api/search?q=%5Ebeta&regex=true")
        assert status.startswith("200"), body
        payload = json_body(body, headers)
        assert payload["regex"] is True
        assert [row["name"] for row in payload["binaries"]] == ["beta.exe"]

        bad, headers, body = wsgi_request("GET", "/api/search?q=(&regex=true")
        assert bad.startswith("400")
        assert json_body(body, headers)["error"] == "invalid regex"


class TestStringFilter:
    def _filtered(self, conn: sqlite3.Connection, *needles: str, regex: bool = False) -> Any:
        return store.list_functions(conn, analysis_id=1, strings=list(needles), regex=regex)

    def test_several_needles_are_any_of(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        store.set_decompilation(conn, 1, 'char *a = "alpha";', "kuna")
        other = store.add_function(conn, analysis_id=1, va=0x2000, name="other")
        store.set_decompilation(conn, other, 'char *b = "beta";', "kuna")
        assert [row["id"] for row in self._filtered(conn, "alpha")] == [1]
        assert [row["id"] for row in self._filtered(conn, "beta")] == [other]
        assert sorted(row["id"] for row in self._filtered(conn, "alpha", "beta")) == [1, other]
        assert self._filtered(conn, "gamma") == []

    def test_a_pattern_filter_matches_the_text(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        store.set_decompilation(conn, 1, 'char *a = "alpha-42";', "kuna")
        assert [row["id"] for row in self._filtered(conn, r"alpha-\d+", regex=True)] == [1]
        assert self._filtered(conn, r"alpha-\d+") == []

    def test_a_bad_pattern_filter_is_refused(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(store.SearchError) as caught:
            self._filtered(conn, "(", regex=True)
        assert caught.value.code == "invalid regex"

    def test_the_route_takes_repeated_strings(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        store.set_decompilation(conn, 1, 'char *a = "alpha";', "kuna")
        other = store.add_function(conn, analysis_id=1, va=0x2000, name="other")
        store.set_decompilation(conn, other, 'char *b = "beta";', "kuna")
        url = "/api/binaries/1/functions?string=alpha&string=beta"
        status, headers, body = wsgi_request("GET", url)
        assert status.startswith("200"), body
        assert sorted(row["id"] for row in json_body(body, headers)["functions"]) == [1, other]

        # A pattern the literal search cannot match: `al.ha` needs the dot.
        patterned, headers, body = wsgi_request(
            "GET", "/api/binaries/1/functions?string=al.ha&regex=true"
        )
        assert patterned.startswith("200"), body
        assert [row["id"] for row in json_body(body, headers)["functions"]] == [1]

        bad, headers, body = wsgi_request("GET", "/api/binaries/1/functions?string=(&regex=true")
        assert bad.startswith("400")
        assert json_body(body, headers)["error"] == "invalid regex"

    def test_the_route_bounds_the_needle_count(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        params = "&".join(f"string=n{index}" for index in range(api.MAX_FUNCTION_STRINGS + 1))
        status, headers, body = wsgi_request("GET", f"/api/binaries/1/functions?{params}")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid string"


class TestSearchCli:
    def test_the_command_lists_every_group(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        payload = json.loads(runner.invoke(cli.app, ["search", "alpha", "--json"]).output)
        assert payload["query"] == "alpha"
        assert [row["name"] for row in payload["binaries"]] == ["alpha.dll"]

        human = runner.invoke(cli.app, ["search", "alpha"])
        assert human.exit_code == 0, human.output
        assert "alpha.dll" in human.output

        nothing = runner.invoke(cli.app, ["search", "nothing-matches-this"])
        assert nothing.exit_code == 0
        assert "Nothing matched" in nothing.output

    def test_the_command_takes_a_pattern_and_a_kind(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        patterned = runner.invoke(
            cli.app, ["search", "^(alpha|beta)", "--regex", "--kind", "binary", "--json"]
        )
        assert patterned.exit_code == 0, patterned.output
        assert [row["name"] for row in json.loads(patterned.output)["binaries"]] == [
            "alpha.dll",
            "beta.exe",
        ]

        bad = runner.invoke(cli.app, ["search", "(", "--regex"])
        assert bad.exit_code == 1
        assert "invalid regex" in bad.output

    def test_the_command_fails_without_a_database(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "missing" / "portal.db"))
        result = runner.invoke(cli.app, ["search", "alpha"])
        assert result.exit_code == 1
        assert "no reportal database" in result.output
