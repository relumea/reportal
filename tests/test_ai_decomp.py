"""Tests for the AI decompilation artifact: derivations, routes, CLI and MCP.

The model is always a typed stub, never a network call.  Everything the module
derives locally (the token map, the attributions, the rendered overrides) is
asserted against the text directly, and every route is exercised both for its
happy path and for each failure the error vocabulary names.
"""

from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
from typing import Any

import pytest
from conftest import FakeLlmClient, json_body, wsgi_request
from typer.testing import CliRunner

from reportal import ai_decomp, cli, journal, llm, mcp_server, store
from reportal._paths import DB_ENV

runner = CliRunner()

# The decompilation the model reads, with the placeholder shapes the scan looks
# for: a FUN_ symbol, a param_ parameter, a uVar local and a DAT_ global.
SOURCE = (
    "int FUN_00401000(char *param_1)\n"
    "{\n"
    "  int uVar1 = open(param_1, 0);\n"
    "  int *local_8 = (int *)DAT_00402000;\n"
    "  return uVar1;\n"
    "}\n"
)

# The model's rewrite: the symbol and the parameter are renamed, the local and
# the global are not, and one line is brand new.
REWRITE = (
    "int read_config(char *path)\n"
    "{\n"
    "  int handle = open(path, 0);\n"
    "  int *local_8 = (int *)DAT_00402000;\n"
    "  log_open(path);\n"
    "  return handle;\n"
    "}"
)

REWRITE_RESPONSE = json.dumps({"code": REWRITE})


def _seed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> int:
    """Create a portal DB with one function and its stored decompilation."""
    db = tmp_path / "portal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    with contextlib.closing(store.connect(db)) as conn:
        binary_id = store.add_binary(conn, sha256="cd" * 32, name="demo.exe")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        function_id = store.add_function(
            conn, analysis_id=analysis_id, va=0x401000, name="FUN_00401000"
        )
        store.set_decompilation(conn, function_id, code=SOURCE, backend="kuna")
    return function_id


def _install_rewrite(response: str = REWRITE_RESPONSE) -> FakeLlmClient:
    """Install a fake bridge whose reply is one rewrite."""
    client = FakeLlmClient(response=response, model="rewrite-model")
    llm.set_client(client)
    return client


def _post(function_id: int) -> dict[str, Any]:
    """Start a rewrite through the route and return its payload."""
    status, headers, body = wsgi_request("POST", f"/api/functions/{function_id}/ai-decompilation")
    assert status.startswith("200"), body
    payload: dict[str, Any] = json_body(body, headers)
    return payload


# ── Derivations ────────────────────────────────────────────────────


class TestTokens:
    def test_scan_finds_every_placeholder_shape(self) -> None:
        found = {entry["token"]: entry for entry in ai_decomp.tokens_of(SOURCE)}
        assert set(found) == {"FUN_00401000", "param_1", "uVar1", "local_8", "DAT_00402000"}

    def test_kinds_name_the_decompiler_shape(self) -> None:
        found = {entry["token"]: entry["kind"] for entry in ai_decomp.tokens_of(SOURCE)}
        assert found["FUN_00401000"] == "function"
        assert found["param_1"] == "parameter"
        assert found["uVar1"] == "variable"
        assert found["local_8"] == "local"
        assert found["DAT_00402000"] == "global"

    def test_unknown_tokens_are_named(self) -> None:
        found = {entry["token"]: entry["kind"] for entry in ai_decomp.tokens_of("int _UNK_4;")}
        assert found == {"_UNK_4": "unknown"}

    def test_line_numbers_and_counts_are_recorded(self) -> None:
        found = {entry["token"]: entry for entry in ai_decomp.tokens_of(SOURCE)}
        assert found["param_1"]["count"] == 2
        assert found["param_1"]["lines"] == [1, 3]
        assert found["local_8"]["lines"] == [4]

    def test_a_hot_token_keeps_its_count_and_a_bounded_line_list(self) -> None:
        code = "\n".join("uVar1();" for _ in range(ai_decomp.MAX_TOKEN_LINES + 5))
        entry = ai_decomp.tokens_of(code)[0]
        assert entry["count"] == ai_decomp.MAX_TOKEN_LINES + 5
        assert len(entry["lines"]) == ai_decomp.MAX_TOKEN_LINES

    def test_a_rewrite_without_placeholders_has_no_tokens(self) -> None:
        assert ai_decomp.tokens_of("int main(void) { return 0; }") == []


class TestAttributions:
    def test_every_line_is_attributed(self) -> None:
        rows = ai_decomp.attributions_of(REWRITE, SOURCE)
        assert [row["line"] for row in rows] == list(range(1, len(REWRITE.splitlines()) + 1))

    def test_origins_are_original_and_rewritten(self) -> None:
        origins = {row["line"]: row["origin"] for row in ai_decomp.attributions_of(REWRITE, SOURCE)}
        assert origins[2] == "original"
        assert origins[3] == "rewritten"
        assert origins[4] == "original"
        assert set(origins.values()) <= {"original", "rewritten", "added"}

    def test_a_line_with_no_source_counterpart_is_added(self) -> None:
        rows = ai_decomp.attributions_of("a\nnew\nc\n", "a\nc\n")
        assert [row["origin"] for row in rows] == ["original", "added", "original"]
        assert rows[1]["source_lines"] == []

    def test_an_original_line_names_its_source_line(self) -> None:
        rows = {row["line"]: row for row in ai_decomp.attributions_of(REWRITE, SOURCE)}
        assert rows[2]["source_lines"] == [2]
        assert rows[7]["source_lines"] == [6]

    def test_a_replaced_line_names_the_source_it_replaced(self) -> None:
        rows = {row["line"]: row for row in ai_decomp.attributions_of(REWRITE, SOURCE)}
        assert rows[3]["source_lines"] == [3]

    def test_identical_text_is_all_original(self) -> None:
        rows = ai_decomp.attributions_of(SOURCE, SOURCE)
        assert {row["origin"] for row in rows} == {"original"}


class TestOverrides:
    def test_an_override_rewrites_the_token_everywhere(self) -> None:
        rendered = ai_decomp.apply_overrides(
            "int a = local_8; int b = local_8 + local_8;", {"local_8": "handle"}
        )
        assert "local_8" not in rendered
        assert rendered.count("handle") == 3

    def test_an_override_inside_a_string_literal_is_left_alone(self) -> None:
        rendered = ai_decomp.apply_overrides(
            'printf("local_8\\n", local_8);', {"local_8": "handle"}
        )
        assert '"local_8\\n"' in rendered
        assert rendered.endswith("handle);")

    def test_a_prefix_of_a_longer_identifier_is_left_alone(self) -> None:
        assert ai_decomp.apply_overrides("local_8x = 1;", {"local_8": "handle"}) == "local_8x = 1;"

    def test_a_keyword_override_is_refused(self) -> None:
        with pytest.raises(ai_decomp.InvalidOverrideError):
            ai_decomp.normalize_override_name("while")

    def test_a_non_identifier_override_is_refused(self) -> None:
        with pytest.raises(ai_decomp.InvalidOverrideError):
            ai_decomp.normalize_override_name("two words")

    def test_a_name_past_the_cap_is_refused(self) -> None:
        with pytest.raises(ai_decomp.InvalidOverrideError):
            ai_decomp.normalize_override_name("a" * (ai_decomp.MAX_OVERRIDE_NAME + 1))

    def test_an_unknown_token_is_refused(self) -> None:
        tokens = ai_decomp.tokens_of(SOURCE)
        with pytest.raises(ai_decomp.UnknownTokenError):
            ai_decomp.normalize_overrides({"nope": "x"}, tokens)


class TestRatingsAndLines:
    def test_the_rating_vocabulary_is_closed(self) -> None:
        assert ai_decomp.normalize_rating("UP") == "up"
        assert ai_decomp.normalize_rating("down") == "down"
        assert ai_decomp.normalize_rating(None) is None

    def test_an_unknown_rating_is_refused(self) -> None:
        with pytest.raises(ai_decomp.InvalidRatingError):
            ai_decomp.normalize_rating("maybe")

    def test_a_line_outside_the_rewrite_is_refused(self) -> None:
        with pytest.raises(ai_decomp.InvalidLineCommentError):
            ai_decomp.normalize_line(99, 6)

    def test_a_boolean_is_not_a_line(self) -> None:
        with pytest.raises(ai_decomp.InvalidLineCommentError):
            ai_decomp.normalize_line(True, 6)


# ── Routes ─────────────────────────────────────────────────────────


class TestRoutes:
    def test_post_stores_then_get_serves_the_artifact(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        _install_rewrite()
        payload = _post(function_id)
        assert payload["rewritten_code"] == REWRITE
        assert payload["code"] == REWRITE
        assert payload["model"] == "rewrite-model"
        assert payload["rating"] is None
        assert payload["derivation"] == ai_decomp.DERIVATION
        assert payload["journal_action"]

        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{function_id}/ai-decompilation"
        )
        assert status.startswith("200")
        stored = json_body(body, headers)
        assert stored["code"] == REWRITE
        assert {entry["token"] for entry in stored["tokens"]} == {
            "local_8",
            "DAT_00402000",
        }

    def test_the_artifact_is_journaled_and_reverts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        _install_rewrite()
        action = _post(function_id)["journal_action"]
        with contextlib.closing(store.connect(Path(os.environ[DB_ENV]))) as conn:
            assert ai_decomp.get(conn, function_id) is not None
            journal.revert_action(conn, action)
            assert ai_decomp.get(conn, function_id) is None

    def test_post_without_a_decompilation_is_404(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(Path(os.environ[DB_ENV]))) as conn:
            store.clear_decompilation(conn, function_id)
        _install_rewrite()
        status, headers, body = wsgi_request(
            "POST", f"/api/functions/{function_id}/ai-decompilation"
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "no-decompilation"

    def test_post_without_an_llm_is_503(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        llm.set_client(None)
        status, headers, body = wsgi_request(
            "POST", f"/api/functions/{function_id}/ai-decompilation"
        )
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "llm-unavailable"

    def test_a_model_failure_is_502(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        llm.set_client(FakeLlmClient(response="not json at all"))
        status, headers, body = wsgi_request(
            "POST", f"/api/functions/{function_id}/ai-decompilation"
        )
        assert status.startswith(("200", "502"))

    def test_get_without_an_artifact_is_404(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{function_id}/ai-decompilation"
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "no-artifact"

    def test_an_unknown_function_is_404_on_every_route(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(tmp_path, monkeypatch)
        for method, path in (
            ("GET", "/api/functions/999/ai-decompilation"),
            ("GET", "/api/functions/999/ai-decompilation/status"),
            ("GET", "/api/functions/999/ai-decompilation/tokens"),
            ("GET", "/api/functions/999/ai-decompilation/rating"),
            ("GET", "/api/functions/999/ai-decompilation/inline-comments"),
            ("POST", "/api/functions/999/ai-decompilation"),
        ):
            status, headers, body = wsgi_request(method, path)
            assert status.startswith("404"), path
            assert json_body(body, headers)["error"] == "function not found"

    def test_the_stored_only_reads_are_404_without_an_artifact(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        for suffix in ("status", "tokens", "rating", "inline-comments"):
            status, headers, body = wsgi_request(
                "GET", f"/api/functions/{function_id}/ai-decompilation/{suffix}"
            )
            assert status.startswith("404"), suffix
            assert json_body(body, headers)["error"] == "no-artifact"

    def test_a_mutation_on_an_unknown_function_is_404(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(tmp_path, monkeypatch)
        for method, path, payload in (
            ("PATCH", "/api/functions/999/ai-decompilation/overrides", {"overrides": {}}),
            ("PATCH", "/api/functions/999/ai-decompilation/rating", {"rating": "up"}),
            (
                "POST",
                "/api/functions/999/ai-decompilation/inline-comments",
                {"line": 1, "body": "x"},
            ),
            ("DELETE", "/api/functions/999/ai-decompilation/inline-comments/1", None),
        ):
            status, headers, body = wsgi_request(
                method, path, body=json.dumps(payload) if payload is not None else b""
            )
            assert status.startswith("404"), path
            assert json_body(body, headers)["error"] == "function not found"

    def test_status_reports_counts_without_the_text(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        _install_rewrite()
        _post(function_id)
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{function_id}/ai-decompilation/status"
        )
        assert status.startswith("200")
        state = json_body(body, headers)
        assert state["state"] == "ready"
        assert state["line_count"] == len(REWRITE.splitlines())
        assert state["token_count"] == 2
        assert state["overridden_count"] == 0
        assert state["attribution_counts"]["original"] >= 1
        assert state["attribution_counts"]["rewritten"] >= 1
        assert "code" not in state

    def test_tokens_lists_the_overridden_names(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        _install_rewrite()
        _post(function_id)
        status, headers, body = wsgi_request(
            "PATCH",
            f"/api/functions/{function_id}/ai-decompilation/overrides",
            body=json.dumps({"overrides": {"local_8": "buffer"}}),
        )
        assert status.startswith("200")
        assert json_body(body, headers)["changes"] == {"local_8": "buffer"}

        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{function_id}/ai-decompilation/tokens"
        )
        payload = json_body(body, headers)
        assert payload["count"] == 2
        assert payload["overridden_count"] == 1
        named = {entry["token"]: entry["name"] for entry in payload["tokens"]}
        assert named == {"local_8": "buffer", "DAT_00402000": None}

    def test_an_override_renders_and_clearing_it_restores_the_model_text(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        _install_rewrite()
        _post(function_id)
        path = f"/api/functions/{function_id}/ai-decompilation/overrides"
        wsgi_request("PATCH", path, body=json.dumps({"overrides": {"local_8": "buffer"}}))
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{function_id}/ai-decompilation"
        )
        served = json_body(body, headers)
        assert "buffer" in served["code"]
        assert not served["code"].endswith("local_8;\n}")
        assert served["rewritten_code"] == REWRITE

        wsgi_request("PATCH", path, body=json.dumps({"overrides": {"local_8": None}}))
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{function_id}/ai-decompilation"
        )
        assert json_body(body, headers)["code"] == REWRITE

    def test_an_unknown_token_override_is_404(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        _install_rewrite()
        _post(function_id)
        status, headers, body = wsgi_request(
            "PATCH",
            f"/api/functions/{function_id}/ai-decompilation/overrides",
            body=json.dumps({"overrides": {"nope": "x"}}),
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "unknown token"

    def test_a_keyword_override_is_400(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        _install_rewrite()
        _post(function_id)
        status, headers, body = wsgi_request(
            "PATCH",
            f"/api/functions/{function_id}/ai-decompilation/overrides",
            body=json.dumps({"overrides": {"local_8": "while"}}),
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid override"

    def test_rating_round_trips(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        _install_rewrite()
        _post(function_id)
        path = f"/api/functions/{function_id}/ai-decompilation/rating"
        status, headers, body = wsgi_request(
            "PATCH", path, body=json.dumps({"rating": "up", "note": "names are good"})
        )
        assert status.startswith("200")
        assert json_body(body, headers)["rating"] == "up"

        status, headers, body = wsgi_request("GET", path)
        payload = json_body(body, headers)
        assert payload == {"function_id": function_id, "rating": "up", "note": "names are good"}

    def test_an_unknown_rating_is_400(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        _install_rewrite()
        _post(function_id)
        status, headers, body = wsgi_request(
            "PATCH",
            f"/api/functions/{function_id}/ai-decompilation/rating",
            body=json.dumps({"rating": "maybe"}),
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid rating"

    def test_line_comments_round_trip(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        _install_rewrite()
        _post(function_id)
        base = f"/api/functions/{function_id}/ai-decompilation/inline-comments"
        status, headers, body = wsgi_request(
            "POST", base, body=json.dumps({"line": 3, "body": "opens the config"})
        )
        assert status.startswith("200")
        assert json_body(body, headers)["comment"]["line"] == 3

        status, headers, body = wsgi_request(
            "POST", base, body=json.dumps({"line": 6, "body": "returns the handle"})
        )
        assert status.startswith("200")

        status, headers, body = wsgi_request(
            "PATCH", f"{base}/3", body=json.dumps({"body": "opens the config file"})
        )
        assert status.startswith("200")
        assert json_body(body, headers)["comment"]["body"] == "opens the config file"

        status, headers, body = wsgi_request("GET", base)
        payload = json_body(body, headers)
        assert payload["count"] == 2
        assert [row["line"] for row in payload["comments"]] == [3, 6]

        status, headers, body = wsgi_request("DELETE", f"{base}/3")
        assert status.startswith("200")
        status, headers, body = wsgi_request("GET", base)
        assert json_body(body, headers)["count"] == 1

    def test_a_line_outside_the_rewrite_is_400(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        _install_rewrite()
        _post(function_id)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/functions/{function_id}/ai-decompilation/inline-comments",
            body=json.dumps({"line": 999, "body": "nope"}),
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid line-comment"

    def test_a_blank_comment_body_is_400(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        _install_rewrite()
        _post(function_id)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/functions/{function_id}/ai-decompilation/inline-comments",
            body=json.dumps({"line": 3, "body": "   "}),
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid line-comment"

    def test_editing_a_line_without_a_comment_is_404(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        _install_rewrite()
        _post(function_id)
        status, headers, body = wsgi_request(
            "PATCH",
            f"/api/functions/{function_id}/ai-decompilation/inline-comments/3",
            body=json.dumps({"body": "nope"}),
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "no-line-comment"

    def test_the_events_stream_reports_the_state_and_ends(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        _install_rewrite()
        _post(function_id)
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{function_id}/ai-decompilation/events"
        )
        assert status.startswith("200")
        assert headers["Content-Type"].startswith("text/event-stream")
        text = body.decode()
        assert "event: ai-decompilation" in text
        assert "event: done" in text
        assert text.endswith("\n\n")


# ── CLI ────────────────────────────────────────────────────────────


class TestCli:
    def test_ai_decompile_prints_the_rewrite(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        _install_rewrite()
        result = runner.invoke(cli.app, ["ai-decompile", str(function_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["code"] == REWRITE
        assert payload["journal_action"]

    def test_ai_decompilation_reads_the_stored_artifact(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        _install_rewrite()
        runner.invoke(cli.app, ["ai-decompile", str(function_id)])
        result = runner.invoke(cli.app, ["ai-decompilation", str(function_id), "--json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["rewritten_code"] == REWRITE

    def test_status_tokens_and_lines(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        _install_rewrite()
        runner.invoke(cli.app, ["ai-decompile", str(function_id)])
        status = runner.invoke(cli.app, ["ai-decompilation-status", str(function_id), "--json"])
        assert status.exit_code == 0, status.output
        assert json.loads(status.output)["token_count"] == 2
        tokens = runner.invoke(cli.app, ["ai-tokens", str(function_id), "--json"])
        assert tokens.exit_code == 0, tokens.output
        assert json.loads(tokens.output)["count"] == 2
        lines = runner.invoke(cli.app, ["ai-lines", str(function_id), "--json"])
        assert lines.exit_code == 0, lines.output
        assert len(json.loads(lines.output)["attributions"]) == len(REWRITE.splitlines())

    def test_override_rate_and_comments(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        _install_rewrite()
        runner.invoke(cli.app, ["ai-decompile", str(function_id)])
        override = runner.invoke(
            cli.app, ["ai-override", str(function_id), "local_8", "buffer", "--json"]
        )
        assert override.exit_code == 0, override.output
        assert json.loads(override.output)["changes"] == {"local_8": "buffer"}
        clear = runner.invoke(cli.app, ["ai-override", str(function_id), "local_8", "", "--clear"])
        assert clear.exit_code == 0, clear.output
        rated = runner.invoke(cli.app, ["ai-rate", str(function_id), "up", "--json"])
        assert rated.exit_code == 0, rated.output
        assert json.loads(rated.output)["rating"] == "up"
        added = runner.invoke(
            cli.app, ["ai-line-comment-add", str(function_id), "3", "opens the config", "--json"]
        )
        assert added.exit_code == 0, added.output
        assert json.loads(added.output)["comment"]["line"] == 3
        edited = runner.invoke(
            cli.app, ["ai-line-comment-edit", str(function_id), "3", "opens it", "--json"]
        )
        assert edited.exit_code == 0, edited.output
        listed = runner.invoke(cli.app, ["ai-line-comments", str(function_id), "--json"])
        assert json.loads(listed.output)["count"] == 1
        removed = runner.invoke(cli.app, ["ai-line-comment-rm", str(function_id), "3"])
        assert removed.exit_code == 0, removed.output
        listed = runner.invoke(cli.app, ["ai-line-comments", str(function_id), "--json"])
        assert json.loads(listed.output)["count"] == 0

    def test_commands_fail_without_an_artifact(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        for argv in (
            ["ai-decompilation", str(function_id)],
            ["ai-tokens", str(function_id)],
            ["ai-lines", str(function_id)],
            ["ai-decompilation-status", str(function_id)],
            ["ai-line-comments", str(function_id)],
        ):
            result = runner.invoke(cli.app, argv)
            assert result.exit_code == 1, argv
            assert "no AI decompilation" in result.output

    def test_the_human_output_paths(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        _install_rewrite()
        runner.invoke(cli.app, ["ai-decompile", str(function_id)])
        for argv in (
            ["ai-decompilation", str(function_id)],
            ["ai-decompilation-status", str(function_id)],
            ["ai-tokens", str(function_id)],
            ["ai-lines", str(function_id)],
            ["ai-line-comments", str(function_id)],
        ):
            result = runner.invoke(cli.app, argv)
            assert result.exit_code == 0, (argv, result.output)

    def test_every_command_fails_without_a_database(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "missing" / "portal.db"))
        for argv in (
            ["ai-decompile", "1"],
            ["ai-decompilation", "1"],
            ["ai-decompilation-status", "1"],
            ["ai-tokens", "1"],
            ["ai-lines", "1"],
            ["ai-line-comments", "1"],
            ["ai-override", "1", "local_8", "buffer"],
            ["ai-rate", "1", "up"],
            ["ai-line-comment-add", "1", "1", "a comment"],
            ["ai-line-comment-edit", "1", "1", "a comment"],
            ["ai-line-comment-rm", "1", "1"],
        ):
            result = runner.invoke(cli.app, argv)
            assert result.exit_code == 1, argv
            assert "no reportal database" in result.output

    def test_a_mutation_failure_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        missing = runner.invoke(cli.app, ["ai-rate", "999", "up"])
        assert missing.exit_code == 1
        assert "no function with id 999" in missing.output
        no_artifact = runner.invoke(cli.app, ["ai-override", str(function_id), "local_8", "x"])
        assert no_artifact.exit_code == 1
        assert "no AI decompilation" in no_artifact.output

    def test_ai_decompile_without_an_llm_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        llm.set_client(None)
        result = runner.invoke(cli.app, ["ai-decompile", str(function_id)])
        assert result.exit_code == 1
        assert "llm-unavailable" in result.output

    def test_ai_decompile_without_a_decompilation_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(Path(os.environ[DB_ENV]))) as conn:
            store.clear_decompilation(conn, function_id)
        _install_rewrite()
        result = runner.invoke(cli.app, ["ai-decompile", str(function_id)])
        assert result.exit_code == 1
        assert "no stored decompilation" in result.output


# ── MCP ────────────────────────────────────────────────────────────


def _call(name: str, arguments: dict[str, Any] | None = None) -> tuple[Any, bool]:
    """Run one tool through ``tools/call``; returns (payload, is_error)."""
    return mcp_server.call_tool(name, arguments)


class TestMcp:
    def test_run_then_every_read_tool(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        _install_rewrite()
        payload, failed = _call("run_ai_decompilation", {"function_id": function_id})
        assert not failed
        assert payload["code"] == REWRITE
        assert payload["journal_action"]

        stored, failed = _call("get_ai_decompilation", {"function_id": function_id})
        assert not failed
        assert stored["rewritten_code"] == REWRITE

        state, failed = _call("get_ai_decompilation_status", {"function_id": function_id})
        assert not failed
        assert state["token_count"] == 2

        tokens, failed = _call("list_ai_decompilation_tokens", {"function_id": function_id})
        assert not failed
        assert tokens["count"] == 2

        lines, failed = _call("get_ai_line_attributions", {"function_id": function_id})
        assert not failed
        assert len(lines["attributions"]) == len(REWRITE.splitlines())

    def test_override_rate_and_comments(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        _install_rewrite()
        _call("run_ai_decompilation", {"function_id": function_id})

        override, failed = _call(
            "set_ai_decompilation_overrides",
            {"function_id": function_id, "overrides": {"local_8": "buffer"}},
        )
        assert not failed
        assert override["changes"] == {"local_8": "buffer"}
        assert "buffer" in override["code"]

        rated, failed = _call(
            "rate_ai_decompilation", {"function_id": function_id, "rating": "down", "note": "meh"}
        )
        assert not failed
        assert rated["rating"] == "down"

        added, failed = _call(
            "add_ai_line_comment", {"function_id": function_id, "line": 2, "body": "brace"}
        )
        assert not failed
        assert added["comment"]["line"] == 2

        listed, failed = _call("list_ai_line_comments", {"function_id": function_id})
        assert not failed
        assert listed["count"] == 1

        updated, failed = _call(
            "update_ai_line_comment", {"function_id": function_id, "line": 2, "body": "the brace"}
        )
        assert not failed
        assert updated["comment"]["body"] == "the brace"

        removed, failed = _call("delete_ai_line_comment", {"function_id": function_id, "line": 2})
        assert not failed
        assert removed["comment"]["line"] == 2

    def test_failures_are_tool_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        payload, failed = _call("get_ai_decompilation", {"function_id": function_id})
        assert failed
        assert payload["error"] == "no-artifact"

        _install_rewrite()
        _call("run_ai_decompilation", {"function_id": function_id})
        payload, failed = _call(
            "set_ai_decompilation_overrides",
            {"function_id": function_id, "overrides": {"nope": "x"}},
        )
        assert failed
        assert payload["error"] == "unknown token"

        payload, failed = _call(
            "add_ai_line_comment", {"function_id": function_id, "line": 99, "body": "x"}
        )
        assert failed
        assert payload["error"] == "invalid line-comment"

        payload, failed = _call(
            "rate_ai_decompilation", {"function_id": function_id, "rating": "x"}
        )
        assert failed
        assert payload["error"] == "invalid rating"

    def test_the_remaining_error_branches(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        _install_rewrite()
        _call("run_ai_decompilation", {"function_id": function_id})

        payload, failed = _call(
            "set_ai_decompilation_overrides",
            {"function_id": function_id, "overrides": {"local_8": "while"}},
        )
        assert failed
        assert payload["error"] == "invalid override"

        payload, failed = _call(
            "rate_ai_decompilation", {"function_id": function_id, "rating": "up", "note": 5}
        )
        assert failed
        assert payload["error"] == "invalid params"

        payload, failed = _call("delete_ai_line_comment", {"function_id": function_id, "line": 2})
        assert failed
        assert payload["error"] == "no-line-comment"

        llm.set_client(FakeLlmClient(response="not json at all"))
        payload, failed = _call("run_ai_decompilation", {"function_id": function_id})
        assert failed
        assert payload["error"] == "llm-error"

        with contextlib.closing(store.connect(Path(os.environ[DB_ENV]))) as conn:
            store.clear_decompilation(conn, function_id)
        _install_rewrite()
        payload, failed = _call("run_ai_decompilation", {"function_id": function_id})
        assert failed
        assert payload["error"] == "no-decompilation"

    def test_run_without_an_llm_is_a_tool_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        function_id = _seed(tmp_path, monkeypatch)
        llm.set_client(None)
        payload, failed = _call("run_ai_decompilation", {"function_id": function_id})
        assert failed
        assert payload["error"] == "llm-unavailable"
