"""Tests for reportal.renames and its API, CLI and MCP surfaces.

No test touches the network: the LLM client is injected process-wide through
``llm.set_client`` and the tools call reportal's internals directly.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import FakeLlmClient, json_body, wsgi_request
from typer.testing import CliRunner

from reportal import cli, llm, mcp_server, mcp_tools, renames, store
from reportal._paths import DB_ENV

runner = CliRunner()

CODE = (
    "int sub_1000(int n)\n"
    "{\n"
    "  int var = 0;\n"
    "  int var2 = n + 1;\n"
    '  char *name = "var";\n'
    "  return var + var2;\n"
    "}\n"
)

CODE_WITH_VAR_RENAMED = (
    "int sub_1000(int n)\n"
    "{\n"
    "  int count = 0;\n"
    "  int var2 = n + 1;\n"
    '  char *name = "var";\n'
    "  return count + var2;\n"
    "}\n"
)


def _response(suggestions: list[dict[str, Any]]) -> str:
    return json.dumps(suggestions)


def _suggestion(
    from_name: str,
    to_name: str,
    *,
    kind: str = "variable",
    reason: str = "clearer",
    confidence: float = 0.8,
) -> dict[str, Any]:
    return {
        "from": from_name,
        "to": to_name,
        "kind": kind,
        "reason": reason,
        "confidence": confidence,
    }


def _seed(conn: sqlite3.Connection, *, decompilation: str | None = CODE) -> dict[str, int]:
    """Seed a binary, an analysis and two functions, with an optional decompilation."""
    binary_id = store.add_binary(conn, sha256="ab" * 32, name="demo.exe")
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    first = store.add_function(conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", size=16)
    second = store.add_function(conn, analysis_id=analysis_id, va=0x2000, name="sub_2000", size=16)
    if decompilation is not None:
        store.set_decompilation(conn, first, decompilation, "kuna")
    return {"binary": binary_id, "analysis": analysis_id, "first": first, "second": second}


def _store_suggestions(
    conn: sqlite3.Connection, function_id: int, suggestions: list[dict[str, Any]]
) -> None:
    store.set_ai_artifact(
        conn, function_id, renames.RENAMES_KIND, {"suggestions": suggestions}, "seed-model"
    )


class TestRenamePrompt:
    def test_messages_carry_the_code_and_the_from_to_contract(self) -> None:
        messages = llm.renames_messages("int f(void) { return 1; }")
        assert [message["role"] for message in messages] == ["system", "user"]
        content = messages[1]["content"]
        assert "int f(void) { return 1; }" in content
        assert '"from"' in content
        assert '"to"' in content
        assert "verbatim" in content

    def test_rename_suggestions_normalize_and_default_the_kind(self) -> None:
        client = FakeLlmClient(
            _response(
                [
                    _suggestion("var", "count", kind="variable", confidence=2.5),
                    {"from": "n", "to": "length", "kind": "mystery"},
                ]
            )
        )
        payload = llm.rename_suggestions("int f(void) {}", client=client)
        assert payload["suggestions"][0]["confidence"] == 1.0
        assert payload["suggestions"][1]["kind"] == llm.DEFAULT_RENAME_KIND

    def test_rename_suggestions_accept_a_fenced_response(self) -> None:
        body = _response([_suggestion("var", "count")])
        client = FakeLlmClient(f"```json\n{body}\n```")
        assert llm.rename_suggestions("int f(void) {}", client=client)["suggestions"]

    def test_rename_suggestions_drop_malformed_entries(self) -> None:
        client = FakeLlmClient(
            _response(
                [
                    _suggestion("var", "count"),
                    {"from": "x"},
                    {"to": "y"},
                    {"from": "", "to": "z"},
                    {"from": 1, "to": "z"},
                ]
            )
        )
        payload = llm.rename_suggestions("int f(void) {}", client=client)
        assert [entry["from"] for entry in payload["suggestions"]] == ["var"]

    def test_rename_suggestions_reject_a_non_list(self) -> None:
        client = FakeLlmClient('{"suggestions": {"from": "var"}}')
        with pytest.raises(llm.LlmError):
            llm.rename_suggestions("int f(void) {}", client=client)


class TestSuggestRenames:
    def test_stores_and_returns_the_payload(
        self, conn: sqlite3.Connection, fake_llm: FakeLlmClient
    ) -> None:
        fake_llm.response = _response([_suggestion("var", "count")])
        ids = _seed(conn)
        result = renames.suggest_renames(conn, function_id=ids["first"])
        assert result["function_id"] == ids["first"]
        assert result["model"] == "fake-model"
        assert result["count"] == 1
        assert result["suggestions"][0]["from"] == "var"
        assert fake_llm.calls and "int var = 0;" in fake_llm.calls[0][1]["content"]
        stored = store.get_ai_artifact(conn, ids["first"], renames.RENAMES_KIND)
        assert stored is not None
        assert stored["payload"]["suggestions"] == result["suggestions"]

    def test_drops_entries_whose_from_is_absent(
        self, conn: sqlite3.Connection, fake_llm: FakeLlmClient
    ) -> None:
        fake_llm.response = _response(
            [_suggestion("nosuchtoken", "anything"), _suggestion("var", "count")]
        )
        ids = _seed(conn)
        result = renames.suggest_renames(conn, function_id=ids["first"])
        assert [entry["from"] for entry in result["suggestions"]] == ["var"]

    def test_dedupes_by_from_keeping_the_first(
        self, conn: sqlite3.Connection, fake_llm: FakeLlmClient
    ) -> None:
        fake_llm.response = _response([_suggestion("var", "count"), _suggestion("var", "other")])
        ids = _seed(conn)
        result = renames.suggest_renames(conn, function_id=ids["first"])
        assert [entry["to"] for entry in result["suggestions"]] == ["count"]

    def test_without_a_stored_decompilation_raises(
        self, conn: sqlite3.Connection, fake_llm: FakeLlmClient
    ) -> None:
        ids = _seed(conn, decompilation=None)
        with pytest.raises(renames.NoDecompilationError):
            renames.suggest_renames(conn, function_id=ids["first"])
        assert fake_llm.calls == []

    def test_unknown_function_raises(
        self, conn: sqlite3.Connection, fake_llm: FakeLlmClient
    ) -> None:
        with pytest.raises(KeyError):
            renames.suggest_renames(conn, function_id=4242)

    def test_without_a_client_raises_unavailable(self, conn: sqlite3.Connection) -> None:
        llm.set_client(llm.LlmClient(None))
        ids = _seed(conn)
        with pytest.raises(llm.LlmUnavailable):
            renames.suggest_renames(conn, function_id=ids["first"])


class TestReplaceIdentifier:
    def test_whole_token_only(self) -> None:
        assert renames.replace_identifier("int var2 = var;", "var", "count") == (
            "int var2 = count;",
            1,
        )

    def test_skips_string_literals(self) -> None:
        assert renames.replace_identifier('char *s = "var"; int var = 0;', "var", "count") == (
            'char *s = "var"; int count = 0;',
            1,
        )

    def test_escaped_quotes_do_not_end_the_literal(self) -> None:
        assert renames.replace_identifier('"a \\" var";', "var", "count") == ('"a \\" var";', 0)


class TestApplyRenames:
    def test_explicit_suggestion_rewrites_whole_tokens(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        result = renames.apply_renames(
            conn, function_id=ids["first"], applied=[_suggestion("var", "count")]
        )
        assert result["decompilation_updated"] is True
        assert [entry["to"] for entry in result["applied"]] == ["count"]
        assert result["skipped"] == []
        stored = store.get_decompilation(conn, ids["first"])
        assert stored is not None
        assert stored["code"] == CODE_WITH_VAR_RENAMED

    def test_var_does_not_rewrite_var2(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        renames.apply_renames(conn, function_id=ids["first"], applied=[_suggestion("var", "count")])
        stored = store.get_decompilation(conn, ids["first"])
        assert stored is not None
        assert "var2" in stored["code"]

    def test_apply_none_applies_every_stored_suggestion(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _store_suggestions(conn, ids["first"], [_suggestion("var", "count")])
        result = renames.apply_renames(conn, function_id=ids["first"])
        assert result["decompilation_updated"] is True
        stored = store.get_decompilation(conn, ids["first"])
        assert stored is not None
        assert "count" in stored["code"]

    def test_apply_none_without_stored_suggestions_raises(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        with pytest.raises(renames.NoSuggestionError):
            renames.apply_renames(conn, function_id=ids["first"])

    def test_refuses_a_protected_keyword(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        result = renames.apply_renames(
            conn, function_id=ids["first"], applied=[_suggestion("int", "number")]
        )
        assert result["applied"] == []
        assert result["skipped"][0]["reason"] == "protected identifier"
        assert result["decompilation_updated"] is False

    def test_refuses_a_too_short_identifier(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        result = renames.apply_renames(
            conn, function_id=ids["first"], applied=[_suggestion("n", "count")]
        )
        assert result["skipped"][0]["reason"].startswith("identifier shorter than")
        assert result["decompilation_updated"] is False

    def test_refuses_a_too_short_target(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        result = renames.apply_renames(
            conn, function_id=ids["first"], applied=[_suggestion("var", "x")]
        )
        assert result["skipped"][0]["reason"].startswith("identifier shorter than")

    def test_refuses_a_from_no_longer_present(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        result = renames.apply_renames(
            conn, function_id=ids["first"], applied=[_suggestion("missing", "found")]
        )
        assert result["skipped"][0]["reason"] == "from is not present in the decompilation"
        assert result["decompilation_updated"] is False

    def test_skips_a_malformed_entry(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        result = renames.apply_renames(
            conn, function_id=ids["first"], applied=[{"from": "var"}, "nope"]
        )
        assert len(result["skipped"]) == 2
        assert result["decompilation_updated"] is False

    def test_requires_a_stored_decompilation(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn, decompilation=None)
        with pytest.raises(renames.NoDecompilationError):
            renames.apply_renames(conn, function_id=ids["first"])

    def test_function_rename_records_history(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        result = renames.apply_renames(
            conn,
            function_id=ids["first"],
            applied=[_suggestion("sub_1000", "ComputeChecksum", kind="function")],
            rename_function=True,
        )
        assert result["decompilation_updated"] is True
        function = store.get_function(conn, ids["first"])
        assert function is not None
        assert function["name"] == "ComputeChecksum"
        assert function["name_source"] == renames.RENAME_SOURCE
        history = store.list_name_history(conn, ids["first"])
        assert len(history) == 1
        assert history[0]["source"] == "renames"
        stored = store.get_decompilation(conn, ids["first"])
        assert stored is not None
        assert "ComputeChecksum" in stored["code"]

    def test_without_rename_function_the_row_is_untouched(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        renames.apply_renames(
            conn,
            function_id=ids["first"],
            applied=[_suggestion("sub_1000", "ComputeChecksum", kind="function")],
        )
        function = store.get_function(conn, ids["first"])
        assert function is not None
        assert function["name"] == "sub_1000"
        assert store.list_name_history(conn, ids["first"]) == []


class TestRevertRenames:
    def test_restores_the_exact_previous_text_and_drops_the_journal(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = _seed(conn)
        renames.apply_renames(conn, function_id=ids["first"], applied=[_suggestion("var", "count")])
        assert store.get_ai_artifact(conn, ids["first"], renames.RENAMES_APPLIED_KIND) is not None
        result = renames.revert_renames(conn, function_id=ids["first"])
        assert result["reverted"] is True
        stored = store.get_decompilation(conn, ids["first"])
        assert stored is not None
        assert stored["code"] == CODE
        assert store.get_ai_artifact(conn, ids["first"], renames.RENAMES_APPLIED_KIND) is None

    def test_without_an_apply_raises(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        with pytest.raises(renames.NoRevertError):
            renames.revert_renames(conn, function_id=ids["first"])

    def test_unknown_function_raises(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(KeyError):
            renames.revert_renames(conn, function_id=4242)


class TestRenamesRoutes:
    def _seed_with_decompilation(self, conn: sqlite3.Connection) -> dict[str, int]:
        return _seed(conn)

    def test_post_stores_then_get_serves(
        self, conn: sqlite3.Connection, fake_llm: FakeLlmClient
    ) -> None:
        fake_llm.response = _response([_suggestion("var", "count")])
        ids = self._seed_with_decompilation(conn)
        status, headers, body = wsgi_request("POST", f"/api/functions/{ids['first']}/renames")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["kind"] == "renames"
        assert payload["model"] == "fake-model"
        assert payload["count"] == 1
        assert payload["payload"]["suggestions"][0]["from"] == "var"

        status, headers, body = wsgi_request("GET", f"/api/functions/{ids['first']}/renames")
        assert status.startswith("200")
        stored = json_body(body, headers)
        assert stored["payload"] == payload["payload"]
        assert stored["created_at"]
        assert len(fake_llm.calls) == 1

    def test_get_absent_is_no_artifact(self, conn: sqlite3.Connection) -> None:
        ids = self._seed_with_decompilation(conn)
        status, headers, body = wsgi_request("GET", f"/api/functions/{ids['first']}/renames")
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["error"] == "no-artifact"
        assert "suggest-renames" in payload["detail"]

    def test_post_without_a_client_503(self, conn: sqlite3.Connection) -> None:
        llm.set_client(llm.LlmClient(None))
        ids = self._seed_with_decompilation(conn)
        status, headers, body = wsgi_request("POST", f"/api/functions/{ids['first']}/renames")
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "llm-unavailable"

    def test_post_without_a_decompilation_404(
        self, conn: sqlite3.Connection, fake_llm: FakeLlmClient
    ) -> None:
        ids = _seed(conn, decompilation=None)
        status, headers, body = wsgi_request("POST", f"/api/functions/{ids['first']}/renames")
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["error"] == "no-decompilation"
        assert "reportal decompile" in payload["detail"]

    def test_post_malformed_model_response_502(
        self, conn: sqlite3.Connection, fake_llm: FakeLlmClient
    ) -> None:
        fake_llm.response = "not json at all"
        ids = self._seed_with_decompilation(conn)
        status, headers, body = wsgi_request("POST", f"/api/functions/{ids['first']}/renames")
        assert status.startswith("502")
        assert json_body(body, headers)["error"] == "llm-error"
        assert store.get_ai_artifact(conn, ids["first"], renames.RENAMES_KIND) is None

    def test_unknown_function_404(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("GET", "/api/functions/999/renames")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "function not found"

    def test_apply_selected_updates_the_decompilation(self, conn: sqlite3.Connection) -> None:
        ids = self._seed_with_decompilation(conn)
        _store_suggestions(
            conn,
            ids["first"],
            [_suggestion("var", "count"), _suggestion("var2", "index")],
        )
        status, headers, body = wsgi_request(
            "POST",
            f"/api/functions/{ids['first']}/renames/apply",
            body=json.dumps({"applied": [_suggestion("var", "count")]}),
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["decompilation_updated"] is True
        assert [entry["to"] for entry in payload["applied"]] == ["count"]
        stored = store.get_decompilation(conn, ids["first"])
        assert stored is not None
        assert "var2" in stored["code"]

    def test_apply_defaults_to_all(self, conn: sqlite3.Connection) -> None:
        ids = self._seed_with_decompilation(conn)
        _store_suggestions(
            conn,
            ids["first"],
            [_suggestion("var", "count"), _suggestion("var2", "index")],
        )
        status, headers, body = wsgi_request(
            "POST", f"/api/functions/{ids['first']}/renames/apply", body="{}"
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert {entry["to"] for entry in payload["applied"]} == {"count", "index"}

    def test_apply_invalid_body_400(self, conn: sqlite3.Connection) -> None:
        ids = self._seed_with_decompilation(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/functions/{ids['first']}/renames/apply",
            body=json.dumps({"applied": "nope"}),
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid applied"

    def test_apply_non_boolean_rename_function_400(self, conn: sqlite3.Connection) -> None:
        ids = self._seed_with_decompilation(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/functions/{ids['first']}/renames/apply",
            body=json.dumps({"rename_function": "yes"}),
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "rename_function must be a boolean"

    def test_apply_without_stored_suggestions_404(self, conn: sqlite3.Connection) -> None:
        ids = self._seed_with_decompilation(conn)
        status, headers, body = wsgi_request(
            "POST", f"/api/functions/{ids['first']}/renames/apply", body="{}"
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "no-artifact"

    def test_apply_rename_function_records_history(self, conn: sqlite3.Connection) -> None:
        ids = self._seed_with_decompilation(conn)
        _store_suggestions(
            conn, ids["first"], [_suggestion("sub_1000", "ComputeChecksum", kind="function")]
        )
        status, headers, body = wsgi_request(
            "POST",
            f"/api/functions/{ids['first']}/renames/apply",
            body=json.dumps({"rename_function": True}),
        )
        assert status.startswith("200")
        function = store.get_function(conn, ids["first"])
        assert function is not None
        assert function["name"] == "ComputeChecksum"

    def test_revert_restores_the_previous_text(self, conn: sqlite3.Connection) -> None:
        ids = self._seed_with_decompilation(conn)
        _store_suggestions(conn, ids["first"], [_suggestion("var", "count")])
        wsgi_request("POST", f"/api/functions/{ids['first']}/renames/apply", body="{}")
        status, headers, body = wsgi_request(
            "POST", f"/api/functions/{ids['first']}/renames/revert", body="{}"
        )
        assert status.startswith("200")
        assert json_body(body, headers)["reverted"] is True
        stored = store.get_decompilation(conn, ids["first"])
        assert stored is not None
        assert stored["code"] == CODE

    def test_revert_without_an_apply_404(self, conn: sqlite3.Connection) -> None:
        ids = self._seed_with_decompilation(conn)
        status, headers, body = wsgi_request(
            "POST", f"/api/functions/{ids['first']}/renames/revert", body="{}"
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "no-artifact"


def _seed_portal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """Create a portal DB with one binary, one analysis and a decompiled function."""
    db = tmp_path / "portal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    with contextlib.closing(store.connect(db)) as conn:
        return _seed(conn)


class TestRenamesCommands:
    def test_suggest_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_llm: FakeLlmClient
    ) -> None:
        fake_llm.response = _response([_suggestion("var", "count")])
        ids = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["suggest-renames", str(ids["first"]), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["count"] == 1
        assert payload["model"] == "fake-model"

    def test_suggest_human_lists_the_suggestion(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_llm: FakeLlmClient
    ) -> None:
        fake_llm.response = _response([_suggestion("var", "count", reason="counts items")])
        ids = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["suggest-renames", str(ids["first"])])
        assert result.exit_code == 0, result.output
        assert "count" in result.output
        assert "counts items" in result.output

    def test_suggest_without_a_client_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        llm.set_client(llm.LlmClient(None))
        ids = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["suggest-renames", str(ids["first"]), "--json"])
        assert result.exit_code == 1
        assert "llm-unavailable" in result.stdout

    def test_apply_all_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            _store_suggestions(conn, ids["first"], [_suggestion("var", "count")])
        result = runner.invoke(cli.app, ["apply-renames", str(ids["first"]), "--all", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["decompilation_updated"] is True
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            stored = store.get_decompilation(conn, ids["first"])
        assert stored is not None
        assert stored["code"] == CODE_WITH_VAR_RENAMED

    def test_apply_from_to_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app,
            [
                "apply-renames",
                str(ids["first"]),
                "--from",
                "var",
                "--to",
                "count",
                "--json",
            ],
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert [entry["to"] for entry in payload["applied"]] == ["count"]

    def test_apply_from_without_to_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app, ["apply-renames", str(ids["first"]), "--from", "var", "--json"]
        )
        assert result.exit_code == 1
        assert "--from and --to must be given together" in result.stdout

    def test_apply_all_with_from_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app,
            [
                "apply-renames",
                str(ids["first"]),
                "--all",
                "--from",
                "var",
                "--to",
                "count",
                "--json",
            ],
        )
        assert result.exit_code == 1
        assert "--all cannot be combined" in result.stdout

    def test_apply_without_stored_suggestions_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["apply-renames", str(ids["first"]), "--json"])
        assert result.exit_code == 1
        assert "no stored rename suggestions" in result.stdout

    def test_apply_rename_function_records_history(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app,
            [
                "apply-renames",
                str(ids["first"]),
                "--from",
                "sub_1000",
                "--to",
                "ComputeChecksum",
                "--rename-function",
                "--json",
            ],
        )
        assert result.exit_code == 0, result.output
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            function = store.get_function(conn, ids["first"])
        assert function is not None
        assert function["name"] == "ComputeChecksum"

    def test_revert_restores(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        runner.invoke(
            cli.app,
            ["apply-renames", str(ids["first"]), "--from", "var", "--to", "count", "--json"],
        )
        result = runner.invoke(cli.app, ["revert-renames", str(ids["first"]), "--json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["reverted"] is True
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            stored = store.get_decompilation(conn, ids["first"])
        assert stored is not None
        assert stored["code"] == CODE

    def test_revert_without_an_apply_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["revert-renames", str(ids["first"]), "--json"])
        assert result.exit_code == 1
        assert "no applied renames to revert" in result.stdout

    def test_unknown_function_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["revert-renames", "4242", "--json"])
        assert result.exit_code == 1
        assert "no function with id 4242" in result.stdout


def _mcp_call(name: str, arguments: dict[str, Any]) -> tuple[Any, bool]:
    """Run one tool through ``tools/call``; returns (payload, is_error)."""
    return mcp_server.call_tool(name, arguments)


class TestRenamesTools:
    def test_the_four_tools_are_registered(self) -> None:
        by_name = {tool.name: tool for tool in mcp_tools.tools()}
        assert by_name["get_renames"].annotations.read_only_hint is True
        for name in ("suggest_renames", "apply_renames", "revert_renames"):
            assert by_name[name].annotations.destructive_hint is True

    def test_get_without_an_artifact_is_a_structured_error(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        payload, is_error = _mcp_call("get_renames", {"function_id": ids["first"]})
        assert is_error is True
        assert payload["error"] == "no-artifact"

    def test_suggest_get_apply_then_revert(
        self, conn: sqlite3.Connection, fake_llm: FakeLlmClient
    ) -> None:
        fake_llm.response = _response([_suggestion("var", "count")])
        ids = _seed(conn)
        payload, is_error = _mcp_call("suggest_renames", {"function_id": ids["first"]})
        assert is_error is False
        assert payload["count"] == 1

        payload, is_error = _mcp_call("get_renames", {"function_id": ids["first"]})
        assert is_error is False
        assert payload["payload"]["suggestions"][0]["from"] == "var"

        payload, is_error = _mcp_call("apply_renames", {"function_id": ids["first"]})
        assert is_error is False
        assert payload["decompilation_updated"] is True

        payload, is_error = _mcp_call("revert_renames", {"function_id": ids["first"]})
        assert is_error is False
        assert payload["reverted"] is True
        stored = store.get_decompilation(conn, ids["first"])
        assert stored is not None
        assert stored["code"] == CODE

    def test_apply_with_an_explicit_list(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        payload, is_error = _mcp_call(
            "apply_renames",
            {"function_id": ids["first"], "applied": [_suggestion("var", "count")]},
        )
        assert is_error is False
        assert [entry["to"] for entry in payload["applied"]] == ["count"]

    def test_suggest_without_a_llm_is_unavailable(self, conn: sqlite3.Connection) -> None:
        llm.set_client(llm.LlmClient(None))
        ids = _seed(conn)
        payload, is_error = _mcp_call("suggest_renames", {"function_id": ids["first"]})
        assert is_error is True
        assert payload["error"] == "llm-unavailable"

    def test_apply_without_stored_suggestions_is_no_artifact(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = _seed(conn)
        payload, is_error = _mcp_call("apply_renames", {"function_id": ids["first"]})
        assert is_error is True
        assert payload["error"] == "no-artifact"

    def test_revert_without_an_apply_is_no_artifact(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        payload, is_error = _mcp_call("revert_renames", {"function_id": ids["first"]})
        assert is_error is True
        assert payload["error"] == "no-artifact"
