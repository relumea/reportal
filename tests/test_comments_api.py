"""Tests for the analyst comment and bulk action API routes."""

from __future__ import annotations

import json
import sqlite3
from typing import Any, cast

import pytest
from conftest import json_body, wsgi_request

from reportal import auth, bulk_actions, clock, comments, store


def _seed(conn: sqlite3.Connection) -> dict[str, int]:
    binary_id = store.add_binary(conn, sha256="aa" * 32, name="demo.exe", path="/x/demo.exe")
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    function_id = store.add_function(
        conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", size=48, status="STUB"
    )
    second = store.add_function(
        conn, analysis_id=analysis_id, va=0x2000, name="sub_2000", size=16, status="EXACT"
    )
    return {"binary": binary_id, "analysis": analysis_id, "function": function_id, "second": second}


def _post(path: str, payload: dict[str, object]) -> tuple[str, dict[str, str], bytes]:
    return wsgi_request("POST", path, body=json.dumps(payload))


class TestCommentRoutes:
    def test_binary_comment_lifecycle(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, headers, body = _post(
            f"/api/binaries/{ids['binary']}/comments", {"body": "first look", "author": "alice"}
        )
        assert status.startswith("201")
        created = json_body(body, headers)
        assert created["author"] == "alice"
        assert created["body"] == "first look"

        _, headers, body = wsgi_request("GET", f"/api/binaries/{ids['binary']}/comments")
        assert [row["body"] for row in json_body(body, headers)["comments"]] == ["first look"]

        status, headers, body = wsgi_request(
            "PATCH", f"/api/comments/{created['id']}", body=json.dumps({"body": "edited"})
        )
        assert status.startswith("200")
        assert json_body(body, headers)["body"] == "edited"

        status, headers, body = wsgi_request("DELETE", f"/api/comments/{created['id']}")
        assert status.startswith("200")
        assert json_body(body, headers)["deleted"] is True
        _, headers, body = wsgi_request("GET", f"/api/binaries/{ids['binary']}/comments")
        assert json_body(body, headers)["comments"] == []

    def test_function_comment_uses_the_default_author(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, headers, body = _post(
            f"/api/functions/{ids['function']}/comments", {"body": "note"}
        )
        assert status.startswith("201")
        assert json_body(body, headers)["author"] == comments.DEFAULT_AUTHOR

    def test_blank_body_is_400(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, headers, body = _post(f"/api/binaries/{ids['binary']}/comments", {"body": "   "})
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid comment"

    def test_oversized_body_is_400(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, headers, body = _post(
            f"/api/binaries/{ids['binary']}/comments",
            {"body": "x" * (comments.MAX_COMMENT_CHARS + 1)},
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid comment"

    def test_non_string_body_is_400(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, headers, body = _post(f"/api/binaries/{ids['binary']}/comments", {"body": 7})
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid comment"

    def test_unknown_binary_scope_is_404(self, conn: sqlite3.Connection) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/999/comments")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_unknown_function_scope_is_404(self, conn: sqlite3.Connection) -> None:
        status, headers, body = _post("/api/functions/999/comments", {"body": "note"})
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "function not found"

    def test_unknown_comment_patch_is_404(self, conn: sqlite3.Connection) -> None:
        status, headers, body = wsgi_request(
            "PATCH", "/api/comments/999", body=json.dumps({"body": "note"})
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "comment not found"

    def test_a_non_member_does_not_patch_or_delete_a_team_comment(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(conn)
        _status, _headers, body = _post(
            f"/api/binaries/{ids['binary']}/comments", {"body": "first look"}
        )
        comment_id = int(json.loads(body.decode("utf-8"))["id"])
        owner, _token = auth.add_user(conn, name="owner", role="admin")
        team_id = int(auth.create_team(conn, name="blue")["id"])
        auth.add_member(conn, team_id, int(owner["id"]))
        _member, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        ana = auth.find_user(conn, "ana")
        assert ana is not None
        auth.add_member(conn, team_id, int(ana["id"]))
        _outsider, outsider = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        store.set_binary_scope(conn, ids["binary"], visibility="team", owner_team_id=team_id)

        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        stranger_status, headers, body = wsgi_request(
            "PATCH",
            f"/api/comments/{comment_id}",
            body=json.dumps({"body": "edited"}),
            headers={"Authorization": f"Bearer {outsider}"},
        )
        assert stranger_status.startswith("403"), body
        assert json_body(body, headers)["error"] == "scope-forbidden"

        member_status, headers, body = wsgi_request(
            "PATCH",
            f"/api/comments/{comment_id}",
            body=json.dumps({"body": "edited"}),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert member_status.startswith("200"), body
        assert json_body(body, headers)["body"] == "edited"

    def test_a_non_member_lists_no_team_comments(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(conn)
        _post(f"/api/binaries/{ids['binary']}/comments", {"body": "first look"})
        _post(f"/api/functions/{ids['function']}/comments", {"body": "on the function"})
        owner, _token = auth.add_user(conn, name="owner", role="admin")
        team_id = int(auth.create_team(conn, name="blue")["id"])
        auth.add_member(conn, team_id, int(owner["id"]))
        _member, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        ana = auth.find_user(conn, "ana")
        assert ana is not None
        auth.add_member(conn, team_id, int(ana["id"]))
        _outsider, outsider = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        store.set_binary_scope(conn, ids["binary"], visibility="team", owner_team_id=team_id)

        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        stranger_status, headers, body = wsgi_request(
            "GET",
            f"/api/binaries/{ids['binary']}/comments",
            headers={"Authorization": f"Bearer {outsider}"},
        )
        assert stranger_status.startswith("404"), body
        assert json_body(body, headers)["error"] == "binary not found"
        stranger_status, headers, body = wsgi_request(
            "GET",
            f"/api/functions/{ids['function']}/comments",
            headers={"Authorization": f"Bearer {outsider}"},
        )
        assert stranger_status.startswith("404"), body
        assert json_body(body, headers)["error"] == "function not found"

        _status, headers, body = wsgi_request(
            "GET",
            f"/api/binaries/{ids['binary']}/comments",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert [row["body"] for row in json_body(body, headers)["comments"]] == ["first look"]

    def test_unknown_comment_delete_is_404(self, conn: sqlite3.Connection) -> None:
        status, headers, body = wsgi_request("DELETE", "/api/comments/999")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "comment not found"

    def test_patch_blank_body_is_400(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        created = store.add_comment(
            conn, scope_kind="binary", scope_id=ids["binary"], author="a", body="b"
        )
        status, headers, body = wsgi_request(
            "PATCH", f"/api/comments/{created['id']}", body=json.dumps({"body": " "})
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid comment"

    def test_comments_are_filtered_by_scope(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _post(f"/api/binaries/{ids['binary']}/comments", {"body": "on binary"})
        _post(f"/api/functions/{ids['function']}/comments", {"body": "on function"})
        _, headers, body = wsgi_request("GET", f"/api/binaries/{ids['binary']}/comments")
        assert [row["body"] for row in json_body(body, headers)["comments"]] == ["on binary"]
        _, headers, body = wsgi_request("GET", f"/api/functions/{ids['function']}/comments")
        assert [row["body"] for row in json_body(body, headers)["comments"]] == ["on function"]

    def test_update_moves_the_updated_timestamp(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(conn)
        stamps = iter(
            [
                "2020-01-01T00:00:00+00:00",
                "2020-01-02T00:00:00+00:00",
                "2020-01-02T00:00:01+00:00",
            ]
        )
        monkeypatch.setattr(clock, "now", lambda: next(stamps))
        created = store.add_comment(
            conn, scope_kind="binary", scope_id=ids["binary"], author="a", body="before"
        )
        _, headers, body = wsgi_request(
            "PATCH", f"/api/comments/{created['id']}", body=json.dumps({"body": "after"})
        )
        assert json_body(body, headers)["updated_at"] != created["created_at"]


class TestAiCommentsRouteMoved:
    def test_ai_comments_is_the_artifact_route(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request("GET", f"/api/functions/{ids['function']}/ai-comments")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "no-artifact"

    def test_comments_path_serves_analyst_comments(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _post(f"/api/functions/{ids['function']}/comments", {"body": "analyst note"})
        _, headers, body = wsgi_request("GET", f"/api/functions/{ids['function']}/comments")
        assert [row["body"] for row in json_body(body, headers)["comments"]] == ["analyst note"]


class TestBulkBinaryRoutes:
    def test_add_and_remove_tag(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        other = store.add_binary(conn, sha256="bb" * 32, name="other.exe", path="/x/other.exe")
        status, headers, body = _post(
            "/api/binaries/bulk",
            {"action": "add_tag", "binary_ids": [ids["binary"], other], "tag": "reviewed"},
        )
        assert status.startswith("200")
        result = json_body(body, headers)
        assert result.pop("journal_action")
        assert result == {"action": "add_tag", "requested": 2, "applied": 2, "skipped": []}
        assert [tag["name"] for tag in store.get_binary_tags(conn, other)] == ["reviewed"]

        _, headers, body = _post(
            "/api/binaries/bulk",
            {"action": "remove_tag", "binary_ids": [ids["binary"], other], "tag": "reviewed"},
        )
        assert json_body(body, headers)["applied"] == 2
        assert store.get_binary_tags(conn, other) == []

    def test_duplicate_tag_link_is_unchanged(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _post(
            "/api/binaries/bulk",
            {"action": "add_tag", "binary_ids": [ids["binary"]], "tag": "reviewed"},
        )

        status, headers, body = _post(
            "/api/binaries/bulk",
            {"action": "add_tag", "binary_ids": [ids["binary"]], "tag": "reviewed"},
        )
        result = json_body(body, headers)
        assert status.startswith("200")
        assert result["applied"] == 0
        assert result["skipped"] == [{"id": ids["binary"], "reason": bulk_actions.REASON_UNCHANGED}]
        assert "journal_action" not in result

        status, headers, body = _post(
            "/api/binaries/bulk",
            {"action": "remove_tag", "binary_ids": [ids["binary"]], "tag": "reviewed"},
        )
        assert json_body(body, headers)["applied"] == 1

        status, headers, body = _post(
            "/api/binaries/bulk",
            {"action": "remove_tag", "binary_ids": [ids["binary"]], "tag": "reviewed"},
        )
        result = json_body(body, headers)
        assert result["applied"] == 0
        assert result["skipped"] == [{"id": ids["binary"], "reason": bulk_actions.REASON_UNCHANGED}]

    def test_remove_unknown_tag_skips_every_id(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _, headers, body = _post(
            "/api/binaries/bulk",
            {"action": "remove_tag", "binary_ids": [ids["binary"]], "tag": "absent"},
        )
        result = json_body(body, headers)
        assert result["applied"] == 0
        assert result["skipped"] == [{"id": ids["binary"], "reason": "tag not found"}]

    def test_delete_cascades_and_reports_per_id(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        other = store.add_binary(conn, sha256="bb" * 32, name="other.exe", path="/x/other.exe")
        store.add_comment(
            conn, scope_kind="binary", scope_id=ids["binary"], author="a", body="on binary"
        )
        status, headers, body = _post(
            "/api/binaries/bulk",
            {"action": "delete", "binary_ids": [ids["binary"], other, 999]},
        )
        assert status.startswith("200")
        result = json_body(body, headers)
        assert result.pop("journal_action")
        assert result == {
            "action": "delete",
            "requested": 3,
            "applied": 2,
            "skipped": [{"id": 999, "reason": "not found"}],
        }
        assert store.get_binary(conn, ids["binary"]) is None
        assert store.get_binary(conn, other) is None
        assert store.list_comments(conn) == []

    def test_empty_id_list_is_400(self, conn: sqlite3.Connection) -> None:
        status, headers, body = _post("/api/binaries/bulk", {"action": "delete", "binary_ids": []})
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid bulk request"

    def test_id_cap_is_enforced(self, conn: sqlite3.Connection) -> None:
        ids = list(range(bulk_actions.MAX_BULK_IDS + 1))
        status, headers, body = _post("/api/binaries/bulk", {"action": "delete", "binary_ids": ids})
        assert status.startswith("400")
        assert "at most" in json_body(body, headers)["detail"]

    def test_unknown_action_is_400(self, conn: sqlite3.Connection) -> None:
        status, headers, body = _post(
            "/api/binaries/bulk", {"action": "explode", "binary_ids": [1]}
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid bulk request"

    def test_tag_is_required_for_a_tag_action(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, headers, body = _post(
            "/api/binaries/bulk", {"action": "add_tag", "binary_ids": [ids["binary"]]}
        )
        assert status.startswith("400")
        payload = json_body(body, headers)
        assert payload["error"] == "invalid bulk request"
        assert "tag is required" in payload["detail"]


class TestBulkFunctionRoutes:
    def test_rename_appends_the_prefix_and_records_history(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, headers, body = _post(
            "/api/functions/bulk",
            {
                "action": "rename",
                "function_ids": [ids["function"], ids["second"]],
                "prefix": "NP_",
            },
        )
        assert status.startswith("200")
        result = json_body(body, headers)
        assert result.pop("journal_action")
        assert result == {
            "action": "rename",
            "requested": 2,
            "applied": 2,
            "skipped": [],
        }
        assert (
            cast(dict[str, Any], store.get_function(conn, ids["function"]))["name"] == "NP_sub_1000"
        )
        history = store.list_name_history(conn, ids["second"])
        assert history[0]["source"] == bulk_actions.BULK_RENAME_SOURCE
        assert history[0]["old_name"] == "sub_2000"

    def test_replace_drops_the_leading_segment(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _, headers, body = _post(
            "/api/functions/bulk",
            {
                "action": "rename",
                "function_ids": [ids["function"]],
                "prefix": "NP_",
                "replace": True,
            },
        )
        assert json_body(body, headers)["applied"] == 1
        assert cast(dict[str, Any], store.get_function(conn, ids["function"]))["name"] == "NP_1000"

    def test_replace_is_idempotent(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        for _ in range(2):
            _post(
                "/api/functions/bulk",
                {
                    "action": "rename",
                    "function_ids": [ids["function"]],
                    "prefix": "NP_",
                    "replace": True,
                },
            )
        assert cast(dict[str, Any], store.get_function(conn, ids["function"]))["name"] == "NP_1000"

    def test_unknown_ids_are_skipped(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _, headers, body = _post(
            "/api/functions/bulk",
            {"action": "rename", "function_ids": [ids["function"], 999], "prefix": "NP_"},
        )
        result = json_body(body, headers)
        assert result["applied"] == 1
        assert result["skipped"] == [{"id": 999, "reason": "not found"}]

    def test_clear_matches(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        store.record_match(
            conn,
            function_id=ids["function"],
            candidate_function_id=ids["second"],
            similarity=0.5,
            confidence=0.5,
        )
        status, headers, body = _post(
            "/api/functions/bulk",
            {"action": "clear_matches", "function_ids": [ids["function"]]},
        )
        assert status.startswith("200")
        assert json_body(body, headers)["applied"] == 1
        assert store.list_matches(conn, ids["function"]) == []

    def test_empty_id_list_is_400(self, conn: sqlite3.Connection) -> None:
        status, headers, body = _post(
            "/api/functions/bulk", {"action": "clear_matches", "function_ids": []}
        )
        assert status.startswith("400")
        payload = json_body(body, headers)
        assert payload["error"] == "invalid bulk request"
        assert "at least one id is required" in payload["detail"]

    def test_unknown_action_is_400(self, conn: sqlite3.Connection) -> None:
        status, headers, body = _post(
            "/api/functions/bulk", {"action": "delete", "function_ids": [1]}
        )
        assert status.startswith("400")
        payload = json_body(body, headers)
        assert payload["error"] == "invalid bulk request"
        assert "unsupported action" in payload["detail"]

    def test_rename_requires_a_prefix(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, headers, body = _post(
            "/api/functions/bulk",
            {"action": "rename", "function_ids": [ids["function"]], "prefix": "  "},
        )
        assert status.startswith("400")
        payload = json_body(body, headers)
        assert payload["error"] == "invalid bulk request"
        assert "prefix is required" in payload["detail"]

    def test_a_non_member_skips_a_team_function(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(conn)
        owner, _token = auth.add_user(conn, name="owner", role="admin")
        team_id = int(auth.create_team(conn, name="blue")["id"])
        auth.add_member(conn, team_id, int(owner["id"]))
        _member, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        ana = auth.find_user(conn, "ana")
        assert ana is not None
        auth.add_member(conn, team_id, int(ana["id"]))
        _outsider, outsider = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        store.set_binary_scope(conn, ids["binary"], visibility="team", owner_team_id=team_id)

        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        _status, headers, body = wsgi_request(
            "POST",
            "/api/functions/bulk",
            body=json.dumps(
                {
                    "action": "rename",
                    "function_ids": [ids["function"]],
                    "prefix": "NP_",
                }
            ),
            headers={"Authorization": f"Bearer {outsider}"},
        )
        result = json_body(body, headers)
        assert result["applied"] == 0
        assert result["skipped"] == [{"id": ids["function"], "reason": "not permitted"}]

        _status, headers, body = wsgi_request(
            "POST",
            "/api/functions/bulk",
            body=json.dumps(
                {
                    "action": "rename",
                    "function_ids": [ids["function"]],
                    "prefix": "NP_",
                }
            ),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert json_body(body, headers)["applied"] == 1


def test_bulk_routes_are_json(conn: sqlite3.Connection) -> None:
    status, headers, body = _post("/api/binaries/bulk", {"action": "delete"})
    assert status.startswith("400")
    assert headers["Content-Type"].startswith("application/json")
    assert "binary_ids" in json_body(body, headers)["detail"]
