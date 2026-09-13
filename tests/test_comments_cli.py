"""Tests for the ``comments``, ``comment-add``, ``comment-rm`` and bulk CLI commands."""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
from typing import Any, cast

import pytest
from typer.testing import CliRunner, Result

from reportal import bulk_actions, cli, comments, store
from reportal._paths import DB_ENV

runner = CliRunner()


def _seed_portal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    db = tmp_path / "portal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    with contextlib.closing(store.connect(db)) as conn:
        binary_id = store.add_binary(conn, sha256="ab" * 32, name="demo.exe", path="/x/demo.exe")
        store.add_binary(conn, sha256="cd" * 32, name="other.exe", path="/x/other.exe")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        store.add_function(conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", size=16)
        store.add_function(conn, analysis_id=analysis_id, va=0x2000, name="sub_2000", size=16)
    return db


def _payload(result: Result) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(result.output))


class TestCommentsCli:
    def test_comment_add_and_list(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        db = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app, ["comment-add", "--binary", "1", "first note", "--author", "alice", "--json"]
        )
        assert result.exit_code == 0, result.output
        assert _payload(result)["author"] == "alice"

        result = runner.invoke(cli.app, ["comments", "--binary", "1", "--json"])
        assert result.exit_code == 0, result.output
        rows = _payload(result)["comments"]
        assert [(row["author"], row["body"]) for row in rows] == [("alice", "first note")]
        with contextlib.closing(store.connect(db)) as conn:
            assert store.counts(conn)["comments"] == 1

    def test_comment_add_defaults_the_author(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["comment-add", "--binary", "1", "note", "--json"])
        assert result.exit_code == 0, result.output
        assert _payload(result)["author"] == comments.DEFAULT_AUTHOR

    def test_comment_add_on_a_function(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["comment-add", "--function", "1", "fn note", "--json"])
        assert result.exit_code == 0, result.output
        assert _payload(result)["scope_kind"] == "function"

    def test_comment_rm(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["comment-add", "--binary", "1", "note", "--json"])
        comment_id = _payload(result)["id"]
        result = runner.invoke(cli.app, ["comment-rm", str(comment_id), "--json"])
        assert result.exit_code == 0, result.output
        assert _payload(result)["deleted"] is True

    def test_comment_rm_unknown_exits_nonzero(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["comment-rm", "999", "--json"])
        assert result.exit_code == 1
        assert _payload(result)["error"] == "no comment with id 999"

    def test_comments_needs_exactly_one_scope(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["comments", "--json"])
        assert result.exit_code == 1
        result = runner.invoke(cli.app, ["comments", "--binary", "1", "--function", "1", "--json"])
        assert result.exit_code == 1

    def test_comments_unknown_scope_exits_nonzero(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["comments", "--binary", "999", "--json"])
        assert result.exit_code == 1
        assert _payload(result)["error"] == "no binary with id 999"

    def test_comment_add_blank_body_exits_nonzero(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["comment-add", "--binary", "1", "   ", "--json"])
        assert result.exit_code == 1
        assert "empty" in _payload(result)["error"]

    def test_human_output_lists_the_comment(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        runner.invoke(cli.app, ["comment-add", "--binary", "1", "readable note", "--json"])
        result = runner.invoke(cli.app, ["comments", "--binary", "1"])
        assert result.exit_code == 0, result.output
        assert "readable note" in result.output


class TestBulkCli:
    def test_bulk_tag_add_and_remove(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        db = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["bulk-tag", "reviewed", "1", "2", "--json"])
        assert result.exit_code == 0, result.output
        payload = _payload(result)
        assert payload.pop("journal_action")
        assert payload == {
            "action": "add_tag",
            "requested": 2,
            "applied": 2,
            "skipped": [],
        }
        with contextlib.closing(store.connect(db)) as conn:
            assert len(store.get_binary_tags(conn, 2)) == 1

        result = runner.invoke(cli.app, ["bulk-tag", "reviewed", "1", "2", "--remove", "--json"])
        assert result.exit_code == 0, result.output
        assert _payload(result)["applied"] == 2

    def test_bulk_tag_skips_unknown_ids(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["bulk-tag", "reviewed", "1", "999", "--json"])
        assert result.exit_code == 0, result.output
        assert _payload(result)["skipped"] == [{"id": 999, "reason": "not found"}]

    def test_bulk_delete_requires_confirmation_without_yes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["bulk-delete", "2", "--json"], input="n\n")
        assert result.exit_code == 1
        with contextlib.closing(store.connect(db)) as conn:
            assert store.get_binary(conn, 2) is not None

    def test_bulk_delete_with_yes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        db = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["bulk-delete", "2", "--yes", "--json"])
        assert result.exit_code == 0, result.output
        assert _payload(result)["applied"] == 1
        with contextlib.closing(store.connect(db)) as conn:
            assert store.get_binary(conn, 2) is None

    def test_bulk_delete_reports_unknown_ids(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["bulk-delete", "999", "--yes", "--json"])
        assert result.exit_code == 0, result.output
        assert _payload(result)["skipped"] == [{"id": 999, "reason": "not found"}]

    def test_bulk_prefix_appends(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        db = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["bulk-prefix", "NP_", "1", "2", "--json"])
        assert result.exit_code == 0, result.output
        assert _payload(result)["applied"] == 2
        with contextlib.closing(store.connect(db)) as conn:
            assert cast(dict[str, Any], store.get_function(conn, 1))["name"] == "NP_sub_1000"
            history = store.list_name_history(conn, 2)
            assert history[0]["source"] == bulk_actions.BULK_RENAME_SOURCE

    def test_bulk_prefix_replace(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        db = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["bulk-prefix", "NP_", "1", "--replace", "--json"])
        assert result.exit_code == 0, result.output
        with contextlib.closing(store.connect(db)) as conn:
            assert cast(dict[str, Any], store.get_function(conn, 1))["name"] == "NP_1000"

    def test_bulk_prefix_empty_prefix_exits_nonzero(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["bulk-prefix", "  ", "1", "--json"])
        assert result.exit_code == 1


def test_ai_comments_command_is_renamed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The analyst list owns `comments`; the AI artifact command is `ai-comments`."""
    _seed_portal(tmp_path, monkeypatch)
    result = runner.invoke(cli.app, ["ai-comments", "1", "--json"])
    assert result.exit_code == 1
    assert "llm-unavailable" in result.output
