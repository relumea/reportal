"""Tests for the bulk analysis actions: `POST /api/analyses/bulk` and its CLI."""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import auth, bulk_actions, cli, journal, store
from reportal._paths import DB_ENV

runner = CliRunner()


def _seed(conn: sqlite3.Connection) -> dict[str, int]:
    """One binary with two analyses and a second whose only analysis has a function."""
    binary_id = store.add_binary(conn, sha256="1" * 64, name="bulk.exe", path="/tmp/bulk.exe")
    first = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    second = store.create_analysis(conn, binary_id=binary_id, engine="rebrew")
    store.add_function(conn, analysis_id=second, va=0x2000, name="sub_2000", size=16)
    lone_binary = store.add_binary(conn, sha256="2" * 64, name="lone.exe", path="/tmp/lone.exe")
    lone = store.create_analysis(conn, binary_id=lone_binary, engine="manual")
    store.add_function(conn, analysis_id=lone, va=0x1000, name="sub_1000", size=8)
    return {"binary": binary_id, "first": first, "second": second, "lone": lone}


def _post(body: dict[str, Any]) -> tuple[str, Any]:
    raw = json.dumps(body).encode()
    status, headers, payload = wsgi_request("POST", "/api/analyses/bulk", body=raw)
    return status, json_body(payload, headers)


class TestBulkApi:
    def test_a_tag_action_writes_the_owning_binaries(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)

        status, payload = _post(
            {"action": "add_tag", "analysis_ids": [ids["first"], ids["second"]], "tag": "reviewed"}
        )

        assert status.startswith("200")
        assert payload["applied"] == 2
        assert payload["requested"] == 2
        assert payload["skipped"] == []
        assert payload["journal_action"]
        assert [tag["name"] for tag in store.get_binary_tags(conn, ids["binary"])] == ["reviewed"]

    def test_removing_a_tag_that_does_not_exist_is_skipped(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)

        status, payload = _post(
            {"action": "remove_tag", "analysis_ids": [ids["first"]], "tag": "nope"}
        )

        assert status.startswith("200")
        assert payload["applied"] == 0
        assert payload["skipped"] == [{"id": ids["first"], "reason": "tag not found"}]

    def test_a_tag_action_without_a_tag_is_400(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)

        status, payload = _post({"action": "add_tag", "analysis_ids": [ids["first"]]})

        assert status.startswith("400")
        assert payload["error"] == "invalid bulk request"

    def test_an_unknown_action_is_400(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)

        status, payload = _post({"action": "explode", "analysis_ids": [ids["first"]]})

        assert status.startswith("400")
        assert payload["error"] == "invalid bulk request"

    def test_the_ids_must_be_a_list(self, conn: sqlite3.Connection) -> None:
        status, payload = _post({"action": "delete", "analysis_ids": 3})

        assert status.startswith("400")
        assert payload["detail"] == "analysis_ids must be a list"

    def test_delete_removes_analyses_and_skips_an_unknown_one(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = _seed(conn)

        status, payload = _post(
            {"action": "delete", "analysis_ids": [ids["second"], ids["first"], 999]}
        )

        assert status.startswith("200")
        assert payload["applied"] == 2
        assert store.get_analysis(conn, ids["second"]) is None
        assert payload["skipped"] == [{"id": 999, "reason": bulk_actions.REASON_NOT_FOUND}]

    def test_delete_skips_a_lone_analysis_with_functions(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)

        status, payload = _post({"action": "delete", "analysis_ids": [ids["lone"]]})

        assert status.startswith("200")
        assert payload["applied"] == 0
        assert payload["skipped"] == [
            {"id": ids["lone"], "reason": bulk_actions.REASON_LAST_ANALYSIS}
        ]
        assert store.get_analysis(conn, ids["lone"]) is not None

    def test_delete_reverts_the_snapshot_it_recorded(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)

        _, payload = _post({"action": "delete", "analysis_ids": [ids["second"]]})
        journal.revert_action(conn, payload["journal_action"])

        restored = store.get_analysis(conn, ids["second"])
        assert restored is not None
        assert store.count_functions(conn, analysis_id=ids["second"]) == 1

    def test_a_non_member_skips_a_team_analysis(
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
        raw = json.dumps({"action": "add_tag", "analysis_ids": [ids["first"]], "tag": "x"}).encode()
        _status, headers, payload = wsgi_request(
            "POST", "/api/analyses/bulk", body=raw, headers={"Authorization": f"Bearer {outsider}"}
        )
        body = json_body(payload, headers)
        assert body["applied"] == 0
        assert body["skipped"] == [{"id": ids["first"], "reason": "not permitted"}]

        _status, headers, payload = wsgi_request(
            "POST",
            "/api/analyses/bulk",
            body=raw,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert json_body(payload, headers)["applied"] == 1

    def test_a_tag_action_reverts_to_the_previous_set(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        store.create_tag(conn, "kept")
        kept = store.find_tag(conn, "kept")
        assert kept is not None
        store.add_binary_tag(conn, ids["binary"], int(kept["id"]))

        _, payload = _post({"action": "add_tag", "analysis_ids": [ids["first"]], "tag": "reviewed"})
        journal.revert_action(conn, payload["journal_action"])

        assert [tag["name"] for tag in store.get_binary_tags(conn, ids["binary"])] == ["kept"]


class TestBulkCli:
    def _workspace(self, tmp_path: Path, monkeypatch: Any) -> dict[str, Any]:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            ids = _seed(conn)
        return {**ids, "db": db}

    def test_bulk_tag_applies_and_reports_an_action(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = self._workspace(tmp_path, monkeypatch)

        result = runner.invoke(
            cli.app, ["analysis-bulk-tag", "reviewed", str(ids["first"]), "--json"]
        )

        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["applied"] == 1
        assert payload["journal_action"]
        with contextlib.closing(store.connect(Path(str(ids["db"])))) as conn:
            assert [tag["name"] for tag in store.get_binary_tags(conn, ids["binary"])] == [
                "reviewed"
            ]

    def test_bulk_tag_remove_takes_the_tag_off(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = self._workspace(tmp_path, monkeypatch)
        assert (
            runner.invoke(cli.app, ["analysis-bulk-tag", "reviewed", str(ids["first"])]).exit_code
            == 0
        )

        result = runner.invoke(
            cli.app, ["analysis-bulk-tag", "reviewed", str(ids["first"]), "--remove", "--json"]
        )

        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["applied"] == 1

    def test_bulk_delete_skips_the_lone_analysis(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = self._workspace(tmp_path, monkeypatch)

        result = runner.invoke(
            cli.app,
            ["analysis-bulk-delete", str(ids["lone"]), str(ids["second"]), "--yes", "--json"],
        )

        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["applied"] == 1
        assert payload["skipped"] == [
            {"id": ids["lone"], "reason": bulk_actions.REASON_LAST_ANALYSIS}
        ]

    def test_bulk_delete_needs_confirmation(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = self._workspace(tmp_path, monkeypatch)

        result = runner.invoke(cli.app, ["analysis-bulk-delete", str(ids["second"])], input="n\n")

        assert result.exit_code == 1
        with contextlib.closing(store.connect(Path(str(ids["db"])))) as conn:
            assert store.get_analysis(conn, ids["second"]) is not None

    def test_an_unknown_action_raises_a_bulk_error(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = self._workspace(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(Path(str(ids["db"])))) as conn:
            try:
                bulk_actions.apply_analysis_action(conn, action="explode", ids=[ids["first"]])
            except bulk_actions.BulkError as exc:
                assert "explode" in str(exc)
            else:  # pragma: no cover - the assertion is the point
                raise AssertionError("an unknown action must raise a BulkError")
