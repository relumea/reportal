"""Tests for the artifact ratings: the store, the routes, the CLI and the tools.

An artifact is a binary's stored scan of one kind, so the tests seed scans and
rate them, checking that a verdict survives a re-run, that a revert restores the
previous one and that an artifact which was never produced is refused.
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import cli, journal, mcp_server, ratings, store
from reportal._paths import DB_ENV

runner = CliRunner()


def _seed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, scan: bool = True) -> dict[str, Any]:
    """A portal DB with one binary, one analysis and (by default) a threat scan."""
    db = tmp_path / "portal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    with contextlib.closing(store.connect(db)) as conn:
        binary_id = store.add_binary(conn, sha256="aa" * 32, name="demo.exe")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        if scan:
            store.set_scan(conn, analysis_id, store.SCAN_KIND_THREAT, {"iocs": {}})
    return {"binary": binary_id, "analysis": analysis_id, "db": db}


class TestVocabulary:
    def test_every_scan_kind_the_store_declares_is_rateable(self) -> None:
        assert "threat" in ratings.SCAN_KINDS
        assert "triage" in ratings.SCAN_KINDS
        assert list(ratings.SCAN_KINDS) == sorted(ratings.SCAN_KINDS)
        assert ratings.kinds() == ratings.SCAN_KINDS

    def test_a_verdict_is_validated(self) -> None:
        assert ratings.normalize_rating("UP") == "up"
        assert ratings.normalize_rating(None) == ""
        assert ratings.normalize_rating("  ") == ""
        for value in ("maybe", 1, "left"):
            with pytest.raises(ratings.InvalidRatingError):
                ratings.normalize_rating(value)

    def test_a_kind_and_a_note_are_validated(self) -> None:
        assert ratings.normalize_kind("threat") == "threat"
        with pytest.raises(ratings.InvalidRatingError):
            ratings.normalize_kind("not-a-kind")
        with pytest.raises(ratings.InvalidRatingError):
            ratings.normalize_kind("")
        assert ratings.normalize_note(None) == ""
        with pytest.raises(ratings.InvalidRatingError):
            ratings.normalize_note(42)
        with pytest.raises(ratings.InvalidRatingError):
            ratings.normalize_note("x" * (ratings.MAX_NOTE_CHARS + 1))


class TestStore:
    def test_a_rating_is_set_read_and_cleared(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            assert ratings.get_rating(conn, binary_id=ids["binary"], kind="threat") is None
            stored = ratings.set_rating(
                conn, binary_id=ids["binary"], kind="threat", rating="up", note="useful", actor="me"
            )
            assert stored["rating"] == "up"
            assert stored["note"] == "useful"
            assert stored["actor"] == "me"

            replaced = ratings.set_rating(
                conn, binary_id=ids["binary"], kind="threat", rating="down"
            )
            assert replaced["rating"] == "down"
            assert replaced["note"] == ""

            cleared = ratings.set_rating(conn, binary_id=ids["binary"], kind="threat", rating=None)
            assert cleared["rating"] == ""
            assert ratings.list_ratings(conn, ids["binary"]) == []

    def test_an_artifact_that_was_never_produced_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, scan=False)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            with pytest.raises(ratings.UnknownArtifactError):
                ratings.set_rating(conn, binary_id=ids["binary"], kind="threat", rating="up")
            with pytest.raises(ratings.UnknownArtifactError):
                ratings.require_artifact(conn, 999, "threat")

    def test_a_verdict_survives_a_scan_re_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            ratings.set_rating(conn, binary_id=ids["binary"], kind="threat", rating="up")
            store.set_scan(conn, ids["analysis"], store.SCAN_KIND_THREAT, {"iocs": {"url": ["x"]}})
            stored = ratings.get_rating(conn, binary_id=ids["binary"], kind="threat")
        assert stored is not None
        assert stored["rating"] == "up"

    def test_a_journaled_write_reverts_both_ways(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            # A first rating: a revert removes the row that created it.
            action = journal.new_action()
            with journal.journaled(conn, action) as log:
                ratings.journaled_set(
                    conn, log, binary_id=ids["binary"], kind="threat", rating="up"
                )
            assert ratings.get_rating(conn, binary_id=ids["binary"], kind="threat") is not None
            assert journal.revert_action(conn, action)["reverted"] > 0
            assert ratings.get_rating(conn, binary_id=ids["binary"], kind="threat") is None

            # A second rating replacing the first: a revert restores the first.
            ratings.set_rating(conn, binary_id=ids["binary"], kind="threat", rating="up")
            action = journal.new_action()
            with journal.journaled(conn, action) as log:
                ratings.journaled_set(
                    conn, log, binary_id=ids["binary"], kind="threat", rating="down"
                )
            assert journal.revert_action(conn, action)["reverted"] > 0
            restored = ratings.get_rating(conn, binary_id=ids["binary"], kind="threat")
        assert restored is not None
        assert restored["rating"] == "up"

    def test_describe_lists_every_stored_artifact(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            ratings.set_rating(conn, binary_id=ids["binary"], kind="threat", rating="down")
            payload = ratings.describe(conn, ids["binary"])
        assert payload["count"] == 1
        assert payload["rated"] == 1
        assert payload["artifacts"][0]["kind"] == "threat"
        assert payload["artifacts"][0]["stored"] is True
        assert "threat" in payload["kinds"]


class TestRoutes:
    def test_the_reads_and_the_write(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        url = f"/api/binaries/{ids['binary']}/ratings"
        status, headers, body = wsgi_request("GET", url)
        assert status.startswith("200"), body
        payload = json_body(body, headers)
        assert payload["artifacts"][0]["rating"] is None

        status, headers, body = wsgi_request(
            "PUT", f"{url}/threat", body=json.dumps({"rating": "up", "note": "useful"})
        )
        assert status.startswith("200"), body
        written = json_body(body, headers)
        assert written["rating"] == "up"
        assert written["journal_action"]

        status, headers, body = wsgi_request("GET", f"{url}/threat")
        assert json_body(body, headers)["rating"]["rating"] == "up"

        cleared, headers, body = wsgi_request(
            "PUT", f"{url}/threat", body=json.dumps({"rating": None})
        )
        assert cleared.startswith("200")
        assert json_body(body, headers)["rating"] == ""

    def test_the_refusals(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        url = f"/api/binaries/{ids['binary']}/ratings"
        bad, headers, body = wsgi_request(
            "PUT", f"{url}/threat", body=json.dumps({"rating": "maybe"})
        )
        assert bad.startswith("400")
        assert json_body(body, headers)["error"] == ratings.ERROR_INVALID

        unknown_kind, headers, body = wsgi_request(
            "PUT", f"{url}/not-a-kind", body=json.dumps({"rating": "up"})
        )
        assert unknown_kind.startswith(("400", "404"))
        assert json_body(body, headers)["error"] == ratings.ERROR_INVALID

        no_artifact, headers, body = wsgi_request("GET", f"{url}/capabilities")
        assert no_artifact.startswith("404")
        assert json_body(body, headers)["error"] == ratings.ERROR_NO_ARTIFACT

        missing, _, _ = wsgi_request("GET", "/api/binaries/999/ratings")
        assert missing.startswith("404")


class TestCliAndMcp:
    def test_the_commands(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        binary = str(ids["binary"])
        rated = runner.invoke(
            cli.app, ["rate", binary, "threat", "up", "--note", "useful", "--json"]
        )
        assert rated.exit_code == 0, rated.output
        assert json.loads(rated.output)["rating"] == "up"

        human = runner.invoke(cli.app, ["ratings", binary])
        assert human.exit_code == 0, human.output
        assert "threat" in human.output

        listed = runner.invoke(cli.app, ["ratings", binary, "--json"])
        assert json.loads(listed.output)["rated"] == 1

        cleared = runner.invoke(cli.app, ["rate", binary, "threat"])
        assert cleared.exit_code == 0, cleared.output
        assert "Cleared" in cleared.output

        bad = runner.invoke(cli.app, ["rate", binary, "threat", "maybe"])
        assert bad.exit_code == 1
        assert "invalid rating" in bad.output

        unknown = runner.invoke(cli.app, ["rate", binary, "capabilities", "up"])
        assert unknown.exit_code == 1
        assert ratings.ERROR_NO_ARTIFACT in unknown.output

        monkeypatch.setenv(DB_ENV, str(tmp_path / "missing" / "portal.db"))
        for argv in (["rate", "1", "threat", "up"], ["ratings", "1"]):
            result = runner.invoke(cli.app, argv)
            assert result.exit_code == 1, argv
            assert "no reportal database" in result.output

    def test_the_tools(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        listed, failed = mcp_server.call_tool("list_artifact_ratings", {"binary_id": ids["binary"]})
        assert not failed, listed
        assert listed["count"] == 1

        rated, failed = mcp_server.call_tool(
            "rate_artifact",
            {"binary_id": ids["binary"], "kind": "threat", "rating": "down", "note": "meh"},
        )
        assert not failed, rated
        assert rated["rating"] == "down"
        assert rated["journal_action"]

        bad, failed = mcp_server.call_tool(
            "rate_artifact", {"binary_id": ids["binary"], "kind": "threat", "rating": "maybe"}
        )
        assert failed
        assert bad["error"] == ratings.ERROR_INVALID

        unknown, failed = mcp_server.call_tool(
            "rate_artifact", {"binary_id": ids["binary"], "kind": "capabilities", "rating": "up"}
        )
        assert failed
        assert unknown["error"] == ratings.ERROR_NO_ARTIFACT

        missing, failed = mcp_server.call_tool("list_artifact_ratings", {"binary_id": 999})
        assert failed
        assert missing["error"] == "binary not found"
