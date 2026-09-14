"""Tests for the collection routes: read one, update, delete, members and tags."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from conftest import json_body, wsgi_request

from reportal import auth, journal, store

CONNECTION: sqlite3.Connection | None = None


def _binary(conn: sqlite3.Connection, name: str) -> int:
    """Register one binary row, the way an upload would."""
    return store.add_binary(
        conn,
        sha256=f"{name:0<64}"[:64],
        name=name,
        path=f"/tmp/{name}",
        size=16,
    )


def _request(method: str, path: str, body: dict[str, Any] | None = None) -> tuple[str, Any]:
    """Drive one request and return its status line and parsed body."""
    raw = b"" if body is None else json.dumps(body).encode()
    status, headers, payload = wsgi_request(method, path, body=raw)
    return status, json_body(payload, headers)


class TestReadOne:
    def test_a_collection_carries_its_members_and_tags(self, conn: sqlite3.Connection) -> None:
        collection_id = store.create_collection(conn, name="games", description="targets")
        first = _binary(conn, "first.exe")
        second = _binary(conn, "second.exe")
        store.add_collection_binary(conn, collection_id, first)
        store.add_collection_binary(conn, collection_id, second)
        store.set_collection_tags(conn, collection_id, ["dos", "pe"])

        status, payload = _request("GET", f"/api/collections/{collection_id}")

        assert status.startswith("200")
        assert payload["name"] == "games"
        assert payload["description"] == "targets"
        assert payload["binary_count"] == 2
        assert [row["name"] for row in payload["binaries"]] == ["first.exe", "second.exe"]
        assert [tag["name"] for tag in payload["tags"]] == ["dos", "pe"]

    def test_an_unknown_collection_is_404(self, conn: sqlite3.Connection) -> None:
        status, payload = _request("GET", "/api/collections/4242")

        assert status.startswith("404")
        assert payload["error"] == "collection not found"


class TestUpdate:
    def test_a_rename_leaves_the_members_alone(self, conn: sqlite3.Connection) -> None:
        collection_id = store.create_collection(conn, name="old")
        binary_id = _binary(conn, "kept.exe")
        store.add_collection_binary(conn, collection_id, binary_id)

        status, payload = _request(
            "PATCH", f"/api/collections/{collection_id}", {"name": "new", "scope": "training"}
        )

        assert status.startswith("200")
        assert payload["name"] == "new"
        assert payload["scope"] == "training"
        stored = store.get_collection(conn, collection_id)
        assert stored is not None
        assert stored["binary_count"] == 1

    def test_a_rename_onto_a_taken_name_is_400(self, conn: sqlite3.Connection) -> None:
        store.create_collection(conn, name="taken")
        other = store.create_collection(conn, name="free")

        status, payload = _request("PATCH", f"/api/collections/{other}", {"name": "taken"})

        assert status.startswith("400")
        assert payload["error"] == "invalid collection"

    def test_an_empty_body_is_400(self, conn: sqlite3.Connection) -> None:
        collection_id = store.create_collection(conn, name="c")

        status, payload = _request("PATCH", f"/api/collections/{collection_id}", {})

        assert status.startswith("400")
        assert payload["detail"] == "name, description or scope is required"

    def test_an_unknown_collection_is_404(self, conn: sqlite3.Connection) -> None:
        status, _payload = _request("PATCH", "/api/collections/4242", {"name": "x"})

        assert status.startswith("404")


class TestDelete:
    def test_a_delete_cascades_membership_and_tags(self, conn: sqlite3.Connection) -> None:
        collection_id = store.create_collection(conn, name="doomed")
        binary_id = _binary(conn, "member.exe")
        store.add_collection_binary(conn, collection_id, binary_id)
        store.set_collection_tags(conn, collection_id, ["keep"])

        status, payload = _request("DELETE", f"/api/collections/{collection_id}")

        assert status.startswith("200")
        assert payload["deleted"] is True
        assert store.get_collection(conn, collection_id) is None
        assert conn.execute("SELECT COUNT(*) FROM collection_binaries").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM collection_tags").fetchone()[0] == 0
        # The tag itself survives; only the link is gone.
        assert store.find_tag(conn, "keep") is not None

    def test_a_delete_is_revertible(self, conn: sqlite3.Connection, portal_db: Any) -> None:
        collection_id = store.create_collection(conn, name="revertible")
        binary_id = _binary(conn, "member.exe")
        store.add_collection_binary(conn, collection_id, binary_id)

        status, payload = _request("DELETE", f"/api/collections/{collection_id}")
        assert status.startswith("200")
        action = payload["journal_action"]
        assert store.get_collection(conn, collection_id) is None

        journal.revert_action(conn, action)

        restored = store.get_collection(conn, collection_id)
        assert restored is not None
        assert [row["id"] for row in restored["binaries"]] == [binary_id]

    def test_an_unknown_collection_is_404(self, conn: sqlite3.Connection) -> None:
        status, payload = _request("DELETE", "/api/collections/4242")

        assert status.startswith("404")
        assert payload["error"] == "collection not found"


class TestMembers:
    def test_replace_makes_the_list_exact(self, conn: sqlite3.Connection) -> None:
        collection_id = store.create_collection(conn, name="exact")
        first = _binary(conn, "first.exe")
        second = _binary(conn, "second.exe")
        third = _binary(conn, "third.exe")
        store.replace_collection_binaries(conn, collection_id, [first, second])

        status, payload = _request(
            "PATCH", f"/api/collections/{collection_id}/binaries", {"binary_ids": [second, third]}
        )

        assert status.startswith("200")
        assert payload["added"] == [third]
        assert payload["removed"] == [first]
        assert payload["kept"] == [second]
        stored = store.get_collection(conn, collection_id)
        assert stored is not None
        assert sorted(row["id"] for row in stored["binaries"]) == [second, third]

    def test_replace_rejects_an_unknown_binary_before_writing(
        self, conn: sqlite3.Connection
    ) -> None:
        collection_id = store.create_collection(conn, name="guarded")
        first = _binary(conn, "first.exe")
        store.add_collection_binary(conn, collection_id, first)

        status, payload = _request(
            "PATCH", f"/api/collections/{collection_id}/binaries", {"binary_ids": [first, 9999]}
        )

        assert status.startswith("404")
        assert payload["error"] == "binary not found"
        stored = store.get_collection(conn, collection_id)
        assert stored is not None, "the collection must survive a refused write"
        assert [row["id"] for row in stored["binaries"]] == [first]

    def test_remove_keeps_the_other_members(self, conn: sqlite3.Connection) -> None:
        collection_id = store.create_collection(conn, name="partial")
        first = _binary(conn, "first.exe")
        second = _binary(conn, "second.exe")
        store.replace_collection_binaries(conn, collection_id, [first, second])

        status, payload = _request(
            "DELETE", f"/api/collections/{collection_id}/binaries", {"binary_ids": [first]}
        )

        assert status.startswith("200")
        assert payload["removed"] == [first]
        stored = store.get_collection(conn, collection_id)
        assert stored is not None
        assert [row["id"] for row in stored["binaries"]] == [second]

    def test_a_missing_list_is_400(self, conn: sqlite3.Connection) -> None:
        collection_id = store.create_collection(conn, name="c")

        status, payload = _request("PATCH", f"/api/collections/{collection_id}/binaries", {})

        assert status.startswith("400")
        assert payload["detail"] == "binary_ids is required"


class TestCollectionTags:
    def test_replace_creates_removes_and_keeps(self, conn: sqlite3.Connection) -> None:
        collection_id = store.create_collection(conn, name="tagged")
        store.set_collection_tags(conn, collection_id, ["keep", "drop"])

        status, payload = _request(
            "PATCH", f"/api/collections/{collection_id}/tags", {"tags": ["keep", "added"]}
        )

        assert status.startswith("200")
        assert payload["added"] == ["added"]
        assert payload["removed"] == ["drop"]
        stored = store.get_collection(conn, collection_id)
        assert stored is not None
        assert [tag["name"] for tag in stored["tags"]] == ["added", "keep"]

    def test_an_empty_list_clears_every_tag(self, conn: sqlite3.Connection) -> None:
        collection_id = store.create_collection(conn, name="cleared")
        store.set_collection_tags(conn, collection_id, ["tag"])

        status, payload = _request("PATCH", f"/api/collections/{collection_id}/tags", {"tags": []})

        assert status.startswith("200")
        assert payload["removed"] == ["tag"]
        stored = store.get_collection(conn, collection_id)
        assert stored is not None
        assert stored["tags"] == []

    def test_a_missing_tags_key_is_400(self, conn: sqlite3.Connection) -> None:
        collection_id = store.create_collection(conn, name="c")

        status, payload = _request("PATCH", f"/api/collections/{collection_id}/tags", {})

        assert status.startswith("400")
        assert payload["detail"] == "tags is required"

    def test_a_non_string_tag_is_400(self, conn: sqlite3.Connection) -> None:
        collection_id = store.create_collection(conn, name="c")

        status, payload = _request("PATCH", f"/api/collections/{collection_id}/tags", {"tags": [7]})

        assert status.startswith("400")
        assert payload["error"] == "tags must be a list of strings"


class TestStoreRules:
    def test_get_collection_of_an_unknown_id_is_none(self, conn: sqlite3.Connection) -> None:
        assert store.get_collection(conn, 4242) is None

    def test_update_of_an_unknown_id_is_none(self, conn: sqlite3.Connection) -> None:
        assert store.update_collection(conn, 4242, name="x") is None

    def test_an_empty_rename_is_a_value_error(self, conn: sqlite3.Connection) -> None:
        collection_id = store.create_collection(conn, name="c")

        try:
            store.update_collection(conn, collection_id, name="  ")
        except ValueError as exc:
            assert "must not be empty" in str(exc)
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an empty name must be refused")

    def test_delete_collection_of_an_unknown_id_is_false(self, conn: sqlite3.Connection) -> None:
        assert store.delete_collection(conn, 4242) is False

    def test_replace_binaries_dedupes_a_repeated_id(self, conn: sqlite3.Connection) -> None:
        collection_id = store.create_collection(conn, name="deduped")
        binary_id = _binary(conn, "one.exe")

        change = store.replace_collection_binaries(conn, collection_id, [binary_id, binary_id])

        assert change["added"] == [binary_id]
        assert change["kept"] == []

    def test_replace_binaries_of_an_unknown_collection_raises(
        self, conn: sqlite3.Connection
    ) -> None:
        try:
            store.replace_collection_binaries(conn, 4242, [])
        except KeyError as exc:
            assert "4242" in str(exc)
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an unknown collection must raise")

    def test_set_tags_of_an_unknown_collection_raises(self, conn: sqlite3.Connection) -> None:
        try:
            store.set_collection_tags(conn, 4242, ["x"])
        except KeyError as exc:
            assert "4242" in str(exc)
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an unknown collection must raise")

    def test_replace_binaries_keeps_only_the_listed_members(self, conn: sqlite3.Connection) -> None:
        collection_id = store.create_collection(conn, name="emptied")
        binary_id = _binary(conn, "one.exe")
        store.add_collection_binary(conn, collection_id, binary_id)

        change = store.replace_collection_binaries(conn, collection_id, [])

        assert change == {"added": [], "removed": [binary_id], "kept": []}
        stored = store.get_collection(conn, collection_id)
        assert stored is not None
        assert stored["binaries"] == []


class TestOrder:
    """The list's sort control: the vocabulary, each order and the timestamps."""

    def _three(self, conn: sqlite3.Connection) -> dict[str, int]:
        ids = {
            "beta": store.create_collection(conn, name="beta"),
            "alpha": store.create_collection(conn, name="alpha"),
            "gamma": store.create_collection(conn, name="Gamma"),
        }
        first = _binary(conn, "first.exe")
        second = _binary(conn, "second.exe")
        store.replace_collection_binaries(conn, ids["alpha"], [first, second])
        store.replace_collection_binaries(conn, ids["beta"], [first])
        return ids

    def _names(self, conn: sqlite3.Connection, order: str) -> list[str]:
        return [row["name"] for row in store.list_collections(conn, order=order)]

    def test_the_default_order_is_creation(self, conn: sqlite3.Connection) -> None:
        self._three(conn)

        assert self._names(conn, "id") == ["beta", "alpha", "Gamma"]
        assert self._names(conn, store.DEFAULT_COLLECTION_ORDER) == ["beta", "alpha", "Gamma"]

    def test_name_sorts_case_insensitively(self, conn: sqlite3.Connection) -> None:
        self._three(conn)

        assert self._names(conn, "name") == ["alpha", "beta", "Gamma"]

    def test_size_sorts_by_member_count_then_name(self, conn: sqlite3.Connection) -> None:
        self._three(conn)

        assert self._names(conn, "size") == ["alpha", "beta", "Gamma"]

    def test_updated_puts_the_most_recently_changed_first(self, conn: sqlite3.Connection) -> None:
        ids = self._three(conn)
        store.update_collection(conn, ids["gamma"], description="touched")

        assert self._names(conn, "updated")[0] == "Gamma"

    def test_an_unknown_order_is_a_value_error(self, conn: sqlite3.Connection) -> None:
        try:
            store.list_collections(conn, order="biggest")
        except ValueError as exc:
            assert "unknown collection order" in str(exc)
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an unknown order must be refused")

    def test_every_write_path_touches_the_timestamp(self, conn: sqlite3.Connection) -> None:
        # Each writer is checked the same way: touch the newest collection and
        # it has to sort first under `updated`, whatever the clock resolution.
        ids = self._three(conn)
        binary_id = _binary(conn, "third.exe")
        for touch in (
            lambda: store.update_collection(conn, ids["gamma"], description="touched"),
            lambda: store.replace_collection_binaries(conn, ids["gamma"], [binary_id]),
            lambda: store.set_collection_tags(conn, ids["gamma"], ["triage"]),
        ):
            touch()

            assert self._names(conn, "updated")[0] == "Gamma"

    def test_a_write_that_changes_nothing_leaves_the_timestamp_alone(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = self._three(conn)
        store.set_collection_tags(conn, ids["gamma"], ["triage"])
        stamped = store.get_collection(conn, ids["gamma"])
        assert stamped is not None
        touched = str(stamped["updated_at"])

        store.replace_collection_binaries(conn, ids["gamma"], [])
        store.set_collection_tags(conn, ids["gamma"], ["triage"])

        unchanged = store.get_collection(conn, ids["gamma"])
        assert unchanged is not None
        assert str(unchanged["updated_at"]) == touched

    def test_the_route_echoes_the_order_it_applied(self, conn: sqlite3.Connection) -> None:
        self._three(conn)

        status, payload = _request("GET", "/api/collections?order=name")

        assert status.startswith("200")
        assert payload["order"] == "name"
        assert [row["name"] for row in payload["collections"]] == ["alpha", "beta", "Gamma"]

    def test_an_unknown_order_is_400(self, conn: sqlite3.Connection) -> None:
        status, payload = _request("GET", "/api/collections?order=biggest")

        assert status.startswith("400")
        assert payload["error"] == "invalid order"
        assert "biggest" in payload["detail"]

    def test_a_column_a_pre_column_database_lacks_is_backfilled(
        self, conn: sqlite3.Connection
    ) -> None:
        collection_id = store.create_collection(conn, name="legacy")
        conn.execute("UPDATE collections SET updated_at = '' WHERE id = ?", (collection_id,))
        conn.commit()

        store._upgrade_schema(conn)

        row = store.get_collection(conn, collection_id)
        assert row is not None
        assert row["updated_at"] == row["created_at"]


class TestScopeFilterAndOwnerOrder:
    """The list's scope filter and its sort by the owning team's name."""

    def _scoped(self, conn: sqlite3.Connection) -> dict[str, int]:
        """Three collections: personal, team-owned and team-owned but public."""
        team = auth.create_team(conn, name="blue")
        ids = {
            "personal": store.create_collection(conn, name="personal-set"),
            "team": store.create_collection(conn, name="team-set"),
            "shared": store.create_collection(conn, name="shared-set"),
        }
        store.set_collection_scope(
            conn, ids["team"], owner_team_id=int(team["id"]), visibility="team"
        )
        store.set_collection_scope(
            conn, ids["shared"], owner_team_id=int(team["id"]), visibility="public"
        )
        return ids

    def _names(self, conn: sqlite3.Connection, workspace: str) -> list[str]:
        rows = store.list_collections(conn, workspace=workspace)
        return [row["name"] for row in rows]

    def test_personal_is_every_collection_no_team_owns(self, conn: sqlite3.Connection) -> None:
        self._scoped(conn)

        assert self._names(conn, "personal") == ["personal-set"]

    def test_team_is_every_collection_a_team_owns(self, conn: sqlite3.Connection) -> None:
        self._scoped(conn)

        assert sorted(self._names(conn, "team")) == ["shared-set", "team-set"]

    def test_public_is_every_collection_the_workspace_may_see(
        self, conn: sqlite3.Connection
    ) -> None:
        self._scoped(conn)

        assert sorted(self._names(conn, "public")) == ["personal-set", "shared-set"]

    def test_a_row_carries_the_owning_team_and_a_personal_one_carries_none(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = self._scoped(conn)

        rows = {row["id"]: row for row in store.list_collections(conn)}

        assert rows[ids["team"]]["owner_team_name"] == "blue"
        assert rows[ids["team"]]["visibility"] == "team"
        assert rows[ids["personal"]]["owner_team_id"] is None
        assert rows[ids["personal"]]["owner_team_name"] is None

    def test_owner_sorts_by_team_name_with_the_personal_first(
        self, conn: sqlite3.Connection
    ) -> None:
        self._scoped(conn)
        second = auth.create_team(conn, name="amber")
        other = store.create_collection(conn, name="other-set")
        store.set_collection_scope(conn, other, owner_team_id=int(second["id"]), visibility="team")

        ordered = [row["name"] for row in store.list_collections(conn, order="owner")]

        # The personal one first, then the owning teams by name (amber before
        # blue), and the id breaks the tie inside one team.
        assert ordered == ["personal-set", "other-set", "team-set", "shared-set"]

    def test_an_unknown_workspace_is_a_value_error(self, conn: sqlite3.Connection) -> None:
        try:
            store.list_collections(conn, workspace="everywhere")
        except ValueError as exc:
            assert "unknown workspace filter" in str(exc)
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an unknown workspace filter must be refused")

    def test_the_route_echoes_the_workspace_it_applied(self, conn: sqlite3.Connection) -> None:
        ids = self._scoped(conn)

        status, payload = _request("GET", "/api/collections?workspace=team")

        assert status.startswith("200")
        assert payload["workspace"] == "team"
        assert sorted(row["name"] for row in payload["collections"]) == ["shared-set", "team-set"]
        assert payload["collections"][0]["id"] in ids.values()

    def test_the_route_without_a_workspace_answers_every_collection(
        self, conn: sqlite3.Connection
    ) -> None:
        self._scoped(conn)

        status, payload = _request("GET", "/api/collections")

        assert status.startswith("200")
        assert payload["workspace"] is None
        assert len(payload["collections"]) == 3

    def test_an_unknown_workspace_is_400(self, conn: sqlite3.Connection) -> None:
        status, payload = _request("GET", "/api/collections?workspace=everywhere")

        assert status.startswith("400")
        assert payload["error"] == "invalid workspace"
        assert "everywhere" in payload["detail"]
