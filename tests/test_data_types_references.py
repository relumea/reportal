"""Tests for the data-type reverse indices: referenced-by and used-by-functions."""

from __future__ import annotations

import sqlite3

import pytest

from reportal import data_types, store


def _seed_binary(conn: sqlite3.Connection) -> int:
    return store.add_binary(conn, sha256="ab" * 32, name="demo.exe")


def _add_type(
    conn: sqlite3.Connection,
    binary_id: int,
    name: str,
    *,
    kind: str = data_types.KIND_STRUCT,
    namespace: str = "",
    members: list[dict[str, object]] | None = None,
    values: list[dict[str, object]] | None = None,
    target: str = "",
    element_count: int | None = None,
) -> int:
    member_rows = members or []
    normalized, size = data_types.recompute(kind, member_rows, target, element_count)
    return store.add_data_type(
        conn,
        binary_id=binary_id,
        name=name,
        size=size,
        members=normalized,
        kind=kind,
        namespace=namespace,
        values=values or [],
        target=target,
        element_count=element_count,
        source=data_types.SOURCE_MANUAL,
    )


def _member(name: str, type_text: str, *, pointer: bool = False) -> dict[str, object]:
    return {"name": name, "type": type_text, "pointer": pointer, "count": None}


def _seed_model(conn: sqlite3.Connection, binary_id: int) -> int:
    """Seed PlayerInfo plus one referrer of every relationship, and return PlayerInfo's id."""
    player = _add_type(conn, binary_id, "PlayerInfo", members=[_member("slot", "int")])
    _add_type(conn, binary_id, "Holder", members=[_member("info", "PlayerInfo")])
    _add_type(conn, binary_id, "PlayerAlias", kind=data_types.KIND_TYPEDEF, target="PlayerInfo")
    _add_type(conn, binary_id, "PlayerPtr", kind=data_types.KIND_POINTER, target="PlayerInfo")
    _add_type(
        conn,
        binary_id,
        "PlayerArray",
        kind=data_types.KIND_ARRAY,
        target="PlayerInfo",
        element_count=2,
    )
    _add_type(
        conn,
        binary_id,
        "PlayerCallback",
        kind=data_types.KIND_FUNCTION,
        target="PlayerInfo",
        members=[_member("", "PlayerInfo")],
    )
    return player


class TestReferences:
    def test_every_relationship_is_reported(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        player = _seed_model(conn, binary_id)
        payload = data_types.references(conn, player)
        by_name = {entry["name"]: entry for entry in payload["referenced_by"]}
        assert by_name["Holder"]["relationships"] == [data_types.RELATION_MEMBER]
        assert by_name["PlayerAlias"]["relationships"] == [data_types.RELATION_TYPEDEF_TARGET]
        assert by_name["PlayerPtr"]["relationships"] == [data_types.RELATION_POINTEE]
        assert by_name["PlayerArray"]["relationships"] == [data_types.RELATION_ARRAY_ELEMENT]
        assert sorted(by_name["PlayerCallback"]["relationships"]) == [
            data_types.RELATION_PARAMETER,
            data_types.RELATION_RETURN_TYPE,
        ]

    def test_the_note_states_that_matching_is_by_name(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        player = _seed_model(conn, binary_id)
        payload = data_types.references(conn, player)
        assert payload["note"] == data_types.REFERENCES_NOTE

    def test_a_type_nothing_references_answers_empty_tables(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        lonely = _add_type(conn, binary_id, "Lonely", members=[_member("a", "int")])
        payload = data_types.references(conn, lonely)
        assert payload["referenced_by"] == []
        assert payload["used_by_functions"] == []
        assert payload["count"] == 0

    def test_an_unknown_id_raises(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(data_types.UnknownDataTypeError):
            data_types.references(conn, 4242)

    def test_a_name_in_two_namespaces_is_two_entries(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        player = _add_type(conn, binary_id, "PlayerInfo", members=[_member("slot", "int")])
        _add_type(
            conn,
            binary_id,
            "WintHolder",
            namespace="winnt",
            members=[_member("info", "PlayerInfo")],
        )
        _add_type(
            conn,
            binary_id,
            "AppHolder",
            namespace="app",
            members=[_member("info", "PlayerInfo")],
        )
        payload = data_types.references(conn, player)
        assert [(entry["name"], entry["namespace"]) for entry in payload["referenced_by"]] == [
            ("AppHolder", "app"),
            ("WintHolder", "winnt"),
        ]


class TestUsedByFunctions:
    def test_a_signature_naming_the_type_is_reported(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        player = _add_type(conn, binary_id, "PlayerInfo", members=[_member("slot", "int")])
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        function_id = store.add_function(
            conn, analysis_id=analysis_id, va=0x1000, name="LoadPlayer"
        )
        store.upsert_signature(
            conn,
            function_id=function_id,
            name="LoadPlayer",
            return_type="PlayerInfo *",
            calling_convention="",
            parameters=[{"index": 0, "type": "PlayerInfo", "name": "info"}],
        )
        payload = data_types.references(conn, player)
        assert payload["used_by_functions"] == [
            {
                "function_id": function_id,
                "name": "LoadPlayer",
                "usages": [data_types.RELATION_RETURN_TYPE, data_types.RELATION_PARAMETER],
            }
        ]

    def test_an_unrelated_signature_is_not_reported(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        player = _add_type(conn, binary_id, "PlayerInfo", members=[_member("slot", "int")])
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        function_id = store.add_function(conn, analysis_id=analysis_id, va=0x1000, name="Other")
        store.upsert_signature(
            conn,
            function_id=function_id,
            name="Other",
            return_type="int",
            calling_convention="",
            parameters=[{"index": 0, "type": "unsigned int", "name": "count"}],
        )
        payload = data_types.references(conn, player)
        assert payload["used_by_functions"] == []
