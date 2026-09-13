"""Deleting a binary and undoing it must restore its history rows.

``bulk_actions.BINARY_DELETE_SNAPSHOTS`` is what the delete journal reverts from,
so a table missing from that tuple is gone for good once the binary is deleted.
The two history tables are children of a binary (``data_type_history`` through
its own ``binary_id``, ``signature_history`` through the function it names), and
they were absent from the tuple: the delete's own undo brought back the types and
signatures but not the record of how they got there.  These tests pin both.
"""

from __future__ import annotations

import contextlib
import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

from reportal import bulk_actions, data_types, journal, signatures, store


@pytest.fixture()
def conn(portal_db: Path) -> Iterator[sqlite3.Connection]:
    with contextlib.closing(store.connect(portal_db)) as connection:
        yield connection


def _seed(conn: sqlite3.Connection) -> tuple[int, int, int]:
    """A binary with one data type that has history and one signed function."""
    binary_id = store.add_binary(conn, sha256="ab" * 32, name="demo.exe", path="")
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="test")
    function_id, _created = store.upsert_function(
        conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", size=0x10, status="STUB"
    )
    type_id = store.add_data_type(
        conn, binary_id=binary_id, name="Widget", size=4, members=[], source="manual"
    )
    data_types.rename_type(conn, type_id, name="WidgetRenamed")
    store.upsert_signature(
        conn,
        function_id=function_id,
        name="sub_1000",
        return_type="void",
        calling_convention="__cdecl",
        parameters=[],
        source="manual",
    )
    signatures.set_return_type(conn, function_id, return_type="unsigned int")
    return binary_id, function_id, type_id


class TestBinaryDeleteRestoresHistory:
    def test_the_delete_undo_brings_back_both_history_tables(
        self, conn: sqlite3.Connection
    ) -> None:
        binary_id, function_id, type_id = _seed(conn)
        assert store.list_data_type_history(conn, type_id) != []
        assert store.list_signature_history(conn, function_id) != []

        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            bulk_actions.apply_binary_action(conn, action="delete", ids=[binary_id], log=log)
        assert store.get_binary(conn, binary_id) is None
        # The cascade took the history with the rows, which is why the snapshot
        # is the only way back.
        assert store.list_data_type_history(conn, type_id) == []

        result = journal.revert_action(conn, action)
        assert result["reverted"] >= 1
        assert store.get_binary(conn, binary_id) is not None
        assert store.list_data_type_history(conn, type_id) != []
        assert store.list_signature_history(conn, function_id) != []

    def test_both_tables_are_named_by_the_snapshot_tuple(self) -> None:
        """The tuple is the contract; naming a table here is what makes undo work."""
        tables = {table for table, _where in bulk_actions.BINARY_DELETE_SNAPSHOTS}
        assert {"data_types", "data_type_history", "signature_history"} <= tables
