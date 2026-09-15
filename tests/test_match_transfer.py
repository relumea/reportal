"""Tests for reportal.matching symbol transfer: modes, bulk and revert.

Every test drives the real journal, so a transfer's writes are asserted twice:
once in the stored rows, and once in the revert that puts them back.
"""

from __future__ import annotations

import sqlite3
from typing import Any

import pytest

from reportal import auth, data_types, journal, matching, store

CANDIDATE_SIGNATURE: dict[str, Any] = {
    "return_type": "int",
    "calling_convention": "cdecl",
    "parameters": [{"index": 0, "type": "NP_ENTRY *", "name": "entry"}],
}


def _put_signature(
    conn: sqlite3.Connection,
    function_id: int,
    *,
    name: str,
    return_type: str,
    calling_convention: str,
    parameters: list[dict[str, Any]],
) -> None:
    store.upsert_signature(
        conn,
        function_id=function_id,
        name=name,
        return_type=return_type,
        calling_convention=calling_convention,
        parameters=parameters,
        source="decompilation",
    )


def _name(conn: sqlite3.Connection, function_id: int) -> str:
    """The stored name of one function, asserting it exists."""
    function = store.get_function(conn, function_id)
    assert function is not None
    return str(function["name"])


def _seed(conn: sqlite3.Connection) -> dict[str, int]:
    """One binary with a target and a recorded candidate."""
    binary = store.add_binary(conn, sha256="aa" * 32, name="a.exe")
    analysis = store.create_analysis(conn, binary_id=binary, engine="manual")
    target = store.add_function(conn, analysis_id=analysis, va=0x1000, name="sub_1000", size=16)
    candidate = store.add_function(conn, analysis_id=analysis, va=0x2000, name="NP_Open", size=16)
    store.record_match(
        conn,
        function_id=target,
        candidate_function_id=candidate,
        similarity=95.0,
        confidence=0.9,
    )
    return {"binary": binary, "analysis": analysis, "target": target, "candidate": candidate}


def _seed_pair(conn: sqlite3.Connection) -> dict[str, int]:
    """Two targets that both recorded the same candidate."""
    ids = _seed(conn)
    second = store.add_function(
        conn, analysis_id=ids["analysis"], va=0x1100, name="sub_1100", size=16
    )
    store.record_match(
        conn,
        function_id=second,
        candidate_function_id=ids["candidate"],
        similarity=92.0,
        confidence=0.8,
    )
    ids["second"] = second
    return ids


def _apply(
    conn: sqlite3.Connection, action: str, plan: matching.TransferPlan
) -> matching.TransferPlan:
    with journal.journaled(conn, action) as log:
        matching.apply_transfer(conn, log, plan, actor="test")
    return plan


class TestPlanModes:
    def test_name_mode_renames_only(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _put_signature(conn, ids["candidate"], name="NP_Open", **CANDIDATE_SIGNATURE)
        _put_signature(
            conn,
            ids["target"],
            name="sub_1000",
            return_type="void",
            calling_convention="",
            parameters=[],
        )
        plan = matching.plan_transfer(
            conn, function_id=ids["target"], candidate_function_id=ids["candidate"], mode="name"
        )
        assert plan.status == matching.TRANSFER_STATUS_APPLIED
        assert plan.renames is True
        assert plan.writes_signature is False
        _apply(conn, journal.new_action(), plan)

        function = store.get_function(conn, ids["target"])
        assert function is not None
        assert function["name"] == "NP_Open"
        assert function["name_source"] == "match"
        signature = store.get_signature(conn, ids["target"])
        assert signature is not None
        assert signature["return_type"] == "void"
        assert store.list_name_history(conn, ids["target"])[0]["source"] == "match"
        assert store.list_signature_history(conn, ids["target"]) == []

    def test_signature_mode_copies_the_signature_only(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _put_signature(conn, ids["candidate"], name="NP_Open", **CANDIDATE_SIGNATURE)
        _put_signature(
            conn,
            ids["target"],
            name="sub_1000",
            return_type="void",
            calling_convention="",
            parameters=[],
        )
        plan = matching.plan_transfer(
            conn,
            function_id=ids["target"],
            candidate_function_id=ids["candidate"],
            mode="signature",
        )
        assert plan.writes_signature is True
        assert plan.renames is False
        _apply(conn, journal.new_action(), plan)

        function = store.get_function(conn, ids["target"])
        assert function is not None
        assert function["name"] == "sub_1000"
        signature = store.get_signature(conn, ids["target"])
        assert signature is not None
        assert signature["name"] == "sub_1000"
        assert signature["return_type"] == "int"
        assert signature["calling_convention"] == "cdecl"
        assert signature["parameters"] == CANDIDATE_SIGNATURE["parameters"]
        history = store.list_signature_history(conn, ids["target"])
        assert history[0]["source"] == "match"
        assert history[0]["previous"]["return_type"] == "void"

    def test_both_mode_writes_name_and_signature(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _put_signature(conn, ids["candidate"], name="NP_Open", **CANDIDATE_SIGNATURE)
        plan = matching.plan_transfer(
            conn, function_id=ids["target"], candidate_function_id=ids["candidate"], mode="both"
        )
        assert plan.status == matching.TRANSFER_STATUS_APPLIED
        action = journal.new_action()
        _apply(conn, action, plan)

        function = store.get_function(conn, ids["target"])
        assert function is not None
        assert function["name"] == "NP_Open"
        signature = store.get_signature(conn, ids["target"])
        assert signature is not None
        assert signature["return_type"] == "int"
        # The signature carries the transferred name too.
        assert signature["name"] == "NP_Open"
        assert store.list_name_history(conn, ids["target"])[0]["source"] == "match"
        assert store.list_signature_history(conn, ids["target"])[0]["source"] == "match"

        report = journal.revert_action(conn, action)
        assert report["failed"] == 0
        restored = store.get_function(conn, ids["target"])
        assert restored is not None
        assert restored["name"] == "sub_1000"
        assert store.get_signature(conn, ids["target"]) is None

    def test_signature_mode_on_a_target_without_a_signature(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _put_signature(conn, ids["candidate"], name="NP_Open", **CANDIDATE_SIGNATURE)
        plan = matching.plan_transfer(
            conn,
            function_id=ids["target"],
            candidate_function_id=ids["candidate"],
            mode="signature",
        )
        assert plan.status == matching.TRANSFER_STATUS_APPLIED
        _apply(conn, journal.new_action(), plan)
        history = store.list_signature_history(conn, ids["target"])
        assert history[0]["previous"] is None

    def test_skipped_when_the_name_already_matches(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        store.rename_function(
            conn, ids["target"], new_name="NP_Open", actor="test", source="manual"
        )
        plan = matching.plan_transfer(
            conn, function_id=ids["target"], candidate_function_id=ids["candidate"], mode="name"
        )
        assert plan.status == matching.TRANSFER_STATUS_SKIPPED
        assert plan.reason == "already matches"

    def test_unknown_mode_is_refused(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        with pytest.raises(matching.InvalidSettingsError) as raised:
            matching.plan_transfer(
                conn,
                function_id=ids["target"],
                candidate_function_id=ids["candidate"],
                mode="everything",
            )
        assert raised.value.error == "invalid mode"

    def test_no_recorded_match_is_refused(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        plan = matching.plan_transfer(
            conn, function_id=ids["candidate"], candidate_function_id=ids["target"], mode="name"
        )
        assert plan.status == matching.TRANSFER_STATUS_FAILED
        assert plan.reason == matching.REASON_NO_SUCH_MATCH

    def test_candidate_without_a_signature_is_refused(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        plan = matching.plan_transfer(
            conn,
            function_id=ids["target"],
            candidate_function_id=ids["candidate"],
            mode="signature",
        )
        assert plan.status == matching.TRANSFER_STATUS_FAILED
        assert plan.reason == matching.REASON_CANDIDATE_HAS_NO_SIGNATURE

    def test_differing_calling_convention_is_refused(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _put_signature(conn, ids["candidate"], name="NP_Open", **CANDIDATE_SIGNATURE)
        _put_signature(
            conn,
            ids["target"],
            name="sub_1000",
            return_type="int",
            calling_convention="stdcall",
            parameters=[],
        )
        plan = matching.plan_transfer(
            conn,
            function_id=ids["target"],
            candidate_function_id=ids["candidate"],
            mode="signature",
        )
        assert plan.status == matching.TRANSFER_STATUS_FAILED
        assert plan.reason == matching.REASON_SIGNATURE_CONFLICT
        assert "stdcall" in plan.detail
        # Nothing was written.
        signature = store.get_signature(conn, ids["target"])
        assert signature is not None
        assert signature["calling_convention"] == "stdcall"


class TestMissingReferencedTypes:
    def test_missing_type_is_reported(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _put_signature(conn, ids["candidate"], name="NP_Open", **CANDIDATE_SIGNATURE)
        plan = matching.plan_transfer(
            conn,
            function_id=ids["target"],
            candidate_function_id=ids["candidate"],
            mode="signature",
        )
        assert plan.missing_types == ("NP_ENTRY",)

    def test_known_type_is_not_reported(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _put_signature(conn, ids["candidate"], name="NP_Open", **CANDIDATE_SIGNATURE)
        store.add_data_type(
            conn,
            binary_id=ids["binary"],
            name="NP_ENTRY",
            size=4,
            kind=data_types.KIND_STRUCT,
            members=[],
            source=data_types.SOURCE_MANUAL,
        )
        plan = matching.plan_transfer(
            conn,
            function_id=ids["target"],
            candidate_function_id=ids["candidate"],
            mode="signature",
        )
        assert plan.missing_types == ()

    def test_primitive_return_is_not_reported(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _put_signature(
            conn,
            ids["candidate"],
            name="NP_Open",
            return_type="unsigned int",
            calling_convention="",
            parameters=[{"index": 0, "type": "char *", "name": "path"}],
        )
        plan = matching.plan_transfer(
            conn,
            function_id=ids["target"],
            candidate_function_id=ids["candidate"],
            mode="signature",
        )
        assert plan.missing_types == ()


class TestBulkTransfer:
    def _requests(self, ids: dict[str, int]) -> list[matching.TransferRequest]:
        return [
            matching.TransferRequest(ids["target"], ids["candidate"], matching.TRANSFER_MODE_NAME),
            matching.TransferRequest(
                ids["second"], ids["candidate"], matching.TRANSFER_MODE_SIGNATURE
            ),
            # No recorded match for this pair, so the row fails alone.
            matching.TransferRequest(ids["target"], ids["second"], matching.TRANSFER_MODE_NAME),
        ]

    def test_dry_run_writes_nothing(self, conn: sqlite3.Connection) -> None:
        ids = _seed_pair(conn)
        _put_signature(conn, ids["candidate"], name="NP_Open", **CANDIDATE_SIGNATURE)
        report = matching.transfer_matches(
            conn,
            None,
            requests=self._requests(ids),
            actor="test",
            binary_id=ids["binary"],
            dry_run=True,
        )
        assert report["dry_run"] is True
        assert report["requested"] == 3
        assert report["applied"] == 2
        assert report["failed"] == 1
        target = store.get_function(conn, ids["target"])
        assert target is not None
        assert target["name"] == "sub_1000"
        assert store.get_signature(conn, ids["second"]) is None
        assert store.list_name_history(conn, ids["target"]) == []

    def test_mixed_batch_applies_and_reports(self, conn: sqlite3.Connection) -> None:
        ids = _seed_pair(conn)
        _put_signature(conn, ids["candidate"], name="NP_Open", **CANDIDATE_SIGNATURE)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            report = matching.transfer_matches(
                conn,
                log,
                requests=self._requests(ids),
                actor="test",
                binary_id=ids["binary"],
            )
        assert report["requested"] == 3
        assert report["applied"] == 2
        assert report["failed"] == 1
        failed_row = report["transfers"][2]
        assert failed_row["status"] == matching.TRANSFER_STATUS_FAILED
        assert failed_row["reason"] == matching.REASON_NO_SUCH_MATCH

        assert _name(conn, ids["target"]) == "NP_Open"
        assert _name(conn, ids["second"]) == "sub_1100"
        signature = store.get_signature(conn, ids["second"])
        assert signature is not None
        assert signature["return_type"] == "int"

        # One action reverses every row the batch wrote.
        revert = journal.revert_action(conn, action)
        assert revert["failed"] == 0
        assert _name(conn, ids["target"]) == "sub_1000"
        assert store.get_signature(conn, ids["second"]) is None

    def test_out_of_binary_row_fails_alone(self, conn: sqlite3.Connection) -> None:
        ids = _seed_pair(conn)
        other_binary = store.add_binary(conn, sha256="bb" * 32, name="b.exe")
        other_analysis = store.create_analysis(conn, binary_id=other_binary, engine="manual")
        other = store.add_function(
            conn, analysis_id=other_analysis, va=0x7000, name="sub_7000", size=16
        )
        store.record_match(
            conn,
            function_id=other,
            candidate_function_id=ids["candidate"],
            similarity=90.0,
            confidence=0.5,
        )
        requests = [
            matching.TransferRequest(ids["target"], ids["candidate"], matching.TRANSFER_MODE_NAME),
            matching.TransferRequest(other, ids["candidate"], matching.TRANSFER_MODE_NAME),
        ]
        report = matching.transfer_matches(
            conn, None, requests=requests, actor="test", binary_id=ids["binary"], dry_run=True
        )
        assert report["applied"] == 1
        assert report["failed"] == 1
        assert report["transfers"][1]["reason"] == matching.REASON_OUT_OF_BINARY

    def test_hidden_candidate_fails_alone(self, conn: sqlite3.Connection) -> None:
        ids = _seed_pair(conn)
        other_binary = store.add_binary(conn, sha256="bb" * 32, name="b.exe")
        other_analysis = store.create_analysis(conn, binary_id=other_binary, engine="manual")
        other = store.add_function(
            conn, analysis_id=other_analysis, va=0x7000, name="NP_Other", size=16
        )
        store.record_match(
            conn,
            function_id=ids["target"],
            candidate_function_id=other,
            similarity=90.0,
            confidence=0.5,
        )
        owner, _token = auth.add_user(conn, name="owner", role="admin")
        team_id = int(auth.create_team(conn, name="blue")["id"])
        auth.add_member(conn, team_id, int(owner["id"]))
        _member, _token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        ana = auth.find_user(conn, "ana")
        assert ana is not None
        auth.add_member(conn, team_id, int(ana["id"]))
        _outsider, _token = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        stranger = auth.find_user(conn, "bob")
        assert stranger is not None
        store.set_binary_scope(conn, other_binary, visibility="team", owner_team_id=team_id)

        requests = [
            matching.TransferRequest(ids["target"], ids["candidate"], matching.TRANSFER_MODE_NAME),
            matching.TransferRequest(ids["target"], other, matching.TRANSFER_MODE_NAME),
        ]
        report = matching.transfer_matches(
            conn, None, requests=requests, actor="test", dry_run=True, visible_to=stranger
        )
        assert report["applied"] == 1
        assert report["failed"] == 1
        assert report["transfers"][1]["reason"] == matching.REASON_UNKNOWN_CANDIDATE
        member = matching.transfer_matches(
            conn, None, requests=requests, actor="test", dry_run=True, visible_to=ana
        )
        assert member["applied"] == 2


class TestTransferRequests:
    def test_empty_list_is_refused(self) -> None:
        with pytest.raises(matching.InvalidSettingsError) as raised:
            matching.parse_transfers({"transfers": []})
        assert "non-empty" in raised.value.error

    def test_non_object_row_is_refused(self) -> None:
        with pytest.raises(matching.InvalidSettingsError) as raised:
            matching.parse_transfers({"transfers": [3]})
        assert raised.value.error == "invalid transfer"

    def test_unknown_mode_is_refused(self) -> None:
        with pytest.raises(matching.InvalidSettingsError) as raised:
            matching.parse_transfers(
                {"transfers": [{"function_id": 1, "candidate_function_id": 2, "mode": "nope"}]}
            )
        assert raised.value.error == "invalid mode"

    def test_default_mode_is_name(self) -> None:
        requests = matching.parse_transfers(
            {"transfers": [{"function_id": 1, "candidate_function_id": 2}]}
        )
        assert requests == (matching.TransferRequest(1, 2, matching.TRANSFER_MODE_NAME),)
