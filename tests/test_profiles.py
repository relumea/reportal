"""Tests for deployment profiles and SaaS tenant guards."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from conftest import FakeLlmClient, json_body, wsgi_request

from reportal import api, auth, clock, error_docs, journal, metering, profiles, store


def _send(
    method: str, path: str, *, token: str = "", body: dict[str, Any] | None = None
) -> tuple[str, Any]:
    status, _headers, payload = _send_raw(method, path, token=token, body=body)
    return status, payload


def _send_raw(
    method: str, path: str, *, token: str = "", body: dict[str, Any] | None = None
) -> tuple[str, Any, Any]:
    raw = b"" if body is None else json.dumps(body).encode()
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    status, response_headers, payload = wsgi_request(method, path, body=raw, headers=headers)
    return status, response_headers, json_body(payload, response_headers)


def _saas(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(profiles.PROFILE_ENV, profiles.PROFILE_SAAS)


def _tenant(conn: sqlite3.Connection, name: str) -> tuple[dict[str, Any], str, int]:
    user, token = auth.add_user(conn, name=name, role=auth.ROLE_ANALYST)
    org = auth.create_organisation(conn, name=f"{name}-org")
    team = auth.create_team(conn, name=f"{name}-team")
    auth.set_team_organisation(conn, int(team["id"]), int(org["id"]))
    auth.add_member(conn, int(team["id"]), int(user["id"]))
    auth.set_active_team(conn, int(user["id"]), int(team["id"]))
    return user, token, int(org["id"])


class TestProfiles:
    def test_default_is_personal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(profiles.PROFILE_ENV, raising=False)
        assert profiles.current() == profiles.PROFILE_PERSONAL
        assert profiles.is_saas() is False

    def test_unknown_value_reads_as_personal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(profiles.PROFILE_ENV, "enterprise")
        assert profiles.current() == profiles.PROFILE_PERSONAL

    def test_saas_forces_auth_required(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(auth.REQUIRED_ENV, raising=False)
        _saas(monkeypatch)
        assert auth.required() is True

    def test_saas_rejects_unauthenticated_api(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        auth.add_user(conn, name="ana", role=auth.ROLE_ADMIN)
        _saas(monkeypatch)
        status, payload = _send("GET", "/api/binaries")
        assert status.startswith("401")
        assert payload["error"] == "unauthorized"


class TestSignup:
    @pytest.fixture(autouse=True)
    def _reset_signup_limiter(self) -> None:
        auth._signup_states.clear()

    def test_personal_profile_refuses(self, conn: sqlite3.Connection) -> None:
        status, payload = _send("POST", "/api/signup", body={"name": "ana"})
        assert status.startswith("403")
        assert payload["error"] == auth.ERROR_SIGNUP_DISABLED

    def test_saas_creates_a_tenant(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _saas(monkeypatch)
        status, payload = _send("POST", "/api/signup", body={"name": "ana"})
        assert status.startswith("201")
        assert payload["name"] == "ana"
        assert payload["role"] == auth.ROLE_ANALYST
        assert payload["token"].startswith(auth.TOKEN_PREFIX)
        assert payload["plan_id"] == "free"
        assert payload["team"]["members"][0]["team_role"] == auth.TEAM_ROLE_OWNER
        listed, binaries = _send("GET", "/api/binaries", token=payload["token"])
        assert listed.startswith("200")
        assert binaries["count"] == 0

    def test_free_plan_refuses_a_second_api_key(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _saas(monkeypatch)
        _, created = _send("POST", "/api/signup", body={"name": "ana"})
        token = str(created["token"])
        status, payload = _send("POST", "/api/iam/keys", token=token, body={"name": "ci"})
        assert status.startswith("402")
        assert payload["error"] == auth.ERROR_API_KEY_LIMIT
        listed, keys = _send("GET", "/api/iam/keys", token=token)
        assert listed.startswith("200")
        assert keys["count"] == 0
        assert keys["used"] == 1
        assert keys["limit"] == 1

    def test_taken_name_is_409(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _saas(monkeypatch)
        _send("POST", "/api/signup", body={"name": "ana"})
        status, payload = _send("POST", "/api/signup", body={"name": "ana"})
        assert status.startswith("409")
        assert payload["error"] == auth.ERROR_USER_EXISTS

    def test_cli_signup_needs_saas(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from typer.testing import CliRunner

        from reportal import cli
        from reportal._paths import DB_ENV

        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        runner = CliRunner()
        refused = runner.invoke(cli.app, ["signup", "ana", "--json"])
        assert refused.exit_code == 1
        assert auth.ERROR_SIGNUP_DISABLED in refused.output
        monkeypatch.setenv(profiles.PROFILE_ENV, profiles.PROFILE_SAAS)
        created = runner.invoke(cli.app, ["signup", "ana", "--json"])
        assert created.exit_code == 0, created.output
        body = json.loads(created.stdout)
        assert body["token"].startswith(auth.TOKEN_PREFIX)
        assert body["plan_id"] == "free"

    def test_http_signup_is_capped(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _saas(monkeypatch)
        statuses = [_send("POST", "/api/signup", body={"name": f"user{i}"})[0] for i in range(5)]
        assert all(status.startswith("201") for status in statuses[: auth.SIGNUP_MAX_HITS])
        limited, headers, payload = _send_raw("POST", "/api/signup", body={"name": "late"})
        assert limited.startswith("429")
        assert payload["error"] == auth.ERROR_RATE_LIMITED
        wait = int(headers["Retry-After"])
        assert 1 <= wait <= int(auth.SIGNUP_WINDOW_S)

    def test_signup_window_drops_a_stale_peer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        clock = [1000.0]
        monkeypatch.setattr(auth, "_signup_monotonic", lambda: clock[0])
        assert auth.signup_allowed("10.0.0.1") is True
        assert "10.0.0.1" in auth._signup_states
        clock[0] += auth.SIGNUP_WINDOW_S + 1
        assert auth.signup_allowed("10.0.0.2") is True
        assert "10.0.0.1" not in auth._signup_states

    def test_write_window_drops_a_stale_caller(self, monkeypatch: pytest.MonkeyPatch) -> None:
        clock = [1000.0]
        monkeypatch.setattr(auth, "_write_monotonic", lambda: clock[0])
        auth._write_states.clear()
        assert auth.write_allowed("user:1") is True
        assert "user:1" in auth._write_states
        clock[0] += auth.WRITE_WINDOW_S + 1
        assert auth.write_allowed("user:2") is True
        assert "user:1" not in auth._write_states

    def test_write_retry_after_tracks_the_oldest_hit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        clock = [1000.0]
        monkeypatch.setattr(auth, "_write_monotonic", lambda: clock[0])
        auth._write_states.clear()
        assert auth.write_allowed("user:1") is True
        assert auth.write_retry_after("user:1") == int(auth.WRITE_WINDOW_S)
        clock[0] += 10
        assert auth.write_retry_after("user:1") == int(auth.WRITE_WINDOW_S) - 10


class TestTenantIsolation:
    def test_org_listing_hides_other_tenants(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, ana, _ = _tenant(conn, "ana")
        _tenant(conn, "bob")
        _saas(monkeypatch)

        status, payload = _send("GET", "/api/organisations", token=ana)

        assert status.startswith("200")
        assert [org["name"] for org in payload["organisations"]] == ["ana-org"]

    def test_org_detail_hides_other_tenant_as_404(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, ana, _ = _tenant(conn, "ana")
        _, _, bob_org = _tenant(conn, "bob")
        _saas(monkeypatch)

        status, payload = _send("GET", f"/api/organisations/{bob_org}", token=ana)

        assert status.startswith("404")
        assert payload["error"] == auth.ERROR_ORGANISATION_NOT_FOUND

    def test_journal_hides_other_actors(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, ana, _ = _tenant(conn, "ana")
        _, bob, _ = _tenant(conn, "bob")
        binary_id = store.add_binary(conn, sha256="ab" * 32, name="b.exe")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="t")
        function_id = store.add_function(conn, analysis_id=analysis_id, va=1, name="f")
        _saas(monkeypatch)
        _send("POST", f"/api/functions/{function_id}/rename", token=bob, body={"name": "g"})

        status, payload = _send("GET", "/api/journal", token=ana)

        assert status.startswith("200")
        assert payload["entries"] == []
        assert payload["actors"] == []

        forbidden, _ = _send("GET", "/api/journal?actor=bob", token=ana)
        assert forbidden.startswith("403")


class TestQuotaGate:
    def test_free_tier_at_zero_refuses_auto_run(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from reportal import plans

        _, ana, org_id = _tenant(conn, "ana")
        binary_id = store.add_binary(conn, sha256="ab" * 32, name="b.exe")
        plan = plans.get_plan("free")
        for _ in range(plan.monthly_auto_runs):
            metering.record_usage(conn, org_id, metering.KIND_AUTO_RUN, 1)
        _saas(monkeypatch)

        status, payload = _send("POST", f"/api/binaries/{binary_id}/auto", token=ana, body={})

        assert status.startswith("402")
        assert payload["error"] == "quota-exceeded"
        assert payload["upgrade"] == "/pricing"
        assert payload["doc_url"] == f"{error_docs.DOC_BASE_URL}#quota-exceeded"

    def test_personal_profile_ignores_quota(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from reportal import plans

        monkeypatch.delenv(profiles.PROFILE_ENV, raising=False)
        _, ana, org_id = _tenant(conn, "ana")
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        binary_id = store.add_binary(conn, sha256="ab" * 32, name="b.exe")
        plan = plans.get_plan("free")
        for _ in range(plan.monthly_auto_runs):
            metering.record_usage(conn, org_id, metering.KIND_AUTO_RUN, 1)

        status, _ = _send("POST", f"/api/binaries/{binary_id}/auto", token=ana, body={})

        assert status.startswith("202")


class TestAiQuotaGates:
    def _function_with_decomp(self, conn: sqlite3.Connection, *, size: int = 4000) -> int:
        binary_id = store.add_binary(conn, sha256="ab" * 32, name="b.exe")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="t")
        function_id = store.add_function(conn, analysis_id=analysis_id, va=1, name="f")
        store.set_decompilation(conn, function_id, "void f(void){}\n" + ("x" * size), "kuna")
        return function_id

    def test_summary_refused_past_credits(
        self,
        conn: sqlite3.Connection,
        monkeypatch: pytest.MonkeyPatch,
        fake_llm: FakeLlmClient,
    ) -> None:
        from reportal import plans

        _, ana, org_id = _tenant(conn, "ana")
        function_id = self._function_with_decomp(conn)
        plan = plans.get_plan("free")
        metering.record_usage(conn, org_id, metering.KIND_CREDITS, plan.monthly_credits)
        _saas(monkeypatch)

        status, payload = _send("POST", f"/api/functions/{function_id}/summary", token=ana)

        assert status.startswith("402")
        assert payload["error"] == "quota-exceeded"
        assert payload["task"] == "summary"
        assert fake_llm.calls == []

    def test_summary_allowed_within_credits(
        self,
        conn: sqlite3.Connection,
        monkeypatch: pytest.MonkeyPatch,
        fake_llm: FakeLlmClient,
    ) -> None:
        _, ana, _ = _tenant(conn, "ana")
        function_id = self._function_with_decomp(conn)
        _saas(monkeypatch)

        status, _ = _send("POST", f"/api/functions/{function_id}/summary", token=ana)

        assert status.startswith("200")
        assert len(fake_llm.calls) == 1


class TestTeamInvites:
    def test_owner_mints_member_redeems_once(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, ana, _ = _tenant(conn, "ana")
        bob, bob_token = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        _, created = _send("POST", "/api/teams", token=ana, body={"name": "owned"})
        team_id = int(created["id"])

        minted, invite = _send("POST", f"/api/teams/{team_id}/invites", token=ana)
        assert minted.startswith("200")
        assert invite["code"].startswith(auth.INVITE_PREFIX)

        joined, team = _send(
            "POST", "/api/teams/join", token=bob_token, body={"code": invite["code"]}
        )
        assert joined.startswith("200")
        assert int(bob["id"]) in [m["id"] for m in team["members"]]

        again, payload = _send(
            "POST", "/api/teams/join", token=bob_token, body={"code": invite["code"]}
        )
        assert again.startswith("410")
        assert payload["error"] == auth.ERROR_INVITE_USED

    def test_member_cannot_mint(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, ana, _ = _tenant(conn, "ana")
        _, bob_token = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        team = auth.create_team(conn, name="other")
        bob_row = auth.find_user(conn, "bob")
        assert bob_row is not None
        auth.add_member(conn, int(team["id"]), int(bob_row["id"]))

        status, _ = _send("POST", f"/api/teams/{team['id']}/invites", token=bob_token)

        assert status.startswith("403")

    def test_an_expired_code_is_410(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, ana, _ = _tenant(conn, "ana")
        _, bob_token = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        _, created = _send("POST", "/api/teams", token=ana, body={"name": "ttl"})
        team_id = int(created["id"])
        clock_state = {"now": "2026-01-01T00:00:00+00:00"}
        monkeypatch.setattr(clock, "now", lambda: clock_state["now"])

        _, invite = _send("POST", f"/api/teams/{team_id}/invites", token=ana)
        listed, payload = _send("GET", f"/api/teams/{team_id}/invites", token=ana)
        assert listed.startswith("200")
        row = payload["invites"][0]
        assert row["expired"] is False
        assert row["expires_at"] == "2026-01-08T00:00:00+00:00"

        clock_state["now"] = "2026-01-08T00:00:00+00:00"
        listed, payload = _send("GET", f"/api/teams/{team_id}/invites", token=ana)
        assert payload["invites"][0]["expired"] is True
        status, body = _send(
            "POST", "/api/teams/join", token=bob_token, body={"code": invite["code"]}
        )
        assert status.startswith("410")
        assert body["error"] == auth.ERROR_INVITE_EXPIRED

    def test_a_legacy_row_derives_expiry(self, conn: sqlite3.Connection) -> None:
        team = auth.create_team(conn, name="legacy")
        user, _ = auth.add_user(conn, name="ana")
        invite_id, _code = auth.create_invite(conn, int(team["id"]), int(user["id"]))
        conn.execute(f"UPDATE {auth.INVITE_TABLE} SET expires_at = '' WHERE id = ?", (invite_id,))
        conn.commit()

        listed = auth.list_invites(conn, int(team["id"]))
        assert listed[0]["expires_at"] == auth.invite_expires_at(str(listed[0]["created_at"]))
        assert listed[0]["expired"] is False

    def test_unknown_code_is_404(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, bob = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")

        status, payload = _send("POST", "/api/teams/join", token=bob, body={"code": "invite_nope"})

        assert status.startswith("404")
        assert payload["error"] == auth.ERROR_INVITE_NOT_FOUND

    def test_owner_revokes_an_unused_invite(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, ana, _ = _tenant(conn, "ana")
        _, bob_token = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        _, created = _send("POST", "/api/teams", token=ana, body={"name": "revoke"})
        team_id = int(created["id"])
        _, invite = _send("POST", f"/api/teams/{team_id}/invites", token=ana)
        invite_id = int(invite["invite_id"])
        code = str(invite["code"])

        revoked, payload = _send("DELETE", f"/api/teams/{team_id}/invites/{invite_id}", token=ana)
        assert revoked.startswith("200")
        assert payload["deleted"] is True
        listed, invites = _send("GET", f"/api/teams/{team_id}/invites", token=ana)
        assert listed.startswith("200")
        assert invites["count"] == 0

        missing, gone = _send("POST", "/api/teams/join", token=bob_token, body={"code": code})
        assert missing.startswith("404")
        assert gone["error"] == auth.ERROR_INVITE_NOT_FOUND

        status, _ = _send("DELETE", f"/api/teams/{team_id}/invites/{invite_id}", token=ana)
        assert status.startswith("404")

    def test_a_used_invite_cannot_be_revoked(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, ana, _ = _tenant(conn, "ana")
        _, bob_token = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        _, created = _send("POST", "/api/teams", token=ana, body={"name": "spent"})
        team_id = int(created["id"])
        _, invite = _send("POST", f"/api/teams/{team_id}/invites", token=ana)
        invite_id = int(invite["invite_id"])
        joined, _ = _send("POST", "/api/teams/join", token=bob_token, body={"code": invite["code"]})
        assert joined.startswith("200")

        status, payload = _send("DELETE", f"/api/teams/{team_id}/invites/{invite_id}", token=ana)
        assert status.startswith("410")
        assert payload["error"] == auth.ERROR_INVITE_USED
        listed, invites = _send("GET", f"/api/teams/{team_id}/invites", token=ana)
        assert listed.startswith("200")
        assert invites["count"] == 1
        assert invites["invites"][0]["used_by"] is not None

    def test_member_cannot_revoke(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, ana, _ = _tenant(conn, "ana")
        _, bob_token = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        _, created = _send("POST", "/api/teams", token=ana, body={"name": "owned"})
        team_id = int(created["id"])
        _, invite = _send("POST", f"/api/teams/{team_id}/invites", token=ana)
        bob_row = auth.find_user(conn, "bob")
        assert bob_row is not None
        auth.add_member(conn, team_id, int(bob_row["id"]))

        status, _ = _send(
            "DELETE", f"/api/teams/{team_id}/invites/{invite['invite_id']}", token=bob_token
        )
        assert status.startswith("403")

    def test_revert_unspends_the_code(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, ana, _ = _tenant(conn, "ana")
        bob, bob_token = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        _, created = _send("POST", "/api/teams", token=ana, body={"name": "revert-join"})
        team_id = int(created["id"])
        _, invite = _send("POST", f"/api/teams/{team_id}/invites", token=ana)
        code = str(invite["code"])

        joined, payload = _send("POST", "/api/teams/join", token=bob_token, body={"code": code})
        assert joined.startswith("200")
        journal.revert_action(conn, str(payload["journal_action"]))

        listed, invites = _send("GET", f"/api/teams/{team_id}/invites", token=ana)
        assert listed.startswith("200")
        assert invites["invites"][0]["used_by"] is None
        assert auth.member_role(conn, team_id, int(bob["id"])) is None

        again, team = _send("POST", "/api/teams/join", token=bob_token, body={"code": code})
        assert again.startswith("200")
        assert int(bob["id"]) in [m["id"] for m in team["members"]]


class TestAutoRunCharge:
    def test_a_started_run_records_one_unit(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, ana, org_id = _tenant(conn, "ana")
        binary_id = store.add_binary(conn, sha256="ab" * 32, name="b.exe")
        _saas(monkeypatch)

        status, _ = _send("POST", f"/api/binaries/{binary_id}/auto", token=ana, body={})

        assert status.startswith("202")
        assert metering.period_usage(conn, org_id, metering.KIND_AUTO_RUN) == 1

    def test_a_second_start_of_a_live_run_does_not_charge_again(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, ana, org_id = _tenant(conn, "ana")
        binary_id = store.add_binary(conn, sha256="ab" * 32, name="b.exe")
        _saas(monkeypatch)
        held = threading.Event()
        release = threading.Event()

        def hang(_conn: sqlite3.Connection, **_kwargs: object) -> None:
            held.set()
            release.wait(timeout=10)

        monkeypatch.setattr("reportal.auto_mode.execute_auto_run", hang)

        first, _ = _send("POST", f"/api/binaries/{binary_id}/auto", token=ana, body={})
        assert first.startswith("202")
        assert held.wait(timeout=2)
        again, _ = _send("POST", f"/api/binaries/{binary_id}/auto", token=ana, body={})
        assert again.startswith("202")
        assert metering.period_usage(conn, org_id, metering.KIND_AUTO_RUN) == 1
        release.set()
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if api._auto_run_slots.acquire(blocking=False):
                api._auto_run_slots.release()
                break
            time.sleep(0.02)


class TestInviteRace:
    def test_concurrent_redeems_leave_one_winner(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import threading

        _, ana, _ = _tenant(conn, "ana")
        _, bob_token = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        _, cara_token = auth.add_user(conn, name="cara", role=auth.ROLE_ANALYST)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        _, created = _send("POST", "/api/teams", token=ana, body={"name": "raced"})
        team_id = int(created["id"])
        _, invite = _send("POST", f"/api/teams/{team_id}/invites", token=ana)
        code = str(invite["code"])

        outcomes: list[str] = []
        lock = threading.Lock()

        def join(token: str) -> None:
            status, _ = _send("POST", "/api/teams/join", token=token, body={"code": code})
            with lock:
                outcomes.append(status.split()[0])

        threads = [
            threading.Thread(target=join, args=(bob_token,)),
            threading.Thread(target=join, args=(cara_token,)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert sorted(outcomes) == ["200", "410"]


class TestHistoryAttribution:
    def _function(self, conn: sqlite3.Connection) -> int:
        binary_id = store.add_binary(conn, sha256="ab" * 32, name="b.exe")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="t")
        return store.add_function(conn, analysis_id=analysis_id, va=1, name="f")

    def test_signature_history_carries_caller_id(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        user, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        function_id = self._function(conn)
        store.upsert_signature(
            conn,
            function_id=function_id,
            name="f",
            return_type="void",
            calling_convention="",
            parameters=[],
            source="manual",
        )
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")

        status, _ = _send(
            "PATCH",
            f"/api/functions/{function_id}/signature",
            token=token,
            body={"return_type": "int"},
        )

        assert status.startswith("200")
        history = store.list_signature_history(conn, function_id)
        assert history
        assert history[0]["actor"] == "ana"
        assert history[0]["actor_user_id"] == int(user["id"])

    def test_comment_history_carries_caller_id(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        user, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        binary_id = store.add_binary(conn, sha256="ab" * 32, name="b.exe")
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")

        status, payload = _send(
            "POST", f"/api/binaries/{binary_id}/comments", token=token, body={"body": "hi"}
        )

        assert status.startswith("201")
        assert payload["author_user_id"] == int(user["id"])
