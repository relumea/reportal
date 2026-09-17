"""The HTTP surface of plans, usage and billing."""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, on_request

from reportal import auth, billing, metering, plans, store

WEBHOOK_SECRET = "whsec_api_test"


def _organisation(portal_db: Path, name: str = "acme") -> int:
    with contextlib.closing(store.connect(portal_db)) as conn:
        created = auth.create_organisation(conn, name=name, description="")
        conn.commit()
        return int(created["id"])


def _signed(payload: dict[str, Any]) -> tuple[bytes, str]:
    body = json.dumps(payload).encode("utf-8")
    timestamp = int(billing._wall_time())
    digest = hmac.new(
        WEBHOOK_SECRET.encode("utf-8"), f"{timestamp}.".encode() + body, hashlib.sha256
    ).hexdigest()
    return body, f"t={timestamp},v1={digest}"


class TestPlansRoute:
    """The read a pricing page makes."""

    def test_it_lists_every_public_plan(self, portal_db: Path) -> None:
        status, _, chunks = on_request("GET", "/api/plans")
        assert status.startswith("200")
        payload = json_body(b"".join(chunks), {})
        assert [plan["id"] for plan in payload["plans"]] == [
            plan.id for plan in plans.public_plans()
        ]

    def test_it_never_advertises_the_internal_tier(self, portal_db: Path) -> None:
        _, _, chunks = on_request("GET", "/api/plans")
        payload = json_body(b"".join(chunks), {})
        assert "internal" not in {plan["id"] for plan in payload["plans"]}

    def test_it_carries_no_secret(self, portal_db: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(billing.STRIPE_SECRET_ENV, "sk_test_should_never_appear")
        _, _, chunks = on_request("GET", "/api/plans")
        assert b"sk_test_should_never_appear" not in b"".join(chunks)


class TestUsageRoute:
    """What a tenant sees about its own consumption."""

    def test_it_reports_the_plan_and_every_dimension(self, portal_db: Path) -> None:
        organisation_id = _organisation(portal_db)
        status, _, chunks = on_request("GET", f"/api/organisations/{organisation_id}/usage")
        assert status.startswith("200")
        payload = json_body(b"".join(chunks), {})
        assert payload["plan"]["id"] == plans.DEFAULT_PLAN_ID
        assert set(payload["usage"]) == set(metering.CUSTOMER_KINDS)

    def test_an_unknown_organisation_is_a_404(self, portal_db: Path) -> None:
        status, _, chunks = on_request("GET", "/api/organisations/424242/usage")
        assert status.startswith("404")
        assert json_body(b"".join(chunks), {})["error"] == auth.ERROR_ORGANISATION_NOT_FOUND

    def test_recorded_usage_shows_up(self, portal_db: Path) -> None:
        organisation_id = _organisation(portal_db)
        with contextlib.closing(store.connect(portal_db)) as conn:
            metering.record_usage(conn, organisation_id, metering.KIND_CREDITS, 4242)
        _, _, chunks = on_request("GET", f"/api/organisations/{organisation_id}/usage")
        payload = json_body(b"".join(chunks), {})
        assert payload["usage"][metering.KIND_CREDITS]["used"] == 4242


class TestBillingRoute:
    """The organisation's plan, quota and subscription in one read."""

    def test_it_reports_no_subscription_before_one_exists(self, portal_db: Path) -> None:
        organisation_id = _organisation(portal_db)
        status, _, chunks = on_request("GET", f"/api/organisations/{organisation_id}/billing")
        assert status.startswith("200")
        payload = json_body(b"".join(chunks), {})
        assert payload["subscription"] is None
        assert payload["billing"]["provider"] in {"disabled", "stripe", "manual"}

    def test_an_unknown_organisation_is_a_404(self, portal_db: Path) -> None:
        status, _, _ = on_request("GET", "/api/organisations/424242/billing")
        assert status.startswith("404")


class TestPlanAssignment:
    """The operator path, journaled so a mistaken grant is revertible."""

    def test_it_sets_the_plan(self, portal_db: Path) -> None:
        organisation_id = _organisation(portal_db)
        status, _, chunks = on_request(
            "PUT",
            f"/api/organisations/{organisation_id}/plan",
            body=json.dumps({"plan_id": "team"}),
            headers={"Content-Type": "application/json"},
        )
        assert status.startswith("200")
        assert json_body(b"".join(chunks), {})["plan"]["id"] == "team"

    def test_it_is_journaled(self, portal_db: Path) -> None:
        organisation_id = _organisation(portal_db)
        _, _, chunks = on_request(
            "PUT",
            f"/api/organisations/{organisation_id}/plan",
            body=json.dumps({"plan_id": "team"}),
            headers={"Content-Type": "application/json"},
        )
        assert json_body(b"".join(chunks), {}).get("journal_action")

    def test_an_unknown_plan_is_a_400(self, portal_db: Path) -> None:
        organisation_id = _organisation(portal_db)
        status, _, chunks = on_request(
            "PUT",
            f"/api/organisations/{organisation_id}/plan",
            body=json.dumps({"plan_id": "platinum"}),
            headers={"Content-Type": "application/json"},
        )
        assert status.startswith("400")
        assert json_body(b"".join(chunks), {})["error"] == "invalid plan"

    def test_setting_the_same_plan_again_does_not_restart_the_period(self, portal_db: Path) -> None:
        """A double-click must not wipe the open period's usage."""
        organisation_id = _organisation(portal_db)
        first_status, _, first_chunks = on_request(
            "PUT",
            f"/api/organisations/{organisation_id}/plan",
            body=json.dumps({"plan_id": "team"}),
            headers={"Content-Type": "application/json"},
        )
        assert first_status.startswith("200")
        first = json_body(b"".join(first_chunks), {})
        started = first["period_started_at"]
        assert started
        assert first.get("journal_action")

        again_status, _, again_chunks = on_request(
            "PUT",
            f"/api/organisations/{organisation_id}/plan",
            body=json.dumps({"plan_id": "team"}),
            headers={"Content-Type": "application/json"},
        )
        assert again_status.startswith("200")
        again = json_body(b"".join(again_chunks), {})
        assert again["period_started_at"] == started
        assert again.get("journal_action") is None


class TestCheckoutRoute:
    """What a self-serve upgrade answers before any provider is configured."""

    def test_it_is_503_while_billing_is_disabled(
        self, portal_db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(billing.PROVIDER_ENV, billing.PROVIDER_DISABLED)
        organisation_id = _organisation(portal_db)
        status, _, _ = on_request(
            "POST",
            f"/api/organisations/{organisation_id}/billing/checkout",
            body=json.dumps({"plan_id": "analyst"}),
            headers={"Content-Type": "application/json"},
        )
        assert status.startswith("503")

    def test_an_unknown_plan_is_a_400(
        self, portal_db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(billing.PROVIDER_ENV, billing.PROVIDER_MANUAL)
        organisation_id = _organisation(portal_db)
        status, _, _ = on_request(
            "POST",
            f"/api/organisations/{organisation_id}/billing/checkout",
            body=json.dumps({"plan_id": "platinum"}),
            headers={"Content-Type": "application/json"},
        )
        assert status.startswith("400")

    def test_a_manual_checkout_round_trips(
        self, portal_db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(billing.PROVIDER_ENV, billing.PROVIDER_MANUAL)
        organisation_id = _organisation(portal_db)
        _, _, chunks = on_request(
            "POST",
            f"/api/organisations/{organisation_id}/billing/checkout",
            body=json.dumps({"plan_id": "analyst"}),
            headers={"Content-Type": "application/json"},
        )
        session = json_body(b"".join(chunks), {})
        status, _, chunks = on_request(
            "POST",
            "/api/billing/manual/confirm",
            body=json.dumps({"token": session["session_id"], "organisation_id": organisation_id}),
            headers={"Content-Type": "application/json"},
        )
        assert status.startswith("200")
        assert json_body(b"".join(chunks), {})["plan_id"] == "analyst"

    def test_cancelling_a_manual_subscription_drops_the_plan(
        self, portal_db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(billing.PROVIDER_ENV, billing.PROVIDER_MANUAL)
        organisation_id = _organisation(portal_db)
        status, _, chunks = on_request(
            "POST", f"/api/organisations/{organisation_id}/billing/cancel-manual"
        )
        assert status.startswith("200")
        assert json_body(b"".join(chunks), {})["plan_id"] == plans.FALLBACK_PLAN_ID


class TestWebhookRoute:
    """The one unauthenticated write, and what guards it."""

    def test_an_unsigned_webhook_is_refused(
        self, portal_db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(billing.STRIPE_WEBHOOK_ENV, WEBHOOK_SECRET)
        status, _, _ = on_request(
            "POST",
            "/api/billing/webhook",
            body=json.dumps({"id": "evt_1", "type": "ping"}),
            headers={"Content-Type": "application/json"},
        )
        assert status.startswith("400")

    def test_a_signed_webhook_applies_and_redelivery_is_a_duplicate(
        self, portal_db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(billing.PROVIDER_ENV, billing.PROVIDER_STRIPE)
        monkeypatch.setenv(billing.STRIPE_SECRET_ENV, "sk_test_123")
        monkeypatch.setenv(billing.STRIPE_WEBHOOK_ENV, WEBHOOK_SECRET)
        monkeypatch.setenv("REPORTAL_STRIPE_PRICE_TEAM", "price_team")
        organisation_id = _organisation(portal_db)
        body, signature = _signed(
            {
                "id": "evt_api_1",
                "type": "customer.subscription.updated",
                "data": {
                    "object": {
                        "id": "sub_api",
                        "status": "active",
                        "customer": "cus_api",
                        "metadata": {"organisation_id": str(organisation_id)},
                        "items": {"data": [{"price": {"id": "price_team"}}]},
                    }
                },
            }
        )
        headers = {"Content-Type": "application/json", "Stripe-Signature": signature}
        status, _, chunks = on_request("POST", "/api/billing/webhook", body=body, headers=headers)
        assert status.startswith("200")
        assert json_body(b"".join(chunks), {})["status"] == "applied"

        status, _, chunks = on_request("POST", "/api/billing/webhook", body=body, headers=headers)
        assert json_body(b"".join(chunks), {})["status"] == "duplicate"

        _, _, chunks = on_request("GET", f"/api/organisations/{organisation_id}/usage")
        assert json_body(b"".join(chunks), {})["plan"]["id"] == "team"


class TestSyncRoute:
    """The reconcile path, which is rate limited because it calls out."""

    def test_it_rate_limits_per_organisation(
        self, portal_db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(billing.PROVIDER_ENV, billing.PROVIDER_MANUAL)
        organisation_id = _organisation(portal_db)
        seen = [
            on_request("POST", f"/api/organisations/{organisation_id}/billing/sync")
            for _ in range(billing._RECONCILE_MAX_HITS + 1)
        ]
        assert seen[-1][0].startswith("429")
        wait = int(seen[-1][1]["Retry-After"])
        assert 1 <= wait <= int(billing._RECONCILE_WINDOW_S)


class TestWebhookUnderSaaS:
    def test_signed_webhook_passes_without_bearer(
        self, portal_db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from reportal import profiles

        monkeypatch.setenv(profiles.PROFILE_ENV, profiles.PROFILE_SAAS)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        monkeypatch.setenv(billing.PROVIDER_ENV, billing.PROVIDER_STRIPE)
        monkeypatch.setenv(billing.STRIPE_SECRET_ENV, "sk_test_123")
        monkeypatch.setenv(billing.STRIPE_WEBHOOK_ENV, WEBHOOK_SECRET)
        monkeypatch.setenv("REPORTAL_STRIPE_PRICE_TEAM", "price_team")
        organisation_id = _organisation(portal_db)
        body, signature = _signed(
            {
                "id": "evt_saas_1",
                "type": "customer.subscription.updated",
                "data": {
                    "object": {
                        "id": "sub_saas",
                        "status": "active",
                        "customer": "cus_saas",
                        "metadata": {"organisation_id": str(organisation_id)},
                        "items": {"data": [{"price": {"id": "price_team"}}]},
                    }
                },
            }
        )
        headers = {"Content-Type": "application/json", "Stripe-Signature": signature}
        status, _, chunks = on_request("POST", "/api/billing/webhook", body=body, headers=headers)
        assert status.startswith("200")
        assert json_body(b"".join(chunks), {})["status"] == "applied"
