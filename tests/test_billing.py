"""Tests for reportal.billing: the four invariants a payment integration needs.

Completion is not payment, webhooks are idempotent, the price id is the source
of truth, and an unverified signature changes nothing.  Each has its own class
below, because each is a way this module loses money or grants a plan nobody
paid for if it regresses.  Nothing here touches the network: the Stripe REST
calls are exercised through their error paths and the webhook path is driven
with bodies signed by the same HMAC Stripe uses.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

import pytest

from reportal import auth, billing, metering, plans, store

WEBHOOK_SECRET = "whsec_test_secret_value"


def _organisation(conn: sqlite3.Connection, name: str = "acme") -> int:
    created = auth.create_organisation(conn, name=name, description="")
    return int(created["id"])


def _signed(
    payload: dict[str, Any], *, secret: str = WEBHOOK_SECRET, age: int = 0
) -> tuple[bytes, str]:
    """A webhook body and the ``Stripe-Signature`` header that verifies it."""
    body = json.dumps(payload).encode("utf-8")
    timestamp = int(billing._wall_time()) - age
    digest = hmac.new(
        secret.encode("utf-8"), f"{timestamp}.".encode() + body, hashlib.sha256
    ).hexdigest()
    return body, f"t={timestamp},v1={digest}"


def _subscription_event(
    organisation_id: int,
    *,
    event_id: str = "evt_1",
    status: str = "active",
    price_id: str = "price_analyst",
    kind: str = "customer.subscription.updated",
) -> dict[str, Any]:
    return {
        "id": event_id,
        "type": kind,
        "data": {
            "object": {
                "id": "sub_123",
                "status": status,
                "customer": "cus_123",
                "cancel_at_period_end": False,
                "current_period_end": int(billing._wall_time()) + 86400,
                "metadata": {"organisation_id": str(organisation_id)},
                "items": {"data": [{"price": {"id": price_id}}]},
            }
        },
    }


@pytest.fixture()
def stripe_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """A configured Stripe install, with the Analyst price mapped."""
    monkeypatch.setenv(billing.PROVIDER_ENV, billing.PROVIDER_STRIPE)
    monkeypatch.setenv(billing.STRIPE_SECRET_ENV, "sk_test_123")
    monkeypatch.setenv(billing.STRIPE_WEBHOOK_ENV, WEBHOOK_SECRET)
    monkeypatch.setenv("REPORTAL_STRIPE_PRICE_ANALYST", "price_analyst")


class TestProviderResolution:
    """Which provider is in force, and what an unconfigured install does."""

    def test_auto_is_disabled_without_a_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(billing.PROVIDER_ENV, raising=False)
        monkeypatch.delenv(billing.STRIPE_SECRET_ENV, raising=False)
        assert billing.provider_name() == billing.PROVIDER_DISABLED
        assert billing.billing_enabled() is False

    def test_auto_selects_stripe_once_a_key_is_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(billing.PROVIDER_ENV, raising=False)
        monkeypatch.setenv(billing.STRIPE_SECRET_ENV, "sk_test_123")
        assert billing.provider_name() == billing.PROVIDER_STRIPE

    def test_an_unknown_provider_disables_rather_than_guesses(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(billing.PROVIDER_ENV, "paypal")
        assert billing.provider_name() == billing.PROVIDER_DISABLED

    def test_the_public_config_never_carries_a_secret(self, stripe_env: None) -> None:
        config = billing.public_billing_config()
        rendered = json.dumps(config)
        assert "sk_test_123" not in rendered
        assert WEBHOOK_SECRET not in rendered
        assert config["provider"] == billing.PROVIDER_STRIPE


class TestSignatureVerification:
    """An unverified body is an unauthenticated request to change entitlement."""

    def test_a_valid_signature_parses(self, stripe_env: None) -> None:
        body, header = _signed({"id": "evt_1", "type": "ping"})
        assert billing.verify_webhook(body, header)["id"] == "evt_1"

    def test_a_forged_signature_is_refused(self, stripe_env: None) -> None:
        body, _ = _signed({"id": "evt_1", "type": "ping"})
        with pytest.raises(billing.BillingError) as caught:
            billing.verify_webhook(body, "t=1,v1=deadbeef")
        assert caught.value.status == 400

    def test_a_body_signed_with_another_secret_is_refused(self, stripe_env: None) -> None:
        body, header = _signed({"id": "evt_1", "type": "ping"}, secret="whsec_attacker")
        with pytest.raises(billing.BillingError):
            billing.verify_webhook(body, header)

    def test_a_tampered_body_is_refused(self, stripe_env: None) -> None:
        """The signature covers the bytes, so editing them invalidates it."""
        _, header = _signed({"id": "evt_1", "type": "ping"})
        with pytest.raises(billing.BillingError):
            billing.verify_webhook(b'{"id": "evt_evil", "type": "ping"}', header)

    def test_a_stale_timestamp_is_refused(self, stripe_env: None) -> None:
        """Past the tolerance a captured body cannot be replayed."""
        body, header = _signed(
            {"id": "evt_1", "type": "ping"}, age=billing.WEBHOOK_TOLERANCE_S + 60
        )
        with pytest.raises(billing.BillingError):
            billing.verify_webhook(body, header)

    def test_no_configured_secret_refuses_every_webhook(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(billing.STRIPE_WEBHOOK_ENV, raising=False)
        body, header = _signed({"id": "evt_1", "type": "ping"})
        with pytest.raises(billing.BillingError) as caught:
            billing.verify_webhook(body, header)
        assert caught.value.status == 503

    def test_a_malformed_header_is_refused(self, stripe_env: None) -> None:
        body, _ = _signed({"id": "evt_1", "type": "ping"})
        for header in ("", "garbage", "t=notanumber,v1=abc", "v1=abc"):
            with pytest.raises(billing.BillingError):
                billing.verify_webhook(body, header)

    def test_signature_age_uses_the_wall_time_seam(
        self, stripe_env: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A pinned wall clock makes webhook age checks replayable."""
        monkeypatch.setattr(billing, "_wall_time", lambda: 1_700_000_000.0)
        body, header = _signed({"id": "evt_pinned", "type": "ping"})
        assert billing.verify_webhook(body, header)["id"] == "evt_pinned"
        stale_body, stale_header = _signed(
            {"id": "evt_stale", "type": "ping"}, age=billing.WEBHOOK_TOLERANCE_S + 1
        )
        with pytest.raises(billing.BillingError):
            billing.verify_webhook(stale_body, stale_header)


class TestCompletionIsNotPayment:
    """A finished checkout form is not a settled charge."""

    def test_an_unpaid_checkout_does_not_entitle(self) -> None:
        event = billing.BillingEvent(
            event_id="evt_1",
            provider=billing.PROVIDER_STRIPE,
            kind="checkout.session.completed",
            payment_status="unpaid",
        )
        assert event.entitles() is False

    def test_a_paid_checkout_entitles(self) -> None:
        event = billing.BillingEvent(
            event_id="evt_1",
            provider=billing.PROVIDER_STRIPE,
            kind="checkout.session.completed",
            payment_status="paid",
        )
        assert event.entitles() is True

    def test_an_unpaid_completion_leaves_the_plan_alone(
        self, conn: sqlite3.Connection, stripe_env: None
    ) -> None:
        organisation_id = _organisation(conn)
        event = billing.normalize_stripe_event(
            {
                "id": "evt_unpaid",
                "type": "checkout.session.completed",
                "data": {
                    "object": {
                        "payment_status": "unpaid",
                        "customer": "cus_1",
                        "subscription": "sub_1",
                        "metadata": {
                            "organisation_id": str(organisation_id),
                            "plan_id": "analyst",
                        },
                    }
                },
            }
        )
        billing.apply_event(conn, event)
        assert metering.organisation_plan(conn, organisation_id).id == plans.DEFAULT_PLAN_ID

    @pytest.mark.parametrize("status", ["active", "trialing"])
    def test_entitling_subscription_statuses_grant_the_plan(self, status: str) -> None:
        event = billing.BillingEvent(
            event_id="evt_1",
            provider=billing.PROVIDER_STRIPE,
            kind="customer.subscription.updated",
            status=status,
        )
        assert event.entitles() is True

    @pytest.mark.parametrize("status", ["past_due", "canceled", "incomplete", "unpaid"])
    def test_non_entitling_statuses_do_not(self, status: str) -> None:
        event = billing.BillingEvent(
            event_id="evt_1",
            provider=billing.PROVIDER_STRIPE,
            kind="customer.subscription.updated",
            status=status,
        )
        assert event.entitles() is False


class TestIdempotency:
    """Stripe redelivers; a redelivery must change nothing."""

    def test_the_first_delivery_applies(self, conn: sqlite3.Connection, stripe_env: None) -> None:
        organisation_id = _organisation(conn)
        event = billing.normalize_stripe_event(_subscription_event(organisation_id))
        assert billing.apply_event(conn, event)["status"] == "applied"
        assert metering.organisation_plan(conn, organisation_id).id == "analyst"

    def test_a_redelivery_is_a_duplicate(self, conn: sqlite3.Connection, stripe_env: None) -> None:
        organisation_id = _organisation(conn)
        event = billing.normalize_stripe_event(_subscription_event(organisation_id))
        billing.apply_event(conn, event)
        assert billing.apply_event(conn, event)["status"] == "duplicate"

    def test_a_redelivery_does_not_restart_the_period(
        self, conn: sqlite3.Connection, stripe_env: None
    ) -> None:
        """Restarting a period on a redelivery would hand back a month of quota."""
        organisation_id = _organisation(conn)
        event = billing.normalize_stripe_event(_subscription_event(organisation_id))
        billing.apply_event(conn, event)
        metering.record_usage(conn, organisation_id, metering.KIND_TOKENS, 1234)
        billing.apply_event(conn, event)
        assert metering.period_usage(conn, organisation_id, metering.KIND_TOKENS) == 1234

    def test_a_mid_period_update_does_not_restart_the_period(
        self, conn: sqlite3.Connection, stripe_env: None
    ) -> None:
        """A fresh subscription.updated with the same period end must keep usage."""
        organisation_id = _organisation(conn)
        period_end = int(billing._wall_time()) + 86400
        first = _subscription_event(organisation_id, event_id="evt_start")
        first["data"]["object"]["current_period_end"] = period_end
        billing.apply_event(conn, billing.normalize_stripe_event(first))
        metering.record_usage(conn, organisation_id, metering.KIND_TOKENS, 1234)
        second = _subscription_event(organisation_id, event_id="evt_flip")
        second["data"]["object"]["current_period_end"] = period_end
        second["data"]["object"]["cancel_at_period_end"] = True
        billing.apply_event(conn, billing.normalize_stripe_event(second))
        assert metering.period_usage(conn, organisation_id, metering.KIND_TOKENS) == 1234

    def test_an_event_with_no_id_is_refused(self, conn: sqlite3.Connection) -> None:
        event = billing.BillingEvent(event_id="", provider="stripe", kind="ping")
        with pytest.raises(billing.BillingError):
            billing.apply_event(conn, event)

    def test_an_unresolvable_tenant_is_recorded_but_not_applied(
        self, conn: sqlite3.Connection, stripe_env: None
    ) -> None:
        event = billing.normalize_stripe_event(
            {"id": "evt_orphan", "type": "customer.subscription.updated", "data": {"object": {}}}
        )
        assert billing.apply_event(conn, event)["status"] == "unresolved"
        row = conn.execute(
            f"SELECT applied FROM {metering.EVENT_TABLE} WHERE event_id = ?", ("evt_orphan",)
        ).fetchone()
        assert int(row["applied"]) == 0


class TestPriceIdIsTheSourceOfTruth:
    """Metadata is caller-supplied; a price id is what was charged."""

    def test_the_price_id_decides_the_plan(self, stripe_env: None) -> None:
        event = billing.normalize_stripe_event(_subscription_event(1, price_id="price_analyst"))
        assert event.plan_id == "analyst"

    def test_a_lying_metadata_plan_loses_to_the_price(
        self, conn: sqlite3.Connection, stripe_env: None
    ) -> None:
        """A customer who edits metadata to claim Enterprise still gets Analyst."""
        organisation_id = _organisation(conn)
        raw = _subscription_event(organisation_id, price_id="price_analyst")
        raw["data"]["object"]["metadata"]["plan_id"] = "enterprise"
        billing.apply_event(conn, billing.normalize_stripe_event(raw))
        assert metering.organisation_plan(conn, organisation_id).id == "analyst"

    def test_an_unmapped_price_falls_back_to_declared_metadata(self, stripe_env: None) -> None:
        """A subscription made outside checkout still resolves, if the name is real."""
        raw = _subscription_event(1, price_id="price_not_configured")
        raw["data"]["object"]["metadata"]["plan_id"] = "team"
        assert billing.normalize_stripe_event(raw).plan_id == "team"

    def test_a_metadata_plan_that_does_not_exist_is_ignored(self, stripe_env: None) -> None:
        raw = _subscription_event(1, price_id="price_not_configured")
        raw["data"]["object"]["metadata"]["plan_id"] = "unlimited-free-forever"
        assert billing.normalize_stripe_event(raw).plan_id is None


class TestSubscriptionLifecycle:
    """What a cancellation and a failed payment do to entitlement."""

    def test_a_deletion_drops_to_the_fallback_plan(
        self, conn: sqlite3.Connection, stripe_env: None
    ) -> None:
        organisation_id = _organisation(conn)
        billing.apply_event(
            conn, billing.normalize_stripe_event(_subscription_event(organisation_id))
        )
        billing.apply_event(
            conn,
            billing.normalize_stripe_event(
                _subscription_event(
                    organisation_id,
                    event_id="evt_gone",
                    status="canceled",
                    kind="customer.subscription.deleted",
                )
            ),
        )
        assert metering.organisation_plan(conn, organisation_id).id == plans.FALLBACK_PLAN_ID

    def test_past_due_marks_the_organisation_rather_than_deleting_it(
        self, conn: sqlite3.Connection, stripe_env: None
    ) -> None:
        organisation_id = _organisation(conn)
        billing.apply_event(
            conn,
            billing.normalize_stripe_event(
                _subscription_event(organisation_id, event_id="evt_due", status="past_due")
            ),
        )
        checked = metering.quota_check(conn, organisation_id, metering.KIND_CREDITS, 1)
        assert checked["allowed"] is False

    @pytest.mark.parametrize("status", ["unpaid", "incomplete", "paused"])
    def test_non_entitling_statuses_fail_closed_on_quota(
        self, conn: sqlite3.Connection, stripe_env: None, status: str
    ) -> None:
        """Unpaid/incomplete/unknown must not leave free-tier quota open."""
        organisation_id = _organisation(conn)
        billing.apply_event(
            conn,
            billing.normalize_stripe_event(
                _subscription_event(organisation_id, event_id=f"evt_{status}", status=status)
            ),
        )
        checked = metering.quota_check(conn, organisation_id, metering.KIND_CREDITS, 1)
        assert checked["allowed"] is False
        assert metering.organisation_plan(conn, organisation_id).id == plans.FALLBACK_PLAN_ID

    def test_the_mirrored_subscription_is_readable(
        self, conn: sqlite3.Connection, stripe_env: None
    ) -> None:
        organisation_id = _organisation(conn)
        billing.apply_event(
            conn, billing.normalize_stripe_event(_subscription_event(organisation_id))
        )
        mirrored = billing.subscription_of(conn, organisation_id)
        assert mirrored is not None
        assert mirrored["subscription_id"] == "sub_123"
        assert mirrored["cancel_at_period_end"] is False

    def test_no_subscription_reads_as_none(self, conn: sqlite3.Connection) -> None:
        assert billing.subscription_of(conn, _organisation(conn)) is None

    def test_public_subscription_omits_provider_ids(
        self, conn: sqlite3.Connection, stripe_env: None
    ) -> None:
        organisation_id = _organisation(conn)
        billing.apply_event(
            conn, billing.normalize_stripe_event(_subscription_event(organisation_id))
        )
        public = billing.public_subscription(conn, organisation_id)
        assert public is not None
        assert "customer_id" not in public
        assert "subscription_id" not in public
        assert public["status"] == "active"
        assert public["provider"] == billing.PROVIDER_STRIPE


class TestEventLedgerPrivacy:
    """The billing_events row must not keep Stripe customer PII."""

    def test_the_ledger_drops_customer_details(
        self, conn: sqlite3.Connection, stripe_env: None
    ) -> None:
        organisation_id = _organisation(conn)
        raw = _subscription_event(organisation_id, event_id="evt_pii")
        raw["data"]["object"]["customer_details"] = {
            "email": "payer@example.com",
            "name": "Payer Name",
            "address": {"line1": "1 Main St", "city": "Town"},
        }
        billing.apply_event(conn, billing.normalize_stripe_event(raw))
        row = conn.execute(
            f"SELECT payload FROM {metering.EVENT_TABLE} WHERE event_id = ?",
            ("evt_pii",),
        ).fetchone()
        assert row is not None
        stored = json.loads(str(row["payload"]))
        dumped = json.dumps(stored)
        assert "payer@example.com" not in dumped
        assert "Payer Name" not in dumped
        assert "1 Main St" not in dumped
        assert stored["event_id"] == "evt_pii"
        assert stored["customer_id"] == "cus_123"
        assert stored["subscription_id"] == "sub_123"

    def test_normalization_does_not_retain_the_raw_provider_body(self) -> None:
        raw = _subscription_event(1, event_id="evt_no_raw")
        raw["data"]["object"]["customer_details"] = {
            "email": "payer@example.com",
            "name": "Payer Name",
        }
        event = billing.normalize_stripe_event(raw)
        assert not hasattr(event, "payload")
        dumped = repr(event)
        assert "payer@example.com" not in dumped
        assert "Payer Name" not in dumped


class TestCheckoutGuards:
    """What a checkout refuses before it ever calls the provider."""

    def test_an_unknown_plan_is_refused(self, conn: sqlite3.Connection, stripe_env: None) -> None:
        with pytest.raises(billing.BillingError) as caught:
            billing.start_checkout(conn, {"id": 1}, "platinum")
        assert caught.value.status == 400

    def test_a_non_self_serve_plan_is_refused(
        self, conn: sqlite3.Connection, stripe_env: None
    ) -> None:
        """Buying the unmetered internal tier through checkout must be impossible."""
        with pytest.raises(billing.BillingError) as caught:
            billing.start_checkout(conn, {"id": 1}, "internal")
        assert caught.value.status == 400

    def test_checkout_is_refused_while_billing_is_disabled(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(billing.PROVIDER_ENV, billing.PROVIDER_DISABLED)
        with pytest.raises(billing.BillingError) as caught:
            billing.start_checkout(conn, {"id": 1}, "analyst")
        assert caught.value.status == 503

    def test_a_plan_with_no_configured_price_fails_loudly(
        self, conn: sqlite3.Connection, stripe_env: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Silently charging the wrong price would be worse than a 503."""
        monkeypatch.delenv("REPORTAL_STRIPE_PRICE_TEAM", raising=False)
        with pytest.raises(billing.BillingError) as caught:
            billing.start_checkout(conn, {"id": 1}, "team")
        assert caught.value.status == 503


class TestManualMode:
    """The development provider, which grants a plan without a payment."""

    @pytest.fixture()
    def manual_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(billing.PROVIDER_ENV, billing.PROVIDER_MANUAL)

    def test_a_manual_checkout_grants_on_confirmation(
        self, conn: sqlite3.Connection, manual_env: None
    ) -> None:
        organisation_id = _organisation(conn)
        session = billing.start_checkout(conn, {"id": organisation_id}, "analyst")
        assert session.provider == billing.PROVIDER_MANUAL
        billing.complete_manual_checkout(conn, session.session_id, organisation_id)
        assert metering.organisation_plan(conn, organisation_id).id == "analyst"

    def test_a_token_is_spent_once(self, conn: sqlite3.Connection, manual_env: None) -> None:
        organisation_id = _organisation(conn)
        session = billing.start_checkout(conn, {"id": organisation_id}, "analyst")
        billing.complete_manual_checkout(conn, session.session_id, organisation_id)
        with pytest.raises(billing.BillingError):
            billing.complete_manual_checkout(conn, session.session_id, organisation_id)

    def test_concurrent_confirms_spend_the_token_once(
        self, portal_db: Path, conn: sqlite3.Connection, manual_env: None
    ) -> None:
        """Two ASGI workers confirming the same token must not both grant."""
        organisation_id = _organisation(conn)
        session = billing.start_checkout(conn, {"id": organisation_id}, "analyst")
        outcomes: list[str] = []
        barrier = threading.Barrier(8)
        gate = threading.Lock()

        def confirm() -> None:
            with contextlib.closing(store.connect(portal_db)) as worker_conn:
                barrier.wait()
                try:
                    billing.complete_manual_checkout(
                        worker_conn, session.session_id, organisation_id
                    )
                    with gate:
                        outcomes.append("ok")
                except billing.BillingError:
                    with gate:
                        outcomes.append("err")

        threads = [threading.Thread(target=confirm) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert outcomes.count("ok") == 1
        assert outcomes.count("err") == 7
        # The fixture connection may hold a snapshot; read the grant on a
        # fresh connection so a concurrent commit is visible.
        with contextlib.closing(store.connect(portal_db)) as check:
            assert metering.organisation_plan(check, organisation_id).id == "analyst"

    def test_a_token_cannot_be_redeemed_by_another_organisation(
        self, conn: sqlite3.Connection, manual_env: None
    ) -> None:
        mine = _organisation(conn, "mine")
        theirs = _organisation(conn, "theirs")
        session = billing.start_checkout(conn, {"id": mine}, "analyst")
        with pytest.raises(billing.BillingError):
            billing.complete_manual_checkout(conn, session.session_id, theirs)

    def test_an_unknown_token_is_refused(self, conn: sqlite3.Connection, manual_env: None) -> None:
        with pytest.raises(billing.BillingError):
            billing.complete_manual_checkout(conn, "not-a-token", _organisation(conn))

    def test_cancelling_drops_to_the_fallback_plan(
        self, conn: sqlite3.Connection, manual_env: None
    ) -> None:
        organisation_id = _organisation(conn)
        session = billing.start_checkout(conn, {"id": organisation_id}, "analyst")
        billing.complete_manual_checkout(conn, session.session_id, organisation_id)
        billing.cancel_manual_subscription(conn, organisation_id)
        assert metering.organisation_plan(conn, organisation_id).id == plans.FALLBACK_PLAN_ID

    def test_the_intent_map_is_bounded(self, conn: sqlite3.Connection, manual_env: None) -> None:
        """Past the cap the oldest token is dropped so a burst cannot grow the map without bound."""
        billing._manual_intents.clear()
        for index in range(billing.MAX_MANUAL_INTENTS + 8):
            # Distinct organisations so each call is a new logical grant; the
            # same org+plan reuses its live token and would never fill the map.
            organisation_id = _organisation(conn, f"tenant-{index}")
            billing.start_checkout(conn, {"id": organisation_id}, "analyst")
        assert len(billing._manual_intents) == billing.MAX_MANUAL_INTENTS

    def test_a_restore_keeps_the_intent_map_bounded(self) -> None:
        """A failed durable write must not grow the map past the same cap."""
        billing._manual_intents.clear()
        for index in range(billing.MAX_MANUAL_INTENTS):
            billing._manual_intents[f"live-{index}"] = (index, "analyst", 1e18)
        billing._restore_manual_intent("restored-token", 999, "analyst")
        assert len(billing._manual_intents) == billing.MAX_MANUAL_INTENTS
        assert "restored-token" in billing._manual_intents

    def test_a_second_checkout_reuses_the_live_token(
        self, conn: sqlite3.Connection, manual_env: None
    ) -> None:
        """A double-click must not mint a second confirmable grant."""
        organisation_id = _organisation(conn)
        billing._manual_intents.clear()
        first = billing.start_checkout(conn, {"id": organisation_id}, "analyst")
        second = billing.start_checkout(conn, {"id": organisation_id}, "analyst")
        assert first.session_id == second.session_id
        assert len(billing._manual_intents) == 1

    def test_manual_intent_uses_the_token_urlsafe_seam(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(billing, "_token_urlsafe", lambda _n: "pinned-manual-token")
        billing._manual_intents.clear()
        token = billing._store_manual_intent(1, "analyst")
        assert token == "pinned-manual-token"
        assert billing.manual_intent(token) == (1, "analyst")


class TestReconcileRateLimit:
    """The reconcile path calls out, so it is bounded."""

    def test_the_first_attempts_pass_and_then_the_cap_bites(self) -> None:
        organisation_id = 987654
        allowed = [billing.reconcile_allowed(organisation_id) for _ in range(5)]
        assert allowed[: billing._RECONCILE_MAX_HITS] == [True] * billing._RECONCILE_MAX_HITS
        assert allowed[-1] is False

    def test_an_expired_window_drops_the_organisation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The limiter holds the organisations reconciling now, not every one ever seen."""
        clock = [1000.0]
        monkeypatch.setattr(billing, "_monotonic", lambda: clock[0])

        assert billing.reconcile_allowed(111111) is True
        assert 111111 in billing._rate_states

        clock[0] += billing._RECONCILE_WINDOW_S + 1
        assert billing.reconcile_allowed(222222) is True
        assert 111111 not in billing._rate_states, "the stale window is dropped"

    def test_reconcile_orgs_are_capped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        clock = [1000.0]
        monkeypatch.setattr(billing, "_monotonic", lambda: clock[0])
        billing._rate_states.clear()
        for index in range(billing.MAX_RECONCILE_ORGS + 8):
            assert billing.reconcile_allowed(index) is True
        assert len(billing._rate_states) == billing.MAX_RECONCILE_ORGS
        assert 0 not in billing._rate_states
        assert billing.MAX_RECONCILE_ORGS + 7 in billing._rate_states

    def test_concurrent_reconciles_respect_the_cap(self) -> None:
        """The check-and-append is atomic across ASGI workers."""
        organisation_id = 555666
        billing._rate_states.pop(organisation_id, None)
        barrier = threading.Barrier(16)
        allowed = 0
        lock = threading.Lock()

        def attempt() -> None:
            nonlocal allowed
            barrier.wait()
            if billing.reconcile_allowed(organisation_id):
                with lock:
                    allowed += 1

        threads = [threading.Thread(target=attempt) for _ in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert allowed == billing._RECONCILE_MAX_HITS

    def test_reconcile_needs_the_stripe_provider(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(billing.PROVIDER_ENV, billing.PROVIDER_MANUAL)
        with pytest.raises(billing.BillingError) as caught:
            billing.reconcile_account(conn, 424242)
        assert caught.value.status == 503


class TestStripeRequestIdempotency:
    """Checkout POSTs must share one Idempotency-Key across retries and double-clicks."""

    def test_the_key_is_stable_inside_the_window(self) -> None:
        now = float(billing.IDEMPOTENCY_WINDOW_S * 5_666_666)
        first = billing._stripe_idempotency_key("checkout", 7, "analyst", now=now)
        second = billing._stripe_idempotency_key(
            "checkout", 7, "analyst", now=now + billing.IDEMPOTENCY_WINDOW_S - 1
        )
        assert first == second
        assert first.startswith("reportal-checkout-7-analyst-")

    def test_the_key_rotates_after_the_window(self) -> None:
        now = float(billing.IDEMPOTENCY_WINDOW_S * 5_666_666)
        first = billing._stripe_idempotency_key("checkout", 7, "analyst", now=now)
        later = billing._stripe_idempotency_key(
            "checkout", 7, "analyst", now=now + billing.IDEMPOTENCY_WINDOW_S
        )
        assert first != later

    def test_a_timeout_retry_reuses_the_same_key(
        self, stripe_env: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A timeout after Stripe applied the write must not open a second session."""
        seen: list[str] = []

        class _Response:
            status_code = 200

            @staticmethod
            def json() -> dict[str, str]:
                return {"id": "cs_test", "url": "https://checkout.example/s"}

        class _Client:
            def __init__(self, *args: object, **kwargs: object) -> None:
                del args, kwargs

            def __enter__(self) -> object:
                return self

            def __exit__(self, *args: object) -> None:
                del args

            def post(self, url: str, data: object, headers: dict[str, str]) -> _Response:
                del url, data
                seen.append(headers["Idempotency-Key"])
                if len(seen) == 1:
                    raise billing.httpx.TimeoutException("timed out")
                return _Response()

        monkeypatch.setattr(billing.httpx, "Client", _Client)
        session = billing._stripe_checkout({"id": 42}, plans.get_plan("analyst"))
        assert session.session_id == "cs_test"
        assert len(seen) == 2
        assert seen[0] == seen[1]
        assert seen[0] == billing._stripe_idempotency_key("checkout", 42, "analyst")


class TestPeriodEndShapes:
    """Stripe moved the period end into the line item; both shapes are read."""

    def test_the_legacy_top_level_field_is_read(self, stripe_env: None) -> None:
        event = billing.normalize_stripe_event(_subscription_event(1))
        assert event.current_period_end

    def test_the_line_item_field_is_read(self, stripe_env: None) -> None:
        raw = _subscription_event(1)
        del raw["data"]["object"]["current_period_end"]
        raw["data"]["object"]["items"]["data"][0]["current_period_end"] = (
            int(billing._wall_time()) + 900
        )
        assert billing.normalize_stripe_event(raw).current_period_end


class TestStripeRequestErrors:
    def test_unknown_provider_disables_billing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(billing.PROVIDER_ENV, "mystery")
        assert billing.provider_name() == billing.PROVIDER_DISABLED
        assert billing.billing_enabled() is False

    def _client(self, monkeypatch: pytest.MonkeyPatch, behavior: str) -> list[dict[str, str]]:
        _httpx = billing.httpx
        seen: list[dict[str, str]] = []

        class _Response:
            status_code = 200 if behavior != "reject" else 402

            @staticmethod
            def json() -> dict[str, object]:
                if behavior == "nonjson":
                    raise ValueError("nope")
                if behavior == "reject":
                    return {"error": {"message": "card declined"}}
                return {"ok": True}

        class _Client:
            def __init__(self, *args: object, **kwargs: object) -> None:
                del args, kwargs

            def __enter__(self) -> object:
                return self

            def __exit__(self, *args: object) -> None:
                del args

            def post(self, url: str, data: object, headers: dict[str, str]) -> _Response:
                del url, data
                seen.append(headers)
                if behavior == "timeout":
                    raise _httpx.TimeoutException("slow")
                if behavior == "unreachable":
                    raise _httpx.ConnectError("down")
                return _Response()

        monkeypatch.setattr(billing.httpx, "Client", _Client)
        return seen

    def test_non_json_body_is_a_502(
        self, stripe_env: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._client(monkeypatch, "nonjson")
        with pytest.raises(billing.BillingError) as caught:
            billing._stripe_request("/x", {}, idempotency_key="k")
        assert caught.value.status == 502

    def test_provider_rejection_names_the_reason(
        self, stripe_env: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._client(monkeypatch, "reject")
        with pytest.raises(billing.BillingError, match="card declined"):
            billing._stripe_request("/x", {}, idempotency_key="k")

    def test_transient_timeouts_exhaust_to_unreachable(
        self, stripe_env: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._client(monkeypatch, "timeout")
        with pytest.raises(billing.BillingError, match="unreachable"):
            billing._stripe_request("/x", {}, idempotency_key="k")

    def test_connect_error_is_unreachable(
        self, stripe_env: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._client(monkeypatch, "unreachable")
        with pytest.raises(billing.BillingError, match="unreachable"):
            billing._stripe_request("/x", {}, idempotency_key="k")
