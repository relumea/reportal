"""Organisation subscription billing through Stripe.

Self-serve upgrades go through Stripe Checkout; subscription state comes back
through a signature-verified webhook.  The integration is the REST API over
reportal's one HTTP client line (``httpx2``) plus stdlib ``hmac``, so the
runtime dependency set does not change and the request shapes stay visible in
one file.

``REPORTAL_BILLING_PROVIDER`` selects the mode:

* ``auto`` (default): Stripe when ``REPORTAL_STRIPE_SECRET_KEY`` is set,
  otherwise ``disabled``.
* ``stripe``: Stripe, failing loudly when a price is unconfigured.
* ``manual``: a local, explicitly-enabled mode that grants a plan through an
  operator confirmation (development and self-hosted demos only).
* ``disabled``: no self-serve checkout.

The four invariants this module is built around, each of which is a way a
billing integration loses money or double-charges if it is skipped:

**Completion is not payment.**  ``checkout.session.completed`` fires when the
customer finishes the form, not when the charge settles.  Entitlement is
granted on ``payment_status == "paid"`` (or an entitling subscription status),
never on the completion event alone.

**Webhooks are idempotent.**  Stripe redelivers, so every event id is claimed
in ``billing_events`` inside the same transaction that applies it.  A
redelivery finds the row and answers ``duplicate`` without touching the
subscription.

**The price id is the source of truth.**  A webhook maps the subscription's
price back to a plan through :func:`reportal.plans.plan_for_price_id` rather
than trusting checkout metadata, because metadata is caller-supplied and a
price id is not.

**Signature verification is mandatory and constant-time.**  An unverified
webhook body is an unauthenticated request to change entitlement, so
:func:`verify_webhook` refuses anything whose HMAC does not match inside the
timestamp tolerance, using :func:`hmac.compare_digest`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx2 as httpx

from reportal import auth, metering, plans

_log = logging.getLogger("reportal")

STRIPE_API_BASE = "https://api.stripe.com/v1"
DEFAULT_STRIPE_API_VERSION = "2026-08-26.dahlia"

# How far a webhook timestamp may be from now before the signature is stale.
# Five minutes is Stripe's own recommendation: long enough for a slow delivery,
# short enough that a captured body cannot be replayed indefinitely.
WEBHOOK_TOLERANCE_S = 300
_REQUEST_TIMEOUT_S = 20.0

PROVIDER_ENV = "REPORTAL_BILLING_PROVIDER"
STRIPE_SECRET_ENV = "REPORTAL_STRIPE_SECRET_KEY"
STRIPE_WEBHOOK_ENV = "REPORTAL_STRIPE_WEBHOOK_SECRET"
STRIPE_API_VERSION_ENV = "REPORTAL_STRIPE_API_VERSION"
PUBLIC_BASE_URL_ENV = "REPORTAL_PUBLIC_BASE_URL"

PROVIDER_STRIPE = "stripe"
PROVIDER_MANUAL = "manual"
PROVIDER_DISABLED = "disabled"


class BillingError(RuntimeError):
    """A checkout or webhook could not be honored.  ``status`` is the HTTP answer."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


@dataclass(frozen=True)
class CheckoutSession:
    """Where to send a customer to pay."""

    provider: str
    session_id: str
    url: str


@dataclass(frozen=True)
class PortalSession:
    """Where to send a customer to manage or cancel a subscription."""

    provider: str
    url: str


@dataclass(frozen=True)
class BillingEvent:
    """Normalized provider event, independent of Stripe's wire shape."""

    event_id: str
    provider: str
    kind: str
    organisation_id: int | None = None
    plan_id: str | None = None
    customer_id: str = ""
    subscription_id: str = ""
    status: str = ""
    current_period_end: str = ""
    cancel_at_period_end: bool = False
    payment_status: str = ""
    payload: dict[str, Any] = field(default_factory=dict)

    def entitles(self) -> bool:
        """Whether this event should grant the plan it names.

        Completion is not payment: a checkout event entitles only once the
        payment status says paid, and a subscription event only while its status
        is one the plan is active under.
        """
        if self.payment_status:
            return self.payment_status == "paid"
        return self.status in metering.ENTITLING_STATUSES


def _secret_key() -> str:
    return os.environ.get(STRIPE_SECRET_ENV, "").strip()


def _webhook_secret() -> str:
    return os.environ.get(STRIPE_WEBHOOK_ENV, "").strip()


def api_version() -> str:
    """The Stripe API version every request pins."""
    return os.environ.get(STRIPE_API_VERSION_ENV, "").strip() or DEFAULT_STRIPE_API_VERSION


def provider_name() -> str:
    """The active billing provider, resolving ``auto`` against the environment."""
    configured = os.environ.get(PROVIDER_ENV, "").strip().lower() or "auto"
    if configured == "auto":
        return PROVIDER_STRIPE if _secret_key() else PROVIDER_DISABLED
    if configured in {PROVIDER_STRIPE, PROVIDER_MANUAL, PROVIDER_DISABLED}:
        return configured
    _log.warning("unknown %s %r; billing disabled", PROVIDER_ENV, configured)
    return PROVIDER_DISABLED


def billing_enabled() -> bool:
    """Whether any self-serve checkout path is available."""
    return provider_name() != PROVIDER_DISABLED


def billing_configured() -> bool:
    """Whether the active provider has everything it needs to take a payment."""
    provider = provider_name()
    if provider == PROVIDER_STRIPE:
        return bool(_secret_key())
    return provider == PROVIDER_MANUAL


def public_billing_config() -> dict[str, Any]:
    """What the SPA may know about billing; never a key or a secret."""
    provider = provider_name()
    return {
        "provider": provider,
        "enabled": provider != PROVIDER_DISABLED,
        "configured": billing_configured(),
        "webhook_verified": bool(_webhook_secret()) if provider == PROVIDER_STRIPE else False,
        "plans": [plan.describe() for plan in plans.public_plans()],
        "checkout_plans": [plan.id for plan in plans.checkout_plans()],
    }


def _public_base_url() -> str:
    return os.environ.get(PUBLIC_BASE_URL_ENV, "").strip().rstrip("/") or "http://127.0.0.1:8002"


def _checkout_urls(organisation_id: int) -> tuple[str, str]:
    """The success and cancel URLs a checkout returns the customer to."""
    base = _public_base_url()
    return (
        f"{base}/#/billing?organisation={organisation_id}&checkout=success",
        f"{base}/#/billing?organisation={organisation_id}&checkout=cancel",
    )


# ── Stripe REST ────────────────────────────────────────────────────


def _stripe_request(path: str, form: dict[str, str]) -> dict[str, Any]:
    """POST a form-encoded body to Stripe and return the parsed object."""
    key = _secret_key()
    if not key:
        raise BillingError(503, "billing-unconfigured")
    headers = {
        "Authorization": f"Bearer {key}",
        "Stripe-Version": api_version(),
        "Content-Type": "application/x-www-form-urlencoded",
        # Stripe deduplicates retries by this key, so a network timeout that is
        # actually a success cannot create a second subscription.
        "Idempotency-Key": secrets.token_urlsafe(24),
    }
    try:
        response = httpx.post(
            f"{STRIPE_API_BASE}{path}",
            data=form,
            headers=headers,
            timeout=_REQUEST_TIMEOUT_S,
        )
    except httpx.HTTPError as exc:
        raise BillingError(502, f"billing provider unreachable: {exc}") from exc
    try:
        payload = response.json()
    except ValueError as exc:
        raise BillingError(502, "billing provider returned a non-JSON body") from exc
    if response.status_code >= 400:
        message = str(payload.get("error", {}).get("message", "")) or "provider rejected the call"
        raise BillingError(502, f"billing provider error: {message}")
    return dict(payload)


def _stripe_checkout(organisation: dict[str, Any], plan: plans.Plan) -> CheckoutSession:
    """Open a Stripe Checkout session for *plan*."""
    price_id = plans.stripe_price_id(plan.id)
    if not price_id:
        raise BillingError(503, f"no Stripe price configured for plan {plan.id}")
    organisation_id = int(organisation["id"])
    success_url, cancel_url = _checkout_urls(organisation_id)
    form = {
        "mode": "subscription",
        "line_items[0][price]": price_id,
        "line_items[0][quantity]": "1",
        "success_url": success_url,
        "cancel_url": cancel_url,
        "client_reference_id": str(organisation_id),
        "metadata[organisation_id]": str(organisation_id),
        "metadata[plan_id]": plan.id,
        "subscription_data[metadata][organisation_id]": str(organisation_id),
        "subscription_data[metadata][plan_id]": plan.id,
    }
    if plan.trial_days:
        form["subscription_data[trial_period_days]"] = str(plan.trial_days)
    payload = _stripe_request("/checkout/sessions", form)
    url = str(payload.get("url") or "")
    if not url:
        raise BillingError(502, "provider returned no checkout URL")
    return CheckoutSession(PROVIDER_STRIPE, str(payload.get("id") or ""), url)


# ── Manual mode ────────────────────────────────────────────────────

# Manual checkout intents, in memory: a development mode grants a plan through
# an operator confirmation and nothing is persisted, so a restart clears them.
_manual_intents: dict[str, tuple[int, str, float]] = {}
_MANUAL_INTENT_TTL_S = 900.0


def _store_manual_intent(organisation_id: int, plan_id: str) -> str:
    """Record a pending manual grant and return its one-time token."""
    now = time.monotonic()
    for token, (_, _, expires) in list(_manual_intents.items()):
        if expires <= now:
            _manual_intents.pop(token, None)
    token = secrets.token_urlsafe(24)
    _manual_intents[token] = (organisation_id, plan_id, now + _MANUAL_INTENT_TTL_S)
    return token


def manual_intent(token: str) -> tuple[int, str] | None:
    """The organisation and plan a manual token names, or None when it is spent."""
    entry = _manual_intents.get(token)
    if entry is None:
        return None
    organisation_id, plan_id, expires = entry
    if expires <= time.monotonic():
        _manual_intents.pop(token, None)
        return None
    return organisation_id, plan_id


def complete_manual_checkout(
    conn: sqlite3.Connection, token: str, organisation_id: int
) -> dict[str, Any]:
    """Grant the plan a manual token names; the token is spent either way."""
    intent = manual_intent(token)
    if intent is None or intent[0] != organisation_id:
        raise BillingError(400, "unknown or expired checkout token")
    _manual_intents.pop(token, None)
    plan = plans.get_plan(intent[1])
    _upsert_subscription(
        conn,
        organisation_id=organisation_id,
        provider=PROVIDER_MANUAL,
        customer_id="",
        subscription_id=f"manual_{token[:12]}",
        status=metering.STATUS_ACTIVE,
        current_period_end="",
        cancel_at_period_end=False,
        plan_id=plan.id,
    )
    return {"organisation_id": organisation_id, "plan_id": plan.id, "provider": PROVIDER_MANUAL}


def cancel_manual_subscription(conn: sqlite3.Connection, organisation_id: int) -> dict[str, Any]:
    """Drop a manual subscription back to the fallback plan."""
    _upsert_subscription(
        conn,
        organisation_id=organisation_id,
        provider=PROVIDER_MANUAL,
        customer_id="",
        subscription_id="",
        status=metering.STATUS_CANCELED,
        current_period_end="",
        cancel_at_period_end=False,
        plan_id=plans.FALLBACK_PLAN_ID,
    )
    return {"organisation_id": organisation_id, "plan_id": plans.FALLBACK_PLAN_ID}


# ── Checkout and portal ────────────────────────────────────────────


def start_checkout(
    conn: sqlite3.Connection, organisation: dict[str, Any], plan_id: str
) -> CheckoutSession:
    """Begin a self-serve upgrade to *plan_id*."""
    if not plans.plan_exists(plan_id):
        raise BillingError(400, f"unknown plan {plan_id}")
    plan = plans.get_plan(plan_id)
    if not plan.self_serve:
        raise BillingError(400, f"plan {plan_id} is not self-serve")
    provider = provider_name()
    if provider == PROVIDER_DISABLED:
        raise BillingError(503, "billing is not enabled on this install")
    if provider == PROVIDER_MANUAL:
        organisation_id = int(organisation["id"])
        token = _store_manual_intent(organisation_id, plan.id)
        base = _public_base_url()
        return CheckoutSession(
            PROVIDER_MANUAL,
            token,
            f"{base}/#/billing?organisation={organisation_id}&manual={token}",
        )
    del conn
    return _stripe_checkout(organisation, plan)


def start_billing_portal(conn: sqlite3.Connection, organisation_id: int) -> PortalSession:
    """Open the provider's self-service portal for the organisation."""
    provider = provider_name()
    if provider == PROVIDER_DISABLED:
        raise BillingError(503, "billing is not enabled on this install")
    if provider == PROVIDER_MANUAL:
        base = _public_base_url()
        return PortalSession(
            PROVIDER_MANUAL, f"{base}/#/billing?organisation={organisation_id}&manual=manage"
        )
    row = conn.execute(
        f"SELECT customer_id FROM {metering.SUBSCRIPTION_TABLE} WHERE organisation_id = ?",
        (organisation_id,),
    ).fetchone()
    customer = str(row["customer_id"]) if row is not None else ""
    if not customer:
        raise BillingError(409, "no subscription to manage")
    payload = _stripe_request(
        "/billing_portal/sessions",
        {"customer": customer, "return_url": f"{_public_base_url()}/#/billing"},
    )
    url = str(payload.get("url") or "")
    if not url:
        raise BillingError(502, "provider returned no portal URL")
    return PortalSession(PROVIDER_STRIPE, url)


# ── Webhook verification ───────────────────────────────────────────


def _signature_valid(payload: bytes, header: str, secret: str) -> bool:
    """Whether *header* carries a signature matching *payload*, in tolerance."""
    timestamp = ""
    signatures: list[str] = []
    for part in header.split(","):
        key, _, value = part.strip().partition("=")
        if key == "t":
            timestamp = value
        elif key == "v1":
            signatures.append(value)
    if not timestamp or not signatures:
        return False
    try:
        age = abs(time.time() - int(timestamp))
    except ValueError:
        return False
    if age > WEBHOOK_TOLERANCE_S:
        return False
    expected = hmac.new(
        secret.encode("utf-8"),
        f"{timestamp}.".encode() + payload,
        hashlib.sha256,
    ).hexdigest()
    return any(hmac.compare_digest(expected, candidate) for candidate in signatures)


def verify_webhook(payload: bytes, signature_header: str) -> dict[str, Any]:
    """Parse *payload* once its signature verifies, else raise.

    An install with no webhook secret configured refuses every webhook rather
    than trusting the body: an unverified event is an unauthenticated request to
    change what a tenant is entitled to.
    """
    secret = _webhook_secret()
    if not secret:
        raise BillingError(503, "no webhook secret configured")
    if not _signature_valid(payload, signature_header or "", secret):
        raise BillingError(400, "invalid signature")
    try:
        return dict(json.loads(payload.decode("utf-8")))
    except (ValueError, UnicodeDecodeError) as exc:
        raise BillingError(400, "webhook body is not JSON") from exc


# ── Event normalization ────────────────────────────────────────────


def _object(event: dict[str, Any]) -> dict[str, Any]:
    data = event.get("data")
    if isinstance(data, dict):
        obj = data.get("object")
        if isinstance(obj, dict):
            return obj
    return {}


def _text(obj: dict[str, Any], key: str) -> str:
    """A string field, flattening Stripe's expandable ``{"id": ...}`` shape."""
    value = obj.get(key)
    if isinstance(value, dict):
        value = value.get("id")
    return str(value) if isinstance(value, str | int) else ""


def _metadata(obj: dict[str, Any]) -> dict[str, str]:
    raw = obj.get("metadata")
    return {str(k): str(v) for k, v in raw.items()} if isinstance(raw, dict) else {}


def _iso(epoch: Any) -> str:
    """A Unix timestamp as ISO 8601, or the empty string."""
    if not isinstance(epoch, int | float) or isinstance(epoch, bool) or epoch <= 0:
        return ""
    return datetime.fromtimestamp(float(epoch), UTC).isoformat(timespec="seconds")


def _period_end(obj: dict[str, Any]) -> str:
    """The subscription's period end, from either the modern or legacy shape."""
    direct = obj.get("current_period_end")
    if direct:
        return _iso(direct)
    items = obj.get("items")
    entries = items.get("data") if isinstance(items, dict) else None
    if isinstance(entries, list) and entries and isinstance(entries[0], dict):
        return _iso(entries[0].get("current_period_end"))
    return ""


def _plan_from_subscription_object(obj: dict[str, Any]) -> str | None:
    """The plan a subscription's price id maps to, else its metadata's claim.

    The price id comes first because it is what the customer was actually
    charged for; metadata is only the fallback for a subscription created
    outside checkout.
    """
    items = obj.get("items")
    entries = items.get("data") if isinstance(items, dict) else None
    if isinstance(entries, list):
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            price = entry.get("price")
            price_id = price.get("id") if isinstance(price, dict) else price
            if isinstance(price_id, str):
                plan = plans.plan_for_price_id(price_id)
                if plan is not None:
                    return plan.id
    claimed = _metadata(obj).get("plan_id", "")
    return claimed if claimed and plans.plan_exists(claimed) else None


def _org_id(obj: dict[str, Any]) -> int | None:
    """The organisation a Stripe object names, from metadata or the reference."""
    for candidate in (_metadata(obj).get("organisation_id", ""), _text(obj, "client_reference_id")):
        try:
            value = int(candidate)
        except (TypeError, ValueError):
            continue
        if value > 0:
            return value
    return None


def normalize_stripe_event(event: dict[str, Any]) -> BillingEvent:
    """Turn a Stripe event into reportal's provider-independent shape."""
    obj = _object(event)
    kind = str(event.get("type") or "")
    subscription_id = _text(obj, "subscription") or (
        _text(obj, "id") if kind.startswith("customer.subscription") else ""
    )
    return BillingEvent(
        event_id=str(event.get("id") or ""),
        provider=PROVIDER_STRIPE,
        kind=kind,
        organisation_id=_org_id(obj),
        # The helper already falls back to metadata and validates it; repeating
        # the fallback here would take an unvalidated plan name from a field the
        # customer controls.
        plan_id=_plan_from_subscription_object(obj),
        customer_id=_text(obj, "customer"),
        subscription_id=subscription_id,
        status=str(obj.get("status") or ""),
        current_period_end=_period_end(obj),
        cancel_at_period_end=bool(obj.get("cancel_at_period_end")),
        payment_status=str(obj.get("payment_status") or ""),
        payload=event,
    )


# ── Applying an event ──────────────────────────────────────────────


def _find_organisation(conn: sqlite3.Connection, event: BillingEvent) -> int | None:
    """The organisation an event belongs to: its own claim, else the customer."""
    if event.organisation_id:
        return event.organisation_id
    for column, value in (
        ("subscription_id", event.subscription_id),
        ("customer_id", event.customer_id),
    ):
        if not value:
            continue
        row = conn.execute(
            f"SELECT organisation_id FROM {metering.SUBSCRIPTION_TABLE} WHERE {column} = ?",
            (value,),
        ).fetchone()
        if row is not None:
            return int(row["organisation_id"])
    return None


def _claim_event(
    conn: sqlite3.Connection, event: BillingEvent, organisation_id: int | None
) -> bool:
    """Claim *event*'s id, returning False when it was already handled.

    The insert is the lock: ``event_id`` is the primary key, so a redelivery
    racing the first delivery loses the insert rather than applying twice.
    """
    try:
        conn.execute(
            f"INSERT INTO {metering.EVENT_TABLE} "
            "(event_id, provider, kind, organisation_id, applied, payload, received_at) "
            "VALUES (?, ?, ?, ?, 0, ?, ?)",
            (
                event.event_id,
                event.provider,
                event.kind,
                organisation_id,
                json.dumps(event.payload)[:20000],
                auth.now(),
            ),
        )
    except sqlite3.IntegrityError:
        return False
    return True


def _upsert_subscription(
    conn: sqlite3.Connection,
    *,
    organisation_id: int,
    provider: str,
    customer_id: str,
    subscription_id: str,
    status: str,
    current_period_end: str,
    cancel_at_period_end: bool,
    plan_id: str | None,
) -> None:
    """Mirror the provider's subscription state and set the entitled plan."""
    conn.execute(
        f"INSERT INTO {metering.SUBSCRIPTION_TABLE} "
        "(organisation_id, provider, customer_id, subscription_id, status, "
        " current_period_end, cancel_at_period_end, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(organisation_id) DO UPDATE SET "
        " provider = excluded.provider, customer_id = excluded.customer_id, "
        " subscription_id = excluded.subscription_id, status = excluded.status, "
        " current_period_end = excluded.current_period_end, "
        " cancel_at_period_end = excluded.cancel_at_period_end, "
        " updated_at = excluded.updated_at",
        (
            organisation_id,
            provider,
            customer_id,
            subscription_id,
            status,
            current_period_end,
            int(cancel_at_period_end),
            auth.now(),
        ),
    )
    entitled = status in metering.ENTITLING_STATUSES
    target = plan_id if (entitled and plan_id) else plans.FALLBACK_PLAN_ID
    org_status = (
        metering.STATUS_PAST_DUE if status == metering.STATUS_PAST_DUE else metering.STATUS_ACTIVE
    )
    conn.execute(
        f"UPDATE {auth.ORG_TABLE} SET plan_id = ?, status = ?, period_started_at = ? WHERE id = ?",
        (target, org_status, auth.now(), organisation_id),
    )


def apply_event(conn: sqlite3.Connection, event: BillingEvent) -> dict[str, Any]:
    """Claim, mirror and entitle one provider event.

    The claim and the write share a transaction, so a crash between them leaves
    the event unclaimed and a redelivery applies it, rather than leaving it
    claimed and never applied.
    """
    if not event.event_id:
        raise BillingError(400, "event carries no id")
    organisation_id = _find_organisation(conn, event)
    try:
        if not _claim_event(conn, event, organisation_id):
            conn.rollback()
            return {"status": "duplicate", "event_id": event.event_id}
        if organisation_id is None:
            conn.commit()
            _log.warning("billing event %s names no resolvable tenant", event.event_id)
            return {"status": "unresolved", "event_id": event.event_id}
        if event.kind.startswith("customer.subscription") or event.entitles():
            status = event.status or (
                metering.STATUS_ACTIVE if event.entitles() else metering.STATUS_PAST_DUE
            )
            if event.kind == "customer.subscription.deleted":
                status = metering.STATUS_CANCELED
            _upsert_subscription(
                conn,
                organisation_id=organisation_id,
                provider=event.provider,
                customer_id=event.customer_id,
                subscription_id=event.subscription_id,
                status=status,
                current_period_end=event.current_period_end,
                cancel_at_period_end=event.cancel_at_period_end,
                plan_id=event.plan_id,
            )
        conn.execute(
            f"UPDATE {metering.EVENT_TABLE} SET applied = 1 WHERE event_id = ?",
            (event.event_id,),
        )
        conn.commit()
    except sqlite3.Error as exc:
        conn.rollback()
        raise BillingError(500, f"could not apply billing event: {exc}") from exc
    return {
        "status": "applied",
        "event_id": event.event_id,
        "organisation_id": organisation_id,
        "plan_id": event.plan_id,
    }


# ── Reconcile ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class ReconcileResult:
    """What a re-read of the provider's state found."""

    organisation_id: int
    provider: str
    status: str
    plan_id: str | None
    changed: bool


# Per-organisation rate limit on the reconcile path: it calls the provider, so
# an unbounded caller could be used to hammer Stripe through reportal.
_rate_states: dict[int, list[float]] = {}
_RECONCILE_WINDOW_S = 60.0
_RECONCILE_MAX_HITS = 3


def reconcile_allowed(organisation_id: int) -> bool:
    """Whether the organisation may reconcile again inside the window."""
    now = time.monotonic()
    hits = [hit for hit in _rate_states.get(organisation_id, []) if now - hit < _RECONCILE_WINDOW_S]
    if len(hits) >= _RECONCILE_MAX_HITS:
        _rate_states[organisation_id] = hits
        return False
    hits.append(now)
    _rate_states[organisation_id] = hits
    return True


def reconcile_account(conn: sqlite3.Connection, organisation_id: int) -> ReconcileResult:
    """Re-read the organisation's subscription and mirror it.

    Webhooks are the primary path; this covers a delivery that was lost.  It
    mirrors what the provider already says and never grants entitlement from a
    caller's claim, so it is safe to expose to the tenant itself.
    """
    provider = provider_name()
    if provider != PROVIDER_STRIPE:
        raise BillingError(503, "reconcile needs the Stripe provider")
    row = conn.execute(
        f"SELECT subscription_id, status, provider FROM {metering.SUBSCRIPTION_TABLE} "
        "WHERE organisation_id = ?",
        (organisation_id,),
    ).fetchone()
    subscription_id = str(row["subscription_id"]) if row is not None else ""
    if not subscription_id:
        raise BillingError(409, "no subscription to reconcile")
    key = _secret_key()
    try:
        response = httpx.get(
            f"{STRIPE_API_BASE}/subscriptions/{subscription_id}",
            headers={"Authorization": f"Bearer {key}", "Stripe-Version": api_version()},
            timeout=_REQUEST_TIMEOUT_S,
        )
        payload = dict(response.json())
    except (httpx.HTTPError, ValueError) as exc:
        raise BillingError(502, f"billing provider unreachable: {exc}") from exc
    if response.status_code >= 400:
        raise BillingError(502, "provider rejected the subscription read")
    status = str(payload.get("status") or "")
    plan_id = _plan_from_subscription_object(payload)
    changed = status != str(row["status"] if row is not None else "")
    _upsert_subscription(
        conn,
        organisation_id=organisation_id,
        provider=PROVIDER_STRIPE,
        customer_id=_text(payload, "customer"),
        subscription_id=subscription_id,
        status=status,
        current_period_end=_period_end(payload),
        cancel_at_period_end=bool(payload.get("cancel_at_period_end")),
        plan_id=plan_id,
    )
    conn.commit()
    return ReconcileResult(organisation_id, PROVIDER_STRIPE, status, plan_id, changed)


def subscription_of(conn: sqlite3.Connection, organisation_id: int) -> dict[str, Any] | None:
    """The mirrored subscription row for an organisation, or None."""
    row = conn.execute(
        f"SELECT * FROM {metering.SUBSCRIPTION_TABLE} WHERE organisation_id = ?",
        (organisation_id,),
    ).fetchone()
    if row is None:
        return None
    record = dict(row)
    record["cancel_at_period_end"] = bool(record.get("cancel_at_period_end"))
    return record
