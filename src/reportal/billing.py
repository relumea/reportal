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

The invariants this module is built around, each of which is a way a
billing integration loses money or double-charges if it is skipped:

**Completion is not payment.**  ``checkout.session.completed`` fires when the
customer finishes the form, not when the charge settles.  Entitlement is
granted on ``payment_status == "paid"`` (or an entitling subscription status),
never on the completion event alone.

**Webhooks are idempotent.**  Stripe redelivers, so every event id is claimed
in ``billing_events`` inside the same transaction that applies it.  A
redelivery finds the row and answers ``duplicate`` without touching the
subscription.

**Outbound Stripe writes share one Idempotency-Key.**  Checkout and portal
POSTs derive the key from the logical operation and a short time bucket, and
transport retries reuse that same key, so a timeout after Stripe already
applied the write cannot open a second session.  Manual checkout reuses the
live token for the same organisation and plan for the same reason.

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
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx2 as httpx

from reportal import auth, metering, plans

_log = logging.getLogger("reportal")

# Entropy source for manual checkout tokens.  A test patches ``_token_urlsafe``
# to pin the key a checkout records.  Stripe writes use
# :func:`_stripe_idempotency_key` instead: a fresh token per HTTP attempt would
# make every retry look new and open a second Checkout session.
_token_urlsafe = secrets.token_urlsafe

# Wall and monotonic clocks.  A test patches ``_wall_time`` to pin webhook age
# and idempotency buckets, and ``_monotonic`` to pin manual-intent TTLs and the
# reconcile rate window, so a failing run replays without freezing the process.
_wall_time = time.time
_monotonic = time.monotonic

STRIPE_API_BASE = "https://api.stripe.com/v1"
DEFAULT_STRIPE_API_VERSION = "2026-08-26.dahlia"

# How far a webhook timestamp may be from now before the signature is stale.
# Five minutes is Stripe's own recommendation: long enough for a slow delivery,
# short enough that a captured body cannot be replayed indefinitely.
WEBHOOK_TOLERANCE_S = 300
_REQUEST_TIMEOUT_S = 20.0
# Stripe retains Idempotency-Key values for 24 hours.  This window is shorter:
# a double-click or a timeout retry inside it shares one key, and a deliberate
# later checkout gets a fresh session.  The key itself is not stored locally.
IDEMPOTENCY_WINDOW_S = 300
# Transient transport failures only: the same Idempotency-Key is reused so a
# timeout after Stripe already applied the write cannot create a second object.
_STRIPE_TRANSIENT_ATTEMPTS = 3

PROVIDER_ENV = "REPORTAL_BILLING_PROVIDER"
STRIPE_SECRET_ENV = "REPORTAL_STRIPE_SECRET_KEY"
STRIPE_WEBHOOK_ENV = "REPORTAL_STRIPE_WEBHOOK_SECRET"
STRIPE_API_VERSION_ENV = "REPORTAL_STRIPE_API_VERSION"
PUBLIC_BASE_URL_ENV = "REPORTAL_PUBLIC_BASE_URL"
DEFAULT_PUBLIC_BASE_URL = "http://127.0.0.1:8002"

PROVIDER_STRIPE = "stripe"
PROVIDER_MANUAL = "manual"
PROVIDER_DISABLED = "disabled"
PROVIDER_AUTO = "auto"
PROVIDERS: frozenset[str] = frozenset(
    {PROVIDER_AUTO, PROVIDER_STRIPE, PROVIDER_MANUAL, PROVIDER_DISABLED}
)


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
    configured = os.environ.get(PROVIDER_ENV, "").strip().lower() or PROVIDER_AUTO
    if configured == PROVIDER_AUTO:
        return PROVIDER_STRIPE if _secret_key() else PROVIDER_DISABLED
    if configured in {PROVIDER_STRIPE, PROVIDER_MANUAL, PROVIDER_DISABLED}:
        return configured
    _log.warning("unknown %s %r; billing disabled", PROVIDER_ENV, configured)
    return PROVIDER_DISABLED


def configured_provider() -> str:
    """The raw provider spelling before ``auto`` resolves, or ``auto`` when unset."""
    return os.environ.get(PROVIDER_ENV, "").strip().lower() or PROVIDER_AUTO


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


def public_base_url() -> str:
    """The externally reachable base URL checkout returns the customer to."""
    return os.environ.get(PUBLIC_BASE_URL_ENV, "").strip().rstrip("/") or DEFAULT_PUBLIC_BASE_URL


def _public_base_url() -> str:
    """Compatibility alias for callers that still use the private name."""
    return public_base_url()


def _checkout_urls(organisation_id: int) -> tuple[str, str]:
    """The success and cancel URLs a checkout returns the customer to."""
    base = _public_base_url()
    return (
        f"{base}/#/billing?organisation={organisation_id}&checkout=success",
        f"{base}/#/billing?organisation={organisation_id}&checkout=cancel",
    )


# ── Stripe REST ────────────────────────────────────────────────────


def _idempotency_bucket(now: float | None = None) -> int:
    """Floor *now* into an :data:`IDEMPOTENCY_WINDOW_S` slot."""
    return int((_wall_time() if now is None else now) // IDEMPOTENCY_WINDOW_S)


def _stripe_idempotency_key(kind: str, *parts: object, now: float | None = None) -> str:
    """A key stable for one logical Stripe write inside the idempotency window.

    Stripe deduplicates POSTs that share this header.  The key is derived from
    the operation (checkout vs portal), its natural inputs, and the current
    time bucket — never from a fresh random token — so a double-click and a
    transport retry of the same logical write cannot open a second session.
    """
    joined = "-".join(str(part).replace(":", "") for part in parts)
    return f"reportal-{kind}-{joined}-{_idempotency_bucket(now)}"


def _stripe_request(path: str, form: dict[str, str], *, idempotency_key: str) -> dict[str, Any]:
    """POST a form-encoded body to Stripe and return the parsed object.

    *idempotency_key* is required and is sent on every attempt of this call.
    A timeout after Stripe already applied the write then returns the first
    object rather than creating a second Checkout or Portal session.
    """
    key = _secret_key()
    if not key:
        raise BillingError(503, "billing-unconfigured")
    headers = {
        "Authorization": f"Bearer {key}",
        "Stripe-Version": api_version(),
        "Content-Type": "application/x-www-form-urlencoded",
        "Idempotency-Key": idempotency_key,
    }
    last_exc: httpx.HTTPError | None = None
    for _attempt in range(_STRIPE_TRANSIENT_ATTEMPTS):
        try:
            with httpx.Client(timeout=_REQUEST_TIMEOUT_S) as client:
                response = client.post(f"{STRIPE_API_BASE}{path}", data=form, headers=headers)
                try:
                    payload = response.json()
                except ValueError as exc:
                    raise BillingError(502, "billing provider returned a non-JSON body") from exc
                if response.status_code >= 400:
                    message = (
                        str(payload.get("error", {}).get("message", ""))
                        or "provider rejected the call"
                    )
                    raise BillingError(502, f"billing provider error: {message}")
                return dict(payload)
        except (httpx.TimeoutException, httpx.ConnectError) as exc:
            last_exc = exc
            continue
        except httpx.HTTPError as exc:
            raise BillingError(502, f"billing provider unreachable: {exc}") from exc
    raise BillingError(502, f"billing provider unreachable: {last_exc}") from last_exc


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
    payload = _stripe_request(
        "/checkout/sessions",
        form,
        idempotency_key=_stripe_idempotency_key("checkout", organisation_id, plan.id),
    )
    url = str(payload.get("url") or "")
    if not url:
        raise BillingError(502, "provider returned no checkout URL")
    return CheckoutSession(PROVIDER_STRIPE, str(payload.get("id") or ""), url)


# ── Manual mode ────────────────────────────────────────────────────

# Manual checkout intents, in memory: a development mode grants a plan through
# an operator confirmation and nothing is persisted, so a restart clears them.
# Cap the map so a caller that opens many checkouts within the TTL cannot grow
# it without bound; past the cap the oldest token is dropped (spent as expired).
# The map is shared across the ASGI thread pool, so every read-modify-write goes
# under ``_manual_intents_lock``; spending a token is a single pop under that
# lock so two concurrent confirms cannot both grant.
_manual_intents: dict[str, tuple[int, str, float]] = {}
_manual_intents_lock = threading.Lock()
_MANUAL_INTENT_TTL_S = 900.0
MAX_MANUAL_INTENTS = 256


def _store_manual_intent(organisation_id: int, plan_id: str) -> str:
    """Record a pending manual grant and return its one-time token.

    A second call for the same organisation and plan while the first token is
    still live returns that token: a double-click must not mint a second grant
    the operator can confirm after the first already entitled the tenant.
    """
    now = _monotonic()
    with _manual_intents_lock:
        for token, (org, plan, expires) in list(_manual_intents.items()):
            if expires <= now:
                _manual_intents.pop(token, None)
                continue
            if org == organisation_id and plan == plan_id:
                return token
        token = _token_urlsafe(24)
        _manual_intents[token] = (organisation_id, plan_id, now + _MANUAL_INTENT_TTL_S)
        while len(_manual_intents) > MAX_MANUAL_INTENTS:
            _manual_intents.pop(next(iter(_manual_intents)))
        return token


def manual_intent(token: str) -> tuple[int, str] | None:
    """The organisation and plan a manual token names, or None when it is spent."""
    with _manual_intents_lock:
        entry = _manual_intents.get(token)
        if entry is None:
            return None
        organisation_id, plan_id, expires = entry
        if expires <= _monotonic():
            _manual_intents.pop(token, None)
            return None
        return organisation_id, plan_id


def _take_manual_intent(token: str, organisation_id: int) -> str | None:
    """Consume a live manual token for *organisation_id*; None when it cannot grant.

    The check and the pop share ``_manual_intents_lock``, so at most one
    concurrent confirm wins.  A token that names another organisation is left
    in place so the rightful tenant can still confirm it.
    """
    with _manual_intents_lock:
        entry = _manual_intents.get(token)
        if entry is None:
            return None
        intent_org, plan_id, expires = entry
        if expires <= _monotonic():
            _manual_intents.pop(token, None)
            return None
        if intent_org != organisation_id:
            return None
        _manual_intents.pop(token, None)
        return plan_id


def _restore_manual_intent(token: str, organisation_id: int, plan_id: str) -> None:
    """Put a spent token back after a failed durable write."""
    with _manual_intents_lock:
        _manual_intents[token] = (
            organisation_id,
            plan_id,
            _monotonic() + _MANUAL_INTENT_TTL_S,
        )
        while len(_manual_intents) > MAX_MANUAL_INTENTS:
            _manual_intents.pop(next(iter(_manual_intents)))


def complete_manual_checkout(
    conn: sqlite3.Connection, token: str, organisation_id: int
) -> dict[str, Any]:
    """Grant the plan a manual token names; the token is spent either way."""
    plan_id = _take_manual_intent(token, organisation_id)
    if plan_id is None:
        raise BillingError(400, "unknown or expired checkout token")
    plan = plans.get_plan(plan_id)
    try:
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
        # The in-memory token is already spent; the entitlement must land before
        # this connection closes or a crash leaves a spent token and no plan.
        conn.commit()
    except Exception:
        _restore_manual_intent(token, organisation_id, plan_id)
        raise
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
    conn.commit()
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
        idempotency_key=_stripe_idempotency_key("portal", organisation_id, customer),
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
        age = abs(_wall_time() - int(timestamp))
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


def _event_audit_payload(event: BillingEvent, organisation_id: int | None) -> dict[str, Any]:
    """Operational snapshot for the event ledger; never Stripe customer PII.

    The raw provider event can carry ``customer_details.email``, a billing
    address and similar fields.  Entitlement already extracted the ids and
    status it needs, so the ledger only keeps those.
    """
    return {
        "event_id": event.event_id,
        "kind": event.kind,
        "organisation_id": organisation_id,
        "customer_id": event.customer_id,
        "subscription_id": event.subscription_id,
        "status": event.status,
        "plan_id": event.plan_id,
        "payment_status": event.payment_status,
        "cancel_at_period_end": event.cancel_at_period_end,
        "current_period_end": event.current_period_end,
    }


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
                json.dumps(_event_audit_payload(event, organisation_id))[:20000],
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
    """Mirror the provider's subscription state and set the entitled plan.

    The quota window restarts only when entitlement begins or the provider's
    billing period advances.  A mid-period status or plan mirror must not wipe
    usage; that would hand the tenant a fresh allowance on every webhook.
    """
    previous = conn.execute(
        f"SELECT current_period_end FROM {metering.SUBSCRIPTION_TABLE} WHERE organisation_id = ?",
        (organisation_id,),
    ).fetchone()
    previous_end = str(previous["current_period_end"] or "") if previous is not None else ""
    org = conn.execute(
        f"SELECT period_started_at FROM {auth.ORG_TABLE} WHERE id = ?",
        (organisation_id,),
    ).fetchone()
    started = str(org["period_started_at"] or "") if org is not None else ""
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
    # Entitled and canceled keep the org active (canceled falls to the free
    # tier).  Every other status, including unpaid/incomplete and anything the
    # provider invents later, fails closed as past_due so quota does not stay
    # open while the subscription is not good.
    org_status = (
        metering.STATUS_ACTIVE
        if entitled or status == metering.STATUS_CANCELED
        else metering.STATUS_PAST_DUE
    )
    period_advanced = bool(current_period_end) and current_period_end != previous_end
    restart = entitled and (not started or period_advanced)
    if restart:
        conn.execute(
            f"UPDATE {auth.ORG_TABLE} SET plan_id = ?, status = ?, period_started_at = ? "
            "WHERE id = ?",
            (target, org_status, auth.now(), organisation_id),
        )
    else:
        conn.execute(
            f"UPDATE {auth.ORG_TABLE} SET plan_id = ?, status = ? WHERE id = ?",
            (target, org_status, organisation_id),
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
# Shared across the ASGI thread pool; compound check-and-append under the lock.
# Cap distinct organisation keys so a scan of every tenant cannot grow the map
# for the whole window; past the cap the oldest organisation is dropped.
_rate_states: dict[int, list[float]] = {}
_rate_states_lock = threading.Lock()
_RECONCILE_WINDOW_S = 60.0
_RECONCILE_MAX_HITS = 3
MAX_RECONCILE_ORGS = 1024


def reconcile_allowed(organisation_id: int) -> bool:
    """Whether the organisation may reconcile again inside the window.

    An organisation whose window has emptied is dropped rather than left as a
    permanent key.  Distinct live organisations are also capped at
    :data:`MAX_RECONCILE_ORGS`.
    """
    now = _monotonic()
    with _rate_states_lock:
        for other, hits in list(_rate_states.items()):
            if all(now - hit >= _RECONCILE_WINDOW_S for hit in hits):
                del _rate_states[other]
        hits = [
            hit for hit in _rate_states.get(organisation_id, []) if now - hit < _RECONCILE_WINDOW_S
        ]
        if len(hits) >= _RECONCILE_MAX_HITS:
            _rate_states[organisation_id] = hits
            return False
        hits.append(now)
        _rate_states[organisation_id] = hits
        while len(_rate_states) > MAX_RECONCILE_ORGS:
            _rate_states.pop(next(iter(_rate_states)))
        return True


def reconcile_retry_after(organisation_id: int) -> int:
    """Seconds until *organisation_id* may reconcile again."""
    now = _monotonic()
    with _rate_states_lock:
        return auth.retry_after_seconds(
            _rate_states.get(organisation_id, []), _RECONCILE_WINDOW_S, now
        )


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
        with httpx.Client(timeout=_REQUEST_TIMEOUT_S) as client:
            response = client.get(
                f"{STRIPE_API_BASE}/subscriptions/{subscription_id}",
                headers={"Authorization": f"Bearer {key}", "Stripe-Version": api_version()},
            )
            try:
                payload = dict(response.json())
            except ValueError as exc:
                raise BillingError(502, f"billing provider unreachable: {exc}") from exc
            if response.status_code >= 400:
                raise BillingError(502, "provider rejected the subscription read")
    except httpx.HTTPError as exc:
        raise BillingError(502, f"billing provider unreachable: {exc}") from exc
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
    """The mirrored subscription row for an organisation, or None.

    Internal callers (portal, reconcile) need ``customer_id`` and
    ``subscription_id``.  Tenant-facing responses use
    :func:`public_subscription` so those provider ids stay off the wire.
    """
    row = conn.execute(
        f"SELECT * FROM {metering.SUBSCRIPTION_TABLE} WHERE organisation_id = ?",
        (organisation_id,),
    ).fetchone()
    if row is None:
        return None
    record = dict(row)
    record["cancel_at_period_end"] = bool(record.get("cancel_at_period_end"))
    return record


def public_subscription(conn: sqlite3.Connection, organisation_id: int) -> dict[str, Any] | None:
    """Subscription state safe for any organisation member: no provider ids.

    Stripe ``customer_id`` / ``subscription_id`` identify the payer; they stay
    server-side for portal and reconcile.  Members see status and period only.
    """
    record = subscription_of(conn, organisation_id)
    if record is None:
        return None
    return {
        "organisation_id": record["organisation_id"],
        "provider": record["provider"],
        "status": record["status"],
        "current_period_end": record["current_period_end"],
        "cancel_at_period_end": record["cancel_at_period_end"],
        "updated_at": record["updated_at"],
    }
