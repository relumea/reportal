# Tenancy, credits and billing

Sources: src/reportal/plans.py, src/reportal/credits.py, src/reportal/metering.py, src/reportal/billing.py, src/reportal/model_rates.py

Four modules split by what each may know: `credits.py` is the price list, `plans.py` the catalog,
`metering.py` the ledger and the quota, `billing.py` the provider integration. Nothing above them
knows a price and nothing below them knows a customer. The unit a tenant spends is the credit;
tokens stay in the ledger as the internal cost read.

## Vocabulary

- `plans.Plan`: `id`, `name`, `tagline`, `price_cents`, `monthly_credits`, `monthly_auto_runs`,
  `max_binaries`, `max_api_keys`, `max_seats` and `features`. `UNLIMITED` is `-1`, and
  `plan_for_price_id` maps a charged Stripe price back to a plan.
- `credits.TaskProfile`: `name`, `label`, `describe`, `input_tokens`, `visible_tokens`,
  `thinking_ratio` and `per_function`. `TASK_PROFILES` is the billable table, `REFERENCE_TASK`
  defines one credit, `SIZE_BANDS` prices a large input, and `credit_cogs_usd` prices a credit.
- `metering.CUSTOMER_KINDS` (`credits`, `auto_run`) is what a quota and the usage panel show;
  `KINDS` adds `llm_tokens`. `quota_check` returns the whole state (limit, used, remaining,
  overage, reason), not a bool.
- `billing.BillingEvent` is the normalized provider event with `entitles()`; `CheckoutSession`,
  `PortalSession` and `ReconcileResult` are the other value types.

## Wiring

- Routes: `GET /api/plans`, `GET /api/organisations/{organisation_id}/usage`,
  `PUT /api/organisations/{organisation_id}/plan`, and the billing paths: `GET`/`PUT .../billing`,
  `POST .../billing/checkout`, `POST .../billing/portal`, `POST .../billing/sync`,
  `POST /api/billing/manual/confirm`, `POST .../billing/cancel-manual`, `POST /api/billing/webhook`.
- CLI: `organisations`, `organisation-add`, `organisation-rm`. MCP: `list_organisations`,
  `create_organisation`, `delete_organisation`.
- Tables: `usage_events`, `subscriptions`, `billing_events` and `organisations`
  (`auth.ORG_TABLE`), which carries `plan_id`, `period_started_at` and `status`.
  `metering.ensure_schema` runs from `auth`.
- Settings: `REPORTAL_BILLING_PROVIDER`, `REPORTAL_STRIPE_SECRET_KEY`,
  `REPORTAL_STRIPE_WEBHOOK_SECRET`, `REPORTAL_STRIPE_API_VERSION`, `REPORTAL_PUBLIC_BASE_URL` and
  the per-plan `REPORTAL_STRIPE_PRICE_*` ids.

## Invariants

- One credit is the cheapest real task, and no task is sold below cost; price order follows cost
  order (`tests/test_credits.py`).
- A paid tier may spend at most `MAX_COGS_SHARE` of its price on inference, and the free tier is
  bounded by `MAX_FREE_COGS_USD` (`tests/test_plans.py`).
- `usage_events` is append-only: `record_usage` inserts and there is no update or delete path
  (`tests/test_metering.py`).
- A workspace with no organisation row reads as the `internal` plan and is unmetered, so an
  upgrade never locks out an existing operator (`tests/test_metering.py`).
- `BillingEvent.entitles()` requires `payment_status == "paid"` or an entitling subscription
  status, never the completion event alone (`tests/test_billing.py`).
- A webhook is applied in the same transaction that claims its event id, so a redelivery answers
  `duplicate` and grants nothing twice (`tests/test_billing.py`).
- A subscription's plan comes from `plan_for_price_id`, never from checkout metadata
  (`tests/test_billing.py`).

## See also

- [ARCHITECTURE.md: Plans and billing](../ARCHITECTURE.md#plans-credits-metering-and-billing)
- [DATA_MODEL.md](../DATA_MODEL.md)
- [CONFIG.md](../CONFIG.md)
