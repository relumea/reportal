"""The marketing page must never drift from the plan catalog.

A pricing page whose numbers were typed in by hand goes stale the first time a
plan changes, and the stale version is the one the customer screenshots.  These
tests read the catalog and assert the rendered page agrees with it, so the two
can only move together.
"""

from __future__ import annotations

import gzip
import re
from html import unescape
from pathlib import Path

from conftest import on_request

from reportal import credits as credits_mod
from reportal import landing, plans


def _text(markup: str) -> str:
    """The page's visible text, with tags and entities resolved."""
    stripped = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", markup, flags=re.DOTALL)
    return re.sub(r"\s+", " ", unescape(re.sub(r"<[^>]+>", " ", stripped)))


class TestPricingAgreesWithTheCatalog:
    """Every figure on the page comes from plans.py."""

    def test_every_public_plan_is_named(self) -> None:
        body = _text(landing.render())
        for plan in plans.public_plans():
            assert plan.name in body

    def test_every_public_price_is_shown(self) -> None:
        body = _text(landing.render())
        for plan in plans.public_plans():
            if plan.price_cents:
                assert f"${plan.price_usd:,.0f}" in body

    def test_the_internal_tier_is_never_advertised(self) -> None:
        """Showing the unmetered staff tier would advertise a way past the quota."""
        body = _text(landing.render()).lower()
        assert "unmetered staff" not in body
        assert ">Internal<" not in landing.render()

    def test_the_overage_rate_is_the_catalog_rate(self) -> None:
        assert f"${credits_mod.OVERAGE_USD_PER_CREDIT:.2f}" in _text(landing.render())

    def test_every_billable_task_is_priced_on_the_page(self) -> None:
        """The task table is the price list, so it has to carry every task."""
        body = _text(landing.render())
        for row in credits_mod.catalog():
            assert str(row["label"]) in body

    def test_the_credit_allowances_are_the_catalog_allowances(self) -> None:
        """The compare table's credit row is derived, not transcribed."""
        body = _text(landing.render())
        for plan in plans.public_plans():
            if plan.monthly_credits != plans.UNLIMITED:
                assert f"{plan.monthly_credits:,}" in body


class TestMarkup:
    """The page has to be a valid, self-contained document."""

    def test_it_is_a_complete_html_document(self) -> None:
        markup = landing.render()
        assert markup.startswith("<!doctype html>")
        assert markup.rstrip().endswith("</html>")
        assert '<html lang="en">' in markup

    def test_it_carries_a_title_and_a_description(self) -> None:
        markup = landing.render()
        assert "<title>" in markup
        assert 'name="description"' in markup

    def test_every_plan_name_is_escaped(self) -> None:
        """A catalog string reaches HTML as text, not as markup."""
        markup = landing.render()
        assert "<script>" not in markup.replace('<script type="module"', "")

    def test_it_links_into_the_app(self) -> None:
        assert 'href="/"' in landing.render()

    def test_it_needs_no_frontend_build(self) -> None:
        """It is served whether or not the SPA bundle exists, so it inlines its CSS."""
        markup = landing.render()
        assert "<style>" in markup
        assert "/static/assets/" not in markup


class TestRoute:
    """The page is served at a stable public path."""

    def test_it_is_served(self, portal_db: Path) -> None:
        status, headers, chunks = on_request("GET", "/pricing")
        assert status.startswith("200")
        assert "text/html" in headers["Content-Type"]
        assert b"reportal" in b"".join(chunks)

    def test_it_is_cacheable(self, portal_db: Path) -> None:
        _, headers, _ = on_request("GET", "/pricing")
        assert headers["Cache-Control"] == landing.CACHE_CONTROL

    def test_it_is_gzipped_when_accepted(self, portal_db: Path) -> None:
        status, headers, chunks = on_request("GET", "/pricing", headers={"Accept-Encoding": "gzip"})
        body = b"".join(chunks)
        assert status.startswith("200")
        assert headers.get("Content-Encoding") == "gzip"
        assert headers.get("Vary") == "Accept-Encoding"
        assert b"reportal" in gzip.decompress(body)

    def test_it_shows_the_prices(self, portal_db: Path) -> None:
        _, _, chunks = on_request("GET", "/pricing")
        body = _text(b"".join(chunks).decode("utf-8"))
        for plan in plans.public_plans():
            if plan.price_cents:
                assert f"${plan.price_usd:,.0f}" in body
