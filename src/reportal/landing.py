"""The public marketing page: what reportal is, and what it costs.

Served at ``/pricing`` (and linked from the app shell), this is the one page a
visitor who is not signed in can read.  It is rendered server-side from the
plan catalog rather than written by hand, which is the point: a pricing page
whose numbers are typed into HTML drifts from the code that bills, and the
version that drifts is always the one the customer screenshots.  Every figure
below comes from :mod:`reportal.plans`, so a catalog edit moves the page in the
same commit and ``tests/test_landing.py`` fails the gate if it ever does not.

The markup is a plain string rather than a template engine: reportal has no
templating dependency and this is one page.  It is escaped through
:func:`html.escape` at every interpolation, because a plan name and a feature
line are still text going into HTML even when today's catalog is trusted.
"""

from __future__ import annotations

from html import escape

from reportal import __version__, plans
from reportal import credits as credits_mod

# Caching: the page is derived from code, so it changes only on deploy.  A short
# max-age keeps a proxy from serving a stale price after an upgrade while still
# absorbing a burst.
CACHE_CONTROL = "public, max-age=300"

_STYLE = """
:root {
  color-scheme: dark;
  --bg: #0b0d10;
  --panel: #14181d;
  --line: #262d35;
  --text: #e6edf3;
  --muted: #9aa7b4;
  --accent: #4c9aff;
  --accent-ink: #04121f;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font: 16px/1.6 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
a { color: var(--accent); }
.wrap { max-width: 1080px; margin: 0 auto; padding: 0 24px; }
header { border-bottom: 1px solid var(--line); }
header .wrap { display: flex; align-items: center; justify-content: space-between; height: 64px; }
.brand { font-weight: 700; letter-spacing: -0.02em; font-size: 1.15rem; }
.brand span { color: var(--muted); font-weight: 400; font-size: 0.8rem; margin-left: 8px; }
nav a { margin-left: 20px; text-decoration: none; color: var(--muted); }
nav a:hover, nav a:focus { color: var(--text); }
.hero { padding: 72px 0 48px; text-align: center; }
.hero h1 { font-size: clamp(2rem, 5vw, 3.1rem); line-height: 1.1; margin: 0 0 16px;
  letter-spacing: -0.03em; }
.hero p { font-size: 1.15rem; color: var(--muted); max-width: 62ch; margin: 0 auto 28px; }
.cta { display: inline-block; background: var(--accent); color: var(--accent-ink);
  padding: 12px 22px; border-radius: 8px; text-decoration: none; font-weight: 600; }
.cta.secondary { background: transparent; color: var(--text);
  border: 1px solid var(--line); margin-left: 10px; }
section { padding: 48px 0; border-top: 1px solid var(--line); }
h2 { font-size: 1.6rem; letter-spacing: -0.02em; margin: 0 0 8px; }
.lede { color: var(--muted); margin: 0 0 28px; max-width: 70ch; }
.grid { display: grid; gap: 18px; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 12px;
  padding: 20px; }
.card h3 { margin: 0 0 8px; font-size: 1.05rem; }
.card p { margin: 0; color: var(--muted); font-size: 0.95rem; }
.plans { display: grid; gap: 18px;
  grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); align-items: start; }
.plan { background: var(--panel); border: 1px solid var(--line); border-radius: 12px;
  padding: 22px; display: flex; flex-direction: column; height: 100%; }
.plan.featured { border-color: var(--accent); }
.badge { display: inline-block; font-size: 0.72rem; text-transform: uppercase;
  letter-spacing: 0.08em; color: var(--accent); margin-bottom: 8px; }
.plan h3 { margin: 0 0 4px; font-size: 1.2rem; }
.price { font-size: 2.1rem; font-weight: 700; letter-spacing: -0.03em; margin: 10px 0 2px; }
.price small { font-size: 0.85rem; font-weight: 400; color: var(--muted); }
.tagline { color: var(--muted); font-size: 0.92rem; margin: 0 0 14px; min-height: 2.8em; }
.plan ul { list-style: none; padding: 0; margin: 0 0 18px; }
.plan li { padding: 6px 0; border-top: 1px solid var(--line); font-size: 0.92rem; }
.plan li:first-child { border-top: 0; }
.plan .cta { margin-top: auto; text-align: center; }
table { width: 100%; border-collapse: collapse; font-size: 0.93rem; }
th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--line); }
th { color: var(--muted); font-weight: 600; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.faq h3 { margin: 22px 0 6px; font-size: 1.02rem; }
.faq p { margin: 0; color: var(--muted); }
footer { border-top: 1px solid var(--line); padding: 28px 0 56px; color: var(--muted);
  font-size: 0.88rem; }
"""

_FEATURES: tuple[tuple[str, str], ...] = (
    (
        "Decompile and read",
        (
            "Disassembly, decompilation, cross-references and control-flow graphs over"
            " every function, with a type model and signatures you can edit."
        ),
    ),
    (
        "Match across binaries",
        (
            "Score functions against a corpus, transfer names and signatures, and track"
            " lineage between builds of the same program."
        ),
    ),
    (
        "Triage what matters",
        (
            "Capability tagging, secrets and protocol scans, hardening checks, library"
            " identification and an SBOM export."
        ),
    ),
    (
        "AI where it earns it",
        (
            "Whole-function rewrites, summaries, comments and rename proposals over a"
            " decompilation you already have, scored against real symbols."
        ),
    ),
    (
        "Automate the sweep",
        (
            "Auto workers batch the whole binary, record every write, and revert cleanly"
            " when a run was wrong."
        ),
    ),
    (
        "Answer to an agent",
        (
            "An MCP server exposes the whole portal as tools, so an agent drives the same"
            " surface your analysts do."
        ),
    ),
)


def _credits(plan: plans.Plan) -> str:
    """A plan's monthly credit allowance, as a human reads it."""
    if plan.monthly_credits == plans.UNLIMITED:
        return "Unlimited"
    return f"{plan.monthly_credits:,}"


def _decompilations(plan: plans.Plan) -> str:
    """What the allowance buys in the task customers ask about most."""
    if plan.monthly_credits == plans.UNLIMITED:
        return "Unlimited"
    per = credits_mod.base_credits(credits_mod.TASK_DECOMPILE)
    return f"~{plan.monthly_credits // per:,}"


def _count(value: int) -> str:
    """A limit as text, with the unlimited sentinel spelled out."""
    return "Unlimited" if value == plans.UNLIMITED else f"{value:,}"


def _price(plan: plans.Plan) -> str:
    return "Free" if plan.price_cents == 0 else f"${plan.price_usd:,.0f}"


def _plan_card(plan: plans.Plan, *, featured: bool) -> str:
    """One pricing card, every figure taken from the catalog."""
    items = "".join(f"<li>{escape(line)}</li>" for line in plan.features)
    badge = '<span class="badge">Most popular</span>' if featured else ""
    if plan.self_serve:
        label = "Start free trial" if plan.trial_days else f"Choose {plan.name}"
        href = f"/#/billing?plan={escape(plan.id)}"
        action = f'<a class="cta" href="{href}">{escape(label)}</a>'
    else:
        action = '<a class="cta secondary" href="/#/billing">Get started</a>'
    suffix = "" if plan.price_cents == 0 else f"<small>/{escape(plan.interval)}</small>"
    return (
        f'<article class="plan{" featured" if featured else ""}">'
        f"{badge}"
        f"<h3>{escape(plan.name)}</h3>"
        f'<div class="price">{_price(plan)}{suffix}</div>'
        f'<p class="tagline">{escape(plan.tagline)}</p>'
        f"<ul>{items}</ul>"
        f"{action}"
        "</article>"
    )


def _comparison_table() -> str:
    """The limits side by side, so the tiers can be compared in one read."""
    shown = plans.public_plans()
    head = "".join(f'<th class="num">{escape(plan.name)}</th>' for plan in shown)
    rows: list[tuple[str, list[str]]] = [
        ("Price / month", [_price(plan) for plan in shown]),
        ("Credits / month", [_credits(plan) for plan in shown]),
        ("AI decompilations", [_decompilations(plan) for plan in shown]),
        ("Auto runs / month", [_count(plan.monthly_auto_runs) for plan in shown]),
        ("Binaries", [_count(plan.max_binaries) for plan in shown]),
        ("Seats", [_count(plan.max_seats) for plan in shown]),
        ("API keys", [_count(plan.max_api_keys) for plan in shown]),
        (
            "Overage",
            [
                (
                    "Not available"
                    if plan.price_cents == 0
                    else f"${credits_mod.OVERAGE_USD_PER_CREDIT:.2f}/credit"
                )
                for plan in shown
            ],
        ),
    ]
    body = "".join(
        f'<tr><th scope="row">{escape(label)}</th>'
        + "".join(f'<td class="num">{escape(cell)}</td>' for cell in cells)
        + "</tr>"
        for label, cells in rows
    )
    return (
        '<table><thead><tr><th scope="col">&nbsp;</th>'
        f"{head}</tr></thead><tbody>{body}</tbody></table>"
    )


def _reference_label() -> str:
    """The task one credit is defined as, named from the catalog.

    Derived rather than written into the copy: the reference task is whichever
    operation measures cheapest, and it has already moved once.
    """
    return str(credits_mod.TASK_PROFILES[credits_mod.REFERENCE_TASK].label)


def _task_table() -> str:
    """What each AI task costs, in credits; the price list itself."""
    rows = "".join(
        "<tr>"
        f'<th scope="row">{escape(str(row["label"]))}</th>'
        f"<td>{escape(str(row['describe']))}</td>"
        f'<td class="num">{row["credits"]}'
        f"{' / function' if row['per_function'] else ''}</td>"
        "</tr>"
        for row in credits_mod.catalog()
    )
    return (
        "<table><thead><tr>"
        '<th scope="col">Task</th><th scope="col">What you get</th>'
        '<th scope="col" class="num">Credits</th>'
        f"</tr></thead><tbody>{rows}</tbody></table>"
    )


def _faq() -> str:
    """The questions the pricing model actually raises, answered plainly."""
    reference = credits_mod.TASK_PROFILES[credits_mod.REFERENCE_TASK]
    credit_answer = (
        f"One credit is one {_reference_label().lower()}, the cheapest thing the"
        " portal does. Every other task is priced against it and published above,"
        " measured rather than estimated, so you can count what a job costs before"
        " you run it rather than after."
    )
    size_answer = (
        "Larger functions cost more, in bands rather than by the token. A normal"
        f" function is the base price, one over ~{credits_mod.SIZE_BANDS[0][1]:,} tokens"
        " of input costs double, and a very large one costs four times. The band is"
        " decided before the call, so nothing surprises you afterwards."
    )
    overage_answer = (
        "A paid plan keeps working and extra credits are billed at"
        f" ${credits_mod.OVERAGE_USD_PER_CREDIT:.2f} each. The free plan stops at its"
        " allowance rather than charging you unexpectedly."
    )
    static_answer = (
        "No. Disassembly, decompilation, cross-references, matching and every scan are"
        " unmetered on every plan. Only the AI tasks above and auto runs cost credits,"
        " because only those spend inference."
    )
    failure_answer = (
        "Nothing. A credit is charged after a task returns a result, so a failed or"
        " refused request costs you nothing."
    )
    own_key_answer = (
        "Yes. Point the bridge at your own endpoint and your inference is your own:"
        " credit allowances stop applying, because we are not paying for it."
    )
    self_host_answer = (
        "Yes. reportal is a self-hosted portal first. A self-hosted install has no"
        " tenant and is unmetered by construction."
    )
    privacy_answer = (
        "Only when you configure it to. There is no telemetry, no sample upload and no"
        " network call until you set an AI endpoint or name a URL to fetch."
    )
    entries: tuple[tuple[str, str], ...] = (
        ("What is a credit?", credit_answer),
        ("Does a big function cost more?", size_answer),
        ("What happens when I run out?", overage_answer),
        ("Is static analysis metered?", static_answer),
        ("What if a task fails?", failure_answer),
        ("Can I use my own model key?", own_key_answer),
        ("Can I self-host?", self_host_answer),
        ("Does my data leave the install?", privacy_answer),
    )
    del reference
    return "".join(
        f"<h3>{escape(question)}</h3><p>{escape(answer)}</p>" for question, answer in entries
    )


def render() -> str:
    """The whole marketing page as one HTML document."""
    catalog = plans.public_plans()
    # The featured tier is the middle paid one: the recommendation is derived
    # from the catalog's own ordering rather than pinned to a plan id that a
    # later edit could rename out from under it.
    purchasable = [plan for plan in catalog if plan.self_serve]
    featured = purchasable[len(purchasable) // 2].id if purchasable else ""
    cards = "".join(_plan_card(plan, featured=plan.id == featured) for plan in catalog)
    features = "".join(
        f'<article class="card"><h3>{escape(title)}</h3><p>{escape(body)}</p></article>'
        for title, body in _FEATURES
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>reportal pricing: a reverse-engineering workbench</title>
<meta name="description" content="reportal is a reverse-engineering portal: decompile,
 match, triage and automate. Plans from free to enterprise, priced on real inference cost.">
<link rel="icon" href="/static/favicon.svg" type="image/svg+xml">
<style>{_STYLE}</style>
</head>
<body>
<header><div class="wrap">
  <div class="brand">reportal <span>v{escape(__version__)}</span></div>
  <nav>
    <a href="#features">Features</a>
    <a href="#pricing">Pricing</a>
    <a href="#credits">Credits</a>
    <a href="#faq">FAQ</a>
    <a href="/">Open the app</a>
  </nav>
</div></header>

<main>
<div class="wrap">
  <div class="hero">
    <h1>Reverse engineering, end to end.</h1>
    <p>Decompile a binary, match its functions against everything you have seen before,
       triage what matters and let an agent drive the sweep. Self-hosted, scriptable,
       and metered only where it actually spends inference.</p>
    <a class="cta" href="/#/billing">Start free</a>
    <a class="cta secondary" href="#pricing">See pricing</a>
  </div>
</div>

<section id="features"><div class="wrap">
  <h2>What it does</h2>
  <p class="lede">One portal over the whole workflow, from the first byte to the report.</p>
  <div class="grid">{features}</div>
</div></section>

<section id="pricing"><div class="wrap">
  <h2>Pricing</h2>
  <p class="lede">Static analysis is unmetered on every plan. Credits cover the AI
     tasks, priced on what the inference actually costs us, so the numbers are
     sustainable rather than promotional.</p>
  <div class="plans">{cards}</div>
</div></section>

<section id="credits"><div class="wrap">
  <h2>What a task costs</h2>
  <p class="lede">One credit is one {_reference_label().lower()}. Everything else is
     priced against it from measured token use, so you can count the cost of a job
     before you run it. A larger function costs more, in bands rather than by the
     token.</p>
  {_task_table()}
</div></section>

<section><div class="wrap">
  <h2>Compare</h2>
  <p class="lede">Every limit, side by side.</p>
  {_comparison_table()}
</div></section>

<section id="faq" class="faq"><div class="wrap">
  <h2>Questions</h2>
  {_faq()}
</div></section>
</main>

<footer><div class="wrap">
  reportal v{escape(__version__)}. Self-hosted reverse-engineering portal.
  <a href="/">Open the app</a>.
</div></footer>
</body>
</html>
"""
