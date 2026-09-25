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

# The relumea brand (BRAND.md in the parent repository), the same tokens the SPA's
# light theme carries: near-white ground, one verdict-green accent, hairlines,
# Archivo for text and JetBrains Mono for figures only, both served from the
# SPA's public fonts at /static/fonts/.
_STYLE = """
@font-face {
  font-family: "Archivo"; src: url("/static/fonts/archivo.woff2") format("woff2");
  font-weight: 100 900; font-style: normal; font-display: swap;
}
@font-face {
  font-family: "JetBrains Mono"; src: url("/static/fonts/jetbrains-mono.woff2") format("woff2");
  font-weight: 400 700; font-style: normal; font-display: swap;
}
:root {
  color-scheme: light;
  --bg: #fafafa;
  --surface: #ffffff;
  --surface-2: #f5f6f8;
  --border: #e7e8ec;
  --border-strong: #d5d8de;
  --text: #0a0a0b;
  --muted: #55585f;
  --faint: #6b7078;
  --accent: #0f7a42;
  --accent-hover: #0b6234;
  --accent-ink: #ffffff;
  --accent-soft: #eaf5ef;
  --font-sans: "Archivo", system-ui, sans-serif;
  --font-mono: "JetBrains Mono", ui-monospace, Menlo, Consolas, monospace;
  --radius-card: 14px;
  --radius-control: 9px;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font: 15px/1.55 var(--font-sans);
}
a { color: var(--accent); }
a:hover, a:focus-visible { color: var(--accent-hover); }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.wrap { max-width: 1120px; margin: 0 auto; padding: 0 24px; }
header { border-bottom: 1px solid var(--border); background: var(--surface); }
header .wrap {
  display: flex; align-items: center; justify-content: space-between;
  min-height: 56px; gap: 16px; flex-wrap: wrap; padding-top: 10px; padding-bottom: 10px;
}
.brand {
  display: inline-flex; align-items: center; gap: 8px;
  font-weight: 700; font-size: 18px; letter-spacing: -0.03em; color: var(--text);
  text-decoration: none;
}
.brand-mark { display: inline-flex; flex: none; width: 20px; height: 20px; color: var(--text); }
.brand-mark svg { display: block; width: 100%; height: 100%; }
.brand-mark-ink { fill: currentColor; }
.brand-mark-cell { fill: var(--accent); }
.brand-mark-off { fill: var(--border-strong); }
.brand-ver {
  font-family: var(--font-mono); font-size: 12px; font-weight: 400; color: var(--faint);
  letter-spacing: 0;
}
nav { display: flex; flex-wrap: wrap; gap: 4px 20px; }
nav a { text-decoration: none; color: var(--muted); font-size: 14px; }
nav a:hover, nav a:focus-visible { color: var(--text); }
.hero {
  padding: 56px 0 40px;
  display: grid; gap: 28px;
  grid-template-columns: minmax(0, 1.5fr) minmax(220px, 0.65fr);
  align-items: end;
}
.hero h1 {
  font-size: clamp(2rem, 4vw, 2.75rem); line-height: 1.08;
  margin: 0 0 14px; font-weight: 700; letter-spacing: -0.028em; max-width: 20ch;
  text-wrap: balance;
}
.hero p { font-size: 18px; color: var(--muted); max-width: 58ch; margin: 0 0 22px; }
.hero-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 12px 18px; }
.cta {
  display: inline-block; background: var(--text); color: var(--bg);
  padding: 10px 18px; border-radius: var(--radius-control); text-decoration: none;
  font-weight: 600; font-size: 14px; border: 1px solid var(--text);
}
.cta:hover, .cta:focus-visible { background: #26262a; border-color: #26262a; color: var(--bg); }
.cta.secondary {
  background: var(--surface); color: var(--text); border-color: var(--border-strong);
}
.cta.secondary:hover, .cta.secondary:focus-visible {
  border-color: var(--text); color: var(--text); background: var(--surface);
}
.link-quiet { color: var(--muted); text-decoration: none; font-size: 14px; }
.link-quiet:hover, .link-quiet:focus-visible { color: var(--text); }
.hero-aside {
  border: 1px solid var(--border); background: var(--surface);
  border-radius: var(--radius-card); padding: 16px 18px; font-size: 14px;
  color: var(--muted); line-height: 1.6;
}
.hero-aside strong { color: var(--text); font-weight: 600; display: block; margin-bottom: 4px; }
section { padding: 48px 0; border-top: 1px solid var(--border); }
h2 {
  font-size: 26px; margin: 0 0 8px; font-weight: 700; letter-spacing: -0.025em;
  line-height: 1.14;
}
.lede { color: var(--muted); margin: 0 0 24px; max-width: 70ch; font-size: 16px; }
.features {
  display: flex; flex-direction: column; gap: 0;
  border: 1px solid var(--border); border-radius: var(--radius-card);
  background: var(--surface); overflow: hidden;
}
.feature {
  display: grid; grid-template-columns: minmax(9rem, 13rem) minmax(0, 1fr);
  gap: 12px 18px; align-items: baseline;
  padding: 14px 18px; border-top: 1px solid var(--border);
}
.feature:first-child { border-top: 0; }
.feature h3 { margin: 0; font-size: 15px; font-weight: 600; color: var(--text); }
.feature p { margin: 0; color: var(--muted); font-size: 14px; line-height: 1.55; }
.plans { display: grid; gap: 16px;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); align-items: start; }
.plan {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--radius-card); padding: 20px; display: flex; flex-direction: column;
  height: 100%;
}
.plan.featured { border-color: var(--accent); }
.plan h3 { margin: 0 0 2px; font-size: 17px; font-weight: 700; letter-spacing: -0.01em; }
.price {
  font-size: 32px; font-weight: 700; margin: 10px 0 2px; letter-spacing: -0.02em;
  font-variant-numeric: tabular-nums;
}
.price small { font-size: 13px; font-weight: 400; color: var(--muted); letter-spacing: 0; }
.tagline { color: var(--muted); font-size: 14px; margin: 0 0 14px; min-height: 2.8em; }
.plan ul { list-style: none; padding: 0; margin: 0 0 18px; }
.plan li { padding: 7px 0; border-top: 1px solid var(--border); font-size: 14px; }
.plan li:first-child { border-top: 0; }
.plan .cta { margin-top: auto; text-align: center; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); }
th {
  color: var(--faint); font-weight: 600; font-size: 12px; text-transform: uppercase;
  letter-spacing: 0.06em;
}
td.num, th.num {
  text-align: right; font-variant-numeric: tabular-nums;
}
td.num { font-family: var(--font-mono); font-size: 13px; }
.faq h3 { margin: 22px 0 6px; font-size: 16px; font-weight: 600; }
.faq p { margin: 0; color: var(--muted); max-width: 72ch; }
footer {
  border-top: 1px solid var(--border); padding: 24px 0 48px; color: var(--faint);
  font-size: 13px;
}
@media (max-width: 720px) {
  .hero { grid-template-columns: 1fr; }
  .feature { grid-template-columns: 1fr; gap: 4px; }
}
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
            "An MCP server exposes the whole workspace as tools, so an agent drives the same"
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
    if plan.self_serve:
        label = "Start free trial" if plan.trial_days else f"Choose {plan.name}"
        href = f"/#/billing?plan={escape(plan.id)}"
        action = f'<a class="cta" href="{href}">{escape(label)}</a>'
    else:
        action = '<a class="cta secondary" href="/#/billing">Open billing</a>'
    suffix = "" if plan.price_cents == 0 else f"<small>/{escape(plan.interval)}</small>"
    return (
        f'<article class="plan{" featured" if featured else ""}">'
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
        f"One credit is one {_reference_label().lower()}, the cheapest AI task."
        " Every other task is priced against it and published above,"
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
        "Yes. The software runs on your own host first; a self-hosted install has no"
        " tenant and nothing to meter."
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
        f'<article class="feature"><h3>{escape(title)}</h3><p>{escape(body)}</p></article>'
        for title, body in _FEATURES
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>relumea: plans and credits</title>
<meta name="description" content="relumea decompiles, matches, triages and automates
 reverse engineering. Static analysis is unmetered; credits cover the AI tasks.">
<link rel="icon" href="/static/favicon.svg" type="image/svg+xml">
<style>{_STYLE}</style>
</head>
<body>
<header><div class="wrap">
  <a class="brand" href="/">
    <span class="brand-mark" aria-hidden="true">
      <svg viewBox="0 0 24 24" focusable="false">
        <rect class="brand-mark-ink" x="1.5" y="1.5" width="6" height="6" rx="1.5"/>
        <rect class="brand-mark-ink" x="9" y="1.5" width="6" height="6" rx="1.5"/>
        <rect class="brand-mark-cell" x="16.5" y="1.5" width="6" height="6" rx="1.5"/>
        <rect class="brand-mark-ink" x="1.5" y="9" width="6" height="6" rx="1.5"/>
        <rect class="brand-mark-off" x="9" y="9" width="6" height="6" rx="1.5"/>
        <rect class="brand-mark-off" x="16.5" y="9" width="6" height="6" rx="1.5"/>
        <rect class="brand-mark-ink" x="1.5" y="16.5" width="6" height="6" rx="1.5"/>
        <rect class="brand-mark-off" x="9" y="16.5" width="6" height="6" rx="1.5"/>
        <rect class="brand-mark-off" x="16.5" y="16.5" width="6" height="6" rx="1.5"/>
      </svg>
    </span>
    <span>relumea</span>
    <span class="brand-ver">v{escape(__version__)}</span>
  </a>
  <nav>
    <a href="#features">What it does</a>
    <a href="#pricing">Plans</a>
    <a href="#credits">Credits</a>
    <a href="#faq">Questions</a>
    <a href="/">Open the workspace</a>
  </nav>
</div></header>

<main>
<div class="wrap">
  <div class="hero">
    <div>
      <h1>Decompile, match, triage, keep the corpus.</h1>
      <p>Read a binary, match its functions against everything you have seen before,
         triage what matters, and let an agent work through the rest. Only the AI
         tasks are metered.</p>
      <div class="hero-actions">
        <a class="cta" href="/#/users">Create a workspace</a>
        <a class="link-quiet" href="/">Open the workspace</a>
        <a class="link-quiet" href="#pricing">Plans and credits</a>
      </div>
    </div>
    <aside class="hero-aside" aria-label="What is metered">
      <strong>Static analysis is free</strong>
      Disasm, decomp, xrefs, matching and scans: unmetered on every plan.<br>
      Credits cover AI tasks and auto runs only.
    </aside>
  </div>
</div>

<section id="features"><div class="wrap">
  <h2>What it does</h2>
  <p class="lede">Each of these runs in the workspace today.</p>
  <div class="features">{features}</div>
</div></section>

<section id="pricing"><div class="wrap">
  <h2>Pricing</h2>
  <p class="lede">Static analysis is unmetered on every plan. Credits cover the AI
     tasks, priced from measured token use.</p>
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
  relumea v{escape(__version__)} · <a href="/">open the workspace</a> ·
  <a href="/static/fonts/OFL.txt">font licenses</a>
</div></footer>
</body>
</html>
"""
