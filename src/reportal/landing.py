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

# Palette and type match the SPA dark workbench tokens in web/src/styles.css so
# /pricing reads as the same product with the logo removed, not a second skin.
_STYLE = """
:root {
  color-scheme: dark;
  --bg: #0e1219;
  --surface: #151b26;
  --surface-2: #1b2331;
  --border: #263044;
  --border-strong: #35435d;
  --text: #e6ecf5;
  --muted: #97a5bd;
  --faint: #8ea0ba;
  --accent: #86b4ff;
  --accent-hover: #9dc5ff;
  --accent-ink: #071122;
  --font-sans: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  --font-mono: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
  --radius: 6px;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font: 14px/1.55 var(--font-sans);
}
a { color: var(--accent); }
a:hover, a:focus-visible { color: var(--accent-hover); }
.wrap { max-width: 1120px; margin: 0 auto; padding: 0 24px; }
header { border-bottom: 1px solid var(--border); background: var(--surface); }
header .wrap {
  display: flex; align-items: center; justify-content: space-between;
  min-height: 52px; gap: 16px; flex-wrap: wrap; padding-top: 10px; padding-bottom: 10px;
}
.brand {
  display: inline-flex; align-items: baseline; gap: 8px;
  font-weight: 700; font-size: 16px; letter-spacing: 0.01em; color: var(--text);
  text-decoration: none;
}
.brand-dot {
  width: 8px; height: 8px; border-radius: 999px; background: var(--accent);
  flex: none; align-self: center;
}
.brand-tag {
  font-size: 11px; font-weight: 500; color: var(--faint);
  text-transform: uppercase; letter-spacing: 0.08em;
}
.brand-ver {
  font-family: var(--font-mono); font-size: 12px; font-weight: 400; color: var(--muted);
}
nav { display: flex; flex-wrap: wrap; gap: 4px 18px; }
nav a { text-decoration: none; color: var(--muted); font-size: 13px; }
nav a:hover, nav a:focus-visible { color: var(--text); }
.hero {
  padding: 56px 0 40px;
  display: grid; gap: 28px;
  grid-template-columns: minmax(0, 1.4fr) minmax(220px, 0.7fr);
  align-items: end;
}
.hero h1 {
  font-size: clamp(1.75rem, 3.6vw, 2.35rem); line-height: 1.15;
  margin: 0 0 14px; font-weight: 700; letter-spacing: 0.005em; max-width: 18ch;
}
.hero p { font-size: 15px; color: var(--muted); max-width: 58ch; margin: 0 0 22px; }
.hero-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 14px 18px; }
.cta {
  display: inline-block; background: var(--accent); color: var(--accent-ink);
  padding: 10px 16px; border-radius: var(--radius); text-decoration: none;
  font-weight: 600; font-size: 13px; border: 1px solid var(--accent);
}
.cta:hover, .cta:focus-visible { background: var(--accent-hover); border-color: var(--accent-hover);
  color: var(--accent-ink); }
.cta.secondary {
  background: transparent; color: var(--text); border-color: var(--border-strong);
}
.cta.secondary:hover, .cta.secondary:focus-visible {
  border-color: var(--accent); color: var(--accent); background: transparent;
}
.link-quiet { color: var(--muted); text-decoration: none; font-size: 13px; }
.link-quiet:hover, .link-quiet:focus-visible { color: var(--text); }
.hero-aside {
  border: 1px solid var(--border); background: var(--surface); border-radius: var(--radius);
  padding: 14px 16px; font-family: var(--font-mono); font-size: 12px; color: var(--muted);
  line-height: 1.7;
}
.hero-aside strong { color: var(--text); font-weight: 600; display: block; margin-bottom: 4px;
  font-family: var(--font-sans); font-size: 13px; }
section { padding: 40px 0; border-top: 1px solid var(--border); }
h2 { font-size: 18px; margin: 0 0 6px; font-weight: 600; letter-spacing: 0.01em; }
.lede { color: var(--muted); margin: 0 0 22px; max-width: 70ch; font-size: 14px; }
.features {
  display: grid; gap: 0; grid-template-columns: repeat(2, minmax(0, 1fr));
  border: 1px solid var(--border); border-radius: var(--radius); background: var(--surface);
  overflow: hidden;
}
.feature {
  padding: 16px 18px; border-top: 1px solid var(--border);
}
.feature:nth-child(-n+2) { border-top: 0; }
.feature:nth-child(odd) { border-right: 1px solid var(--border); }
.feature h3 {
  margin: 0 0 6px; font-size: 13px; font-family: var(--font-mono); font-weight: 600;
  color: var(--text);
}
.feature p { margin: 0; color: var(--muted); font-size: 13px; line-height: 1.5; }
.plans { display: grid; gap: 14px;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); align-items: start; }
.plan {
  background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
  padding: 18px; display: flex; flex-direction: column; height: 100%;
}
.plan.featured { border-color: var(--accent); background: var(--surface-2); }
.badge {
  display: inline-block; font-size: 12px; color: var(--accent); margin-bottom: 8px;
  font-family: var(--font-mono);
}
.plan h3 { margin: 0 0 2px; font-size: 15px; }
.price {
  font-size: 28px; font-weight: 700; margin: 10px 0 2px;
  font-family: var(--font-mono); font-variant-numeric: tabular-nums;
}
.price small { font-size: 12px; font-weight: 400; color: var(--muted); }
.tagline { color: var(--muted); font-size: 13px; margin: 0 0 14px; min-height: 2.8em; }
.plan ul { list-style: none; padding: 0; margin: 0 0 16px; }
.plan li { padding: 6px 0; border-top: 1px solid var(--border); font-size: 13px; }
.plan li:first-child { border-top: 0; }
.plan .cta { margin-top: auto; text-align: center; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); }
th { color: var(--muted); font-weight: 600; }
td.num, th.num {
  text-align: right; font-variant-numeric: tabular-nums; font-family: var(--font-mono);
}
.faq h3 { margin: 20px 0 6px; font-size: 14px; }
.faq p { margin: 0; color: var(--muted); max-width: 72ch; }
footer {
  border-top: 1px solid var(--border); padding: 24px 0 48px; color: var(--muted);
  font-size: 12px; font-family: var(--font-mono);
}
@media (max-width: 720px) {
  .hero { grid-template-columns: 1fr; }
  .features { grid-template-columns: 1fr; }
  .feature:nth-child(odd) { border-right: 0; }
  .feature:nth-child(2) { border-top: 1px solid var(--border); }
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
    badge = '<span class="badge">Recommended</span>' if featured else ""
    if plan.self_serve:
        label = "Start free trial" if plan.trial_days else f"Choose {plan.name}"
        href = f"/#/billing?plan={escape(plan.id)}"
        action = f'<a class="cta" href="{href}">{escape(label)}</a>'
    else:
        action = '<a class="cta secondary" href="/#/billing">Open billing</a>'
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
        f'<article class="feature"><h3>{escape(title)}</h3><p>{escape(body)}</p></article>'
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
  <a class="brand" href="/">
    <span class="brand-dot" aria-hidden="true"></span>
    <span>reportal</span>
    <span class="brand-tag">workbench</span>
    <span class="brand-ver">v{escape(__version__)}</span>
  </a>
  <nav>
    <a href="#features">Capabilities</a>
    <a href="#pricing">Plans</a>
    <a href="#credits">Credits</a>
    <a href="#faq">Questions</a>
    <a href="/">Open workbench</a>
  </nav>
</div></header>

<main>
<div class="wrap">
  <div class="hero">
    <div>
      <h1>reportal</h1>
      <p>A self-hosted reverse-engineering workbench: decompile a binary, match its
         functions against everything you have seen before, triage what matters, and
         let an agent drive the sweep. Metered only where inference actually runs.</p>
      <div class="hero-actions">
        <a class="cta" href="/#/users">Create a workspace</a>
        <a class="link-quiet" href="/">Open the workbench</a>
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
  <h2>Capabilities</h2>
  <p class="lede">One portal over the whole workflow, from the first byte to the report.</p>
  <div class="features">{features}</div>
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
  reportal v{escape(__version__)} · self-hosted reverse-engineering workbench ·
  <a href="/">open workbench</a>
</div></footer>
</body>
</html>
"""
