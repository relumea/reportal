"""What each AI task costs a tenant, in credits.

Tokens are the wrong unit to sell.  A customer cannot predict them, cannot
compare two vendors with them, and a bill that moves because a model got
chattier is a support ticket rather than a price.  So the token ledger stays
(:mod:`reportal.metering` keeps recording it, and it is what proves the margin
internally), and what a tenant actually spends is a **credit**: a fixed,
published price per task.

The unit is defined rather than chosen.  One credit is one *reference task*:
the cheapest real operation the portal performs (currently function triage over
a median function).  :data:`REFERENCE_TASK` names it, :func:`credit_cogs_usd`
prices it at the published Claude rates, and every other task's credit cost is
its measured cost divided by that, rounded up.  So the table below is derived:
change the rates in :mod:`reportal.plans` and every credit cost moves with
them, which is what keeps the catalog honest when a model is repriced.

Where the profiles come from
----------------------------

:data:`TASK_PROFILES` is measurement, not estimate, and the measurement is
repeatable: ``tools/bench_credits.py`` runs the real task functions over real
decompiled C through the same sink the server meters with, and records the
token counts the endpoint itself reported.  The numbers below came from a run
of 8 functions per task from the ``notepad-rebrew`` corpus against
``deepseek-flash``.  Re-run it after a prompt change, a model change or a
corpus change; it exits non-zero when a task now costs more than it charges.

That run overturned the first version of this table, and the reason is the
thing to keep in mind when reading it.  The *visible* answer sizes were close
(the prompt's declared shape predicts them to about 23% median error), but a
reasoning model bills its deliberation as completion tokens, and the
deliberation is where the money goes: between 2.7x the visible answer for
triage and 22.3x for a whole-function rewrite.  So a profile is stated as
:attr:`TaskProfile.visible_tokens` (what a reader sees, which a prompt shape
predicts) times :attr:`TaskProfile.thinking_ratio` (what the model spends
getting there, which only measurement finds).  A task that looks cheap in
output can be the most expensive one to serve, and ``ai-decompilation`` is
exactly that task.

The ratios are model-specific.  A model that does not reason has a ratio near
1.0, and re-running the benchmark against it produces a much cheaper table:
this is the knob to re-measure when the bridge is pointed somewhere new, not a
constant of the product.

Size bands
----------

A published price still has to survive a 10,000-line function.  A task's cost
is its base credits times a band multiplier taken from the *input* size
(:data:`SIZE_BANDS`), so a large function costs more credits than a small one
and the per-credit margin holds at both ends.  Input is used rather than output
because it is known before the call, which is what lets a quota refuse work
instead of discovering the overrun afterwards.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from reportal import llm

# Characters of decompiled C per token, shared with the module that sizes the
# real prompts.  Used only to size a caller's text when it has no count of its
# own, never to invent one.
CHARS_PER_TOKEN = llm.CHARS_PER_TOKEN


@dataclass(frozen=True)
class TaskProfile:
    """One AI task: what it is, and what one call of it costs to serve."""

    name: str
    label: str
    describe: str
    # Median prompt tokens for one call, measured over the reference corpus.
    input_tokens: int
    # Median tokens of *visible* answer: the summary, the rewritten function,
    # the comment list.  This is the part a reader sees and the part a prompt's
    # declared answer shape predicts.
    visible_tokens: int
    # Total billed output divided by visible output, measured per task.  A
    # reasoning model thinks before it answers and bills the thinking as
    # completion, so this is the multiplier that turns a visible answer into
    # what the invoice says.  1.0 is a model that does not reason.
    thinking_ratio: float = 1.0
    # Whether one call covers one function (so a binary-wide run charges per
    # function) or the whole request.
    per_function: bool = False

    @property
    def output_tokens(self) -> int:
        """Total billed output tokens: the visible answer plus the thinking."""
        return round(self.visible_tokens * self.thinking_ratio)

    def cogs_usd(self) -> float:
        """What one call of this task costs in inference, at the current rates."""
        # Imported lazily: plans reads this module for credit cogs, so a
        # top-level import would close a cycle.
        from reportal import plans

        input_rate, output_rate = plans.MODEL_RATES.get(
            plans.COST_MODEL, max(plans.MODEL_RATES.values(), key=lambda pair: pair[1])
        )
        return self.input_tokens * input_rate / 1e6 + self.output_tokens * output_rate / 1e6


# Every billable AI task, keyed by the name the API, CLI and MCP all use.
# A task absent from this table is not billable: the static analysis surface
# (disassembly, xrefs, structs, matching, every rule-based scan) spends CPU
# rather than inference and is unmetered on every plan, which is the single
# most important thing this table says by omission.
TASK_SUMMARY = llm.TASK_SUMMARY
TASK_COMMENTS = llm.TASK_COMMENTS
TASK_TYPES = llm.TASK_TYPES
TASK_DECOMPILE = llm.TASK_DECOMPILE
TASK_RENAMES = llm.TASK_RENAMES
TASK_TRIAGE = llm.TASK_TRIAGE
TASK_THREAT = llm.TASK_THREAT
TASK_AGENT = llm.TASK_AGENT

TASK_PROFILES: dict[str, TaskProfile] = {
    TASK_TRIAGE: TaskProfile(
        name=TASK_TRIAGE,
        label="Function triage",
        describe="A summary, score and capabilities per function.",
        input_tokens=376,
        visible_tokens=114,
        thinking_ratio=2.7,
        per_function=True,
    ),
    TASK_THREAT: TaskProfile(
        name=TASK_THREAT,
        label="Threat narrative",
        describe="The written half of a threat report.",
        input_tokens=352,
        visible_tokens=110,
        thinking_ratio=4.2,
    ),
    TASK_SUMMARY: TaskProfile(
        name=TASK_SUMMARY,
        label="Function summary",
        describe="One paragraph on what a function does.",
        input_tokens=348,
        visible_tokens=134,
        thinking_ratio=3.6,
    ),
    TASK_TYPES: TaskProfile(
        name=TASK_TYPES,
        label="Type suggestions",
        describe="Parameter, return and local type proposals.",
        input_tokens=380,
        visible_tokens=200,
        thinking_ratio=3.8,
    ),
    TASK_AGENT: TaskProfile(
        name=TASK_AGENT,
        label="Agent turn",
        describe="One reasoning step of the conversation agent.",
        # Not in the benchmark: an agent turn carries a tool registry and a
        # conversation rather than one function, so it has no corpus to sample.
        # Priced from the measured neighbours it most resembles (a large prompt
        # and a deliberating answer) and marked here as the one estimate left.
        input_tokens=1200,
        visible_tokens=300,
        thinking_ratio=4.0,
    ),
    TASK_RENAMES: TaskProfile(
        name=TASK_RENAMES,
        label="Rename suggestions",
        describe="Proposed identifier names for a function.",
        input_tokens=428,
        visible_tokens=308,
        thinking_ratio=10.2,
    ),
    TASK_COMMENTS: TaskProfile(
        name=TASK_COMMENTS,
        label="Inline comments",
        describe="A comment on every meaningful line of a function.",
        input_tokens=360,
        visible_tokens=463,
        thinking_ratio=7.2,
    ),
    TASK_DECOMPILE: TaskProfile(
        name=TASK_DECOMPILE,
        label="AI decompilation",
        describe="A whole function rewritten as readable C.",
        input_tokens=400,
        visible_tokens=268,
        thinking_ratio=22.3,
    ),
}

# The task one credit is defined as: the cheapest real operation, so every other
# task costs a whole number of credits at or above one and nothing is priced in
# fractions.  Measurement picks it rather than preference, and
# `tests/test_credits.py` fails if it stops being the cheapest, which is what
# caught the move from `summary` to `function-triage` when the benchmark showed
# summaries deliberate three and a half times their visible answer.
REFERENCE_TASK = TASK_TRIAGE

# Input-size bands.  A call whose input fits the first ceiling costs the task's
# base credits; each band above doubles it.  The first ceiling is set above the
# reference corpus's 90th percentile (about 1,300 tokens), so an ordinary
# function is never surcharged and only a genuinely large one is.
SIZE_BANDS: tuple[tuple[str, int, int], ...] = (
    ("standard", 1_500, 1),
    ("large", 6_000, 2),
    ("very large", 20_000, 4),
)
# Multiplier for an input above the last band's ceiling.
OVERSIZE_MULTIPLIER = 8

# What a tenant pays for a credit beyond its allowance.  Above the plan rate
# because unplanned capacity carries a thinner margin, and above the measured
# cost of a credit, which `tests/test_credits.py` checks.
OVERAGE_USD_PER_CREDIT = 0.04


def credit_cogs_usd() -> float:
    """What one credit costs to serve: the reference task, at current rates."""
    return TASK_PROFILES[REFERENCE_TASK].cogs_usd()


def credits_for_budget(usd: float) -> int:
    """How many credits *usd* of inference budget buys, rounded down."""
    if not isinstance(usd, (int, float)) or isinstance(usd, bool):
        return 0
    if not math.isfinite(usd) or usd <= 0:
        return 0
    return int(usd / credit_cogs_usd())


def band_for(input_tokens: int) -> tuple[str, int]:
    """The size band an input falls in, as ``(name, multiplier)``."""
    for name, ceiling, multiplier in SIZE_BANDS:
        if input_tokens <= ceiling:
            return name, multiplier
    return "oversize", OVERSIZE_MULTIPLIER


def base_credits(task: str) -> int:
    """The credits one standard-sized call of *task* costs.

    Derived from the task's measured cost against the reference task and
    rounded up, so a task never costs less than it takes to serve and the
    cheapest task is exactly one credit.  An unknown task is priced at the
    most expensive profile rather than free, because an unpriced task must
    never be a way to spend inference for nothing.
    """
    profile = TASK_PROFILES.get(task)
    if profile is None:
        profile = max(TASK_PROFILES.values(), key=lambda entry: entry.cogs_usd())
    return max(1, math.ceil(profile.cogs_usd() / credit_cogs_usd()))


def cost_of(task: str, input_tokens: int = 0) -> int:
    """Credits one call of *task* costs, with its size band applied."""
    return base_credits(task) * band_for(max(0, input_tokens))[1]


def tokens_of(text: str) -> int:
    """Approximate token count of *text*, for sizing a call before it runs."""
    return math.ceil(len(text) / CHARS_PER_TOKEN)


def describe_task(task: str) -> dict[str, object]:
    """One task's public price row: what it is and what it costs."""
    profile = TASK_PROFILES[task]
    base = base_credits(task)
    bands: list[dict[str, object]] = [
        {"name": name, "max_input_tokens": ceiling, "credits": base * multiplier}
        for name, ceiling, multiplier in SIZE_BANDS
    ]
    # Past the last ceiling there is still a price; omit it and the catalog
    # understates what an oversize input actually costs.
    bands.append(
        {
            "name": "oversize",
            "max_input_tokens": None,
            "credits": base * OVERSIZE_MULTIPLIER,
        }
    )
    return {
        "task": profile.name,
        "label": profile.label,
        "describe": profile.describe,
        "credits": base,
        "per_function": profile.per_function,
        "bands": bands,
    }


def catalog() -> list[dict[str, object]]:
    """Every billable task, cheapest first; the published price list."""
    return [
        describe_task(name)
        for name in sorted(TASK_PROFILES, key=lambda entry: (base_credits(entry), entry))
    ]
