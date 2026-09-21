"""Published LLM token rates used by the credit and plan cost models.

Rates live below both :mod:`reportal.plans` and :mod:`reportal.credits` so the
catalog can price tiers from credit COGS and the credit table can price tasks
from the same numbers without importing each other.
"""

from __future__ import annotations

import math
from decimal import ROUND_HALF_UP, Decimal

# (input, output) pairs per million tokens.
# Source: https://platform.claude.com/docs/en/about-claude/pricing
# gpt-4o-mini matches :data:`reportal.llm.DEFAULT_MODEL` so a default bridge
# install records COGS at the published OpenAI rate rather than falling through
# to the fail-closed Opus ceiling.
MODEL_RATES: dict[str, tuple[float, float]] = {
    "claude-opus-5": (5.0, 25.0),
    "claude-sonnet-5": (2.0, 10.0),
    "claude-haiku-4.5": (1.0, 5.0),
    "gpt-4o-mini": (0.15, 0.60),
}

# Sonnet is the default working model for reportal's AI extras.
COST_MODEL = "claude-sonnet-5"

# Share of a metered token that is input rather than output.
INPUT_SHARE = 0.8


def blended_usd_per_mtok(model: str = COST_MODEL) -> float:
    """Cost of one million metered tokens, USD, at :data:`INPUT_SHARE`."""
    return float(_blended_rate(model))


def _blended_rate(model: str) -> Decimal:
    if model in MODEL_RATES:
        input_rate, output_rate = MODEL_RATES[model]
    else:
        input_rate, output_rate = max(MODEL_RATES.values(), key=lambda pair: pair[1])
    share = Decimal(str(INPUT_SHARE))
    return Decimal(str(input_rate)) * share + Decimal(str(output_rate)) * (1 - share)


def tokens_for_budget(usd: float, model: str = COST_MODEL) -> int:
    """How many tokens *usd* buys at the blended rate, rounded down."""
    if not isinstance(usd, (int, float)) or isinstance(usd, bool):
        return 0
    if not math.isfinite(usd) or usd <= 0:
        return 0
    return int(Decimal(str(usd)) * 1_000_000 / _blended_rate(model))


def micro_usd_for_tokens(tokens: int, model: str = COST_MODEL) -> int:
    """What *tokens* cost in micro-USD at the blended rate, rounded half-up."""
    if not isinstance(tokens, int) or isinstance(tokens, bool) or tokens <= 0:
        return 0
    return int((Decimal(tokens) * _blended_rate(model)).to_integral_value(rounding=ROUND_HALF_UP))


def usd_for_tokens(tokens: int, model: str = COST_MODEL) -> float:
    """What *tokens* cost to serve at the blended rate."""
    return micro_usd_for_tokens(tokens, model) / 1_000_000


def rates_for(model: str = COST_MODEL) -> tuple[float, float]:
    """``(input, output)`` USD-per-MTok for *model*, or the priciest catalog entry."""
    if model in MODEL_RATES:
        return MODEL_RATES[model]
    return max(MODEL_RATES.values(), key=lambda pair: pair[1])
