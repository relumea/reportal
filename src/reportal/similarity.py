"""Structural assembly similarity, backed by the optional ``similarity`` extra.

reportal ranks functions by comparing their disassembly text.  The scoring
core is the sibling ``resembl`` project's token/MinHash pipeline: tokens are
normalized (registers, immediates and memory sizes collapse to placeholders),
shingled and hashed, and compared with a weighted Jaccard blended with a
text-level ratio.  Register-allocation and constant differences therefore do
not dominate the score.

The extra is optional: without it ``available`` is False and
:func:`similarity` raises :class:`SimilarityUnavailable`, so the default
install and its test suite run unchanged.

Tokenizing a listing and building its MinHash fingerprint costs far more than
the pair comparison that consumes them, and matching scores the same listing
against every other function of the corpus.  Both sides of a comparison are
therefore routed through a bounded cache of packed fingerprints keyed by the
listing text: each distinct listing is prepared once per process, two
functions with identical disassembly share one entry, and the optional
imports are resolved once.  :func:`cache_info` reports the counters and
:func:`clear_cache` drops the entries; neither changes a score.
"""

from __future__ import annotations

import importlib.util
import math
import threading
from functools import _CacheInfo, lru_cache
from types import ModuleType

# Weight of the MinHash Jaccard term in the blended score; the remainder
# weights the text ratio.  0.4 is resembl's documented default.
JACCARD_WEIGHT = 0.4

# Scores are rounded to this many decimals before storage, so a re-run
# produces the same stored value.
SCORE_DECIMALS = 1

# The scale a blended score lives on: the Jaccard term is JACCARD_WEIGHT of it
# and the text ratio the rest, so the ratio alone can carry (1 - weight) * this.
SCORE_SCALE = 100.0

# Distinct listings whose prepared fingerprint stays resident.  Bounded
# because the key is the listing text itself and an unbounded cache would pin
# a whole corpus of listings in memory for the process lifetime.
PREPARED_CACHE_SIZE = 4096

# Import probes for `available`; `resembl.scoring` pulls pygments/numpy only
# when actually imported, which `available` deliberately avoids.
_REQUIRED_MODULES = ("rapidfuzz", "resembl.scoring")

# The modules behind the optional extra, stored as modules rather than as the
# functions taken from them: a caller that scores thousands of pairs must not
# re-run the import statement per pair, and the attribute lookup stays live
# for a monkeypatched `resembl.scoring.code_tokenize`.
_loaded_modules: tuple[ModuleType, ModuleType] | None = None
_loaded_modules_lock = threading.Lock()


class SimilarityUnavailable(RuntimeError):  # noqa: N818  # name fixed by the similarity contract
    """The optional similarity extra (resembl + rapidfuzz) is not installed."""


def available() -> bool:
    """True when the optional similarity imports resolve.

    Probes the module specs instead of importing them; a caller that only
    wants a yes/no answer should not pay for pygments or numpy.
    """
    for name in _REQUIRED_MODULES:
        try:
            if importlib.util.find_spec(name) is None:
                return False
        except (ImportError, ValueError):
            return False
    return True


def _load_modules() -> tuple[ModuleType, ModuleType]:
    """Return ``(resembl.scoring, rapidfuzz.fuzz)``, importing them once.

    Raises :class:`SimilarityUnavailable` when the extra is not installed.
    """
    global _loaded_modules
    with _loaded_modules_lock:
        modules = _loaded_modules
        if modules is None:
            try:
                from rapidfuzz import fuzz
                from resembl import scoring
            except ImportError as exc:
                raise SimilarityUnavailable(
                    "function similarity requires the optional 'similarity' extra"
                    " (uv sync --extra similarity)"
                ) from exc
            modules = (scoring, fuzz)
            _loaded_modules = modules
        return modules


@lru_cache(maxsize=PREPARED_CACHE_SIZE)
def _prepare(text: str) -> bytes:
    """Tokenize, MinHash and pack one listing into its fingerprint bytes.

    Keyed by the listing text, so identical disassembly is prepared once.
    """
    scoring, _ = _load_modules()
    tokens = scoring.code_tokenize(text)
    packed: bytes = scoring.minhash_pack(scoring.minhash_from_tokens(tokens))
    return packed


def cache_info() -> _CacheInfo:
    """Counters for the prepared-listing cache: hits, misses, size and limit."""
    return _prepare.cache_info()


def clear_cache() -> None:
    """Drop every prepared listing; the next comparison prepares from scratch."""
    _prepare.cache_clear()


def similarity(left: str, right: str) -> float:
    """Structural similarity (0-100) between two assembly listings.

    Identical non-empty text scores 100.  Either side empty scores 0: there
    is no structure to compare.  Raises :class:`SimilarityUnavailable` when
    the extra is not installed.
    """
    if not left or not right:
        return 0.0
    if left == right:
        return 100.0
    scoring, fuzz = _load_modules()
    jaccard = scoring.minhash_jaccard(_prepare(left), _prepare(right))
    ratio = float(fuzz.ratio(left, right))
    blended = scoring.score_hybrid(float(jaccard), ratio, JACCARD_WEIGHT)
    return float(round(blended, SCORE_DECIMALS))


def jaccard(left: str, right: str) -> float:
    """The MinHash Jaccard of two listings (0-1), without the text ratio.

    The cheap half of :func:`similarity`'s blend: tokenizing and packing are
    cached per listing, and the comparison walks the packed fingerprints, so a
    caller that only needs the structural term pays a fraction of a full score.
    The early answers mirror :func:`similarity`: an empty side has no structure
    to compare, and identical non-empty text is a perfect match.
    """
    if not left or not right:
        return 0.0
    if left == right:
        return 1.0
    scoring, _ = _load_modules()
    return float(scoring.minhash_jaccard(_prepare(left), _prepare(right)))


def jaccard_floor(min_score: float) -> float:
    """The smallest Jaccard a pair can carry and still reach *min_score*.

    A blended score is ``JACCARD_WEIGHT`` of the Jaccard term on a 0-100 scale
    plus the rest of the text ratio, and that ratio is at most 100, so a pair
    scoring at least *min_score* has a Jaccard of at least
    ``(min_score - (1 - JACCARD_WEIGHT) * 100) / (JACCARD_WEIGHT * 100)``.  A
    floor of zero proves nothing (a threshold the ratio alone can reach) and
    means no pair may be ruled out by this bound.
    """
    floor = (min_score - (1.0 - JACCARD_WEIGHT) * SCORE_SCALE) / (JACCARD_WEIGHT * SCORE_SCALE)
    return max(0.0, floor)


def confidence_scores(scores: list[float]) -> list[float]:
    """Softmax over *scores*, shifted by the maximum for numerical stability.

    The shift leaves the result unchanged mathematically but keeps ``exp``
    from overflowing on large scores.  An empty input returns an empty list.
    """
    if not scores:
        return []
    peak = max(scores)
    weights = [math.exp(score - peak) for score in scores]
    total = sum(weights)
    return [weight / total for weight in weights]
