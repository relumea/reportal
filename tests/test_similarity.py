"""Tests for reportal.similarity: softmax confidence and resembl-backed scoring.

The real scoring tests are skipped when the optional ``similarity`` extra is
absent, so the suite passes with or without it.
"""

from __future__ import annotations

import importlib.util

import pytest

from reportal import similarity

HAS_SIMILARITY = similarity.available()

requires_similarity = pytest.mark.skipif(
    not HAS_SIMILARITY, reason="similarity extra not installed"
)


class TestConfidenceScores:
    def test_empty_returns_empty(self) -> None:
        assert similarity.confidence_scores([]) == []

    def test_uniform_scores_are_equal(self) -> None:
        result = similarity.confidence_scores([50.0, 50.0, 50.0])
        assert result == pytest.approx([1 / 3, 1 / 3, 1 / 3])

    def test_dominated_score_wins(self) -> None:
        result = similarity.confidence_scores([10.0, 100.0])
        assert result[1] > 0.99
        assert result[0] < 0.01

    def test_result_length_and_sum_to_one(self) -> None:
        result = similarity.confidence_scores([1.0, 2.0, 3.0, 4.0])
        assert len(result) == 4
        assert sum(result) == pytest.approx(1.0)

    def test_large_scores_do_not_overflow(self) -> None:
        result = similarity.confidence_scores([1000.0, 1000.0])
        assert sum(result) == pytest.approx(1.0)


class TestAvailable:
    def test_returns_bool(self) -> None:
        assert isinstance(similarity.available(), bool)

    def test_missing_probe_module_is_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(importlib.util, "find_spec", lambda name: None)
        assert similarity.available() is False


class TestScoring:
    def test_empty_side_scores_zero(self) -> None:
        assert similarity.similarity("", "mov eax, 1") == 0.0
        assert similarity.similarity("mov eax, 1", "") == 0.0
        assert similarity.similarity("", "") == 0.0

    @requires_similarity
    def test_identical_text_scores_100(self) -> None:
        text = "mov eax, ebx\nadd eax, 1\nret\n"
        assert similarity.similarity(text, text) == 100.0

    @requires_similarity
    def test_bounded_and_symmetric(self) -> None:
        left = "mov eax, 1\nadd eax, edx\nret\n"
        right = "push ebp\nmov ebp, esp\nxor eax, eax\npop ebp\nret\n"
        forward = similarity.similarity(left, right)
        assert 0.0 <= forward <= 100.0
        assert similarity.similarity(right, left) == pytest.approx(forward)

    @pytest.mark.skipif(HAS_SIMILARITY, reason="similarity extra installed")
    def test_missing_extra_raises(self) -> None:
        with pytest.raises(similarity.SimilarityUnavailable):
            similarity.similarity("mov eax, 1", "mov ebx, 2")


# Distinct real-looking listings for the cache tests, so a preparation count
# attributes every call to a known text.
LISTING_A = "push ebp\nmov ebp, esp\nmov eax, [ebp+8]\nadd eax, 3\npop ebp\nret\n"
LISTING_B = "push ebp\nmov ebp, esp\nxor eax, eax\npop ebp\nret\n"
LISTING_C = "push ebx\nmov ebx, 2\nsub ebx, 1\nmov eax, ebx\npop ebx\nret\n"
LISTING_D = "xor ecx, ecx\ntest eax, eax\nje 0x401020\ninc ecx\nmov eax, ecx\nret\n"
LISTING_E = "sub esp, 8\nmov dword ptr [esp], 1\ncall 0x401100\nadd esp, 8\nret\n"
LISTING_F = "push esi\nmov esi, [esp+8]\nlodsb\nstosb\ndec ecx\npop esi\nret\n"

ALL_LISTINGS = (LISTING_A, LISTING_B, LISTING_C, LISTING_D, LISTING_E, LISTING_F)


def _count_tokenize(monkeypatch: pytest.MonkeyPatch, calls: list[str]) -> None:
    """Record every listing resembl's tokenizer is handed."""
    from resembl import scoring as resembl_scoring

    real_tokenize = resembl_scoring.code_tokenize

    def counting_tokenize(text: str, normalize: bool = True) -> list[str]:
        calls.append(text)
        result: list[str] = real_tokenize(text, normalize)
        return result

    monkeypatch.setattr(resembl_scoring, "code_tokenize", counting_tokenize)


@requires_similarity
class TestPreparedCache:
    """One tokenize/MinHash preparation per distinct listing, reused pairwise."""

    def test_shared_listing_is_prepared_once(self) -> None:
        similarity.clear_cache()
        candidates = (LISTING_B, LISTING_C, LISTING_D, LISTING_E, LISTING_F)
        for candidate in candidates:
            similarity.similarity(LISTING_A, candidate)
        info = similarity.cache_info()
        # LISTING_A is prepared on the first pair and hit by every later one;
        # each candidate is seen exactly once.
        assert info.misses == len(candidates) + 1
        assert info.hits == len(candidates) - 1

    def test_tokenizer_runs_once_per_distinct_listing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[str] = []
        _count_tokenize(monkeypatch, calls)
        similarity.clear_cache()
        for candidate in (LISTING_B, LISTING_C, LISTING_D):
            similarity.similarity(LISTING_A, candidate)
        assert calls.count(LISTING_A) == 1
        assert len(calls) == 4

    def test_second_comparison_of_a_pair_hits_both_entries(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[str] = []
        _count_tokenize(monkeypatch, calls)
        similarity.clear_cache()
        similarity.similarity(LISTING_A, LISTING_B)
        first = similarity.cache_info()
        similarity.similarity(LISTING_A, LISTING_B)
        second = similarity.cache_info()
        assert len(calls) == 2
        assert second.misses == first.misses
        assert second.hits == first.hits + 2

    def test_equal_listings_share_one_entry(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[str] = []
        _count_tokenize(monkeypatch, calls)
        similarity.clear_cache()
        duplicate = "".join((LISTING_A[:20], LISTING_A[20:]))
        assert duplicate == LISTING_A
        similarity.similarity(LISTING_A, LISTING_B)
        similarity.similarity(duplicate, LISTING_B)
        assert len(calls) == 2

    def test_clear_cache_resets_counters_and_keeps_scores(self) -> None:
        pairs = ((LISTING_A, LISTING_B), (LISTING_A, LISTING_C), (LISTING_D, LISTING_E))
        similarity.clear_cache()
        before = [similarity.similarity(left, right) for left, right in pairs]
        assert similarity.cache_info().currsize > 0
        similarity.clear_cache()
        info = similarity.cache_info()
        assert (info.hits, info.misses, info.currsize) == (0, 0, 0)
        after = [similarity.similarity(left, right) for left, right in pairs]
        assert after == before

    def test_short_circuits_leave_the_cache_untouched(self) -> None:
        similarity.clear_cache()
        assert similarity.similarity(LISTING_A, LISTING_A) == 100.0
        assert similarity.similarity(LISTING_A, "") == 0.0
        assert similarity.similarity("", LISTING_A) == 0.0
        assert similarity.cache_info().currsize == 0

    def test_identical_listing_scores_100_with_a_warm_cache(self) -> None:
        similarity.clear_cache()
        similarity.similarity(LISTING_A, LISTING_B)
        assert similarity.similarity(LISTING_A, LISTING_A) == 100.0

    def test_cache_is_bounded(self) -> None:
        assert similarity.PREPARED_CACHE_SIZE > 0
        assert similarity.cache_info().maxsize == similarity.PREPARED_CACHE_SIZE

    def test_cached_and_uncached_scores_agree(self, monkeypatch: pytest.MonkeyPatch) -> None:
        pairs = [(left, right) for left in ALL_LISTINGS for right in ALL_LISTINGS if left != right]
        similarity.clear_cache()
        cached = [similarity.similarity(left, right) for left, right in pairs]
        # __wrapped__ is lru_cache's uncached function: the same preparation on
        # every call, which is the reference the cache must reproduce.
        monkeypatch.setattr(similarity, "_prepare", similarity._prepare.__wrapped__)
        uncached = [similarity.similarity(left, right) for left, right in pairs]
        assert uncached == cached
        assert any(score > 0.0 for score in cached)
