"""Tests for reportal.match_index: the LSH candidate index and its exactness.

The equivalence tests run the real scorer over a seeded corpus of listing
families (a base function and mutated copies of it) twice, once through the
index and once forced pairwise, and require byte-identical match rows.  The
candidate-count test is the benchmark: it counts the Jaccard comparisons each
path makes on the same corpus.
"""

from __future__ import annotations

import math
import random
import sqlite3
from typing import Any

import pytest

from reportal import engines, match_index, matching, similarity, store

pytestmark = pytest.mark.skipif(not similarity.available(), reason="similarity extra not installed")

# Instruction templates the synthetic listings draw from.  The tokenizer
# collapses registers and immediates, so the mnemonic and operand shapes are
# what make two listings differ.
TEMPLATES: tuple[str, ...] = (
    "push ebp",
    "mov ebp, esp",
    "sub esp, 0x{imm:x}",
    "mov eax, dword [ebp + {imm}]",
    "mov dword [ebp - {imm}], ecx",
    "lea edx, [eax + ecx*4]",
    "add eax, {imm}",
    "xor ecx, ecx",
    "cmp eax, {imm}",
    "jne 0x{addr:x}",
    "je 0x{addr:x}",
    "test eax, eax",
    "call 0x{addr:x}",
    "imul eax, ecx",
    "shl edx, {small}",
    "movzx eax, byte [esi + {imm}]",
    "inc edi",
    "dec ecx",
    "and eax, 0x{imm:x}",
    "or edx, ebx",
    "sar eax, {small}",
    "cdq",
    "idiv ecx",
    "rep movsb",
    "fld dword [ebp - {imm}]",
    "fstp qword [esp]",
    "pop esi",
    "pop ebp",
    "ret",
    "leave",
)

# Corpus shape: families of related listings, each a base plus mutated copies.
FAMILY_COUNT = 12
FAMILY_SIZE = 5
BASE_LENGTH = 40
MUTATIONS_PER_COPY = (1, 3, 6, 10)
SEED = 20260924

# Thresholds the equivalence test sweeps: the index boundary itself, and above.
INDEXED_THRESHOLDS = (
    math.nextafter(match_index.LSH_PAIRWISE_MAX_SIMILARITY, math.inf),
    80.5,
    85.0,
    90.0,
    95.0,
)


def _instruction(rng: random.Random) -> str:
    template = rng.choice(TEMPLATES)
    return template.format(
        imm=rng.randrange(1, 0x200),
        addr=rng.randrange(0x401000, 0x40F000),
        small=rng.randrange(1, 8),
    )


def _family(rng: random.Random) -> list[str]:
    base = [_instruction(rng) for _ in range(BASE_LENGTH)]
    listings = ["\n".join(base) + "\n"]
    for mutations in MUTATIONS_PER_COPY[: FAMILY_SIZE - 1]:
        copy = list(base)
        for _ in range(mutations):
            copy[rng.randrange(len(copy))] = _instruction(rng)
        listings.append("\n".join(copy) + "\n")
    return listings


def _corpus(families: int, seed: int = SEED) -> list[str]:
    rng = random.Random(seed)
    listings: list[str] = []
    for _ in range(families):
        listings.extend(_family(rng))
    return listings


def _seed_corpus(conn: sqlite3.Connection, listings: list[str], binaries: int) -> dict[int, str]:
    """Spread *listings* round-robin over *binaries* binaries; returns id -> listing."""
    analyses: list[int] = []
    for index in range(binaries):
        binary_id = store.add_binary(conn, sha256=f"{index:064x}", name=f"b{index}.exe")
        analyses.append(store.create_analysis(conn, binary_id=binary_id, engine="manual"))
    texts: dict[int, str] = {}
    for index, listing in enumerate(listings):
        function_id = store.add_function(
            conn,
            analysis_id=analyses[index % binaries],
            va=0x1000 + index * 0x40,
            name=f"f{index}",
            size=64,
        )
        texts[function_id] = listing
    return texts


def _match_rows(conn: sqlite3.Connection) -> list[tuple[int, int, float, float, str]]:
    cursor = conn.execute(
        "SELECT function_id, candidate_function_id, similarity, confidence, settings_json"
        " FROM matches ORDER BY function_id, candidate_function_id"
    )
    return [(int(r[0]), int(r[1]), float(r[2]), float(r[3]), str(r[4])) for r in cursor]


def _run_all(
    conn: sqlite3.Connection, texts: dict[int, str], settings: matching.MatchSettings
) -> None:
    binary_ids = [int(row["id"]) for row in conn.execute("SELECT id FROM binaries ORDER BY id")]
    for binary_id in binary_ids:
        matching.match_binary(
            conn,
            binary_id=binary_id,
            engine=engines.RebrewEngine(enabled=False),
            disassembler=lambda function: texts.get(int(function["id"])),
            settings=settings,
        )


def _count_jaccard(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Count every Jaccard comparison the run makes; returns the live counter."""
    real = similarity.jaccard
    calls = [0]

    def counting(left: str, right: str) -> float:
        calls[0] += 1
        return real(left, right)

    monkeypatch.setattr(similarity, "jaccard", counting)
    return calls


class TestThreshold:
    def test_the_boundary_is_the_derived_constant(self) -> None:
        assert match_index.LSH_BANDS * match_index.LSH_ROWS == similarity.NUM_PERMUTATIONS
        assert match_index.LSH_MIN_AGREEING == 65
        assert match_index.LSH_PAIRWISE_MAX_SIMILARITY == 80.0
        above = math.nextafter(match_index.LSH_PAIRWISE_MAX_SIMILARITY, math.inf)
        assert match_index.required_bands(above) == 1
        assert match_index.required_bands(match_index.LSH_PAIRWISE_MAX_SIMILARITY) == 0

    def test_the_default_match_floor_stays_pairwise(self) -> None:
        assert not match_index.uses_index(matching.DEFAULT_MIN_SIMILARITY)
        assert match_index.uses_index(matching.DEFAULT_SIMILAR_MIN_SIMILARITY)

    def test_a_perfect_score_needs_every_band(self) -> None:
        assert match_index.required_bands(100.0) == match_index.LSH_BANDS

    def test_a_pair_the_floor_admits_shares_the_required_bands(self) -> None:
        # The exactness argument, checked on real fingerprints: every pair of
        # the corpus whose Jaccard clears a threshold's floor shares at least
        # that threshold's required bands.
        listings = _corpus(4)
        keys = [
            similarity.band_keys(
                similarity.fingerprint(text), match_index.LSH_BANDS, match_index.LSH_ROWS
            )
            for text in listings
        ]
        checked = 0
        for threshold in INDEXED_THRESHOLDS:
            floor = similarity.jaccard_floor(threshold)
            needed = match_index.required_bands(threshold)
            for left in range(len(listings)):
                for right in range(left + 1, len(listings)):
                    if similarity.jaccard(listings[left], listings[right]) < floor:
                        continue
                    shared = sum(a == b for a, b in zip(keys[left], keys[right], strict=True))
                    assert shared >= needed
                    checked += 1
        assert checked > 0, "the corpus must contain pairs above the floor"


class TestEquivalence:
    @pytest.mark.parametrize("threshold", INDEXED_THRESHOLDS)
    def test_the_index_records_the_pairwise_rows(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch, threshold: float
    ) -> None:
        texts = _seed_corpus(conn, _corpus(FAMILY_COUNT), binaries=3)
        settings = matching.MatchSettings(min_similarity=threshold, top=FAMILY_SIZE)

        with monkeypatch.context() as patch:
            patch.setattr(match_index, "uses_index", lambda score: False)
            _run_all(conn, texts, settings)
        pairwise = _match_rows(conn)

        _run_all(conn, texts, settings)
        indexed = _match_rows(conn)

        assert pairwise, "the corpus must produce matches at this threshold"
        assert indexed == pairwise

    def test_a_scope_and_self_exclusion_hold_through_the_index(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        texts = _seed_corpus(conn, _corpus(FAMILY_COUNT), binaries=3)
        binary_ids = [int(row["id"]) for row in conn.execute("SELECT id FROM binaries")]
        settings = matching.MatchSettings(
            min_similarity=85.0, include_self=False, binary_ids=(binary_ids[1],)
        )

        with monkeypatch.context() as patch:
            patch.setattr(match_index, "uses_index", lambda score: False)
            _run_all(conn, texts, settings)
        pairwise = _match_rows(conn)
        _run_all(conn, texts, settings)

        assert pairwise
        assert _match_rows(conn) == pairwise


class TestCandidateCount:
    def test_the_index_compares_far_fewer_pairs(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        texts = _seed_corpus(conn, _corpus(FAMILY_COUNT * 4), binaries=4)
        settings = matching.MatchSettings(min_similarity=85.0, top=FAMILY_SIZE)

        with monkeypatch.context() as patch:
            patch.setattr(match_index, "uses_index", lambda score: False)
            pairwise_calls = _count_jaccard(patch)
            _run_all(conn, texts, settings)
        pairwise_rows = _match_rows(conn)

        with monkeypatch.context() as patch:
            indexed_calls = _count_jaccard(patch)
            _run_all(conn, texts, settings)

        functions = len(texts)
        assert pairwise_calls[0] == functions * (functions - 1)
        # Each function's candidates are its own family, not the corpus.
        assert indexed_calls[0] * 10 < pairwise_calls[0]
        assert _match_rows(conn) == pairwise_rows

    def test_below_the_boundary_the_run_stays_pairwise(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        texts = _seed_corpus(conn, _corpus(2), binaries=2)
        calls = _count_jaccard(monkeypatch)

        _run_all(conn, texts, matching.MatchSettings(min_similarity=80.0))

        functions = len(texts)
        assert calls[0] == functions * (functions - 1)
        assert match_index.status(conn)["functions"] == 0


class TestMaintenance:
    def _cached(self, conn: sqlite3.Connection, count: int) -> dict[int, str]:
        texts = _seed_corpus(conn, _corpus(1)[:count], binaries=1)
        for function_id, text in texts.items():
            assert store.set_disasm(conn, function_id, text)
        return texts

    def test_status_counts_unindexed_listings(self, conn: sqlite3.Connection) -> None:
        self._cached(conn, 3)

        payload = match_index.status(conn)

        assert payload["functions"] == 0
        assert payload["cached_listings"] == 3
        assert payload["unindexed"] == 3
        assert payload["bands"] == match_index.LSH_BANDS
        assert payload["rows_per_band"] == match_index.LSH_ROWS
        assert payload["pairwise_max_similarity"] == match_index.LSH_PAIRWISE_MAX_SIMILARITY

    def test_rebuild_indexes_every_cached_listing(self, conn: sqlite3.Connection) -> None:
        self._cached(conn, 3)

        payload = match_index.rebuild(conn)

        assert payload["indexed"] == 3
        assert payload["functions"] == 3
        assert payload["buckets"] == 3 * match_index.LSH_BANDS
        assert payload["unindexed"] == 0

    def test_replacing_a_listing_drops_its_row_and_sync_restores_it(
        self, conn: sqlite3.Connection
    ) -> None:
        texts = self._cached(conn, 2)
        match_index.rebuild(conn)
        function_id = min(texts)

        store.set_disasm(conn, function_id, "xor eax, eax\nret\n")

        assert match_index.status(conn)["unindexed"] == 1
        assert match_index.sync(conn) == 1
        row = conn.execute(
            "SELECT listing_sha256 FROM lsh_fingerprints WHERE function_id = ?", (function_id,)
        ).fetchone()
        assert row[0] == match_index.listing_digest("xor eax, eax\nret\n")

    def test_clearing_a_listing_drops_its_buckets(self, conn: sqlite3.Connection) -> None:
        texts = self._cached(conn, 2)
        match_index.rebuild(conn)

        store.clear_disasm(conn, min(texts))

        payload = match_index.status(conn)
        assert payload["functions"] == 1
        assert payload["buckets"] == match_index.LSH_BANDS

    def test_a_listing_indexed_from_other_text_is_rewritten(self, conn: sqlite3.Connection) -> None:
        texts = self._cached(conn, 1)
        function_id = min(texts)

        assert match_index.index_listings(conn, {function_id: "ret\n"}) == 1
        assert match_index.index_listings(conn, {function_id: "ret\n"}) == 0
        assert match_index.index_listings(conn, {function_id: texts[function_id]}) == 1
        assert match_index.near(conn, texts[function_id], match_index.LSH_BANDS) == {
            function_id: match_index.LSH_BANDS
        }

    def test_rebuild_without_the_extra_refuses(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(similarity, "available", lambda: False)

        with pytest.raises(similarity.SimilarityUnavailable):
            match_index.rebuild(conn)


class TestFindSimilar:
    def _cached_corpus(self, conn: sqlite3.Connection) -> dict[int, str]:
        texts = _seed_corpus(conn, _corpus(FAMILY_COUNT), binaries=3)
        for function_id, text in texts.items():
            assert store.set_disasm(conn, function_id, text)
        return texts

    def test_the_family_ranks_first_and_the_query_is_excluded(
        self, conn: sqlite3.Connection
    ) -> None:
        texts = self._cached_corpus(conn)
        ids = sorted(texts)
        base = ids[FAMILY_SIZE]

        payload = matching.find_similar(conn, texts[base], exclude_function_id=base)

        assert payload["candidate_source"] == matching.CANDIDATES_FROM_INDEX
        hits = [hit["function_id"] for hit in payload["hits"]]
        assert base not in hits
        assert hits[0] == base + 1, "the one-mutation copy is the nearest"
        assert set(hits) <= set(ids[FAMILY_SIZE : 2 * FAMILY_SIZE])
        assert payload["compared"] < len(ids) // 2

    @pytest.mark.parametrize("threshold", INDEXED_THRESHOLDS)
    def test_the_index_answers_the_pairwise_query(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch, threshold: float
    ) -> None:
        texts = self._cached_corpus(conn)
        queries = sorted(texts)[:: FAMILY_SIZE + 1]

        def answers() -> list[Any]:
            return [
                matching.find_similar(conn, texts[query], min_similarity=threshold, limit=100)[
                    "hits"
                ]
                for query in queries
            ]

        indexed = answers()
        with monkeypatch.context() as patch:
            patch.setattr(match_index, "uses_index", lambda score: False)
            pairwise = answers()

        assert any(indexed)
        assert indexed == pairwise

    def test_a_hidden_binary_is_never_a_hit(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        texts = self._cached_corpus(conn)
        base = min(texts)
        function = store.get_function(conn, base + 1)
        assert function is not None
        hidden = int(function["binary_id"])
        visible = frozenset(
            int(row["id"]) for row in conn.execute("SELECT id FROM binaries") if row["id"] != hidden
        )
        monkeypatch.setattr(matching, "resolve_scope", lambda *args, **kwargs: visible)

        everyone = matching.find_similar(conn, texts[base])
        scoped = matching.find_similar(conn, texts[base], visible_to={"id": 1})

        assert hidden in {hit["binary_id"] for hit in everyone["hits"]}
        assert scoped["hits"]
        assert all(hit["binary_id"] != hidden for hit in scoped["hits"])
