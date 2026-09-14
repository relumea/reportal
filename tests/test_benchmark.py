"""Tests for reportal.benchmark: labels, metrics and the scored run.

The run's scorer and disassembler are injected, so the metric tests are exact
and need neither the engine nor the optional extra.  The route, the CLI and the
MCP tests that reach the real matcher are skipped without that extra.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import FakeEngine, json_body, wsgi_request
from typer.testing import CliRunner

from reportal import benchmark, cli, engines, matching, mcp_server, similarity, store

runner = CliRunner()

HAS_SIMILARITY = similarity.available()
requires_similarity = pytest.mark.skipif(
    not HAS_SIMILARITY, reason="similarity extra not installed"
)

# Deterministic pair scores over the seeded names: the labelled counterpart is
# the best candidate for `crc32_init`, the second for `inflate_block`.
PAIR_SCORES: dict[tuple[str, str], float] = {
    ("asm:crc32_init", "asm:crc32_init"): 95.0,
    ("asm:crc32_init", "asm:inflate_block"): 70.0,
    ("asm:inflate_block", "asm:crc32_init"): 97.0,
    ("asm:inflate_block", "asm:inflate_block"): 96.0,
    ("asm:sub_3000", "asm:crc32_init"): 40.0,
}


def _get(path: str) -> Any:
    """Issue a GET and return its JSON body, asserting the 200."""
    status, headers, body = wsgi_request("GET", path)
    assert status.startswith("200"), body
    return json_body(body, headers)


def _post(path: str, payload: dict[str, Any]) -> tuple[str, Any]:
    """Issue a POST with a JSON body and return its status and JSON body."""
    status, headers, body = wsgi_request(
        "POST",
        path,
        body=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    return status, json_body(body, headers)


def _disassembler(function: dict[str, Any]) -> str | None:
    return f"asm:{function['name']}"


def _scorer(left: str, right: str) -> float:
    return PAIR_SCORES.get((left, right), 0.0)


def _seed(conn: sqlite3.Connection) -> dict[str, int]:
    """Two binaries of three functions each, with shared and private names."""
    left = store.add_binary(conn, sha256="aa" * 32, name="a.exe")
    analysis_left = store.create_analysis(conn, binary_id=left, engine="manual")
    ids = {"left": left, "right": store.add_binary(conn, sha256="bb" * 32, name="b.exe")}
    analysis_right = store.create_analysis(conn, binary_id=ids["right"], engine="manual")
    ids["a1"] = store.add_function(
        conn, analysis_id=analysis_left, va=0x1000, name="crc32_init", size=32
    )
    ids["a2"] = store.add_function(
        conn, analysis_id=analysis_left, va=0x2000, name="inflate_block", size=48
    )
    ids["a3"] = store.add_function(
        conn, analysis_id=analysis_left, va=0x3000, name="sub_3000", size=16
    )
    ids["b1"] = store.add_function(
        conn, analysis_id=analysis_right, va=0x4000, name="crc32_init", size=32
    )
    ids["b2"] = store.add_function(
        conn, analysis_id=analysis_right, va=0x5000, name="inflate_block", size=48
    )
    store.add_function(conn, analysis_id=analysis_right, va=0x6000, name="write_log", size=24)
    return ids


def _run(conn: sqlite3.Connection, ids: dict[str, int], **kwargs: Any) -> dict[str, Any]:
    """Run the benchmark with the injected scorer and an available stub engine."""
    return benchmark.run(
        conn,
        left_binary_id=ids["left"],
        right_binary_id=ids["right"],
        engine=engines.RebrewEngine(enabled=False),
        scorer=_scorer,
        disassembler=_disassembler,
        **kwargs,
    )


class TestLabels:
    def test_shared_real_names_become_labels(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        labels = benchmark.labels_from_names(conn, ids["left"], ids["right"])
        assert labels == [
            {"name": "crc32_init", "left_va": 0x1000, "right_va": 0x4000},
            {"name": "inflate_block", "left_va": 0x2000, "right_va": 0x5000},
        ]

    def test_a_placeholder_name_is_not_a_label(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        analysis = store.latest_analysis_for_binary(conn, ids["right"])
        assert analysis is not None
        store.add_function(conn, analysis_id=analysis, va=0x3000, name="sub_3000", size=16)
        labels = benchmark.labels_from_names(conn, ids["left"], ids["right"])
        assert all(entry["name"] != "sub_3000" for entry in labels)
        assert len(labels) == 2

    def test_an_ambiguous_name_labels_nothing(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        analysis = store.latest_analysis_for_binary(conn, ids["left"])
        assert analysis is not None
        store.add_function(conn, analysis_id=analysis, va=0x7000, name="crc32_init", size=32)
        labels = benchmark.labels_from_names(conn, ids["left"], ids["right"])
        assert [entry["name"] for entry in labels] == ["inflate_block"]

    def test_every_shared_name_is_a_label(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        assert len(benchmark.labels_from_names(conn, ids["left"], ids["right"])) == 2

    def test_a_name_only_one_side_has_is_not_a_label(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        labels = benchmark.labels_from_names(conn, ids["left"], ids["right"])
        assert all(entry["name"] != "write_log" for entry in labels)


class TestLoadLabels:
    def test_a_corpus_file_is_read(self, tmp_path: Path) -> None:
        path = tmp_path / "corpus.json"
        path.write_text(
            json.dumps({"pairs": [{"left_va": "0x1000", "right_va": 4096}]}), encoding="utf-8"
        )
        assert benchmark.load_labels(path) == [{"left_va": "0x1000", "right_va": 4096}]

    def test_a_non_object_corpus_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "corpus.json"
        path.write_text("[1, 2]", encoding="utf-8")
        with pytest.raises(benchmark.BenchmarkError) as failure:
            benchmark.load_labels(path)
        assert failure.value.code == "invalid-labels"

    def test_a_corpus_without_pairs_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "corpus.json"
        path.write_text('{"rows": []}', encoding="utf-8")
        with pytest.raises(benchmark.BenchmarkError) as failure:
            benchmark.load_labels(path)
        assert "pairs" in failure.value.detail

    def test_a_pair_that_is_not_an_object_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "corpus.json"
        path.write_text('{"pairs": ["0x1000"]}', encoding="utf-8")
        with pytest.raises(benchmark.BenchmarkError) as failure:
            benchmark.load_labels(path)
        assert "pairs[0]" in failure.value.detail

    def test_a_missing_file_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(benchmark.BenchmarkError) as failure:
            benchmark.load_labels(tmp_path / "gone.json")
        assert "cannot read" in failure.value.detail


class TestMetrics:
    def _labels(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "a1",
                "left_va": 0x1000,
                "left_function_id": 1,
                "right_va": 0x4000,
                "right_function_id": 11,
            },
            {
                "name": "a2",
                "left_va": 0x2000,
                "left_function_id": 2,
                "right_va": 0x5000,
                "right_function_id": 12,
            },
        ]

    def _rows(self) -> list[dict[str, Any]]:
        return [
            {"source_function_id": 1, "candidate_function_id": 11, "similarity": 95.0},
            {"source_function_id": 1, "candidate_function_id": 12, "similarity": 70.0},
            {"source_function_id": 2, "candidate_function_id": 11, "similarity": 90.0},
            {"source_function_id": 2, "candidate_function_id": 12, "similarity": 60.0},
        ]

    def test_a_perfect_run_scores_one(self) -> None:
        rows = [self._rows()[0], self._rows()[3]]
        scored = benchmark.metrics(self._labels(), rows, top=10)
        assert scored["precision"] == 1.0
        assert scored["recall"] == 1.0
        assert scored["f1"] == 1.0
        assert scored["mrr"] == 1.0
        assert scored["mean_rank"] == 1.0

    def test_a_hit_at_rank_two_halves_the_reciprocal_rank(self) -> None:
        scored = benchmark.metrics(self._labels(), self._rows(), top=10)
        assert scored["hits"] == 2
        assert scored["retrieved"] == 4
        assert scored["precision"] == 0.5
        assert scored["recall"] == 1.0
        assert scored["mrr"] == 0.75
        assert [entry["rank"] for entry in scored["detail"]] == [1, 2]

    def test_a_miss_is_reported_and_scores_zero(self) -> None:
        rows = [self._rows()[1], self._rows()[2]]
        scored = benchmark.metrics(self._labels(), rows, top=10)
        assert scored["hits"] == 0
        assert scored["recall"] == 0.0
        assert scored["mrr"] == 0.0
        assert scored["mean_rank"] is None
        assert [entry["rank"] for entry in scored["detail"]] == [None, None]
        assert len(scored["misses"]) == 2

    def test_the_top_cap_hides_a_lower_ranked_hit(self) -> None:
        scored = benchmark.metrics(self._labels(), self._rows(), top=1)
        assert scored["retrieved"] == 2
        assert scored["hits"] == 1
        assert scored["recall"] == 0.5
        assert [entry["rank"] for entry in scored["detail"]] == [1, None]

    def test_no_labels_scores_zero_without_dividing_by_zero(self) -> None:
        scored = benchmark.metrics([], [], top=10)
        assert scored["queries"] == 0
        assert scored["precision"] == 0.0
        assert scored["recall"] == 0.0
        assert scored["f1"] == 0.0
        assert scored["mrr"] == 0.0

    def test_a_query_with_no_retrieval_still_counts(self) -> None:
        scored = benchmark.metrics(self._labels(), [self._rows()[0]], top=10)
        assert scored["queries"] == 2
        assert scored["retrieved"] == 1
        assert scored["recall"] == 0.5


class TestRun:
    def test_the_run_scores_the_labels_it_derived(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        payload = _run(conn, ids)
        assert payload["label_source"] == "names"
        assert payload["labels"]["count"] == 2
        assert payload["metrics"]["queries"] == 2
        assert payload["metrics"]["hits"] == 2
        assert payload["metrics"]["retrieved"] == 3
        assert payload["metrics"]["mrr"] == 0.75
        assert payload["metrics"]["precision"] == 0.6667
        assert payload["metrics"]["recall"] == 1.0
        assert payload["stored"] is True
        assert payload["matching"]["pairs"] == 3
        assert payload["settings"]["binary_ids"] == [ids["right"]]
        assert payload["settings"]["include_self"] is False
        assert any("name transfer gets right for free" in note for note in payload["notes"])

    def test_supplied_labels_are_used_as_the_ground_truth(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        payload = _run(
            conn,
            ids,
            labels=[{"left_va": "0x1000", "right_va": "0x5000"}],
        )
        assert payload["label_source"] == "corpus"
        assert payload["labels"]["count"] == 1
        assert payload["metrics"]["queries"] == 1
        assert payload["metrics"]["hits"] == 0
        assert payload["metrics"]["detail"][0]["rank"] is None

    def test_a_label_that_names_no_function_is_reported(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        payload = _run(
            conn,
            ids,
            labels=[
                {"left_va": "0x1000", "right_va": "0x4000"},
                {"left_va": "0x9999", "right_va": "0x4000"},
            ],
        )
        assert payload["labels"]["count"] == 1
        assert payload["labels"]["unmatched"] == [
            {
                "left_va": 0x9999,
                "right_va": 0x4000,
                "reason": "no function at 0x9999 in the left binary",
            }
        ]
        assert any("name no stored function" in note for note in payload["notes"])

    def test_labels_that_resolve_to_nothing_are_refused(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        with pytest.raises(benchmark.BenchmarkError) as failure:
            _run(conn, ids, labels=[{"left_va": "0x9999", "right_va": "0x9999"}])
        assert failure.value.code == "no-labels"

    def test_a_malformed_address_is_refused(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        with pytest.raises(benchmark.BenchmarkError) as failure:
            _run(conn, ids, labels=[{"left_va": "later", "right_va": "0x4000"}])
        assert failure.value.code == "invalid-labels"
        assert "left_va" in failure.value.detail

    def test_a_boolean_address_is_refused(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        with pytest.raises(benchmark.BenchmarkError) as failure:
            _run(conn, ids, labels=[{"left_va": True, "right_va": 0x4000}])
        assert "left_va" in failure.value.detail

    def test_a_label_that_is_not_an_object_is_refused(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        with pytest.raises(benchmark.BenchmarkError) as failure:
            _run(conn, ids, labels=["0x1000"])
        assert "labels[0]" in failure.value.detail

    def test_a_truncated_label_list_says_so(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(conn)
        monkeypatch.setattr(benchmark, "MAX_LABELS", 1)
        payload = _run(
            conn,
            ids,
            labels=[
                {"left_va": "0x1000", "right_va": "0x4000"},
                {"left_va": "0x2000", "right_va": "0x5000"},
            ],
        )
        assert payload["labels"]["count"] == 1
        assert payload["labels"]["truncated"] is True
        assert any("were scored" in note for note in payload["notes"])

    def test_a_pair_without_an_address_is_refused(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        with pytest.raises(benchmark.BenchmarkError) as failure:
            _run(conn, ids, labels=[{"left_va": 0x1000}])
        assert "right_va" in failure.value.detail

    def test_two_binaries_that_share_no_name_have_no_labels(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        analysis = store.latest_analysis_for_binary(conn, ids["right"])
        assert analysis is not None
        for function in store.list_functions(conn, binary_id=ids["right"]):
            store.rename_function(
                conn, int(function["id"]), new_name=f"x_{function['id']}", actor="test"
            )
        with pytest.raises(benchmark.BenchmarkError) as failure:
            _run(conn, ids)
        assert failure.value.code == "no-labels"

    def test_the_same_binary_is_refused(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        with pytest.raises(benchmark.BenchmarkError) as failure:
            _run(conn, {**ids, "right": ids["left"]})
        assert failure.value.code == "invalid-labels"
        assert "two different binaries" in failure.value.detail

    def test_an_unknown_partner_is_refused(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        with pytest.raises(benchmark.BenchmarkError) as failure:
            _run(conn, {**ids, "right": 9999})
        assert failure.value.code == "binary not found"

    def test_an_unknown_left_binary_is_refused(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        with pytest.raises(benchmark.BenchmarkError) as failure:
            _run(conn, {**ids, "left": 9999})
        assert failure.value.code == "binary not found"

    def test_the_top_cap_narrows_the_retrieval(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        payload = _run(conn, ids, settings=matching.MatchSettings(top=1))
        assert payload["settings"]["top"] == 1
        assert payload["metrics"]["top"] == 1
        assert payload["metrics"]["retrieved"] == 2
        assert payload["metrics"]["recall"] == 0.5

    def test_a_scored_run_records_the_matches(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _run(conn, ids)
        rows = matching.binary_match_rows(conn, ids["left"])
        assert len(rows) == 3
        assert all(row["candidate_name"] in {"crc32_init", "inflate_block"} for row in rows)

    def test_a_run_that_records_nothing_says_so(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        payload = _run(conn, ids, settings=matching.MatchSettings(min_similarity=99.0))
        assert payload["matching"]["pairs"] == 0
        assert payload["metrics"]["retrieved"] == 0
        assert any("lower min_similarity" in note for note in payload["notes"])


class TestDescribe:
    def test_an_unscored_binary_reads_empty(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        payload = benchmark.describe(conn, ids["left"])
        assert payload["stored"] is False
        assert payload["metrics"] is None
        assert "reportal benchmark" in payload["notes"][0]

    def test_an_unknown_binary_is_refused(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(benchmark.BenchmarkError) as failure:
            benchmark.describe(conn, 9999)
        assert failure.value.code == "binary not found"


class TestRoutes:
    def test_post_scores_and_get_serves_the_stored_run(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        fake_engine: FakeEngine,
    ) -> None:
        ids = _seed(conn)
        store.set_rebrew_context(conn, ids["left"], str(tmp_path))
        status, payload = _post(
            f"/api/binaries/{ids['left']}/benchmark",
            {"right_binary_id": ids["right"], "min_similarity": 0},
        )
        assert status.startswith("200"), payload
        assert payload.pop("journal_action")
        assert payload["label_source"] == "names"
        assert payload["metrics"]["queries"] == 2
        assert payload["settings"]["binary_ids"] == [ids["right"]]

        served = _get(f"/api/binaries/{ids['left']}/benchmark")
        assert served["stored"] is True
        assert served["metrics"]["queries"] == 2
        assert served["left"]["binary_id"] == ids["left"]

    def test_get_before_a_run_is_empty(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        payload = _get(f"/api/binaries/{ids['left']}/benchmark")
        assert payload == {
            "binary_id": ids["left"],
            "binary_name": "a.exe",
            "stored": False,
            "metrics": None,
            "notes": [
                f"no stored benchmark scan; run 'reportal benchmark {ids['left']} <right-id>'"
            ],
        }

    def test_an_unknown_binary_is_a_404(self, conn: sqlite3.Connection) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/9999/benchmark")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_a_missing_partner_is_a_400(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, payload = _post(f"/api/binaries/{ids['left']}/benchmark", {})
        assert status.startswith("400")
        assert payload["error"] == "invalid right_binary_id"

    def test_labels_that_are_not_a_list_are_a_400(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, payload = _post(
            f"/api/binaries/{ids['left']}/benchmark",
            {"right_binary_id": ids["right"], "labels": "0x1000"},
        )
        assert status.startswith("400")
        assert payload["error"] == "invalid labels"

    def test_the_same_binary_is_a_400(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, payload = _post(
            f"/api/binaries/{ids['left']}/benchmark", {"right_binary_id": ids["left"]}
        )
        assert status.startswith("400")
        assert payload["error"] == "invalid-labels"

    def test_a_bad_setting_is_a_400(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, payload = _post(
            f"/api/binaries/{ids['left']}/benchmark",
            {"right_binary_id": ids["right"], "top": 0},
        )
        assert status.startswith("400")
        assert payload["error"] == "top must be positive"

    def test_without_the_similarity_extra_it_is_a_503(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(conn)
        monkeypatch.setattr(similarity, "available", lambda: False)
        status, payload = _post(
            f"/api/binaries/{ids['left']}/benchmark",
            {
                "right_binary_id": ids["right"],
                "labels": [{"left_va": 0x1000, "right_va": 0x4000}],
            },
        )
        assert status.startswith("503")
        assert payload["error"] == "similarity-unavailable"

    def test_labels_that_resolve_to_nothing_are_a_400(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, payload = _post(
            f"/api/binaries/{ids['left']}/benchmark",
            {
                "right_binary_id": ids["right"],
                "labels": [{"left_va": 0x7777, "right_va": 0x7777}],
            },
        )
        assert status.startswith("400")
        assert payload["error"] == "no-labels"


class TestMcp:
    def test_the_read_and_the_run_answer(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        payload, failed = mcp_server.call_tool("get_benchmark", {"binary_id": ids["left"]})
        assert failed is False
        assert payload["stored"] is False

        run, failed = mcp_server.call_tool("get_benchmark", {"binary_id": 9999})
        assert failed is True
        assert run["error"] == "binary not found"

    def test_a_run_without_labels_is_a_tool_error(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        payload, failed = mcp_server.call_tool(
            "run_benchmark",
            {
                "binary_id": ids["left"],
                "right_binary_id": ids["right"],
                "labels": [{"left_va": 0x7777, "right_va": 0x7777}],
            },
        )
        assert failed is True
        assert payload["error"] == "no-labels"

    def test_without_the_similarity_extra_it_is_a_tool_error(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(conn)
        monkeypatch.setattr(similarity, "available", lambda: False)
        payload, failed = mcp_server.call_tool(
            "run_benchmark",
            {
                "binary_id": ids["left"],
                "right_binary_id": ids["right"],
                "labels": [{"left_va": 0x1000, "right_va": 0x4000}],
            },
        )
        assert failed is True
        assert payload["error"] == "similarity-unavailable"

    def test_labels_that_are_not_a_list_are_a_tool_error(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        payload, failed = mcp_server.call_tool(
            "run_benchmark",
            {"binary_id": ids["left"], "right_binary_id": ids["right"], "labels": "0x1000"},
        )
        assert failed is True
        assert payload["error"] == "invalid params"


class TestCli:
    @requires_similarity
    def test_the_labels_file_scores_the_run(
        self,
        portal_db: Path,
        conn: sqlite3.Connection,
        tmp_path: Path,
        fake_engine: FakeEngine,
    ) -> None:
        ids = _seed(conn)
        store.set_rebrew_context(conn, ids["left"], str(tmp_path))
        corpus = tmp_path / "corpus.json"
        corpus.write_text(
            json.dumps({"pairs": [{"left_va": "0x1000", "right_va": "0x4000"}]}), encoding="utf-8"
        )
        conn.commit()
        result = runner.invoke(
            cli.app,
            [
                "benchmark",
                str(ids["left"]),
                str(ids["right"]),
                "--labels",
                str(corpus),
                "--min-similarity",
                "0",
                "--json",
            ],
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["label_source"] == "corpus"
        assert payload["labels"]["count"] == 1
        assert "journal_action" in payload
        stored = benchmark.describe(conn, ids["left"])
        assert stored["stored"] is True
        assert stored["metrics"]["queries"] == 1

    @requires_similarity
    def test_benchmark_info_prints_the_stored_run(
        self,
        portal_db: Path,
        conn: sqlite3.Connection,
        tmp_path: Path,
        fake_engine: FakeEngine,
    ) -> None:
        ids = _seed(conn)
        store.set_rebrew_context(conn, ids["left"], str(tmp_path))
        conn.commit()
        run = runner.invoke(
            cli.app, ["benchmark", str(ids["left"]), str(ids["right"]), "--min-similarity", "0"]
        )
        assert run.exit_code == 0, run.output

        result = runner.invoke(cli.app, ["benchmark-info", str(ids["left"])])
        assert result.exit_code == 0, result.output
        assert "precision" in result.output
        assert "queries" in result.output

        empty = runner.invoke(cli.app, ["benchmark-info", str(ids["right"])])
        assert empty.exit_code == 0, empty.output
        assert "no stored benchmark scan" in empty.output

    def test_an_unknown_binary_fails_loud(self, portal_db: Path, conn: sqlite3.Connection) -> None:
        conn.commit()
        result = runner.invoke(cli.app, ["benchmark-info", "9999"])
        assert result.exit_code == 1
        assert "binary not found" in result.output

    @requires_similarity
    def test_the_real_scorer_reaches_the_cli(
        self,
        portal_db: Path,
        conn: sqlite3.Connection,
        tmp_path: Path,
        fake_engine: FakeEngine,
    ) -> None:
        ids = _seed(conn)
        store.set_rebrew_context(conn, ids["left"], str(tmp_path))
        conn.commit()
        result = runner.invoke(
            cli.app, ["benchmark", str(ids["left"]), str(ids["right"]), "--min-similarity", "0"]
        )
        assert result.exit_code == 0, result.output
        assert "precision" in result.output
        assert "recall" in result.output
