"""Tests for the deterministic knowledge graph: build, payload and neighbors."""

from __future__ import annotations

import sqlite3

import pytest
from graph_helpers import (
    CAPABILITY_NAME,
    DOCUMENT_TITLE,
    FLIRT_NAME,
    FUNCTION_NAME,
    LIBRARY_MODULE,
    MATCH_SIMILARITY,
    SECOND_FUNCTION_NAME,
    STRUCT_NAME,
    STRUCT_VA,
    TAG_NAME,
    TRIAGE_LIBRARY_CONFIDENCE,
    node_id,
    ordered,
    relations,
    seed_corpus,
)

from reportal import graph, knowledge, store

CORPUS_NODE_KINDS = {
    "binary",
    "function",
    "document",
    "struct",
    "tag",
    "capability",
    "library",
}

CORPUS_RELATIONS = {
    "contains",
    "documented-by",
    "has-capability",
    "has-tag",
    "recovered",
    "identifies",
    "matched-with",
    "mentions",
}


class TestEntityMentions:
    def test_name_matches_at_a_word_boundary(self) -> None:
        text = f"the {FUNCTION_NAME} routine handles this"
        assert graph.entity_mentions(text, names={FUNCTION_NAME}) == {FUNCTION_NAME}

    def test_name_inside_a_longer_identifier_does_not_match(self) -> None:
        text = f"call my{FUNCTION_NAME}X now"
        assert graph.entity_mentions(text, names={FUNCTION_NAME}) == set()

    def test_short_name_is_rejected(self) -> None:
        assert graph.entity_mentions("abc abd", names={"abc"}) == set()

    def test_name_at_the_minimum_length_matches(self) -> None:
        assert graph.entity_mentions("see sub_ here", names={"sub_"}) == {"sub_"}

    def test_va_literals_are_canonicalized(self) -> None:
        text = "at 0x00401000, again 0X401000, and 0xdeadbeef"
        assert graph.entity_mentions(text, names=set()) == {"0x401000", "0xdeadbeef"}

    def test_va_literal_inside_an_identifier_is_not_a_literal(self) -> None:
        assert graph.entity_mentions("a0x1234", names=set()) == set()

    def test_va_literal_with_a_trailing_word_character_is_not_a_literal(self) -> None:
        assert graph.entity_mentions("0x12z", names=set()) == set()

    def test_va_literal_needs_hex_digits(self) -> None:
        assert graph.entity_mentions("0xZZ and 0x", names=set()) == set()

    def test_names_and_literals_come_back_together(self) -> None:
        text = f"{FUNCTION_NAME} lives at 0x1000"
        assert graph.entity_mentions(text, names={FUNCTION_NAME}) == {FUNCTION_NAME, "0x1000"}

    def test_empty_text_mentions_nothing(self) -> None:
        assert graph.entity_mentions("", names={FUNCTION_NAME}) == set()


class TestBuildGraph:
    def test_every_node_kind_is_built(self, conn: sqlite3.Connection) -> None:
        ids = seed_corpus(conn)
        graph.build_graph(conn, binary_id=ids["binary"])
        kinds = {node["kind"] for node in store.list_graph_nodes(conn, ids["binary"])}
        assert kinds == CORPUS_NODE_KINDS

    def test_every_relation_is_built(self, conn: sqlite3.Connection) -> None:
        ids = seed_corpus(conn)
        graph.build_graph(conn, binary_id=ids["binary"])
        edges = store.list_graph_edges(conn, ids["binary"])
        assert relations(edges) == CORPUS_RELATIONS

    def test_binary_links_to_each_entity(self, conn: sqlite3.Connection) -> None:
        ids = seed_corpus(conn)
        graph.build_graph(conn, binary_id=ids["binary"])
        binary = node_id(ids["binary"], "binary", ids["binary"])
        linked = {
            (edge["rel"], edge["target"])
            for edge in store.list_graph_edges(conn, ids["binary"])
            if edge["source"] == binary
        }
        assert ("contains", node_id(ids["binary"], "function", ids["first"])) in linked
        assert ("contains", node_id(ids["binary"], "function", ids["second"])) in linked
        assert ("documented-by", node_id(ids["binary"], "document", ids["document"])) in linked
        assert ("recovered", node_id(ids["binary"], "struct", STRUCT_NAME)) in linked
        assert ("has-tag", node_id(ids["binary"], "tag", ids["tag"])) in linked
        assert (
            "has-capability",
            node_id(ids["binary"], "capability", CAPABILITY_NAME),
        ) in linked
        assert ("identifies", node_id(ids["binary"], "library", LIBRARY_MODULE)) in linked

    def test_matched_with_carries_the_similarity(self, conn: sqlite3.Connection) -> None:
        ids = seed_corpus(conn)
        graph.build_graph(conn, binary_id=ids["binary"])
        edge = next(
            edge
            for edge in store.list_graph_edges(conn, ids["binary"])
            if edge["rel"] == "matched-with"
        )
        assert edge["source"] == node_id(ids["binary"], "function", ids["first"])
        assert edge["target"] == node_id(ids["binary"], "function", ids["second"])
        assert edge["weight"] == MATCH_SIMILARITY

    def test_cross_binary_match_candidate_is_skipped(self, conn: sqlite3.Connection) -> None:
        ids = seed_corpus(conn)
        other_binary = store.add_binary(conn, sha256="cd" * 32, name="other.exe")
        other_analysis = store.create_analysis(conn, binary_id=other_binary, engine="manual")
        outsider = store.add_function(
            conn, analysis_id=other_analysis, va=0x9000, name="Foreign", size=8
        )
        store.record_match(
            conn,
            function_id=ids["first"],
            candidate_function_id=outsider,
            similarity=50.0,
            confidence=0.5,
        )
        graph.build_graph(conn, binary_id=ids["binary"])
        assert node_id(ids["binary"], "function", outsider) not in {
            node["id"] for node in store.list_graph_nodes(conn, ids["binary"])
        }
        targets = {
            edge["target"]
            for edge in store.list_graph_edges(conn, ids["binary"])
            if edge["rel"] == "matched-with"
        }
        assert targets == {node_id(ids["binary"], "function", ids["second"])}

    def test_document_mentions_a_function_by_name_and_by_va(self, conn: sqlite3.Connection) -> None:
        ids = seed_corpus(conn)
        graph.build_graph(conn, binary_id=ids["binary"])
        document = node_id(ids["binary"], "document", ids["document"])
        targets = {
            edge["target"]
            for edge in store.list_graph_edges(conn, ids["binary"])
            if edge["source"] == document and edge["rel"] == "mentions"
        }
        assert targets == {
            node_id(ids["binary"], "function", ids["first"]),
            node_id(ids["binary"], "struct", STRUCT_NAME),
        }

    def test_a_va_mention_matches_the_padded_form(self, conn: sqlite3.Connection) -> None:
        ids = seed_corpus(conn)
        graph.build_graph(conn, binary_id=ids["binary"])
        document = node_id(ids["binary"], "document", ids["document"])
        struct_edge = next(
            edge
            for edge in store.list_graph_edges(conn, ids["binary"])
            if edge["source"] == document and edge["target"].endswith(f"struct:{STRUCT_NAME}")
        )
        assert struct_edge["meta"]["token"] == f"0x{STRUCT_VA:x}"

    def test_absent_entity_name_creates_no_mention_edge(self, conn: sqlite3.Connection) -> None:
        ids = seed_corpus(conn)
        store.set_scan(
            conn,
            ids["analysis"],
            store.SCAN_KIND_STRUCTS,
            {"decompiled": 0, "skipped": 0, "structs": []},
        )
        graph.build_graph(conn, binary_id=ids["binary"])
        document = node_id(ids["binary"], "document", ids["document"])
        mentioned = {
            edge["target"]
            for edge in store.list_graph_edges(conn, ids["binary"])
            if edge["source"] == document and edge["rel"] == "mentions"
        }
        assert mentioned == {node_id(ids["binary"], "function", ids["first"])}

    def test_unnamed_function_gets_a_placeholder_label(self, conn: sqlite3.Connection) -> None:
        ids = seed_corpus(conn)
        store.add_function(conn, analysis_id=ids["analysis"], va=0x4000, name="", size=8)
        graph.build_graph(conn, binary_id=ids["binary"])
        labels = {
            node["label"]
            for node in store.list_graph_nodes(conn, ids["binary"])
            if node["kind"] == "function"
        }
        assert "sub_4000" in labels

    def test_a_binary_without_functions_holds_only_the_binary_node(
        self, conn: sqlite3.Connection
    ) -> None:
        binary_id = store.add_binary(conn, sha256="ef" * 32, name="bare.exe")
        result = graph.build_graph(conn, binary_id=binary_id)
        assert result["nodes"] == 1
        assert result["edges"] == 0
        assert store.list_graph_nodes(conn, binary_id)[0]["kind"] == "binary"

    def test_build_reports_counts_and_timestamp(self, conn: sqlite3.Connection) -> None:
        ids = seed_corpus(conn)
        result = graph.build_graph(conn, binary_id=ids["binary"])
        assert result["binary_id"] == ids["binary"]
        assert result["nodes"] == len(store.list_graph_nodes(conn, ids["binary"]))
        assert result["edges"] == len(store.list_graph_edges(conn, ids["binary"]))
        assert result["truncated"] is False
        assert result["built_at"].endswith("+00:00")

    def test_rebuild_produces_identical_rows(self, conn: sqlite3.Connection) -> None:
        ids = seed_corpus(conn)
        graph.build_graph(conn, binary_id=ids["binary"])
        first_nodes = ordered(store.list_graph_nodes(conn, ids["binary"]))
        first_edges = ordered(store.list_graph_edges(conn, ids["binary"]))
        graph.build_graph(conn, binary_id=ids["binary"])
        assert ordered(store.list_graph_nodes(conn, ids["binary"])) == first_nodes
        assert ordered(store.list_graph_edges(conn, ids["binary"])) == first_edges

    def test_rebuild_drops_a_fact_that_is_gone(self, conn: sqlite3.Connection) -> None:
        ids = seed_corpus(conn)
        graph.build_graph(conn, binary_id=ids["binary"])
        document_node = node_id(ids["binary"], "document", ids["document"])
        assert store.get_graph_node(conn, document_node) is not None
        store.delete_document(conn, ids["document"])
        graph.build_graph(conn, binary_id=ids["binary"])
        assert store.get_graph_node(conn, document_node) is None

    def test_unknown_binary_raises_keyerror(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(KeyError):
            graph.build_graph(conn, binary_id=4242)

    def test_library_nodes_merge_the_stored_sources(self, conn: sqlite3.Connection) -> None:
        ids = seed_corpus(conn)
        graph.build_graph(conn, binary_id=ids["binary"])
        modules = {
            node["key"]: node
            for node in store.list_graph_nodes(conn, ids["binary"])
            if node["kind"] == "library"
        }
        assert set(modules) == {LIBRARY_MODULE, FLIRT_NAME}
        assert modules[LIBRARY_MODULE]["meta"]["source"] == "unstrip"
        assert modules[LIBRARY_MODULE]["meta"]["kind"] == "import"
        assert modules[LIBRARY_MODULE]["meta"]["confidence"] == TRIAGE_LIBRARY_CONFIDENCE
        assert modules[FLIRT_NAME]["meta"]["kind"] == "flirt"

    def test_proposals_without_a_module_fall_back_to_their_kind(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = seed_corpus(conn)
        store.set_scan(
            conn,
            ids["analysis"],
            store.SCAN_KIND_UNSTRIP,
            {
                "candidates": 1,
                "proposals": [
                    {
                        "function_id": ids["first"],
                        "va": 0x1000,
                        "module": "",
                        "kind": "crt",
                        "confidence": 0.4,
                    }
                ],
                "applied": False,
            },
        )
        graph.build_graph(conn, binary_id=ids["binary"])
        keys = {
            node["key"]
            for node in store.list_graph_nodes(conn, ids["binary"])
            if node["kind"] == "library"
        }
        assert "crt" in keys

    def test_node_cap_stops_cleanly_and_records_the_truncation(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_corpus(conn)
        monkeypatch.setattr(graph, "MAX_GRAPH_NODES", 3)
        result = graph.build_graph(conn, binary_id=ids["binary"])
        assert result["truncated"] is True
        nodes = store.list_graph_nodes(conn, ids["binary"])
        assert len(nodes) == 3
        node_ids = {node["id"] for node in nodes}
        for edge in store.list_graph_edges(conn, ids["binary"]):
            assert edge["source"] in node_ids
            assert edge["target"] in node_ids
        assert graph.graph_payload(conn, binary_id=ids["binary"])["truncated"] is True

    def test_edge_cap_stops_cleanly_and_records_the_truncation(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_corpus(conn)
        monkeypatch.setattr(graph, "MAX_GRAPH_EDGES", 1)
        result = graph.build_graph(conn, binary_id=ids["binary"])
        assert result["truncated"] is True
        edges = store.list_graph_edges(conn, ids["binary"])
        assert len(edges) == 1
        assert edges[0]["rel"] == "contains"


class TestGraphPayload:
    def test_documents_are_left_out_by_default(self, conn: sqlite3.Connection) -> None:
        ids = seed_corpus(conn)
        graph.build_graph(conn, binary_id=ids["binary"])
        payload = graph.graph_payload(conn, binary_id=ids["binary"])
        assert {node["kind"] for node in payload["nodes"]} == CORPUS_NODE_KINDS - {"document"}
        assert "mentions" not in {edge["rel"] for edge in payload["edges"]}
        assert payload["counts"]["document"] == 0

    def test_include_documents_adds_the_document_nodes_and_mentions(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = seed_corpus(conn)
        graph.build_graph(conn, binary_id=ids["binary"])
        payload = graph.graph_payload(conn, binary_id=ids["binary"], include_documents=True)
        assert payload["counts"]["document"] == 1
        assert "mentions" in {edge["rel"] for edge in payload["edges"]}

    def test_kind_filter_keeps_one_kind_and_its_edges(self, conn: sqlite3.Connection) -> None:
        ids = seed_corpus(conn)
        graph.build_graph(conn, binary_id=ids["binary"])
        payload = graph.graph_payload(conn, binary_id=ids["binary"], kind="function")
        assert {node["kind"] for node in payload["nodes"]} == {"function"}
        assert {edge["rel"] for edge in payload["edges"]} == {"matched-with"}

    def test_degrees_count_the_returned_edges(self, conn: sqlite3.Connection) -> None:
        ids = seed_corpus(conn)
        graph.build_graph(conn, binary_id=ids["binary"])
        payload = graph.graph_payload(conn, binary_id=ids["binary"], include_documents=True)
        degrees = {node["id"]: node["degree"] for node in payload["nodes"]}
        assert degrees[node_id(ids["binary"], "binary", ids["binary"])] == 8
        document = next(node for node in payload["nodes"] if node["kind"] == "document")
        assert document["degree"] == 3

    def test_counts_report_every_kind(self, conn: sqlite3.Connection) -> None:
        ids = seed_corpus(conn)
        graph.build_graph(conn, binary_id=ids["binary"])
        counts = graph.graph_payload(conn, binary_id=ids["binary"])["counts"]
        assert set(counts) == set(graph.GRAPH_NODE_KINDS)
        assert counts["function"] == 2
        assert counts["struct"] == 1
        assert counts["library"] == 2

    def test_node_payload_carries_identity_and_meta(self, conn: sqlite3.Connection) -> None:
        ids = seed_corpus(conn)
        graph.build_graph(conn, binary_id=ids["binary"])
        payload = graph.graph_payload(conn, binary_id=ids["binary"])
        node = next(item for item in payload["nodes"] if item["kind"] == "struct")
        assert node["id"] == node_id(ids["binary"], "struct", STRUCT_NAME)
        assert node["key"] == STRUCT_NAME
        assert node["label"] == STRUCT_NAME
        assert node["meta"]["va"] == STRUCT_VA


class TestNeighbors:
    def test_groups_edges_by_relation(self, conn: sqlite3.Connection) -> None:
        ids = seed_corpus(conn)
        graph.build_graph(conn, binary_id=ids["binary"])
        detail = graph.neighbors(conn, node_id=node_id(ids["binary"], "function", ids["first"]))
        assert detail["node"]["label"] == FUNCTION_NAME
        assert set(detail["incoming"]) == {"contains", "mentions"}
        assert set(detail["outgoing"]) == {"matched-with"}
        assert detail["outgoing"]["matched-with"][0]["label"] == SECOND_FUNCTION_NAME
        assert detail["outgoing"]["matched-with"][0]["weight"] == MATCH_SIMILARITY

    def test_document_neighbors_name_the_mentions(self, conn: sqlite3.Connection) -> None:
        ids = seed_corpus(conn)
        graph.build_graph(conn, binary_id=ids["binary"])
        detail = graph.neighbors(conn, node_id=node_id(ids["binary"], "document", ids["document"]))
        assert detail["node"]["label"] == DOCUMENT_TITLE
        assert set(detail["incoming"]) == {"documented-by"}
        assert set(detail["outgoing"]) == {"mentions"}
        labels = {entry["label"] for entry in detail["outgoing"]["mentions"]}
        assert labels == {FUNCTION_NAME, STRUCT_NAME}

    def test_unknown_node_raises_keyerror(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(KeyError):
            graph.neighbors(conn, node_id="b1:function:999")

    def test_node_degree_counts_incident_edges(self, conn: sqlite3.Connection) -> None:
        ids = seed_corpus(conn)
        graph.build_graph(conn, binary_id=ids["binary"])
        detail = graph.neighbors(conn, node_id=node_id(ids["binary"], "function", ids["first"]))
        assert detail["node"]["degree"] == 3


class TestDeleteGraph:
    def test_delete_removes_every_row(self, conn: sqlite3.Connection) -> None:
        ids = seed_corpus(conn)
        graph.build_graph(conn, binary_id=ids["binary"])
        stored = len(store.list_graph_nodes(conn, ids["binary"])) + len(
            store.list_graph_edges(conn, ids["binary"])
        )
        assert store.delete_graph(conn, ids["binary"]) == stored
        assert store.count_graph_nodes(conn, ids["binary"]) == 0
        assert store.count_graph_edges(conn, ids["binary"]) == 0

    def test_delete_of_an_unbuilt_graph_removes_nothing(self, conn: sqlite3.Connection) -> None:
        assert store.delete_graph(conn, 4242) == 0


@pytest.mark.parametrize("kind", sorted(CORPUS_NODE_KINDS))
def test_each_kind_is_a_named_constant(kind: str) -> None:
    assert kind in graph.GRAPH_NODE_KINDS


def test_tag_node_carries_the_tag_name(conn: sqlite3.Connection) -> None:
    ids = seed_corpus(conn)
    graph.build_graph(conn, binary_id=ids["binary"])
    tag = next(
        node for node in store.list_graph_nodes(conn, ids["binary"]) if node["kind"] == "tag"
    )
    assert tag["label"] == TAG_NAME


def test_document_node_counts_its_chunks(conn: sqlite3.Connection) -> None:
    ids = seed_corpus(conn)
    graph.build_graph(conn, binary_id=ids["binary"])
    document = next(
        node for node in store.list_graph_nodes(conn, ids["binary"]) if node["kind"] == "document"
    )
    assert document["meta"]["chunk_count"] == 1


def test_project_scoped_documents_stay_out_of_the_binary_graph(
    conn: sqlite3.Connection,
) -> None:
    ids = seed_corpus(conn)
    knowledge.ingest_document(
        conn,
        scope_kind=knowledge.SCOPE_KIND_PROJECT,
        scope_id=0,
        title="Project note",
        source="notes.md",
        mime="text/markdown",
        data=b"# Project\n\nGeneral notes.\n",
    )
    graph.build_graph(conn, binary_id=ids["binary"])
    documents = [
        node for node in store.list_graph_nodes(conn, ids["binary"]) if node["kind"] == "document"
    ]
    assert [node["label"] for node in documents] == [DOCUMENT_TITLE]
