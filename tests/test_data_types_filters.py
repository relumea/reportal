"""Tests for the data-type filters and the namespace tree."""

from __future__ import annotations

from typing import Any

from reportal import data_types


def _type(
    name: str,
    *,
    kind: str = data_types.KIND_STRUCT,
    namespace: str = "",
    members: list[dict[str, Any]] | None = None,
    values: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "id": abs(hash((name, namespace))) % 10_000,
        "name": name,
        "kind": kind,
        "namespace": namespace,
        "members": members or [],
        "values": values or [],
    }


TYPES: list[dict[str, Any]] = [
    _type("NP_HEADER", members=[{"name": "magic"}, {"name": "flags"}]),
    _type("NP_ENTRY", members=[{"name": "va"}, {"name": "next"}]),
    _type("NP_FLAGS", kind=data_types.KIND_ENUM, values=[{"name": "NP_FLAG_A"}]),
    _type("WIN_DWORD", kind=data_types.KIND_TYPEDEF, namespace="winnt"),
    _type("WIN_HANDLE", kind=data_types.KIND_POINTER, namespace="winnt"),
    _type("KERNEL_MUTEX", kind=data_types.KIND_STRUCT, namespace="winnt::kernel"),
]


class TestFilterTypes:
    def test_no_filter_returns_every_type(self) -> None:
        assert data_types.filter_types(TYPES) == TYPES

    def test_kind_filter(self) -> None:
        selected = data_types.filter_types(TYPES, kind=data_types.KIND_ENUM)
        assert [data_type["name"] for data_type in selected] == ["NP_FLAGS"]

    def test_namespace_filter_includes_descendants(self) -> None:
        selected = data_types.filter_types(TYPES, namespace="winnt")
        assert [data_type["name"] for data_type in selected] == [
            "WIN_DWORD",
            "WIN_HANDLE",
            "KERNEL_MUTEX",
        ]

    def test_program_namespace_selects_unqualified_types(self) -> None:
        selected = data_types.filter_types(TYPES, namespace=data_types.PROGRAM_NAMESPACE)
        assert [data_type["name"] for data_type in selected] == [
            "NP_HEADER",
            "NP_ENTRY",
            "NP_FLAGS",
        ]

    def test_unknown_namespace_returns_an_empty_list(self) -> None:
        assert data_types.filter_types(TYPES, namespace="nope") == []

    def test_search_matches_a_member_name(self) -> None:
        selected = data_types.filter_types(TYPES, search="magic")
        assert [data_type["name"] for data_type in selected] == ["NP_HEADER"]

    def test_search_matches_an_enum_value_name(self) -> None:
        selected = data_types.filter_types(TYPES, search="np_flag_a")
        assert [data_type["name"] for data_type in selected] == ["NP_FLAGS"]

    def test_filters_stack(self) -> None:
        selected = data_types.filter_types(TYPES, namespace="winnt", kind=data_types.KIND_POINTER)
        assert [data_type["name"] for data_type in selected] == ["WIN_HANDLE"]


class TestNamespaceTree:
    def test_splits_paths_and_counts_descendants(self) -> None:
        tree = data_types.namespace_tree(TYPES)
        roots = {node["path"]: node for node in tree}
        assert roots["winnt"]["count"] == 3
        children = {node["path"]: node for node in roots["winnt"]["children"]}
        assert children["winnt::kernel"]["count"] == 1

    def test_groups_program_types_under_the_binary_node(self) -> None:
        tree = data_types.namespace_tree(TYPES)
        program = next(node for node in tree if node["path"] == data_types.PROGRAM_NAMESPACE)
        assert program["count"] == 3

    def test_no_namespaces_is_empty_when_every_type_is_program_defined(self) -> None:
        tree = data_types.namespace_tree([_type("Only")])
        assert [node["path"] for node in tree] == [data_types.PROGRAM_NAMESPACE]
