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

    def test_search_matches_a_namespace(self) -> None:
        selected = data_types.filter_types(TYPES, search="winnt")
        assert [data_type["name"] for data_type in selected] == [
            "WIN_DWORD",
            "WIN_HANDLE",
            "KERNEL_MUTEX",
        ]

    def test_search_matches_namespace_and_name_together(self) -> None:
        selected = data_types.filter_types(TYPES, search="winnt::win_dword")
        assert [data_type["name"] for data_type in selected] == ["WIN_DWORD"]

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


def _sized(name: str, size: int, namespace: str = "") -> dict[str, Any]:
    row = _type(name, namespace=namespace)
    row["size"] = size
    return row


class TestSortTypes:
    SIZED: list[dict[str, Any]] = [
        _sized("Beta", 16),
        _sized("alpha", 0),
        _sized("Gamma", 8),
        _sized("delta", 0),
    ]

    def _names(self, **kwargs: Any) -> list[str]:
        return [row["name"] for row in data_types.sort_types(self.SIZED, **kwargs)]

    def test_name_ascending_is_case_insensitive(self) -> None:
        assert self._names() == ["alpha", "Beta", "delta", "Gamma"]

    def test_name_descending_reverses_it(self) -> None:
        assert self._names(direction="desc") == ["Gamma", "delta", "Beta", "alpha"]

    def test_size_ascending_puts_the_unknown_ones_last(self) -> None:
        assert self._names(sort="size") == ["Gamma", "Beta", "alpha", "delta"]

    def test_size_descending_also_puts_the_unknown_ones_last(self) -> None:
        # A type whose size the model could not state is not the largest one.
        assert self._names(sort="size", direction="desc") == ["Beta", "Gamma", "alpha", "delta"]

    def test_the_default_is_the_order_the_model_was_read_in(self) -> None:
        assert data_types.DEFAULT_TYPE_SORT == "name"
        assert data_types.DEFAULT_SORT_DIRECTION == "asc"
        assert self._names() == self._names(sort="name", direction="asc")

    def test_a_missing_size_reads_as_unknown(self) -> None:
        rows = [{"id": 1, "name": "no-size"}, _sized("sized", 4)]

        assert [row["name"] for row in data_types.sort_types(rows, sort="size")] == [
            "sized",
            "no-size",
        ]

    def test_an_unknown_sort_or_direction_is_a_value_error(self) -> None:
        for kwargs, message in (
            ({"sort": "weight"}, "unknown type sort"),
            ({"direction": "up"}, "unknown sort direction"),
        ):
            try:
                data_types.sort_types(self.SIZED, **kwargs)
            except ValueError as exc:
                assert message in str(exc)
            else:  # pragma: no cover - the assertion is the point
                raise AssertionError(f"{kwargs} must be refused")
