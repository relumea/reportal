"""Tests for reportal.related: relationship signals and the stored ranking scan."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from reportal import auth, engines, related, store

SHA = "aa" * 32
IMPHASH = "11" * 16
RICH = "22" * 8


def _bundle(
    *,
    sha256: str | None = SHA,
    imphash: str | None = None,
    rich: str | None = None,
    imports: list[str] | None = None,
    capabilities: list[str] | None = None,
    fmt: str = "pe",
    arch: str = "x86_32",
    size: int = 1000,
) -> dict[str, Any]:
    return {
        "sha256": sha256,
        "imphash": imphash,
        "rich_header_hash": rich,
        "import_names": imports or [],
        "capabilities": capabilities or [],
        "format": fmt,
        "arch": arch,
        "size": size,
    }


def _binary(
    conn: sqlite3.Connection,
    tmp_path: Path,
    *,
    name: str,
    sha: str,
    size: int = 1000,
    fmt: str = "EXE",
    on_disk: bool = True,
) -> int:
    path = tmp_path / name
    if on_disk:
        path.write_bytes(b"MZ" + name.encode())
    return store.add_binary(conn, sha256=sha, name=name, path=str(path), size=size, fmt=fmt)


def _store_fingerprint(
    conn: sqlite3.Connection,
    binary_id: int,
    *,
    sha256: str | None = None,
    imphash: str | None = None,
    rich: str | None = None,
    fmt: str = "pe",
    arch: str = "x86_32",
    size: int = 1000,
) -> None:
    store.set_fingerprint(
        conn,
        binary_id,
        {
            "sha256": sha256,
            "imphash": imphash,
            "rich_header_hash": rich,
            "format": fmt,
            "arch": arch,
            "size": size,
        },
    )


def _store_capabilities(conn: sqlite3.Connection, binary_id: int, names: list[str]) -> None:
    analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine=store.SCAN_ENGINE)
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_CAPABILITIES,
        {
            "binary_id": binary_id,
            "capabilities": [{"name": name} for name in names],
            "count": len(names),
        },
    )


class _MapEngine:
    """Engine stub keyed by file name, with fixed payloads and a call log."""

    def __init__(self, payloads: dict[str, dict[str, Any]]) -> None:
        self.payloads = payloads
        self.calls: list[str] = []

    def available(self) -> bool:
        return True

    def _payload(self, binary: str | Path) -> dict[str, Any]:
        return self.payloads[Path(str(binary)).name]

    def fingerprint(self, binary: str | Path) -> dict[str, Any]:
        self.calls.append("fingerprint")
        return dict(self._payload(binary)["fingerprint"])

    def imports(self, binary: str | Path) -> dict[str, Any]:
        self.calls.append("imports")
        return dict(self._payload(binary)["imports"])

    def strings(self, binary: str | Path) -> dict[str, Any]:
        self.calls.append("strings")
        return dict(self._payload(binary).get("strings", {"strings": []}))


def _import(name: str) -> dict[str, str]:
    return {"dll": "KERNEL32.dll", "name": name}


class TestRelationshipSignals:
    def test_identical_sha256_is_high(self) -> None:
        result = related.relationship(_bundle(), _bundle())
        assert result["classification"] == related.CLASSIFICATION_IDENTICAL
        assert result["confidence"] == related.CONFIDENCE_HIGH
        assert result["similarity"] == 1.0
        assert [signal["kind"] for signal in result["signals"]] == [related.SIGNAL_IDENTICAL]

    def test_imphash_is_same_imports_high(self) -> None:
        result = related.relationship(
            _bundle(sha256="01" * 32, imphash=IMPHASH),
            _bundle(sha256="02" * 32, imphash=IMPHASH),
        )
        assert result["classification"] == related.CLASSIFICATION_SAME_IMPORTS
        assert result["confidence"] == related.CONFIDENCE_HIGH
        assert result["signals"][0]["kind"] == related.SIGNAL_SAME_IMPORTS

    def test_rich_header_is_same_toolchain_medium(self) -> None:
        result = related.relationship(
            _bundle(sha256="01" * 32, rich=RICH, fmt="pe", arch="x86_32"),
            _bundle(sha256="02" * 32, rich=RICH, fmt="elf", arch="x86_64"),
        )
        assert result["classification"] == related.CLASSIFICATION_SAME_TOOLCHAIN
        assert result["confidence"] == related.CONFIDENCE_MEDIUM
        assert result["signals"][0]["kind"] == related.SIGNAL_SAME_TOOLCHAIN

    def test_import_jaccard_at_the_threshold_is_similar_lifecycle(self) -> None:
        result = related.relationship(
            _bundle(sha256="01" * 32, imports=["a", "b", "c", "d"], fmt="elf", arch="x86_64"),
            _bundle(sha256="02" * 32, imports=["a", "b", "c", "d", "e"], fmt="elf", arch="x86_64"),
        )
        assert result["classification"] == related.CLASSIFICATION_SIMILAR_LIFECYCLE
        assert result["confidence"] == related.CONFIDENCE_MEDIUM
        assert result["signals"][0]["kind"] == related.SIGNAL_IMPORT_OVERLAP
        assert "0.800" in result["signals"][0]["detail"]
        assert "4/5" in result["signals"][0]["detail"]

    def test_import_jaccard_below_the_threshold_does_not_fire(self) -> None:
        result = related.relationship(
            _bundle(
                sha256="01" * 32,
                imports=["a", "b", "c", "d", "e", "f", "g", "h"],
                fmt="elf",
                arch="x86_64",
                size=1000,
            ),
            _bundle(
                sha256="02" * 32,
                imports=["a", "b", "c", "d", "e", "f", "g", "i"],
                fmt="macho",
                arch="arm64",
                size=5000,
            ),
        )
        assert result["classification"] == related.CLASSIFICATION_UNRELATED
        assert result["signals"] == []

    def test_capability_jaccard_at_the_threshold_is_low(self) -> None:
        result = related.relationship(
            _bundle(sha256="01" * 32, capabilities=["a", "b", "c", "d"], fmt="elf", arch="x86_64"),
            _bundle(
                sha256="02" * 32, capabilities=["a", "b", "c", "d", "e"], fmt="elf", arch="x86_64"
            ),
        )
        assert result["classification"] == related.CLASSIFICATION_SIMILAR_CAPABILITIES
        assert result["confidence"] == related.CONFIDENCE_LOW
        assert result["signals"][0]["kind"] == related.SIGNAL_CAPABILITY_OVERLAP

    def test_capability_jaccard_below_the_threshold_does_not_fire(self) -> None:
        result = related.relationship(
            _bundle(
                sha256="01" * 32,
                capabilities=["a", "b", "c", "d", "e", "f", "g", "h"],
                fmt="elf",
                arch="x86_64",
                size=1000,
            ),
            _bundle(
                sha256="02" * 32,
                capabilities=["a", "b", "c", "d", "e", "f", "g", "i"],
                fmt="macho",
                arch="arm64",
                size=5000,
            ),
        )
        assert result["classification"] == related.CLASSIFICATION_UNRELATED

    def test_same_format_arch_and_size_is_the_fallback(self) -> None:
        result = related.relationship(
            _bundle(sha256="01" * 32, size=1000),
            _bundle(sha256="02" * 32, size=1050),
        )
        assert result["classification"] == related.CLASSIFICATION_SIMILAR_SIZE
        assert result["confidence"] == related.CONFIDENCE_LOW
        assert result["signals"][0]["kind"] == related.SIGNAL_SIZE_WINDOW
        assert result["similarity"] == pytest.approx(1 - 50 / 1050)

    def test_size_outside_the_window_is_unrelated(self) -> None:
        result = related.relationship(
            _bundle(sha256="01" * 32, size=1000),
            _bundle(sha256="02" * 32, size=2000),
        )
        assert result["classification"] == related.CLASSIFICATION_UNRELATED

    def test_different_format_or_arch_is_unrelated(self) -> None:
        result = related.relationship(
            _bundle(sha256="01" * 32, size=1000),
            _bundle(sha256="02" * 32, size=1000, fmt="elf", arch="x86_64"),
        )
        assert result["classification"] == related.CLASSIFICATION_UNRELATED

    def test_size_window_is_not_added_beside_a_stronger_signal(self) -> None:
        result = related.relationship(
            _bundle(sha256="01" * 32, imphash=IMPHASH, size=1000),
            _bundle(sha256="02" * 32, imphash=IMPHASH, size=1000),
        )
        kinds = [signal["kind"] for signal in result["signals"]]
        assert kinds == [related.SIGNAL_SAME_IMPORTS]

    def test_strongest_signal_wins_with_every_match_listed(self) -> None:
        target = _bundle(
            imports=["a", "b"],
            capabilities=["networking"],
            imphash=IMPHASH,
            rich=RICH,
        )
        other = _bundle(
            sha256=SHA,
            imports=["a", "b"],
            capabilities=["networking"],
            imphash=IMPHASH,
            rich=RICH,
        )
        result = related.relationship(target, other)
        assert result["classification"] == related.CLASSIFICATION_IDENTICAL
        assert [signal["kind"] for signal in result["signals"]] == [
            related.SIGNAL_IDENTICAL,
            related.SIGNAL_SAME_IMPORTS,
            related.SIGNAL_SAME_TOOLCHAIN,
            related.SIGNAL_IMPORT_OVERLAP,
            related.SIGNAL_CAPABILITY_OVERLAP,
        ]

    def test_unrelated_carries_no_confidence(self) -> None:
        result = related.relationship(
            _bundle(sha256="01" * 32, fmt="elf", arch="x86_64", size=1),
            _bundle(sha256="02" * 32, size=999999),
        )
        assert result["classification"] == related.CLASSIFICATION_UNRELATED
        assert result["confidence"] == related.CONFIDENCE_NONE
        assert result["signals"] == []
        assert result["similarity"] == 0.0


class TestFindRelated:
    def test_stored_fingerprints_rank_without_an_engine(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
        other = _binary(conn, tmp_path, name="other.exe", sha="bb" * 32)
        _store_fingerprint(conn, target, sha256=SHA, imphash=IMPHASH)
        _store_fingerprint(conn, other, sha256=SHA, imphash=IMPHASH)
        payload = related.find_related(
            conn, binary_id=target, engine=engines.RebrewEngine(enabled=False), limit=10
        )
        assert payload["candidates_considered"] == 1
        assert payload["count"] == 1
        assert payload["related"][0]["binary_id"] == other
        assert payload["related"][0]["classification"] == related.CLASSIFICATION_IDENTICAL
        assert related.NO_ENGINE_NOTE in payload["notes"]

    def test_engine_supplies_the_bundles(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        target = _binary(conn, tmp_path, name="target.exe", sha="01" * 32)
        _binary(conn, tmp_path, name="other.exe", sha="02" * 32)
        engine = _MapEngine(
            {
                "target.exe": {
                    "fingerprint": {"sha256": "01" * 32, "format": "pe", "arch": "x86_32"},
                    "imports": {
                        "imports": [
                            _import("A"),
                            _import("B"),
                            _import("C"),
                            _import("D"),
                        ]
                    },
                },
                "other.exe": {
                    "fingerprint": {"sha256": "02" * 32, "format": "pe", "arch": "x86_32"},
                    "imports": {
                        "imports": [
                            _import("A"),
                            _import("B"),
                            _import("C"),
                            _import("D"),
                            _import("E"),
                        ]
                    },
                },
            }
        )
        payload = related.find_related(conn, binary_id=target, engine=engine, limit=10)
        assert payload["related"][0]["classification"] == related.CLASSIFICATION_SIMILAR_LIFECYCLE
        assert "import-overlap" in [s["kind"] for s in payload["related"][0]["signals"]]
        assert related.NO_ENGINE_NOTE not in payload["notes"]

    def test_sorts_by_classification_then_similarity_then_name(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
        _store_fingerprint(
            conn,
            target,
            sha256=SHA,
            imphash=IMPHASH,
            rich=RICH,
            size=1000,
        )
        _store_capabilities(conn, target, ["a", "b", "c", "d", "e"])

        identical = _binary(conn, tmp_path, name="z-identical.exe", sha="b1" * 32)
        _store_fingerprint(conn, identical, sha256=SHA, imphash=None, rich=None, size=1000)
        imports = _binary(conn, tmp_path, name="y-imports.exe", sha="b2" * 32)
        _store_fingerprint(conn, imports, sha256="b2" * 32, imphash=IMPHASH, rich=None, size=1000)
        toolchain = _binary(conn, tmp_path, name="x-toolchain.exe", sha="b3" * 32)
        _store_fingerprint(conn, toolchain, sha256="b3" * 32, imphash=None, rich=RICH, size=1000)
        caps = _binary(conn, tmp_path, name="w-caps.exe", sha="b4" * 32)
        _store_fingerprint(conn, caps, sha256="b4" * 32, imphash=None, rich=None, size=1000)
        _store_capabilities(conn, caps, ["a", "b", "c", "d"])
        size_only = _binary(conn, tmp_path, name="v-size.exe", sha="b5" * 32, size=1050)
        _store_fingerprint(conn, size_only, sha256="b5" * 32, imphash=None, rich=None, size=1050)
        unrelated = _binary(conn, tmp_path, name="a-unrelated.exe", sha="b6" * 32, size=50)
        _store_fingerprint(
            conn,
            unrelated,
            sha256="b6" * 32,
            imphash=None,
            rich=None,
            fmt="elf",
            arch="x86_64",
            size=50,
        )

        payload = related.find_related(
            conn, binary_id=target, engine=engines.RebrewEngine(enabled=False), limit=10
        )
        assert [row["name"] for row in payload["related"]] == [
            "z-identical.exe",
            "y-imports.exe",
            "x-toolchain.exe",
            "w-caps.exe",
            "v-size.exe",
        ]
        assert payload["candidates_considered"] == 6
        assert payload["count"] == 5

    def test_similarity_breaks_a_classification_tie(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
        _store_fingerprint(conn, target, sha256=SHA, size=1000)
        near = _binary(conn, tmp_path, name="near.exe", sha="b1" * 32, size=1000)
        _store_fingerprint(conn, near, sha256="b1" * 32, size=1000)
        far = _binary(conn, tmp_path, name="far.exe", sha="b2" * 32, size=1090)
        _store_fingerprint(conn, far, sha256="b2" * 32, size=1090)
        payload = related.find_related(
            conn, binary_id=target, engine=engines.RebrewEngine(enabled=False)
        )
        assert [row["name"] for row in payload["related"]] == ["near.exe", "far.exe"]
        assert payload["related"][0]["similarity"] > payload["related"][1]["similarity"]

    def test_unrelated_is_excluded_by_default(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
        _store_fingerprint(conn, target, sha256=SHA, fmt="elf", arch="x86_64", size=1)
        other = _binary(conn, tmp_path, name="other.exe", sha="b2" * 32, size=999999)
        _store_fingerprint(conn, other, sha256="b2" * 32, fmt="elf", arch="x86_64", size=999999)
        payload = related.find_related(
            conn, binary_id=target, engine=engines.RebrewEngine(enabled=False)
        )
        assert payload["related"] == []
        assert payload["candidates_considered"] == 1

    def test_include_unrelated_lists_it(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
        _store_fingerprint(conn, target, sha256=SHA, fmt="elf", arch="x86_64", size=1)
        other = _binary(conn, tmp_path, name="other.exe", sha="b2" * 32, size=999999)
        _store_fingerprint(conn, other, sha256="b2" * 32, fmt="elf", arch="x86_64", size=999999)
        payload = related.find_related(
            conn,
            binary_id=target,
            engine=engines.RebrewEngine(enabled=False),
            include_unrelated=True,
        )
        assert payload["count"] == 1
        assert payload["related"][0]["classification"] == related.CLASSIFICATION_UNRELATED

    def test_limit_caps_the_rows_and_the_count_is_exact(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
        for index in range(3):
            other = _binary(conn, tmp_path, name=f"other{index}.exe", sha=f"b{index}" * 32)
            _store_fingerprint(conn, other, sha256=SHA, size=1000)
        payload = related.find_related(
            conn, binary_id=target, engine=engines.RebrewEngine(enabled=False), limit=2
        )
        assert payload["candidates_considered"] == 3
        assert payload["count"] == 2
        assert len(payload["related"]) == 2
        assert any("showing 2 of 3" in note for note in payload["notes"])

    def test_self_is_never_a_candidate(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
        payload = related.find_related(
            conn, binary_id=target, engine=engines.RebrewEngine(enabled=False)
        )
        assert payload["candidates_considered"] == 0
        assert payload["related"] == []

    def test_binary_without_a_file_is_skipped_with_a_note(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
        _binary(conn, tmp_path, name="gone.exe", sha="b1" * 32, on_disk=False)
        other = _binary(conn, tmp_path, name="other.exe", sha="b2" * 32)
        _store_fingerprint(conn, other, sha256=SHA, size=1000)
        payload = related.find_related(
            conn, binary_id=target, engine=engines.RebrewEngine(enabled=False)
        )
        assert payload["candidates_considered"] == 1
        assert any("no file on disk" in note for note in payload["notes"])

    def test_scan_is_stored_and_replaces_the_previous_one(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
        other = _binary(conn, tmp_path, name="other.exe", sha="b1" * 32)
        _store_fingerprint(conn, other, sha256=SHA, size=1000)
        first = related.find_related(
            conn, binary_id=target, engine=engines.RebrewEngine(enabled=False)
        )
        assert related.stored_related(conn, target) == first

        _store_fingerprint(conn, other, sha256="cc" * 32, fmt="elf", arch="x86_64", size=1)
        second = related.find_related(
            conn, binary_id=target, engine=engines.RebrewEngine(enabled=False)
        )
        assert second["related"] == []
        assert related.stored_related(conn, target) == second
        analysis_id = store.latest_analysis_for_binary(conn, target)
        kinds = [row["kind"] for row in store.list_scans(conn, analysis_id or 0)]
        assert kinds.count(store.SCAN_KIND_RELATED) == 1

    def test_default_limit_is_a_named_constant(self) -> None:
        assert related.DEFAULT_LIMIT == 20
        assert related.MAX_LIMIT >= related.DEFAULT_LIMIT

    def test_a_non_member_ranks_only_visible_binaries(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
        other = _binary(conn, tmp_path, name="other.exe", sha="b1" * 32)
        _store_fingerprint(conn, other, sha256=SHA, size=1000)
        owner, _token = auth.add_user(conn, name="owner", role="admin")
        team_id = int(auth.create_team(conn, name="blue")["id"])
        auth.add_member(conn, team_id, int(owner["id"]))
        _member, _token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        ana = auth.find_user(conn, "ana")
        assert ana is not None
        auth.add_member(conn, team_id, int(ana["id"]))
        _outsider, _token = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        stranger = auth.find_user(conn, "bob")
        assert stranger is not None
        store.set_binary_scope(conn, other, visibility="team", owner_team_id=team_id)

        hidden = related.find_related(
            conn,
            binary_id=target,
            engine=engines.RebrewEngine(enabled=False),
            visible_to=stranger,
        )
        assert hidden["related"] == []
        assert hidden["candidates_considered"] == 0
        member = related.find_related(
            conn, binary_id=target, engine=engines.RebrewEngine(enabled=False), visible_to=ana
        )
        assert [row["binary_id"] for row in member["related"]] == [other]

    def test_unknown_binary_raises_key_error(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(KeyError, match="no binary with id 4242"):
            related.find_related(conn, binary_id=4242, engine=engines.RebrewEngine(enabled=False))

    def test_bad_limit_raises_value_error(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
        with pytest.raises(ValueError, match="must be positive"):
            related.find_related(conn, binary_id=target, limit=0)
        with pytest.raises(ValueError, match="at most"):
            related.find_related(conn, binary_id=target, limit=related.MAX_LIMIT + 1)

    def test_stored_related_is_none_before_the_first_run(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
        assert related.stored_related(conn, target) is None


class TestRelatedHelpers:
    def test_string_set_ignores_non_sequences(self) -> None:
        assert related._string_set("nope") == set()
        assert related._string_set(b"nope") == set()
        assert related._string_set(["a", 1, "b"]) == {"a", "b"}
        assert related._string_set(None) == set()

    def test_size_window_needs_two_sizes(self) -> None:
        base = {"format": "PE", "arch": "x64", "size": 100}
        assert related._size_window(base, {"format": "PE", "arch": "x64"}) is None
        assert related._size_window(base, {"format": "PE", "arch": "x64", "size": "x"}) is None

    def test_entries_ignore_non_list_shapes(self) -> None:
        assert related._entries({}, "functions") == []
        assert related._entries({"functions": "nope"}, "functions") == []
        assert related._entries({"functions": ["nope", {"va": 1}]}, "functions") == [{"va": 1}]
