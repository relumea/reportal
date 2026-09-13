"""Tests for reportal.families: signature bundles, matching signals and the store."""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from reportal import engines, families, store

SHA = "bda21f387f7d53bd188a1fd91179efbd688723d18c26e78465c2ced8fb75463f"
IMPHASH = "27abfd9cfda7519d5efb3f08a2a4f3ce"
RICH = "1f3f6484"


def _fingerprint(
    *,
    sha256: str | None = SHA,
    imphash: str | None = IMPHASH,
    rich: str | None = RICH,
) -> dict[str, Any]:
    return {"sha256": sha256, "imphash": imphash, "rich_header_hash": rich}


class _StubEngine(engines.RebrewEngine):
    """Engine surface with fixed payloads and a call log, never a subprocess."""

    def __init__(
        self,
        *,
        fingerprint: dict[str, Any] | None = None,
        imports: dict[str, Any] | None = None,
        strings: dict[str, Any] | None = None,
    ) -> None:
        self.calls: list[str] = []
        self._fingerprint = fingerprint if fingerprint is not None else _fingerprint()
        self._imports = imports if imports is not None else {"imports": []}
        self._strings = strings if strings is not None else {"strings": []}

    def fingerprint(self, binary: str | Path) -> dict[str, Any]:
        self.calls.append("fingerprint")
        return dict(self._fingerprint)

    def imports(self, binary: str | Path) -> dict[str, Any]:
        self.calls.append("imports")
        return dict(self._imports)

    def strings(self, binary: str | Path) -> dict[str, Any]:
        self.calls.append("strings")
        return dict(self._strings)


def _import(name: str, dll: str = "KERNEL32.dll") -> dict[str, Any]:
    return {"dll": dll, "name": name, "iat_va": "0x401000"}


def _string(text: str) -> dict[str, Any]:
    return {"text": text, "va": "0x402000", "kind": "ascii", "section": ".rdata"}


def _binary(
    conn: sqlite3.Connection, tmp_path: Path, *, name: str = "demo.exe", sha: str = "ab" * 32
) -> int:
    target = tmp_path / name
    target.write_bytes(b"MZ")
    return store.add_binary(conn, sha256=sha, name=name, path=str(target))


class TestImportSet:
    def test_ordering_does_not_change_the_names_or_the_hash(self) -> None:
        first = {"imports": [_import("B"), _import("A")]}
        second = {"imports": [_import("A"), _import("B")]}
        assert families.import_names(first) == families.import_names(second)
        assert families.import_hash(families.import_names(first)) == families.import_hash(
            families.import_names(second)
        )

    def test_casing_does_not_change_the_names_or_the_hash(self) -> None:
        lower = {"imports": [{"dll": "kernel32.dll", "name": "gettickcount"}]}
        upper = {"imports": [{"dll": "KERNEL32.DLL", "name": "GetTickCount"}]}
        assert (
            families.import_names(lower)
            == families.import_names(upper)
            == ["kernel32.dll:gettickcount"]
        )
        assert families.import_hash(families.import_names(lower)) == families.import_hash(
            families.import_names(upper)
        )

    def test_hash_is_the_sha256_of_the_sorted_joined_names(self) -> None:
        names = ["a.dll:f", "b.dll:g"]
        expected = hashlib.sha256("\n".join(names).encode("utf-8")).hexdigest()
        assert families.import_hash(names) == expected

    def test_entry_without_a_name_is_skipped(self) -> None:
        payload = {"imports": [{"dll": "KERNEL32.dll", "iat_va": "0x1"}, _import("A")]}
        assert families.import_names(payload) == ["kernel32.dll:a"]

    def test_malformed_payload_yields_no_names(self) -> None:
        assert families.import_names({"imports": "nope"}) == []


class TestCapabilitySet:
    def test_import_evidence_names_the_category(self) -> None:
        names = families.capability_names([_import("WSAStartup")], [])
        assert names == ["networking"]

    def test_string_evidence_names_the_category(self) -> None:
        names = families.capability_names([], [_string("https://c2.example/beacon")])
        assert names == ["networking"]

    def test_names_are_sorted_and_distinct(self) -> None:
        imports = [_import("WSAStartup"), _import("CryptEncrypt"), _import("wsaStartup")]
        assert families.capability_names(imports, []) == ["crypto", "networking"]

    def test_unrelated_input_matches_nothing(self) -> None:
        assert families.capability_names([_import("GetTickCount")], [_string("hello")]) == []


class TestDeriveBundle:
    def test_bundle_carries_every_derived_field(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        stub = _StubEngine(
            imports={"imports": [_import("WSAStartup")]},
            strings={"strings": [_string("https://c2.example/beacon")]},
        )
        bundle = families.derive_bundle(conn, binary_id=binary_id, engine=stub)
        assert bundle["sha256"] == SHA
        assert bundle["imphash"] == IMPHASH
        assert bundle["rich_header_hash"] == RICH
        assert bundle["import_names"] == ["kernel32.dll:wsastartup"]
        assert bundle["import_hash"] == families.import_hash(bundle["import_names"])
        assert bundle["capabilities"] == ["networking"]
        assert stub.calls == ["fingerprint", "imports", "strings"]

    def test_fingerprint_hashes_are_lowercased(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        stub = _StubEngine(fingerprint=_fingerprint(sha256=SHA.upper(), imphash=IMPHASH.upper()))
        bundle = families.derive_bundle(conn, binary_id=binary_id, engine=stub)
        assert bundle["sha256"] == SHA
        assert bundle["imphash"] == IMPHASH

    def test_missing_fingerprint_fields_stay_none(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        stub = _StubEngine(fingerprint=_fingerprint(imphash=None, rich=None))
        bundle = families.derive_bundle(conn, binary_id=binary_id, engine=stub)
        assert bundle["imphash"] is None
        assert bundle["rich_header_hash"] is None

    def test_unknown_binary_raises_key_error(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(KeyError, match="no binary with id 4242"):
            families.derive_bundle(conn, binary_id=4242)

    def test_missing_file_raises_file_not_found(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="cd" * 32, name="gone.exe", path="/nope/gone.exe")
        with pytest.raises(FileNotFoundError, match="has no file"):
            families.derive_bundle(conn, binary_id=binary_id, engine=_StubEngine())

    def test_engine_unavailable_propagates(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _binary(conn, tmp_path)
        with pytest.raises(engines.EngineUnavailable):
            families.derive_bundle(
                conn, binary_id=binary_id, engine=engines.RebrewEngine(enabled=False)
            )


class TestRegisterFamily:
    def test_stores_the_bundle_and_returns_the_family(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        stub = _StubEngine(
            imports={"imports": [_import("WSAStartup")]},
            strings={"strings": [_string("https://c2.example/beacon")]},
        )
        family = families.register_family(
            conn,
            name="Demo",
            reference_binary_id=binary_id,
            aliases=[" DEMO.A ", ""],
            notes="first",
            engine=stub,
        )
        assert family["family_id"] > 0
        assert family["name"] == "Demo"
        assert family["aliases"] == ["DEMO.A"]
        assert family["notes"] == "first"
        assert family["reference_binary_id"] == binary_id
        assert family["signatures"]["sha256"] == SHA
        assert family["signatures"]["capabilities"] == ["networking"]
        assert stub.calls == ["fingerprint", "imports", "strings"]
        assert families.get_family(conn, family["family_id"]) == family

    def test_detection_needs_no_engine_for_the_reference(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        stub = _StubEngine(imports={"imports": [_import("A")]})
        families.register_family(conn, name="Demo", reference_binary_id=binary_id, engine=stub)
        stub.calls.clear()
        other = _binary(conn, tmp_path, name="other.exe", sha="ef" * 32)
        families.detect_binary(conn, binary_id=other, engine=stub)
        assert stub.calls == ["fingerprint", "imports", "strings"]

    def test_blank_name_is_rejected(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _binary(conn, tmp_path)
        with pytest.raises(families.InvalidFamilyNameError, match="must not be empty"):
            families.register_family(
                conn, name="  ", reference_binary_id=binary_id, engine=_StubEngine()
            )

    def test_duplicate_name_is_rejected_case_insensitively(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        stub = _StubEngine()
        families.register_family(conn, name="Demo", reference_binary_id=binary_id, engine=stub)
        with pytest.raises(families.DuplicateFamilyError, match="already exists"):
            families.register_family(conn, name="demo", reference_binary_id=binary_id, engine=stub)

    def test_duplicate_name_does_not_run_the_engine(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        stub = _StubEngine()
        families.register_family(conn, name="Demo", reference_binary_id=binary_id, engine=stub)
        stub.calls.clear()
        with pytest.raises(families.DuplicateFamilyError):
            families.register_family(conn, name="DEMO", reference_binary_id=binary_id, engine=stub)
        assert stub.calls == []

    def test_unknown_reference_binary_is_rejected(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(KeyError, match="no binary with id 99"):
            families.register_family(
                conn, name="Demo", reference_binary_id=99, engine=_StubEngine()
            )

    def test_engine_unavailable_is_rejected(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _binary(conn, tmp_path)
        with pytest.raises(engines.EngineUnavailable):
            families.register_family(
                conn,
                name="Demo",
                reference_binary_id=binary_id,
                engine=engines.RebrewEngine(enabled=False),
            )


class TestEvaluate:
    def test_exact_sha256_is_high_and_exact_binary(self) -> None:
        signals, similarity = families.evaluate({"sha256": SHA}, {"sha256": SHA})
        assert signals == [
            {
                "kind": families.SIGNAL_EXACT_BINARY,
                "confidence": families.CONFIDENCE_HIGH,
                "detail": SHA,
            }
        ]
        assert similarity == 1.0

    def test_imphash_is_high_and_import_fingerprint(self) -> None:
        signals, _ = families.evaluate({"imphash": IMPHASH}, {"imphash": IMPHASH})
        assert [signal["kind"] for signal in signals] == [families.SIGNAL_IMPORT_FINGERPRINT]
        assert signals[0]["confidence"] == families.CONFIDENCE_HIGH

    def test_rich_header_is_medium_and_toolchain_fingerprint(self) -> None:
        signals, _ = families.evaluate({"rich_header_hash": RICH}, {"rich_header_hash": RICH})
        assert [signal["kind"] for signal in signals] == [families.SIGNAL_TOOLCHAIN_FINGERPRINT]
        assert signals[0]["confidence"] == families.CONFIDENCE_MEDIUM

    def test_import_hash_is_high_and_import_set(self) -> None:
        signals, _ = families.evaluate(
            {"import_hash": "deadbeef", "import_names": []},
            {"import_hash": "deadbeef", "import_names": ["a.dll:f"]},
        )
        assert [signal["kind"] for signal in signals] == [families.SIGNAL_IMPORT_SET]
        assert signals[0]["confidence"] == families.CONFIDENCE_HIGH

    def test_import_jaccard_exactly_at_the_threshold_fires(self) -> None:
        signature = {"import_names": ["a", "b", "c", "d"]}
        target = {"import_names": ["a", "b", "c", "d", "e"]}
        signals, similarity = families.evaluate(signature, target)
        assert [signal["kind"] for signal in signals] == [families.SIGNAL_IMPORT_OVERLAP]
        assert signals[0]["confidence"] == families.CONFIDENCE_MEDIUM
        assert "0.800" in signals[0]["detail"]
        assert "4/5" in signals[0]["detail"]
        assert similarity == pytest.approx(0.8)

    def test_import_jaccard_below_the_threshold_does_not_fire(self) -> None:
        signals, _ = families.evaluate(
            {"import_names": ["a", "b", "c"]}, {"import_names": ["a", "b", "c", "d"]}
        )
        assert signals == []

    def test_capability_jaccard_at_the_threshold_is_low(self) -> None:
        signature = {"capabilities": ["a", "b", "c", "d"]}
        target = {"capabilities": ["a", "b", "c", "d", "e"]}
        signals, _ = families.evaluate(signature, target)
        assert [signal["kind"] for signal in signals] == [families.SIGNAL_CAPABILITY_OVERLAP]
        assert signals[0]["confidence"] == families.CONFIDENCE_LOW
        assert "capability jaccard 0.800" in signals[0]["detail"]

    def test_capability_jaccard_below_the_threshold_does_not_fire(self) -> None:
        signals, _ = families.evaluate(
            {"capabilities": ["a", "b"]}, {"capabilities": ["a", "b", "c"]}
        )
        assert signals == []

    def test_multi_signal_evidence_is_ordered(self) -> None:
        signature = {
            "sha256": SHA,
            "imphash": IMPHASH,
            "rich_header_hash": RICH,
            "import_hash": "h",
            "import_names": ["a", "b"],
            "capabilities": ["networking"],
        }
        target = {
            "sha256": SHA,
            "imphash": IMPHASH,
            "rich_header_hash": RICH,
            "import_hash": "h",
            "import_names": ["a", "b"],
            "capabilities": ["networking"],
        }
        signals, similarity = families.evaluate(signature, target)
        assert [signal["kind"] for signal in signals] == [
            families.SIGNAL_EXACT_BINARY,
            families.SIGNAL_IMPORT_FINGERPRINT,
            families.SIGNAL_TOOLCHAIN_FINGERPRINT,
            families.SIGNAL_IMPORT_SET,
            families.SIGNAL_IMPORT_OVERLAP,
            families.SIGNAL_CAPABILITY_OVERLAP,
        ]
        assert similarity == 1.0

    def test_different_binaries_match_nothing(self) -> None:
        signals, similarity = families.evaluate(
            {"sha256": SHA, "import_names": ["a"]}, {"sha256": "00", "import_names": ["z"]}
        )
        assert signals == []
        assert similarity == 0.0


class TestDetectBinary:
    def _register(
        self, conn: sqlite3.Connection, binary_id: int, name: str = "Demo"
    ) -> _StubEngine:
        stub = _StubEngine(
            imports={"imports": [_import("WSAStartup")]},
            strings={"strings": [_string("https://c2.example/beacon")]},
        )
        families.register_family(conn, name=name, reference_binary_id=binary_id, engine=stub)
        return stub

    def test_reference_binary_matches_its_own_family(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        stub = self._register(conn, binary_id)
        result = families.detect_binary(conn, binary_id=binary_id, engine=stub)
        assert result["families_checked"] == 1
        assert result["count"] == 1
        match = result["matches"][0]
        assert match["family_id"] > 0
        assert match["name"] == "Demo"
        assert match["confidence"] == families.CONFIDENCE_HIGH
        assert families.SIGNAL_EXACT_BINARY in [signal["kind"] for signal in match["signals"]]

    def test_byte_identical_copy_matches_exact_binary(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        reference = _binary(conn, tmp_path, name="reference.exe")
        copy_id = _binary(conn, tmp_path, name="copy.exe", sha="cd" * 32)
        stub = self._register(conn, reference)
        result = families.detect_binary(conn, binary_id=copy_id, engine=stub)
        match = result["matches"][0]
        assert match["confidence"] == families.CONFIDENCE_HIGH
        assert [signal["kind"] for signal in match["signals"]][0] == families.SIGNAL_EXACT_BINARY

    def test_stores_the_detection_scan(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _binary(conn, tmp_path)
        stub = self._register(conn, binary_id)
        result = families.detect_binary(conn, binary_id=binary_id, engine=stub)
        assert families.stored_detection(conn, binary_id) == result

    def test_no_match_is_a_valid_result(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _binary(conn, tmp_path)
        self._register(conn, binary_id)
        unrelated = _StubEngine(fingerprint=_fingerprint(sha256="11", imphash="22", rich=None))
        other = _binary(conn, tmp_path, name="other.exe", sha="ef" * 32)
        result = families.detect_binary(conn, binary_id=other, engine=unrelated)
        assert result["families_checked"] == 1
        assert result["matches"] == []
        assert result["count"] == 0

    def test_notes_state_the_scope_and_thresholds(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        result = families.detect_binary(conn, binary_id=binary_id, engine=_StubEngine())
        notes = " ".join(result["notes"])
        assert "no external threat-intelligence feed" in notes
        assert str(families.IMPORT_OVERLAP_THRESHOLD) in notes
        assert str(families.CAPABILITY_OVERLAP_THRESHOLD) in notes

    def test_matches_sort_by_confidence_then_similarity(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        reference = _binary(conn, tmp_path, name="reference.exe")
        low_stub = _StubEngine(
            imports={"imports": [_import("WSAStartup")]},
            strings={"strings": [_string("https://c2.example/beacon")]},
        )
        families.register_family(
            conn, name="LowOnly", reference_binary_id=reference, engine=low_stub
        )
        exact_stub = _StubEngine()
        families.register_family(
            conn, name="Exact", reference_binary_id=reference, engine=exact_stub
        )
        other = _binary(conn, tmp_path, name="other.exe", sha="ef" * 32)
        detect_stub = _StubEngine(
            imports={"imports": [_import("WSAStartup")]},
            strings={"strings": [_string("https://c2.example/beacon")]},
        )
        result = families.detect_binary(conn, binary_id=other, engine=detect_stub)
        assert [match["name"] for match in result["matches"]] == ["Exact", "LowOnly"]

    def test_unknown_binary_raises_key_error(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(KeyError, match="no binary with id 7"):
            families.detect_binary(conn, binary_id=7, engine=_StubEngine())

    def test_missing_file_raises_file_not_found(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="cd" * 32, name="gone.exe", path="/nope")
        with pytest.raises(FileNotFoundError, match="has no file"):
            families.detect_binary(conn, binary_id=binary_id, engine=_StubEngine())

    def test_engine_unavailable_propagates(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _binary(conn, tmp_path)
        with pytest.raises(engines.EngineUnavailable):
            families.detect_binary(
                conn, binary_id=binary_id, engine=engines.RebrewEngine(enabled=False)
            )


class TestStoreRoundTrip:
    def test_crud_round_trip(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _binary(conn, tmp_path)
        family_id = store.add_family(
            conn,
            name="Demo",
            aliases=["A"],
            notes="n",
            reference_binary_id=binary_id,
            signatures={"sha256": SHA},
        )
        stored = store.get_family(conn, family_id)
        assert stored is not None
        assert stored["name"] == "Demo"
        assert stored["aliases"] == ["A"]
        assert stored["signatures"] == {"sha256": SHA}
        assert [row["id"] for row in store.list_families(conn)] == [family_id]

    def test_find_by_name_is_case_insensitive(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        store.add_family(
            conn,
            name="Demo",
            aliases=[],
            notes="",
            reference_binary_id=binary_id,
            signatures={},
        )
        assert store.find_family_by_name(conn, "DEMO") is not None
        assert store.find_family_by_name(conn, "other") is None

    def test_list_orders_by_name_case_insensitively(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        first = _binary(conn, tmp_path, name="a.exe")
        second = _binary(conn, tmp_path, name="b.exe", sha="cd" * 32)
        store.add_family(
            conn, name="zeta", aliases=[], notes="", reference_binary_id=first, signatures={}
        )
        store.add_family(
            conn, name="Alpha", aliases=[], notes="", reference_binary_id=second, signatures={}
        )
        assert [row["name"] for row in store.list_families(conn)] == ["Alpha", "zeta"]

    def test_delete_reports_whether_a_row_existed(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        family_id = store.add_family(
            conn, name="Demo", aliases=[], notes="", reference_binary_id=binary_id, signatures={}
        )
        assert store.delete_family(conn, family_id) is True
        assert store.delete_family(conn, family_id) is False

    def test_deleting_the_reference_binary_cascades(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        store.add_family(
            conn, name="Demo", aliases=[], notes="", reference_binary_id=binary_id, signatures={}
        )
        conn.execute("DELETE FROM binaries WHERE id = ?", (binary_id,))
        conn.commit()
        assert store.list_families(conn) == []

    def test_counts_include_families(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _binary(conn, tmp_path)
        store.add_family(
            conn, name="Demo", aliases=[], notes="", reference_binary_id=binary_id, signatures={}
        )
        assert store.counts(conn)["families"] == 1

    def test_stored_detection_is_none_before_the_first_run(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        assert families.stored_detection(conn, binary_id) is None
