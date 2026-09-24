"""Corpus packs: named functions and listings exported from one workspace, matched in another."""

from __future__ import annotations

import contextlib
import gzip
import json
import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reportal import cli, corpus, engines, matching, store
from reportal._paths import DB_ENV

LISTING = (
    "push ebp\nmov ebp, esp\nmov eax, dword [ebp + 8]\nxor edx, edx\n"
    "cmp eax, 0x10\njle 0x401020\nmov eax, 0x10\npop ebp\nret\n"
)
runner = CliRunner()


def _db(tmp_path: Path, name: str) -> Path:
    path = tmp_path / name
    store.init_db(path)
    return path


def _seed_source(conn: sqlite3.Connection) -> int:
    """A binary with one exportable function beside ones a pack leaves out."""
    binary_id = store.add_binary(conn, sha256="ab" * 32, name="libclamp.dll", arch="x86_32")
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual", status="done")
    named = store.add_function(conn, analysis_id=analysis_id, va=0x401000, name="clamp16", size=32)
    placeholder = store.add_function(
        conn, analysis_id=analysis_id, va=0x401040, name="fcn_00401040", size=32
    )
    store.add_function(conn, analysis_id=analysis_id, va=0x401080, name="unlisted", size=8)
    thunk = store.add_function(
        conn, analysis_id=analysis_id, va=0x4010C0, name="_initterm", size=6, status="THUNK"
    )
    ordinal = store.add_function(
        conn, analysis_id=analysis_id, va=0x401100, name="ordinal_2016", size=32
    )
    for function_id in (named, placeholder, thunk, ordinal):
        store.set_disasm(conn, function_id, LISTING)
    # A binary with no content hash cannot key a pack entry.
    hashless = store.add_binary(conn, sha256=None, name="nohash.exe", path="/nowhere")
    hashless_analysis = store.create_analysis(conn, binary_id=hashless, engine="manual")
    listed = store.add_function(conn, analysis_id=hashless_analysis, va=0x10, name="real", size=4)
    store.set_disasm(conn, listed, LISTING)
    return binary_id


@pytest.fixture()
def pack(tmp_path: Path) -> Path:
    with contextlib.closing(store.connect(_db(tmp_path, "source.db"))) as conn:
        _seed_source(conn)
        summary = corpus.export_pack(
            conn, tmp_path / "packs" / "base.corpus.gz", engine=engines.RebrewEngine(enabled=False)
        )
    assert summary == {
        "path": str(tmp_path / "packs" / "base.corpus.gz"),
        "binaries": 1,
        "functions": 1,
    }
    return tmp_path / "packs" / "base.corpus.gz"


class TestExport:
    def test_only_named_listed_functions_of_hashed_binaries(self, pack: Path) -> None:
        with gzip.open(pack, "rt", encoding="utf-8") as handle:
            data = json.load(handle)
        assert (data["format"], data["version"]) == (corpus.PACK_FORMAT, corpus.PACK_VERSION)
        [binary] = data["binaries"]
        assert (binary["name"], binary["arch"]) == ("libclamp.dll", "x86_32")
        assert [(fn["name"], fn["listing"]) for fn in binary["functions"]] == [("clamp16", LISTING)]

    def test_an_unknown_binary_is_refused(self, tmp_path: Path) -> None:
        with (
            contextlib.closing(store.connect(_db(tmp_path, "x.db"))) as conn,
            pytest.raises(corpus.CorpusError, match="no binary with id 7"),
        ):
            corpus.export_pack(conn, tmp_path / "p.gz", binary_ids=[7])


class TestImport:
    def test_imported_functions_are_match_candidates(self, pack: Path, tmp_path: Path) -> None:
        with contextlib.closing(store.connect(_db(tmp_path, "target.db"))) as conn:
            summary = corpus.import_pack(conn, pack)
            assert (summary["binaries"], summary["functions"]) == (1, 1)
            # A stripped binary here whose function has the same code.
            target = store.add_binary(conn, sha256="cd" * 32, name="app.exe", arch="x86_32")
            analysis_id = store.create_analysis(conn, binary_id=target, engine="manual")
            stripped = store.add_function(
                conn, analysis_id=analysis_id, va=0x5000, name="fcn_00005000", size=32
            )
            store.set_disasm(conn, stripped, LISTING)
            matching.match_binary(
                conn, binary_id=target, engine=engines.RebrewEngine(enabled=False)
            )
            candidates = store.list_matches(conn, stripped)
            assert [row["candidate_name"] for row in candidates] == ["clamp16"]

    def test_a_reimport_refreshes_and_an_owned_binary_is_skipped(
        self, pack: Path, tmp_path: Path
    ) -> None:
        with contextlib.closing(store.connect(_db(tmp_path, "target.db"))) as conn:
            corpus.import_pack(conn, pack)
            again = corpus.import_pack(conn, pack)
            assert (again["binaries"], again["functions"], again["pruned"]) == (1, 1, 0)
            binary = store.find_binary_by_sha256(conn, "ab" * 32)
            assert binary is not None and binary["function_count"] == 1
        with contextlib.closing(store.connect(_db(tmp_path, "owner.db"))) as conn:
            store.add_binary(conn, sha256="ab" * 32, name="mine.dll")
            summary = corpus.import_pack(conn, pack)
            assert (summary["binaries"], summary["skipped_binaries"]) == (0, 1)

    def test_a_newer_pack_drops_what_it_no_longer_carries(self, tmp_path: Path) -> None:
        def write(path: Path, names: list[str]) -> None:
            functions = [
                {"va": 0x10 * index, "size": 4, "name": name, "listing": f"{name}\nret\n"}
                for index, name in enumerate(names, start=1)
            ]
            data = {
                "format": corpus.PACK_FORMAT,
                "version": 1,
                "binaries": [{"sha256": "ef" * 32, "name": "lib.a", "functions": functions}],
            }
            with gzip.open(path, "wt", encoding="utf-8") as handle:
                json.dump(data, handle)

        with contextlib.closing(store.connect(_db(tmp_path, "t.db"))) as conn:
            write(tmp_path / "v1.gz", ["alpha", "beta"])
            corpus.import_pack(conn, tmp_path / "v1.gz")
            write(tmp_path / "v2.gz", ["alpha"])
            summary = corpus.import_pack(conn, tmp_path / "v2.gz")
            assert summary["pruned"] == 1
            binary = store.find_binary_by_sha256(conn, "ef" * 32)
            assert binary is not None and binary["function_count"] == 1

    def test_a_malformed_function_is_counted_not_fatal(self, tmp_path: Path) -> None:
        path = tmp_path / "hand.corpus.gz"
        entries = [
            {"va": 0x10, "size": 4, "name": "good", "listing": "ret\n"},
            {"va": "0x20", "size": 4, "name": "bad va", "listing": "ret\n"},
            {"va": 0x30, "size": 4, "name": "", "listing": "ret\n"},
        ]
        data = {
            "format": corpus.PACK_FORMAT,
            "version": 1,
            "binaries": [
                {"sha256": "ef" * 32, "name": "hand.bin", "functions": entries},
                "not a binary",
            ],
        }
        with gzip.open(path, "wt", encoding="utf-8") as handle:
            json.dump(data, handle)
        with contextlib.closing(store.connect(_db(tmp_path, "t.db"))) as conn:
            summary = corpus.import_pack(conn, path)
        assert (summary["functions"], summary["malformed"]) == (1, 3)

    @pytest.mark.parametrize(
        ("content", "message"),
        [
            (b"not gzip", "not a readable corpus pack"),
            (gzip.compress(b'{"format": "other"}'), "is not a reportal-corpus pack"),
            (
                gzip.compress(b'{"format": "reportal-corpus", "version": 99, "binaries": []}'),
                "pack version 99",
            ),
        ],
    )
    def test_a_bad_file_is_refused(self, tmp_path: Path, content: bytes, message: str) -> None:
        path = tmp_path / "bad.gz"
        path.write_bytes(content)
        with (
            contextlib.closing(store.connect(_db(tmp_path, "t.db"))) as conn,
            pytest.raises(corpus.CorpusError, match=message),
        ):
            corpus.import_pack(conn, path)


class TestCli:
    def test_info_and_import(
        self, pack: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(DB_ENV, str(_db(tmp_path, "cli.db")))
        info = runner.invoke(cli.app, ["corpus-info", str(pack), "--json"])
        assert info.exit_code == 0, info.output
        assert json.loads(info.stdout)["functions"] == 1
        result = runner.invoke(cli.app, ["corpus-import", str(pack), "--json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["binaries"] == 1
        missing = runner.invoke(cli.app, ["corpus-import", str(tmp_path / "none.gz")])
        assert missing.exit_code == 1


class LibraryEngine(engines.RebrewEngine):
    """An engine whose static libraries hold fixed functions."""

    def __init__(self, functions: dict[str, list[dict[str, object]]]) -> None:
        super().__init__(enabled=True)
        self.functions = functions

    def library_functions(self, library: str | Path) -> list[dict[str, object]]:
        name = Path(library).name
        if name not in self.functions:
            raise engines.EngineError("rebrew library functions failed: not an archive")
        return self.functions[name]


class TestLibraries:
    def test_a_library_pack_holds_its_named_functions(self, tmp_path: Path) -> None:
        library = tmp_path / "LIBC.LIB"
        library.write_bytes(b"!<arch>\n")
        engine = LibraryEngine(
            {
                "LIBC.LIB": [
                    {"name": "_strlen", "size": 40, "arch": "x86_32", "listing": LISTING},
                    {"name": "_stub", "size": 4, "arch": "x86_32", "listing": "ret\n"},
                    {"name": "fcn_00000100", "size": 40, "arch": "x86_32", "listing": LISTING},
                    {"name": "_memcpy", "size": 64, "arch": "x86_32", "listing": LISTING},
                ]
            }
        )
        summary = corpus.pack_from_libraries([library], tmp_path / "libs.gz", engine=engine)
        assert (summary["binaries"], summary["functions"]) == (1, 2)
        with gzip.open(tmp_path / "libs.gz", "rt", encoding="utf-8") as handle:
            [binary] = json.load(handle)["binaries"]
        assert (binary["name"], binary["format"], binary["arch"]) == ("LIBC.LIB", "lib", "x86_32")
        # Laid out end to end from 0, since an object carries no address.
        assert [(fn["name"], fn["va"]) for fn in binary["functions"]] == [
            ("_strlen", 0),
            ("_memcpy", 40),
        ]
        with contextlib.closing(store.connect(_db(tmp_path, "t.db"))) as conn:
            assert corpus.import_pack(conn, tmp_path / "libs.gz")["functions"] == 2

    def test_an_x86_64_library_carries_its_isa(self, tmp_path: Path) -> None:
        library = tmp_path / "libc.a"
        library.write_bytes(b"!<arch>\n")
        listing = "push rbp\nmov rbp, rsp\nmov eax, edi\npop rbp\nret\n" * 2
        engine = LibraryEngine(
            {"libc.a": [{"name": "abs", "size": 32, "arch": "x86_64", "listing": listing}]}
        )
        corpus.pack_from_libraries([library], tmp_path / "libc.gz", engine=engine)
        with gzip.open(tmp_path / "libc.gz", "rt", encoding="utf-8") as handle:
            [binary] = json.load(handle)["binaries"]
        assert binary["arch"] == "x86_64"

    def test_a_mixed_isa_library_is_refused(self, tmp_path: Path) -> None:
        library = tmp_path / "fat.a"
        library.write_bytes(b"!<arch>\n")
        engine = LibraryEngine(
            {
                "fat.a": [
                    {"name": "a", "size": 32, "arch": "x86_64", "listing": LISTING},
                    {"name": "b", "size": 32, "arch": "arm64", "listing": LISTING},
                ]
            }
        )
        with pytest.raises(corpus.CorpusError, match=r"more than one ISA \(arm64, x86_64\)"):
            corpus.pack_from_libraries([library], tmp_path / "x.gz", engine=engine)

    def test_an_unreadable_library_names_itself(self, tmp_path: Path) -> None:
        library = tmp_path / "broken.a"
        library.write_bytes(b"junk")
        with pytest.raises(corpus.CorpusError, match=r"broken\.a: rebrew library functions failed"):
            corpus.pack_from_libraries([library], tmp_path / "x.gz", engine=LibraryEngine({}))
