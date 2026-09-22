"""Tests for the FLIRT signature catalog and its match cache.

The engine itself is faked: what these cover is the catalog's identity rules
(one row per file, content-keyed), the signature-library key that invalidates
cached scans, and the two caches -- one per process for the engine, one in the
database for the result.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from reportal import flirt_sigs


class _FakeMatch:
    def __init__(self, names: list[tuple[str, str]]) -> None:
        self.names = names


class _FakeMatcher:
    """Stands in for the compiled engine; counts how often it was asked."""

    builds = 0

    def __init__(self) -> None:
        _FakeMatcher.builds += 1

    def match(self, data: bytes) -> list[_FakeMatch]:
        assert data
        return [_FakeMatch([("memcpy", "msvc"), ("memcpy", "msvc")])]


def _checkout(tmp_path: Path, *, blob: bytes = b"IDASGNfake") -> Path:
    root = tmp_path / "sigs"
    (root / "msvc" / "vc6").mkdir(parents=True)
    (root / "msvc" / "vc6" / "libc.sig").write_bytes(blob)
    (root / "index.json").write_text(
        json.dumps(
            {
                "files": {
                    "msvc/vc6/libc.sig": {
                        "arch": "x86",
                        "family": "msvc",
                        "source": "vc6",
                        "patterns": 7,
                    }
                }
            }
        )
    )
    return root


class TestCatalog:
    def test_refresh_indexes_one_row_per_file(
        self, tmp_path: Path, conn: sqlite3.Connection
    ) -> None:
        root = _checkout(tmp_path)

        result = flirt_sigs.refresh(conn, root)

        assert result == {"added": 1, "updated": 0, "unchanged": 0, "pruned": 0}
        row = flirt_sigs.list_sigsets(conn)[0]
        assert row["rel_path"] == "msvc/vc6/libc.sig"
        assert row["arch"] == "x86"
        assert row["family"] == "msvc"
        assert row["pattern_count"] == 7
        assert row["enabled"] == 1

    def test_blob_paths_refuse_a_catalog_row_that_escapes_the_root(
        self, tmp_path: Path, conn: sqlite3.Connection
    ) -> None:
        root = _checkout(tmp_path)
        flirt_sigs.refresh(conn, root)
        conn.execute(
            "UPDATE sigset SET rel_path = ? WHERE rel_path = ?",
            ("../../outside.sig", "msvc/vc6/libc.sig"),
        )
        conn.commit()

        assert flirt_sigs._blob_paths(conn, "x86", root) == []

    def test_a_second_refresh_of_unchanged_bytes_writes_nothing(
        self, tmp_path: Path, conn: sqlite3.Connection
    ) -> None:
        root = _checkout(tmp_path)
        flirt_sigs.refresh(conn, root)

        result = flirt_sigs.refresh(conn, root)

        assert result == {"added": 0, "updated": 0, "unchanged": 1, "pruned": 0}

    def test_changed_bytes_update_in_place_and_keep_the_enabled_flag(
        self, tmp_path: Path, conn: sqlite3.Connection
    ) -> None:
        root = _checkout(tmp_path)
        flirt_sigs.refresh(conn, root)
        sigset_id = flirt_sigs.list_sigsets(conn)[0]["id"]
        flirt_sigs.set_enabled(conn, sigset_id, False)

        (root / "msvc" / "vc6" / "libc.sig").write_bytes(b"IDASGNchanged")
        result = flirt_sigs.refresh(conn, root)

        assert result["updated"] == 1
        rows = flirt_sigs.list_sigsets(conn)
        assert len(rows) == 1
        assert rows[0]["enabled"] == 0

    def test_the_key_moves_when_the_blob_moves(
        self, tmp_path: Path, conn: sqlite3.Connection
    ) -> None:
        root = _checkout(tmp_path)
        flirt_sigs.refresh(conn, root)
        before = flirt_sigs.sigset_key(conn, "x86")

        (root / "msvc" / "vc6" / "libc.sig").write_bytes(b"IDASGNother")
        flirt_sigs.refresh(conn, root)

        assert before
        assert isinstance(before, str)
        assert flirt_sigs.sigset_key(conn, "x86") != before

    def test_an_empty_catalog_has_no_key(self, tmp_path: Path, conn: sqlite3.Connection) -> None:
        assert flirt_sigs.sigset_key(conn, "x86") == ""
        assert flirt_sigs.matcher_for(conn, "x86", tmp_path)[1] is None


class TestScanCache:
    def test_a_scan_is_matched_once_and_served_from_cache_after(
        self, tmp_path: Path, conn: sqlite3.Connection, monkeypatch: Any
    ) -> None:
        root = _checkout(tmp_path)
        flirt_sigs.refresh(conn, root)
        flirt_sigs.forget_matchers()
        _FakeMatcher.builds = 0
        monkeypatch.setattr(flirt_sigs, "_build_matcher", lambda blobs: _FakeMatcher())

        first = flirt_sigs.scan(
            conn, binary_sha256="ab" * 32, arch="x86_32", data=b"\x00" * 64, root=root
        )
        second = flirt_sigs.scan(
            conn, binary_sha256="ab" * 32, arch="x86_32", data=b"\x00" * 64, root=root
        )

        assert first["cached"] is False
        assert second["cached"] is True
        assert second["sigset_key"] == first["sigset_key"]
        assert first["matches"] == [{"name": "memcpy", "library": "msvc"}]
        assert _FakeMatcher.builds == 1

    def test_a_refresh_prunes_the_orphaned_scan_row(
        self, tmp_path: Path, conn: sqlite3.Connection, monkeypatch: Any
    ) -> None:
        root = _checkout(tmp_path)
        flirt_sigs.refresh(conn, root)
        monkeypatch.setattr(flirt_sigs, "_build_matcher", lambda blobs: _FakeMatcher())
        flirt_sigs.scan(conn, binary_sha256="ab" * 32, arch="x86", data=b"\x00" * 64, root=root)

        (root / "msvc" / "vc6" / "libc.sig").write_bytes(b"IDASGNother")
        flirt_sigs.refresh(conn, root)
        again = flirt_sigs.scan(
            conn, binary_sha256="ab" * 32, arch="x86", data=b"\x00" * 64, root=root
        )

        assert again["cached"] is False
        assert conn.execute("SELECT COUNT(*) AS n FROM flirt_scan").fetchone()["n"] == 1

    def test_disabling_a_sigset_forgets_matchers_and_prunes_scans(
        self, tmp_path: Path, conn: sqlite3.Connection, monkeypatch: Any
    ) -> None:
        root = _checkout(tmp_path)
        flirt_sigs.refresh(conn, root)
        monkeypatch.setattr(flirt_sigs, "_build_matcher", lambda blobs: _FakeMatcher())
        flirt_sigs.scan(conn, binary_sha256="ab" * 32, arch="x86", data=b"\x00" * 64, root=root)
        sigset_id = flirt_sigs.list_sigsets(conn)[0]["id"]
        assert flirt_sigs.matcher_for(conn, "x86", root)[1] is not None

        assert flirt_sigs.set_enabled(conn, sigset_id, False) is True

        assert flirt_sigs.sigset_key(conn, "x86") == ""
        assert conn.execute("SELECT COUNT(*) AS n FROM flirt_scan").fetchone()["n"] == 0
        # The in-process map was cleared; an empty catalog builds nothing.
        assert flirt_sigs.matcher_for(conn, "x86", root)[1] is None

    def test_concurrent_misses_share_one_match(
        self, tmp_path: Path, portal_db: Path, monkeypatch: Any
    ) -> None:
        import threading
        import time

        from reportal import store

        root = _checkout(tmp_path)
        with contextlib.closing(store.connect(portal_db)) as seed:
            flirt_sigs.refresh(seed, root)
        flirt_sigs.forget_matchers()
        _FakeMatcher.builds = 0
        matches = 0
        match_lock = threading.Lock()

        class _SlowMatcher(_FakeMatcher):
            def match(self, data: bytes) -> list[_FakeMatch]:
                nonlocal matches
                with match_lock:
                    matches += 1
                # Hold the gate open long enough for the other waiters to park.
                time.sleep(0.2)
                return super().match(data)

        monkeypatch.setattr(flirt_sigs, "_build_matcher", lambda blobs: _SlowMatcher())
        results: list[dict[str, Any]] = []
        errors: list[BaseException] = []
        barrier = threading.Barrier(4)

        def worker() -> None:
            try:
                with contextlib.closing(store.connect(portal_db)) as local:
                    barrier.wait(timeout=5.0)
                    results.append(
                        flirt_sigs.scan(
                            local,
                            binary_sha256="ab" * 32,
                            arch="x86",
                            data=b"\x00" * 64,
                            root=root,
                        )
                    )
            except BaseException as exc:  # collect for the parent
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5.0)
            assert not thread.is_alive()

        assert not errors
        assert len(results) == 4
        assert matches == 1
        assert _FakeMatcher.builds == 1
        assert sum(1 for row in results if row["cached"]) == 3
        assert sum(1 for row in results if not row["cached"]) == 1

    def test_concurrent_matcher_misses_share_one_build(
        self, tmp_path: Path, portal_db: Path, monkeypatch: Any
    ) -> None:
        import threading
        import time

        from reportal import store

        root = _checkout(tmp_path)
        with contextlib.closing(store.connect(portal_db)) as seed:
            flirt_sigs.refresh(seed, root)
        flirt_sigs.forget_matchers()
        _FakeMatcher.builds = 0

        def _slow_build(blobs: Any) -> _FakeMatcher:
            time.sleep(0.2)
            return _FakeMatcher()

        monkeypatch.setattr(flirt_sigs, "_build_matcher", _slow_build)
        results: list[Any] = []
        errors: list[BaseException] = []
        barrier = threading.Barrier(4)

        def worker() -> None:
            try:
                with contextlib.closing(store.connect(portal_db)) as local:
                    barrier.wait(timeout=5.0)
                    results.append(flirt_sigs.matcher_for(local, "x86", root)[1])
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5.0)
            assert not thread.is_alive()

        assert not errors
        assert len(results) == 4
        assert _FakeMatcher.builds == 1
        assert all(matcher is results[0] for matcher in results)

    def test_a_failed_leader_does_not_fan_waiters_into_matches(
        self, tmp_path: Path, portal_db: Path, monkeypatch: Any
    ) -> None:
        import threading
        import time

        from reportal import store

        root = _checkout(tmp_path)
        with contextlib.closing(store.connect(portal_db)) as seed:
            flirt_sigs.refresh(seed, root)
        flirt_sigs.forget_matchers()
        attempts = 0
        attempt_lock = threading.Lock()

        class _FailThenMatch(_FakeMatcher):
            def match(self, data: bytes) -> list[_FakeMatch]:
                nonlocal attempts
                with attempt_lock:
                    attempts += 1
                    first = attempts == 1
                if first:
                    time.sleep(0.15)
                    raise RuntimeError("matcher blew up")
                return super().match(data)

        monkeypatch.setattr(flirt_sigs, "_build_matcher", lambda blobs: _FailThenMatch())
        results: list[dict[str, Any]] = []
        errors: list[BaseException] = []
        barrier = threading.Barrier(3)

        def worker() -> None:
            try:
                with contextlib.closing(store.connect(portal_db)) as local:
                    barrier.wait(timeout=5.0)
                    results.append(
                        flirt_sigs.scan(
                            local,
                            binary_sha256="cd" * 32,
                            arch="x86",
                            data=b"\x00" * 64,
                            root=root,
                        )
                    )
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(3)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5.0)
            assert not thread.is_alive()

        # One failed leader plus one successful re-entry; waiters must not each match.
        assert attempts == 2
        assert len(errors) == 1
        assert len(results) == 2
        assert all(row["match_count"] == 1 for row in results)

    def test_clear_cache_keeps_the_catalog(
        self, tmp_path: Path, conn: sqlite3.Connection, monkeypatch: Any
    ) -> None:
        root = _checkout(tmp_path)
        flirt_sigs.refresh(conn, root)
        monkeypatch.setattr(flirt_sigs, "_build_matcher", lambda blobs: _FakeMatcher())
        flirt_sigs.scan(conn, binary_sha256="ab" * 32, arch="x86", data=b"\x00" * 64, root=root)

        assert flirt_sigs.clear_cache(conn) == 1
        assert flirt_sigs.cached_scan(conn, "ab" * 32, "x86") is None
        assert len(flirt_sigs.list_sigsets(conn)) == 1


class TestRoutes:
    def test_refresh_indexes_the_configured_checkout(
        self, tmp_path: Path, portal_db: Path, monkeypatch: Any
    ) -> None:
        from conftest import json_body, wsgi_request

        root = _checkout(tmp_path)
        monkeypatch.setenv(flirt_sigs.SIGS_DIR_ENV, str(root))
        flirt_sigs.forget_matchers()

        status, headers, body = wsgi_request("POST", "/api/flirt/sigsets/refresh")
        assert status == "200 OK"
        assert json_body(body, headers)["added"] == 1

        status, headers, body = wsgi_request("GET", "/api/flirt/sigsets?arch=x86")
        assert status == "200 OK"
        payload = json_body(body, headers)
        assert [row["rel_path"] for row in payload["sigsets"]] == ["msvc/vc6/libc.sig"]

    def test_no_configured_checkout_is_a_400_not_a_crash(
        self, portal_db: Path, monkeypatch: Any
    ) -> None:
        from conftest import json_body, wsgi_request

        monkeypatch.delenv(flirt_sigs.SIGS_DIR_ENV, raising=False)

        status, headers, body = wsgi_request("POST", "/api/flirt/sigsets/refresh")

        assert status == "400 Bad Request"
        assert json_body(body, headers)["error"] == "no-signature-dir"

    def test_an_unscanned_binary_reports_404(
        self, tmp_path: Path, portal_db: Path, monkeypatch: Any
    ) -> None:
        from conftest import json_body, wsgi_request

        from reportal import store

        root = _checkout(tmp_path)
        monkeypatch.setenv(flirt_sigs.SIGS_DIR_ENV, str(root))
        with contextlib.closing(store.connect(portal_db)) as raw:
            binary_id = store.add_binary(
                raw, name="sample.exe", path=str(tmp_path / "sample.exe"), sha256="cd" * 32
            )

        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/flirt")

        assert status == "404 Not Found"
        assert json_body(body, headers)["error"] == "no-flirt-scan"

    def test_a_run_stores_a_reading_and_a_second_run_reads_it_back(
        self, tmp_path: Path, portal_db: Path, monkeypatch: Any
    ) -> None:
        from conftest import json_body, wsgi_request

        from reportal import store

        root = _checkout(tmp_path)
        monkeypatch.setenv(flirt_sigs.SIGS_DIR_ENV, str(root))
        flirt_sigs.forget_matchers()
        _FakeMatcher.builds = 0
        monkeypatch.setattr(flirt_sigs, "_build_matcher", lambda blobs: _FakeMatcher())
        sample = tmp_path / "sample.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 128)
        with contextlib.closing(store.connect(portal_db)) as raw:
            flirt_sigs.refresh(raw, root)
            binary_id = store.add_binary(
                raw,
                name="sample.exe",
                path=str(sample),
                sha256="cd" * 32,
                size=sample.stat().st_size,
            )

        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{binary_id}/flirt", body=b'{"arch": "x86"}'
        )

        assert status == "200 OK"
        payload = json_body(body, headers)
        assert payload["match_count"] == 1
        assert payload["libraries"] == [{"library": "msvc", "matches": 1, "names": ["memcpy"]}]
        assert payload["cached"] is False

        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/flirt")
        assert status == "200 OK"
        assert json_body(body, headers)["libraries"] == payload["libraries"]
        assert _FakeMatcher.builds == 1

    def test_apply_renames_the_function_and_refuses_a_manual_name(
        self, tmp_path: Path, portal_db: Path, monkeypatch: Any
    ) -> None:
        from conftest import json_body, wsgi_request

        from reportal import store

        root = _checkout(tmp_path)
        monkeypatch.setenv(flirt_sigs.SIGS_DIR_ENV, str(root))
        sample = tmp_path / "sample.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 128)
        with contextlib.closing(store.connect(portal_db)) as raw:
            binary_id = store.add_binary(raw, name="sample.exe", path=str(sample), sha256="cd" * 32)
            analysis_id = store.ensure_analysis_for_binary(raw, binary_id, engine=store.SCAN_ENGINE)
            function_id = store.add_function(
                raw, analysis_id=analysis_id, va=0x1000, name="", name_source=""
            )

        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{binary_id}/flirt/apply",
            body=json.dumps({"function_id": function_id, "name": "memcpy"}).encode(),
        )

        assert status == "200 OK"
        assert json_body(body, headers)["new_name"] == "memcpy"
        with contextlib.closing(store.connect(portal_db)) as raw:
            row = store.get_function(raw, function_id)
            assert row is not None and row["name_source"] == flirt_sigs.PROPOSAL_SOURCE
            store.rename_function(raw, function_id, new_name="analyst_name", actor="ana")

        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{binary_id}/flirt/apply",
            body=json.dumps({"function_id": function_id, "name": "memcpy"}).encode(),
        )

        assert status == "400 Bad Request"
        assert json_body(body, headers)["error"] == "manual-name"

    def test_apply_refuses_a_function_of_another_binary(
        self, tmp_path: Path, portal_db: Path, monkeypatch: Any
    ) -> None:
        from conftest import json_body, wsgi_request

        from reportal import store

        sample = tmp_path / "sample.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 128)
        other_path = tmp_path / "other.exe"
        other_path.write_bytes(b"MZ" + b"\x00" * 64)
        with contextlib.closing(store.connect(portal_db)) as raw:
            binary_id = store.add_binary(raw, name="sample.exe", path=str(sample), sha256="cd" * 32)
            other_id = store.add_binary(
                raw, name="other.exe", path=str(other_path), sha256="ef" * 32
            )
            other_analysis = store.ensure_analysis_for_binary(
                raw, other_id, engine=store.SCAN_ENGINE
            )
            other_fn = store.add_function(
                raw, analysis_id=other_analysis, va=0x1000, name="sub_1000", name_source=""
            )

        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{binary_id}/flirt/apply",
            body=json.dumps({"function_id": other_fn, "name": "memcpy"}).encode(),
        )

        assert status == "404 Not Found"
        assert json_body(body, headers)["error"] == "function not found"
        with contextlib.closing(store.connect(portal_db)) as raw:
            row = store.get_function(raw, other_fn)
            assert row is not None and row["name"] == "sub_1000"


class TestQueued:
    def test_the_job_kind_runs_the_scan(
        self, tmp_path: Path, portal_db: Path, monkeypatch: Any
    ) -> None:
        from reportal import jobs, store

        root = _checkout(tmp_path)
        monkeypatch.setenv(flirt_sigs.SIGS_DIR_ENV, str(root))
        flirt_sigs.forget_matchers()
        monkeypatch.setattr(flirt_sigs, "_build_matcher", lambda blobs: _FakeMatcher())
        sample = tmp_path / "sample.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 128)
        with contextlib.closing(store.connect(portal_db)) as raw:
            flirt_sigs.refresh(raw, root)
            binary_id = store.add_binary(raw, name="sample.exe", path=str(sample), sha256="ef" * 32)
            queued = jobs.submit(raw, kind="flirt", binary_id=binary_id, params={"arch": "x86"})
            jobs.run_pending(raw)
            job = jobs.get_job(raw, int(queued["id"]))

        assert job is not None and job["status"] == "done"
        assert job["result"]["match_count"] == 1


class TestCatalogEdges:
    def test_arch_aliases_fold(self) -> None:
        assert flirt_sigs.normalize_arch("AMD64") == "x64"
        assert flirt_sigs.normalize_arch("aarch64") == "arm64"
        assert flirt_sigs.normalize_arch("weird") == "weird"
        assert flirt_sigs.normalize_arch(None) == ""

    def test_broken_index_is_an_empty_catalog(self, tmp_path: Path) -> None:
        root = tmp_path / "sigs"
        root.mkdir()
        (root / "index.json").write_text("not json{")
        assert flirt_sigs._load_index(root) == {}
        assert flirt_sigs._load_index(tmp_path / "missing") == {}

    def test_prune_removes_deleted_files(self, tmp_path: Path, conn: sqlite3.Connection) -> None:
        root = _checkout(tmp_path)
        first = flirt_sigs.refresh(conn, root)
        assert first["added"] == 1
        (root / "msvc" / "vc6" / "libc.sig").unlink()
        second = flirt_sigs.refresh(conn, root, prune=True)
        assert second["pruned"] == 1
        assert flirt_sigs.list_sigsets(conn) == []

    def test_list_filters_by_arch_and_enabled(
        self, tmp_path: Path, conn: sqlite3.Connection
    ) -> None:
        root = _checkout(tmp_path)
        flirt_sigs.refresh(conn, root)
        assert len(flirt_sigs.list_sigsets(conn, arch="x86")) == 1
        assert flirt_sigs.list_sigsets(conn, arch="arm64") == []
        row = flirt_sigs.list_sigsets(conn)[0]
        assert flirt_sigs.set_enabled(conn, int(row["id"]), False) is True
        assert flirt_sigs.list_sigsets(conn, enabled_only=True) == []
        assert flirt_sigs.set_enabled(conn, 424242, True) is False

    def test_blob_paths_skip_a_symlink_escape(
        self, tmp_path: Path, conn: sqlite3.Connection
    ) -> None:
        root = _checkout(tmp_path)
        outside = tmp_path / "outside.sig"
        outside.write_bytes(b"IDASGNfake")
        link = root / "msvc" / "evil.sig"
        try:
            link.symlink_to(outside)
        except OSError:
            pytest.skip("symlinks are not permitted here")

        result = flirt_sigs.refresh(conn, root)
        assert result["added"] == 1
        assert {row["rel_path"] for row in flirt_sigs.list_sigsets(conn)} == {"msvc/vc6/libc.sig"}


class TestFlirtEdges:
    def test_arch_from_filename_tokens(self) -> None:
        assert flirt_sigs._arch_from_name("msvc/libc-x86_64.sig") == "x64"
        assert flirt_sigs._arch_from_name("libc-aarch64.sig") == "arm64"
        assert flirt_sigs._arch_from_name("libc-riscv64.sig") == "riscv64"
        assert flirt_sigs._arch_from_name("libc-powerpc.sig") == "ppc"
        assert flirt_sigs._arch_from_name("plain/libc.sig") == flirt_sigs.ARCH_UNKNOWN

    def test_matcher_cache_evicts_the_oldest(
        self, tmp_path: Path, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import reportal.flirt_sigs as _flirt

        monkeypatch.setattr(_flirt, "MATCHER_CACHE_MAX", 1)
        _flirt._MATCHERS.clear()
        root = _checkout(tmp_path)
        flirt_sigs.refresh(conn, root)
        monkeypatch.setattr(_flirt, "_build_matcher", lambda blobs: object())
        first_key, _ = flirt_sigs.matcher_for(conn, "x86", root)
        assert first_key
        (root / "msvc" / "vc6" / "libc.sig").write_bytes(b"IDASGNchanged!")
        flirt_sigs.refresh(conn, root)
        second_key, _ = flirt_sigs.matcher_for(conn, "x86", root)
        assert second_key != first_key
        assert len(_flirt._MATCHERS) == 1
        _flirt._MATCHERS.clear()

    def test_empty_symbol_pairs_are_skipped(
        self, tmp_path: Path, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import reportal.flirt_sigs as _flirt

        class _EmptyMatch:
            names = [("", "")]

        class _EmptyMatcher:
            def match(self, data: bytes) -> list[_EmptyMatch]:
                assert data
                return [_EmptyMatch()]

        _flirt._MATCHERS.clear()
        root = _checkout(tmp_path)
        flirt_sigs.refresh(conn, root)
        monkeypatch.setattr(_flirt, "_build_matcher", lambda blobs: _EmptyMatcher())
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 64)
        payload = flirt_sigs.scan(
            conn, binary_sha256="ab" * 32, arch="x86", data=target.read_bytes(), root=root
        )
        assert payload["matches"] == []
        _flirt._MATCHERS.clear()


class TestSigsDirText:
    def test_unset_is_blank(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(flirt_sigs.SIGS_DIR_ENV, raising=False)
        assert flirt_sigs.sigs_dir_text() == ""

    def test_set_is_text(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setenv(flirt_sigs.SIGS_DIR_ENV, str(tmp_path))
        assert flirt_sigs.sigs_dir_text() == str(tmp_path)
