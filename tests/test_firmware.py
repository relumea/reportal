"""Tests for firmware carving and the region extraction that follows it."""

from __future__ import annotations

import contextlib
import gzip
import io
import json
import sqlite3
import tarfile
import zipfile
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import api, cli, firmware, journal, store
from reportal._paths import DB_ENV

runner = CliRunner()


def _firmware_bytes() -> tuple[bytes, int, int]:
    """A synthetic image: a gzip member, a squashfs magic and a nested zip.

    Returns the bytes and the offsets the squashfs magic and the zip start at.
    """
    blob = bytearray(b"\x00" * 8192)
    packed = gzip.compress(b"firmware payload")
    blob[4096 : 4096 + len(packed)] = packed
    squashfs_at = len(blob)
    blob += b"hsqs" + bytes(range(256)) * 8
    zip_at = len(blob)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("inside.bin", b"member bytes")
    blob += buffer.getvalue()
    return bytes(blob), squashfs_at, zip_at


def _seed(conn: sqlite3.Connection, workspace: Path) -> dict[str, int]:
    """A workspace with the synthetic firmware stored as a binary."""
    payload, squashfs_at, zip_at = _firmware_bytes()
    directory = Path(workspace) / "binaries"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "firmware.bin"
    path.write_bytes(payload)
    binary_id = store.add_binary(
        conn, sha256="a" * 64, name="firmware.bin", path=str(path), size=len(payload)
    )
    return {"binary": binary_id, "squashfs": squashfs_at, "zip": zip_at, "size": len(payload)}


class TestCarve:
    def test_it_finds_the_regions_and_their_entropy(self, tmp_path: Path) -> None:
        payload, squashfs_at, zip_at = _firmware_bytes()
        path = tmp_path / "fw.bin"
        path.write_bytes(payload)

        result = firmware.carve(path)

        kinds = [region["kind"] for region in result["regions"]]
        assert "gzip" in kinds
        assert "squashfs" in kinds
        assert "zip" in kinds
        offsets = [region["offset"] for region in result["regions"]]
        assert 4096 in offsets
        assert squashfs_at in offsets
        assert zip_at in offsets
        assert result["size"] == len(payload)
        assert result["truncated"] is False
        assert result["entropy_window"] == firmware.ENTROPY_WINDOW
        assert result["entropy"], "the entropy map is never empty for a non-empty file"
        assert result["extractable_kinds"] == ["gzip", "tar", "zip"]

    def test_a_region_at_offset_zero_is_the_signature_reading(self, tmp_path: Path) -> None:
        path = tmp_path / "fw.bin"
        path.write_bytes(b"hsqs" + b"\x01" * 128)

        result = firmware.carve(path)

        assert result["regions"][0]["confidence"] == firmware.CONFIDENCE_SIGNATURE
        assert result["regions"][0]["offset"] == 0

    def test_an_embedded_region_is_labelled_embedded(self, tmp_path: Path) -> None:
        path = tmp_path / "fw.bin"
        path.write_bytes(b"\x00" * 64 + b"hsqs" + b"\x01" * 64)

        result = firmware.carve(path)

        assert result["regions"][0]["confidence"] == firmware.CONFIDENCE_EMBEDDED

    def test_a_signature_across_a_chunk_boundary_is_found(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(firmware, "SCAN_CHUNK_BYTES", 16)
        path = tmp_path / "fw.bin"
        path.write_bytes(b"\x00" * 30 + b"hsqs" + b"\x00" * 30)

        result = firmware.carve(path)

        assert [region["offset"] for region in result["regions"]] == [30]

    def test_the_entropy_map_is_sampled_and_bounded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(firmware, "MAX_ENTROPY_SAMPLES", 2)
        monkeypatch.setattr(firmware, "ENTROPY_WINDOW", 16)
        path = tmp_path / "fw.bin"
        path.write_bytes(bytes(range(256)) * 4)

        samples = firmware.entropy_map(path, size=path.stat().st_size)

        assert len(samples) == 2
        assert all(sample["length"] == 16 for sample in samples)
        assert all(sample["entropy"] <= 8 for sample in samples)

    def test_an_empty_file_has_no_entropy_and_no_regions(self, tmp_path: Path) -> None:
        path = tmp_path / "empty.bin"
        path.write_bytes(b"")

        result = firmware.carve(path)

        assert result["regions"] == []
        assert result["entropy"] == []

    def test_a_region_is_capped_and_says_it_is_truncated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(firmware, "MAX_REGION_BYTES", 8)
        path = tmp_path / "fw.bin"
        path.write_bytes(b"hsqs" + b"\x00" * 64)

        result = firmware.carve(path)

        assert result["regions"][0]["size"] == 8
        assert result["regions"][0]["truncated"] is True

    def test_a_gzip_region_is_trimmed_to_its_stream(self, tmp_path: Path) -> None:
        packed = gzip.compress(b"payload")
        path = tmp_path / "fw.bin"
        # The trailing bytes belong to the region (it runs to the next magic),
        # and the archive reader refuses a gzip with non-zero trailing data.
        path.write_bytes(b"\x00" * 16 + packed + b"\x01" * 8 + b"hsqs" + b"\x00" * 16)

        result = firmware.carve(path)
        gzip_region = next(region for region in result["regions"] if region["kind"] == "gzip")

        entry = firmware.region(path, index=int(gzip_region["index"]), regions_payload=result)

        assert entry["trimmed"] is True
        assert entry["size"] == len(packed)


class TestScanStore:
    def test_scan_stores_and_regions_reads_back(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = _seed(conn, tmp_path)

        payload = firmware.scan(conn, ids["binary"])

        assert payload["region_count"] >= 3
        stored = firmware.regions(conn, ids["binary"])
        assert stored is not None
        assert stored["region_count"] == payload["region_count"]
        analysis = store.get_analysis(conn, int(payload["analysis_id"]))
        assert analysis is not None and analysis["status"] == "done"

    def test_regions_is_none_before_the_first_scan(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="b" * 64, name="plain.bin")

        assert firmware.regions(conn, binary_id) is None

    def test_an_unknown_binary_or_a_missing_file_is_refused(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        with pytest.raises(firmware.FirmwareError):
            firmware.scan(conn, 4242)

        binary_id = store.add_binary(
            conn, sha256="c" * 64, name="gone.bin", path=str(tmp_path / "gone.bin")
        )
        with pytest.raises(firmware.FirmwareError) as caught:
            firmware.scan(conn, binary_id)
        assert caught.value.code == "binary not on disk"


class TestFirmwareApi:
    def _get(self, path: str) -> tuple[str, Any]:
        status, headers, body = wsgi_request("GET", path)
        return status, json_body(body, headers)

    def _post(self, path: str, body: dict[str, Any] | None = None) -> tuple[str, Any]:
        raw = b"" if body is None else json.dumps(body).encode()
        status, headers, payload = wsgi_request("POST", path, body=raw)
        return status, json_body(payload, headers)

    def test_the_scan_stores_the_pass_and_the_read_serves_it(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = _seed(conn, tmp_path)

        status, payload = self._post(f"/api/binaries/{ids['binary']}/firmware")

        assert status.startswith("200")
        assert payload["region_count"] >= 3
        assert payload["note"]

        read_status, stored = self._get(f"/api/binaries/{ids['binary']}/firmware")
        assert read_status.startswith("200")
        assert stored["region_count"] == payload["region_count"]

    def test_the_read_before_the_scan_is_404(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = _seed(conn, tmp_path)

        status, payload = self._get(f"/api/binaries/{ids['binary']}/firmware")

        assert status.startswith("404")
        assert payload["error"] == "no-scan"

    def test_the_carve_is_one_journaled_action_and_reverts(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        """The stored pass is a write like every other scan, so a revert takes it back."""
        ids = _seed(conn, tmp_path)

        status, payload = self._post(f"/api/binaries/{ids['binary']}/firmware")

        assert status.startswith("200")
        assert payload["journal_action"], "a scan route journals the row it stores"
        analysis_id = int(payload["analysis_id"])
        assert store.get_scan(conn, analysis_id, firmware.SCAN_KIND) is not None

        journal.revert_action(conn, payload["journal_action"])

        assert store.get_scan(conn, analysis_id, firmware.SCAN_KIND) is None
        assert store.get_analysis(conn, analysis_id) is None, "the pass created its carrier"

    def test_an_unknown_binary_is_404(self, conn: sqlite3.Connection) -> None:
        assert self._post("/api/binaries/4242/firmware")[0].startswith("404")
        assert self._get("/api/binaries/4242/firmware")[0].startswith("404")

    def test_extract_carves_every_region_and_reverts(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = _seed(conn, tmp_path)
        self._post(f"/api/binaries/{ids['binary']}/firmware")

        status, payload = self._post(f"/api/binaries/{ids['binary']}/firmware/extract")

        assert status.startswith("201")
        assert payload["kept"] >= 3, "the gzip member, the zip member and the squashfs carve"
        kinds = {member["kind"] for member in payload["members"]}
        assert {"gzip", "zip", "squashfs"} <= kinds
        collection = store.get_collection(conn, int(payload["collection_id"]))
        assert collection is not None
        carved = [
            member["binary_id"] for member in payload["members"] if member["binary_id"] is not None
        ]
        assert carved

        journal.revert_action(conn, payload["journal_action"])

        assert store.get_collection(conn, int(payload["collection_id"])) is None
        for binary_id in carved:
            assert store.get_binary(conn, int(binary_id)) is None

    def test_extract_selects_one_region(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        ids = _seed(conn, tmp_path)
        _, scan = self._post(f"/api/binaries/{ids['binary']}/firmware")
        squashfs = next(
            region["index"] for region in scan["regions"] if region["kind"] == "squashfs"
        )

        status, payload = self._post(
            f"/api/binaries/{ids['binary']}/firmware/extract", {"regions": [squashfs]}
        )

        assert status.startswith("201")
        assert [member["region"] for member in payload["members"]] == [squashfs]

    def test_extract_before_the_scan_is_404(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        ids = _seed(conn, tmp_path)

        status, payload = self._post(f"/api/binaries/{ids['binary']}/firmware/extract")

        assert status.startswith("404")
        assert payload["error"] == "no-scan"

    def test_an_out_of_range_region_is_400(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        ids = _seed(conn, tmp_path)
        self._post(f"/api/binaries/{ids['binary']}/firmware")

        status, payload = self._post(
            f"/api/binaries/{ids['binary']}/firmware/extract", {"regions": [99]}
        )

        assert status.startswith("404")
        assert payload["error"] == "region not found"

    def test_a_malformed_regions_list_is_400(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = _seed(conn, tmp_path)

        status, payload = self._post(
            f"/api/binaries/{ids['binary']}/firmware/extract", {"regions": "all"}
        )

        assert status.startswith("400")
        assert payload["error"] == "invalid-region"

    def test_an_unknown_collection_is_404(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        ids = _seed(conn, tmp_path)
        self._post(f"/api/binaries/{ids['binary']}/firmware")

        status, payload = self._post(
            f"/api/binaries/{ids['binary']}/firmware/extract", {"collection_id": 4242}
        )

        assert status.startswith("404")
        assert payload["error"] == "collection not found"

    def test_a_non_integer_collection_id_is_400(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = _seed(conn, tmp_path)
        self._post(f"/api/binaries/{ids['binary']}/firmware")

        status, payload = self._post(
            f"/api/binaries/{ids['binary']}/firmware/extract",
            {"collection_id": "main"},
        )

        assert status.startswith("400")
        assert payload["error"] == "collection_id must be an integer"


class TestFirmwareCli:
    def _portal(self, tmp_path: Path, monkeypatch: Any) -> dict[str, Any]:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            ids = _seed(conn, tmp_path)
        return {**ids, "db": db}

    def test_the_carve_prints_its_regions(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = self._portal(tmp_path, monkeypatch)

        result = runner.invoke(cli.app, ["firmware", str(ids["binary"]), "--json"])

        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["region_count"] >= 3

        human = runner.invoke(cli.app, ["firmware", str(ids["binary"])])
        assert human.exit_code == 0, human.output
        assert "region(s)" in human.output

    def test_the_extract_carves_one_region(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = self._portal(tmp_path, monkeypatch)
        assert runner.invoke(cli.app, ["firmware", str(ids["binary"])]).exit_code == 0

        result = runner.invoke(
            cli.app,
            ["firmware-extract", str(ids["binary"]), "--region", "0", "--json"],
        )

        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert len(payload["regions"]) == 1
        human = runner.invoke(cli.app, ["firmware-extract", str(ids["binary"])])
        assert human.exit_code == 0, human.output

    def test_an_unknown_binary_exits_non_zero(self, tmp_path: Path, monkeypatch: Any) -> None:
        self._portal(tmp_path, monkeypatch)

        assert runner.invoke(cli.app, ["firmware", "4242"]).exit_code == 1
        assert runner.invoke(cli.app, ["firmware-extract", "4242"]).exit_code == 1


class TestFirmwareMcp:
    def test_the_scan_stores_and_the_read_serves(
        self, portal_db: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        from reportal import mcp_tools

        ids = _seed(conn, tmp_path)
        run = mcp_tools.get_tool("run_firmware_scan")
        read = mcp_tools.get_tool("get_firmware_scan")
        assert run is not None and read is not None
        assert read.annotations.read_only_hint is True
        assert run.annotations.destructive_hint is True

        scanned = run.handler({"binary_id": ids["binary"]})

        assert scanned["region_count"] >= 3
        assert read.handler({"binary_id": ids["binary"]})["region_count"] == scanned["region_count"]

    def test_the_extract_carves_the_regions(
        self, portal_db: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        from reportal import mcp_tools

        ids = _seed(conn, tmp_path)
        api.firmware_carve_binary(conn, ids["binary"])
        tool = mcp_tools.get_tool("extract_firmware_regions")
        assert tool is not None

        payload = tool.handler({"binary_id": ids["binary"]})

        assert payload["kept"] >= 3
        assert payload["journal_action"]

    def test_the_read_before_the_scan_is_a_tool_error(
        self, portal_db: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        from reportal import mcp_tools

        ids = _seed(conn, tmp_path)
        tool = mcp_tools.get_tool("get_firmware_scan")
        assert tool is not None

        try:
            tool.handler({"binary_id": ids["binary"]})
        except mcp_tools.ToolError as exc:
            assert exc.error == "no-scan"
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("a missing scan must be a tool error")


class TestTarInsideGzip:
    def test_a_gzip_wrapped_tar_region_extracts_its_members(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            member = tarfile.TarInfo("inner.txt")
            data = b"inner payload"
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        packed = gzip.compress(buffer.getvalue())
        payload = b"\x00" * 32 + packed + b"\x00" * 32
        directory = Path(tmp_path) / "binaries"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "tarfw.bin"
        path.write_bytes(payload)
        binary_id = store.add_binary(
            conn, sha256="d" * 64, name="tarfw.bin", path=str(path), size=len(payload)
        )

        api.firmware_carve_binary(conn, binary_id)
        carved = api.firmware_extract_binary(conn, binary_id)

        names = {member["name"] for member in carved["members"]}
        assert "inner.txt" in names
        assert carved["kept"] == 1
