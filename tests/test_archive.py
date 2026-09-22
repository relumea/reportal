"""Tests for ``reportal.archive``: the supported formats and every refusal."""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import random
import struct
import tarfile
import zipfile
import zlib
from collections.abc import Iterable
from pathlib import Path

import pytest

from reportal import archive

# Content that does not collapse under compression, so a legitimate archive's
# ratio never trips the bomb guard the way a run of one byte would.
BODY = bytes(range(256)) * 4
OTHER = bytes(reversed(range(256))) * 3

# The password the encrypted-zip fixture is written with.
PASSWORD = "hunter2"


def _entry(path: str, data: bytes = BODY) -> tuple[str, bytes]:
    return path, data


def _write_zip(path: Path, entries: Iterable[tuple[str, bytes]]) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries:
            zf.writestr(name, data)


def _add_tar_entries(archive: tarfile.TarFile, entries: Iterable[tuple[str, bytes]]) -> None:
    for name, data in entries:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))


def _write_tar(path: Path, entries: Iterable[tuple[str, bytes]], mode: str = "") -> None:
    if mode == "gz":
        with tarfile.open(path, "w:gz") as archive:
            _add_tar_entries(archive, entries)
    elif mode == "bz2":
        with tarfile.open(path, "w:bz2") as archive:
            _add_tar_entries(archive, entries)
    elif mode == "xz":
        with tarfile.open(path, "w:xz") as archive:
            _add_tar_entries(archive, entries)
    else:
        with tarfile.open(path, "w") as archive:
            _add_tar_entries(archive, entries)


def _write_bomb_tar(path: Path, size: int) -> None:
    """A tar.bz2 holding one highly compressible member, past the ratio cap."""
    with tarfile.open(path, "w:bz2") as tf:
        info = tarfile.TarInfo("zeros.bin")
        info.size = size
        tf.addfile(info, io.BytesIO(b"\x00" * size))


def _write_tar_fifo(path: Path) -> None:
    with tarfile.open(path, "w") as tf:
        info = tarfile.TarInfo("pipe")
        info.type = tarfile.FIFOTYPE
        info.size = 0
        tf.addfile(info)


# ── a zipfile the stdlib cannot write: legacy ZipCrypto encryption ──
#
# `zipfile` reads ZipCrypto but cannot write it, and the encrypted-password
# path is part of what reportal claims, so the fixture builds the container by
# hand.  The algorithm is the one PKWARE documents and `zipfile` implements:
# three keys seeded from the password, a 12-byte header whose last byte is the
# CRC's high byte, then the data encrypted with the same keystream.

_CRC_TABLE = [0] * 256
for _n in range(256):
    _c = _n
    for _ in range(8):
        _c = (_c >> 1) ^ 0xEDB88320 if _c & 1 else _c >> 1
    _CRC_TABLE[_n] = _c


def _crc32_update(crc: int, byte: int) -> int:
    return (crc >> 8) ^ _CRC_TABLE[(crc ^ byte) & 0xFF]


class _ZipCrypto:
    """The legacy ZipCrypto keystream, enough to encrypt a stored entry."""

    def __init__(self, password: bytes) -> None:
        self.key0, self.key1, self.key2 = 305419896, 591751049, 878082192
        self._update(password)

    def _update(self, data: bytes) -> None:
        for byte in data:
            self.key0 = _crc32_update(self.key0, byte)
            self.key1 = (self.key1 + (self.key0 & 0xFF)) & 0xFFFFFFFF
            self.key1 = (self.key1 * 134775813 + 1) & 0xFFFFFFFF
            self.key2 = _crc32_update(self.key2, (self.key1 >> 24) & 0xFF)

    def _stream_byte(self) -> int:
        temp = (self.key2 | 2) & 0xFFFF
        return ((temp * (temp ^ 1)) >> 8) & 0xFF

    def encrypt(self, data: bytes) -> bytes:
        out = bytearray()
        for byte in data:
            out.append(byte ^ self._stream_byte())
            self._update(bytes([byte]))
        return bytes(out)


def _write_encrypted_zip(path: Path, name: str, data: bytes, password: bytes) -> None:
    crc = zlib.crc32(data) & 0xFFFFFFFF
    cipher = _ZipCrypto(password)
    header = bytes(11) + bytes([(crc >> 24) & 0xFF])
    payload = cipher.encrypt(header + data)
    name_bytes = name.encode()
    local = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50,
        20,
        0x0001,
        0,
        0,
        0,
        crc,
        len(payload),
        len(data),
        len(name_bytes),
        0,
    )
    local += name_bytes + payload
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50,
        20,
        20,
        0x0001,
        0,
        0,
        0,
        crc,
        len(payload),
        len(data),
        len(name_bytes),
        0,
        0,
        0,
        0,
        0,
        0,
    )
    central += name_bytes
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), len(local), 0)
    path.write_bytes(local + central + end)


def _extracted(root: Path) -> list[str]:
    """Every regular file under *root*, relative and posix-separated."""
    return sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file())


class TestSupportedFormats:
    def test_zip_round_trip(self, tmp_path: Path) -> None:
        source = tmp_path / "sample.zip"
        _write_zip(source, [_entry("dir/one.bin"), _entry("two.exe", OTHER)])
        dest = tmp_path / "out"
        result = archive.extract(source, dest)
        assert _extracted(dest) == ["dir/one.bin", "two.exe"]
        assert [member.skipped for member in result.members] == ["", ""]
        assert (dest / "dir" / "one.bin").read_bytes() == BODY

    def test_apk_is_read_as_a_zip(self, tmp_path: Path) -> None:
        source = tmp_path / "app.apk"
        _write_zip(source, [_entry("classes.dex", OTHER)])
        dest = tmp_path / "out"
        result = archive.extract(source, dest)
        assert result.kept[0].name == "classes.dex"
        assert _extracted(dest) == ["classes.dex"]

    @pytest.mark.parametrize(
        ("filename", "mode"),
        [
            ("plain.tar", ""),
            ("gzip.tar.gz", "gz"),
            ("short.tgz", "gz"),
            ("bzip.tar.bz2", "bz2"),
            ("xz.tar.xz", "xz"),
        ],
    )
    def test_tar_variants_round_trip(self, tmp_path: Path, filename: str, mode: str) -> None:
        source = tmp_path / filename
        _write_tar(source, [_entry("sub/one.bin"), _entry("two.bin", OTHER)], mode)
        dest = tmp_path / "out"
        result = archive.extract(source, dest)
        assert _extracted(dest) == ["sub/one.bin", "two.bin"]
        assert all(member.skipped == "" for member in result.members)

    def test_single_member_gzip_names_the_member_after_the_archive(self, tmp_path: Path) -> None:
        source = tmp_path / "firmware.bin.gz"
        with gzip.open(source, "wb") as handle:
            handle.write(BODY)
        dest = tmp_path / "out"
        result = archive.extract(source, dest)
        assert result.kept[0].name == "firmware.bin"
        assert (dest / "firmware.bin").read_bytes() == BODY

    @pytest.mark.parametrize("suffix", [".bz2", ".xz"])
    def test_stored_compressed_tar_name_is_read_as_a_tar(self, tmp_path: Path, suffix: str) -> None:
        # An upload keeps only the last suffix, so `foo.tar.bz2` arrives as
        # `<sha>.bz2`; the reader has to sniff the contents.
        source = tmp_path / f"deadbeef{suffix}"
        _write_tar(source, [_entry("one.bin")], "bz2" if suffix == ".bz2" else "xz")
        dest = tmp_path / "out"
        archive.extract(source, dest)
        assert archive.archive_kind(source) == archive.KIND_TAR
        assert _extracted(dest) == ["one.bin"]

    def test_large_but_legitimate_gzip_is_not_a_bomb(self, tmp_path: Path) -> None:
        source = tmp_path / "big.gz"
        payload = random.Random(0).randbytes(256 * 1024)
        with gzip.open(source, "wb") as handle:
            handle.write(payload)
        dest = tmp_path / "out"
        result = archive.extract(source, dest)
        assert result.kept[0].size == len(payload)


class TestPassword:
    def test_encrypted_zip_with_the_password_extracts(self, tmp_path: Path) -> None:
        source = tmp_path / "secret.zip"
        _write_encrypted_zip(source, "secret.bin", BODY, PASSWORD.encode())
        dest = tmp_path / "out"
        result = archive.extract(source, dest, password=PASSWORD)
        assert result.kept[0].name == "secret.bin"
        assert (dest / "secret.bin").read_bytes() == BODY

    def test_encrypted_zip_without_a_password_is_refused(self, tmp_path: Path) -> None:
        source = tmp_path / "secret.zip"
        _write_encrypted_zip(source, "secret.bin", BODY, PASSWORD.encode())
        dest = tmp_path / "out"
        with pytest.raises(archive.ArchiveError) as caught:
            archive.extract(source, dest)
        assert caught.value.code == "password-required"
        assert _extracted(dest) == []

    def test_wrong_password_is_refused(self, tmp_path: Path) -> None:
        source = tmp_path / "secret.zip"
        _write_encrypted_zip(source, "secret.bin", BODY, PASSWORD.encode())
        dest = tmp_path / "out"
        with pytest.raises(archive.ArchiveError) as caught:
            archive.extract(source, dest, password="wrong")
        assert caught.value.code == "bad-password"
        assert _extracted(dest) == []

    def test_tar_password_is_noted_as_unused(self, tmp_path: Path) -> None:
        source = tmp_path / "plain.tar"
        _write_tar(source, [_entry("one.bin")])
        result = archive.extract(source, tmp_path / "out", password="ignored")
        assert any("no password" in note for note in result.notes)


class TestRefusals:
    def test_traversal_name_is_refused(self, tmp_path: Path) -> None:
        source = tmp_path / "evil.zip"
        _write_zip(source, [_entry("../escape.bin"), _entry("good.bin", OTHER)])
        dest = tmp_path / "out"
        result = archive.extract(source, dest)
        skipped = {member.name: member.skipped for member in result.members if member.skipped}
        assert "../escape.bin" in skipped
        assert "escapes" in skipped["../escape.bin"]
        assert _extracted(dest) == ["good.bin"]
        assert not (tmp_path / "escape.bin").exists()

    def test_absolute_name_is_refused(self, tmp_path: Path) -> None:
        source = tmp_path / "abs.tar"
        _write_tar(source, [_entry("/etc/passwd")])
        dest = tmp_path / "out"
        result = archive.extract(source, dest)
        assert "absolute" in result.members[0].skipped
        assert _extracted(dest) == []

    def test_symlink_is_refused(self, tmp_path: Path) -> None:
        source = tmp_path / "link.tar"
        with tarfile.open(source, "w") as tf:
            info = tarfile.TarInfo("link")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            tf.addfile(info)
        dest = tmp_path / "out"
        result = archive.extract(source, dest)
        assert result.members[0].skipped == "the member is a symlink"
        assert _extracted(dest) == []

    def test_hardlink_is_refused(self, tmp_path: Path) -> None:
        source = tmp_path / "hard.tar"
        with tarfile.open(source, "w") as tf:
            data = tarfile.TarInfo("real.bin")
            data.size = len(BODY)
            tf.addfile(data, io.BytesIO(BODY))
            link = tarfile.TarInfo("hard")
            link.type = tarfile.LNKTYPE
            link.linkname = "real.bin"
            tf.addfile(link)
        result = archive.extract(source, tmp_path / "out")
        skipped = {member.name: member.skipped for member in result.members}
        assert skipped["hard"] == "the member is a hardlink"

    def test_fifo_is_refused(self, tmp_path: Path) -> None:
        source = tmp_path / "fifo.tar"
        _write_tar_fifo(source)
        result = archive.extract(source, tmp_path / "out")
        assert result.members[0].skipped == "the member is a FIFO"

    def test_zip_symlink_mode_is_refused(self, tmp_path: Path) -> None:
        source = tmp_path / "link.zip"
        with zipfile.ZipFile(source, "w") as zf:
            info = zipfile.ZipInfo("link")
            info.external_attr = (0xA1FF) << 16  # S_IFLNK | 0777
            zf.writestr(info, "/etc/passwd")
        result = archive.extract(source, tmp_path / "out")
        assert result.members[0].skipped == "the member is a symlink"

    def test_oversized_member_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(archive, "MAX_MEMBER_BYTES", 16)
        source = tmp_path / "big.zip"
        _write_zip(source, [_entry("big.bin", BODY)])
        dest = tmp_path / "out"
        result = archive.extract(source, dest)
        assert "MAX_MEMBER_BYTES" in result.members[0].skipped
        assert _extracted(dest) == []

    def test_ratio_bomb_is_refused(self, tmp_path: Path) -> None:
        source = tmp_path / "bomb.zip"
        _write_zip(source, [_entry("zeros.bin", b"\x00" * 100_000)])
        dest = tmp_path / "out"
        result = archive.extract(source, dest)
        assert "compression ratio" in result.members[0].skipped
        assert _extracted(dest) == []

    def test_total_size_cap_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(archive, "MAX_TOTAL_BYTES", 10)
        source = tmp_path / "many.zip"
        _write_zip(source, [_entry("one.bin", BODY[:8]), _entry("two.bin", BODY[8:16])])
        result = archive.extract(source, tmp_path / "out")
        assert "MAX_TOTAL_BYTES" in result.members[1].skipped

    def test_too_many_members_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(archive, "MAX_MEMBERS", 1)
        source = tmp_path / "many.zip"
        _write_zip(source, [_entry("one.bin"), _entry("two.bin", OTHER)])
        with pytest.raises(archive.ArchiveError) as caught:
            archive.extract(source, tmp_path / "out")
        assert caught.value.code == "too-many-members"

    def test_compressed_tar_bomb_is_refused(self, tmp_path: Path) -> None:
        source = tmp_path / "bomb.tar.bz2"
        _write_bomb_tar(source, 4 * 1024 * 1024)
        dest = tmp_path / "out"
        with pytest.raises(archive.ArchiveError) as caught:
            archive.extract(source, dest)
        assert caught.value.code == "archive-too-large"
        assert _extracted(dest) == []


class TestUnsupportedFormats:
    def test_rar_names_the_external_tool(self, tmp_path: Path) -> None:
        source = tmp_path / "sample.rar"
        source.write_bytes(b"Rar!\x1a\x07\x00")
        with pytest.raises(archive.ArchiveError) as caught:
            archive.archive_kind(source)
        assert caught.value.code == "external-tool-required"
        assert "unrar" in caught.value.detail

    def test_7z_names_the_external_tool(self, tmp_path: Path) -> None:
        source = tmp_path / "sample.7z"
        source.write_bytes(b"7z\xbc\xaf\x27\x1c")
        with pytest.raises(archive.ArchiveError) as caught:
            archive.archive_kind(source)
        assert caught.value.code == "external-tool-required"
        assert "7z" in caught.value.detail

    def test_unknown_extension_is_refused(self, tmp_path: Path) -> None:
        source = tmp_path / "sample.exe"
        source.write_bytes(b"MZ")
        with pytest.raises(archive.ArchiveError) as caught:
            archive.archive_kind(source)
        assert caught.value.code == "unsupported-format"

    def test_missing_file_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(archive.ArchiveError) as caught:
            archive.extract(tmp_path / "nope.zip", tmp_path / "out")
        assert caught.value.code == "corrupt-archive"

    def test_unsupported_extension_in_extract(self, tmp_path: Path) -> None:
        source = tmp_path / "sample.rar"
        source.write_bytes(b"Rar!")
        with pytest.raises(archive.ArchiveError) as caught:
            archive.extract(source, tmp_path / "out")
        assert caught.value.code == "external-tool-required"


def test_archive_kind_reads_a_gz_tar(tmp_path: Path) -> None:
    source = tmp_path / "store.gz"
    _write_tar(source, [_entry("one.bin")], "gz")
    assert archive.archive_kind(source) == archive.KIND_TAR


def test_archive_kind_reads_a_plain_gzip(tmp_path: Path) -> None:
    source = tmp_path / "one.gz"
    with gzip.open(source, "wb") as handle:
        handle.write(BODY)
    assert archive.archive_kind(source) == archive.KIND_GZIP


def test_bz2_without_a_tar_is_refused(tmp_path: Path) -> None:
    source = tmp_path / "raw.bz2"
    source.write_bytes(bz2.compress(BODY))
    with pytest.raises(archive.ArchiveError) as caught:
        archive.archive_kind(source)
    assert caught.value.code == "unsupported-format"


def test_xz_without_a_tar_is_refused(tmp_path: Path) -> None:
    source = tmp_path / "raw.xz"
    source.write_bytes(lzma.compress(BODY))
    with pytest.raises(archive.ArchiveError) as caught:
        archive.archive_kind(source)
    assert caught.value.code == "unsupported-format"


def test_notes_report_the_extraction_sizes(tmp_path: Path) -> None:
    source = tmp_path / "one.zip"
    _write_zip(source, [_entry("one.bin")])
    result = archive.extract(source, tmp_path / "out")
    assert result.notes and "compressed bytes" in result.notes[0]


def test_mapping_helpers_are_typed(tmp_path: Path) -> None:
    """The public result types carry exactly the fields the route reads."""
    source = tmp_path / "one.zip"
    _write_zip(source, [_entry("one.bin")])
    result: archive.Extraction = archive.extract(source, tmp_path / "out")
    member: archive.MemberOutcome = result.kept[0]
    assert (member.name, member.size, member.skipped) == ("one.bin", len(BODY), "")
    assert isinstance(result.notes, tuple)


def test_empty_archive_has_no_members(tmp_path: Path) -> None:
    source = tmp_path / "empty.zip"
    _write_zip(source, [])
    result = archive.extract(source, tmp_path / "out")
    assert result.members == ()
    assert result.kept == ()


def test_zip_directory_entries_are_skipped(tmp_path: Path) -> None:
    source = tmp_path / "dirs.zip"
    with zipfile.ZipFile(source, "w") as zf:
        zf.writestr("sub/", b"")
        zf.writestr("sub/one.bin", BODY)
    result = archive.extract(source, tmp_path / "out")
    assert [member.name for member in result.members] == ["sub/one.bin"]


def test_corrupt_zip_is_refused(tmp_path: Path) -> None:
    source = tmp_path / "broken.zip"
    source.write_bytes(b"not a zip at all")
    with pytest.raises(archive.ArchiveError) as caught:
        archive.extract(source, tmp_path / "out")
    assert caught.value.code == "corrupt-archive"


def test_corrupt_gzip_is_refused(tmp_path: Path) -> None:
    source = tmp_path / "broken.gz"
    source.write_bytes(b"\x1f\x8b\x08\x00garbage")
    with pytest.raises(archive.ArchiveError) as caught:
        archive.extract(source, tmp_path / "out")
    assert caught.value.code == "corrupt-archive"


def test_member_entry_helper_is_stable() -> None:
    """The fixture builder keeps producing the bytes the round trips assert."""
    name, data = _entry("x.bin", OTHER)
    assert data is OTHER
    assert _entry("x.bin", OTHER) == (name, data)


def test_zipcrypto_helper_round_trips_through_zipfile(tmp_path: Path) -> None:
    """The hand-built encrypted zip is readable by the stdlib with the password."""
    source = tmp_path / "secret.zip"
    _write_encrypted_zip(source, "secret.bin", BODY, PASSWORD.encode())
    with zipfile.ZipFile(source) as zf:
        assert zf.read("secret.bin", pwd=PASSWORD.encode()) == BODY


class TestRefusalHelpers:
    def test_refuse_name_rejects_hostile_names(self, tmp_path: Path) -> None:
        assert archive._refuse_name("", tmp_path)[0] is None
        assert archive._refuse_name("a\x00b", tmp_path)[0] is None
        assert archive._refuse_name("a\\b", tmp_path)[0] is None
        assert archive._refuse_name("/abs", tmp_path)[0] is None
        assert archive._refuse_name("../up", tmp_path)[0] is None
        target, reason = archive._refuse_name("sub/ok.txt", tmp_path)
        assert target is not None and reason == ""

    def test_refuse_mode_rejects_special_files(self) -> None:
        import stat as _stat

        assert archive._refuse_mode(0o100644) == ""
        assert "symlink" in archive._refuse_mode(_stat.S_IFLNK | 0o777)
        assert "device" in archive._refuse_mode(_stat.S_IFCHR | 0o666)
        assert "device" in archive._refuse_mode(_stat.S_IFBLK | 0o666)
        assert "FIFO" in archive._refuse_mode(_stat.S_IFIFO | 0o666)
        assert "socket" in archive._refuse_mode(_stat.S_IFSOCK | 0o666)

    def test_ratio_refusal_flags_bombs(self) -> None:
        assert archive._ratio_refusal(10, 0) == ""
        assert archive._ratio_refusal(10, 10) == ""
        assert "ratio" in archive._ratio_refusal(10**9, 10)


class TestCorruptArchives:
    def test_truncated_zip_is_corrupt(self, tmp_path: Path) -> None:
        target = tmp_path / "cut.zip"
        target.write_bytes(b"PK\x03\x04" + b"\x00" * 20)
        with pytest.raises(archive.ArchiveError) as caught:
            archive.extract(target, tmp_path / "out")
        assert caught.value.code == "corrupt-archive"

    def test_truncated_tar_is_corrupt(self, tmp_path: Path) -> None:
        target = tmp_path / "cut.tar"
        target.write_bytes(b"\x00" * 100)
        with pytest.raises(archive.ArchiveError) as caught:
            archive.extract(target, tmp_path / "out")
        assert caught.value.code == "corrupt-archive"

    def test_too_many_zip_members_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(archive, "MAX_MEMBERS", 2)
        target = tmp_path / "many.zip"
        with zipfile.ZipFile(target, "w") as handle:
            for index in range(3):
                handle.writestr(f"f{index}.txt", b"x")
        with pytest.raises(archive.ArchiveError) as caught:
            archive.extract(target, tmp_path / "out")
        assert caught.value.code == "too-many-members"

    def test_too_many_tar_members_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(archive, "MAX_MEMBERS", 2)
        target = tmp_path / "many.tar"
        with tarfile.open(target, "w") as handle:
            for index in range(3):
                info = tarfile.TarInfo(f"f{index}.txt")
                info.size = 1
                handle.addfile(info, io.BytesIO(b"x"))
        with pytest.raises(archive.ArchiveError) as caught:
            archive.extract(target, tmp_path / "out")
        assert caught.value.code == "too-many-members"
