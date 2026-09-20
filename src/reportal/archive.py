"""Archive extraction for stored binaries.

reportal unpacks an archive with the standard library only: ``zipfile`` for
``.zip``/``.apk``, ``tarfile`` for ``.tar``, ``.tar.gz``/``.tgz``, ``.tar.bz2``
and ``.tar.xz``, and ``gzip`` for a single-member ``.gz``.  ``.rar`` and
``.7z`` need an external unpacker reportal does not ship, so they are refused
by name rather than shelled out to.  Firmware images are not unpacked here:
the hosted portal runs a hosted extractor for them, reportal has no local
equivalent, and ``docs/PARITY.md`` records that as not-applicable.

Safety comes before the feature.  Every member is checked before a byte of it
is written: a name that is absolute, carries a ``..`` component or resolves
outside the extraction root is refused, as is a symlink, a hardlink, a device,
a FIFO or a socket (reportal stores regular files, never links, so a link is a
path-escape primitive with no use here).  A member past
:data:`MAX_MEMBER_BYTES`, an archive whose members total past
:data:`MAX_TOTAL_BYTES`, and a member whose uncompressed-to-compressed ratio
passes :data:`MAX_COMPRESSION_RATIO` are refused as decompression bombs, as is
an archive with more than :data:`MAX_MEMBERS` entries.  The caller supplies an
empty destination directory inside the workspace and extraction writes nothing
outside it.

Each refusal is reported per member through :class:`MemberOutcome`; a refusal
that leaves the whole archive unreadable (an unsupported format, a password
that is missing or wrong, a corrupt stream) raises :class:`ArchiveError` with a
stable code the API and CLI map onto their own vocabulary.
"""

from __future__ import annotations

import gzip
import lzma
import stat
import tarfile
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Protocol

# Stdlib readers raise these for a truncated or mutated stream.  They are
# mapped onto ``corrupt-archive`` so an upload never escapes as a 500.
_STREAM_ERRORS = (OSError, EOFError, zlib.error, lzma.LZMAError)


# Anything with a binary ``read``: a zip entry, a tar member or a gzip stream.
class _BinaryReader(Protocol):
    def read(self, size: int = -1) -> bytes: ...  # pragma: no cover - typing only


# Archive kinds the stdlib can read.  Detection is by file name: the stored
# copy keeps only the client filename's suffix, so a `.tar.gz` arrives as
# `.gz` and is told apart from a single-member gzip by sniffing it.
KIND_ZIP = "zip"
KIND_TAR = "tar"
KIND_GZIP = "gzip"

# Every extension reportal reads.  The hosted portal recognises more; these are
# the ones the standard library can consume without an external tool.
SUPPORTED_EXTENSIONS: tuple[str, ...] = (
    ".zip",
    ".apk",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tar.xz",
    ".gz",
)

# Formats the hosted portal unpacks with an external tool reportal does not
# ship.  They are refused by name, never shelled out to.
EXTERNAL_UNPACKERS: dict[str, str] = {".rar": "unrar", ".7z": "7z"}

# Largest single member reportal writes, in bytes.  A member that declares more
# is refused before it is read.
MAX_MEMBER_BYTES = 256 * 1024 * 1024

# Largest total of member bytes one extraction writes.  A second cap beside the
# per-member one so many mid-sized members cannot fill the disk.
MAX_TOTAL_BYTES = 512 * 1024 * 1024

# Largest uncompressed-to-compressed ratio a member (or a whole compressed tar)
# may carry.  Well above ordinary text and code, far below a bomb.
MAX_COMPRESSION_RATIO = 200

# Most entries one archive may hold.  A huge central directory is refused
# before any member is touched.
MAX_MEMBERS = 4096

# Read size while a member streams to disk.
CHUNK_BYTES = 1024 * 1024


class ArchiveError(Exception):
    """An archive reportal refuses to open at all.

    ``code`` is a stable name the API and CLI map onto their own vocabulary;
    ``detail`` is a human sentence safe to return to a caller.
    """

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class MemberOutcome:
    """What happened to one archive member.

    ``path`` is the written file when the member was kept, or ``None`` when it
    was skipped; ``skipped`` carries the reason in that case and is empty for a
    kept member.
    """

    name: str
    size: int
    path: Path | None
    skipped: str = ""


@dataclass(frozen=True)
class Extraction:
    """One extraction: the per-member outcome and the run's own notes."""

    members: tuple[MemberOutcome, ...] = ()
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def kept(self) -> tuple[MemberOutcome, ...]:
        """The members that reached the destination directory."""
        return tuple(member for member in self.members if member.path is not None)


def archive_kind(path: Path) -> str:
    """Return the archive kind *path* holds, or raise :class:`ArchiveError`.

    A `.gz` (or `.bz2`/`.xz`) whose contents are a tar is read as a tar; a
    plain `.gz` is a single-member archive.  An extension the stdlib cannot
    read is refused, and an external-tool format names the tool it would need.
    """
    name = path.name.lower()
    for extension, tool in EXTERNAL_UNPACKERS.items():
        if name.endswith(extension):
            raise ArchiveError(
                "external-tool-required",
                f"{extension} needs the external {tool} unpacker, which reportal does not ship",
            )
    if name.endswith((".zip", ".apk")):
        return KIND_ZIP
    if name.endswith((".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz")):
        return KIND_TAR
    if name.endswith((".gz", ".bz2", ".xz")):
        # An upload keeps only the client filename's last suffix, so a
        # `foo.tar.bz2` is stored as `<sha>.bz2`: a compressed stream is a tar
        # only if its contents say so, and a single-member `.bz2`/`.xz` is not
        # a format reportal reads.
        try:
            if tarfile.is_tarfile(path):
                return KIND_TAR
        except (OSError, EOFError, tarfile.TarError):
            # A corrupt stream is not a tar; the reader below reports it.
            pass
        if name.endswith(".gz"):
            return KIND_GZIP
        raise ArchiveError(
            "unsupported-format",
            f"{path.name} is not a tar and a single-member {Path(name).suffix} is not a format"
            f" reportal reads; supported: {', '.join(SUPPORTED_EXTENSIONS)}",
        )
    raise ArchiveError(
        "unsupported-format",
        f"{path.name} is not an archive format reportal reads; supported:"
        f" {', '.join(SUPPORTED_EXTENSIONS)}",
    )


def extract(archive: Path, destination: Path, *, password: str | None = None) -> Extraction:
    """Extract *archive* into *destination* and report each member.

    *destination* is created when absent.  Every member is validated before it
    is written (see the module docstring); a refused member is reported in the
    result and leaves nothing on disk.  An archive that cannot be read at all
    raises :class:`ArchiveError`.
    """
    if not archive.is_file():
        raise ArchiveError("corrupt-archive", f"{archive.name} is not a readable file")
    destination.mkdir(parents=True, exist_ok=True)
    kind = archive_kind(archive)
    if kind == KIND_ZIP:
        return _extract_zip(archive, destination, password)
    if kind == KIND_TAR:
        return _extract_tar(archive, destination, password)
    return _extract_gzip(archive, destination)


def _refuse_name(name: str, destination: Path) -> tuple[Path | None, str]:
    """Return the target path for *name*, or ``(None, reason)`` when refused."""
    if not name:
        return None, "the member name is empty"
    if "\x00" in name:
        return None, "the member name carries a NUL byte"
    if "\\" in name:
        return None, "the member name carries a backslash"
    candidate = PurePosixPath(name)
    if candidate.is_absolute():
        return None, "the member name is absolute"
    if any(part == ".." for part in candidate.parts):
        return None, "the member name escapes the extraction root (..)"
    target = destination.joinpath(*candidate.parts)
    try:
        resolved = target.resolve()
    except OSError:
        return None, "the member path cannot be resolved"
    if not resolved.is_relative_to(destination.resolve()):
        return None, "the member path escapes the extraction root"
    return target, ""


def _refuse_mode(mode: int) -> str:
    """Return why a member's ``st_mode`` is refused, or "" for a regular file."""
    if stat.S_ISLNK(mode):
        return "the member is a symlink"
    if stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
        return "the member is a device node"
    if stat.S_ISFIFO(mode):
        return "the member is a FIFO"
    if stat.S_ISSOCK(mode):
        return "the member is a socket"
    return ""


def _ratio_refusal(uncompressed: int, compressed: int) -> str:
    """Return why a size pair is a bomb by ratio, or "" when it is fine."""
    if compressed <= 0:
        return ""
    if uncompressed > compressed * MAX_COMPRESSION_RATIO:
        return (
            f"content expands past the {MAX_COMPRESSION_RATIO}:1 compression ratio"
            f" ({uncompressed} bytes from {compressed})"
        )
    return ""


def _copy_member(
    source: _BinaryReader, target: Path, *, cap: int, ratio_base: int | None = None
) -> int:
    """Stream *source* into *target*, refusing a member past the caps.

    *cap* bounds the bytes written; *ratio_base* (when given) is the compressed
    size the running total is checked against.  A refusal removes the partial
    file before raising :class:`_MemberRefusedError`.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    try:
        with target.open("wb") as handle:
            while True:
                chunk = source.read(CHUNK_BYTES)
                if not chunk:
                    break
                written += len(chunk)
                if written > cap:
                    raise _MemberRefusedError(
                        f"the member is larger than MAX_MEMBER_BYTES ({MAX_MEMBER_BYTES} bytes)"
                    )
                if ratio_base is not None and ratio_base > 0:
                    refusal = _ratio_refusal(written, ratio_base)
                    if refusal:
                        raise _MemberRefusedError(refusal)
                handle.write(chunk)
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    return written


class _MemberRefusedError(Exception):
    """One member kept out of the extraction; the message is the reason."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _extract_zip(archive: Path, destination: Path, password: str | None) -> Extraction:
    """Extract a zip or apk, one entry per member."""
    pwd = password.encode("utf-8") if password else None
    try:
        with zipfile.ZipFile(archive) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_MEMBERS:
                raise ArchiveError(
                    "too-many-members",
                    f"{archive.name} holds {len(infos)} entries, past MAX_MEMBERS ({MAX_MEMBERS})",
                )
            encrypted = any(info.flag_bits & 0x1 for info in infos if not info.is_dir())
            if encrypted and pwd is None:
                raise ArchiveError(
                    "password-required",
                    f"{archive.name} is encrypted; provide the archive password",
                )
            members: list[MemberOutcome] = []
            total = 0
            for info in infos:
                if info.is_dir():
                    continue
                outcome, total = _zip_member(zf, info, destination, pwd, total)
                members.append(outcome)
            notes = _size_ratio_note(total, archive.stat().st_size)
        return Extraction(members=tuple(members), notes=tuple(notes))
    except zipfile.BadZipFile:
        raise ArchiveError("corrupt-archive", f"{archive.name} is not a readable zip") from None
    except _STREAM_ERRORS:
        # A mutated central directory can seek past the file (OSError) or a
        # deflate stream can raise zlib.error mid-member; both are corrupt.
        raise ArchiveError("corrupt-archive", f"{archive.name} is not a readable zip") from None


def _zip_member(
    zf: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    destination: Path,
    pwd: bytes | None,
    total: int,
) -> tuple[MemberOutcome, int]:
    """Validate, then extract one zip entry; returns its outcome and the new total."""
    mode = info.external_attr >> 16
    target, reason = _refuse_name(info.filename, destination)
    if not reason:
        reason = _refuse_mode(mode)
    if not reason and info.file_size > MAX_MEMBER_BYTES:
        reason = f"the member declares {info.file_size} bytes, past MAX_MEMBER_BYTES"
    if not reason:
        reason = _ratio_refusal(info.file_size, info.compress_size)
    if not reason and total + info.file_size > MAX_TOTAL_BYTES:
        reason = f"the extraction would pass MAX_TOTAL_BYTES ({MAX_TOTAL_BYTES} bytes)"
    if reason or target is None:
        refusal = reason or "the member path is invalid"
        return MemberOutcome(info.filename, info.file_size, None, refusal), total
    try:
        with zf.open(info, pwd=pwd) as source:
            written = _copy_member(source, target, cap=MAX_MEMBER_BYTES)
    except _MemberRefusedError as exc:
        return MemberOutcome(info.filename, info.file_size, None, exc.reason), total
    except RuntimeError as exc:
        raise _password_error(exc) from None
    return MemberOutcome(info.filename, written, target), total + written


def _extract_tar(archive: Path, destination: Path, password: str | None) -> Extraction:
    """Extract a tar (optionally gz/bz2/xz compressed), one entry per member."""
    notes: list[str] = []
    if password:
        notes.append("tar archives carry no password; the supplied one was not used")
    try:
        with tarfile.open(archive, "r:*") as tf:
            members = tf.getmembers()
            if len(members) > MAX_MEMBERS:
                raise ArchiveError(
                    "too-many-members",
                    f"{archive.name} holds {len(members)} entries, past"
                    f" MAX_MEMBERS ({MAX_MEMBERS})",
                )
            archive_size = archive.stat().st_size
            declared = sum(member.size for member in members if member.isfile())
            ratio_refusal = _ratio_refusal(declared, archive_size)
            if ratio_refusal:
                # A (possibly compressed) tar is one stream, so the bomb check
                # is over the archive: a member-by-member ratio has no meaning.
                raise ArchiveError("archive-too-large", f"{archive.name}: {ratio_refusal}")
            outcomes: list[MemberOutcome] = []
            total = 0
            for member in members:
                if member.isdir():
                    continue
                outcome, total = _tar_member(tf, member, destination, total)
                outcomes.append(outcome)
            notes.extend(_size_ratio_note(total, archive_size))
    except tarfile.TarError:
        raise ArchiveError("corrupt-archive", f"{archive.name} is not a readable tar") from None
    except _STREAM_ERRORS:
        # ``r:*`` opens through gzip/bz2/xz; a truncated outer stream raises
        # EOFError or zlib/lzma errors before TarError is produced.
        raise ArchiveError("corrupt-archive", f"{archive.name} is not a readable tar") from None
    return Extraction(members=tuple(outcomes), notes=tuple(notes))


def _tar_member(
    tf: tarfile.TarFile,
    member: tarfile.TarInfo,
    destination: Path,
    total: int,
) -> tuple[MemberOutcome, int]:
    """Validate, then extract one tar entry."""
    target, reason = _refuse_name(member.name, destination)
    if not reason and member.issym():
        reason = "the member is a symlink"
    if not reason and member.islnk():
        reason = "the member is a hardlink"
    if not reason and member.ischr():
        reason = "the member is a device node"
    if not reason and member.isblk():
        reason = "the member is a device node"
    if not reason and member.isfifo():
        reason = "the member is a FIFO"
    if not reason and not member.isfile():
        reason = "the member is not a regular file"
    if not reason and member.size > MAX_MEMBER_BYTES:
        reason = f"the member declares {member.size} bytes, past MAX_MEMBER_BYTES"
    if not reason and total + member.size > MAX_TOTAL_BYTES:
        reason = f"the extraction would pass MAX_TOTAL_BYTES ({MAX_TOTAL_BYTES} bytes)"
    if reason or target is None:
        refusal = reason or "the member path is invalid"
        return MemberOutcome(member.name, member.size, None, refusal), total
    source = tf.extractfile(member)
    if source is None:
        return MemberOutcome(
            member.name, member.size, None, "the member has no readable data"
        ), total
    with source:
        written = _copy_member(source, target, cap=MAX_MEMBER_BYTES)
    return MemberOutcome(member.name, written, target), total + written


def _extract_gzip(archive: Path, destination: Path) -> Extraction:
    """Extract a single-member gzip, named after the archive without its suffix."""
    name = archive.name[:-3] if archive.name.lower().endswith(".gz") else archive.name
    if not name:
        name = "member"
    target, reason = _refuse_name(name, destination)
    compressed = archive.stat().st_size
    if reason or target is None:
        refusal = reason or "the member path is invalid"
        return Extraction(members=(MemberOutcome(name, 0, None, refusal),))
    try:
        with gzip.open(archive, "rb") as source:
            written = _copy_member(source, target, cap=MAX_MEMBER_BYTES, ratio_base=compressed)
    except _MemberRefusedError as exc:
        return Extraction(
            members=(MemberOutcome(name, 0, None, exc.reason),),
            notes=_ratio_note_parts(compressed),
        )
    except _STREAM_ERRORS:
        raise ArchiveError("corrupt-archive", f"{archive.name} is not a readable gzip") from None
    return Extraction(
        members=(MemberOutcome(name, written, target),),
        notes=_ratio_note_parts(compressed),
    )


def _ratio_note_parts(compressed: int) -> tuple[str, ...]:
    """The note stating the compressed size a gzip member was checked against."""
    return (f"single-member gzip checked against {compressed} compressed bytes",)


def _size_ratio_note(total: int, compressed: int) -> list[str]:
    """A note naming the archive's compression ratio, when it is knowable."""
    if compressed <= 0 or total <= 0:
        return []
    return [f"extracted {total} bytes from {compressed} compressed bytes"]


def _password_error(exc: RuntimeError) -> ArchiveError:
    """Map a zipfile password failure onto :class:`ArchiveError`."""
    text = str(exc).lower()
    if "bad password" in text:
        return ArchiveError("bad-password", "the archive password is wrong")
    if "password" in text and "required" in text:
        return ArchiveError("password-required", "the archive is encrypted; provide the password")
    return ArchiveError("corrupt-archive", "the archive could not be read")
