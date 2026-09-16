"""Unpack a packed executable back into the image its packer compressed.

A packer replaces a program's code with a decompressor stub and an encoded
image, so the bytes an analyst wants are the ones the stub rebuilds at run
time.  Two packers are known here: the engine rebuilds LZEXE in process, and
the external ``upx`` tool rebuilds UPX.  reportal ships no packer, so a UPX
sample on a machine without the tool is a named error carrying the install
hint, never a silent no-op.

Detection reads the file's own bytes.  The LZEXE stub at the entry point is the
real test (the string in the header is not, which is why the engine checks the
stub), and the UPX marker is a signature a packer that rewrites its own stub
does not carry, the same ceiling :mod:`reportal.filetypes` states.  Nothing
here executes the sample: ``upx -d`` decodes a file rather than running it, and
the LZEXE case is arithmetic over the bytes.

The action itself lives in :func:`reportal.binary_actions.unpack_binary`, which writes the
rebuilt image into the workspace as a new binary and stores its provenance as
that binary's ``unpack`` scan.
"""

from __future__ import annotations

import shutil
import sqlite3
import subprocess
from pathlib import Path
from typing import Any

from reportal import store
from reportal.engines import RebrewEngine, get_engine

# The scan kind the provenance of an unpacked binary is stored under.  It hangs
# off the new binary, not the packed source.
SCAN_KIND = "unpack"

PACKER_LZEXE = "lzexe"
PACKER_UPX = "upx"
PACKERS: tuple[str, ...] = (PACKER_LZEXE, PACKER_UPX)

# The method recorded for the LZEXE case: the engine rebuilds it in process, so
# no external tool is involved.
METHOD_ENGINE = "engine"

UPX_TOOL = "upx"
UPX_TIMEOUT_SECONDS = 120
UPX_MARKER = b"UPX!"

# Bytes at each end of a file the UPX marker is looked for in.  The stub names
# itself in its own header, which is not always the first page of the file.
UPX_MARKER_WINDOW = 4096

ERROR_UNKNOWN_PACKER = "unknown-packer"
ERROR_NO_PACKER = "no-packer"
ERROR_NO_UNPACKER = "no-unpacker"
ERROR_UNPACK_FAILED = "unpack-failed"

NO_PACKER_DETAIL = "binary {binary_id} ({name}) carries no known packer signature"
NO_PACKER_METHOD = "{detail}; a packer that rewrites its own stub is not identified"
UPX_HINT = "unpacking UPX needs the external '{tool}' tool, which reportal does not ship"

# The provenance note each method contributes, so a reader of the scan knows
# what produced the bytes.
METHOD_NOTES: dict[str, str] = {
    PACKER_LZEXE: "the LZEXE image is rebuilt in process through the engine",
    PACKER_UPX: "the UPX image is rebuilt by the external '{tool}' tool",
}

CEILING_NOTE = (
    "the rebuilt image is the packer's own payload; reportal runs no sample and"
    " verifies no checksum of it"
)

# Resolved at call time, so a test can put a stand-in tool on the lookup without
# a package on the machine.
_which = shutil.which


class UnpackError(Exception):
    """An unpack the caller refuses, as ``(code, detail)``."""

    code = ERROR_UNPACK_FAILED

    def __init__(self, detail: str, code: str = ERROR_UNPACK_FAILED) -> None:
        self.code = code
        self.detail = detail
        super().__init__(detail)


def detect(path: str | Path, *, engine: RebrewEngine | None = None) -> list[dict[str, Any]]:
    """Every known packer *path*'s own bytes identify, most specific first.

    The LZEXE probe goes through *engine* (the process-wide one by default) and
    is skipped when the engine is unavailable, so a machine without rebrew
    still names a UPX sample.  Reading a file that vanished is not an error
    here: it reports nothing.
    """
    source = Path(path)
    found: list[dict[str, Any]] = []
    probe = engine if engine is not None else get_engine()
    if probe.available():
        version = probe.lzexe_version(source)
        if version is not None:
            found.append(
                {"packer": PACKER_LZEXE, "detail": f"LZEXE {version} stub", "method": METHOD_ENGINE}
            )
    if upx_marker(source):
        found.append({"packer": PACKER_UPX, "detail": "UPX! marker", "method": UPX_TOOL})
    return found


def upx_marker(path: Path) -> bool:
    """True when *path* carries the UPX signature in its first or last page."""
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            if UPX_MARKER in handle.read(UPX_MARKER_WINDOW):
                return True
            if size > UPX_MARKER_WINDOW:
                handle.seek(size - UPX_MARKER_WINDOW)
                return UPX_MARKER in handle.read()
    except OSError:
        return False
    return False


def unpack_to(
    source: str | Path,
    target: str | Path,
    *,
    packer: str,
    engine: RebrewEngine | None = None,
) -> dict[str, Any]:
    """Rebuild packed *source* into *target* with *packer*.

    Output describes what ran: ``packer``, ``method`` and the sizes the rebuild
    reported.  Raises :class:`UnpackError` for a packer this module does not
    know, for UPX without the tool installed, and for a tool that failed.
    """
    origin = Path(source)
    output = Path(target)
    if packer == PACKER_LZEXE:
        probe = engine if engine is not None else get_engine()
        return {"packer": packer, "method": METHOD_ENGINE, **probe.unpack_lzexe(origin, output)}
    if packer == PACKER_UPX:
        tool = _which(UPX_TOOL)
        if not tool:
            raise UnpackError(UPX_HINT.format(tool=UPX_TOOL), code=ERROR_NO_UNPACKER)
        _run_upx(tool, origin, output)
        return {
            "packer": packer,
            "method": UPX_TOOL,
            "tool": tool,
            "file_size": output.stat().st_size,
        }
    raise UnpackError(
        f"unknown packer {packer!r}; known packers are {', '.join(PACKERS)}",
        code=ERROR_UNKNOWN_PACKER,
    )


def _run_upx(tool: str, source: Path, target: Path) -> None:
    """Run ``upx -d`` from *source* into *target*, refusing any other outcome.

    The command is a list, never a shell, its output is captured rather than
    printed, and it is bounded by :data:`UPX_TIMEOUT_SECONDS`.  UPX writes only
    where ``-o`` names, which is the workspace's own temporary directory.
    """
    command = [tool, "-d", "-q", "-f", "-o", str(target), str(source)]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            timeout=UPX_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise UnpackError(f"{UPX_TOOL} could not be run: {exc}", code=ERROR_UNPACK_FAILED) from None
    if completed.returncode != 0:
        detail = (
            _one_line(completed.stderr or completed.stdout) or f"exit code {completed.returncode}"
        )
        raise UnpackError(f"{UPX_TOOL} could not unpack the binary: {detail}")
    if not target.is_file():
        raise UnpackError(f"{UPX_TOOL} reported success but wrote no file")


def _one_line(data: bytes) -> str:
    """The last non-empty line of a tool's captured output, one line and capped."""
    text = data.decode("utf-8", "replace") if isinstance(data, bytes) else data
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return lines[-1][:200] if lines else ""


def describe(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any]:
    """The stored provenance of one unpacked binary, or an empty reading.

    Raises :class:`UnpackError` for an unknown binary.  A binary that reportal
    did not unpack answers ``stored: false`` rather than 404: "this binary came
    from somewhere else" is an answer, and the command that produces one is
    named.
    """
    binary = store.get_binary(conn, binary_id)
    if binary is None:
        raise UnpackError(f"no binary with id {binary_id}", code="binary not found")
    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    stored = None if analysis_id is None else store.get_scan(conn, analysis_id, SCAN_KIND)
    if stored is None:
        return {
            "binary_id": binary_id,
            "binary_name": str(binary["name"]),
            "stored": False,
            "source": None,
            "packer": "",
            "notes": [f"no stored unpack scan; run 'reportal unpack {binary_id}'"],
        }
    return stored
