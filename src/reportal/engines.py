"""In-process adapters for the reportal engine stack.

reportal never reimplements an engine: it calls the sibling ``rebrew`` package
and stores what it returns.  This module is the single place that knows how the
engine is imported and invoked.  ``rebrew`` is the engine wired here: binary
fingerprints, imports, strings, PE metadata, one-shot triage dossiers, reports,
struct recovery, crypto scans, security scans, library identification,
decompilation and cross-references as parsed dicts, and disassembly as text.

``rebrew`` is a base dependency, imported lazily on the first call.  An install
whose rebrew package cannot be imported reports :meth:`RebrewEngine.available`
false and every call raises :class:`EngineUnavailable`, so a broken engine
degrades to a named error instead of a traceback.

Every method is in-process: the engine's own entry points (``rebrew.asm``,
``rebrew.test``, ...) are imported inside the method, so a missing package
fails at call time with :class:`EngineUnavailable`, never at import time.

``rebrew`` exposes no raw byte-read entry point, so
:meth:`RebrewEngine.read_memory` takes its section map from the engine's own
``pe_info`` call and then reads the file exactly where that map says the bytes
live; reportal never parses a PE.
"""

from __future__ import annotations

import functools
import importlib
import importlib.machinery
import importlib.util
import os
import threading
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Concatenate

import typer

# Message every unavailable-engine surface reports.  `rebrew` is a base
# dependency of reportal, so an engine that is not importable means the
# installed distribution is broken or the package was removed, not an
# unrequested extra.
ENGINE_UNAVAILABLE_HINT = "rebrew is required but failed to import; reinstall reportal (uv sync)"

# Engine message kept in an error.  A rebrew failure can embed a whole
# diagnostic; the API and CLI surface the message, so it is bounded.
ERROR_MESSAGE_CHARS = 400

# Output formats `disassemble` accepts; the engine serves both in process.
DISASM_FORMATS = frozenset({"nasm", "hex"})

# Decompiler backends `rebrew decompile --decompiler` accepts, plus `auto`
# for the engine's own backend selection.  `kuna` is rebrew's default.
DECOMPILER_BACKENDS = frozenset({"auto", "kuna", "r2ghidra", "r2dec", "ghidra"})
DEFAULT_DECOMPILER_BACKEND = "kuna"

# Severity floor `rebrew security-scan --min-severity` accepts, and the floor
# the engine applies itself.
SECURITY_SEVERITIES = frozenset({"high", "medium", "low"})
DEFAULT_SECURITY_MIN_SEVERITY = "low"

# Byte window `read_memory` returns.  The hosted portal's `read_memory` tool
# defaults to 64 bytes and caps at 1024, so a caller cannot ask for an
# unbounded read and one byte over the cap is refused.
MEMORY_READ_DEFAULT = 64
MEMORY_READ_MAX = 1024

# Byte page `read_memory_page` returns: the full-file hex view's working set.
# One page is 16 grid rows of 16 bytes at the default, and the cap bounds one
# call the same way MEMORY_READ_MAX bounds a window read.
MEMORY_PAGE_DEFAULT = 256
MEMORY_PAGE_MAX = 4096

# Space the full-file view lays out between byte rows.  Exposed so the SPA and
# the engine agree on row geometry without duplicating the section math.
MEMORY_BYTES_PER_ROW = 16

# Address kinds `read_memory` accepts: an absolute virtual address, an RVA
# (relative to the image base) or a raw file offset.
MEMORY_ADDRESS_KIND_VA = "va"
MEMORY_ADDRESS_KINDS = frozenset({MEMORY_ADDRESS_KIND_VA, "rva", "file"})


class EngineError(Exception):
    """A local engine could not produce a result."""


class EngineUnavailable(EngineError):  # noqa: N818  # name fixed by the engine contract
    """The ``rebrew`` engine package is not importable."""


class UnmappedAddressError(EngineError):
    """A read_memory address is not backed by the image's raw bytes."""


def _rebrew_spec() -> importlib.machinery.ModuleSpec | None:
    """The installed ``rebrew`` package's spec, or None when it is absent."""
    try:
        return importlib.util.find_spec("rebrew")
    except (ImportError, ValueError):
        return None


def _bounded(text: str) -> str:
    """Collapse *text* to one line and cap it at :data:`ERROR_MESSAGE_CHARS`."""
    return " ".join(text.split())[:ERROR_MESSAGE_CHARS]


def _call[T](what: str, call: Callable[[], T]) -> T:
    """Run one engine call, mapping its failures to :class:`EngineError`.

    ``what`` names the rebrew operation for the message.  rebrew refuses a
    request through ``typer.Exit`` (its ``error_exit``) and reports a broken
    one with a plain exception; both become a bounded message, never a
    traceback.
    """
    try:
        return call()
    except EngineError:
        raise
    except ImportError as exc:
        raise EngineUnavailable(f"rebrew failed to import: {exc}") from None
    except typer.Exit as exc:
        raise EngineError(f"rebrew {what} exited with code {exc.exit_code}") from None
    except Exception as exc:  # the engine is a trust boundary; nothing leaks out
        message = _bounded(str(exc)) or type(exc).__name__
        raise EngineError(f"rebrew {what} failed: {message}") from None


def _require_file(binary: str | Path) -> str:
    """Return *binary* as a string path, raising :class:`EngineError` if absent.

    Checked before the engine is called: handing it a path that cannot exist
    wastes a call and reports a worse error.
    """
    path = Path(binary).expanduser()
    if not path.is_file():
        raise EngineError(f"binary not found: {path}")
    return str(path)


def _require_project(project_dir: str | Path) -> Path:
    """Return the rebrew project root *project_dir*, raising if it is unusable.

    Every in-process rebrew call resolves its target from
    ``rebrew-project.toml``, so a missing directory or marker is checked
    before the engine is called.
    """
    root = Path(project_dir).expanduser()
    if not root.is_dir():
        raise EngineError(f"rebrew project directory not found: {root}")
    if not (root / "rebrew-project.toml").is_file():
        raise EngineError(f"not a rebrew project (no rebrew-project.toml): {root}")
    return root


def _load_config(root: Path) -> Any:
    """Load the rebrew project config at *root*, mapping failures to EngineError."""
    from rebrew.config import load_config

    try:
        return load_config(root)
    except (OSError, KeyError, ValueError) as exc:
        raise EngineError(
            f"cannot load the rebrew project at {root}: {_bounded(str(exc))}"
        ) from None


def _project_config_or_none() -> Any | None:
    """Load the project config of the process cwd, or None outside a project.

    The standalone commands (``rebrew analyze``, ``rebrew crypto-scan``) read
    the cwd's ``rebrew-project.toml`` when there is one and fall back to their
    project-free path when there is not; reportal calls them with a binary
    path, so the fallback is the normal case.
    """
    from rebrew.config import load_config

    try:
        return load_config()
    except (OSError, KeyError, ValueError):
        return None


def _standalone_config(binary: Path) -> Any:
    """The stand-in project config ``rebrew analyze`` builds outside a project.

    Mirrors ``rebrew/analyze.py::main``: no root, no metadata, no reversed
    sources, so the project-scoped dossier sections come back empty or None
    instead of aborting the dossier.
    """
    from types import SimpleNamespace

    return SimpleNamespace(
        root=None,
        target_binary=binary,
        metadata_dir=None,
        marker="",
        target_name=binary.stem,
        crt_sources={},
        reversed_dir=Path("/nonexistent"),
        source_ext=".c",
    )


def _section_for_rva(info: Mapping[str, Any], rva: int) -> tuple[Mapping[str, Any], int] | None:
    """Return the section backing *rva* and its file offset, or None.

    Only raw (file-backed) section bytes count: a section whose virtual size
    exceeds its raw size has no bytes past the raw end, so an RVA there is
    unmapped rather than fabricated.
    """
    sections = info.get("sections")
    for section in sections if isinstance(sections, Sequence) else []:
        if not isinstance(section, Mapping):
            continue
        start = int(section.get("virtual_address") or 0)
        raw_size = int(section.get("raw_size") or 0)
        if start <= rva < start + raw_size:
            return section, int(section.get("raw_offset") or 0) + (rva - start)
    return None


def _section_entries(info: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """The section mappings a ``pe-info`` payload carries, in payload order."""
    sections = info.get("sections")
    if not isinstance(sections, Sequence):
        return []
    return [section for section in sections if isinstance(section, Mapping)]


def _section_span(section: Mapping[str, Any], image_base: int) -> tuple[int, int] | None:
    """The absolute-VA half-open interval a section's raw bytes back, or None.

    A section with no raw bytes backs nothing, and its uninitialized tail
    (``virtual_size`` past ``raw_size``) is deliberately outside the interval:
    the engine refuses a read there rather than fabricating zeros.
    """
    raw_size = int(section.get("raw_size") or 0)
    if raw_size <= 0:
        return None
    start = image_base + int(section.get("virtual_address") or 0)
    return start, start + raw_size


def _va_for_file_offset(
    info: Mapping[str, Any], offset: int
) -> tuple[Mapping[str, Any], int, int] | None:
    """Return the section backing file *offset*, the file offset, and its VA."""
    image_base = int(info.get("image_base") or 0)
    sections = info.get("sections")
    for section in sections if isinstance(sections, Sequence) else []:
        if not isinstance(section, Mapping):
            continue
        raw_offset = int(section.get("raw_offset") or 0)
        raw_size = int(section.get("raw_size") or 0)
        if raw_size > 0 and raw_offset <= offset < raw_offset + raw_size:
            va = image_base + int(section.get("virtual_address") or 0) + (offset - raw_offset)
            return section, raw_offset, va
    return None


def _read_window(path: Path, *, offset: int, length: int) -> bytes:
    """Read *length* raw bytes at *offset*, refusing a window past the file end."""
    if offset < 0 or length <= 0:
        raise UnmappedAddressError(f"cannot read {length} bytes at file offset {offset}")
    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        if offset + length > size:
            raise UnmappedAddressError(
                f"window of {length} bytes at file offset {offset} runs past the file"
                f" ({size} bytes)"
            )
        handle.seek(offset)
        data = handle.read(length)
    if len(data) != length:
        raise UnmappedAddressError(
            f"short read at file offset {offset}: {len(data)} of {length} bytes"
        )
    return data


def _maps_missing_engine[**P, R](
    method: Callable[Concatenate[RebrewEngine, P], R],
) -> Callable[Concatenate[RebrewEngine, P], R]:
    """Answer an engine import failure as :class:`EngineUnavailable`.

    A method's lazy ``from rebrew.<module> import ...`` fails when the package
    is absent or a module or dependency of it is missing.  Both mean the same
    unusable engine, so the ImportError becomes :class:`EngineUnavailable`
    rather than an uncaught traceback (or a sanitized 500 that hides which
    install is broken).
    """

    @functools.wraps(method)
    def wrapper(self: RebrewEngine, *args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return method(self, *args, **kwargs)
        except ImportError as exc:
            raise EngineUnavailable(f"rebrew failed to import: {exc}") from None

    return wrapper


class RebrewEngine:
    """Adapter over the ``rebrew`` package.

    Availability is process-level: :meth:`available` reports whether the engine
    package is importable, which ``enabled`` overrides so a caller can pin
    either side of the degraded path.  JSON methods return the engine's parsed
    object unchanged; :meth:`disassemble` returns the engine's text listing.
    """

    def __init__(self, *, enabled: bool | None = None) -> None:
        self._enabled = enabled

    def available(self) -> bool:
        """True when the ``rebrew`` package is importable."""
        if self._enabled is not None:
            return self._enabled
        return _rebrew_spec() is not None

    @property
    def origin(self) -> str | None:
        """The installed ``rebrew`` package's path, or None when absent."""
        if not self.available():
            return None
        spec = _rebrew_spec()
        return spec.origin if spec is not None else None

    @_maps_missing_engine
    def fingerprint(self, binary: str | Path) -> dict[str, Any]:
        """Hashes, format, arch and section entropies of *binary*.

        The bundle carries the streamed digests (md5, sha1, sha256, sha512,
        the four SHA-3 digests, crc32), ``imphash``, ``export_hash``,
        ``rich_header_hash`` and ``section_entropies``; a field that cannot be
        derived is ``None`` (``export_hash`` when the export table cannot be
        read).
        """
        path = _require_file(binary)
        self._require_available()
        from rebrew.fingerprints import fingerprint_bundle

        return _call("fingerprints", lambda: fingerprint_bundle(path))

    @_maps_missing_engine
    def imports(self, binary: str | Path) -> dict[str, Any]:
        """Imported DLLs and functions of *binary*, with IAT addresses."""
        path = _require_file(binary)
        self._require_available()
        from rebrew.imports import imports_payload

        return _call("imports", lambda: imports_payload(Path(path)))

    @_maps_missing_engine
    def strings(self, binary: str | Path) -> dict[str, Any]:
        """Printable strings of *binary*."""
        path = _require_file(binary)
        self._require_available()
        from rebrew.strings import collect_strings

        return _call("strings", lambda: collect_strings(Path(path), json_output=True))

    @_maps_missing_engine
    def analyze(self, binary: str | Path) -> dict[str, Any]:
        """One-shot intelligence dossier of *binary*.

        The binary path is the whole input, since the dossier needs no project
        directory; outside a rebrew project the engine's standalone stand-in
        config is used, exactly as ``rebrew analyze`` does.  Output is the
        engine's parsed object (``meta``, ``toolchain``, plus strings, imports,
        references, functions, dispatch and FLIRT sections).
        """
        path = _require_file(binary)
        self._require_available()
        from rebrew.analyze import build_dossier

        cfg = _project_config_or_none()
        if cfg is None:
            cfg = _standalone_config(Path(path))
        return _call("analyze", lambda: build_dossier(cfg, Path(path)))

    @_maps_missing_engine
    def crypto_scan(self, binary: str | Path) -> dict[str, Any]:
        """Crypto constants and APIs detected in *binary*.

        The binary path is the whole input.  The engine also contributes the
        cwd project's function names when there is one, so a scan started
        inside a rebrew project sees the same signal the CLI would.  Output is
        the engine's parsed object (``findings``, ``count``,
        ``by_confidence``); an empty ``findings`` is a valid result.
        """
        path = _require_file(binary)
        self._require_available()
        from rebrew.crypto_scan import _project_function_names, crypto_scan

        cfg = _project_config_or_none()
        function_names = _project_function_names(cfg) if cfg is not None else []
        return _call("crypto-scan", lambda: crypto_scan(path, function_names))

    @_maps_missing_engine
    def pe_info(self, binary: str | Path) -> dict[str, Any]:
        """Identity, sections and security metadata of *binary*.

        The binary path is the whole input.  Output is the engine's parsed
        object (identity fields with the PE ``type`` and ``resource_count``,
        ``sections`` with each section's entropy and ``IMAGE_SCN_*`` names,
        ``security_flags``, the 11-item ``security`` checklist with
        ``security_score``, ``exports`` and ``export_count``,
        ``flags_summary``, ``authenticode``, ``debug``, ``rich_header``,
        ``presence`` and ``counts``); a binary whose format carries no PE
        metadata answers identity plus a ``note``.
        """
        path = _require_file(binary)
        self._require_available()
        from rebrew.pe_info import pe_info

        return _call("pe-info", lambda: pe_info(path))

    @_maps_missing_engine
    def identify_library(self, project_dir: str | Path) -> dict[str, Any]:
        """Library-identified function candidates of a rebrew project.

        The project is resolved from ``rebrew-project.toml`` in *project_dir*.
        Nothing is written: this is the engine's dry run, so the payload
        reports what a write would do.  Output is the engine's parsed object
        (``identified``, ``to_write``, ``candidates``), each candidate carrying
        a hex ``va``, a ``name``, a ``module``, a ``kind`` and a float
        ``confidence``.
        """
        root = _require_project(project_dir)
        self._require_available()
        from rebrew.identify_library import _existing_vas, collect_candidates

        cfg = _load_config(root)

        def collect() -> list[Any]:
            return list(collect_candidates(cfg))

        candidates = _call("identify-library", collect)
        existing = _call("identify-library", lambda: _existing_vas(cfg))
        fresh = [candidate for candidate in candidates if candidate.va not in existing]
        return {
            "sigs_written": 0,
            "identified": len(candidates),
            "already_annotated": len(candidates) - len(fresh),
            "to_write": len(fresh),
            "written": 0,
            "candidates": [
                {
                    "va": f"0x{candidate.va:08x}",
                    "name": candidate.name,
                    "module": candidate.module,
                    "kind": candidate.kind,
                    "confidence": round(candidate.confidence, 2),
                }
                for candidate in candidates
            ],
        }

    @_maps_missing_engine
    def report(self, project_dir: str | Path, output_dir: str | Path) -> dict[str, Any]:
        """Generate the HTML report of a rebrew project into *output_dir*.

        The project is resolved from ``rebrew-project.toml`` in *project_dir*.
        *output_dir* is reportal's own report directory, so the engine never
        writes into the rebrew project's output tree.  Output is the engine's
        parsed object (``out``, ``pages``, ``summary``).
        """
        root = _require_project(project_dir)
        self._require_available()
        from rebrew.report import generate_report

        cfg = _load_config(root)
        return _call("report", lambda: generate_report(cfg, Path(output_dir)))

    @_maps_missing_engine
    def decompile(
        self,
        project_dir: str | Path,
        va: int,
        decompiler: str = DEFAULT_DECOMPILER_BACKEND,
        named: bool = False,
    ) -> dict[str, Any]:
        """Return the decompiled C source of *va* from a rebrew project.

        The project is resolved from ``rebrew-project.toml`` in *project_dir*.
        ``named`` asks the engine to apply known symbol names.  Output is the
        engine's parsed object (``va``, ``backend``, ``named``, ``applied``,
        ``code``).
        """
        if decompiler not in DECOMPILER_BACKENDS:
            raise EngineError(f"unsupported decompiler backend: {decompiler}")
        root = _require_project(project_dir)
        self._require_available()
        from rebrew.decompiler import fetch_decompilation

        cfg = _load_config(root)
        code, backend = _call(
            "decompile",
            lambda: fetch_decompilation(decompiler, cfg.target_binary, va, cfg.root),
        )
        if not code:
            raise EngineError(
                f"decompilation failed via '{decompiler}' for 0x{va:x}"
                " (backend unavailable or unsupported address)"
            )
        applied: list[dict[str, Any]] = []
        if named:
            from rebrew.name_decomp import apply_known_names
            from rebrew.sources import iter_library_headers, iter_sources
            from rebrew.struct_recover import existing_structs

            sources = list(iter_sources(cfg.reversed_dir, cfg))
            sources += list(iter_library_headers(cfg.reversed_dir, cfg))
            definitions = existing_structs(sources)
            pointer_width = int(getattr(cfg, "pointer_size", 4) or 4)
            original = code
            result = _call(
                "decompile --named",
                lambda: apply_known_names(original, definitions, pointer_width=pointer_width),
            )
            code = result.code
            applied = result.applied
        return {
            "va": f"0x{va:x}",
            "backend": backend,
            "named": bool(applied),
            "applied": applied,
            "code": code,
        }

    @_maps_missing_engine
    def xrefs(self, project_dir: str | Path, va: int, kinds: Sequence[str] = ()) -> dict[str, Any]:
        """Return the cross-references to *va* from a rebrew project.

        The project is resolved from ``rebrew-project.toml`` in *project_dir*.
        *kinds* filters the result; an empty sequence keeps every kind.  Output
        is the engine's parsed object (``target``, ``import_name``, ``count``,
        ``refs``).
        """
        root = _require_project(project_dir)
        self._require_available()
        from rebrew.xrefs import build_xrefs_payload

        cfg = _load_config(root)
        return _call("xrefs", lambda: build_xrefs_payload(cfg.target_binary, va, list(kinds)))

    @_maps_missing_engine
    def describe(self, project_dir: str | Path, va: int) -> dict[str, Any]:
        """Return one function's recon dossier from a rebrew project.

        The project is resolved from ``rebrew-project.toml`` in *project_dir*.
        Output is the engine's parsed object (``va``, ``name``, ``status``,
        ``size``, ``cflags``, ``pattern``, ``convention``, ``callers``,
        ``callees``, ``strings``, ``globals``, ``imports``): a caller is
        ``{"from_va", "name"}``, a callee ``{"to_va", "name", "kind"}`` with an
        IAT kind for an indirect call, and a global ``{"va", "kind"}`` whose
        kind names the access (``mov_mem`` a read, ``mov_mem_store`` a write,
        ``lea``/``mov``/``push`` an address load).
        """
        root = _require_project(project_dir)
        self._require_available()
        from rebrew.analysis import is_inside
        from rebrew.binary_loader import load_binary
        from rebrew.describe import _JSON_KEYS, build_dossier

        cfg = _load_config(root)
        info = _call("describe", lambda: load_binary(cfg.target_binary))
        if not is_inside(info, va):
            raise EngineError(f"VA 0x{va:x} is outside the binary image")
        dossier = _call("describe", lambda: build_dossier(cfg, info, va))
        return {key: dossier[key] for key in _JSON_KEYS}

    @_maps_missing_engine
    def structs(
        self,
        project_dir: str | Path,
        *,
        decompiler: str = DEFAULT_DECOMPILER_BACKEND,
        limit: int = 0,
    ) -> dict[str, Any]:
        """Return struct definitions recovered from a rebrew project.

        The project is resolved from ``rebrew-project.toml`` in *project_dir*;
        its annotated functions are decompiled and their member accesses
        aggregated.  ``limit`` caps how many functions are decompiled, with 0
        leaving the engine's own cap.  Nothing is written back into the
        project.  Output is the engine's parsed object (``decompiled``,
        ``skipped``, ``structs``).
        """
        if decompiler not in DECOMPILER_BACKENDS:
            raise EngineError(f"unsupported decompiler backend: {decompiler}")
        if limit < 0:
            raise EngineError(f"struct limit must not be negative, got {limit}")
        root = _require_project(project_dir)
        self._require_available()
        from rebrew.struct_recover import recover_project_structs

        cfg = _load_config(root)
        return _call(
            "recover-structs",
            lambda: recover_project_structs(
                cfg, decompiler=decompiler, limit=limit, json_output=True
            ),
        )

    def read_memory(
        self,
        binary: str | Path,
        *,
        address: int,
        length: int = MEMORY_READ_DEFAULT,
        kind: str = MEMORY_ADDRESS_KIND_VA,
    ) -> dict[str, Any]:
        """Return a window of *binary*'s bytes by address.

        rebrew exposes no raw byte-read entry point, so the section map comes
        from the engine's own ``pe_info`` call and the bytes are then read from
        the file exactly where that map says they live; reportal never parses a
        PE.  *kind* is ``va`` (an absolute virtual address), ``rva`` (relative
        to the image base) or ``file`` (a raw file offset, which needs no map).

        Raises :class:`EngineError` for a length outside ``1..MEMORY_READ_MAX``
        or an unknown kind, and :class:`UnmappedAddressError` (a subclass) for
        an address not backed by the image's raw bytes (an unmapped address, a
        header-only RVA, or a section's uninitialized tail) or a window that
        runs past the backing bytes.  Output is ``{"kind", "address", "va",
        "section", "length", "bytes"}`` with the address fields hex and
        ``bytes`` lowercase hex.
        """
        if kind not in MEMORY_ADDRESS_KINDS:
            raise EngineError(f"unsupported address kind: {kind}")
        if length <= 0 or length > MEMORY_READ_MAX:
            raise EngineError(f"length must be between 1 and {MEMORY_READ_MAX}, got {length}")
        if address < 0:
            raise EngineError(f"address must not be negative, got {address}")
        path = Path(_require_file(binary))
        if kind == "file":
            data = _read_window(path, offset=address, length=length)
            return {
                "kind": kind,
                "address": hex(address),
                "va": None,
                "section": None,
                "length": len(data),
                "bytes": data.hex(),
            }
        info = self.pe_info(path)
        image_base = int(info.get("image_base") or 0)
        rva = address if kind == "rva" else address - image_base
        if rva < 0:
            raise UnmappedAddressError(
                f"address {hex(address)} is below the image base {hex(image_base)}"
            )
        found = _section_for_rva(info, rva)
        if found is None:
            raise UnmappedAddressError(
                f"address {hex(address)} is not backed by the binary's raw bytes"
            )
        section, offset = found
        raw_end = int(section.get("virtual_address") or 0) + int(section.get("raw_size") or 0)
        available = raw_end - rva
        if length > available:
            raise UnmappedAddressError(
                f"window of {length} bytes at {hex(address)} runs past"
                f" {section.get('name') or 'the section'} ({available} bytes available)"
            )
        data = _read_window(path, offset=offset, length=length)
        return {
            "kind": kind,
            "address": hex(address),
            "va": hex(image_base + rva),
            "section": str(section.get("name") or ""),
            "length": len(data),
            "bytes": data.hex(),
        }

    def read_memory_page(
        self,
        binary: str | Path,
        *,
        address: int | None = None,
        length: int = MEMORY_PAGE_DEFAULT,
        kind: str = MEMORY_ADDRESS_KIND_VA,
    ) -> dict[str, Any]:
        """Return one page of the binary's bytes for the full-file hex view.

        The page walks the image's virtual address space with the same
        ``pe-info`` section map :meth:`read_memory` uses: a run inside a
        section's raw bytes is a ``bytes`` row read from the file where the map
        says it lives, and every byte the map does not back (a header, the gap
        between two sections, a section's uninitialized tail, or a page that
        runs past the last section) is one ``gap`` row.  A gap is a stated
        fact: the engine refuses the read it cannot serve rather than rendering
        zeros.

        *address* is the page's first address and *kind* its address kind
        (``va``, ``rva`` or ``file``); ``None`` starts at the first raw-backed
        section.  *length* is bounded by :data:`MEMORY_PAGE_MAX`.  A start not
        backed by raw bytes raises :class:`UnmappedAddressError`, so a caller's
        jump is refused rather than answered with an all-gap page.

        Output is ``{"kind", "address", "start", "length", "next", "prev",
        "sections", "rows", "mapped", "gaps"}``: addresses and offsets are hex
        strings (``next``/``prev`` are the neighbouring *mapped* page starts, so
        a step never lands where the engine cannot read, and ``None`` at either
        end), each bytes row carries its address, file offset and lowercase hex,
        and each gap row its address and byte length.
        """
        if kind not in MEMORY_ADDRESS_KINDS:
            raise EngineError(f"unsupported address kind: {kind}")
        if length <= 0 or length > MEMORY_PAGE_MAX:
            raise EngineError(f"length must be between 1 and {MEMORY_PAGE_MAX}, got {length}")
        path = Path(_require_file(binary))
        info = self.pe_info(path)
        image_base = int(info.get("image_base") or 0)
        spans: list[tuple[tuple[int, int], Mapping[str, Any]]] = []
        for section in _section_entries(info):
            span = _section_span(section, image_base)
            if span is not None:
                spans.append((span, section))
        spans.sort(key=lambda item: item[0])
        if not spans:
            raise UnmappedAddressError(f"{path.name} has no raw-backed sections")
        if address is None:
            start = spans[0][0][0]
        elif kind == "file":
            found = _va_for_file_offset(info, address)
            if found is None:
                raise UnmappedAddressError(f"file offset {hex(address)} is not backed by a section")
            start = found[2]
        else:
            rva = address if kind == "rva" else address - image_base
            if rva < 0:
                raise UnmappedAddressError(
                    f"address {hex(address)} is below the image base {hex(image_base)}"
                )
            if _section_for_rva(info, rva) is None:
                raise UnmappedAddressError(
                    f"address {hex(address)} is not backed by the binary's raw bytes"
                )
            start = image_base + rva
        end = start + length
        low = spans[0][0][0]

        def is_mapped(va: int) -> bool:
            """True when a raw-backed section covers *va*."""
            return any(span_start <= va < span_end for (span_start, span_end), _section in spans)

        # Neighbouring page starts.  A page never begins where the engine
        # cannot read, so a step that would land in a gap snaps to the nearest
        # mapped start instead; a page whose range still crosses into a gap
        # renders it, because the walk starts inside backed bytes.
        next_va: int | None
        if is_mapped(end):
            next_va = end
        else:
            later = [span_start for (span_start, _span_end), _section in spans if span_start > end]
            next_va = min(later) if later else None
        prev_va: int | None = None
        candidate = start - length
        if candidate >= low and is_mapped(candidate):
            prev_va = candidate
        else:
            earlier = [
                (span_start, span_end)
                for (span_start, span_end), _section in spans
                if span_start < start
            ]
            if earlier:
                span_start, span_end = earlier[-1]
                prev_va = max(span_start, span_end - length)

        rows: list[dict[str, Any]] = []
        mapped = 0
        gaps = 0
        cursor = start
        for (span_start, span_end), section in spans:
            if span_end <= cursor or span_start >= end:
                continue
            run_start = max(span_start, cursor)
            run_end = min(span_end, end)
            if run_start > cursor:
                gaps += run_start - cursor
                rows.append({"kind": "gap", "address": hex(cursor), "length": run_start - cursor})
            run_offset = int(section.get("raw_offset") or 0) + (run_start - span_start)
            data = _read_window(path, offset=run_offset, length=run_end - run_start)
            for row_start in range(0, len(data), MEMORY_BYTES_PER_ROW):
                chunk = data[row_start : row_start + MEMORY_BYTES_PER_ROW]
                mapped += len(chunk)
                rows.append(
                    {
                        "kind": "bytes",
                        "address": hex(run_start + row_start),
                        "offset": hex(run_offset + row_start),
                        "length": len(chunk),
                        "hex": chunk.hex(),
                    }
                )
            cursor = run_end
        if cursor < end:
            gaps += end - cursor
            rows.append({"kind": "gap", "address": hex(cursor), "length": end - cursor})
        return {
            "kind": kind,
            "address": hex(address) if address is not None else None,
            "start": hex(start),
            "length": length,
            "next": hex(next_va) if next_va is not None else None,
            "prev": hex(prev_va) if prev_va is not None else None,
            "sections": [
                {
                    "name": str(section.get("name") or ""),
                    "va": hex(image_base + int(section.get("virtual_address") or 0)),
                    "offset": hex(int(section.get("raw_offset") or 0)),
                    "raw_size": int(section.get("raw_size") or 0),
                    "virtual_size": int(section.get("virtual_size") or 0),
                }
                for _span, section in spans
            ],
            "rows": rows,
            "mapped": mapped,
            "gaps": gaps,
        }

    @_maps_missing_engine
    def security_scan(
        self,
        project_dir: str | Path,
        min_severity: str = DEFAULT_SECURITY_MIN_SEVERITY,
    ) -> dict[str, Any]:
        """Return rule-based security findings for a rebrew project's sources.

        The project is resolved from ``rebrew-project.toml`` in *project_dir*,
        and its reversed sources are scanned.  ``min_severity`` drops findings
        below that severity.  Output is the engine's parsed object (``root``,
        ``files_scanned``, ``findings``, ``count``, ``by_severity``), each
        finding carrying a ``rule``, ``cwe``, ``severity``, ``confidence``,
        ``file``, ``line``, ``function``, ``snippet`` and ``message``.
        """
        if min_severity not in SECURITY_SEVERITIES:
            raise EngineError(f"unsupported security severity: {min_severity}")
        root = _require_project(project_dir)
        self._require_available()
        from rebrew.security_scan import _filter_result, security_scan

        cfg = _load_config(root)
        return _call(
            "security-scan",
            lambda: _filter_result(security_scan(cfg.reversed_dir), min_severity),
        )

    @_maps_missing_engine
    def disassemble(self, project_dir: str | Path, va: int, size: int, fmt: str = "nasm") -> str:
        """Return the NASM (or hex) listing of *va* from a rebrew project.

        The project is resolved from ``rebrew-project.toml`` in *project_dir*.
        Output is the engine's text listing, not JSON: ``nasm`` is the NASM
        source ``rebrew asm --format nasm`` prints, ``hex`` the hex dump
        ``--format hex`` prints.
        """
        self._require_available()
        if fmt not in DISASM_FORMATS:
            raise EngineError(f"unsupported disassembly format: {fmt}")
        if size <= 0:
            raise EngineError(f"function size must be positive, got {size}")
        root = _require_project(project_dir)
        cfg = _load_config(root)

        if fmt == "hex":
            from rebrew.asm import hex_disassembly

            return _call("asm", lambda: hex_disassembly(cfg, va, size))

        from rebrew.asm import disassemble_to_nasm

        def _nasm() -> str:
            from rebrew.binary_loader import extract_raw_bytes

            code = extract_raw_bytes(cfg.target_binary, va, size)
            if code is None:
                raise EngineError(f"Could not extract {size} bytes at VA 0x{va:08X}")
            source, _stats = disassemble_to_nasm(code, va, f"func_{va:08X}")
            return source + "\n"

        return _call("asm", _nasm)

    @_maps_missing_engine
    def control_flow_graph(self, project_dir: str | Path, va: int, size: int = 0) -> dict[str, Any]:
        """Return the basic-block control-flow graph of *va* from a rebrew project.

        The project is resolved from ``rebrew-project.toml`` in *project_dir*.
        A positive *size* is the declared extent, the same value
        :meth:`disassemble` uses; zero lets the engine resolve the extent
        itself and answer empty ``blocks`` with a ``note`` when it cannot
        (never a guessed window).

        Output is the engine's payload with addresses as ``0x...`` text:
        ``va``, ``size``, ``blocks`` (each ``va``, ``size``,
        ``instruction_count``, ``first``, ``last``), ``edges`` (each ``from``,
        ``to``, ``back_edge``), ``block_count``, ``block_total``,
        ``block_cap``, ``truncated`` and ``note``.  A non-x86 target raises
        :class:`EngineError`.
        """
        root = _require_project(project_dir)
        self._require_available()
        cfg = _load_config(root)
        from rebrew.asm import build_cfg_payload

        return _call("asm", lambda: build_cfg_payload(cfg, va, size))

    @_maps_missing_engine
    def test_source(self, project_dir: str | Path, source: str | Path) -> dict[str, Any]:
        """Compile one reversed source file and byte-compare it to the target.

        The project is resolved from ``rebrew-project.toml`` in *project_dir*.
        ``source`` is the file to compile.  ``no_promote`` keeps the engine
        from writing STATUS/SIZE back into the project's metadata: reportal is
        the only writer of the state it tracks, and the caller reads the
        returned status instead.

        A mismatch is a result, not a failure: the engine returns the same
        object for a match and a mismatch, and only a tooling failure raises
        :class:`EngineError`.

        Output is the engine's object (``status``, ``match_count``, ``total``,
        ``mismatches``, ...).
        """
        root = _require_project(project_dir)
        self._require_available()
        cfg = _load_config(root)
        from rebrew.test import run_test

        return _call(
            "test",
            lambda: run_test(cfg, source, no_promote=True, json_output=True),
        )

    @_maps_missing_engine
    def lzexe_version(self, binary: str | Path) -> int | None:
        """The LZEXE version *binary* was packed with (90 or 91), or None.

        Detection reads the MZ header and the decompressor stub at the entry
        point, so "not packed" is an answer rather than a failure: a plain MZ,
        another packer and a non-MZ file all come back None.
        """
        path = _require_file(binary)
        self._require_available()
        from rebrew.lzexe import lzexe_version

        return _call("lzexe", lambda: lzexe_version(path))

    @_maps_missing_engine
    def unpack_lzexe(self, binary: str | Path, output: str | Path) -> dict[str, Any]:
        """Rebuild the image of an LZEXE-packed *binary* into *output*.

        Output is ``{"version", "image_size", "file_size"}``: the version the
        stub reports and the byte counts of the decompressed image and of the
        MZ file written.  A binary that is not LZEXE-packed raises
        :class:`EngineError`.
        """
        path = _require_file(binary)
        self._require_available()
        target = Path(output)
        from rebrew.lzexe import unpack_lzexe

        def rebuild() -> dict[str, Any]:
            result = unpack_lzexe(path)
            data = result.to_bytes()
            target.write_bytes(data)
            return {
                "version": result.version,
                "image_size": len(result.image),
                "file_size": len(data),
            }

        return _call("lzexe", rebuild)

    def _require_available(self) -> None:
        """Raise :class:`EngineUnavailable` when the engine is not importable."""
        if not self.available():
            raise EngineUnavailable(ENGINE_UNAVAILABLE_HINT)


_engine: RebrewEngine | None = None
_engine_lock = threading.Lock()


def get_engine() -> RebrewEngine:
    """Return the process-wide engine, probing rebrew on first use."""
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = RebrewEngine()
        return _engine


def set_engine(engine: RebrewEngine | None) -> None:
    """Install *engine* process-wide; None restores the default resolution."""
    global _engine
    with _engine_lock:
        _engine = engine
