# File and format analysis

Sources: src/reportal/filetypes.py, src/reportal/firmware.py, src/reportal/unpack.py, src/reportal/gobuildinfo.py, src/reportal/archive.py, src/reportal/zipcrypto.py

This subsystem answers what a stored file is and what it carries: type, packer and protector
detection, embedded-image carving, packer rebuilding, Go build info, archive extraction and the
protected zip download. All six modules read bytes reportal already stores, and none executes a
sample.

## Vocabulary

- `FileSignature(name, category, confidence, match)`: one entry of `SIGNATURES`. The categories
  are `packer`, `protector`, `installer`, `runtime` and `toolchain`.
- `SignatureMatch`: the evidence a signature can fire on (section-name prefix, entry-point prefix,
  string marker, import DLL, Rich header, high-entropy section). `SIGNAL_CONFIDENCES` caps each
  kind.
- `firmware.Signature(kind, label, magic, offset)`: a carve runs from one magic in `SIGNATURES` to
  the next, capped at `MAX_REGION_BYTES` and `MAX_REGIONS`.
- `archive.MemberOutcome(name, size, path, skipped)` and `Extraction(members, notes)`: one outcome
  per member. `ArchiveError.code` names a refusal that makes the archive unreadable.
- `unpack.UnpackError.code`: `unknown-packer`, `no-packer`, `no-unpacker` or `unpack-failed`.
  `PACKERS` is `lzexe` and `upx`.
- `gobuildinfo.GobuildinfoError.code` defaults to `not-go`; the payload carries the Go version,
  the module path, the build settings and the build id.
- `zipcrypto.DEFAULT_PASSWORD`, `MAX_PASSWORD_CHARS` and `validate_password`, the request gate.

## Wiring

- Routes: `POST /api/binaries/{binary_id}/filetype`, `.../firmware`, `.../firmware/extract`,
  `.../gobuildinfo`, `.../unpack`; `POST /api/binaries/{binary_id}/extract`; and
  `GET /api/binaries/{binary_id}/download-zipped`.
- CLI: `filetype`, `firmware`, `firmware-extract`, `gobuildinfo`, `extract`, `unpack`,
  `unpack-info` and `download --zip`.
- MCP: `run_filetype`, `run_firmware_scan`, `extract_firmware_regions`, `run_gobuildinfo`,
  `extract_archive`, `run_unpack`, `export_zipped_binary`, each with its `get_*` read.
- Scan kinds in `store.py`: `filetype`, `firmware`, `gobuildinfo`, `unpack`.

## Invariants

- Two independent signal kinds make a match `high`; a lone string or entropy signal never exceeds
  `low` (`tests/test_filetypes.py`).
- `run_filetype` records a failed evidence call as a note with an empty field, never a failed run
  (`tests/test_filetypes.py`).
- A gzip region is trimmed to `gzip_member_length`, so trailing non-zero data is refused
  (`tests/test_firmware.py`).
- Every archive member is refused before a byte is written: absolute or `..` names, links,
  devices, and members past the size, total, ratio or member cap (`tests/test_archive.py`).
- A missing `upx` reports `no-unpacker` with the install hint, never a silent no-op
  (`tests/test_unpack.py`).
- A file with no `Go buildinf:` magic is `not-go`, not an error (`tests/test_gobuildinfo.py`).
- Two downloads with the same password differ unless the caller passes `header=`
  (`tests/test_download_zipped.py`).

## See also

- [ARCHITECTURE.md: File type detection](../ARCHITECTURE.md#file-type-detection)
- [ARCHITECTURE.md: Firmware carving](../ARCHITECTURE.md#firmware-carving)
- [THREAT_MODEL.md](../THREAT_MODEL.md)
