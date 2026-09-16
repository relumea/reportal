"""The password-protected zip the zipped download serves.

The hosted portal answers ``GET /v2/binaries/{id}/download-zipped`` with a zip
whose one member is encrypted, which is what an analyst sends to a mailbox or a
sandbox that refuses to look at a raw sample.  Python's ``zipfile`` *reads* that
format (``ZipFile.setpassword``) but cannot write it, so the writer is here:
the traditional PKWARE scheme (``ZipCrypto``), as specified in APPNOTE 6.3.x
section 4.4.4.

Two honesty notes, both deliberate:

- The password is **not a security measure**.  ZipCrypto is a stream cipher with
  a 12-byte known-plaintext header and no authentication, and the default
  password this module is called with is a shared convention, not a secret.  It
  defeats a naive scanner that opens every zip it sees, which is the whole
  reason the hosted portal offers it too.
- The 11 random header bytes are drawn per call, so two downloads of the same
  binary with the same password are not byte-identical.  ``header=`` is the
  seam a test uses to pin the output.

The archive is written in one pass over a spooled temporary file so a stored
binary of any size (uploads are capped at 256 MiB) never has to be held in
memory: the plaintext is deflated into the spool while its CRC and compressed
length are computed, then the spool is encrypted into the target.
"""

from __future__ import annotations

import os
import struct
import tempfile
import zlib
from collections.abc import Iterator
from io import BytesIO
from typing import Protocol

# The password a caller that does not name one gets, the malware-analysis
# convention for a shared sample archive.  It is not a secret.
DEFAULT_PASSWORD = "infected"

# Longest password the routes and tools accept.  ZipCrypto folds at most a few
# bytes usefully, so the cap is a request-shape bound rather than a strength
# one; it lives here because the scheme is what it describes.
MAX_PASSWORD_CHARS = 128

# Detail :func:`validate_password` raises when the password is empty or too long.
PASSWORD_LENGTH_DETAIL = f"password must be 1 to {MAX_PASSWORD_CHARS} characters"

# Detail when the password carries a control character: the download route echoes
# the value in ``X-Reportal-Zip-Password``, so CR/LF/NUL would split or corrupt
# the response headers.
PASSWORD_CONTROL_DETAIL = "password must not contain control characters"


def validate_password(password: str) -> str:
    """Return *password* when it is safe to put in a zip and a response header.

    Empty or overlong values, and any ASCII control character (including CR,
    LF and NUL), are refused.  Callers map the :class:`ValueError` message onto
    their own error vocabulary.
    """
    if not password or len(password) > MAX_PASSWORD_CHARS:
        raise ValueError(PASSWORD_LENGTH_DETAIL)
    if any(ord(ch) < 32 for ch in password):
        raise ValueError(PASSWORD_CONTROL_DETAIL)
    return password


# Bytes one read of the source takes while it is deflated.
READ_CHUNK_BYTES = 1024 * 1024

# Spool size before the deflated copy goes to disk instead of staying in memory.
SPOOL_MEMORY_BYTES = 8 * 1024 * 1024

# The DOS timestamp every member carries: 1980-01-01 00:00, the earliest the
# format can express.  A fixed value keeps a download reproducible given the
# same header, rather than depending on the clock.
_DOS_TIME = 0
_DOS_DATE = 0x0021

# Zip method and flags: deflate, encrypted, sizes written up front.
# Bit 11 (UTF-8) is set because member names are always encoded as UTF-8;
# without it, readers assume CP437 and turn non-ASCII names into mojibake
# (APPNOTE 6.3.x section 4.4.4).
_METHOD_DEFLATE = 8
_FLAG_ENCRYPTED = 0x0001
_FLAG_UTF8 = 0x0800
_MEMBER_FLAGS = _FLAG_ENCRYPTED | _FLAG_UTF8

_LOCAL_HEADER = 0x04034B50
_CENTRAL_HEADER = 0x02014B50
_END_OF_DIRECTORY = 0x06054B50


class Readable(Protocol):
    """The read surface the writer needs from a source."""

    def read(self, size: int = -1) -> bytes: ...


class Writable(Protocol):
    """The write surface the writer needs from a target."""

    def write(self, data: bytes) -> int: ...


# The 12-byte encryption header PKWARE puts before every encrypted member.
_HEADER_BYTES = 12
_HEADER_RANDOM_BYTES = _HEADER_BYTES - 1

# ZipCrypto's three keys and the constant in key1's update.
_KEY0_INIT = 0x12345678
_KEY1_INIT = 0x23456789
_KEY2_INIT = 0x34567890
_KEY1_MULTIPLIER = 134775813
_KEY1_INCREMENT = 1
_UINT32 = 0xFFFFFFFF


def _crc_table() -> tuple[int, ...]:
    """The reflected CRC-32 table (polynomial 0xEDB88320).

    Hand-rolled rather than :func:`zlib.crc32` on purpose: zlib finalizes
    (XOR-out) on every call, while ZipCrypto's key schedule needs the raw
    internal CRC state after each byte.  The table update below is that raw
    step; the suite's round-trip tests pin it byte for byte.
    """
    table = []
    for index in range(256):
        value = index
        for _ in range(8):
            value = (value >> 1) ^ (0xEDB88320 if value & 1 else 0)
        table.append(value)
    return tuple(table)


_CRC_TABLE = _crc_table()


def _crc32_byte(crc: int, byte: int) -> int:
    """One step of the CRC-32 update ZipCrypto keys with."""
    return (crc >> 8) ^ _CRC_TABLE[(crc ^ byte) & 0xFF]


class _Keys:
    """ZipCrypto's three-key state and its keystream."""

    __slots__ = ("key0", "key1", "key2")

    def __init__(self, password: str) -> None:
        self.key0 = _KEY0_INIT
        self.key1 = _KEY1_INIT
        self.key2 = _KEY2_INIT
        for byte in password.encode("utf-8"):
            self.update(byte)

    def update(self, byte: int) -> None:
        """Fold one plaintext byte into the key state."""
        self.key0 = _crc32_byte(self.key0, byte)
        self.key1 = (self.key1 + (self.key0 & 0xFF)) & _UINT32
        self.key1 = (self.key1 * _KEY1_MULTIPLIER + _KEY1_INCREMENT) & _UINT32
        self.key2 = _crc32_byte(self.key2, (self.key1 >> 24) & 0xFF)

    def keystream(self) -> int:
        """The next keystream byte, which is XORed with one plaintext byte.

        Only the product's bits 8 to 15 survive the shift and the mask, and
        those depend only on the key's low 16 bits, so the 16-bit truncation
        some implementations write is equivalent here.
        """
        temp = self.key2 | 2
        return ((temp * (temp ^ 1)) >> 8) & 0xFF

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt *data*, advancing the key state."""
        out = bytearray(len(data))
        for index, byte in enumerate(data):
            out[index] = byte ^ self.keystream()
            self.update(byte)
        return bytes(out)


def _encryption_header(keys: _Keys, crc: int, header: bytes | None) -> bytes:
    """Encrypt the 12-byte header with *keys*, leaving them ready for the data.

    The header is 11 bytes of the caller's material (random by default) and the
    check byte, the high byte of the member's CRC, because the local header
    writes the real sizes rather than a trailing data descriptor.  The plaintext
    is what the key state folds in, so the same *keys* object encrypts the
    member's data next.
    """
    if header is None:
        prefix = os.urandom(_HEADER_RANDOM_BYTES)
    else:
        prefix = bytes(header)
        if len(prefix) != _HEADER_RANDOM_BYTES:
            raise ValueError(f"header must be {_HEADER_RANDOM_BYTES} bytes")
    return keys.encrypt(prefix + bytes([(crc >> 24) & 0xFF]))


def write_protected_zip(
    target: Writable,
    name: str,
    source: Readable,
    password: str,
    *,
    header: bytes | None = None,
) -> int:
    """Write one encrypted member named *name* from *source* into *target*.

    *source* is read from its current position to the end and deflated into a
    spooled temporary file (memory up to :data:`SPOOL_MEMORY_BYTES`, then disk),
    so a large binary is compressed and then encrypted without ever being held
    whole.  Returns the number of bytes written to *target*.
    """
    plaintext_crc = 0
    plaintext_size = 0
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    with tempfile.SpooledTemporaryFile(max_size=SPOOL_MEMORY_BYTES) as spool:
        while True:
            chunk = source.read(READ_CHUNK_BYTES)
            if not chunk:
                break
            plaintext_size += len(chunk)
            plaintext_crc = zlib.crc32(chunk, plaintext_crc)
            spool.write(compressor.compress(chunk))
        spool.write(compressor.flush())
        compressed_size = spool.tell()
        spool.seek(0)

        # One key state covers the encryption header and the member data: the
        # plaintext of both is what it folds in.
        keys = _Keys(password)
        encryption_header = _encryption_header(keys, plaintext_crc, header)
        encoded_name = name.encode("utf-8")
        # The compressed size counts the 12-byte encryption header, which is
        # what makes an encrypted member's local header self-describing.
        stored_size = compressed_size + _HEADER_BYTES
        written = 0
        written += target.write(
            struct.pack(
                "<IHHHHHIIIHH",
                _LOCAL_HEADER,
                20,
                _MEMBER_FLAGS,
                _METHOD_DEFLATE,
                _DOS_TIME,
                _DOS_DATE,
                plaintext_crc & _UINT32,
                stored_size,
                plaintext_size,
                len(encoded_name),
                0,
            )
        )
        written += target.write(encoded_name)
        written += target.write(encryption_header)
        while True:
            chunk = spool.read(READ_CHUNK_BYTES)
            if not chunk:
                break
            written += target.write(keys.encrypt(chunk))

        directory_offset = written
        written += target.write(
            struct.pack(
                "<IHHHHHHIIIHHHHHII",
                _CENTRAL_HEADER,
                20,
                20,
                _MEMBER_FLAGS,
                _METHOD_DEFLATE,
                _DOS_TIME,
                _DOS_DATE,
                plaintext_crc & _UINT32,
                stored_size,
                plaintext_size,
                len(encoded_name),
                0,
                0,
                0,
                0,
                0,
                0,
            )
        )
        written += target.write(encoded_name)
        directory_size = written - directory_offset
        written += target.write(
            struct.pack(
                "<IHHHHIIH",
                _END_OF_DIRECTORY,
                0,
                0,
                1,
                1,
                directory_size,
                directory_offset,
                0,
            )
        )
        return written


def build_protected_zip(
    name: str, data: bytes, password: str = DEFAULT_PASSWORD, *, header: bytes | None = None
) -> bytes:
    """The encrypted zip for *data* as bytes; the in-memory form of the writer."""
    buffer = BytesIO()
    write_protected_zip(buffer, name, BytesIO(data), password, header=header)
    return buffer.getvalue()


def stream_protected_zip(
    name: str,
    source: Readable,
    password: str = DEFAULT_PASSWORD,
    *,
    header: bytes | None = None,
    chunk_bytes: int = READ_CHUNK_BYTES,
) -> Iterator[bytes]:
    """Yield the encrypted zip in *chunk_bytes* pieces, for a streaming response.

    The archive is assembled in a spooled temporary file first (the sizes and
    the CRC have to precede the data), then handed out in bounded reads, so the
    response never holds the whole archive either.
    """
    with tempfile.SpooledTemporaryFile(max_size=SPOOL_MEMORY_BYTES) as spool:
        write_protected_zip(spool, name, source, password, header=header)
        spool.seek(0)
        while True:
            piece = spool.read(chunk_bytes)
            if not piece:
                break
            yield piece
