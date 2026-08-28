"""
Wire framing (ADR-P041, vsify-enterprise-mcp) — the SAME frame codec as the host's
``vsify_enterprise_mcp.isolation.wire_framing``, mirrored byte-for-byte on the image side. Pinned
against ``schemas/SANDBOX_WIRE.json`` (vendored byte-identical from the host repo) by
``tests/test_wire_conformance.py`` — neither side can drift without a red build.

Pure codec, NO I/O of its own: ``read_frame`` takes an injected ``read`` callable so the whole
module is unit-testable with ``io.BytesIO``.

Frame layout (12-byte header + payload)::

    MAGIC(4=b"VSB1") | VERSION(u16 BE) | TYPE(u8) | FLAGS(u8, bit0=truncated) | LENGTH(u32 BE) | payload
"""
from __future__ import annotations

from collections.abc import Callable

MAGIC = b"VSB1"
WIRE_VERSION = 1
_HEADER_SIZE = 4 + 2 + 1 + 1 + 4  # magic + version + type + flags + length

FRAME_READY = 0
FRAME_REQUEST = 1
FRAME_RESPONSE = 2
FRAME_ERROR = 3

_FLAG_TRUNCATED = 0b0000_0001


class SandboxWireError(Exception):
    """A wire-framing fault — malformed header, version mismatch, oversize/short/incomplete
    frame. ``reason`` is a categorical, secret-free token."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def encode_frame(frame_type: int, payload: bytes, *, truncated: bool = False) -> bytes:
    """Build one complete frame (header + payload) — pure, no I/O."""
    flags = _FLAG_TRUNCATED if truncated else 0
    header = (
        MAGIC + WIRE_VERSION.to_bytes(2, "big") + bytes([frame_type & 0xFF, flags])
        + len(payload).to_bytes(4, "big")
    )
    return header + payload


def _decode_header(header: bytes) -> tuple[int, bool, int]:
    if len(header) != _HEADER_SIZE:
        raise SandboxWireError("header_incomplete")
    if header[:4] != MAGIC:
        raise SandboxWireError("bad_magic")
    version = int.from_bytes(header[4:6], "big")
    if version != WIRE_VERSION:
        raise SandboxWireError("version_mismatch")
    frame_type = header[6]
    flags = header[7]
    length = int.from_bytes(header[8:12], "big")
    return frame_type, bool(flags & _FLAG_TRUNCATED), length


def read_frame(read: Callable[[int], bytes], *, max_payload_bytes: int) -> tuple[int, bytes, bool]:
    """Read one complete frame via the injected ``read(n) -> bytes`` callable. The LENGTH field is
    checked against ``max_payload_bytes`` BEFORE any payload read is attempted (anti-OOM). Raises
    :class:`SandboxWireError` on any fault. Returns ``(frame_type, payload, truncated)``."""
    header = _read_exact(read, _HEADER_SIZE)
    frame_type, truncated, length = _decode_header(header)
    if length > max_payload_bytes:
        raise SandboxWireError("frame_too_large")
    payload = _read_exact(read, length) if length else b""
    return frame_type, payload, truncated


def _read_exact(read: Callable[[int], bytes], n: int) -> bytes:
    if n == 0:
        return b""
    chunks: list[bytes] = []
    remaining = n
    while remaining > 0:
        chunk = read(remaining)
        if not chunk:
            raise SandboxWireError("incomplete_frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
