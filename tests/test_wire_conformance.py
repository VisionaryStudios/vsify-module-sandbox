"""Cross-repo wire-format conformance (ADR-P041): THIS image's codec against
``schemas/SANDBOX_WIRE.json`` — the SAME file vendored byte-identical from vsify-enterprise-mcp
(whose own ``tests/test_sandbox_wire_conformance.py`` asserts the same vectors against its own
codec). Neither side can drift from the other without a red build.
"""
from __future__ import annotations

import io
import json
from pathlib import Path

from vsify_sandbox.framing import MAGIC, WIRE_VERSION, encode_frame, read_frame

_VECTORS_PATH = Path(__file__).resolve().parent.parent / "schemas" / "SANDBOX_WIRE.json"


def _load():
    return json.loads(_VECTORS_PATH.read_text())


def test_magic_and_version_match_the_pinned_constants():
    doc = _load()
    assert doc["magic_hex"] == MAGIC.hex()
    assert doc["wire_version"] == WIRE_VERSION


def test_every_vector_encodes_to_the_pinned_frame_hex():
    doc = _load()
    for vector in doc["vectors"]:
        payload = bytes.fromhex(vector["payload_hex"])
        frame = encode_frame(vector["frame_type"], payload, truncated=vector["truncated"])
        assert frame.hex() == vector["frame_hex"], f"vector {vector['name']!r} encode mismatch"


def test_every_vector_decodes_back_to_its_own_fields():
    doc = _load()
    for vector in doc["vectors"]:
        frame_bytes = bytes.fromhex(vector["frame_hex"])
        frame_type, payload, truncated = read_frame(io.BytesIO(frame_bytes).read, max_payload_bytes=1024)
        assert frame_type == vector["frame_type"], f"vector {vector['name']!r} type mismatch"
        assert payload.hex() == vector["payload_hex"], f"vector {vector['name']!r} payload mismatch"
        assert truncated == vector["truncated"], f"vector {vector['name']!r} truncated-flag mismatch"
