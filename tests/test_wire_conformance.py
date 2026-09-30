"""Cross-repo wire-format conformance (ADR-P041): THIS image's codec against
``schemas/SANDBOX_WIRE.json`` — the host's own pin, of which there is exactly ONE copy
(ADR-P048 §1/§2). The host's ``tests/test_sandbox_wire_conformance.py`` asserts the same vectors
against the host codec, so neither codec can drift from the other without a red build.

WHERE THE PIN IS READ FROM, and why there are two answers:

- **In-tree** (``vsify-enterprise-mcp/sandbox/``, the canonical home since ADR-P048 §1): the pin is
  the host's ``../schemas/SANDBOX_WIRE.json``. This tree deliberately carries NO copy of its own —
  a second copy is precisely the hand-vendored duplicate that used to drift, and the host's
  ``tests/test_sandbox_tree_provenance.py`` refuses one.
- **In the mirror** (``vsify-module-sandbox``, a generated DO-NOT-EDIT tree): the publisher renders
  the host pin into the mirror's own ``schemas/`` (ADR-P048 §2), so there is no ``..`` to read.

The in-tree layout is recognised by the host package directory sitting beside this tree. When it
is recognised, ONLY the host pin is consulted: a stray local copy is never allowed to shadow it.
An absent pin is a named failure, never a skip — a conformance test that skips on a missing input
reports coverage it did not provide.
"""
from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from vsify_sandbox.framing import MAGIC, WIRE_VERSION, encode_frame, read_frame

_SANDBOX_ROOT = Path(__file__).resolve().parent.parent
_HOST_ROOT = _SANDBOX_ROOT.parent
#: The host package directory. Its presence beside this tree is what "in-tree" means.
_HOST_MARKER = _HOST_ROOT / "vsify_enterprise_mcp"
_HOST_PIN = _HOST_ROOT / "schemas" / "SANDBOX_WIRE.json"
_MIRROR_PIN = _SANDBOX_ROOT / "schemas" / "SANDBOX_WIRE.json"


def _vectors_path() -> Path:
    in_tree = _HOST_MARKER.is_dir()
    path = _HOST_PIN if in_tree else _MIRROR_PIN
    if not path.is_file():
        layout = "in-tree (host package found beside sandbox/)" if in_tree else "mirror"
        pytest.fail(
            f"SANDBOX_WIRE.json not found at {path} ({layout} layout). In-tree, the pin is the "
            f"host's schemas/SANDBOX_WIRE.json and sandbox/ must not carry its own copy; in the "
            f"mirror, the publisher renders it into schemas/ (ADR-P048 §2). A missing pin means "
            f"this codec is being asserted against nothing."
        )
    return path


def _load():
    return json.loads(_vectors_path().read_text())


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
