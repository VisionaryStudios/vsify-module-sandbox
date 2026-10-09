"""The Dockerfile's ``org.vsify.sandbox.loader_sha256`` LABEL is the hash of the loader this image runs.

The host compares a consumer image's inherited label against the same hash computed from its own
mirror (``runtime_image_loader_skew``, issue #862), so a stale literal would refuse every consumer
image built on the current base. The literal is recomputed here; the failure prints the new value.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_LOADER_FILES = ("module_loader.py", "import_closure.py", "package_tree.py")
_LABEL = re.compile(r'^LABEL org\.vsify\.sandbox\.loader_sha256="([0-9a-f]{64})"$', re.MULTILINE)


def _expected() -> str:
    digest = hashlib.sha256()
    for name in _LOADER_FILES:
        digest.update((_ROOT / "vsify_sandbox" / name).read_bytes())
    return digest.hexdigest()


def test_loader_label_matches_the_loader_files():
    labels = _LABEL.findall((_ROOT / "Dockerfile").read_text(encoding="utf-8"))
    assert len(labels) == 1, "expected exactly one loader_sha256 LABEL line in the Dockerfile"
    expected = _expected()
    assert labels[0] == expected, (
        "sandbox/Dockerfile's loader_sha256 LABEL is stale. A loader file changed; set it to\n"
        f'    LABEL org.vsify.sandbox.loader_sha256="{expected}"'
    )
