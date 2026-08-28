"""``vsify_sandbox.entrypoint_resolve`` — the dotted-ref shape re-validation (ADR-P041), mirroring
``vsify_enterprise_mcp.entrypoint_ref._dotted_ref_candidates``'s validation half exactly.
"""
from __future__ import annotations

import pytest

from vsify_sandbox.entrypoint_resolve import EntrypointRefMalformed, validate_dotted_ref


def test_a_simple_dotted_ref_validates():
    assert validate_dotted_ref("modules.acme.entrypoint") == ("modules", "acme", "entrypoint")


def test_a_single_segment_ref_validates():
    assert validate_dotted_ref("entrypoint") == ("entrypoint",)


@pytest.mark.parametrize("bad_ref", [
    "",
    "modules/acme/entrypoint",  # slashes — not a dotted ref
    "modules.-acme.entrypoint",  # leading hyphen segment
    "modules.1acme.entrypoint",  # leading digit segment
    "modules..entrypoint",  # empty segment
    "modules.acmé.entrypoint",  # non-ASCII homoglyph segment
])
def test_malformed_refs_are_refused(bad_ref):
    with pytest.raises(EntrypointRefMalformed):
        validate_dotted_ref(bad_ref)
