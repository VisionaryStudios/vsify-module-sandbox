"""
Dotted-ref shape validation (ADR-P041, mirrors ``vsify_enterprise_mcp.entrypoint_ref``'s
``_dotted_ref_candidates`` validation half EXACTLY).

The host has already resolved a ``python_module`` entrypoint's dotted ref to a file and
bind-mounted that single file read-only at ``/module/entrypoint`` before this image ever starts —
this module does NOT re-resolve a file path from the ref (there is no repo tree inside the
container to resolve against). It exists so the image independently RE-VALIDATES the ref's shape
(defense-in-depth: never trust a host-supplied string blindly) using the identical rule, and uses
the ref for the loaded module's reported name / log messages.
"""
from __future__ import annotations


class EntrypointRefMalformed(Exception):
    """The dotted ref failed shape validation — never trust it for loading or logging as-is."""


def validate_dotted_ref(ref: str) -> tuple[str, ...]:
    """Validate ``ref`` against the SAME rule ``entrypoint_ref.py``'s ``_dotted_ref_candidates``
    enforces host-side: every dot-separated segment MUST be ``str.isascii()`` AND
    ``str.isidentifier()`` (rejects ``/``, ``-``, leading digits, empty segments, and any
    non-ASCII homoglyph segment). Returns the validated segment tuple. Raises
    :class:`EntrypointRefMalformed` on any violation."""
    ref = str(ref or "")
    segments = tuple(ref.split("."))
    if not segments or not all(seg.isascii() and seg.isidentifier() for seg in segments):
        raise EntrypointRefMalformed("entrypoint_ref_malformed")
    return segments
