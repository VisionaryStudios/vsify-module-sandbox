"""
Dotted-ref shape validation (ADR-P041, mirrors ``vsify_enterprise_mcp.entrypoint_ref``'s
``_dotted_ref_candidates`` validation half EXACTLY).

The host has already resolved a ``python_module`` entrypoint's dotted ref to a file and
bind-mounted that single file read-only at ``/module/entrypoint`` before this image ever starts —
this module does NOT re-resolve a file path from the ref (there is no repo tree inside the
container to resolve against). It exists so the image independently RE-VALIDATES the ref's shape
(defense-in-depth: never trust a host-supplied string blindly) using the identical rule, and uses
the ref for the loaded module's reported name / log messages.

A RE-EXPORT SHIM: the implementation lives in the pure ``import_closure`` module (which the host
mirrors byte-identically). This shim imports ONLY that module — never the exec-capable
``module_loader`` — so validating a ref can never pull a loader into scope.
"""
from __future__ import annotations

from .import_closure import _EntrypointRefMalformed, _validate_dotted_ref

EntrypointRefMalformed = _EntrypointRefMalformed
validate_dotted_ref = _validate_dotted_ref
