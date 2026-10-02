#!/usr/bin/env python3
"""Derive the verify matrix from the pushed image index (issue #672, ADR-P048 v1.11).

`verify` must cover every member the tag will point at. `promote` moves a tag to the whole index
(`imagetools create` copies it), so a matrix written by hand beside the build is one edit away from
promoting a member nothing pulled, smoke-tested or scanned. This reads the index the digest
actually names and emits one leg per platform it carries -- so the verified set and the promoted
set are the same set by construction, not by two lists agreeing.

Fail-closed edges:
  * attestation entries (`provenance`/`sbom`, platform unknown/unknown) are not platforms;
  * a platform with no NATIVE runner refuses -- the smoke test needs native Linux Docker
    (ADR-P041), so an emulated leg would be a verification in name only, and skipping the
    platform would promote it unverified;
  * a bare manifest refuses -- this pipeline always pushes an index, and guessing a platform for
    one would verify a member by assumption;
  * `--require` (the set `build` was asked for) refuses an index carrying anything else, which is
    how a build that silently dropped a platform -- the #672 gap itself -- reddens instead of
    promoting the survivors. rollback-latest omits it: its target may predate #672 (amd64 only).

Usage: docker buildx imagetools inspect --raw IMAGE@DIGEST | \
         python3 scripts/verify_matrix.py [--require linux/amd64,linux/arm64] >> "$GITHUB_OUTPUT"
"""
from __future__ import annotations

import json
import sys

# The ONE map from a published platform to the hosted runner that executes it natively. Adding a
# platform to `build` without a row here refuses at `verify` -- see CONTRIBUTING.md step `B8`.
RUNNERS = {"linux/amd64": "ubuntu-latest", "linux/arm64": "ubuntu-24.04-arm"}

_INDEX_TYPES = frozenset({
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
})
# arm64's only variant is v8; registries and buildx spell it both ways for the same platform.
_EQUIVALENT_VARIANTS = {("arm64", "v8")}


class MatrixError(ValueError):
    """The index cannot be verified as-is. The message names the reason."""


def _platform(entry: dict) -> str | None:
    if (entry.get("annotations") or {}).get("vnd.docker.reference.type") == "attestation-manifest":
        return None
    p = entry.get("platform") or {}
    os_, arch, variant = p.get("os"), p.get("architecture"), p.get("variant")
    if not os_ or not arch or os_ == "unknown" or arch == "unknown":
        return None
    if variant and (arch, variant) not in _EQUIVALENT_VARIANTS:
        return f"{os_}/{arch}/{variant}"
    return f"{os_}/{arch}"


def _parse_require(require: str | None) -> set[str] | None:
    if require is None or not require.strip():
        return None
    return {p.strip() for p in require.split(",") if p.strip()}


def matrix(index: dict, require: str | None = None) -> list[dict[str, str]]:
    """One ``{platform, arch, runner}`` row per platform ``index`` carries, sorted by platform."""
    if not isinstance(index, dict) or index.get("mediaType") not in _INDEX_TYPES:
        raise MatrixError(
            "not an image index: this pipeline always pushes an index (provenance/sbom attach as "
            "index entries), so a bare manifest has no platform to verify against"
        )
    entries = index.get("manifests")
    if not isinstance(entries, list):
        raise MatrixError("not an image index: no manifests list")
    found = {p for p in (_platform(e) for e in entries if isinstance(e, dict)) if p}
    if not found:
        raise MatrixError("the index carries no platform (attestation entries only)")
    unsupported = sorted(found - RUNNERS.keys())
    if unsupported:
        raise MatrixError(
            f"no native runner for {', '.join(unsupported)}: add the platform to RUNNERS in "
            "scripts/verify_matrix.py (CONTRIBUTING.md step B8) or drop it from the build"
        )
    wanted = _parse_require(require)
    if wanted is not None and wanted != found:
        missing, extra = sorted(wanted - found), sorted(found - wanted)
        raise MatrixError(
            f"the index does not carry exactly the built platform set {sorted(wanted)}: "
            f"missing {missing}, unexpected {extra}"
        )
    return [{"platform": p, "arch": p.split("/", 1)[1].replace("/", "-"), "runner": RUNNERS[p]}
            for p in sorted(found)]


def _escape(message: str) -> str:
    # GitHub workflow-command data escaping: `%` first, so the CR/LF escapes are not re-escaped.
    return message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def main(argv: list[str]) -> int:
    require = None
    if argv[:1] == ["--require"] and len(argv) == 2:
        require = argv[1]
    elif argv:
        print("::error title=verify matrix::usage: verify_matrix.py [--require p1,p2] < index.json",
              file=sys.stderr)
        return 1
    try:
        rows = matrix(json.loads(sys.stdin.read()), require)
    except (MatrixError, json.JSONDecodeError) as e:
        # stderr, because stdout is appended to $GITHUB_OUTPUT: a refusal must write no matrix line.
        print(f"::error title=verify matrix::{_escape(str(e))}", file=sys.stderr)
        return 1
    print("matrix=" + json.dumps(rows, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
