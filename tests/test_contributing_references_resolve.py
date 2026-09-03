"""CONTRIBUTING.md names real files — ADR-G015 §5 applied to REFERENTS, not to prose.

§5's rule is that necessary duplication drifts and must be pinned by a test. The checklists in
CONTRIBUTING.md duplicate exactly one thing a test can hold: the IDENTIFIERS they name — file
paths, module paths, workflow paths. This module asserts every locally-resolvable one exists, and
that the cross-repo marker convention those checklists depend on is still in use.

Deliberate ceiling, stated so this is not mistaken for more than it is: this proves the checklists
REFER to things that exist. It cannot prove the steps are correct, complete, or workably ordered.
Referential integrity is the ceiling; process correctness is not testable here — which is exactly
why issue #353 asked for a written checklist rather than automation.
"""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_DOC = _ROOT / "CONTRIBUTING.md"

_FENCE = re.compile(r"```.*?```", re.DOTALL)
_CODE_SPAN = re.compile(r"`([^`\n]+)`")
_PATHISH = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_./-]*\.(py|json|ya?ml|md|toml)$")
_BARE_FILES = {"Dockerfile", ".trivyignore"}

# A referent in the other repo is MARKED, so "lives elsewhere" is distinguishable from "exists
# nowhere" — and so a future cross-repo parity check has a syntax to read without this document
# being rewritten.
_CROSS_REPO_PREFIX = "vsify-enterprise-mcp:"

_STEP_ID = re.compile(r"^- \[ \] \*\*`([A-Z]\d+)`", re.MULTILINE)


def _spans() -> list[str]:
    """Every inline code span outside a fenced block."""
    return _CODE_SPAN.findall(_FENCE.sub("", _DOC.read_text(encoding="utf-8")))


def test_contributing_md_is_the_documented_home_of_the_checklists():
    assert _DOC.is_file(), "CONTRIBUTING.md is where issue #353's checklists live"


def test_every_local_path_reference_resolves():
    missing = [
        span
        for span in _spans()
        if not span.startswith(_CROSS_REPO_PREFIX)
        and (_PATHISH.match(span) or span in _BARE_FILES)
        and not (_ROOT / span).exists()
    ]
    assert not missing, (
        f"CONTRIBUTING.md names paths absent from this repo: {sorted(set(missing))}. "
        f"If one lives in the host repo, prefix it '{_CROSS_REPO_PREFIX}'."
    )


def test_cross_repo_references_are_marked_and_well_formed():
    # A span that is EXACTLY the prefix is the document naming its own convention (the Notation
    # section has to be able to say it), not a referent. Anything longer is a referent.
    refs = [
        s for s in _spans() if s.startswith(_CROSS_REPO_PREFIX) and s != _CROSS_REPO_PREFIX
    ]
    assert refs, "the cross-repo marker convention is load-bearing; it must stay in use"
    for ref in refs:
        rel = ref[len(_CROSS_REPO_PREFIX) :]
        assert not rel.startswith("/"), f"cross-repo ref must be repo-relative: {ref!r}"


def test_checklist_step_ids_are_unique():
    ids = _STEP_ID.findall(_DOC.read_text(encoding="utf-8"))
    assert ids, "step ids are the mechanisation seam — they must not disappear"
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    assert not duplicates, f"duplicate checklist step id(s): {duplicates}"
