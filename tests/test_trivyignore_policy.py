"""The `.trivyignore` supply-chain escape hatch is BOUNDED (issue #354).

Trivy already stops honouring an `exp:`-dated line on its date. These tests exist because nothing
forces anyone to WRITE the date, to keep the window short, or to say why. An undated suppression
is a permanent, invisible hole in the ADR-P041 promote gate — and a hole nobody can see is worse
than an absent gate, because the green check still reads as coverage.

Deliberate ceiling, stated so this is not over-trusted: these tests prove the FORM of a
suppression, never its justification. Whether a given CVE should have been suppressed at all is a
review question.
"""

from __future__ import annotations

import datetime as dt
import re
from pathlib import Path

_PATH = Path(__file__).resolve().parent.parent / ".trivyignore"
_MAX_DAYS = 30
_ENTRY = re.compile(r"^(?P<id>[A-Za-z][A-Za-z0-9._-]*)\s+exp:(?P<exp>\d{4}-\d{2}-\d{2})\s*$")


def _lines() -> list[str]:
    return _PATH.read_text(encoding="utf-8").splitlines()


def _today() -> dt.date:
    # UTC explicitly. CI runners are UTC and laptops are not, and a local/UTC day-boundary
    # disagreement is a known flake class in this org's date-sensitive tests.
    return dt.datetime.now(dt.UTC).date()


def test_the_ignore_file_exists_so_the_scan_never_points_at_a_missing_path():
    assert _PATH.is_file(), "verify passes `trivyignores: .trivyignore`; the file must exist"


def test_every_suppression_is_time_boxed_and_within_the_ceiling():
    today = _today()
    for lineno, raw in enumerate(_lines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _ENTRY.match(line)
        assert match, f"line {lineno}: {line!r} — every entry needs `<ID> exp:YYYY-MM-DD`"
        expiry = dt.date.fromisoformat(match.group("exp"))
        assert expiry > today, (
            f"line {lineno}: {match.group('id')} expired on {expiry}. Trivy has already stopped "
            f"honouring it, so `verify` is red regardless — bump the base digest and delete "
            f"this line."
        )
        assert (expiry - today).days <= _MAX_DAYS, (
            f"line {lineno}: {match.group('id')} suppressed until {expiry} "
            f"(> {_MAX_DAYS} days out). A suppression is a delay, not a waiver."
        )


def test_every_suppression_names_a_reason_directly_above_it():
    lines = _lines()
    for index, raw in enumerate(lines):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        previous = lines[index - 1].strip() if index else ""
        assert previous.lower().startswith("# why:"), (
            f"line {index + 1}: {line!r} needs a `# why:` comment naming a tracking issue "
            f"directly above it"
        )
