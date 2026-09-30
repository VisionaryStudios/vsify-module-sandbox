"""The `.trivyignore` supply-chain escape hatch is BOUNDED (issue #354; 7 days since #628).

Trivy already stops honouring an `exp:`-dated line on its date. These tests exist because nothing
forces anyone to WRITE the date, to keep the window short, or to say why. An undated suppression
is a permanent, invisible hole in the ADR-P041 promote gate — and a hole nobody can see is worse
than an absent gate, because the green check still reads as coverage.

These are form checks over the file alone, so they cannot see the release channel and the
`_MAX_DAYS` cap is global. The channel rule -- a GA build refuses every active suppression -- is
`scripts/trivyignore_channel_gate.py`, run by `verify` (ADR-P041 v1.8).

Deliberate ceiling, stated so this is not over-trusted: these tests prove the FORM of a
suppression, never its justification. Whether a given CVE should have been suppressed at all is a
review question.
"""

from __future__ import annotations

import datetime as dt
import re
from pathlib import Path

from conftest import load_script_module

_ROOT = Path(__file__).resolve().parent.parent
_PATH = _ROOT / ".trivyignore"
_MAX_DAYS = 7
_ENTRY = re.compile(r"^(?P<id>[A-Za-z][A-Za-z0-9._-]*)\s+exp:(?P<exp>\d{4}-\d{2}-\d{2})\s*$")

# One definition of "active line", shared with the gate `verify` runs, so the form check and the
# GA refusal can never disagree about which lines Trivy honours.
_gate = load_script_module("trivyignore_channel_gate", "scripts/trivyignore_channel_gate.py")


def _lines() -> list[str]:
    return _PATH.read_text(encoding="utf-8").splitlines()


def _today() -> dt.date:
    # UTC explicitly. CI runners are UTC and laptops are not, and a local/UTC day-boundary
    # disagreement is a known flake class in this org's date-sensitive tests.
    return dt.datetime.now(dt.UTC).date()


def _expiry_violations(text: str, today: dt.date) -> list[str]:
    violations = []
    for line in _gate.active_lines(text):
        match = _ENTRY.match(line)
        if not match:
            violations.append(f"{line!r} — every entry needs `<ID> exp:YYYY-MM-DD`")
            continue
        expiry = dt.date.fromisoformat(match.group("exp"))
        if expiry <= today:
            violations.append(
                f"{match.group('id')} expired on {expiry}. Trivy has already stopped honouring it, "
                f"so `verify` is red regardless — bump the base digest and delete this line."
            )
        elif (expiry - today).days > _MAX_DAYS:
            violations.append(
                f"{match.group('id')} suppressed until {expiry} (> {_MAX_DAYS} days out). "
                f"A suppression is a delay, not a waiver."
            )
    return violations


def test_the_ignore_file_exists_so_the_scan_never_points_at_a_missing_path():
    assert _PATH.is_file(), "verify passes `trivyignores: .trivyignore`; the file must exist"


def test_every_suppression_is_time_boxed_and_within_the_ceiling():
    assert _expiry_violations(_PATH.read_text(encoding="utf-8"), _today()) == []


def test_the_ceiling_is_inclusive_and_one_day_past_it_fails():
    today = dt.date(2026, 9, 30)
    at_cap = f"CVE-2026-1 exp:{today + dt.timedelta(days=_MAX_DAYS)}"
    past_cap = f"CVE-2026-1 exp:{today + dt.timedelta(days=_MAX_DAYS + 1)}"
    assert _expiry_violations(at_cap, today) == []
    assert len(_expiry_violations(past_cap, today)) == 1
    assert len(_expiry_violations(f"CVE-2026-1 exp:{today}", today)) == 1, "expiring today is expired"
    assert len(_expiry_violations("CVE-2026-1", today)) == 1, "an undated line is refused"


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
