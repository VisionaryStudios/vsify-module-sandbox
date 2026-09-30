"""The GA channel refuses every active `.trivyignore` suppression (issue #628, ADR-P041 v1.8).

`test_trivyignore_policy.py` checks the FORM of a suppression and cannot see the release channel,
so its 7-day cap is global. The channel rule lives in `scripts/trivyignore_channel_gate.py`, which
`verify` runs with `needs.mirror-guard.outputs.channel`. These tests are the negative control for
that rule: without them, the GA refusal would first execute on a real GA tag in the mirror, the
one place a broken gate is most expensive to discover.

The workflow wiring (verify needs mirror-guard, the step runs before the Trivy gate) is asserted
where a YAML parser is available: `tests/test_publish_scaffold_mirror.py` in the framework.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "trivyignore_channel_gate.py"

_ACTIVE = (
    "# why: rc lane only; base bump tracked in #629\n"
    "CVE-2026-75804 exp:2026-10-07\n"
)
_COMMENTS_ONLY = "# header\n#\n# (No active suppressions.)\n\n"


def _run(tmp_path: Path, channel: str, text: str | None) -> subprocess.CompletedProcess[str]:
    path = tmp_path / ".trivyignore"
    if text is not None:
        path.write_text(text, encoding="utf-8")
    # Env inherited: a from-scratch env drops LD_LIBRARY_PATH, which setup-python's interpreter needs.
    return subprocess.run(
        [sys.executable, str(_SCRIPT), channel, str(path)], capture_output=True, text=True, check=False
    )


def test_ga_refuses_an_active_suppression_and_names_it(tmp_path):
    result = _run(tmp_path, "ga", _ACTIVE)
    assert result.returncode == 1
    assert "::error" in result.stdout
    assert "CVE-2026-75804 exp:2026-10-07" in result.stdout
    assert "base" in result.stdout, "the error must name the remedy (bump the base digest)"


def test_ga_passes_when_every_line_is_a_comment_or_blank(tmp_path):
    assert _run(tmp_path, "ga", _COMMENTS_ONLY).returncode == 0


def test_prerelease_passes_when_every_line_is_a_comment_or_blank(tmp_path):
    result = _run(tmp_path, "prerelease", _COMMENTS_ONLY)
    assert result.returncode == 0
    assert "no active suppressions" in result.stdout


def test_prerelease_allows_an_active_suppression(tmp_path):
    result = _run(tmp_path, "prerelease", _ACTIVE)
    assert result.returncode == 0
    assert "CVE-2026-75804" in result.stdout, "an rc bypass is announced, never silent"


def test_an_unknown_or_empty_channel_fails_closed(tmp_path):
    # An empty channel is what `needs.mirror-guard.outputs.channel` evaluates to if `verify` ever
    # stops listing mirror-guard in `needs:` -- job outputs are not transitive.
    for channel in ("", "GA", "release", "rc"):
        result = _run(tmp_path, channel, _COMMENTS_ONLY)
        assert result.returncode == 1, f"channel {channel!r} must not be treated as either lane"


def test_a_missing_ignore_file_fails_closed_on_both_channels(tmp_path):
    # A missing file is never read as "no suppressions": on prerelease that would pass a verify
    # whose scan then points `trivyignores:` at a path that is not there.
    for channel in ("ga", "prerelease"):
        assert _run(tmp_path, channel, None).returncode == 1, channel


def test_workflow_command_text_is_escaped(tmp_path):
    # GitHub parses `%`, CR and LF inside a workflow command's message; a raw one would truncate
    # or forge the annotation.
    result = _run(tmp_path, "ga", "# why: x\nCVE-1%0A::notice::forged exp:2026-10-07\n")
    assert result.returncode == 1
    assert "CVE-1%250A" in result.stdout
