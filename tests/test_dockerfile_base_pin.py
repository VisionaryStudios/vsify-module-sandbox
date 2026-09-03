"""The base image MUST stay digest-pinned (issue #352).

`ARG BASE_IMAGE=python:3.12-slim` + `FROM ${BASE_IMAGE}` made Dependabot a silent no-op
(dependabot-core#4597, #10190 — both closed NOT PLANNED), and a bare tag never yields a PR for a
republished-in-place patch. The fix was to write the base inline as `tag@sha256:<digest>`. Nothing
in CI asserts that shape stays true — a future revert to a floating tag (accidental or otherwise)
would pass `test` -> `build` -> `verify` -> `promote` undetected for up to a week, until
`base-image-watch`'s next scheduled run. This test closes that gap at PR time instead.
"""

from __future__ import annotations

import re
from pathlib import Path

_PATH = Path(__file__).resolve().parent.parent / "Dockerfile"
_FROM = re.compile(
    r"^FROM\s+(?P<tag>[A-Za-z0-9_.:\-/]+)@sha256:(?P<digest>[0-9a-f]{64})(?:\s+AS\s+(?P<stage>\S+))?\s*$",
    re.MULTILINE,
)


def _from_lines() -> list[str]:
    text = _PATH.read_text(encoding="utf-8")
    return [line for line in text.splitlines() if line.strip().startswith("FROM ")]


def test_the_dockerfile_exists():
    assert _PATH.is_file()


def test_exactly_one_from_line():
    # A future multi-stage build (CONTRIBUTING step B5) adds a `builder` stage ABOVE this one;
    # if that ever happens this assertion is the intentional signal to update it deliberately,
    # not a check meant to hold forever unconditionally.
    assert len(_from_lines()) == 1, (
        "expected exactly one FROM line in this single-stage image; "
        "if a builder stage was intentionally added, update this test to match"
    )


def test_the_base_image_is_digest_pinned_not_a_floating_tag():
    (line,) = _from_lines()
    match = _FROM.match(line.strip())
    assert match, (
        f"FROM line does not match '<image>@sha256:<64 hex chars>' — got: {line!r}. "
        f"A bare tag (e.g. `FROM python:3.12-slim`) is silently invisible to Dependabot's "
        f"docker ecosystem (dependabot-core#4597/#10190) and defeats issue #352's fix."
    )
    assert match.group("tag") == "python:3.12-slim", (
        f"base tag drifted from python:3.12-slim to {match.group('tag')!r} — the TAG must stay "
        f"alongside the digest (Dependabot compares tag strings; a bare digest is untracked)."
    )
    assert match.group("stage") == "runtime", "expected the `AS runtime` stage name to be preserved"
