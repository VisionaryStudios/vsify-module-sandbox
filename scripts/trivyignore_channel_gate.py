#!/usr/bin/env python3
"""The `.trivyignore` escape hatch is an rc-lane tool only (issue #628, ADR-P041 v1.8).

A prerelease build may ship with a dated, justified suppression while the base-digest bump waits on
upstream. A GA build may not: `verify` fails when any suppression is active, and the only remedy is
the bump itself. The channel comes from `mirror-guard`, which derives it from the tag.

Unknown channels fail closed. An empty one is what `needs.mirror-guard.outputs.channel` evaluates
to if `verify` stops listing `mirror-guard` in its `needs:`, because job outputs are not transitive.

Usage: python3 scripts/trivyignore_channel_gate.py <prerelease|ga> <path/to/.trivyignore>
"""
from __future__ import annotations

import sys
from pathlib import Path

CHANNELS = ("prerelease", "ga")
_REMEDY = (
    "GA ships with no suppressions. Bump the base digest in Dockerfile to one that carries the fix, "
    "delete the suppression lines, and cut the release again."
)


def active_lines(text: str) -> list[str]:
    """Every non-blank, non-comment line: the ones Trivy honours. The single definition of 'active'."""
    return [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]


def _escape(message: str) -> str:
    # GitHub workflow-command data escaping: `%` first, so the CR/LF escapes are not re-escaped.
    return message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("::error title=trivyignore channel gate::usage: trivyignore_channel_gate.py <channel> <path>")
        return 1
    channel, raw_path = argv
    if channel not in CHANNELS:
        print(
            f"::error title=trivyignore channel gate::channel {_escape(repr(channel))} is neither "
            f"{' nor '.join(CHANNELS)}; refusing rather than guessing a lane"
        )
        return 1
    path = Path(raw_path)
    if not path.is_file():
        print(f"::error title=trivyignore channel gate::{_escape(raw_path)} does not exist")
        return 1

    active = active_lines(path.read_text(encoding="utf-8"))
    if channel == "ga" and active:
        for line in active:
            print(
                f"::error title=GA refuses .trivyignore::{_escape(line)} is an active suppression. {_REMEDY}"
            )
        return 1
    if active:
        for line in active:
            print(f"::notice title=rc suppression::{_escape(line)} (prerelease lane only; GA refuses it)")
    else:
        print(f"::notice title=trivyignore channel gate::{channel}: no active suppressions")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
