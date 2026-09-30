"""Shared helpers for the sandbox image's own suite.

This tree is published as its own repository (ADR-P048), with its own pytest rootdir, so the
framework's ``tests/conftest.py`` never reaches it. Helpers the sandbox tests need live here.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_SANDBOX_ROOT = Path(__file__).resolve().parents[1]


def load_script_module(name: str, rel: str):
    """Import a bare, unpackaged ``*.py`` script (``scripts/x.py``) as a module for testing.

    A port of the framework's ``tests/conftest.py`` helper of the same name. That helper exists
    because hand-rolled copies of this loader drifted and two of them silently dropped the
    ``sys.modules`` registration.

    Registration MUST precede ``exec_module``: ``@dataclass`` resolves its own module through
    ``sys.modules[cls.__module__]`` during class creation, so an unregistered path-loaded module
    raises there. ``rel`` is sandbox-root-relative and may not escape it.
    """
    target = (_SANDBOX_ROOT / rel).resolve()
    target.relative_to(_SANDBOX_ROOT)  # raises ValueError if `rel` escapes the sandbox tree
    spec = importlib.util.spec_from_file_location(name, target)
    assert spec is not None and spec.loader is not None, f"cannot load {rel}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module
