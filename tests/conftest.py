"""Shared helpers for the sandbox image's own suite.

This tree is published as its own repository (ADR-P048), with its own pytest rootdir, so the
framework's ``tests/conftest.py`` never reaches it. Helpers the sandbox tests need live here.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import sys
from pathlib import Path

_SANDBOX_ROOT = Path(__file__).resolve().parents[1]

LOADER_CORPUS_DIR = Path(__file__).resolve().parent / "fixtures" / "loader_corpus"


def load_loader_corpus() -> dict:
    """``fixtures/loader_corpus/CASES.json`` — the ONE corpus every analyser/loader copy is run
    against (see that directory's README)."""
    return json.loads((LOADER_CORPUS_DIR / "CASES.json").read_text(encoding="utf-8"))


def corpus_source_bytes(spec: dict) -> bytes:
    """A corpus ``source`` spec's bytes: a ``*.src`` file read unchanged, or a synthesised
    ``segments`` source (see the corpus README for the format)."""
    if "file" in spec:
        target = (LOADER_CORPUS_DIR / spec["file"]).resolve()
        target.relative_to(LOADER_CORPUS_DIR)  # a case may not name a file outside the corpus
        return target.read_bytes()
    text = "".join(chunk * times for chunk, times in spec["segments"])
    return text.encode(spec.get("encoding", "utf-8"))


def stage_load_case(case: dict, tmp_path: Path) -> Path:
    """Materialise a corpus ``load`` case's entrypoint at an extension-less path, as the host
    bind-mounts it. Shared so every loader copy (the image's and the host mirror's) is run against
    the SAME staged file, not a per-suite re-implementation of the ``setup`` vocabulary."""
    target = tmp_path / "entrypoint"
    setup = case.get("setup")
    if setup == "missing":
        return target
    if setup == "directory":
        target.mkdir()
        return target
    source = corpus_source_bytes(case["source"])
    if setup == "symlink":
        real = tmp_path / "real_entrypoint"
        real.write_bytes(source)
        target.symlink_to(real)
        return target
    target.write_bytes(source)
    return target


def classifier_for(case: dict, target: Path, classify):
    """The ``classify`` keyword for a ``load`` case: ``classify`` itself, or — for the
    ``swap_after_classify`` setup — a wrapper that rewrites ``target`` after the loader has read it
    and before it returns ``classify``'s verdict."""
    if case.get("setup") != "swap_after_classify":
        return classify
    swap = corpus_source_bytes(case["swap_source"])

    def _classify_then_swap(source: bytes):
        target.write_bytes(swap)  # the file changes AFTER the loader has read it
        return classify(source)

    return _classify_then_swap


def _top_level_bindings(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names.update((alias.asname or alias.name).split(".")[0] for alias in node.names)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names.update(n.id for t in targets for n in ast.walk(t) if isinstance(n, ast.Name))
    return names


def assert_mirrorable(path: Path, stdlib: frozenset[str]) -> None:
    """The properties a byte-identical copy of an image module into the host package depends on:
    no relative import, stdlib-only imports, and only underscored top-level names (so the host's
    private mirror publishes nothing into ``SURFACE.json``)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    public = sorted(name for name in _top_level_bindings(tree) if not name.startswith("_"))
    assert not public, f"{path.name} binds non-underscored top-level names: {public}"
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert node.level == 0, f"{path.name} has a relative import"
            assert (node.module or "").split(".")[0] in stdlib, f"{path.name}: {node.module}"
        elif isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in stdlib, f"{path.name}: {alias.name}"


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
