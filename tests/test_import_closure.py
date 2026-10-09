"""``vsify_sandbox.import_closure`` — the static import-closure analyser and the pure dotted-ref
validator (ADR-P039, ADR-P041). Runs the image's copy against the shared loader corpus, plus the
properties the corpus cannot express: the frozen stdlib literal is in sync with the image's Python,
the analyser never imports or executes what it classifies, it never raises, and the file stays
mirrorable (stdlib-only, no relative imports, only underscored top-level names).
"""
from __future__ import annotations

import ast
import re
import sys
import warnings
from pathlib import Path

import pytest
from conftest import assert_mirrorable, corpus_source_bytes, load_loader_corpus

from vsify_sandbox import entrypoint_resolve, import_closure

_CORPUS = load_loader_corpus()
_PACKAGE_DIR = Path(import_closure.__file__).resolve().parent
_DOCKERFILE = _PACKAGE_DIR.parent / "Dockerfile"


@pytest.mark.parametrize("case", _CORPUS["classify"], ids=lambda case: case["id"])
def test_corpus_classify(case):
    assert import_closure._classify_imports(corpus_source_bytes(case["source"])) == case["expect"]


@pytest.mark.parametrize("case", _CORPUS["dotted_refs"], ids=lambda case: repr(case["ref"]))
def test_corpus_dotted_refs(case):
    if isinstance(case["expect"], list):
        assert import_closure._validate_dotted_ref(case["ref"]) == tuple(case["expect"])
    else:
        with pytest.raises(import_closure._EntrypointRefMalformed) as ei:
            import_closure._validate_dotted_ref(case["ref"])
        assert str(ei.value) == case["expect"]


def test_the_corpus_covers_all_three_analyser_verdicts_and_a_pass():
    verdicts = {case["expect"] for case in _CORPUS["classify"]}
    assert verdicts == {
        None,
        "entrypoint_relative_import",
        "entrypoint_nonstdlib_import",
        "entrypoint_unparseable",
    }


# --------------------------------------------------------------------------- the frozen stdlib literal


def test_stdlib_literal_python_matches_the_image_base():
    """``_STDLIB`` was generated on the Python the image runs. A base-image minor bump reddens this
    until the literal is regenerated on the new Python and ``_STDLIB_PYTHON`` follows it."""
    match = re.search(r"^FROM python:(\d+\.\d+)-slim", _DOCKERFILE.read_text(), re.MULTILINE)
    assert match, "sandbox/Dockerfile no longer has a `FROM python:<minor>-slim` line"
    assert import_closure._STDLIB_PYTHON == match.group(1)


@pytest.mark.skipif(
    f"{sys.version_info.major}.{sys.version_info.minor}" != import_closure._STDLIB_PYTHON,
    reason="the stdlib literal is compared on the image's own Python minor only (CI runs it)",
)
def test_stdlib_literal_is_in_sync_with_the_image_python():
    missing = sorted(set(sys.stdlib_module_names) - import_closure._STDLIB)
    extra = sorted(import_closure._STDLIB - set(sys.stdlib_module_names))
    assert not missing and not extra, (
        f"_STDLIB drifted from sys.stdlib_module_names (missing={missing}, extra={extra}); regenerate "
        "it per sandbox/CONTRIBUTING.md"
    )


# --------------------------------------------------------------------------- analyser properties


@pytest.mark.parametrize("source, expect", [
    (b"if not TYPE_CHECKING:\n    import vsify_corpus_absent_pkg\n", "entrypoint_nonstdlib_import"),
    (b"if TYPE_CHECKING or True:\n    import vsify_corpus_absent_pkg\n", "entrypoint_nonstdlib_import"),
    (b"if other.TYPE_CHECKING:\n    import vsify_corpus_absent_pkg\n", "entrypoint_nonstdlib_import"),
    (b"try:\n    import vsify_corpus_absent_pkg\nexcept:\n    pass\n", "entrypoint_nonstdlib_import"),
    (b"try:\n    pass\nexcept ImportError:\n    pass\nelse:\n    import vsify_corpus_absent_pkg\n",
     "entrypoint_nonstdlib_import"),
    (b"try:\n    pass\nexcept ImportError:\n    pass\nfinally:\n    import vsify_corpus_absent_pkg\n",
     "entrypoint_nonstdlib_import"),
    (b"try:\n    import vsify_corpus_absent_pkg\nexcept* ImportError:\n    pass\n", None),
    (b"import json, vsify_corpus_absent_pkg\n", "entrypoint_nonstdlib_import"),
    (b"import os.path as p\nfrom xml.etree import ElementTree\n", None),
    (b"class C:\n    import vsify_corpus_absent_pkg\n", "entrypoint_nonstdlib_import"),
    (b"f = lambda: __import__('vsify_corpus_absent_pkg')\n", None),
    (b"from . import x\n", "entrypoint_relative_import"),
    (b"from .x import y\n", "entrypoint_relative_import"),
])
def test_exemptions_are_exactly_the_documented_ones(source, expect):
    assert import_closure._classify_imports(source) == expect


@pytest.mark.parametrize("bad_input", ["import json\n", None, 42, memoryview(b"import json\n")])
def test_non_bytes_input_is_unparseable(bad_input):
    assert import_closure._classify_imports(bad_input) == "entrypoint_unparseable"


def test_bytearray_is_accepted():
    assert import_closure._classify_imports(bytearray(b"import json\n")) is None


def test_the_size_cap_is_exact():
    at_cap = b"#" * import_closure._MAX_SOURCE_BYTES
    assert import_closure._classify_imports(at_cap) is None
    assert import_closure._classify_imports(at_cap + b"\n") == "entrypoint_unparseable"


def test_an_analyser_fault_while_walking_is_unparseable_never_raised(monkeypatch):
    def _boom(node, exempt):
        raise RuntimeError("walker fault")

    monkeypatch.setattr(import_closure, "_children", _boom)
    assert import_closure._classify_imports(b"import json\n") == "entrypoint_unparseable"


def test_an_analyser_fault_while_parsing_is_unparseable_never_raised(monkeypatch):
    def _boom(*args, **kwargs):
        raise RecursionError("parser fault")

    monkeypatch.setattr(import_closure._astlib, "parse", _boom)
    assert import_closure._classify_imports(b"import json\n") == "entrypoint_unparseable"


# --------------------------------------------------------------------------- the grammar is the image's


def test_the_feature_version_is_derived_from_the_image_minor():
    assert import_closure._FEATURE_VERSION == tuple(
        int(part) for part in import_closure._STDLIB_PYTHON.split(".")
    )


@pytest.mark.parametrize("source", [
    b"type Alias = int\n",
    b"def f[T](x: T) -> T:\n    return x\n",
    b"class C[T]:\n    pass\n",
])
def test_syntax_newer_than_the_pinned_minor_is_unparseable(monkeypatch, source):
    """The REAL control on a 3.12 host: pin the grammar one minor lower and 3.12-only syntax is
    refused, though this interpreter parses it — the verdict follows ``_FEATURE_VERSION``, not the
    running Python. The same mechanism refuses 3.13/3.14-only syntax against the 3.12 pin (below)."""
    assert import_closure._classify_imports(source) is None  # the image's own grammar admits it
    monkeypatch.setattr(import_closure, "_FEATURE_VERSION", (3, 11))
    assert import_closure._classify_imports(source) == "entrypoint_unparseable"


@pytest.mark.skipif(sys.version_info < (3, 13), reason="needs a host whose parser accepts 3.13+ syntax")
@pytest.mark.parametrize("source, needs", [
    (b"def f[T=int](x: T) -> T:\n    return x\n", (3, 13)),  # PEP 696 type-parameter default
    (b"try:\n    pass\nexcept ValueError, TypeError:\n    pass\n", (3, 14)),  # PEP 758
])
def test_a_newer_host_does_not_admit_syntax_the_image_refuses(source, needs):
    if sys.version_info < needs:
        pytest.skip(f"needs Python {needs[0]}.{needs[1]}+ to parse the construct at all")
    assert import_closure._classify_imports(source) == "entrypoint_unparseable"


@pytest.mark.parametrize("source", [
    b"import re\nPATTERN = re.compile('\\d+')\n",  # SyntaxWarning: invalid escape sequence
    b"x = 0 if 1else 2\n",  # SyntaxWarning (3.12): invalid decimal literal
])
def test_under_warnings_as_errors_the_bare_analyser_fails_closed(source):
    """The analyser leaves warning filters alone (it is called from threaded host code, and
    ``catch_warnings`` is process-global), so in a host process run with warnings as errors a
    compile-time ``SyntaxWarning`` is a parse failure: the host refuses ``entrypoint_unparseable``
    where the image (default filters) admits the source. That is the documented fail-closed
    residual; the public test aid suppresses these warnings for its own call instead."""
    with warnings.catch_warnings(record=True) as shown:
        warnings.simplefilter("always")
        assert import_closure._classify_imports(source) is None  # the image's verdict
    assert any(issubclass(w.category, SyntaxWarning) for w in shown)  # it really warns
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert import_closure._classify_imports(source) == "entrypoint_unparseable"


def test_the_analyser_never_touches_the_process_warning_filters(monkeypatch):
    """``catch_warnings`` swaps ``warnings.filters`` for a copy and puts the original back, so
    the list is checked DURING the parse as well as after it."""
    before = warnings.filters
    snapshot = list(before)
    during = []
    real_parse = ast.parse

    def spy(*args, **kwargs):
        during.append((warnings.filters is before, list(warnings.filters) == snapshot))
        return real_parse(*args, **kwargs)

    monkeypatch.setattr(import_closure._astlib, "parse", spy)
    assert import_closure._classify_imports(b"import json\n") is None
    assert during == [(True, True)], "the analyser replaced or edited the warning filters"
    assert warnings.filters is before and list(warnings.filters) == snapshot


def test_the_analyser_source_has_no_warnings_handling():
    """Belt to the runtime check above: the SoT neither imports ``warnings`` nor names a
    filter-mutating call, so no code path (including one the corpus does not reach) can."""
    tree = ast.parse((_PACKAGE_DIR / "import_closure.py").read_text())
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }
    assert "warnings" not in imported
    named = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)} | {
        node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
    }
    assert not named & {"catch_warnings", "simplefilter", "filterwarnings", "resetwarnings"}


def test_classification_never_executes_or_imports_the_source(tmp_path):
    marker = tmp_path / "executed"
    source = (
        f"open({str(marker)!r}, 'w').close()\n"
        "import vsify_corpus_never_imported\n"
        "raise SystemExit(7)\n"
    ).encode()
    assert import_closure._classify_imports(source) == "entrypoint_nonstdlib_import"
    assert not marker.exists()
    assert "vsify_corpus_never_imported" not in sys.modules


# --------------------------------------------------------------------------- the shim + mirrorability


def test_entrypoint_resolve_reexports_the_pure_validator():
    assert entrypoint_resolve.validate_dotted_ref is import_closure._validate_dotted_ref
    assert entrypoint_resolve.EntrypointRefMalformed is import_closure._EntrypointRefMalformed


def test_entrypoint_resolve_never_imports_the_exec_capable_loader():
    tree = ast.parse((_PACKAGE_DIR / "entrypoint_resolve.py").read_text())
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    } | {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
    assert "module_loader" not in imported
    assert imported <= {"__future__", "annotations", "import_closure", "_EntrypointRefMalformed",
                        "_validate_dotted_ref"}


def test_import_closure_is_mirrorable():
    assert_mirrorable(_PACKAGE_DIR / "import_closure.py", import_closure._STDLIB)


def test_import_closure_passes_its_own_analysis():
    assert import_closure._classify_imports((_PACKAGE_DIR / "import_closure.py").read_bytes()) is None
