"""``vsify_sandbox.module_loader`` — the entrypoint loader core (ADR-P041), run against the shared
loader corpus, plus the image entrypoint's delegation to it.

The load table covers the refusal order and every reason token; the tests below it pin what the table
cannot: the loader executes the bytes it classified (TOCTOU), a faulting analyser fails closed, the
module's compiler flags never inherit the loader's, and the file stays mirrorable.
"""
from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest
from conftest import (
    assert_mirrorable,
    classifier_for,
    corpus_source_bytes,
    load_loader_corpus,
    stage_load_case,
)

from vsify_sandbox import entrypoint, import_closure, module_loader

_CORPUS = load_loader_corpus()
_LOADER_FILE = Path(module_loader.__file__).resolve()
_stage = stage_load_case
_CAP = import_closure._MAX_SOURCE_BYTES


def _classifier_for(case: dict, target: Path):
    return classifier_for(case, target, import_closure._classify_imports)


@pytest.mark.parametrize("case", _CORPUS["load"], ids=lambda case: case["id"])
def test_corpus_load(case, tmp_path):
    target = _stage(case, tmp_path)
    load = lambda: module_loader._load_entrypoint(  # noqa: E731
        str(target),
        case["kind"],
        case["module_ref"],
        classify=_classifier_for(case, target),
        validate_ref=import_closure._validate_dotted_ref, max_source_bytes=_CAP,
    )
    if case["expect"] != "ok":
        with pytest.raises(module_loader._LoadRefused) as ei:
            load()
        assert ei.value.reason == case["expect"] == str(ei.value)
        return
    serve = load()
    io = case["serve_io"]
    assert serve(bytes.fromhex(io["in_hex"])) == bytes.fromhex(io["out_hex"])


def test_the_swap_case_really_swapped_the_file(tmp_path):
    """Guard for the TOCTOU case above: had the loader re-read the path, it would have run this."""
    case = next(c for c in _CORPUS["load"] if c.get("setup") == "swap_after_classify")
    target = _stage(case, tmp_path)
    module_loader._load_entrypoint(
        str(target), case["kind"], case["module_ref"],
        classify=_classifier_for(case, target), validate_ref=import_closure._validate_dotted_ref,
        max_source_bytes=_CAP,
    )
    assert target.read_bytes() == corpus_source_bytes(case["swap_source"])


def test_a_faulting_analyser_fails_closed(tmp_path):
    target = tmp_path / "entrypoint"
    target.write_bytes(b"def serve(payload):\n    return payload\n")

    def _boom(source):
        raise RuntimeError("analyser fault")

    with pytest.raises(module_loader._LoadRefused) as ei:
        module_loader._load_entrypoint(
            str(target), "python_module", "entrypoint",
            classify=_boom, validate_ref=import_closure._validate_dotted_ref, max_source_bytes=_CAP,
        )
    assert ei.value.reason == "entrypoint_unparseable"


def test_the_script_kind_never_calls_the_analyser(tmp_path):
    target = tmp_path / "entrypoint"
    target.write_bytes(b"def serve(payload):\n    return payload\n")

    def _must_not_run(source):
        raise AssertionError("script kind was classified")

    serve = module_loader._load_entrypoint(
        str(target), "script", "", classify=_must_not_run,
        validate_ref=import_closure._validate_dotted_ref, max_source_bytes=_CAP,
    )
    assert serve(b"x") == b"x"


def test_module_code_does_not_inherit_the_loaders_compiler_flags(tmp_path):
    """Annotations are evaluated eagerly in the module, exactly as a standalone import would."""
    target = tmp_path / "entrypoint"
    target.write_bytes(b"def f(x: vsify_undefined_name): pass\ndef serve(p):\n    return p\n")
    with pytest.raises(module_loader._LoadRefused) as ei:
        module_loader._load_entrypoint(
            str(target), "python_module", "entrypoint",
            classify=import_closure._classify_imports,
            validate_ref=import_closure._validate_dotted_ref, max_source_bytes=_CAP,
        )
    assert ei.value.reason == "entrypoint_import_failed:NameError"


@pytest.mark.parametrize("kind, ref, expected_name", [
    ("python_module", "modules.acme.entrypoint", "modules_acme_entrypoint"),
    ("script", "ignored.for.script", "vsify_sandbox_entrypoint_module"),
])
def test_the_module_runs_under_its_ref_derived_name(tmp_path, kind, ref, expected_name):
    target = tmp_path / "entrypoint"
    target.write_bytes(b"def serve(p):\n    return __name__.encode() + b'|' + __file__.encode()\n")
    serve = module_loader._load_entrypoint(
        str(target), kind, ref,
        classify=import_closure._classify_imports, validate_ref=import_closure._validate_dotted_ref,
        max_source_bytes=_CAP,
    )
    assert serve(b"") == f"{expected_name}|{target}".encode()


def _load(target, kind="python_module", ref="modules.acme.entrypoint", **overrides):
    kwargs = {"classify": import_closure._classify_imports,
              "validate_ref": import_closure._validate_dotted_ref, "max_source_bytes": _CAP}
    kwargs.update(overrides)
    return module_loader._load_entrypoint(str(target), kind, ref, **kwargs)


@pytest.mark.parametrize("kind, expected_name", [
    ("python_module", "modules_acme_entrypoint"),
    ("script", "vsify_sandbox_entrypoint_module"),
])
def test_the_module_gets_the_dunders_an_import_gave_it(tmp_path, kind, expected_name):
    """Parity with the pre-#771 ``module_from_spec(SourceFileLoader(...))`` loader: ``__spec__``
    names the module and its origin, ``__file__`` is the path and ``__package__`` is ``''`` (not
    ``None``). ``__loader__`` alone is ``None`` — no loader may re-read the classified file."""
    target = tmp_path / "entrypoint"
    target.write_bytes(
        b"import json\n"
        b"def serve(p):\n"
        b"    return json.dumps([__name__, __file__, __package__, __spec__.name, __spec__.origin,\n"
        b"                       __spec__.parent, __loader__ is None]).encode()\n"
    )
    serve = _load(target, kind=kind)
    assert serve(b"") == (
        f'["{expected_name}", "{target}", "", "{expected_name}", "{target}", "", true]'.encode()
    )


def _in_thread_with_deadline(fn, deadline_s=5.0):
    """Run ``fn`` in a daemon thread; return ``("ok", value)`` / ``("raised", exc)``, or
    ``("hung", None)`` when it has not finished by the deadline — so a regression to a blocking
    open fails this test instead of hanging the suite."""
    result: list = []

    def _run():
        try:
            result.append(("ok", fn()))
        except BaseException as exc:  # noqa: BLE001 — the test inspects whatever happened
            result.append(("raised", exc))

    worker = threading.Thread(target=_run, daemon=True)
    worker.start()
    worker.join(deadline_s)
    return result[0] if result else ("hung", None)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs os.mkfifo")
def test_a_fifo_swapped_in_after_the_lstat_is_refused_promptly(tmp_path, monkeypatch):
    """The lstat -> open window: the path was a regular file at ``lstat`` time, and a FIFO by
    ``open``. A blocking ``O_RDONLY`` open of a FIFO waits for a writer forever; ``O_NONBLOCK``
    returns at once and the ``fstat`` refuses it."""
    regular = tmp_path / "regular"
    regular.write_bytes(b"def serve(p):\n    return p\n")
    fifo = tmp_path / "entrypoint"
    os.mkfifo(fifo)
    real_lstat = os.lstat
    monkeypatch.setattr(module_loader._os, "lstat",
                        lambda p, *a, **k: real_lstat(regular) if str(p) == str(fifo)
                        else real_lstat(p, *a, **k))
    try:
        outcome, value = _in_thread_with_deadline(lambda: _load(fifo))
    finally:
        # Release a reader a regression left blocked, so the daemon thread can finish.
        try:
            os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
        except OSError:
            pass
    assert outcome == "raised", f"the loader {outcome} on a FIFO instead of refusing it"
    assert isinstance(value, module_loader._LoadRefused)
    assert value.reason == "entrypoint_missing"


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="needs os.O_NOFOLLOW")
@pytest.mark.parametrize("kind", ["python_module", "script"])
def test_a_symlink_swapped_in_after_the_lstat_is_refused_not_followed(tmp_path, monkeypatch, kind):
    """The lstat -> open window for a symlink: the path was a regular file at ``lstat`` time and a
    symlink (to a perfectly loadable entrypoint) by ``open``. ``O_NOFOLLOW`` makes that open fail
    with ``ELOOP``, which is ``entrypoint_unloadable``; without it the link is followed and the
    target's ``serve`` comes back."""
    real = tmp_path / "real"
    real.write_bytes(b"def serve(p):\n    return p\n")
    link = tmp_path / "entrypoint"
    link.symlink_to(real)
    real_lstat = os.lstat
    monkeypatch.setattr(module_loader._os, "lstat",
                        lambda p, *a, **k: real_lstat(real) if str(p) == str(link)
                        else real_lstat(p, *a, **k))
    with pytest.raises(module_loader._LoadRefused) as ei:
        _load(link, kind=kind)
    assert ei.value.reason == "entrypoint_unloadable"
    # Control: the target itself loads, so the refusal is the symlink and nothing else.
    assert _load(real, kind=kind)(b"ok") == b"ok"


def test_an_oversize_python_module_is_refused_without_being_read_whole(tmp_path, monkeypatch):
    """The read is bounded to the analyser's cap + 1 byte, and the oversize verdict is the
    analyser's own (``entrypoint_unparseable``), reached before the analyser is even called."""
    target = tmp_path / "entrypoint"
    target.write_bytes(b"#" * (4 * 1024))
    read_sizes: list = []
    real_fdopen = os.fdopen

    class _Recording:
        def __init__(self, handle):
            self._handle = handle

        def __enter__(self):
            self._handle.__enter__()
            return self

        def __exit__(self, *exc):
            return self._handle.__exit__(*exc)

        def fileno(self):
            return self._handle.fileno()

        def read(self, size=-1):
            read_sizes.append(size)
            return self._handle.read(size)

    monkeypatch.setattr(module_loader._os, "fdopen", lambda *a, **k: _Recording(real_fdopen(*a, **k)))

    def _must_not_run(source):
        raise AssertionError("an oversize file reached the analyser")

    with pytest.raises(module_loader._LoadRefused) as ei:
        _load(target, classify=_must_not_run, max_source_bytes=1024)
    assert ei.value.reason == "entrypoint_unparseable"
    assert read_sizes == [1025]


def test_a_python_module_exactly_at_the_cap_still_loads(tmp_path):
    target = tmp_path / "entrypoint"
    body = b"def serve(p):\n    return p\n"
    target.write_bytes(body + b"#" * (256 - len(body)))
    assert _load(target, max_source_bytes=256)(b"x") == b"x"


def test_the_image_entrypoint_passes_the_analysers_cap(monkeypatch):
    seen: dict = {}
    monkeypatch.setenv("VSIFY_SANDBOX_ENTRYPOINT_KIND", "script")

    def _spy(*args, **kwargs):
        seen.update(kwargs)
        return lambda p: p

    monkeypatch.setattr(module_loader, "_load_entrypoint", _spy)
    entrypoint._load_serve_callable()
    assert seen["max_source_bytes"] == import_closure._MAX_SOURCE_BYTES


def test_module_loader_is_mirrorable():
    assert_mirrorable(_LOADER_FILE, import_closure._STDLIB)


def test_module_loader_passes_the_analyser():
    assert import_closure._classify_imports(_LOADER_FILE.read_bytes()) is None


# --------------------------------------------------------------------------- the image entrypoint


@pytest.fixture
def mounted(tmp_path, monkeypatch):
    target = tmp_path / "entrypoint"
    monkeypatch.setattr(entrypoint, "ENTRYPOINT_PATH", str(target))
    monkeypatch.setenv("VSIFY_SANDBOX_ENTRYPOINT_KIND", "python_module")
    monkeypatch.setenv("VSIFY_SANDBOX_ENTRYPOINT_MODULE", "modules.acme.entrypoint")
    return target


@pytest.mark.parametrize("case_id, reason", [
    ("nonstdlib_framework", "entrypoint_nonstdlib_import"),
    ("m365_relative_import", "entrypoint_relative_import"),
    ("syntax_error", "entrypoint_unparseable"),
])
def test_load_serve_callable_refuses_an_incompatible_python_module(mounted, case_id, reason):
    case = next(c for c in _CORPUS["classify"] if c["id"] == case_id)
    mounted.write_bytes(corpus_source_bytes(case["source"]))
    with pytest.raises(entrypoint.SetupError) as ei:
        entrypoint._load_serve_callable()
    assert str(ei.value) == reason


def test_load_serve_callable_launches_the_stdlib_bundle(mounted):
    mounted.write_bytes(corpus_source_bytes({"file": "m365_stdlib_bundle.src"}))
    assert entrypoint._load_serve_callable()(b"ok") == b"ok"


def test_load_serve_callable_refuses_a_symlinked_entrypoint(mounted, tmp_path):
    real = tmp_path / "elsewhere"
    real.write_bytes(b"def serve(p):\n    return p\n")
    os.symlink(real, mounted)
    with pytest.raises(entrypoint.SetupError) as ei:
        entrypoint._load_serve_callable()
    assert str(ei.value) == "entrypoint_symlink_refused"


def test_load_serve_callable_reads_the_path_at_call_time(mounted, tmp_path, monkeypatch):
    mounted.write_bytes(b"def serve(p):\n    return b'first'\n")
    assert entrypoint._load_serve_callable()(b"") == b"first"
    second = tmp_path / "second"
    second.write_bytes(b"def serve(p):\n    return b'second'\n")
    monkeypatch.setattr(entrypoint, "ENTRYPOINT_PATH", str(second))
    assert entrypoint._load_serve_callable()(b"") == b"second"


def test_the_egress_shim_still_starts_before_the_module_loads(monkeypatch):
    order: list[str] = []
    monkeypatch.setattr(entrypoint, "_start_egress_shim", lambda: order.append("shim"))

    def _load():
        order.append("load")
        raise entrypoint.SetupError("entrypoint_missing")

    monkeypatch.setattr(entrypoint, "_load_serve_callable", _load)
    assert entrypoint.main() == 1
    assert order == ["shim", "load"]
