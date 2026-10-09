"""``layout: package`` (issue #862): the shared package walker, the package import-closure analyser,
and the loader core's ``_load_package`` — plus the image entrypoint's layout dispatch.

The m365-shaped fixture is the motivating consumer: an entrypoint that does
``from . import cred_contract, wire`` inside a package with no ``__init__.py`` of its own, mounted as
``modules.m365_graph``.
"""
from __future__ import annotations

import importlib.resources
import os
import stat
import sys
import uuid
from pathlib import Path

import pytest
from conftest import assert_mirrorable

from vsify_sandbox import entrypoint, import_closure, module_loader, package_tree

_ENTRY = (
    "from . import cred_contract, wire\n"
    "\n"
    "def serve(payload: bytes) -> bytes:\n"
    "    return wire.frame(cred_contract.prefix() + payload)\n"
)
_WIRE = "def frame(data: bytes) -> bytes:\n    return b'[' + data + b']'\n"
_CRED = "import os\n\ndef prefix() -> bytes:\n    return b'ok:'\n"


@pytest.fixture
def isolated_import_state():
    """``_load_package`` mutates process-global import state; restore all of it."""
    saved_path = list(sys.path)
    saved_modules = set(sys.modules)
    saved_bytecode = sys.dont_write_bytecode
    try:
        yield
    finally:
        sys.path[:] = saved_path
        for name in set(sys.modules) - saved_modules:
            sys.modules.pop(name, None)
        sys.dont_write_bytecode = saved_bytecode


def _unique_top() -> str:
    return f"pkgtest_{uuid.uuid4().hex[:10]}"


def _write_tree(root: Path, files: dict[str, str | bytes]) -> Path:
    for relpath, content in files.items():
        target = root / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content if isinstance(content, bytes) else content.encode())
    return root


def _m365_package(tmp_path: Path) -> Path:
    return _write_tree(
        tmp_path / "m365_graph",
        {"entrypoint_src.py": _ENTRY, "wire.py": _WIRE, "cred_contract.py": _CRED},
    )


def _load(root: Path, ref: str, *, expected=None, extra_allowed=(), scratch=None):
    files = package_tree._walk_package(root)
    return module_loader._load_package(
        str(root),
        ref,
        walk=package_tree._walk_package,
        files_digest=package_tree._files_digest,
        classify_package=import_closure._classify_package,
        validate_ref=import_closure._validate_dotted_ref,
        expected_files_sha256=expected if expected is not None else package_tree._files_digest(files),
        extra_allowed=frozenset(extra_allowed),
        scratch_dir=str(scratch or root.parent),
    )


# --------------------------------------------------------------------------- the walker


def test_walker_maps_every_member_and_skips_root_exclusions_and_pycache(tmp_path):
    root = _write_tree(
        tmp_path / "pkg",
        {
            "entry.py": "x = 1\n",
            "manifest.json": "{}",
            "sig.bundle": "sig",
            "data/template.txt": "hello",
            "sub/manifest.json": "{}",  # nested: mapped like any other file
            "__pycache__/entry.cpython-312.pyc": b"\x00",
            "sub/__pycache__/x.pyc": b"\x00",
        },
    )
    files = package_tree._walk_package(root, exclude={"manifest.json", "sig.bundle"})
    assert list(files) == ["data/template.txt", "entry.py", "sub/manifest.json"]
    assert files["data/template.txt"] == b"hello"


def test_walker_digest_is_deterministic_and_moves_with_any_sibling(tmp_path):
    root = _m365_package(tmp_path)
    first = package_tree._files_digest(package_tree._walk_package(root))
    assert first == package_tree._files_digest(package_tree._walk_package(root))
    (root / "wire.py").write_text(_WIRE + "# tampered\n")
    assert package_tree._files_digest(package_tree._walk_package(root)) != first


@pytest.mark.parametrize("kind", ["file_symlink", "dir_symlink", "fifo", "hardlink"])
def test_walker_refuses_non_regular_members(tmp_path, kind):
    root = _m365_package(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("x = 1\n")
    if kind == "file_symlink":
        (root / "linked.py").symlink_to(outside / "secret.py")
    elif kind == "dir_symlink":
        (root / "linked").symlink_to(outside)
    elif kind == "fifo":
        os.mkfifo(root / "pipe")
    else:
        os.link(outside / "secret.py", root / "hard.py")
    with pytest.raises(package_tree._PackageRefused) as err:
        package_tree._walk_package(root)
    assert err.value.reason == "package_member_refused"


def test_walker_refuses_a_root_that_is_not_a_directory(tmp_path):
    target = tmp_path / "file.py"
    target.write_text("x = 1\n")
    with pytest.raises(package_tree._PackageRefused):
        package_tree._walk_package(target)
    (tmp_path / "link").symlink_to(_m365_package(tmp_path))
    with pytest.raises(package_tree._PackageRefused):
        package_tree._walk_package(tmp_path / "link")


@pytest.mark.parametrize("name", ["café.py", "bad\\name.py", "tab\tname.py"])
def test_walker_refuses_names_outside_the_grammar(tmp_path, name):
    root = _m365_package(tmp_path)
    try:
        (root / name).write_text("x = 1\n")
    except OSError:
        pytest.skip("this filesystem cannot hold the name")
    with pytest.raises(package_tree._PackageRefused) as err:
        package_tree._walk_package(root)
    assert err.value.reason == "package_member_refused"


def test_walker_refuses_case_colliding_names(tmp_path):
    root = _m365_package(tmp_path)
    (root / "Wire.py").write_text("x = 1\n")
    if len(list(root.iterdir())) == 3:
        pytest.skip("case-insensitive filesystem: the collision cannot be created")
    with pytest.raises(package_tree._PackageRefused) as err:
        package_tree._walk_package(root)
    assert err.value.reason == "package_member_refused"


@pytest.mark.parametrize(
    "constant, value, build",
    [
        ("_MAX_PACKAGE_FILES", 2, lambda r: None),
        ("_MAX_PACKAGE_FILE_BYTES", 10, lambda r: None),
        ("_MAX_PACKAGE_TOTAL_BYTES", 100, lambda r: None),
        ("_MAX_PACKAGE_DEPTH", 2, lambda r: _write_tree(r, {"a/b/c.py": "x = 1\n"})),
        ("_MAX_PACKAGE_DIRS", 1, lambda r: [(r / "a").mkdir(), (r / "b").mkdir()]),
    ],
)
def test_walker_caps_fail_closed(tmp_path, monkeypatch, constant, value, build):
    root = _m365_package(tmp_path)
    build(root)
    monkeypatch.setattr(package_tree, constant, value)
    with pytest.raises(package_tree._PackageRefused) as err:
        package_tree._walk_package(root)
    assert err.value.reason == "package_too_large"


def test_the_walker_per_file_cap_is_the_analyser_source_cap():
    # The mirror design keeps these modules from importing each other, so this is the only link
    # between the two copies. Drifted apart, a member the walker admits would be refused as
    # entrypoint_unparseable by the analyser (or the reverse), and nothing else would fail.
    assert package_tree._MAX_PACKAGE_FILE_BYTES == import_closure._MAX_SOURCE_BYTES


def test_walker_open_handles_are_bounded_by_depth_not_width(tmp_path, monkeypatch):
    # A wide tree must never need more open directory handles than its depth: the verdict cannot
    # depend on a file-descriptor limit that differs between the host and the image.
    root = _m365_package(tmp_path)
    for index in range(40):
        _write_tree(root, {f"d{index:02}/inner/x.py": "x = 1\n"})
    live: set = set()
    peak = [0]
    real_open_dir, real_close_dir = package_tree._open_dir, package_tree._close_dir

    def counting_open(path, dir_fd, st):
        handle = real_open_dir(path, dir_fd, st)
        live.add(handle)
        peak[0] = max(peak[0], len(live))
        return handle

    def counting_close(handle):
        live.discard(handle)
        real_close_dir(handle)

    monkeypatch.setattr(package_tree, "_open_dir", counting_open)
    monkeypatch.setattr(package_tree, "_close_dir", counting_close)
    files = package_tree._walk_package(root)
    assert len(files) == 43
    assert peak[0] == 3  # root, d<nn>, inner
    assert not live


@pytest.mark.parametrize("names, expected", [
    (["Util", "util"], "package_member_refused"),  # two directories, no shared file name inside
    (["Util", "other"], "ok"),
])
def test_walker_case_fold_check_covers_directories(tmp_path, monkeypatch, names, expected):
    # Synthetic listing again: `Util/` and `util/` cannot coexist on this machine's filesystem
    # when it is case-insensitive, which is exactly the platform the check protects.
    root = _write_tree(tmp_path / "pkg", {"real/x.py": "x = 1\n"})
    dir_st = os.lstat(root / "real")
    monkeypatch.setattr(package_tree, "_open_dir", lambda path, dir_fd, st: f"handle:{path}")
    monkeypatch.setattr(package_tree, "_close_dir", lambda handle: None)
    monkeypatch.setattr(package_tree, "_list_names",
                        lambda handle: list(names) if handle == f"handle:{root}" else [])
    monkeypatch.setattr(package_tree, "_lstat_member", lambda handle, name: dir_st)
    assert _verdict(root) == expected


def _verdict(root: Path, exclude=frozenset()) -> str:
    try:
        package_tree._walk_package(root, exclude=exclude)
    except package_tree._PackageRefused as err:
        return err.reason
    return "ok"


@pytest.mark.parametrize("constant", ["_MAX_PACKAGE_FILES", "_MAX_PACKAGE_TOTAL_BYTES"])
def test_host_and_image_walks_agree_at_the_cap_edge(tmp_path, monkeypatch, constant):
    # The host walks with the manifest and signature excluded; the image walks the same mount with
    # no exclusions. Excluded files still count, so the host accepts exactly what the image accepts.
    root = _m365_package(tmp_path)
    _write_tree(root, {"manifest.json": "{" + " " * 40 + "}", "sig.bundle": "s" * 40})
    exclude = {"manifest.json", "sig.bundle"}
    members = [path for path in root.rglob("*") if path.is_file()]
    edge = len(members) if constant == "_MAX_PACKAGE_FILES" else sum(p.stat().st_size for p in members)
    for cap, expected in ((edge - 1, "package_too_large"), (edge, "ok")):
        monkeypatch.setattr(package_tree, constant, cap)
        assert _verdict(root) == expected  # the image
        assert _verdict(root, exclude) == expected  # the host


def test_member_read_refuses_a_file_that_is_not_the_lstat_ed_one(tmp_path):
    first = tmp_path / "first.py"
    second = tmp_path / "second.py"
    first.write_text("x = 1\n")
    second.write_text("x = 2\n")
    assert package_tree._read_member_once(str(first), os.lstat(first)) == b"x = 1\n"
    with pytest.raises(package_tree._PackageRefused) as err:
        package_tree._read_member_once(str(first), os.lstat(second))
    assert err.value.reason == "package_member_refused"


def _walk_modes():
    return [pytest.param(True, id="fd_walk", marks=pytest.mark.skipif(
        not package_tree._FD_WALK, reason="no dir_fd traversal on this platform")),
        pytest.param(False, id="path_walk")]


def _swap_for_symlink(directory: Path, target: Path) -> None:
    directory.rename(directory.with_name(directory.name + "_moved"))
    directory.symlink_to(target, target_is_directory=True)


@pytest.mark.parametrize("fd_walk", _walk_modes())
def test_walker_refuses_a_directory_swapped_for_a_symlink_before_it_is_opened(
    tmp_path, monkeypatch, fd_walk
):
    root = _write_tree(_m365_package(tmp_path), {"sub/inner.py": "x = 1\n"})
    outside = _write_tree(tmp_path / "outside", {"inner.py": "SECRET = 1\n"})
    monkeypatch.setattr(package_tree, "_FD_WALK", fd_walk)
    real_open_dir = package_tree._open_dir

    def swap_then_open(path, dir_fd, st):
        if os.path.basename(path) == "sub":
            _swap_for_symlink(root / "sub", outside)
        return real_open_dir(path, dir_fd, st)

    monkeypatch.setattr(package_tree, "_open_dir", swap_then_open)
    assert _verdict(root) == "package_member_refused"


@pytest.mark.skipif(not package_tree._FD_WALK, reason="no dir_fd traversal on this platform")
def test_walker_reads_the_held_directory_when_it_is_swapped_after_opening(tmp_path, monkeypatch):
    # Every child is resolved relative to the directory's open fd, so renaming the directory and
    # planting a symlink in its place cannot redirect the walk outside the tree.
    root = _write_tree(_m365_package(tmp_path), {"sub/inner.py": "x = 1\n"})
    outside = _write_tree(tmp_path / "outside", {"inner.py": "SECRET = 1\n"})
    real_open_dir = package_tree._open_dir

    def open_then_swap(path, dir_fd, st):
        handle = real_open_dir(path, dir_fd, st)
        if os.path.basename(path) == "sub":
            _swap_for_symlink(root / "sub", outside)
        return handle

    monkeypatch.setattr(package_tree, "_open_dir", open_then_swap)
    files = package_tree._walk_package(root)
    assert files["sub/inner.py"] == b"x = 1\n"
    assert b"SECRET" not in b"".join(files.values())


@pytest.mark.parametrize("names, expected", [
    (["Mod.py", "mod.py"], "package_member_refused"),
    (["Mod.py", "other.py"], "ok"),
])
def test_walker_case_fold_check_runs_on_any_filesystem(tmp_path, monkeypatch, names, expected):
    # Fed a synthetic listing, so the check runs on a case-insensitive filesystem as well.
    root = _write_tree(tmp_path / "pkg", {"real.py": "x = 1\n"})
    real_st = os.lstat(root / "real.py")
    monkeypatch.setattr(package_tree, "_list_names", lambda handle: list(names))
    monkeypatch.setattr(package_tree, "_lstat_member", lambda handle, name: real_st)
    monkeypatch.setattr(package_tree, "_read_member_once", lambda *args: b"x = 1\n")
    assert _verdict(root) == expected


# --------------------------------------------------------------------------- the package analyser


def _classify(files: dict[str, str | bytes], package=("modules", "m365_graph"), allowed=()):
    encoded = {k: v if isinstance(v, bytes) else v.encode() for k, v in files.items()}
    return import_closure._classify_package(encoded, package, extra_allowed=frozenset(allowed))


@pytest.mark.parametrize(
    "files, expect",
    [
        ({"entry.py": "from . import wire\nfrom .wire import frame\n", "wire.py": ""}, None),
        ({"entry.py": "import modules.m365_graph.wire\n", "wire.py": ""}, None),
        ({"entry.py": "import modules\nimport os, json\n"}, None),
        ({"sub/x.py": "from .. import wire\nfrom ..wire import frame\n", "wire.py": ""}, None),
        ({"entry.py": "from .. import other\n"}, "entrypoint_relative_escape"),
        ({"sub/x.py": "from ... import other\n"}, "entrypoint_relative_escape"),
        ({"entry.py": "import modules.other\n"}, "entrypoint_relative_escape"),
        ({"entry.py": "from modules import other\n"}, "entrypoint_relative_escape"),
        ({"entry.py": "from modules import *\n"}, "entrypoint_relative_escape"),
        ({"entry.py": "from modules import m365_graph\n"}, None),
        ({"entry.py": "from modules.m365_graph import wire\n", "wire.py": ""}, None),
        ({"entry.py": "import requests\n"}, "entrypoint_nonstdlib_import"),
        ({"entry.py": "def f(:\n"}, "entrypoint_unparseable"),
        ({"a.py": "def f(:\n", "b.py": "import requests\n"}, "entrypoint_nonstdlib_import"),
        ({"a.py": "def f(:\n", "z.py": "from .. import x\n"}, "entrypoint_relative_escape"),
        ({"entry.py": "try:\n    import requests\nexcept ImportError:\n    pass\n"}, None),
        ({"data.txt": "from .. import nothing — not python, never classified"}, None),
        # Importable but unanalysable members: the closure verdict would not cover them.
        ({"entry.py": "", "entry.cpython-312-x86_64-linux-gnu.so": b"\x7fELF"}, "package_member_refused"),
        ({"entry.py": "", "helper.abi3.so": b"\x7fELF"}, "package_member_refused"),
        ({"entry.py": "", "helper.pyd": b"MZ"}, "package_member_refused"),
        ({"entry.py": "", "helper.pyc": b"\x00"}, "package_member_refused"),
        ({"entry.py": "", "sub/helper.PYO": b"\x00"}, "package_member_refused"),
        ({"entry.py": "from .. import x\n", "helper.pyc": b"\x00"}, "package_member_refused"),
        ({"entry.py": "", "notes.so.txt": "a data file, not an extension"}, None),
    ],
)
def test_classify_package(files, expect):
    assert _classify(files) == expect


def test_classify_package_admits_declared_imports_only():
    assert _classify({"e.py": "import sqlalchemy\n"}, allowed=("sqlalchemy",)) is None
    assert _classify({"e.py": "import sqlalchemy\n"}) == "entrypoint_nonstdlib_import"


def test_classify_package_never_raises_on_garbage():
    assert import_closure._classify_package(None, ("p",)) == "entrypoint_unparseable"
    assert import_closure._classify_package({"a.py": b"x = 1\n"}, ()) == "entrypoint_unparseable"
    oversize = b"#" * (import_closure._MAX_SOURCE_BYTES + 1)
    assert import_closure._classify_package({"a.py": oversize}, ("p",)) == "entrypoint_unparseable"


def test_classify_imports_is_unchanged_by_the_package_rule():
    assert import_closure._classify_imports(b"from . import wire\n") == "entrypoint_relative_import"


@pytest.mark.parametrize(
    "names, ok",
    [
        (["sqlalchemy", "vsify_enterprise_mcp"], True),
        ([], True),
        (["os"], False),
        (["vsify_sandbox"], False),
        (["modules"], False),
        (["dup", "dup"], False),
        (["not-an-identifier"], False),
        (["café"], False),
        ([f"n{i}" for i in range(33)], False),
        ("sqlalchemy", False),
    ],
)
def test_validate_import_names(names, ok):
    if ok:
        assert import_closure._validate_import_names(names, "modules") == tuple(names)
    else:
        with pytest.raises(ValueError, match="declared_import_malformed"):
            import_closure._validate_import_names(names, "modules")


# --------------------------------------------------------------------------- the loader


def test_m365_shaped_package_loads_and_serves(tmp_path, isolated_import_state):
    top = _unique_top()
    root = _m365_package(tmp_path / top)
    serve = _load(root, f"{top}.m365_graph.entrypoint_src")
    assert serve(b"x") == b"[ok:x]"
    assert sys.dont_write_bytecode is True


def test_loader_refuses_a_digest_that_is_not_the_signed_one(tmp_path, isolated_import_state):
    top = _unique_top()
    root = _m365_package(tmp_path / top)
    signed = package_tree._files_digest(package_tree._walk_package(root))
    (root / "wire.py").write_text(_WIRE + "# swapped after approval\n")
    with pytest.raises(module_loader._LoadRefused) as err:
        _load(root, f"{top}.m365_graph.entrypoint_src", expected=signed)
    assert err.value.reason == "package_digest_mismatch"


@pytest.mark.parametrize("expected", ["", "short", "Z" * 64])
def test_loader_refuses_a_malformed_expected_digest(tmp_path, isolated_import_state, expected):
    top = _unique_top()
    root = _m365_package(tmp_path / top)
    with pytest.raises(module_loader._LoadRefused) as err:
        _load(root, f"{top}.m365_graph.entrypoint_src", expected=expected)
    assert err.value.reason == "package_digest_mismatch"


@pytest.mark.parametrize(
    "ref, reason",
    [
        ("entrypoint_src", "entrypoint_ref_malformed"),
        ("bad ref.x", "entrypoint_ref_malformed"),
        ("TOP.m365_graph.absent", "entrypoint_missing"),
    ],
)
def test_loader_ref_refusals(tmp_path, isolated_import_state, ref, reason):
    top = _unique_top()
    root = _m365_package(tmp_path / top)
    with pytest.raises(module_loader._LoadRefused) as err:
        _load(root, ref.replace("TOP", top))
    assert err.value.reason == reason


def test_loader_refuses_an_escaping_member(tmp_path, isolated_import_state):
    top = _unique_top()
    root = _m365_package(tmp_path / top)
    (root / "evil.py").write_text("from .. import neighbour\n")
    with pytest.raises(module_loader._LoadRefused) as err:
        _load(root, f"{top}.m365_graph.entrypoint_src")
    assert err.value.reason == "entrypoint_relative_escape"


@pytest.mark.parametrize("top", ["email", "ssl", "vsify_sandbox"])
def test_loader_refuses_a_package_named_like_stdlib_or_the_sandbox(tmp_path, isolated_import_state,
                                                                   top):
    """A package whose top-level name is stdlib or ``vsify_sandbox`` would shadow that module from
    ``sys.path[0]`` for the loader, egress shim and framing code. It is refused by the classifier,
    so before anything is extracted or put on ``sys.path``."""
    root = _m365_package(tmp_path / top)
    scratch_before = set(os.listdir(tmp_path / top))
    path_before = list(sys.path)
    with pytest.raises(module_loader._LoadRefused) as err:
        _load(root, f"{top}.m365_graph.entrypoint_src")
    assert err.value.reason == "package_name_reserved"
    assert sys.path == path_before
    assert set(os.listdir(tmp_path / top)) == scratch_before  # nothing extracted


def test_classify_package_reserved_name_outranks_member_verdicts():
    files = {"entry.py": b"from .. import x\n", "native.so": b"\x00"}
    assert import_closure._classify_package(files, ("ssl", "pkg")) == "package_name_reserved"
    assert import_closure._classify_package(files, ("vsify_sandbox",)) == "package_name_reserved"
    assert import_closure._classify_package({"entry.py": b"x = 1\n"}, ("sslx", "pkg")) is None


@pytest.mark.parametrize("member", ["wire.pyc", "wire.cpython-312-x86_64-linux-gnu.so"])
def test_loader_refuses_a_sourceless_importable_member(tmp_path, isolated_import_state, member):
    # Without the refusal the path finder would load this in place of (or beside) analysed source.
    top = _unique_top()
    root = _m365_package(tmp_path / top)
    (root / member).write_bytes(b"\x00not analysable")
    with pytest.raises(module_loader._LoadRefused) as err:
        _load(root, f"{top}.m365_graph.entrypoint_src")
    assert err.value.reason == "package_member_refused"


def test_loader_maps_walker_refusals(tmp_path, isolated_import_state):
    top = _unique_top()
    root = _m365_package(tmp_path / top)
    os.mkfifo(root / "pipe")
    with pytest.raises(module_loader._LoadRefused) as err:
        module_loader._load_package(
            str(root), f"{top}.m365_graph.entrypoint_src",
            walk=package_tree._walk_package, files_digest=package_tree._files_digest,
            classify_package=import_closure._classify_package,
            validate_ref=import_closure._validate_dotted_ref,
            expected_files_sha256="0" * 64, extra_allowed=frozenset(), scratch_dir=str(tmp_path),
        )
    assert err.value.reason == "package_member_refused"


def test_unmapped_files_are_never_extracted_or_importable(tmp_path, isolated_import_state):
    top = _unique_top()
    root = _m365_package(tmp_path / top)
    (root / "__pycache__").mkdir()
    (root / "__pycache__" / "shadow.py").write_text("raise SystemExit('never')\n")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    serve = _load(root, f"{top}.m365_graph.entrypoint_src", scratch=scratch)
    assert serve(b"") == b"[ok:]"
    (extract_root,) = list(scratch.iterdir())
    extracted = sorted(p.relative_to(extract_root).as_posix() for p in extract_root.rglob("*") if p.is_file())
    assert extracted == [
        f"{top}/m365_graph/cred_contract.py",
        f"{top}/m365_graph/entrypoint_src.py",
        f"{top}/m365_graph/wire.py",
    ]
    assert str(root) not in sys.path


def test_extraction_is_sealed_read_only(tmp_path, isolated_import_state):
    top = _unique_top()
    root = _m365_package(tmp_path / top)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    _load(root, f"{top}.m365_graph.entrypoint_src", scratch=scratch)
    (extract_root,) = list(scratch.iterdir())
    for path in [extract_root, *extract_root.rglob("*")]:
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == (0o500 if path.is_dir() else 0o400), path


def test_package_resources_are_read_from_the_verified_bytes(tmp_path, isolated_import_state):
    top = _unique_top()
    root = _write_tree(
        tmp_path / top / "m365_graph",
        {
            "__init__.py": "",
            "entrypoint_src.py": (
                "import importlib.resources\n"
                "def serve(payload: bytes) -> bytes:\n"
                "    return importlib.resources.files(__package__).joinpath('t.txt').read_bytes()\n"
            ),
            "t.txt": "template",
        },
    )
    serve = _load(root, f"{top}.m365_graph.entrypoint_src")
    assert serve(b"") == b"template"
    assert importlib.resources is not None


def test_import_failure_is_categorical(tmp_path, isolated_import_state):
    top = _unique_top()
    root = _write_tree(tmp_path / top / "pkg", {"entry.py": "raise RuntimeError('boom')\n"})
    with pytest.raises(module_loader._LoadRefused) as err:
        _load(root, f"{top}.pkg.entry")
    assert err.value.reason == "entrypoint_import_failed:RuntimeError"


def test_missing_serve_is_refused(tmp_path, isolated_import_state):
    top = _unique_top()
    root = _write_tree(tmp_path / top / "pkg", {"entry.py": "x = 1\n"})
    with pytest.raises(module_loader._LoadRefused) as err:
        _load(root, f"{top}.pkg.entry")
    assert err.value.reason == "serve_callable_missing"


# --------------------------------------------------------------------------- the image entrypoint


@pytest.mark.parametrize(
    "env, reason",
    [
        ({"VSIFY_SANDBOX_ENTRYPOINT_LAYOUT": "zip"}, "unsupported_entrypoint_layout"),
        (
            {"VSIFY_SANDBOX_ENTRYPOINT_LAYOUT": "package", "VSIFY_SANDBOX_ENTRYPOINT_KIND": "script"},
            "unsupported_entrypoint_layout",
        ),
        (
            {"VSIFY_SANDBOX_ENTRYPOINT_LAYOUT": "package", "VSIFY_SANDBOX_ENTRYPOINT_MODULE": "solo"},
            "entrypoint_ref_malformed",
        ),
        (
            {"VSIFY_SANDBOX_ENTRYPOINT_LAYOUT": "package", "VSIFY_SANDBOX_ALLOWED_IMPORTS": "os"},
            "declared_import_malformed",
        ),
        (
            {
                "VSIFY_SANDBOX_ENTRYPOINT_LAYOUT": "package",
                "VSIFY_SANDBOX_ALLOWED_IMPORTS": "definitely_not_installed_xyz",
            },
            "declared_import_unavailable",
        ),
    ],
)
def test_entrypoint_package_dispatch_refusals(monkeypatch, env, reason):
    monkeypatch.setenv("VSIFY_SANDBOX_ENTRYPOINT_KIND", "python_module")
    monkeypatch.setenv("VSIFY_SANDBOX_ENTRYPOINT_MODULE", "modules.m365_graph.entrypoint_src")
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(entrypoint.SetupError) as err:
        entrypoint._load_serve_callable()
    assert str(err.value) == reason


def test_entrypoint_package_dispatch_loads_from_the_mount(monkeypatch, tmp_path, isolated_import_state):
    top = _unique_top()
    root = _m365_package(tmp_path / "mount" / top)
    digest = package_tree._files_digest(package_tree._walk_package(root))
    monkeypatch.setattr(entrypoint, "PACKAGE_MOUNT_ROOT", str(tmp_path / "mount"))
    monkeypatch.setattr(entrypoint, "PACKAGE_SCRATCH_DIR", str(tmp_path))
    monkeypatch.setenv("VSIFY_SANDBOX_ENTRYPOINT_KIND", "python_module")
    monkeypatch.setenv("VSIFY_SANDBOX_ENTRYPOINT_MODULE", f"{top}.m365_graph.entrypoint_src")
    monkeypatch.setenv("VSIFY_SANDBOX_ENTRYPOINT_LAYOUT", "package")
    monkeypatch.setenv("VSIFY_SANDBOX_PACKAGE_FILES_SHA256", digest)
    monkeypatch.delenv("VSIFY_SANDBOX_ALLOWED_IMPORTS", raising=False)
    serve = entrypoint._load_serve_callable()
    assert serve(b"y") == b"[ok:y]"


def test_package_tree_stays_mirrorable():
    assert_mirrorable(Path(package_tree.__file__).resolve(), import_closure._STDLIB)
