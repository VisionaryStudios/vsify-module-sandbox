"""
The sandbox entrypoint loader core (ADR-P041): turn the one bind-mounted entrypoint file into its
``serve(payload: bytes) -> bytes`` callable, or refuse with a categorical reason token.

The image's ``entrypoint.py`` delegates here, and this exact file is MIRRORED BYTE-IDENTICALLY into the
host package (``vsify_enterprise_mcp/_sandbox_mirror/``, sha256-pinned) so a consumer's test can load
an entrypoint with the image's real loader instead of a hand-copied replica. So it is stdlib-only, has
NO relative imports (the analyser and the ref validator are passed in as required keywords, which is
what lets the same bytes work in both homes), and binds only underscored top-level names.
``sandbox/`` is the source of truth (ADR-P048): edit here, then copy.

TOCTOU: the file is ``lstat``-checked (a symlinked entrypoint is refused), opened without following a
symlink and without blocking (a FIFO swapped in after the ``lstat`` is refused by the ``fstat``, never
waited on), read ONCE — bounded to the analyser's size cap for ``python_module`` — classified, and those
same bytes are compiled and executed. There is no ``SourceFileLoader`` re-read, so a file swapped after
classification never runs. The executed module still gets the dunders an import would give it
(``__spec__``, ``__file__``, ``__package__ == ''``); only ``__loader__`` is ``None``, because no loader
ever re-reads the file.

Every refusal is a :class:`_LoadRefused` carrying a fixed reason token — never an exception message,
path, or content digest. The reason strings the image emitted before this module existed are
preserved verbatim.

``_load_package`` is the ``layout: package`` sibling (issue #862): the package directory is mounted
instead of one file, every member is walked and read once by the shared ``package_tree`` walker, the
map's digest must equal the one the host signed, every member is classified, and only then are
exactly the mapped bytes extracted to a private scratch directory and imported normally. The
``layout: file`` path above is unchanged.
"""
import importlib as _importlib
import importlib.util as _importlib_util
import os as _os
import stat as _stat
import sys as _sys
import tempfile as _tempfile

_SUPPORTED_KINDS = frozenset({"script", "python_module"})

# The ``__name__`` an entrypoint runs under when no dotted ref names it (the ``script`` kind).
_DEFAULT_MODULE_NAME = "vsify_sandbox_entrypoint_module"


class _LoadRefused(Exception):
    """A categorical load refusal. ``reason`` (also ``str(exc)``) is a fixed token."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _read_entrypoint_once(path: str, limit: int | None = None) -> bytes:
    """The entrypoint's bytes, read exactly once, from a regular file that is not a symlink.

    With ``limit``, at most ``limit + 1`` bytes are read — enough for the caller to see the file is
    over the cap without ever holding more of it than that. Without one (the ``script`` kind) the
    read is UNBOUNDED, an accepted residual (ADR-P041): the script is the operator's own file, it
    is never handed to the analyser, and in the image the read is held to the container's own
    memory budget."""
    try:
        st = _os.lstat(path)
    except OSError:
        raise _LoadRefused("entrypoint_missing") from None
    if _stat.S_ISLNK(st.st_mode):
        raise _LoadRefused("entrypoint_symlink_refused")
    if not _stat.S_ISREG(st.st_mode):
        raise _LoadRefused("entrypoint_missing")
    try:
        # O_NOFOLLOW closes the lstat -> open window for a symlink: one swapped in fails to open
        # (ELOOP) rather than being followed. O_NONBLOCK closes it for a FIFO: opening one for
        # reading would otherwise block until a writer appears — forever — before the fstat below
        # could refuse it. On the regular file that is the only thing ever read, O_NONBLOCK is a
        # no-op, so it is left set.
        flags = _os.O_RDONLY | getattr(_os, "O_NOFOLLOW", 0) | getattr(_os, "O_NONBLOCK", 0)
        fd = _os.open(path, flags)
        with _os.fdopen(fd, "rb") as handle:
            if not _stat.S_ISREG(_os.fstat(handle.fileno()).st_mode):
                raise _LoadRefused("entrypoint_missing")
            return handle.read() if limit is None else handle.read(limit + 1)
    except OSError:
        raise _LoadRefused("entrypoint_unloadable") from None


def _load_entrypoint(path, kind, module_ref, *, classify, validate_ref, max_source_bytes):
    """Load the entrypoint at ``path`` and return its ``serve`` callable, or raise :class:`_LoadRefused`.

    ``classify`` is the import-closure analyser (``import_closure._classify_imports``): a callable
    taking the source bytes and returning a reason token or ``None``. ``validate_ref`` is the dotted-ref
    validator (``import_closure._validate_dotted_ref``): it returns the segment tuple or raises a
    ``ValueError``. ``max_source_bytes`` is the analyser's own size cap
    (``import_closure._MAX_SOURCE_BYTES``): a ``python_module`` file is read only up to one byte past
    it, and one over it is refused ``entrypoint_unparseable`` (the analyser's verdict for it) without
    being read whole. All three are required keywords so this file never imports its sibling.

    Order, each a refusal: kind -> dotted ref (``python_module`` only) -> the file -> the import closure
    (``python_module`` only; the ``script`` kind is not checked) -> compile + execute -> ``serve``."""
    if kind not in _SUPPORTED_KINDS:
        raise _LoadRefused(f"unsupported_entrypoint_kind:{kind}")

    module_name = _DEFAULT_MODULE_NAME
    if kind == "python_module":
        try:
            segments = validate_ref(module_ref)
        except ValueError:
            raise _LoadRefused("entrypoint_ref_malformed") from None
        module_name = "_".join(segments) or module_name  # for __name__/log messages only

    filename = _os.fspath(path)
    if kind == "python_module":
        source = _read_entrypoint_once(filename, max_source_bytes)
        if len(source) > max_source_bytes:
            raise _LoadRefused("entrypoint_unparseable")
        try:
            reason = classify(source)
        except Exception:  # noqa: BLE001 — fail closed: a faulting analyser is a refusal, never a pass
            reason = "entrypoint_unparseable"
        if reason is not None:
            raise _LoadRefused(str(reason))
    else:
        source = _read_entrypoint_once(filename)

    # The dunders ``module_from_spec(SourceFileLoader(...))`` gave the module before this loader
    # existed — ``__spec__`` (origin = the file), ``__file__``, ``__package__ == ''`` — from a spec
    # with NO loader, so nothing can re-read the file behind the classified bytes.
    spec = _importlib_util.spec_from_loader(module_name, None, origin=filename)
    spec.has_location = True  # what makes ``module_from_spec`` set ``__file__`` from ``origin``
    module = _importlib_util.module_from_spec(spec)
    try:
        # dont_inherit: this file's own compiler flags must never leak into the module's code.
        code = compile(source, filename, "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except Exception as exc:  # noqa: BLE001 — any import-time failure is a setup refusal
        raise _LoadRefused(f"entrypoint_import_failed:{type(exc).__name__}") from exc

    serve = getattr(module, "serve", None)
    if not callable(serve):
        raise _LoadRefused("serve_callable_missing")
    return serve


_PACKAGE_DIGEST_MISMATCH = "package_digest_mismatch"


def _write_new_file(path: str, data: bytes) -> None:
    """Create ``path`` (it must not exist, and is never followed through a symlink) holding ``data``."""
    flags = _os.O_WRONLY | _os.O_CREAT | _os.O_EXCL | getattr(_os, "O_NOFOLLOW", 0)
    fd = _os.open(path, flags, 0o600)
    with _os.fdopen(fd, "wb") as handle:
        handle.write(data)


def _extract_package(files, package, scratch_dir) -> str:
    """Write exactly the mapped ``files`` under a fresh private directory, as package ``package``.

    Returns the extraction root (the directory to put on ``sys.path``). Directories are created
    0700, files 0600 with ``O_EXCL | O_NOFOLLOW``; nothing outside the map is ever written."""
    extract_root = _tempfile.mkdtemp(prefix="vsify-pkg-", dir=scratch_dir)
    try:
        package_dir = _os.path.join(extract_root, *package)
        _os.makedirs(package_dir, mode=0o700)
        for relpath in sorted(files):
            parts = relpath.split("/")
            target_dir = _os.path.join(package_dir, *parts[:-1])
            _os.makedirs(target_dir, mode=0o700, exist_ok=True)
            _write_new_file(_os.path.join(target_dir, parts[-1]), files[relpath])
    except BaseException:
        _discard_tree(extract_root)
        raise
    return extract_root


def _discard_tree(top: str) -> None:
    """Best-effort removal of an extraction tree this loader created, sealed or not.

    Directories are made writable top-down first (a sealed tree is 0500 throughout), then every
    entry is removed bottom-up. Nothing in the tree is a symlink — :func:`_extract_package` writes
    only regular files with ``O_NOFOLLOW`` — so the walk never leaves ``top``. Never raises: a tree
    that cannot be removed is left behind rather than masking the refusal that triggered it."""
    try:
        _os.chmod(top, 0o700)
        for dirpath, dirnames, _filenames in _os.walk(top):
            for name in dirnames:
                _os.chmod(_os.path.join(dirpath, name), 0o700)
        for dirpath, dirnames, filenames in _os.walk(top, topdown=False):
            for name in filenames:
                _os.unlink(_os.path.join(dirpath, name))
            for name in dirnames:
                _os.rmdir(_os.path.join(dirpath, name))
        _os.rmdir(top)
    except OSError:
        pass


def _seal_tree(top: str) -> None:
    """Make an extracted tree read-only: files 0400, directories 0500 (bottom-up)."""
    for dirpath, dirnames, filenames in _os.walk(top, topdown=False):
        for name in filenames:
            _os.chmod(_os.path.join(dirpath, name), 0o400)
        for name in dirnames:
            _os.chmod(_os.path.join(dirpath, name), 0o500)
    _os.chmod(top, 0o500)


def _load_package(root, ref, *, walk, files_digest, classify_package, validate_ref,
                  expected_files_sha256, extra_allowed, scratch_dir):
    """Load a ``layout: package`` module (issue #862) and return its ``serve`` callable, or raise
    :class:`_LoadRefused`.

    ``root`` is the read-only package mount (``/module/<package segments>`` in the image); ``ref`` the
    dotted entry ref, whose last segment names the entry module and whose remaining segments are the
    package ``root`` is imported as. Every collaborator is passed in, so this file still imports no
    sibling: ``walk`` (``package_tree._walk_package``), ``files_digest``
    (``package_tree._files_digest``), ``classify_package`` (``import_closure._classify_package``),
    ``validate_ref`` (``import_closure._validate_dotted_ref``).

    Order, each a refusal: dotted ref (>= 2 segments) -> walk the mount (each member read ONCE,
    ``lstat``/``O_NOFOLLOW``; refusals ``package_member_refused`` / ``package_too_large``) -> the
    entry module is a member (``entrypoint_missing``) -> the map's digest equals
    ``expected_files_sha256``, the digest the host signed (``package_digest_mismatch``) -> classify
    every member -> extract EXACTLY the mapped files into a fresh private directory under
    ``scratch_dir``, re-walk and re-digest the extraction (``package_digest_mismatch``), seal it
    read-only -> import the dotted ref with the standard path finder from the extraction root, which
    is put first on ``sys.path`` (the mount itself never is) -> ``serve``.

    The verified bytes are what runs: the extraction holds only mapped files, so an unsigned file in
    the mount is never importable, and a mount changed after the walk changes nothing extracted.

    **A refusal leaves nothing behind.** In the image this is a single-shot process on a private
    tmpfs, so leftovers would be harmless; the host-mirrored testing aid, though, calls this
    repeatedly in one process. Every refusal raised after the extraction exists -- and any other
    exception escaping it, such as module code calling ``sys.exit`` at import -- therefore restores
    ``sys.path``, drops the ``sys.modules`` entries the failed import added under this package's own
    names (never anything else — an unrelated module imported along the way stays), and removes the
    extraction root. On success the extraction stays: ``serve`` may import lazily from it."""
    try:
        segments = validate_ref(ref)
    except ValueError:
        raise _LoadRefused("entrypoint_ref_malformed") from None
    if len(segments) < 2:
        raise _LoadRefused("entrypoint_ref_malformed")
    package, entry = tuple(segments[:-1]), segments[-1]
    expected = str(expected_files_sha256 or "")
    if len(expected) != 64 or any(ch not in "0123456789abcdef" for ch in expected):
        raise _LoadRefused(_PACKAGE_DIGEST_MISMATCH)

    try:
        files = walk(_os.fspath(root))
    except Exception as exc:  # noqa: BLE001 — every walker fault is a categorical refusal
        raise _LoadRefused(getattr(exc, "reason", None) or "entrypoint_unloadable") from None
    if entry + ".py" not in files and entry + "/__init__.py" not in files:
        raise _LoadRefused("entrypoint_missing")
    if files_digest(files) != expected:
        raise _LoadRefused(_PACKAGE_DIGEST_MISMATCH)
    try:
        reason = classify_package(files, package, extra_allowed=frozenset(extra_allowed))
    except Exception:  # noqa: BLE001 — fail closed: a faulting analyser is a refusal, never a pass
        reason = "entrypoint_unparseable"
    if reason is not None:
        raise _LoadRefused(str(reason))

    try:
        extract_root = _extract_package(files, package, scratch_dir)
    except Exception:  # noqa: BLE001 — an extraction that cannot be completed never runs
        raise _LoadRefused("entrypoint_unloadable") from None
    path_before = list(_sys.path)
    modules_before = set(_sys.modules)
    try:
        return _import_extracted(extract_root, package, segments, walk=walk,
                                 files_digest=files_digest, expected=expected)
    except BaseException:
        # Not only _LoadRefused: module code can raise SystemExit/KeyboardInterrupt at import time,
        # which ``except Exception`` below lets through. Clean up either way; re-raise unchanged.
        _sys.path[:] = path_before
        owned = ".".join(package)
        for name in set(_sys.modules) - modules_before:
            if name == owned or name.startswith(owned + ".") or owned.startswith(name + "."):
                _sys.modules.pop(name, None)
        _discard_tree(extract_root)
        raise


def _import_extracted(extract_root, package, segments, *, walk, files_digest, expected):
    """Re-verify, seal and import an extraction (the tail of :func:`_load_package`, which owns the
    cleanup when this refuses)."""
    try:
        extracted = walk(_os.path.join(extract_root, *package))
    except Exception:  # noqa: BLE001 — an extraction that cannot be re-walked never runs
        raise _LoadRefused("entrypoint_unloadable") from None
    if files_digest(extracted) != expected:
        raise _LoadRefused(_PACKAGE_DIGEST_MISMATCH)
    try:
        _seal_tree(extract_root)
    except OSError:
        raise _LoadRefused("entrypoint_unloadable") from None

    _sys.dont_write_bytecode = True
    _sys.path.insert(0, extract_root)
    _importlib.invalidate_caches()
    try:
        module = _importlib.import_module(".".join(segments))
    except Exception as exc:  # noqa: BLE001 — any import-time failure is a setup refusal
        raise _LoadRefused(f"entrypoint_import_failed:{type(exc).__name__}") from exc

    serve = getattr(module, "serve", None)
    if not callable(serve):
        raise _LoadRefused("serve_callable_missing")
    return serve
