"""
The ONE package walker for ``layout: package`` modules (issue #862): read a module package
directory into a ``{relpath: bytes}`` map, or refuse with a categorical reason token.

Both homes use these exact bytes. The image walks the read-only package mount before it imports
anything; the host walks the module directory when it signs, pins, stages and launches the module.
Because there is one walker, the file map the host signs and the file map the image verifies are
the same map by construction, not by agreement between two implementations. The file is exec-free
(it reads bytes and hashes them, nothing else), so the host may import it on its framework load
paths exactly as it imports ``import_closure`` (ADR-P048).

SECURITY SHAPE — the tree is untrusted input:

- the walk is ``dir_fd``-relative wherever the platform supports it: each directory is opened
  ``O_DIRECTORY | O_NOFOLLOW`` relative to its parent's open fd and checked against its ``lstat``
  (same device and inode), and every child is listed, ``lstat``-ed and opened relative to that held
  fd. A directory swapped for a symlink before its open is refused; one swapped after its open no
  longer changes what is read, because no path is ever re-resolved from the root. Where ``dir_fd``
  is unavailable (Windows) each directory is re-``lstat``-ed against its queued identity before it
  is listed — a narrower check, not an equivalent one.
- every entry is ``lstat``-ed: a symlink (file or directory), FIFO, socket, device, or any other
  non-regular entry is ``package_member_refused``; a regular file with more than one hard link is
  refused too (a hardlink is a second name for bytes the signer never chose).
- each regular file is opened ``O_NOFOLLOW | O_NONBLOCK``, re-checked with ``fstat`` (same device
  and inode as the ``lstat``, still regular), and read ONCE, bounded by the per-file cap. A swap
  between ``lstat`` and ``open`` is refused, never followed.
- names: every path segment must be non-empty printable ASCII, not ``.`` or ``..``, with no NUL,
  ``/`` or ``\\``; two relpaths — files or directories — that collide under ``str.casefold()``
  are refused (a map that is
  unambiguous on Linux must not become ambiguous on a case-insensitive filesystem).
- caps: file count, per-file bytes, total bytes, directory count and directory depth fail closed
  as ``package_too_large`` before the read that would exceed them. The walk is depth-first, so the
  directory handles it holds open never exceed the depth cap: a verdict never depends on the
  process's file-descriptor limit, which differs between the host and the image.
- exclusions are EXACT root-level relpaths only (the manifest and the signature artifact). A file
  of the same name in a subdirectory is mapped like any other file. An excluded file is still
  checked and still COUNTED against every cap and the case-fold set, without being read: the image
  walks the same mount with no exclusions, so a tree the host accepts must be one the image accepts
  too, file for file and byte for byte. ``__pycache__`` directories
  are skipped at any depth: build output, never signed material, and never extracted or served.

THIS FILE IS MIRRORED BYTE-IDENTICALLY into the host package (``vsify_enterprise_mcp/_sandbox_mirror/``)
and pinned by sha256. So it is stdlib-only, has no relative imports, and binds only underscored
top-level names. ``sandbox/`` is the source of truth (ADR-P048): edit here, then copy.
"""
import hashlib as _hashlib
import json as _json
import os as _os
import stat as _stat

_PACKAGE_MEMBER_REFUSED = "package_member_refused"
_PACKAGE_TOO_LARGE = "package_too_large"

_MAX_PACKAGE_FILES = 512
_MAX_PACKAGE_FILE_BYTES = 1024 * 1024  # 1 MiB — the analyser's own per-source cap
_MAX_PACKAGE_TOTAL_BYTES = 8 * 1024 * 1024  # 8 MiB
_MAX_PACKAGE_DEPTH = 16
_MAX_PACKAGE_DIRS = 256  # directories below the root; bounds the walk's work, not just its output

_PYCACHE = "__pycache__"

# fd-relative traversal needs every one of these; a platform lacking any walks by path instead.
_FD_WALK = (
    hasattr(_os, "O_DIRECTORY")
    and hasattr(_os, "O_NOFOLLOW")
    and _os.open in _os.supports_dir_fd
    and _os.stat in _os.supports_dir_fd
    and _os.scandir in _os.supports_fd
)


class _PackageRefused(ValueError):
    """A categorical walker refusal. ``reason`` (also ``str(exc)``) is a fixed token."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _valid_segment(name: str) -> bool:
    """One path segment: non-empty printable ASCII, not ``.``/``..``, no NUL, ``/`` or ``\\``."""
    return (
        isinstance(name, str)
        and bool(name)
        and name not in (".", "..")
        and name.isascii()
        and name.isprintable()
        and "\x00" not in name
        and "/" not in name
        and "\\" not in name
    )


def _member(handle, name: str):
    """``(path, dir_fd)`` naming child ``name`` of the directory ``handle`` (an fd, or a path)."""
    if isinstance(handle, int):
        return name, handle
    return _os.path.join(handle, name), None


def _same_inode(a, b) -> bool:
    return (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)


def _open_dir(path: str, dir_fd, st: _os.stat_result):
    """A handle on the directory ``st`` was ``lstat``-ed from: an fd under :data:`_FD_WALK`, else
    the path itself after a re-``lstat``. Anything that is no longer that directory is refused."""
    if not _FD_WALK:
        try:
            again = _os.lstat(path)
        except OSError:
            raise _PackageRefused(_PACKAGE_MEMBER_REFUSED) from None
        if not _stat.S_ISDIR(again.st_mode) or not _same_inode(again, st):
            raise _PackageRefused(_PACKAGE_MEMBER_REFUSED)
        return path
    try:
        fd = _os.open(path, _os.O_RDONLY | _os.O_DIRECTORY | _os.O_NOFOLLOW, dir_fd=dir_fd)
    except OSError:
        raise _PackageRefused(_PACKAGE_MEMBER_REFUSED) from None
    try:
        fst = _os.fstat(fd)
    except OSError:
        _close_dir(fd)
        raise _PackageRefused(_PACKAGE_MEMBER_REFUSED) from None
    if not _stat.S_ISDIR(fst.st_mode) or not _same_inode(fst, st):
        _close_dir(fd)
        raise _PackageRefused(_PACKAGE_MEMBER_REFUSED)
    return fd


def _close_dir(handle) -> None:
    if isinstance(handle, int):
        try:
            _os.close(handle)
        except OSError:
            pass


def _list_names(handle) -> list:
    """The sorted entry names of the directory ``handle``."""
    try:
        with _os.scandir(handle) as entries:
            return sorted(entry.name for entry in entries)
    except OSError:
        raise _PackageRefused(_PACKAGE_MEMBER_REFUSED) from None


def _lstat_member(handle, name: str) -> _os.stat_result:
    path, dir_fd = _member(handle, name)
    try:
        return _os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
    except OSError:
        raise _PackageRefused(_PACKAGE_MEMBER_REFUSED) from None


def _fold_once(folded: set, relpath: str) -> None:
    """Record ``relpath`` (a file OR a directory) under case-folding, refusing a second spelling.

    Directories are folded too: ``Util/`` and ``util/`` are one directory on a case-insensitive
    filesystem even when no two files inside them share a name."""
    key = relpath.casefold()
    if key in folded:
        raise _PackageRefused(_PACKAGE_MEMBER_REFUSED)
    folded.add(key)


def _read_member_once(path: str, st: _os.stat_result, dir_fd=None) -> bytes:
    """A regular member's bytes, read once, refusing anything that is not the ``lstat``-ed file."""
    flags = _os.O_RDONLY | getattr(_os, "O_NOFOLLOW", 0) | getattr(_os, "O_NONBLOCK", 0)
    try:
        fd = _os.open(path, flags, dir_fd=dir_fd)
    except OSError:
        raise _PackageRefused(_PACKAGE_MEMBER_REFUSED) from None
    try:
        with _os.fdopen(fd, "rb") as handle:
            fst = _os.fstat(handle.fileno())
            if (
                not _stat.S_ISREG(fst.st_mode)
                or not _same_inode(fst, st)
                or fst.st_nlink > 1
            ):
                raise _PackageRefused(_PACKAGE_MEMBER_REFUSED)
            data = handle.read(_MAX_PACKAGE_FILE_BYTES + 1)
    except OSError:
        raise _PackageRefused(_PACKAGE_MEMBER_REFUSED) from None
    if len(data) > _MAX_PACKAGE_FILE_BYTES:
        raise _PackageRefused(_PACKAGE_TOO_LARGE)
    return data


def _walk_package(root, *, exclude=frozenset()):
    """Read the package directory ``root`` into a ``{posix relpath: bytes}`` map (sorted keys).

    ``exclude`` holds EXACT root-level relpaths to leave out of the map (the manifest, the
    signature artifact); they still count against the caps. Raises :class:`_PackageRefused`
    (``package_member_refused`` / ``package_too_large``)
    on any refusal; never returns a partial map."""
    root = _os.fspath(root)
    try:
        root_st = _os.lstat(root)
    except OSError:
        raise _PackageRefused(_PACKAGE_MEMBER_REFUSED) from None
    if not _stat.S_ISDIR(root_st.st_mode):
        raise _PackageRefused(_PACKAGE_MEMBER_REFUSED)
    excluded = frozenset(exclude)

    files: dict = {}
    folded: set = set()
    tally = {"dirs": 0, "files": 0, "bytes": 0}

    def visit(handle, rel_parts) -> None:
        # Depth-first: a subdirectory is opened only while it is being visited and closed before its
        # next sibling, so the open handles at any moment are the current path — at most the depth
        # cap — however wide the tree is.
        try:
            for name in _list_names(handle):
                if not _valid_segment(name):
                    raise _PackageRefused(_PACKAGE_MEMBER_REFUSED)
                st = _lstat_member(handle, name)
                parts = rel_parts + (name,)
                relpath = "/".join(parts)
                if _stat.S_ISLNK(st.st_mode):
                    raise _PackageRefused(_PACKAGE_MEMBER_REFUSED)
                if _stat.S_ISDIR(st.st_mode):
                    if name == _PYCACHE:
                        continue
                    _fold_once(folded, relpath)
                    tally["dirs"] += 1
                    if len(parts) >= _MAX_PACKAGE_DEPTH or tally["dirs"] > _MAX_PACKAGE_DIRS:
                        raise _PackageRefused(_PACKAGE_TOO_LARGE)
                    path, dir_fd = _member(handle, name)
                    visit(_open_dir(path, dir_fd, st), parts)
                    continue
                if not _stat.S_ISREG(st.st_mode) or st.st_nlink > 1:
                    raise _PackageRefused(_PACKAGE_MEMBER_REFUSED)
                _fold_once(folded, relpath)
                tally["files"] += 1
                if tally["files"] > _MAX_PACKAGE_FILES:
                    raise _PackageRefused(_PACKAGE_TOO_LARGE)
                if (
                    st.st_size > _MAX_PACKAGE_FILE_BYTES
                    or tally["bytes"] + st.st_size > _MAX_PACKAGE_TOTAL_BYTES
                ):
                    raise _PackageRefused(_PACKAGE_TOO_LARGE)
                if len(parts) == 1 and relpath in excluded:
                    tally["bytes"] += st.st_size
                    continue
                path, dir_fd = _member(handle, name)
                data = _read_member_once(path, st, dir_fd)
                tally["bytes"] += len(data)
                if tally["bytes"] > _MAX_PACKAGE_TOTAL_BYTES:
                    raise _PackageRefused(_PACKAGE_TOO_LARGE)
                files[relpath] = data
        finally:
            _close_dir(handle)

    visit(_open_dir(root, None, root_st), ())
    return {key: files[key] for key in sorted(files)}


def _files_map(files) -> dict:
    """``{relpath: sha256 hex}`` over a walked package — what the signing payload v2 embeds."""
    return {relpath: _hashlib.sha256(files[relpath]).hexdigest() for relpath in sorted(files)}


def _files_digest(files) -> str:
    """Hex sha256 of the canonical JSON file map (sorted keys, compact separators).

    The single digest function: the host's signing payload, lockfile pin and launch projection,
    and the image's pre-import check, all compute it here."""
    canonical = _json.dumps(_files_map(files), sort_keys=True, separators=(",", ":"))
    return _hashlib.sha256(canonical.encode("utf-8")).hexdigest()
