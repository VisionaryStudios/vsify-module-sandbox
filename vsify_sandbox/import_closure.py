"""
Static import-closure analyser for ``python_module`` entrypoints (ADR-P039, ADR-P041).

The sandbox image is stdlib-only and, for the default ``layout: file``, mounts exactly ONE file at
``/module/entrypoint``, loaded under a flat module name. An entrypoint that imports a sibling
(``from . import wire``), a package-relative name, or any third-party top-level name therefore dies
inside the container before READY. ``_classify_imports`` names that defect from the source bytes
alone, so it can be refused on the host before a container starts and again by the image on the
exact bytes it is about to execute.

A ``layout: package`` module (issue #862) is mounted as a package instead, so ``_classify_package``
classifies EVERY member: relative and self-absolute imports are admitted while they stay inside the
mounted package root (``entrypoint_relative_escape`` otherwise), and the allowed top-level set is
``_STDLIB`` plus the module's validated ``core.runtime.imports`` (``_validate_import_names``) — the
non-stdlib names its consumer-built image provides.

SECURITY SHAPE — this is a pure function over untrusted bytes:

- static ``ast`` only. Nothing is imported, compiled to bytecode, or executed to classify it.
- input is size-capped (``_MAX_SOURCE_BYTES``) before the parser sees it; the tree walk is iterative,
  so a deeply nested tree cannot exhaust the Python stack here, and the parser's own nesting limits
  raise, which collapses to ``entrypoint_unparseable``.
- it NEVER raises: any exception while parsing or walking is ``entrypoint_unparseable`` (fail closed).
- the grammar is the image's Python minor (``_FEATURE_VERSION``), never the host interpreter's, so a
  host's newer Python cannot move the verdict.
- it leaves the process's warning filters alone. It is called concurrently from threaded host code,
  and ``warnings.catch_warnings`` mutates process-global state, so it is never used here. The
  consequence is a fail-closed residual: in a host process running with warnings as errors, a
  compile-time ``SyntaxWarning`` (an invalid escape such as ``"\\d"``) becomes a parse failure and
  the verdict is ``entrypoint_unparseable``, where the image (default filters) would admit it.

THIS FILE IS MIRRORED BYTE-IDENTICALLY into the host package (``vsify_enterprise_mcp/_sandbox_mirror/``)
and pinned by sha256, because the image cannot import the host package and the host must reach the
same verdict as the image. So it is stdlib-only, has no relative imports, and binds only underscored
top-level names (the mirror must publish nothing into ``SURFACE.json``). ``sandbox/`` is the source of
truth (ADR-P048): edit here, then copy.
"""
import ast as _astlib

# The reason tokens. INTERNAL only: host-side every one collapses to the single fixed
# ``entrypoint_unresolvable`` launch outcome (ADR-P036's closed vocabulary is unchanged).
_RELATIVE_IMPORT = "entrypoint_relative_import"
_NONSTDLIB_IMPORT = "entrypoint_nonstdlib_import"
_UNPARSEABLE = "entrypoint_unparseable"
# ``layout: package`` only (issue #862): an import that leaves the mounted package root — a relative
# import climbing above it, or an absolute import of a sibling of it. It ranks at the relative tier.
_ESCAPE = "entrypoint_relative_escape"
# A malformed ``core.runtime.imports`` declaration (host and image refuse it with the same helper).
_DECLARED_IMPORT_MALFORMED = "declared_import_malformed"
_MAX_DECLARED_IMPORTS = 32
# The image's own package: a module may never declare it, so a consumer image cannot shadow the loader.
_SANDBOX_PACKAGE = "vsify_sandbox"

_MAX_SOURCE_BYTES = 1024 * 1024  # 1 MiB — larger than any real single-file entrypoint

# The Python minor version ``_STDLIB`` was generated from: the sandbox image's base
# (``sandbox/Dockerfile``'s ``FROM python:<minor>-slim``). A test pins the two together, and the sync
# test compares ``_STDLIB`` against ``sys.stdlib_module_names`` on an interpreter of this minor.
_STDLIB_PYTHON = "3.12"

# The grammar the source is parsed under: the image's minor, NOT the host interpreter's. Without it a
# 3.13+ host would admit syntax the 3.12 image then refuses (PEP 696 type-parameter defaults, PEP 758
# unparenthesised ``except`` tuples). ``ast.parse(feature_version=...)`` is best-effort — it refuses
# the version-gated constructs the parser knows about, which is exactly the class this closes.
_FEATURE_VERSION = tuple(int(part) for part in _STDLIB_PYTHON.split("."))

# FROZEN literal of the image interpreter's ``sys.stdlib_module_names`` — deliberately NOT read at
# runtime, so the host's verdict matches the image's on any host Python. Regenerate on a base-image
# Python bump (sandbox/CONTRIBUTING.md):
#   python3.12 -c "import sys; print(sorted(sys.stdlib_module_names))"
_STDLIB = frozenset({
    "__future__", "_abc", "_aix_support", "_ast", "_asyncio", "_bisect", "_blake2", "_bz2", "_codecs",
    "_codecs_cn", "_codecs_hk", "_codecs_iso2022", "_codecs_jp", "_codecs_kr", "_codecs_tw",
    "_collections", "_collections_abc", "_compat_pickle", "_compression", "_contextvars", "_crypt",
    "_csv", "_ctypes", "_curses", "_curses_panel", "_datetime", "_dbm", "_decimal", "_elementtree",
    "_frozen_importlib", "_frozen_importlib_external", "_functools", "_gdbm", "_hashlib", "_heapq",
    "_imp", "_io", "_json", "_locale", "_lsprof", "_lzma", "_markupbase", "_md5", "_msi",
    "_multibytecodec", "_multiprocessing", "_opcode", "_operator", "_osx_support", "_overlapped",
    "_pickle", "_posixshmem", "_posixsubprocess", "_py_abc", "_pydatetime", "_pydecimal", "_pyio",
    "_pylong", "_queue", "_random", "_scproxy", "_sha1", "_sha2", "_sha3", "_signal", "_sitebuiltins",
    "_socket", "_sqlite3", "_sre", "_ssl", "_stat", "_statistics", "_string", "_strptime", "_struct",
    "_symtable", "_thread", "_threading_local", "_tkinter", "_tokenize", "_tracemalloc", "_typing",
    "_uuid", "_warnings", "_weakref", "_weakrefset", "_winapi", "_wmi", "_zoneinfo", "abc", "aifc",
    "antigravity", "argparse", "array", "ast", "asyncio", "atexit", "audioop", "base64", "bdb",
    "binascii", "bisect", "builtins", "bz2", "cProfile", "calendar", "cgi", "cgitb", "chunk", "cmath",
    "cmd", "code", "codecs", "codeop", "collections", "colorsys", "compileall", "concurrent",
    "configparser", "contextlib", "contextvars", "copy", "copyreg", "crypt", "csv", "ctypes", "curses",
    "dataclasses", "datetime", "dbm", "decimal", "difflib", "dis", "doctest", "email", "encodings",
    "ensurepip", "enum", "errno", "faulthandler", "fcntl", "filecmp", "fileinput", "fnmatch",
    "fractions", "ftplib", "functools", "gc", "genericpath", "getopt", "getpass", "gettext", "glob",
    "graphlib", "grp", "gzip", "hashlib", "heapq", "hmac", "html", "http", "idlelib", "imaplib",
    "imghdr", "importlib", "inspect", "io", "ipaddress", "itertools", "json", "keyword", "lib2to3",
    "linecache", "locale", "logging", "lzma", "mailbox", "mailcap", "marshal", "math", "mimetypes",
    "mmap", "modulefinder", "msilib", "msvcrt", "multiprocessing", "netrc", "nis", "nntplib", "nt",
    "ntpath", "nturl2path", "numbers", "opcode", "operator", "optparse", "os", "ossaudiodev", "pathlib",
    "pdb", "pickle", "pickletools", "pipes", "pkgutil", "platform", "plistlib", "poplib", "posix",
    "posixpath", "pprint", "profile", "pstats", "pty", "pwd", "py_compile", "pyclbr", "pydoc",
    "pydoc_data", "pyexpat", "queue", "quopri", "random", "re", "readline", "reprlib", "resource",
    "rlcompleter", "runpy", "sched", "secrets", "select", "selectors", "shelve", "shlex", "shutil",
    "signal", "site", "smtplib", "sndhdr", "socket", "socketserver", "spwd", "sqlite3", "sre_compile",
    "sre_constants", "sre_parse", "ssl", "stat", "statistics", "string", "stringprep", "struct",
    "subprocess", "sunau", "symtable", "sys", "sysconfig", "syslog", "tabnanny", "tarfile", "telnetlib",
    "tempfile", "termios", "textwrap", "this", "threading", "time", "timeit", "tkinter", "token",
    "tokenize", "tomllib", "trace", "traceback", "tracemalloc", "tty", "turtle", "turtledemo", "types",
    "typing", "unicodedata", "unittest", "urllib", "uu", "uuid", "venv", "warnings", "wave", "weakref",
    "webbrowser", "winreg", "winsound", "wsgiref", "xdrlib", "xml", "xmlrpc", "zipapp", "zipfile",
    "zipimport", "zlib", "zoneinfo",
})

# A ``try:`` body is exempt only when one of its handlers names one of these exactly. A bare
# ``except:`` or ``except Exception`` does NOT exempt: refusing there is a deliberate false positive.
_IMPORT_ERROR_NAMES = frozenset({"ImportError", "ModuleNotFoundError"})


def _is_type_checking_test(test: _astlib.expr) -> bool:
    """``if TYPE_CHECKING:`` or ``if typing.TYPE_CHECKING:`` — the body never runs at import."""
    if isinstance(test, _astlib.Name):
        return test.id == "TYPE_CHECKING"
    return (
        isinstance(test, _astlib.Attribute)
        and test.attr == "TYPE_CHECKING"
        and isinstance(test.value, _astlib.Name)
        and test.value.id == "typing"
    )


def _handler_catches_import_error(handler: _astlib.ExceptHandler) -> bool:
    caught = handler.type
    names = caught.elts if isinstance(caught, _astlib.Tuple) else [caught]
    return any(isinstance(name, _astlib.Name) and name.id in _IMPORT_ERROR_NAMES for name in names)


def _children(node: _astlib.AST, exempt: bool) -> list[tuple[_astlib.AST, bool]]:
    """``node``'s children, each paired with whether imports beneath it are exempt. Only the guarded
    BODY of an exempting ``if``/``try`` is exempt — never its ``else``, handlers or ``finally``."""
    exempt_body: list[_astlib.stmt] = []
    if isinstance(node, _astlib.If) and _is_type_checking_test(node.test):
        exempt_body = node.body
    elif isinstance(node, (_astlib.Try, _astlib.TryStar)) and any(
        _handler_catches_import_error(handler) for handler in node.handlers
    ):
        exempt_body = node.body
    exempt_ids = {id(stmt) for stmt in exempt_body}
    return [(child, exempt or id(child) in exempt_ids) for child in _astlib.iter_child_nodes(node)]


def _import_verdict(node: _astlib.AST) -> str | None:
    """The reason one import statement is refused, or ``None``. ``__future__`` is always allowed."""
    if isinstance(node, _astlib.ImportFrom):
        if node.level:
            return _RELATIVE_IMPORT
        tops = [(node.module or "").split(".")[0]]
    elif isinstance(node, _astlib.Import):
        tops = [alias.name.split(".")[0] for alias in node.names]
    else:
        return None
    if all(top in _STDLIB for top in tops):
        return None
    return _NONSTDLIB_IMPORT


def _parse(source: bytes) -> _astlib.Module:
    """Parse under the IMAGE's grammar (``_FEATURE_VERSION``, read at call time).

    Warning filters are deliberately NOT touched (see the module docstring): under a caller's
    warnings-as-errors filter a compile-time ``SyntaxWarning`` raises here, and the caller's
    fail-closed handler turns it into ``entrypoint_unparseable``. The public test aid
    (``vsify_enterprise_mcp.testing.load_sandbox_entrypoint``) scopes its own suppression around
    the whole load instead."""
    return _astlib.parse(source, mode="exec", feature_version=_FEATURE_VERSION)


def _classify_imports(source: bytes) -> str | None:
    """Classify an entrypoint's imports from its raw bytes. Returns a reason token or ``None``.

    - any relative import (``ImportFrom.level > 0``) -> ``entrypoint_relative_import``
    - any absolute import whose top-level name is not in ``_STDLIB`` -> ``entrypoint_nonstdlib_import``
    - non-bytes input, input over 1 MiB, or ANY exception while parsing/walking ->
      ``entrypoint_unparseable``

    A relative import outranks a non-stdlib one, so the verdict never depends on walk order. Imports
    lexically inside an ``if TYPE_CHECKING:`` body, or inside a ``try:`` body whose handlers catch
    ``ImportError``/``ModuleNotFoundError``, are exempt. The WHOLE tree is walked, so a function-level
    import is checked like a module-level one. Never raises."""
    try:
        if not isinstance(source, (bytes, bytearray)) or len(source) > _MAX_SOURCE_BYTES:
            return _UNPARSEABLE
        tree = _parse(bytes(source))
        verdict = None
        stack: list[tuple[_astlib.AST, bool]] = [(tree, False)]
        while stack:
            node, exempt = stack.pop()
            if not exempt:
                reason = _import_verdict(node)
                if reason == _RELATIVE_IMPORT:
                    return reason
                verdict = verdict or reason
            stack.extend(_children(node, exempt))
        return verdict
    except Exception:  # noqa: BLE001 — fail closed: an analyser fault is a refusal, never a pass
        return _UNPARSEABLE


def _validate_import_names(names, package_top: str = "") -> tuple:
    """Validate a ``core.runtime.imports`` declaration; return the names as a tuple.

    The ONE rule host and image both apply (issue #862), so the allowed set is computed identically
    in both homes. Each entry must be an ASCII identifier, not a stdlib name, not the module's own
    top-level package, not ``vsify_sandbox``, and not repeated; at most ``_MAX_DECLARED_IMPORTS``.
    Raises ``ValueError("declared_import_malformed")`` on any violation. Pure."""
    if not isinstance(names, (list, tuple)) or len(names) > _MAX_DECLARED_IMPORTS:
        raise ValueError(_DECLARED_IMPORT_MALFORMED)
    seen = set()
    for name in names:
        if (
            not isinstance(name, str)
            or not name.isascii()
            or not name.isidentifier()
            or name in _STDLIB
            or name == _SANDBOX_PACKAGE
            or (package_top and name == package_top)
            or name in seen
        ):
            raise ValueError(_DECLARED_IMPORT_MALFORMED)
        seen.add(name)
    return tuple(names)


def _package_import_verdict(node, member_package: tuple, package: tuple, allowed: frozenset):
    """The reason one import statement inside a ``layout: package`` member is refused, or ``None``.

    ``member_package`` is the dotted package the member file lives in; ``package`` the mounted root.
    A relative import resolves against ``member_package`` and is admitted only while it stays at or
    below ``package``. An absolute import of ``package`` itself, of something beneath it, or of one of
    its (empty, synthesised) namespace parents is admitted; any other absolute import under the
    root's top-level name escapes. Everything else must be stdlib or declared. ``__future__`` passes."""
    if isinstance(node, _astlib.ImportFrom):
        if node.level:
            if node.level - 1 > len(member_package) - len(package):
                return _ESCAPE
            return None
        module = tuple((node.module or "").split("."))
        if len(module) < len(package) and package[: len(module)] == module:
            # ``from <namespace parent> import name``: each name is a SIBLING of the package (or the
            # package itself), so judge every imported name, and a star import from a parent escapes.
            if any(alias.name == "*" for alias in node.names):
                return _ESCAPE
            targets = [module + (alias.name,) for alias in node.names]
        else:
            targets = [module]
    elif isinstance(node, _astlib.Import):
        targets = [tuple(alias.name.split(".")) for alias in node.names]
    else:
        return None
    verdict = None
    for target in targets:
        if target[: len(package)] == package or package[: len(target)] == target:
            continue  # the package itself, beneath it, or a namespace parent of it
        if target[0] == package[0]:
            return _ESCAPE
        if target[0] in _STDLIB or target[0] in allowed:
            continue
        verdict = _NONSTDLIB_IMPORT
    return verdict


_PACKAGE_MEMBER_REFUSED = "package_member_refused"

# A package whose top-level name is a stdlib module or ``vsify_sandbox``. The image loader puts the
# extraction root FIRST on ``sys.path``, and every import of the package's own top-level name is a
# self-import here, so such a package would replace that module for the loader, the egress shim and
# the framing code that run in the same process after it. The same names ``_validate_import_names``
# already refuses as a declared import.
_PACKAGE_NAME_RESERVED = "package_name_reserved"

# Members the standard path finder would import that are not source this module can analyse: native
# extensions, and sourceless bytecode. A FIXED literal set rather than the running interpreter's
# ``importlib.machinery`` suffixes, so the host and the image refuse exactly the same members.
_UNANALYSABLE_IMPORT_SUFFIXES = (".so", ".pyd", ".pyc", ".pyo")

_VERDICT_RANK = {_PACKAGE_MEMBER_REFUSED: 4, _ESCAPE: 3, _NONSTDLIB_IMPORT: 2, _UNPARSEABLE: 1}


def _classify_package(files, package_segments, *, extra_allowed=frozenset()):
    """Classify every ``.py`` member of a ``layout: package`` module. Returns a reason token or ``None``.

    ``files`` is the walked ``{posix relpath: bytes}`` map (``package_tree._walk_package``);
    ``package_segments`` the dotted package the root is mounted as (the entry ref minus its last
    segment); ``extra_allowed`` the validated ``core.runtime.imports`` names. A member the path
    finder could import without it being analysable source (``.so`` / ``.pyd`` / ``.pyc`` / ``.pyo``)
    is ``package_member_refused``: the closure verdict is only true if every importable member was
    read. A package whose top-level name is a stdlib module or ``vsify_sandbox`` is
    ``package_name_reserved``, before any member is read: it would shadow that module from
    ``sys.path[0]``. The worst verdict across all members wins, ranked ``package_member_refused`` >
    ``entrypoint_relative_escape`` > ``entrypoint_nonstdlib_import`` > ``entrypoint_unparseable``,
    so the result never depends on walk order. Exemptions are exactly
    ``_classify_imports``'s (``TYPE_CHECKING`` bodies, ``try`` bodies catching ``ImportError``). A
    member over ``_MAX_SOURCE_BYTES`` is unparseable. Pure, never raises."""
    try:
        package = tuple(package_segments)
        if not package or not all(isinstance(seg, str) and seg for seg in package):
            return _UNPARSEABLE
        if package[0] in _STDLIB or package[0] == _SANDBOX_PACKAGE:
            return _PACKAGE_NAME_RESERVED
        if not isinstance(files, dict):
            return _UNPARSEABLE
        allowed = frozenset(extra_allowed)
        if any(relpath.lower().endswith(_UNANALYSABLE_IMPORT_SUFFIXES) for relpath in files):
            return _PACKAGE_MEMBER_REFUSED
        worst = None
        for relpath in sorted(files):
            if not relpath.endswith(".py"):
                continue
            source = files[relpath]
            if not isinstance(source, (bytes, bytearray)) or len(source) > _MAX_SOURCE_BYTES:
                verdict = _UNPARSEABLE
            else:
                member_package = package + tuple(relpath.split("/")[:-1])
                verdict = None
                try:
                    stack: list = [(_parse(bytes(source)), False)]
                    while stack:
                        node, exempt = stack.pop()
                        if not exempt:
                            reason = _package_import_verdict(node, member_package, package, allowed)
                            if reason == _ESCAPE:
                                return _ESCAPE
                            verdict = verdict or reason
                        stack.extend(_children(node, exempt))
                except Exception:  # noqa: BLE001 — one unparseable member must not mask another's escape
                    verdict = _UNPARSEABLE
            if verdict and _VERDICT_RANK[verdict] > _VERDICT_RANK.get(worst, 0):
                worst = verdict
        return worst
    except Exception:  # noqa: BLE001 — fail closed: an analyser fault is a refusal, never a pass
        return _UNPARSEABLE


class _EntrypointRefMalformed(ValueError):
    """The dotted ref failed shape validation — never trust it for loading or logging as-is."""


def _validate_dotted_ref(ref: str) -> tuple[str, ...]:
    """Validate ``ref`` against the SAME rule the host's ``entrypoint_ref._dotted_ref_candidates``
    enforces: every dot-separated segment MUST be ``str.isascii()`` (checked first) AND
    ``str.isidentifier()`` (rejects ``/``, ``-``, leading digits, empty segments, and any non-ASCII
    homoglyph segment). Returns the validated segment tuple. Raises :class:`_EntrypointRefMalformed`
    (``"entrypoint_ref_malformed"``) on any violation. Pure: lives here, not in the loader, so the
    ``entrypoint_resolve`` shim can re-export it without importing anything exec-capable."""
    ref = str(ref or "")
    segments = tuple(ref.split("."))
    if not segments or not all(seg.isascii() and seg.isidentifier() for seg in segments):
        raise _EntrypointRefMalformed("entrypoint_ref_malformed")
    return segments
