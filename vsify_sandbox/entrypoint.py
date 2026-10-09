"""
The vsify-module-sandbox entrypoint (ADR-P041, vsify-enterprise-mcp).

Dispatch env vars (all non-secret, set by ``ContainerIsolationBackend._build_serving_argv``):

- ``VSIFY_SANDBOX_TRANSPORT``: ``"stdio"`` | ``"unix_socket"``
- ``VSIFY_SANDBOX_ENTRYPOINT_KIND``: ``"script"`` | ``"python_module"`` (always set)
- ``VSIFY_SANDBOX_ENTRYPOINT_MODULE``: the dotted ref (only set for ``python_module``)
- ``VSIFY_SANDBOX_ENTRYPOINT_LAYOUT``: ``"package"`` for a ``layout: package`` module (issue #862);
  absent or ``"file"`` keeps the single-file path below byte-for-byte
- ``VSIFY_SANDBOX_PACKAGE_FILES_SHA256``: the signed package file-map digest (``package`` only)
- ``VSIFY_SANDBOX_ALLOWED_IMPORTS``: the module's ``core.runtime.imports``, comma-joined (``package``
  only; empty for a stdlib-only package)
- ``VSIFY_SANDBOX_SOCKET``: the in-container socket path (only set for ``unix_socket``)
- ``SANDBOX_EGRESS_ALLOW``: the claim's ``egress_allow``, comma-joined (only set with an allowlist)

Before the module is imported, the egress shim (``egress_proxy.py``, ADR-P048 §7) is started on
loopback and ``HTTP_PROXY``/``HTTPS_PROXY`` (both cases) are pointed at it, so every HTTP client the
module constructs inherits a default-deny, per-claim proxy. A shim that cannot bind is a setup
refusal like any other: the module is never imported with its egress unfiltered.

The module to serve is ALWAYS bind-mounted read-only at ``/module/entrypoint`` by the host — this
entrypoint never resolves a file path from the dotted ref itself (see ``entrypoint_resolve.py``'s
docstring). It loads that one file through the shared loader core (``module_loader.py``, which
runs the ``import_closure.py`` analyser on the exact bytes it executes), binds its required
``serve(payload: bytes) -> bytes`` callable, and serves REQUEST frames until the channel closes.

Exits non-zero (never a degraded/partial mode) on any setup failure — a missing ``serve``
callable, a malformed dotted ref, or an unsupported transport/kind are all refusals, matching the
host's own "never fall back, always fail closed" posture (ADR-P010).
"""
from __future__ import annotations

import importlib.util
import os
import socket
import sys
from typing import Callable

from . import egress_proxy, framing, import_closure, module_loader, package_tree

ENTRYPOINT_PATH = "/module/entrypoint"
# ``layout: package`` (issue #862): the package is mounted at ``/module/<package segments>`` and its
# verified bytes are extracted under the container's private tmpfs before import.
PACKAGE_MOUNT_ROOT = "/module"
PACKAGE_SCRATCH_DIR = "/tmp"  # nosec B108 — the container's own tmpfs (``--tmpfs /tmp``), not a host path
MAX_REQUEST_BYTES = 4 * 1024 * 1024  # 4 MiB — mirrors isolation/serving_contracts.py
MAX_RESPONSE_BYTES = 16 * 1024 * 1024  # 16 MiB

_TRANSPORT_ENV = "VSIFY_SANDBOX_TRANSPORT"
_ENTRYPOINT_KIND_ENV = "VSIFY_SANDBOX_ENTRYPOINT_KIND"
_ENTRYPOINT_MODULE_ENV = "VSIFY_SANDBOX_ENTRYPOINT_MODULE"
_ENTRYPOINT_LAYOUT_ENV = "VSIFY_SANDBOX_ENTRYPOINT_LAYOUT"
_PACKAGE_FILES_SHA256_ENV = "VSIFY_SANDBOX_PACKAGE_FILES_SHA256"
_ALLOWED_IMPORTS_ENV = "VSIFY_SANDBOX_ALLOWED_IMPORTS"
_SOCKET_ENV = "VSIFY_SANDBOX_SOCKET"


class SetupError(Exception):
    """A fatal setup failure — always exits non-zero, never a degraded/partial serving mode."""


class _StdioChannel:
    def __init__(self) -> None:
        self._in = sys.stdin.buffer
        self._out = sys.stdout.buffer

    def read(self, n: int) -> bytes:
        return self._in.read(n) or b""

    def write(self, data: bytes) -> None:
        self._out.write(data)
        self._out.flush()

    def close(self) -> None:
        pass


class _SocketChannel:
    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock

    def read(self, n: int) -> bytes:
        return self._sock.recv(n)

    def write(self, data: bytes) -> None:
        self._sock.sendall(data)

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


def _connect_channel(transport: str):
    if transport == "stdio":
        return _StdioChannel()
    if transport == "unix_socket":
        path = os.environ.get(_SOCKET_ENV, "")
        if not path:
            raise SetupError("missing_socket_path")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(path)
        return _SocketChannel(sock)
    raise SetupError(f"unsupported_transport:{transport}")


def _load_serve_callable() -> Callable[[bytes], bytes]:
    """Load the bind-mounted entrypoint through the shared loader core (``module_loader.py``).

    ``ENTRYPOINT_PATH`` is read here, at call time, and ``main`` has already started the egress shim.
    For ``python_module`` the loader runs the import-closure analyser on the exact bytes it then
    executes, so a relative or non-stdlib import is a categorical refusal
    (``entrypoint_relative_import`` / ``entrypoint_nonstdlib_import`` / ``entrypoint_unparseable``)
    instead of ``entrypoint_import_failed:ImportError`` from inside the module.

    ``VSIFY_SANDBOX_ENTRYPOINT_LAYOUT`` absent or ``file`` takes exactly that path; ``package`` takes
    :func:`_load_package_serve_callable` (issue #862)."""
    kind = os.environ.get(_ENTRYPOINT_KIND_ENV, "")
    ref = os.environ.get(_ENTRYPOINT_MODULE_ENV, "")
    layout = os.environ.get(_ENTRYPOINT_LAYOUT_ENV, "") or "file"
    if layout == "package":
        return _load_package_serve_callable(kind, ref)
    if layout != "file":
        raise SetupError("unsupported_entrypoint_layout")
    try:
        return module_loader._load_entrypoint(
            ENTRYPOINT_PATH,
            kind,
            ref,
            classify=import_closure._classify_imports,
            validate_ref=import_closure._validate_dotted_ref,
            max_source_bytes=import_closure._MAX_SOURCE_BYTES,
        )
    except module_loader._LoadRefused as exc:
        raise SetupError(exc.reason) from exc


def _declared_imports(segments: tuple) -> tuple:
    """The module's ``core.runtime.imports``, as the host projected them, validated by the SAME rule
    the host used (``import_closure._validate_import_names``) and each confirmed importable in this
    image before READY — so an image missing a declared dependency fails setup, not the first call."""
    raw = os.environ.get(_ALLOWED_IMPORTS_ENV, "")
    names = [name for name in raw.split(",") if name] if raw else []
    try:
        declared = import_closure._validate_import_names(names, segments[0])
    except ValueError as exc:
        raise SetupError(str(exc)) from None
    for name in declared:
        try:
            found = importlib.util.find_spec(name) is not None
        except (ImportError, ValueError):
            found = False
        if not found:
            raise SetupError("declared_import_unavailable")
    return declared


def _load_package_serve_callable(kind: str, ref: str) -> Callable[[bytes], bytes]:
    """``layout: package``: load the package mounted at ``/module/<package segments>`` through the
    shared loader core's ``_load_package``, verifying it against the digest the host signed."""
    if kind != "python_module":
        raise SetupError("unsupported_entrypoint_layout")
    try:
        segments = import_closure._validate_dotted_ref(ref)
    except ValueError:
        raise SetupError("entrypoint_ref_malformed") from None
    if len(segments) < 2:
        raise SetupError("entrypoint_ref_malformed")
    declared = _declared_imports(segments)
    root = os.path.join(PACKAGE_MOUNT_ROOT, *segments[:-1])
    try:
        return module_loader._load_package(
            root,
            ref,
            walk=package_tree._walk_package,
            files_digest=package_tree._files_digest,
            classify_package=import_closure._classify_package,
            validate_ref=import_closure._validate_dotted_ref,
            expected_files_sha256=os.environ.get(_PACKAGE_FILES_SHA256_ENV, ""),
            extra_allowed=frozenset(declared),
            scratch_dir=PACKAGE_SCRATCH_DIR,
        )
    except module_loader._LoadRefused as exc:
        raise SetupError(exc.reason) from exc


def _serve_forever(channel, serve: Callable[[bytes], bytes]) -> None:
    channel.write(framing.encode_frame(framing.FRAME_READY, b""))
    while True:
        try:
            frame_type, payload, _truncated = framing.read_frame(
                channel.read, max_payload_bytes=MAX_REQUEST_BYTES
            )
        except framing.SandboxWireError:
            return  # the host closed the channel or sent a malformed frame — exit cleanly
        if frame_type != framing.FRAME_REQUEST:
            continue  # ignore anything that isn't a request; never desync the channel by replying

        try:
            response = serve(payload)
        except Exception as exc:  # noqa: BLE001 — the module's own fault must not crash the loop
            channel.write(framing.encode_frame(framing.FRAME_ERROR, type(exc).__name__.encode()))
            continue

        truncated = False
        if len(response) > MAX_RESPONSE_BYTES:
            response = response[:MAX_RESPONSE_BYTES]
            truncated = True  # the PRODUCER cut its own output — the only honest use of this flag
        channel.write(framing.encode_frame(framing.FRAME_RESPONSE, response, truncated=truncated))


def _start_egress_shim() -> egress_proxy.EgressProxy:
    """Start the egress shim and export its address to the module's environment (ADR-P048 §7).

    ORDER is the security property: this runs before ``_load_serve_callable`` executes a single
    line of module code, so a module's import-time HTTP calls are proxied too, and a bind failure
    exits before the module exists at all. With no allowlist the container is also on
    ``--network none`` (ADR-P017) and the shim is a deny-all listener: one loopback bind and one
    daemon thread, so that path stays cheap.

    Defence in depth, never the boundary: a module that ignores the proxy variables and opens a
    raw socket is contained by the network posture, not by this."""
    try:
        return egress_proxy.install(os.environ)
    except OSError as exc:
        raise SetupError(f"egress_proxy_bind_failed:{type(exc).__name__}") from exc


def main() -> int:
    transport = os.environ.get(_TRANSPORT_ENV, "")
    try:
        _start_egress_shim()
        serve = _load_serve_callable()
        channel = _connect_channel(transport)
    except SetupError as exc:
        sys.stderr.write(f"vsify-module-sandbox setup failed: {exc}\n")
        return 1

    try:
        _serve_forever(channel, serve)
    finally:
        channel.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
