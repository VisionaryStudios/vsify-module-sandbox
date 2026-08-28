"""
The vsify-module-sandbox entrypoint (ADR-P041, vsify-enterprise-mcp).

Dispatch env vars (all non-secret, set by ``ContainerIsolationBackend._build_serving_argv``):

- ``VSIFY_SANDBOX_TRANSPORT``: ``"stdio"`` | ``"unix_socket"``
- ``VSIFY_SANDBOX_ENTRYPOINT_KIND``: ``"script"`` | ``"python_module"`` (always set)
- ``VSIFY_SANDBOX_ENTRYPOINT_MODULE``: the dotted ref (only set for ``python_module``)
- ``VSIFY_SANDBOX_SOCKET``: the in-container socket path (only set for ``unix_socket``)

The module to serve is ALWAYS bind-mounted read-only at ``/module/entrypoint`` by the host — this
entrypoint never resolves a file path from the dotted ref itself (see ``entrypoint_resolve.py``'s
docstring). It loads that one file, binds its required ``serve(payload: bytes) -> bytes``
callable, and serves REQUEST frames until the channel closes.

Exits non-zero (never a degraded/partial mode) on any setup failure — a missing ``serve``
callable, a malformed dotted ref, or an unsupported transport/kind are all refusals, matching the
host's own "never fall back, always fail closed" posture (ADR-P010).
"""
from __future__ import annotations

import importlib.util
import os
import socket
import sys
from importlib.machinery import SourceFileLoader
from types import ModuleType
from typing import Callable

from . import framing
from .entrypoint_resolve import EntrypointRefMalformed, validate_dotted_ref

ENTRYPOINT_PATH = "/module/entrypoint"
MAX_REQUEST_BYTES = 4 * 1024 * 1024  # 4 MiB — mirrors isolation/serving_contracts.py
MAX_RESPONSE_BYTES = 16 * 1024 * 1024  # 16 MiB

_TRANSPORT_ENV = "VSIFY_SANDBOX_TRANSPORT"
_ENTRYPOINT_KIND_ENV = "VSIFY_SANDBOX_ENTRYPOINT_KIND"
_ENTRYPOINT_MODULE_ENV = "VSIFY_SANDBOX_ENTRYPOINT_MODULE"
_SOCKET_ENV = "VSIFY_SANDBOX_SOCKET"

_SUPPORTED_KINDS = frozenset({"script", "python_module"})


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
    kind = os.environ.get(_ENTRYPOINT_KIND_ENV, "")
    if kind not in _SUPPORTED_KINDS:
        raise SetupError(f"unsupported_entrypoint_kind:{kind}")

    module_name = "vsify_sandbox_entrypoint_module"
    if kind == "python_module":
        ref = os.environ.get(_ENTRYPOINT_MODULE_ENV, "")
        try:
            segments = validate_dotted_ref(ref)
        except EntrypointRefMalformed as exc:
            raise SetupError(str(exc)) from exc
        module_name = "_".join(segments) or module_name  # for __name__/log messages only

    if not os.path.isfile(ENTRYPOINT_PATH):
        raise SetupError("entrypoint_missing")

    # The host bind-mounts the resolved file at a FIXED, extension-less path
    # ("/module/entrypoint" — never "entrypoint.py"), so `spec_from_file_location`'s default
    # suffix-based loader inference finds no match and silently returns `None`. An explicit
    # `SourceFileLoader` is required regardless of the on-disk file's original extension.
    loader = SourceFileLoader(module_name, ENTRYPOINT_PATH)
    spec = importlib.util.spec_from_file_location(module_name, ENTRYPOINT_PATH, loader=loader)
    if spec is None or spec.loader is None:
        raise SetupError("entrypoint_unloadable")
    module: ModuleType = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001 — any import-time failure is a setup refusal
        raise SetupError(f"entrypoint_import_failed:{type(exc).__name__}") from exc

    serve = getattr(module, "serve", None)
    if not callable(serve):
        raise SetupError("serve_callable_missing")
    return serve


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


def main() -> int:
    transport = os.environ.get(_TRANSPORT_ENV, "")
    try:
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
