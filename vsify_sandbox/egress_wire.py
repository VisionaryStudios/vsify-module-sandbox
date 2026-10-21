"""
The byte-level HTTP helpers the module shim and the session gateway share (ADR-P058 §6).

The shim (``egress_proxy.py``) and the gateway (``egress_gateway.py``) both read a CONNECT request
head, parse its authority, relay bytes, and write one diagnostic line to stderr. Those four jobs
live here under public names so neither server reaches into the other's private namespace: a change
to a helper is then a change to a module both import, visible to a reader and to a tool, instead of
an underscore name one sibling quietly depended on.

Policy lives elsewhere. Every allow/deny decision is ``egress_policy.py``'s; this file only moves
and frames bytes. Stdlib only, and nothing here writes to stdout (under the ``stdio`` transport
stdout IS the wire channel): :func:`note` goes to stderr.
"""
from __future__ import annotations

import re
import selectors
import socket
import sys
import time

#: The most bytes a request head may occupy before it is refused (``head_too_large``).
MAX_HEAD_BYTES = 64 * 1024

#: The default bound on the WHOLE request head, however its bytes are spaced (the per-recv timeout
#: alone lets a trickling client hold a connection forever). Callers pass their own; this is the
#: default for one that does not.
HEAD_DEADLINE_S = 30.0

#: A relayed pair that moves no byte in either direction for this long is closed.
RELAY_IDLE_TIMEOUT_S = 300.0
RELAY_CHUNK = 64 * 1024

#: A request host must be a DNS name or an IP literal — letters, digits, ``-``, ``.``, ``_`` and,
#: for IPv6, ``:``. Anything else (whitespace, ``%``, ``@``, control bytes) is refused before it can
#: reach the matcher or the resolver. Narrower than the grammar on purpose: an entry that needs a
#: character outside this set is unreachable, which is the fail-closed direction.
HOST_CHARS_RE = re.compile(r"\A[A-Za-z0-9._:-]+\Z")


class BadRequest(Exception):
    """The request cannot be parsed unambiguously — refused with 400 (shim) or dropped (gateway)."""


def split_authority(authority: str, default_port: int | None) -> tuple[str, int]:
    """``host:port`` / ``[v6]:port`` → ``(host, port)``. The port is REQUIRED when
    ``default_port`` is ``None`` (``CONNECT``), and must be a decimal 1..65535."""
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0:
            raise BadRequest("unterminated_ipv6_literal")
        host, rest = authority[1:end], authority[end + 1:]
        if rest and not rest.startswith(":"):
            raise BadRequest("malformed_authority")
        port_text = rest[1:] if rest else ""
    elif authority.count(":") == 1:
        host, port_text = authority.split(":", 1)
    elif ":" in authority:
        raise BadRequest("unbracketed_ipv6_literal")
    else:
        host, port_text = authority, ""
    if not port_text:
        if default_port is None:
            raise BadRequest("port_required")
        port = default_port
    else:
        if not port_text.isdigit() or not port_text.isascii():
            raise BadRequest("malformed_port")
        port = int(port_text)
        if not 1 <= port <= 65535:
            raise BadRequest("malformed_port")
    if not host or not HOST_CHARS_RE.match(host):
        raise BadRequest("malformed_host")
    return host, port


def read_head(sock: socket.socket, deadline_s: float = HEAD_DEADLINE_S) -> tuple[bytes, bytes]:
    """Read up to the end of the request head. Returns ``(head, already_read_body_bytes)``.

    Two bounds, both enforced here so the shim and the gateway share them. The socket's own
    timeout (set by the caller) bounds each ``recv``; ``deadline_s`` bounds the WHOLE head, so a
    peer that trickles one byte just inside the per-recv timeout (slowloris) cannot hold the
    connection, a thread and a gateway capacity slot open indefinitely. Past the deadline this
    raises ``BadRequest("head_deadline")``. The socket's timeout is restored on every path."""
    per_recv = sock.gettimeout()
    deadline = time.monotonic() + deadline_s
    buf = b""
    try:
        while b"\r\n\r\n" not in buf:
            if len(buf) > MAX_HEAD_BYTES:
                raise BadRequest("head_too_large")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BadRequest("head_deadline")
            sock.settimeout(remaining if per_recv is None else min(per_recv, remaining))
            try:
                chunk = sock.recv(8192)
            except TimeoutError:
                if deadline - time.monotonic() <= 0:
                    raise BadRequest("head_deadline") from None
                raise
            if not chunk:
                raise BadRequest("client_closed")
            buf += chunk
    finally:
        try:
            sock.settimeout(per_recv)
        except OSError:
            pass
    head, _, rest = buf.partition(b"\r\n\r\n")
    if len(head) > MAX_HEAD_BYTES:
        raise BadRequest("head_too_large")
    return head, rest


def relay(a: socket.socket, b: socket.socket) -> None:
    """Shuttle bytes both ways until both directions have closed, either side errors, or the pair
    goes idle. An EOF on one side is propagated as a half-close (``SHUT_WR``) to the other, so a
    client that finishes sending still receives the whole response."""
    peers = {a: b, b: a}
    reading = {a, b}
    sel = selectors.DefaultSelector()
    try:
        for sock in reading:
            sel.register(sock, selectors.EVENT_READ)
        while reading:
            events = sel.select(timeout=RELAY_IDLE_TIMEOUT_S)
            if not events:
                return
            for key, _ in events:
                src = key.fileobj
                dst = peers[src]
                try:
                    data = src.recv(RELAY_CHUNK)
                except OSError:
                    return
                if not data:
                    sel.unregister(src)
                    reading.discard(src)
                    try:
                        dst.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    continue
                try:
                    dst.sendall(data)
                except OSError:
                    return
    finally:
        sel.close()


def note(prefix: str, message: str) -> None:
    """One diagnostic line to STDERR — never stdout, which is the wire channel under ``stdio``.
    ``prefix`` is the caller's own (the shim's and the gateway's differ), and the whole line is
    best-effort: a closed or broken stderr must never take a handler down."""
    try:
        sys.stderr.write(f"{prefix} {message}\n")
        sys.stderr.flush()
    except (OSError, ValueError):
        pass
