"""
The in-sandbox egress shim: a default-deny, per-claim forward proxy (ADR-P048 §7, issue #548).

``ContainerIsolationBackend._network_args`` projects a claim's ``egress_allow`` into the container
as ``SANDBOX_EGRESS_ALLOW`` (the entries joined with ``,``). Until this module existed nothing in
the image read it, so on a firewalled egress network shared across claims a module could reach any
host that network admitted, not just the hosts its own claim declared (the ADR-P010 status note
under the ``egress_allow`` grammar decision records that history). This proxy is the reader.

**What it is — and what it is NOT.** It is DEFENCE IN DEPTH, not the containment boundary. A
module can ignore ``HTTP_PROXY``/``HTTPS_PROXY`` and open a raw socket, and nothing in this file can
stop it. The boundary stays where ADR-P017 puts it: ``--network none`` when the claim has no
allowlist, and otherwise the operator-provisioned firewalled egress network. What the shim adds is
that a WELL-BEHAVED module (any HTTP client that honours the standard proxy variables) is narrowed
to its OWN claim on a network that is shared across claims. It must never be described as the thing
that contains a hostile module, because it is not.

**Default-deny, in every direction that can go wrong.**

* An absent or empty ``SANDBOX_EGRESS_ALLOW`` denies every request (the no-allowlist case also runs
  under ``--network none``, so this path only has to be correct and cheap, never permissive).
* A MALFORMED allowlist — any entry the grammar refuses — denies EVERY request, not just requests
  that would have touched the bad entry. That mirrors the host's materialize-time gate
  (``assert_egress_allow_grammar`` refuses the whole list), and it is the only safe reading: a
  partially-honoured allowlist is a policy nobody declared.
* A request the proxy cannot parse unambiguously (no port on ``CONNECT``, an origin-form request
  line, userinfo in the URL, a host outside the DNS/IP-literal character set) is refused with 400,
  never guessed at.
* The upstream connection is made to the NORMALIZED host that was matched — never to a ``Host``
  header, never to a re-resolved alias — so the string that was checked is the string dialled.

**One grammar, two implementations, one pin.** The image cannot import the framework, so the
matcher is a line-for-line mirror of ``vsify_enterprise_mcp/egress_grammar.py``. It lives in
``egress_policy.py`` (ADR-P058 §6), the decision core this shim and the session gateway share, and
is re-exported here unchanged: the same
normalization (strip whitespace, strip dots from BOTH ends, lower-case), the same single ``*.``
wildcard form with a two-label floor, the same LDH label regex, the same refusal of an
address-shaped (decimal, hex or octal) final label, the same no-apex and dot-separated suffix rule,
and the same error codes. The two are held together mechanically, not by review:
``schemas/EGRESS_GRAMMAR.json`` is GENERATED from the framework's own functions and asserted against
BOTH matchers (``tests/test_egress_grammar_vectors.py`` host-side, ``tests/test_egress_proxy.py``
here). A grammar change that is not republished reddens the host; a shim that falls behind the
republished pin reddens this image's build.

**Ports are not part of the grammar.** ``egress_allow`` is hostname-only (the projection carries no
port), so an allowed host is allowed on any port. Narrowing ports is the firewalled network's job,
and inventing a port rule here would be a policy the claim never stated.

**Known residuals, stated rather than implied away.** DNS is not pinned: an allowed name that
resolves to an internal address is reached (the firewalled network is what stops that). The comma
projection means an entry that itself contains ``,`` would arrive here as two entries, and this
module cannot tell the difference. Since issue #560 the host refuses such an entry at the grammar
and refuses to project a list its grammar refuses, so a current host never sends one. An older
host could, which is why the gap is recorded here rather than claimed closed.

**The upstream chain (ADR-P058 §3).** Only when ``SANDBOX_EGRESS_UPSTREAM`` is set (the gateway
topology), a request this shim allows is not dialled directly: it is sent to the session gateway as a
``CONNECT host:port`` carrying the session token in ``Proxy-Authorization``, and the gateway makes
the real decision (port, address, dial). Plain HTTP rides the same CONNECT tunnel. The token is read
from ``VSIFY_EGRESS_TOKEN`` once and popped from the environment, so module code does not inherit it
through ``os.environ``; it is never logged and never forwarded to a client. When the variable is
absent the shim behaves exactly as described above.

Stdlib only, no logging to stdout ever: under the ``stdio`` transport stdout IS the wire channel,
so a single stray byte from this module would desync framing. Diagnostics go to stderr.
"""
from __future__ import annotations

import os
import re
import socket
import socketserver
import threading
from collections.abc import MutableMapping
from urllib.parse import urlsplit

# The byte-level helpers (head reader, authority parser, relay, stderr line) are shared with the
# session gateway and live in ``egress_wire`` under public names (ADR-P058 §6).
from . import egress_wire

# The matcher and the allowlist policy live in the shared decision core (ADR-P058 §6) and are
# re-exported here unchanged, so every existing caller of ``egress_proxy.<name>`` keeps working.
from .egress_policy import (
    EGRESS_ALLOW_ENV,
    EGRESS_WILDCARD_MIN_LABELS,
    EGRESS_WILDCARD_PREFIX,
    TOKEN_ENV,
    EgressGrammarError,
    EgressPolicy,
    _normalize,
    assert_egress_allow_grammar,
    host_matches_egress_allow,
    parse_egress_allow,
    proxy_authorization_value,
)
from .egress_wire import BadRequest, read_head, relay, split_authority

__all__ = [
    "EGRESS_ALLOW_ENV",
    "EGRESS_WILDCARD_MIN_LABELS",
    "EGRESS_WILDCARD_PREFIX",
    "NO_PROXY_ENV_NAMES",
    "PROXY_ENV_NAMES",
    "UPSTREAM_ENV",
    "EgressGrammarError",
    "EgressPolicy",
    "EgressProxy",
    "EgressUpstreamConfigError",
    "assert_egress_allow_grammar",
    "host_matches_egress_allow",
    "install",
    "parse_egress_allow",
]

#: Set only in the gateway topology: ``host:port`` of the session gateway (ADR-P058 §3).
UPSTREAM_ENV = "SANDBOX_EGRESS_UPSTREAM"

#: Every variable a mainstream HTTP client reads to find its proxy. Both cases: Python's
#: ``urllib`` ignores upper-case ``HTTP_PROXY`` under CGI, and curl ignores it entirely, while other
#: clients read only upper-case. ``ALL_PROXY`` routes clients that consult it for other schemes
#: through the same default-deny listener, which refuses what it cannot proxy.
PROXY_ENV_NAMES = (
    "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy",
)

#: Removed from the module's environment. An inherited ``NO_PROXY`` is a bypass list: every host it
#: named would go direct, around the shim, and no claim ever declared one.
NO_PROXY_ENV_NAMES = ("NO_PROXY", "no_proxy")

LOOPBACK = "127.0.0.1"

# --------------------------------------------------------------------------- the proxy

_CLIENT_HEAD_TIMEOUT_S = 30.0
#: The whole request head must arrive within this, however the bytes are spaced (the per-recv
#: timeout alone lets a trickling client hold a connection forever). A normal client sends its head
#: in one write, so for it this changes nothing. The reader itself is the shared ``egress_wire``'s.
_HEAD_DEADLINE_S = egress_wire.HEAD_DEADLINE_S
_CONNECT_TIMEOUT_S = 10.0

#: The prefix of every line this shim writes to stderr (the gateway's is its own).
_LINE_PREFIX = "vsify-module-sandbox egress:"

#: Request headers never forwarded upstream on plain HTTP: proxy credentials and hop-by-hop
#: connection management. ``Connection: close`` is always sent instead, so one client connection
#: can never be reused for a second request to a different host.
_HOP_BY_HOP = frozenset({
    b"connection", b"keep-alive", b"proxy-connection", b"proxy-authorization",
    b"proxy-authenticate", b"te", b"trailer", b"upgrade",
})


#: A ``Proxy-Authorization`` credential must be token68 (RFC 9110 §11.2): no space, CR or LF can
#: reach a header line, whatever the environment held.
_TOKEN68_RE = re.compile(r"\A[A-Za-z0-9._~+/-]+=*\Z")


class EgressUpstreamConfigError(OSError):
    """``SANDBOX_EGRESS_UPSTREAM`` is set but the chain cannot be configured (a malformed gateway
    address, or no usable token). An ``OSError`` on purpose: the entrypoint already turns an
    ``OSError`` from :func:`install` into a setup failure BEFORE the module is imported, so a
    misconfigured chain fails closed exactly as a failed bind does."""


def _chain_request(authority: str, token: str) -> bytes:
    """The CONNECT the shim sends the gateway. The token rides ``Proxy-Authorization`` only."""
    return (
        f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"
        f"Proxy-Authorization: {proxy_authorization_value(token)}\r\n\r\n"
    ).encode("ascii")


def _read_status(sock: socket.socket) -> tuple[int, bytes]:
    """The gateway's status code and any bytes already read past its response head."""
    head, rest = read_head(sock)
    parts = head.split(b"\r\n", 1)[0].decode("ascii").split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/") or not parts[1].isdigit():
        raise BadRequest("malformed_upstream_status")
    return int(parts[1]), rest


class _ProxyHandler(socketserver.BaseRequestHandler):
    server: _ProxyServer

    def _reply(self, status: str) -> None:
        try:
            self.request.sendall(
                f"HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode()
            )
        except OSError:
            pass

    def handle(self) -> None:
        client: socket.socket = self.request
        client.settimeout(_CLIENT_HEAD_TIMEOUT_S)
        try:
            head, leftover = read_head(client, deadline_s=_HEAD_DEADLINE_S)
            lines = head.split(b"\r\n")
            parts = lines[0].decode("ascii").split(" ")
            if len(parts) != 3 or not parts[2].startswith("HTTP/"):
                raise BadRequest("malformed_request_line")
            method, target, version = parts
            if method == "CONNECT":
                host, port = split_authority(target, default_port=None)
                forward: bytes | None = None
            else:
                host, port, forward = self._plain_http(method, target, version, lines[1:])
        except (BadRequest, UnicodeDecodeError, OSError) as exc:
            self._reply("400 Bad Request")
            _note(f"refused malformed request ({type(exc).__name__}: {exc})")
            return

        if not self.server.policy.allows(host):
            # Counted and logged BEFORE the reply, so a client that has read its 403 can rely on
            # both the count and its line having been written.
            self.server.record_denial(host)
            self._reply("403 Forbidden")
            return

        if self.server.upstream is not None:
            # The gateway topology (ADR-P058 §3): never dial directly, chain to the session gateway.
            self._chain(client, host, port, forward, leftover)
            return

        target_host = _normalize(host)
        try:
            upstream = socket.create_connection((target_host, port), timeout=_CONNECT_TIMEOUT_S)
        except OSError as exc:
            self._reply("502 Bad Gateway")
            _note(f"upstream connect to {target_host!r} failed ({type(exc).__name__})")
            return
        try:
            client.settimeout(None)
            upstream.settimeout(None)
            if forward is None:
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                upstream.sendall(forward)
            if leftover:
                upstream.sendall(leftover)
            relay(client, upstream)
        except OSError:
            pass
        finally:
            upstream.close()

    def _chain(
        self, client: socket.socket, host: str, port: int, forward: bytes | None, leftover: bytes
    ) -> None:
        """Carry one allowed request through the session gateway: ``CONNECT host:port`` with the
        token in ``Proxy-Authorization``, then the client's bytes through the tunnel (plain HTTP
        sends its rewritten head first). A gateway 403 reaches the client as 403; any other
        refusal or failure as 502. Neither the token nor a gateway header is ever echoed."""
        target_host = _normalize(host)
        authority = f"[{target_host}]:{port}" if ":" in target_host else f"{target_host}:{port}"
        try:
            upstream = socket.create_connection(self.server.upstream, timeout=_CONNECT_TIMEOUT_S)
        except OSError as exc:
            self._reply("502 Bad Gateway")
            _note(f"egress gateway connect failed ({type(exc).__name__})")
            return
        try:
            try:
                upstream.sendall(_chain_request(authority, self.server.token))
                status, rest = _read_status(upstream)
            except (BadRequest, UnicodeDecodeError, ValueError, OSError) as exc:
                self._reply("502 Bad Gateway")
                _note(f"egress gateway answered unreadably ({type(exc).__name__})")
                return
            if status != 200:
                self._reply("403 Forbidden" if status == 403 else "502 Bad Gateway")
                _note(f"egress gateway refused {target_host!r} (status={status})")
                return
            client.settimeout(None)
            upstream.settimeout(None)
            if forward is None:
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                upstream.sendall(forward)
            if rest:
                client.sendall(rest)
            if leftover:
                upstream.sendall(leftover)
            relay(client, upstream)
        except OSError:
            pass
        finally:
            upstream.close()

    @staticmethod
    def _plain_http(
        method: str, target: str, version: str, header_lines: list[bytes]
    ) -> tuple[str, int, bytes]:
        """An absolute-form ``http://`` request → ``(host, port, rewritten_head)``. Origin-form
        (``GET /path``) is refused: a forward proxy receiving it has only a client-chosen ``Host``
        header to go on, and this proxy never routes on that."""
        parts = urlsplit(target)
        if parts.scheme.lower() != "http" or not parts.netloc:
            raise BadRequest("absolute_http_uri_required")
        if "@" in parts.netloc:
            raise BadRequest("userinfo_refused")
        host, port = split_authority(parts.netloc, default_port=80)
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        out = [f"{method} {path} {version}".encode("ascii")]
        for line in header_lines:
            name = line.split(b":", 1)[0].strip().lower()
            if name in _HOP_BY_HOP:
                continue
            out.append(line)
        out.append(b"Connection: close")
        return host, port, b"\r\n".join(out) + b"\r\n\r\n"


class _ProxyServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False
    # socketserver's default listen backlog is 5: a module opening more than five connections at
    # once (parallel HTTP, batching) would have the excess RESET by the kernel before the accept
    # loop reached them — an outage that looks like an upstream fault, not a policy one.
    request_queue_size = 128

    def __init__(
        self,
        address: tuple[str, int],
        policy: EgressPolicy,
        upstream: tuple[str, int] | None = None,
        token: str = "",
    ) -> None:
        self.policy = policy
        # The gateway chain (ADR-P058 §3); ``None`` is the unchanged ADR-P048 §7 path.
        self.upstream = upstream
        self.token = token
        # Monotonic per-container denial count. The shim is process-isolated from the host's
        # metrics registry, so the count rides the stderr line instead: the HIGHEST
        # `denials_total` in the log is the container's running total, no live tailing needed.
        self._denied_total = 0
        self._denied_lock = threading.Lock()
        super().__init__(address, _ProxyHandler)

    def record_denial(self, host: str) -> int:
        """Count one refused request and write its line; return the new running total.

        The total is assigned under the lock, so every denial gets a unique, gap-free number.
        The line is written AFTER the lock is released: a stalled stderr consumer (log-driver
        backpressure) then blocks only this handler, never every other denial in the container.
        The price is that concurrent denials may write their lines out of order, so the running
        total is the MAXIMUM `denials_total` in the log, not necessarily the last line's."""
        with self._denied_lock:
            self._denied_total += 1
            total = self._denied_total
        _note(f"denied egress to {host!r} ({self.policy.deny_reason}; denials_total={total})")
        return total

    @property
    def denied_total(self) -> int:
        """Requests refused with a 403 so far."""
        with self._denied_lock:
            return self._denied_total

    def handle_error(self, request, client_address) -> None:
        # socketserver's default prints a traceback to STDERR, which is safe, but a module can
        # provoke one per connection; one categorical line is enough.
        _note("handler error")


class EgressProxy:
    """The loopback forward proxy. :meth:`start` binds SYNCHRONOUSLY and raises ``OSError`` on
    failure, so a caller cannot proceed believing a shim exists when it does not."""

    def __init__(
        self,
        policy: EgressPolicy,
        host: str = LOOPBACK,
        port: int = 0,
        poll_interval: float = 0.5,
        upstream: tuple[str, int] | None = None,
        token: str = "",
    ) -> None:
        self.policy = policy
        self._bind = (host, port)
        self._upstream = upstream
        self._token = token
        # How often serve_forever checks for shutdown. Only close() latency depends on it; the
        # entrypoint never closes the shim (it lives exactly as long as the container).
        self._poll_interval = poll_interval
        self._server: _ProxyServer | None = None
        self._thread: threading.Thread | None = None
        # Kept after close(): shutdown() stops the accept loop but does not join daemon handler
        # threads, so a denial already in flight can still land. Reading the live counter keeps
        # denied_total exact; only the shutdown LINE is a point-in-time snapshot.
        self._closed_server: _ProxyServer | None = None

    def start(self) -> tuple[str, int]:
        self._server = _ProxyServer(self._bind, self.policy, self._upstream, self._token)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={"poll_interval": self._poll_interval},
            name="vsify-egress-proxy",
            daemon=True,
        )
        self._thread.start()
        return self.address

    @property
    def address(self) -> tuple[str, int]:
        if self._server is None:
            raise RuntimeError("egress proxy not started")
        host, port = self._server.server_address[:2]
        return str(host), int(port)

    @property
    def url(self) -> str:
        host, port = self.address
        return f"http://{host}:{port}"

    @property
    def denied_total(self) -> int:
        """Requests this shim has refused with a 403, including any that land after :meth:`close`
        from a handler already in flight."""
        server = self._server or self._closed_server
        return server.denied_total if server is not None else 0

    def close(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._closed_server, self._server = self._server, None
            # A snapshot, like every line: an in-flight handler may still write a denial line with
            # a higher total after this one. Read the maximum, never the last line.
            _note(f"shutting down; denials_total={self._closed_server.denied_total}")


def install(environ: MutableMapping[str, str] | None = None) -> EgressProxy:
    """Start the shim for this container and point the module's proxy variables at it.

    Reads ``SANDBOX_EGRESS_ALLOW`` from ``environ`` (default ``os.environ``), binds the proxy on
    loopback, sets every :data:`PROXY_ENV_NAMES` entry to it and removes ``NO_PROXY``. Raises
    ``OSError`` when the proxy cannot bind — the entrypoint turns that into a non-zero exit BEFORE
    the module is imported, so a missing shim fails closed rather than leaving traffic unfiltered.

    ``VSIFY_EGRESS_TOKEN`` is read once and POPPED, whatever else is set, so module code never
    inherits it through ``os.environ``. When ``SANDBOX_EGRESS_UPSTREAM`` is set, allowed requests
    are chained to that gateway with the token (ADR-P058 §3); a malformed gateway address or a
    missing/unusable token raises :class:`EgressUpstreamConfigError` (an ``OSError``) before
    anything binds.
    """
    env = os.environ if environ is None else environ
    token = env.pop(TOKEN_ENV, None)
    upstream = _parse_upstream(env.get(UPSTREAM_ENV), token)
    policy = parse_egress_allow(env.get(EGRESS_ALLOW_ENV))
    if policy.malformed is not None:
        _note(f"{EGRESS_ALLOW_ENV} is malformed ({policy.malformed}); denying ALL egress")
    if upstream is None:
        proxy = EgressProxy(policy)
    else:
        proxy = EgressProxy(policy, upstream=upstream, token=token or "")
    proxy.start()
    url = proxy.url
    for name in PROXY_ENV_NAMES:
        env[name] = url
    for name in NO_PROXY_ENV_NAMES:
        env.pop(name, None)
    return proxy


def _parse_upstream(raw: str | None, token: str | None) -> tuple[str, int] | None:
    """``SANDBOX_EGRESS_UPSTREAM`` → the gateway ``(host, port)``, or ``None`` when it is absent.
    Present but unusable — blank, no port, a bad host, or no token68 token to send — refuses, never
    falls back to dialling directly. The token's value never appears in the error."""
    if raw is None:
        return None
    try:
        host, port = split_authority(raw.strip(), default_port=None)
    except BadRequest as exc:
        raise EgressUpstreamConfigError(f"{UPSTREAM_ENV} is malformed ({exc})") from None
    if not token or not _TOKEN68_RE.match(token):
        raise EgressUpstreamConfigError(f"{UPSTREAM_ENV} is set but {TOKEN_ENV} is absent or unusable")
    return host, port


def _note(message: str) -> None:
    """One diagnostic line to STDERR — never stdout, which is the wire channel under ``stdio``."""
    egress_wire.note(_LINE_PREFIX, message)
