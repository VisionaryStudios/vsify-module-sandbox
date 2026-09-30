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
matcher below is a line-for-line mirror of ``vsify_enterprise_mcp/egress_grammar.py``: the same
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

Stdlib only, no logging to stdout ever: under the ``stdio`` transport stdout IS the wire channel,
so a single stray byte from this module would desync framing. Diagnostics go to stderr.
"""
from __future__ import annotations

import functools
import os
import re
import selectors
import socket
import socketserver
import sys
import threading
import unicodedata
from collections.abc import Iterable, MutableMapping
from dataclasses import dataclass
from urllib.parse import urlsplit

EGRESS_ALLOW_ENV = "SANDBOX_EGRESS_ALLOW"

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

# --------------------------------------------------------------------------- the mirrored grammar
# Everything in this block mirrors vsify_enterprise_mcp/egress_grammar.py. The regexes are copied
# VERBATIM and applied with `fullmatch`, as the framework applies them, because the golden vectors
# pin the framework's behaviour exactly. "Tidying" one side is how the two matchers would start to
# disagree.

#: The ONLY wildcard form: exactly one LEADING label wildcard (``*.sharepoint.com``).
EGRESS_WILDCARD_PREFIX = "*."

#: Minimum labels after the wildcard prefix: ``*.sharepoint.com`` accepted, ``*.com`` refused.
EGRESS_WILDCARD_MIN_LABELS = 2

_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
_NUMERIC_LABEL_RE = re.compile(r"^([0-9]+|0x[0-9a-f]+)$")


class EgressGrammarError(ValueError):
    """A malformed ``egress_allow`` entry. ``code`` is the framework's own ``KindUnsupported``
    reason string, so the golden vectors can assert that both matchers refuse for the SAME reason,
    not merely that both refuse."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _has_forbidden_character(entry: str) -> bool:
    """Mirror of ``egress_grammar._has_forbidden_character``: a comma, whitespace
    (``str.isspace``) or a control character (Unicode category ``Cc``) left inside a normalized
    entry. A deny-list, as on the host, so literals such as ``::1`` keep their meaning."""
    return any(ch == "," or ch.isspace() or unicodedata.category(ch) == "Cc" for ch in entry)


def _normalize(value: str) -> str:
    """Mirror of ``egress_grammar._normalize``: strip whitespace, strip dots from BOTH ends,
    lower-case. A leading-dot entry (``.sharepoint.com``) therefore means the bare apex only — it
    never silently becomes a wildcard."""
    return (value or "").strip().strip(".").lower()


@functools.lru_cache(maxsize=1024)
def _wildcard_suffix(entry: str) -> str | None:
    """Mirror of ``egress_grammar._wildcard_suffix``: the suffix a wildcard delegates to, ``None``
    for a literal host, and a RAISE (never ``None``) for a malformed wildcard — returning ``None``
    would let a refused pattern be compared as an opaque literal, the fail-open direction.

    Cached like the framework original (PR 452 f-6): a pure function of one string, called on every
    proxied request. A raise is not cached, so a refused entry re-raises every time."""
    normalized = _normalize(entry)
    if _has_forbidden_character(normalized):
        raise EgressGrammarError("egress_allow_forbidden_character")
    if "*" not in normalized:
        return None
    if not normalized.startswith(EGRESS_WILDCARD_PREFIX):
        raise EgressGrammarError("egress_allow_malformed_wildcard")
    suffix = normalized[len(EGRESS_WILDCARD_PREFIX):]
    if "*" in suffix:
        raise EgressGrammarError("egress_allow_malformed_wildcard")
    labels = suffix.split(".")
    if len(labels) < EGRESS_WILDCARD_MIN_LABELS:
        raise EgressGrammarError("egress_allow_wildcard_suffix_too_broad")
    if not all(_LABEL_RE.fullmatch(label) for label in labels):
        raise EgressGrammarError("egress_allow_malformed_wildcard")
    if _NUMERIC_LABEL_RE.fullmatch(labels[-1]):
        raise EgressGrammarError("egress_allow_malformed_wildcard")
    return suffix


def assert_egress_allow_grammar(egress_allow: Iterable[str]) -> None:
    """Mirror of ``egress_grammar.assert_egress_allow_grammar``: every entry is a literal host or a
    well-formed wildcard, else :class:`EgressGrammarError`."""
    for entry in egress_allow:
        _wildcard_suffix(entry)


def host_matches_egress_allow(host: str, egress_allow: Iterable[str]) -> bool:
    """Mirror of ``egress_grammar.host_matches_egress_allow``, including its evaluation ORDER: a
    literal hit returns before a later malformed entry is examined, and a malformed entry reached
    first raises. The proxy never relies on that order — :func:`parse_egress_allow` refuses the
    whole list up front — but the mirror must reproduce it, or the vectors would disagree."""
    normalized = _normalize(host)
    if not normalized:
        return False
    for raw in egress_allow:
        entry = _normalize(raw)
        if not entry:
            continue
        suffix = _wildcard_suffix(entry)
        if suffix is None:
            if normalized == entry:
                return True
        elif normalized.endswith("." + suffix):
            return True
    return False


# --------------------------------------------------------------------------- the policy


@dataclass(frozen=True)
class EgressPolicy:
    """The allowlist the proxy enforces. ``malformed`` carries the grammar error code when the
    projected list was refused — in which case ``entries`` is empty and every request is denied."""

    entries: tuple[str, ...] = ()
    malformed: str | None = None

    @property
    def deny_reason(self) -> str:
        """Why a denied request was denied — categorical, for the stderr diagnostic only."""
        if self.malformed is not None:
            return f"allowlist malformed: {self.malformed}; all egress denied"
        if not self.entries:
            return "no allowlist; all egress denied"
        return "not in this claim's egress_allow"

    def allows(self, host: str) -> bool:
        if self.malformed is not None or not self.entries:
            return False
        try:
            return host_matches_egress_allow(host, self.entries)
        except EgressGrammarError:  # unreachable after parse_egress_allow; fail closed regardless
            return False


def parse_egress_allow(raw: str | None) -> EgressPolicy:
    """Read the projected ``SANDBOX_EGRESS_ALLOW`` value. Absent or blank → deny-all; any entry the
    grammar refuses → deny-all with the reason recorded. Blank entries (``a.com,,b.com``) are
    skipped, exactly as the host matcher skips them."""
    if raw is None or not raw.strip():
        return EgressPolicy()
    entries = tuple(raw.split(","))
    try:
        assert_egress_allow_grammar(entries)
    except EgressGrammarError as exc:
        return EgressPolicy(entries=(), malformed=exc.code)
    return EgressPolicy(entries=tuple(e for e in entries if _normalize(e)))


# --------------------------------------------------------------------------- the proxy

_MAX_HEAD_BYTES = 64 * 1024
_CLIENT_HEAD_TIMEOUT_S = 30.0
_CONNECT_TIMEOUT_S = 10.0
_RELAY_IDLE_TIMEOUT_S = 300.0
_RELAY_CHUNK = 64 * 1024

#: A request host must be a DNS name or an IP literal — letters, digits, ``-``, ``.``, ``_`` and,
#: for IPv6, ``:``. Anything else (whitespace, ``%``, ``@``, control bytes) is refused before it can
#: reach the matcher or the resolver. Narrower than the grammar on purpose: an entry that needs a
#: character outside this set is unreachable, which is the fail-closed direction.
_HOST_CHARS_RE = re.compile(r"\A[A-Za-z0-9._:-]+\Z")

#: Request headers never forwarded upstream on plain HTTP: proxy credentials and hop-by-hop
#: connection management. ``Connection: close`` is always sent instead, so one client connection
#: can never be reused for a second request to a different host.
_HOP_BY_HOP = frozenset({
    b"connection", b"keep-alive", b"proxy-connection", b"proxy-authorization",
    b"proxy-authenticate", b"te", b"trailer", b"upgrade",
})


class _BadRequest(Exception):
    """The request cannot be parsed unambiguously — refused with 400."""


def _split_authority(authority: str, default_port: int | None) -> tuple[str, int]:
    """``host:port`` / ``[v6]:port`` → ``(host, port)``. The port is REQUIRED when
    ``default_port`` is ``None`` (``CONNECT``), and must be a decimal 1..65535."""
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0:
            raise _BadRequest("unterminated_ipv6_literal")
        host, rest = authority[1:end], authority[end + 1:]
        if rest and not rest.startswith(":"):
            raise _BadRequest("malformed_authority")
        port_text = rest[1:] if rest else ""
    elif authority.count(":") == 1:
        host, port_text = authority.split(":", 1)
    elif ":" in authority:
        raise _BadRequest("unbracketed_ipv6_literal")
    else:
        host, port_text = authority, ""
    if not port_text:
        if default_port is None:
            raise _BadRequest("port_required")
        port = default_port
    else:
        if not port_text.isdigit() or not port_text.isascii():
            raise _BadRequest("malformed_port")
        port = int(port_text)
        if not 1 <= port <= 65535:
            raise _BadRequest("malformed_port")
    if not host or not _HOST_CHARS_RE.match(host):
        raise _BadRequest("malformed_host")
    return host, port


def _read_head(sock: socket.socket) -> tuple[bytes, bytes]:
    """Read up to the end of the request head. Returns ``(head, already_read_body_bytes)``."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        if len(buf) > _MAX_HEAD_BYTES:
            raise _BadRequest("head_too_large")
        chunk = sock.recv(8192)
        if not chunk:
            raise _BadRequest("client_closed")
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    if len(head) > _MAX_HEAD_BYTES:
        raise _BadRequest("head_too_large")
    return head, rest


def _relay(a: socket.socket, b: socket.socket) -> None:
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
            events = sel.select(timeout=_RELAY_IDLE_TIMEOUT_S)
            if not events:
                return
            for key, _ in events:
                src = key.fileobj
                dst = peers[src]
                try:
                    data = src.recv(_RELAY_CHUNK)
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
            head, leftover = _read_head(client)
            lines = head.split(b"\r\n")
            parts = lines[0].decode("ascii").split(" ")
            if len(parts) != 3 or not parts[2].startswith("HTTP/"):
                raise _BadRequest("malformed_request_line")
            method, target, version = parts
            if method == "CONNECT":
                host, port = _split_authority(target, default_port=None)
                forward: bytes | None = None
            else:
                host, port, forward = self._plain_http(method, target, version, lines[1:])
        except (_BadRequest, UnicodeDecodeError, OSError) as exc:
            self._reply("400 Bad Request")
            _note(f"refused malformed request ({type(exc).__name__}: {exc})")
            return

        if not self.server.policy.allows(host):
            # Counted and logged BEFORE the reply, so a client that has read its 403 can rely on
            # both the count and its line having been written.
            self.server.record_denial(host)
            self._reply("403 Forbidden")
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
            _relay(client, upstream)
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
            raise _BadRequest("absolute_http_uri_required")
        if "@" in parts.netloc:
            raise _BadRequest("userinfo_refused")
        host, port = _split_authority(parts.netloc, default_port=80)
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

    def __init__(self, address: tuple[str, int], policy: EgressPolicy) -> None:
        self.policy = policy
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
        self, policy: EgressPolicy, host: str = LOOPBACK, port: int = 0, poll_interval: float = 0.5
    ) -> None:
        self.policy = policy
        self._bind = (host, port)
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
        self._server = _ProxyServer(self._bind, self.policy)
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
    """
    env = os.environ if environ is None else environ
    policy = parse_egress_allow(env.get(EGRESS_ALLOW_ENV))
    if policy.malformed is not None:
        _note(f"{EGRESS_ALLOW_ENV} is malformed ({policy.malformed}); denying ALL egress")
    proxy = EgressProxy(policy)
    proxy.start()
    url = proxy.url
    for name in PROXY_ENV_NAMES:
        env[name] = url
    for name in NO_PROXY_ENV_NAMES:
        env.pop(name, None)
    return proxy


def _note(message: str) -> None:
    """One diagnostic line to STDERR — never stdout, which is the wire channel under ``stdio``."""
    try:
        sys.stderr.write(f"vsify-module-sandbox egress: {message}\n")
        sys.stderr.flush()
    except (OSError, ValueError):
        pass
