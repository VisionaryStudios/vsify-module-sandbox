"""
The per-session egress gateway (ADR-P058): the sandbox image run with
``VSIFY_SANDBOX_MODE=egress-gateway``, the only container on a session network with a route out.

This file is the SERVER only. Every decision it makes comes from ``egress_policy.py``, the decision
core the module's shim shares (ADR-P058 §6); the byte-level HTTP helpers (head reader, authority
parser, relay, stderr line) are ``egress_wire``'s, which the shim imports too, so neither server
reaches into the other's private names.

**Per request, in order (ADR-P058 §6).**

1. **Token.** Exactly one ``Proxy-Authorization: Bearer <token>`` header whose credential equals
   ``VSIFY_EGRESS_TOKEN`` under :func:`hmac.compare_digest`. Checked BEFORE the request line is
   interpreted, so a request without the token learns nothing about the policy: **407**, reason
   ``token``, and the line carries no target.
2. **Method.** ``CONNECT`` only. Any other method, absolute-URI forwarding of plain HTTP included,
   is **403** ``method``.
3. **Host.** The target must match ``SANDBOX_EGRESS_ALLOW`` under the shared matcher. An IP literal
   passes only when the allowlist names that literal. An unparseable target is ``host`` as well.
4. **Port.** The target port must be in ``VSIFY_EGRESS_PORTS`` (deployment-wide): **403** ``port``.
5. **Address.** The name is resolved ONCE, within a bounded time (:data:`_RESOLVE_TIMEOUT_S`, at most
   :data:`_MAX_RESOLVES` in flight); every address must be ``allowed`` by the address policy, and a
   name that does not resolve in time, or at all, is refused too: **403** ``address``.
6. **Dial.** The gateway connects to a validated IP from that one resolution (never re-resolving the
   name) on the validated port, answers 200 and relays. The tunnel goes nowhere else. The whole dial
   phase shares ONE budget (:data:`_CONNECT_TIMEOUT_S`): each attempt gets the time that is left,
   and an exhausted budget is **502** ``upstream``.

Every 407 body is the same bytes and every 403 body is the same bytes; the reason is only in the
stderr line (ADR-P058 §4, §7). A connection that closes or stalls before sending a request head (the
``--probe`` health check, a port scan) gets no reply and no line, and so does one whose head has not
fully arrived within the overall head deadline (a slowloris trickle), whatever the per-recv timeout.

Decision lines are coalesced (:class:`DecisionLines`): at most one per ``(status, reason, host)`` per
second, in a table bounded at 256 hosted keys (an overflow collapses into ``host=*``). A dropped line
is counted, and the count is written as one ``suppressed count=<n> ...`` summary line for its key by a
timer (each second) and at shutdown, so a module cannot flood the host's log by choosing its own
decision rate. Hosted lines, decision and summary alike, share a per-second budget; past it counts
fold into ``host=*``, so the volume is never hidden, though host identities are then only sampled.

**Bind (ADR-P058 §5).** The gateway is created on the uplink, so the uplink is the interface holding
the default route; the session network is the one other non-loopback interface. The gateway binds
``<session address>:3128`` and nothing else, never a wildcard address. Anything but exactly one
uplink and exactly one session interface with one address, or a failed bind, is
``config error: <reason>`` and exit 1, so the gateway never reports healthy. Interface discovery is
:func:`select_bind_address`, a pure function over ``(iface, address, is_default_route)`` tuples;
:func:`discover_interfaces` reads them from ``/proc/net/route`` and ``SIOCGIFADDR`` in the image.

**Lifecycle.** Once bound it writes its address to ``/tmp/egress-gateway.addr``;
``python -m vsify_sandbox --probe`` (:func:`probe`) makes one TCP connect there and exits 0 or 1.
The gateway serves until its stdin reaches EOF, which is how a host that dies, however it dies,
takes its gateway with it (``docker start -a -i`` plus ``--rm``). The other direction holds too: if
the serve loop ends while stdin is still open, :func:`run` writes ``fatal: listener_stopped`` and
exits 1, so the container stops and ``docker start -a`` returns, and the host sees the gateway die
instead of a live container that no longer serves.

Stdlib only. Nothing is written to stdout; every line goes to stderr with the prefix
``vsify-module-sandbox egress-gateway:``. No line ever carries the token, a header value, or a
resolved address.
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import socketserver
import sys
import threading
import time
from collections.abc import Callable, Iterable, MutableMapping
from dataclasses import dataclass
from pathlib import Path

from .egress_policy import (
    EGRESS_ALLOW_ENV,
    EGRESS_PORTS_ENV,
    REASON_ADDRESS,
    REASON_HOST,
    REASON_METHOD,
    REASON_PORT,
    TOKEN_ENV,
    TOKEN_SCHEME,
    EgressPolicy,
    EgressPortsError,
    _normalize,
    addresses_verdict,
    parse_egress_allow,
    parse_egress_ports,
    target_verdict,
    token_matches,
)
from .egress_wire import BadRequest, note, read_head, relay, split_authority

#: The ``VSIFY_SANDBOX_MODE`` value that selects this server (``__main__`` branches on it).
MODE = "egress-gateway"

#: The port the gateway listens on; the module reaches it as ``vsify-egress-gw:3128``.
GATEWAY_PORT = 3128

#: Written once the listener is bound; read by ``--probe`` (on the gateway's tmpfs).
ADDR_FILE = "/tmp/egress-gateway.addr"

LINE_PREFIX = "vsify-module-sandbox egress-gateway:"

#: The loopback interface's name in the image (Linux). It is never the uplink or the session.
LOOPBACK_IFACE = "lo"

#: Per ``recv`` while reading a request head.
_HEAD_TIMEOUT_S = 10.0
#: For the WHOLE request head, however its bytes are spaced: a client trickling one byte inside the
#: per-recv timeout (slowloris) is dropped here, with no reply and no line, and frees its slot.
_HEAD_DEADLINE_S = 10.0
#: ONE budget for the whole dial phase (ADR-P058 §6 step 6), not per address: a name with several
#: unreachable records would otherwise hold a capacity slot for N x this. Each attempt is given only
#: the time that is left, and an exhausted budget is a 502 ``upstream``.
_CONNECT_TIMEOUT_S = 10.0
#: The resolve step's budget (§6 step 5). ``getaddrinfo`` has no timeout of its own, so it runs in a
#: worker the handler waits on for at most this long; past it the name is refused as ``address``.
_RESOLVE_TIMEOUT_S = 5.0
#: At most this many resolutions in flight at once. A resolver that never answers cannot be
#: interrupted, only abandoned, so the abandoned workers are bounded here; at the cap a new
#: resolution is refused as ``address`` (fail closed) rather than starting one more thread.
_MAX_RESOLVES = 16
#: The ``detail=`` token appended to the ``reason=address`` line when the resolve step ITSELF could not
#: answer, so an outage reads differently from a policy refusal (ADR-P058 §7). A name that simply does
#: not resolve (the resolver raising ``OSError``) is the ordinary refusal and carries no detail.
DETAIL_RESOLVE_TIMEOUT = "resolve_timeout"
DETAIL_RESOLVE_CAP = "resolve_cap"
DETAIL_RESOLVE_ERROR = "resolve_error"
#: Decision lines are coalesced to at most one per key per this window (§7), and pending suppressed
#: counts are flushed on a timer of the same period.
_LINE_WINDOW_S = 1.0
#: At most this many keys that carry a host are tracked at once. A new host beyond it is counted
#: under its ``(status, reason, "*")`` overflow key, so memory is bounded whatever the module sends.
_MAX_LINE_KEYS = 256
#: At most this many lines that carry a host (decision and ``suppressed`` lines together) are written
#: per window, across all hosts. Past it, a hosted line is counted under its ``(status, reason, "*")``
#: overflow key instead, so the line rate is bounded whatever number of hosts the module cycles through.
_HOSTED_LINE_BUDGET = 32
_PROBE_TIMEOUT_S = 2.0
_MAX_CONNECTIONS = 64
_SIOCGIFADDR = 0x8915

#: Uniform response bodies (ADR-P058 §4): one byte string per status, whatever the reason.
RESPONSE_407 = (
    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
    b"Proxy-Authenticate: " + TOKEN_SCHEME.encode("ascii") + b"\r\n"
    b"Content-Length: 0\r\nConnection: close\r\n\r\n"
)
RESPONSE_403 = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
RESPONSE_502 = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
RESPONSE_200 = b"HTTP/1.1 200 Connection Established\r\n\r\n"

#: What a logged host may contain; anything else is replaced, and the value is length-capped.
_LOG_UNSAFE_RE = re.compile(r"[^A-Za-z0-9._:-]")

#: ``(interface name, IPv4/IPv6 address, holds the default route)``.
Interface = tuple[str, str, bool]
Resolver = Callable[[str, int], list[str]]
#: ``(validated address, port), timeout -> connected socket``; ``socket.create_connection`` in prod.
Dialer = Callable[[tuple[str, int], float], socket.socket]


class GatewayConfigError(Exception):
    """A configuration the gateway refuses to serve under. ``reason`` is categorical and is the
    whole of the ``config error:`` line."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class GatewayConfig:
    token: str
    policy: EgressPolicy
    ports: frozenset[int]

    def __repr__(self) -> str:  # never let a stray repr carry the token
        return f"GatewayConfig(policy={self.policy!r}, ports={sorted(self.ports)!r})"


# --------------------------------------------------------------------------- configuration


def load_config(environ: MutableMapping[str, str]) -> GatewayConfig:
    """Read the gateway's environment (ADR-P058 §3). The token is POPPED. An absent token, an
    absent or malformed port list, or an absent or malformed allowlist is a configuration error:
    the gateway exists only for an egress claim, so it never serves a policy nobody sent."""
    token = environ.pop(TOKEN_ENV, None)
    if not token or not token.strip():
        raise GatewayConfigError("token_absent")
    try:
        ports = parse_egress_ports(environ.get(EGRESS_PORTS_ENV))
    except EgressPortsError as exc:
        raise GatewayConfigError(exc.code) from None
    policy = parse_egress_allow(environ.get(EGRESS_ALLOW_ENV))
    if policy.malformed is not None:
        raise GatewayConfigError("egress_allow_malformed")
    if not policy.entries:
        raise GatewayConfigError("egress_allow_absent")
    return GatewayConfig(token=token.strip(), policy=policy, ports=ports)


def select_bind_address(interfaces: Iterable[Interface]) -> str:
    """The session-network address to bind, from ``(iface, address, is_default_route)`` tuples.

    The uplink is the interface holding the default route; the session interface is the one other
    non-loopback interface, and it must carry exactly one address. Anything else raises
    :class:`GatewayConfigError`: guessing between two candidates could put the listener on the
    uplink, which is exactly what the strict bind exists to prevent."""
    entries = [entry for entry in interfaces if entry[0] != LOOPBACK_IFACE]
    uplinks = {iface for iface, _, is_default in entries if is_default}
    if not uplinks:
        raise GatewayConfigError("no_uplink_interface")
    if len(uplinks) > 1:
        raise GatewayConfigError("multiple_uplink_interfaces")
    sessions: dict[str, list[str]] = {}
    for iface, address, _ in entries:
        if iface in uplinks:
            continue
        addresses = sessions.setdefault(iface, [])
        if address not in addresses:
            addresses.append(address)
    if not sessions:
        raise GatewayConfigError("no_session_interface")
    if len(sessions) > 1:
        raise GatewayConfigError("multiple_session_interfaces")
    (addresses,) = sessions.values()
    if len(addresses) != 1:
        raise GatewayConfigError("session_address_ambiguous")
    try:
        parsed = ipaddress.ip_address(addresses[0])
    except ValueError:
        raise GatewayConfigError("session_address_invalid") from None
    if parsed.is_unspecified:
        raise GatewayConfigError("session_address_invalid")
    return str(parsed)


def _ipv4_of(name: str) -> str | None:
    """The interface's IPv4 address via ``SIOCGIFADDR`` (Linux), or ``None``."""
    import fcntl
    import struct

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            packed = fcntl.ioctl(sock.fileno(), _SIOCGIFADDR, struct.pack("256s", name[:15].encode()))
        except OSError:
            return None
    return socket.inet_ntoa(packed[20:24])


def discover_interfaces(route_path: str = "/proc/net/route") -> list[Interface]:
    """The container's interfaces as :data:`Interface` tuples (IPv4; the image's Docker networks
    are IPv4). The default-route interfaces are those with a ``0.0.0.0/0`` row in the route table."""
    try:
        table = Path(route_path).read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError):
        raise GatewayConfigError("route_table_unreadable") from None
    defaults = set()
    for line in table.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 8 and fields[1] == "00000000" and fields[7] == "00000000":
            defaults.add(fields[0])
    found: list[Interface] = []
    for _, name in socket.if_nameindex():
        address = _ipv4_of(name)
        if address is not None:
            found.append((name, address, name in defaults))
    return found


def default_resolver(host: str, port: int) -> list[str]:
    """Resolve ``host`` ONCE: its unique stream addresses, in resolver order."""
    addresses: list[str] = []
    for family, _, _, _, sockaddr in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        address = str(sockaddr[0])
        if address not in addresses:
            addresses.append(address)
    return addresses


# --------------------------------------------------------------------------- the server


def _log_host(value: str) -> str:
    return _LOG_UNSAFE_RE.sub("?", value)[:253] or "?"


#: A coalescing key: ``(status, reason, host)``. Status and reason come from closed sets; the host is
#: the logged (sanitised, capped) host, or ``""`` for a line that names none. Hosted keys are bounded
#: by ``max_keys``; beyond it a host is counted under :data:`OVERFLOW_HOST`.
LineKey = tuple[str, str, str]
#: The host of an overflow key. ``_log_host`` maps ``*`` to ``?``, so no real host can collide.
OVERFLOW_HOST = "*"
KEY_CAPACITY: LineKey = ("none", "capacity", "")
KEY_HANDLER_ERROR: LineKey = ("none", "handler_error", "")


def _summary_line(key: LineKey, count: int) -> str:
    status, reason, host = key
    return f"suppressed count={count} status={status} reason={reason}" + (f" host={host}" if host else "")


class DecisionLines:
    """Coalesces the gateway's decision lines (ADR-P058 §7): at most ONE line per ``(status, reason,
    host)`` key per ``window_s``. The rate of decisions is the module's to choose, and the host
    inherits this stderr, so without a bound a module could flood the host's own log. The host is in
    the key so that one decoy target refused at any rate does not stand in for every other target.

    A line that falls inside its key's window is not written; it is counted. A key's count is
    written as ONE summary line, ``suppressed count=<n> status=<s> reason=<r>[ host=<h>]``, by
    :meth:`flush`: on a timer every ``flush_interval_s`` once the key's window has passed (started
    by :meth:`start`), at :meth:`close` whatever the window, and just before the key's next line
    when that comes first. So the volume is never lost, and a decision line always stands for one
    decision.

    Memory is bounded: at most ``max_keys`` hosted keys are tracked. A key that has written nothing
    for a window and owes no count is evicted; a new host arriving at a full table is counted under
    ``(status, reason, "*")`` instead.

    The line rate is bounded too: at most ``hosted_line_budget`` lines that carry a host, decision
    and summary lines together, are written per budget window, across all hosts. Past it, a hosted
    decision whose own window has passed is accounted under its overflow key instead (written there
    once per window, the rest counted), and a hosted summary folds its count into that overflow key.
    So the volume is never hidden, but beyond the budget host identities are only sampled: with as
    many decoys as the budget in one window, another host's decisions are counted under ``host=*``
    and its name may not appear. The worst case is ``hosted_line_budget`` lines plus two (one
    decision, one summary) for each of the nine host-free and overflow keys, per window.
    Thread-safe; nothing here ever raises."""

    def __init__(
        self,
        write: Callable[[str], None] | None = None,
        clock: Callable[[], float] = time.monotonic,
        window_s: float = _LINE_WINDOW_S,
        *,
        max_keys: int = _MAX_LINE_KEYS,
        flush_interval_s: float | None = _LINE_WINDOW_S,
        hosted_line_budget: int = _HOSTED_LINE_BUDGET,
    ) -> None:
        self._write = _note if write is None else write
        self._clock = clock
        self._window_s = window_s
        self._max_keys = max_keys
        self._budget = hosted_line_budget
        # the current budget window: when it started (None: not yet) and hosted lines written in it
        self._budget_start: float | None = None
        self._budget_used = 0
        self._flush_interval_s = flush_interval_s
        self._lock = threading.Lock()
        # key -> (clock time the key last WROTE a line, decisions suppressed since)
        self._state: dict[LineKey, tuple[float, int]] = {}
        self._hosted = 0  # keys in _state whose host is a real host (not "" or the overflow host)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @staticmethod
    def _is_hosted(key: LineKey) -> bool:
        return key[2] not in ("", OVERFLOW_HOST)

    def _evict(self, now: float) -> None:
        """Drop every key that owes no count and has written nothing for a window. Lock held."""
        for key, (last, count) in list(self._state.items()):
            if count == 0 and now - last >= self._window_s:
                del self._state[key]
                if self._is_hosted(key):
                    self._hosted -= 1

    def _admit(self, key: LineKey, now: float) -> LineKey:
        """The key to account ``key`` under: itself, or its overflow key at a full table. Lock held."""
        if key in self._state or not self._is_hosted(key):
            return key
        if self._hosted >= self._max_keys:
            self._evict(now)
        if self._hosted >= self._max_keys:
            return (key[0], key[1], OVERFLOW_HOST)
        self._hosted += 1  # emit() inserts it next
        return key

    def _spend(self, now: float) -> bool:
        """Take one hosted line from the current window's budget; False when it is spent. Lock held."""
        if self._budget_start is None or now - self._budget_start >= self._window_s:
            self._budget_start, self._budget_used = now, 0
        if self._budget_used >= self._budget:
            return False
        self._budget_used += 1
        return True

    def _fold(self, key: LineKey, count: int, now: float) -> None:
        """Move a hosted key's owed ``count`` to its overflow key: past the budget the volume is kept,
        the identity is not. An absent overflow key is created as one that has written nothing for a
        window, so it reports the count at its next flush or line. Lock held."""
        self._state[key] = (self._state[key][0], 0)
        overflow = (key[0], key[1], OVERFLOW_HOST)
        previous = self._state.get(overflow)
        if previous is None:
            self._state[overflow] = (now - self._window_s, count)
        else:
            self._state[overflow] = (previous[0], previous[1] + count)

    def emit(self, key: LineKey, line: str) -> bool:
        """Write ``line`` unless its key wrote one within the window. Returns whether it was written."""
        try:
            out: list[str] = []
            with self._lock:
                now = self._clock()
                key = self._admit(key, now)
                previous = self._state.get(key)
                if previous is None or now - previous[0] >= self._window_s:
                    if self._is_hosted(key) and not self._spend(now):
                        # Past the budget: account it under the overflow key instead.
                        if previous is None:
                            self._hosted -= 1  # admitted above, never inserted
                        key = (key[0], key[1], OVERFLOW_HOST)
                        previous = self._state.get(key)
                if previous is not None and now - previous[0] < self._window_s:
                    self._state[key] = (previous[0], previous[1] + 1)
                    return False
                if previous is not None and previous[1]:
                    if self._is_hosted(key) and not self._spend(now):
                        self._fold(key, previous[1], now)
                    else:
                        out.append(_summary_line(key, previous[1]))
                self._state[key] = (now, 0)
                out.append(line)
            # Written outside the lock: a stalled stderr blocks only this handler.
            for text in out:
                self._write(text)
            return True
        except Exception:  # a log line must never take a connection down
            return False

    def flush(self, *, force: bool = False) -> int:
        """Write one summary line for each key that owes a count and whose window has passed (every
        such key when ``force``). Evicts idle keys. Returns how many summary lines were written."""
        try:
            out: list[str] = []
            with self._lock:
                now = self._clock()
                # Hosted keys first: a hosted summary spends the window's budget like a decision
                # line, and past it folds its count into the overflow key, written in the second pass.
                for hosted in (True, False):
                    for key, (last, count) in list(self._state.items()):
                        if self._is_hosted(key) != hosted:
                            continue
                        if count and (force or now - last >= self._window_s):
                            if hosted and not self._spend(now):
                                self._fold(key, count, now)
                                continue
                            out.append(_summary_line(key, count))
                            self._state[key] = (now, 0)
                self._evict(now)
            for text in out:
                self._write(text)
            return len(out)
        except Exception:
            return 0

    def start(self) -> None:
        """Start the flush timer (a daemon thread). No-op when ``flush_interval_s`` is ``None``."""
        try:
            if self._flush_interval_s is None or self._thread is not None:
                return
            self._thread = threading.Thread(
                target=self._timer, name="vsify-egress-gateway-lines", daemon=True)
            self._thread.start()
        except Exception:
            self._thread = None

    def _timer(self) -> None:
        while not self._stop.wait(self._flush_interval_s):
            self.flush()

    def close(self) -> None:
        """Stop the timer and write every count still owed (shutdown, stdin EOF)."""
        try:
            self._stop.set()
            if self._thread is not None:
                self._thread.join(timeout=5.0)
        except Exception:
            pass
        self.flush(force=True)


def _header_values(lines: list[bytes], name: bytes) -> list[str]:
    values = []
    for line in lines:
        key, sep, value = line.partition(b":")
        if sep and key.strip().lower() == name:
            values.append(value.strip().decode("latin-1"))
    return values


class _GatewayHandler(socketserver.BaseRequestHandler):
    server: GatewayServer

    def _send(self, payload: bytes) -> None:
        try:
            self.request.sendall(payload)
        except OSError:
            pass

    def _deny(self, status: int, reason: str, line: str, host: str = "") -> None:
        # Logged (or counted, when coalesced) BEFORE the reply, so a client that has read its
        # refusal can rely on the line or its count having been recorded.
        self.server.lines.emit((str(status), reason, host), line)
        self._send(RESPONSE_407 if status == 407 else RESPONSE_403)

    def handle(self) -> None:
        client: socket.socket = self.request
        client.settimeout(_HEAD_TIMEOUT_S)
        try:
            head, leftover = read_head(client, deadline_s=_HEAD_DEADLINE_S)
        except (BadRequest, OSError):
            return  # no request head: a probe, a scan or a stall. No decision, no line.
        lines = head.split(b"\r\n")
        config = self.server.config

        # 1. Token — before the request line is even interpreted.
        presented = _header_values(lines[1:], b"proxy-authorization")
        if len(presented) != 1 or not token_matches(presented[0], config.token):
            self._deny(407, "token", "denied status=407 reason=token")
            return

        # 2. Method.
        parts = lines[0].decode("latin-1").split(" ")
        if len(parts) != 3 or parts[0] != "CONNECT" or not parts[2].startswith("HTTP/"):
            self._deny(403, REASON_METHOD, f"denied status=403 reason={REASON_METHOD}")
            return

        # 3-4. Host, then port.
        try:
            host, port = split_authority(parts[1], default_port=None)
        except BadRequest:
            raw = _log_host(parts[1])
            self._deny(403, REASON_HOST, f"denied status=403 reason={REASON_HOST} host={raw}", raw)
            return
        name = _normalize(host)
        shown = _log_host(name)
        verdict = target_verdict(name, port, config.policy, config.ports)
        if verdict == REASON_HOST:
            self._deny(403, REASON_HOST, f"denied status=403 reason={REASON_HOST} host={shown}", shown)
            return
        if verdict == REASON_PORT:
            line = f"denied status=403 reason={REASON_PORT} host={shown} port={port}"
            self._deny(403, REASON_PORT, line, shown)
            return

        # 5. Address: resolve ONCE (bounded), every address must pass.
        addresses, detail = self.server.resolve(name, port)
        if addresses_verdict(addresses) is not None:
            # The detail rides inside the reason, so it is also part of the coalescing key: an outage
            # (timeout, cap, error) is never folded into a policy refusal's count, nor the reverse,
            # and the ``suppressed`` summary line reads the same way as the decision line.
            reason = REASON_ADDRESS if not detail else f"{REASON_ADDRESS} detail={detail}"
            self._deny(403, reason, f"denied status=403 reason={reason} host={shown}", shown)
            return

        # 6. Dial a validated IP from that resolution, never the name.
        upstream = None
        deadline = time.monotonic() + _CONNECT_TIMEOUT_S
        for address in addresses:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                upstream = self.server.dialer((address, port), remaining)
                break
            except OSError:
                continue
        if upstream is None:
            line = f"failed status=502 reason=upstream host={shown} port={port}"
            self.server.lines.emit(("502", "upstream", shown), line)
            self._send(RESPONSE_502)
            return
        try:
            self.server.lines.emit(("200", "allowed", shown), f"allowed host={shown} port={port}")
            client.settimeout(None)
            upstream.settimeout(None)
            client.sendall(RESPONSE_200)
            if leftover:
                upstream.sendall(leftover)
            relay(client, upstream)
        except OSError:
            pass
        finally:
            upstream.close()


class GatewayServer(socketserver.ThreadingTCPServer):
    """Thread per connection, at most ``max_connections`` at once; an excess connection is closed
    at accept, before a byte is read."""

    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 128

    def __init__(
        self,
        address: tuple[str, int],
        config: GatewayConfig,
        resolver: Resolver = default_resolver,
        max_connections: int = _MAX_CONNECTIONS,
        dialer: Dialer = socket.create_connection,
        lines: DecisionLines | None = None,
    ) -> None:
        self.config = config
        self.resolver = resolver
        self.dialer = dialer
        self.lines = DecisionLines() if lines is None else lines
        self._slots = threading.BoundedSemaphore(max_connections)
        self._resolves = threading.BoundedSemaphore(_MAX_RESOLVES)
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address, _GatewayHandler)

    def resolve(self, name: str, port: int) -> tuple[list[str], str | None]:
        """Resolve ``name`` once, within :data:`_RESOLVE_TIMEOUT_S` (ADR-P058 §6 step 5).

        Returns ``(addresses, detail)``. Every way this cannot produce an answer returns ``[]``, which
        the caller refuses as ``address``: the resolver raising, the deadline passing, and the
        in-flight cap being reached. ``detail`` says which, so an outage is not logged as a policy
        refusal: ``None`` for an answer and for the ordinary "this name does not resolve" (the resolver
        raising ``OSError``, ``UnicodeError`` or ``ValueError``); otherwise one of the ``DETAIL_*``
        tokens. The worker is a daemon holding one of :data:`_MAX_RESOLVES` permits until the resolver
        returns, so an abandoned worker stays counted and the number of them is bounded."""
        if not self._resolves.acquire(blocking=False):
            return [], DETAIL_RESOLVE_CAP
        outcome: list[tuple[list[str], str | None]] = []

        def work() -> None:
            try:
                outcome.append((list(self.resolver(name, port)), None))
            except (OSError, UnicodeError, ValueError):
                outcome.append(([], None))
            except Exception:  # noqa: BLE001 — a resolver that cannot answer refuses, never admits
                outcome.append(([], DETAIL_RESOLVE_ERROR))
            finally:
                self._resolves.release()

        worker = threading.Thread(target=work, name="vsify-egress-gateway-resolve", daemon=True)
        try:
            worker.start()
        except RuntimeError:  # no thread could be started: refuse, and give the permit back
            self._resolves.release()
            return [], DETAIL_RESOLVE_ERROR
        worker.join(_RESOLVE_TIMEOUT_S)
        return outcome[0] if outcome else ([], DETAIL_RESOLVE_TIMEOUT)

    def process_request(self, request, client_address) -> None:
        if not self._slots.acquire(blocking=False):
            self.lines.emit(KEY_CAPACITY, "connection dropped: at capacity")
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        # socketserver.ThreadingMixIn's body, with the slot freed BEFORE the socket is closed: a
        # client that has seen its connection end can reconnect at once and is never dropped at
        # capacity by a slot its own finished connection still held.
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self._slots.release()
            self.shutdown_request(request)

    def handle_error(self, request, client_address) -> None:
        self.lines.emit(KEY_HANDLER_ERROR, "handler error")


# --------------------------------------------------------------------------- lifecycle


def _format_address(address: tuple) -> str:
    host, port = str(address[0]), int(address[1])
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def write_addr_file(path: str, address: tuple) -> None:
    """Write the bound ``host:port`` atomically, so ``--probe`` never reads a partial file."""
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="ascii") as handle:
        handle.write(_format_address(address) + "\n")
    os.replace(tmp, path)


def probe(addr_file: str = ADDR_FILE, timeout: float = _PROBE_TIMEOUT_S) -> int:
    """``--probe``: ONE TCP connect to the address the gateway wrote. 0 when it connects, else 1.
    Sends nothing, so the gateway records no decision for it."""
    try:
        text = Path(addr_file).read_text(encoding="ascii").strip()
        host, port = split_authority(text, default_port=None)
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except (OSError, ValueError, BadRequest):
        return 1
    return 0


def _wait_for_eof(stream) -> None:
    """Block until ``stream`` reaches EOF (or cannot be read, which is treated the same).

    Reads the file descriptor with ``os.read`` when there is one, so the waiting thread never holds
    a buffered reader's lock: :func:`run` may return (the serve loop died) while this is still
    blocked, and interpreter shutdown must not stall on that lock."""
    if stream is None:
        return
    try:
        fd = stream.fileno()
    except (AttributeError, OSError, ValueError):
        fd = None
    try:
        if fd is not None:
            while os.read(fd, 4096):
                pass
            return
        raw = getattr(stream, "buffer", stream)
        while raw.read(4096):
            pass
    except (OSError, ValueError):
        return


#: :func:`run`'s categorical line when the serve loop ends while stdin is still open (exit 1).
FATAL_LISTENER_STOPPED = "fatal: listener_stopped"


def run(
    environ: MutableMapping[str, str] | None = None,
    stdin=None,
    *,
    interfaces: Iterable[Interface] | None = None,
    resolver: Resolver = default_resolver,
    port: int = GATEWAY_PORT,
    addr_file: str = ADDR_FILE,
    max_connections: int = _MAX_CONNECTIONS,
    dialer: Dialer = socket.create_connection,
    lines: DecisionLines | None = None,
) -> int:
    """Configure, bind strictly, publish the address, serve until stdin EOF. Returns the exit
    code: 0 after EOF; 1 on any configuration error (one ``config error:`` line); 1 when the serve
    loop ends first (one ``fatal: listener_stopped`` line), so the container exits and the host's
    ``docker start -a`` sees the gateway die."""
    env = os.environ if environ is None else environ
    try:
        config = load_config(env)
        found = discover_interfaces() if interfaces is None else interfaces
        host = select_bind_address(found)
        try:
            server = GatewayServer((host, port), config, resolver, max_connections, dialer, lines)
        except OSError:
            raise GatewayConfigError("bind_failed") from None
        try:
            write_addr_file(addr_file, server.server_address)
        except OSError:
            server.server_close()
            raise GatewayConfigError("addr_file_unwritable") from None
    except GatewayConfigError as exc:
        _note(f"config error: {exc.reason}")
        return 1

    # Whichever ends first decides: stdin EOF (the host is gone or released us, exit 0) or the
    # serve loop (it should only ever end by our own shutdown(), so ending first is a fault, exit 1).
    ended = threading.Event()
    first: list[str] = []

    def _serve() -> None:
        try:
            server.serve_forever(poll_interval=0.2)
        except BaseException:  # noqa: BLE001 — any way the loop ends is reported the same
            pass
        finally:
            first.append("serve")
            ended.set()

    def _stdin() -> None:
        _wait_for_eof(sys.stdin if stdin is None else stdin)
        first.append("eof")
        ended.set()

    threading.Thread(target=_serve, name="vsify-egress-gateway", daemon=True).start()
    server.lines.start()
    threading.Thread(target=_stdin, name="vsify-egress-gateway-stdin", daemon=True).start()
    serve_died = False
    try:
        ended.wait()
        serve_died = bool(first) and first[0] == "serve"
    finally:
        # shutdown() waits for serve_forever to acknowledge; a loop that already ended cannot.
        if not serve_died:
            server.shutdown()
        server.server_close()
        server.lines.close()
    if serve_died:
        _note(FATAL_LISTENER_STOPPED)
        return 1
    return 0


def main() -> int:
    return run()


def _note(message: str) -> None:
    """One categorical line to STDERR (ADR-P058 §7)."""
    note(LINE_PREFIX, message)
