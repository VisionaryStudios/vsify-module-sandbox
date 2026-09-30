"""The sandbox half of the egress-grammar pin, plus the shim's behaviour on real sockets
(ADR-P048 §7, issue #548).

**Parity.** THIS image's matcher (``vsify_sandbox/egress_proxy.py``) against
``schemas/EGRESS_GRAMMAR.json`` — vectors GENERATED from the framework's ``egress_grammar.py``. The
host's ``tests/test_egress_grammar_vectors.py`` asserts the same file against the framework
matcher, so neither matcher can move without the other reddening. Every vector's ``sandbox_env``
is the literal ``SANDBOX_EGRESS_ALLOW`` value the host's ``ContainerIsolationBackend`` projects, so
the proxy is fed the bytes it will really receive, not a re-spelling of the projection.

WHERE THE PIN IS READ FROM, and why there are two answers — identical to
``test_wire_conformance.py``, deliberately:

- **In-tree** (``vsify-enterprise-mcp/sandbox/``): the pin is the host's
  ``../schemas/EGRESS_GRAMMAR.json``. This tree carries NO copy of its own; the host's
  ``tests/test_egress_grammar_vectors.py`` refuses one.
- **In the mirror** (``vsify-module-sandbox``, a generated DO-NOT-EDIT tree): the publisher renders
  the host pin into the mirror's own ``schemas/`` (ADR-P048 §2), so there is no ``..`` to read.

The in-tree layout is recognised by the host package directory sitting beside this tree. An absent
pin is a named failure, never a skip.

**Behaviour.** A CONNECT to a denied host is refused with 403 and never dialled; an allowed one is
tunnelled end to end; an empty or malformed allowlist denies everything; a failed bind stops the
entrypoint before the module is imported. All on loopback, no Docker.
"""
from __future__ import annotations

import json
import socket
import threading
from pathlib import Path

import pytest

from vsify_sandbox import egress_proxy, entrypoint
from vsify_sandbox.egress_proxy import (
    EgressGrammarError,
    EgressPolicy,
    EgressProxy,
    assert_egress_allow_grammar,
    host_matches_egress_allow,
    parse_egress_allow,
)

_SANDBOX_ROOT = Path(__file__).resolve().parent.parent
_HOST_ROOT = _SANDBOX_ROOT.parent
#: The host package directory. Its presence beside this tree is what "in-tree" means.
_HOST_MARKER = _HOST_ROOT / "vsify_enterprise_mcp"
_HOST_PIN = _HOST_ROOT / "schemas" / "EGRESS_GRAMMAR.json"
_MIRROR_PIN = _SANDBOX_ROOT / "schemas" / "EGRESS_GRAMMAR.json"

_TIMEOUT_S = 5.0


def _vectors_path() -> Path:
    in_tree = _HOST_MARKER.is_dir()
    path = _HOST_PIN if in_tree else _MIRROR_PIN
    if not path.is_file():
        layout = "in-tree (host package found beside sandbox/)" if in_tree else "mirror"
        pytest.fail(
            f"EGRESS_GRAMMAR.json not found at {path} ({layout} layout). In-tree, the pin is the "
            f"host's schemas/EGRESS_GRAMMAR.json and sandbox/ must not carry its own copy; in the "
            f"mirror, the publisher renders it into schemas/ (ADR-P048 §2). A missing pin means "
            f"this matcher is being asserted against nothing."
        )
    return path


def _load():
    return json.loads(_vectors_path().read_text())


def _mirror_grammar_error(allow) -> str | None:
    try:
        assert_egress_allow_grammar(allow)
    except EgressGrammarError as exc:
        return exc.code
    return None


# ─────────────────────────────────────────── parity with the generated vectors

def test_the_pinned_constants_match_the_shim():
    doc = _load()
    assert doc["env_var"] == egress_proxy.EGRESS_ALLOW_ENV
    assert doc["wildcard_prefix"] == egress_proxy.EGRESS_WILDCARD_PREFIX
    assert doc["wildcard_min_labels"] == egress_proxy.EGRESS_WILDCARD_MIN_LABELS


def test_every_grammar_vector_agrees_with_the_shim():
    for vector in _load()["grammar_vectors"]:
        got = _mirror_grammar_error(vector["egress_allow"])
        assert got == vector["grammar_error"], f"vector {vector['name']!r}: shim says {got!r}"
        # And through the real projection. Since issue #560 the host refuses to project a list its
        # grammar refuses, so a malformed vector projects nothing and the shim sees deny-all.
        policy = parse_egress_allow(vector["sandbox_env"])
        if vector["grammar_error"] is None:
            assert policy.malformed is None, f"vector {vector['name']!r} (parsed)"
        else:
            assert vector["sandbox_env"] is None, f"vector {vector['name']!r}: host projected it"
            assert not policy.entries and policy.malformed is None


def test_every_match_vector_agrees_with_the_shim_matcher():
    for vector in _load()["match_vectors"]:
        try:
            got = (host_matches_egress_allow(vector["host"], vector["egress_allow"]), None)
        except EgressGrammarError as exc:
            got = (None, exc.code)
        want = (vector["matches"], vector["match_error"])
        assert got == want, f"vector {vector['name']!r}: shim {got!r} != framework {want!r}"


def test_every_match_vector_agrees_with_the_proxy_decision():
    """The decision the proxy actually enforces, from the bytes the host actually projects."""
    for vector in _load()["match_vectors"]:
        policy = parse_egress_allow(vector["sandbox_env"])
        decision = "allow" if policy.allows(vector["host"]) else "deny"
        assert decision == vector["sandbox_decision"], (
            f"vector {vector['name']!r}: proxy would {decision} {vector['host']!r}"
        )


def test_the_negative_control_is_present_and_denied():
    controls = [v for v in _load()["match_vectors"] if v["negative_control"]]
    assert len(controls) == 1, "the pin must carry exactly one seeded negative control"
    control = controls[0]
    assert control["sandbox_decision"] == "deny"
    assert not parse_egress_allow(control["sandbox_env"]).allows(control["host"])


def test_the_vectors_would_catch_a_naive_suffix_matcher():
    """Non-vacuity: a mirror with the classic bug (bare ``endswith``, no separating dot) must
    disagree with the pin somewhere — otherwise agreement above proves nothing."""

    def naive(host, allow):
        host = egress_proxy._normalize(host)
        for raw in allow:
            entry = egress_proxy._normalize(raw)
            if entry and (host == entry or host.endswith(entry.removeprefix("*."))):
                return True
        return False

    disagreements = [
        v["name"] for v in _load()["match_vectors"]
        if v["match_error"] is None and naive(v["host"], v["egress_allow"]) != v["matches"]
    ]
    assert disagreements, "no vector distinguishes a bare-endswith matcher from the real one"


@pytest.mark.parametrize("raw", [None, "", "   ", ",", " , ,"])
def test_an_absent_or_empty_allowlist_denies_everything(raw):
    policy = parse_egress_allow(raw)
    assert policy.malformed is None
    for host in ("graph.microsoft.com", "127.0.0.1", "localhost", "contoso.sharepoint.com"):
        assert not policy.allows(host)


def test_a_malformed_allowlist_denies_even_its_valid_entries():
    policy = parse_egress_allow("graph.microsoft.com,*.com")
    assert policy.malformed == "egress_allow_wildcard_suffix_too_broad"
    assert not policy.allows("graph.microsoft.com")


# ─────────────────────────────────────────── the proxy on real loopback sockets

class _Upstream:
    """A one-shot loopback echo server that counts the connections it accepts."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.sock.settimeout(_TIMEOUT_S)
        self.port = self.sock.getsockname()[1]
        self.accepted = 0
        self.received = b""
        self._closing = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        if self._closing:  # the wake-up connection from close(), not a proxied one
            conn.close()
            return
        self.accepted += 1
        with conn:
            conn.settimeout(_TIMEOUT_S)
            try:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        return
                    self.received += data
                    conn.sendall(data)
            except OSError:
                return

    def close(self) -> None:
        # Closing a listening socket does not interrupt a blocked accept() on every platform, so
        # wake the thread with one throwaway connection it knows to ignore.
        self._closing = True
        try:
            socket.create_connection(("127.0.0.1", self.port), timeout=_TIMEOUT_S).close()
        except OSError:
            pass
        self._thread.join(timeout=_TIMEOUT_S)
        self.sock.close()


@pytest.fixture
def upstream():
    server = _Upstream()
    yield server
    server.close()


@pytest.fixture
def start_proxy():
    started: list[EgressProxy] = []

    def _start(raw: str | None) -> tuple[str, int]:
        proxy = EgressProxy(parse_egress_allow(raw), poll_interval=0.05)
        started.append(proxy)
        return proxy.start()

    yield _start
    for proxy in started:
        proxy.close()


def _ask(address: tuple[str, int], request: bytes) -> tuple[socket.socket, bytes]:
    """Send a request head to the proxy; return the socket and the status line it answered."""
    client = socket.create_connection(address, timeout=_TIMEOUT_S)
    client.sendall(request)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = client.recv(4096)
        if not chunk:
            break
        buf += chunk
    return client, buf.split(b"\r\n", 1)[0]


def test_connect_to_an_allowed_host_is_tunnelled(start_proxy, upstream):
    address = start_proxy("127.0.0.1")
    client, status = _ask(address, f"CONNECT 127.0.0.1:{upstream.port} HTTP/1.1\r\n\r\n".encode())
    with client:
        assert status == b"HTTP/1.1 200 Connection Established"
        client.sendall(b"ping-through-the-tunnel")
        assert client.recv(4096) == b"ping-through-the-tunnel"
    assert upstream.accepted == 1


def test_connect_to_a_denied_host_is_refused_with_403_and_never_dialled(start_proxy, upstream):
    """The upstream is REAL and reachable; only the claim stands between the module and it."""
    address = start_proxy("graph.microsoft.com,*.sharepoint.com")
    client, status = _ask(address, f"CONNECT 127.0.0.1:{upstream.port} HTTP/1.1\r\n\r\n".encode())
    client.close()
    assert status == b"HTTP/1.1 403 Forbidden"
    assert upstream.accepted == 0


def test_a_suffix_lookalike_is_refused(start_proxy):
    address = start_proxy("*.sharepoint.com")
    client, status = _ask(address, b"CONNECT evilsharepoint.com:443 HTTP/1.1\r\n\r\n")
    client.close()
    assert status == b"HTTP/1.1 403 Forbidden"


@pytest.mark.parametrize("raw", [None, "", "127.0.0.1,*.com"], ids=["absent", "empty", "malformed"])
def test_an_empty_or_malformed_allowlist_denies_all(start_proxy, upstream, raw):
    address = start_proxy(raw)
    client, status = _ask(address, f"CONNECT 127.0.0.1:{upstream.port} HTTP/1.1\r\n\r\n".encode())
    client.close()
    assert status == b"HTTP/1.1 403 Forbidden"
    assert upstream.accepted == 0


def test_plain_http_is_rewritten_to_origin_form_and_forwarded(start_proxy, upstream):
    address = start_proxy("127.0.0.1")
    client = socket.create_connection(address, timeout=_TIMEOUT_S)
    with client:
        client.sendall(
            f"GET http://127.0.0.1:{upstream.port}/x?y=1 HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\nProxy-Authorization: Basic c2VjcmV0\r\n"
            f"Connection: keep-alive\r\n\r\n".encode()
        )
        echoed = b""
        while b"\r\n\r\n" not in echoed:
            chunk = client.recv(4096)
            if not chunk:
                break
            echoed += chunk
    assert echoed.startswith(b"GET /x?y=1 HTTP/1.1\r\n")
    assert b"Proxy-Authorization" not in echoed
    assert b"keep-alive" not in echoed
    assert b"Connection: close\r\n" in echoed


def test_plain_http_to_a_denied_host_is_refused(start_proxy, upstream):
    address = start_proxy("graph.microsoft.com")
    client, status = _ask(
        address, f"GET http://127.0.0.1:{upstream.port}/ HTTP/1.1\r\nHost: x\r\n\r\n".encode()
    )
    client.close()
    assert status == b"HTTP/1.1 403 Forbidden"
    assert upstream.accepted == 0


@pytest.mark.parametrize(
    "request_head",
    [
        b"CONNECT 127.0.0.1 HTTP/1.1\r\n\r\n",  # no port
        b"CONNECT 127.0.0.1:99999 HTTP/1.1\r\n\r\n",  # port out of range
        b"CONNECT ::1:443 HTTP/1.1\r\n\r\n",  # unbracketed IPv6
        b"CONNECT bad%20host:443 HTTP/1.1\r\n\r\n",  # outside the host charset
        b"GET /origin-form HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",  # would route on Host header
        b"GET http://127.0.0.1@evil.example/ HTTP/1.1\r\n\r\n",  # userinfo
        b"GET ftp://127.0.0.1/ HTTP/1.1\r\n\r\n",  # not http
        b"NONSENSE\r\n\r\n",
    ],
)
def test_an_ambiguous_request_is_refused_with_400(start_proxy, request_head):
    address = start_proxy("127.0.0.1,evil.example")
    client, status = _ask(address, request_head)
    client.close()
    assert status == b"HTTP/1.1 400 Bad Request"


# ─────────────────────────────────────────── install() and the entrypoint's fail-closed order

def test_install_points_every_proxy_variable_at_the_shim_and_drops_no_proxy(capsys):
    env = {"SANDBOX_EGRESS_ALLOW": "graph.microsoft.com", "NO_PROXY": "*", "no_proxy": "evil"}
    proxy = egress_proxy.install(env)
    try:
        for name in egress_proxy.PROXY_ENV_NAMES:
            assert env[name] == proxy.url
        assert "NO_PROXY" not in env and "no_proxy" not in env
        assert proxy.address[0] == "127.0.0.1", "the shim listens on loopback only"
    finally:
        proxy.close()
    assert capsys.readouterr().out == "", "the shim must never write to stdout (the stdio wire)"


def test_a_malformed_allowlist_is_reported_on_stderr_never_stdout(capsys):
    proxy = egress_proxy.install({"SANDBOX_EGRESS_ALLOW": "*.com"})
    proxy.close()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "egress_allow_wildcard_suffix_too_broad" in captured.err


def test_a_proxy_that_cannot_bind_stops_the_entrypoint_before_the_module_is_imported(
    tmp_path, monkeypatch
):
    marker = tmp_path / "imported"
    module_file = tmp_path / "entrypoint"
    module_file.write_text(
        f"open({str(marker)!r}, 'w').close()\ndef serve(payload):\n    return payload\n"
    )
    monkeypatch.setattr(entrypoint, "ENTRYPOINT_PATH", str(module_file))
    monkeypatch.setenv("VSIFY_SANDBOX_ENTRYPOINT_KIND", "script")
    monkeypatch.setenv("VSIFY_SANDBOX_TRANSPORT", "stdio")

    def _refuse(self):
        raise OSError(98, "Address already in use")

    monkeypatch.setattr(EgressProxy, "start", _refuse)
    assert entrypoint.main() == 1
    assert not marker.exists(), "the module was imported although the egress shim never started"


def test_the_shim_is_started_before_module_code_runs(monkeypatch):
    """ORDER is the property: the module's import-time HTTP calls must already see the proxy."""
    fake_env: dict[str, str] = {"SANDBOX_EGRESS_ALLOW": "graph.microsoft.com"}
    monkeypatch.setattr(entrypoint.os, "environ", fake_env)
    started: list[EgressProxy] = []
    real_install = egress_proxy.install

    def _install(environ=None):
        proxy = real_install(environ)
        started.append(proxy)
        return proxy

    seen: dict[str, str | None] = {}

    def _load():
        seen["HTTPS_PROXY"] = fake_env.get("HTTPS_PROXY")
        raise entrypoint.SetupError("stop_here")

    monkeypatch.setattr(egress_proxy, "install", _install)
    monkeypatch.setattr(entrypoint, "_load_serve_callable", _load)
    try:
        assert entrypoint.main() == 1
        assert started and seen["HTTPS_PROXY"] == started[0].url
    finally:
        for proxy in started:
            proxy.close()


def test_policy_allows_is_fail_closed_on_a_bad_entry_that_slipped_through():
    """``parse_egress_allow`` refuses a malformed list up front; ``allows`` is closed even if a
    policy were ever constructed around one directly."""
    assert not EgressPolicy(entries=("graph.microsoft.com", "*.com")).allows("example.org")


def test_denials_are_counted_and_the_running_total_rides_the_stderr_line(upstream, capsys):
    """Denial VOLUME must be observable without live-tailing: every 403 line carries the
    container's running total, and an allowed request never moves it (PR #555 review f-2)."""
    proxy = EgressProxy(parse_egress_allow("127.0.0.1"), poll_interval=0.05)
    address = proxy.start()
    try:
        for _ in range(3):
            client, status = _ask(address, b"CONNECT denied.example.com:443 HTTP/1.1\r\n\r\n")
            client.close()
            assert status == b"HTTP/1.1 403 Forbidden"
        client, status = _ask(
            address, f"CONNECT 127.0.0.1:{upstream.port} HTTP/1.1\r\n\r\n".encode()
        )
        client.close()
        assert status == b"HTTP/1.1 200 Connection Established"
        assert proxy.denied_total == 3
    finally:
        proxy.close()
    assert proxy.denied_total == 3, "the total must survive close()"
    err = capsys.readouterr().err
    denial_lines = [ln for ln in err.splitlines() if "denied egress to" in ln]
    assert [ln.rsplit("denials_total=", 1)[1].rstrip(")") for ln in denial_lines] == ["1", "2", "3"]
    assert "shutting down; denials_total=3" in err


def test_a_deny_all_policy_counts_every_refusal(capsys):
    proxy = EgressProxy(parse_egress_allow(None), poll_interval=0.05)
    address = proxy.start()
    try:
        for _ in range(2):
            client, status = _ask(address, b"CONNECT a.example.com:443 HTTP/1.1\r\n\r\n")
            client.close()
            assert status == b"HTTP/1.1 403 Forbidden"
        assert proxy.denied_total == 2
    finally:
        proxy.close()
    assert "no allowlist; all egress denied; denials_total=2" in capsys.readouterr().err


def _totals(err: str) -> list[int]:
    return [
        int(ln.rsplit("denials_total=", 1)[1].rstrip(")"))
        for ln in err.splitlines()
        if "denied egress to" in ln
    ]


def test_concurrent_denials_each_get_a_unique_gap_free_total(capsys):
    """One handler thread per connection: N simultaneous denials must yield exactly N, each line
    carrying a distinct total from 1..N. ORDER is deliberately not asserted — the line is written
    outside the lock (see the blocked-writer test), so the running total is the MAXIMUM."""
    from concurrent.futures import ThreadPoolExecutor

    n = 24
    proxy = EgressProxy(parse_egress_allow("allowed.example.com"), poll_interval=0.05)
    address = proxy.start()

    def deny(_):
        client, status = _ask(address, b"CONNECT denied.example.com:443 HTTP/1.1\r\n\r\n")
        client.close()
        return status

    try:
        with ThreadPoolExecutor(max_workers=n) as pool:
            statuses = list(pool.map(deny, range(n)))
        assert statuses == [b"HTTP/1.1 403 Forbidden"] * n, "a burst above the old backlog of 5"
        assert proxy.denied_total == n
    finally:
        proxy.close()
    assert sorted(_totals(capsys.readouterr().err)) == list(range(1, n + 1))


def test_a_blocked_stderr_writer_does_not_stall_other_denials(monkeypatch):
    """The line is written OUTSIDE the counter's lock, so one handler stuck on a stalled log sink
    (docker log-driver backpressure) must not hold every other denial in the container hostage
    (PR #555 review pass 3, f-0)."""
    release = threading.Event()
    stuck = threading.Event()
    real_note = egress_proxy._note

    def note(message: str) -> None:
        if "stall.example.com" in message:
            stuck.set()
            release.wait(_TIMEOUT_S)
        real_note(message)

    monkeypatch.setattr(egress_proxy, "_note", note)
    proxy = EgressProxy(parse_egress_allow(None), poll_interval=0.05)
    address = proxy.start()
    staller = socket.create_connection(address, timeout=_TIMEOUT_S)
    try:
        staller.sendall(b"CONNECT stall.example.com:443 HTTP/1.1\r\n\r\n")
        assert stuck.wait(_TIMEOUT_S), "the first handler never reached its stderr write"
        client = socket.create_connection(address, timeout=1.0)
        client.sendall(b"CONNECT other.example.com:443 HTTP/1.1\r\n\r\n")
        with client:
            assert client.recv(4096).split(b"\r\n", 1)[0] == b"HTTP/1.1 403 Forbidden"
        assert proxy.denied_total == 2
    finally:
        release.set()
        staller.close()
        proxy.close()


def test_a_denial_in_flight_at_close_still_counts(monkeypatch):
    """A REAL handler thread, parked mid-request, races close(): shutdown() does not join daemon
    handler threads, so its denial lands after close() — and denied_total must include it."""
    entered = threading.Event()
    release = threading.Event()
    policy = parse_egress_allow(None)
    proxy = EgressProxy(policy, poll_interval=0.05)
    address = proxy.start()
    real_allows = EgressPolicy.allows

    def parked_allows(self, host):
        entered.set()
        release.wait(_TIMEOUT_S)
        return real_allows(self, host)

    monkeypatch.setattr(EgressPolicy, "allows", parked_allows)
    client = socket.create_connection(address, timeout=_TIMEOUT_S)
    try:
        client.sendall(b"CONNECT late.example.com:443 HTTP/1.1\r\n\r\n")
        assert entered.wait(_TIMEOUT_S), "the handler never started"
        proxy.close()  # must not deadlock on the parked handler
        assert proxy.denied_total == 0
        release.set()
        assert client.recv(4096).split(b"\r\n", 1)[0] == b"HTTP/1.1 403 Forbidden"
        assert proxy.denied_total == 1
    finally:
        release.set()
        client.close()


def test_denied_total_is_zero_before_start():
    assert EgressProxy(parse_egress_allow(None)).denied_total == 0


@pytest.mark.parametrize("entry", [
    "graph microsoft.com",             # interior space
    "a.example,b.example",             # comma: would split into two entries
    "*.foo\n.com",                     # the #560 newline, which `$` let through
    "graph.microsoft.com\x00",         # NUL
    "graph\x7f.microsoft.com",         # DEL
    "graph\x9b.microsoft.com",         # C1 control (CSI)
    "graph\u00a0microsoft.com",        # NO-BREAK SPACE
    "graph\u2028microsoft.com",        # LINE SEPARATOR
])
def test_a_forbidden_character_inside_an_entry_is_refused(entry):
    """Issue #560, mirrored. The pin carries only ASCII cases; the DEL, C1 and Unicode-space cases
    are asserted on both sides by name (tests/test_egress_grammar.py holds the host's copy)."""
    with pytest.raises(EgressGrammarError) as excinfo:
        assert_egress_allow_grammar([entry])
    assert excinfo.value.code == "egress_allow_forbidden_character"


def test_surrounding_whitespace_is_still_stripped_not_refused():
    """The control for the test above: normalization runs first, so a trailing newline or spaces
    around an entry are not "inside" it."""
    assert_egress_allow_grammar(["  graph.microsoft.com\n", "*.sharepoint.com\t"])
    assert host_matches_egress_allow("graph.microsoft.com", ["graph.microsoft.com\n"]) is True


def test_an_ipv6_literal_keeps_its_meaning():
    """The precheck is a deny-list, not an LDH allow-list, so ``::1`` still matches ``::1``."""
    assert host_matches_egress_allow("::1", ["::1"]) is True
