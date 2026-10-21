"""The session egress gateway (ADR-P058) and its decision core, ``egress_policy.py``.

**Parity.** ``egress_policy`` mirrors the framework's ``validate_egress_ports`` and
``classify_resolved_address`` because the image cannot import the framework (ADR-P048 §7). The ONLY
oracle is the generated pin ``schemas/EGRESS_GRAMMAR.json``: its ``port_vectors`` and
``address_vectors`` are asserted here against the mirror and in ``tests/test_egress_grammar_vectors.py``
against the framework. The pin is read from the same place ``test_egress_proxy.py`` reads it (the
host's ``schemas/`` in-tree, the mirror's own ``schemas/`` in the published tree); an absent pin is a
named failure, never a skip.

**Behaviour.** Every denial category, the allowed tunnel, resolve-once/dial-the-validated-IP, the
strict bind, ``--probe``, stdin EOF and the ``__main__`` branch — on loopback, with a stubbed
resolver and dialer, no Docker and no Linux networking.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from vsify_sandbox import __main__ as sandbox_main
from vsify_sandbox import egress_gateway, egress_policy, egress_proxy
from vsify_sandbox.egress_gateway import (
    RESPONSE_403,
    RESPONSE_407,
    GatewayConfigError,
    discover_interfaces,
    load_config,
    probe,
    select_bind_address,
)
from vsify_sandbox.egress_policy import (
    ADDRESS_VERDICTS,
    EgressPortsError,
    addresses_verdict,
    classify_resolved_address,
    parse_egress_allow,
    parse_egress_ports,
    target_verdict,
    token_matches,
    validate_egress_ports,
)

_SANDBOX_ROOT = Path(__file__).resolve().parent.parent
_HOST_ROOT = _SANDBOX_ROOT.parent
_HOST_MARKER = _HOST_ROOT / "vsify_enterprise_mcp"
_HOST_PIN = _HOST_ROOT / "schemas" / "EGRESS_GRAMMAR.json"
_MIRROR_PIN = _SANDBOX_ROOT / "schemas" / "EGRESS_GRAMMAR.json"

_TIMEOUT_S = 5.0
_TOKEN = "s3ss10n-T0ken_value-abcdefghijklmnopqrstuvwxyz0123"
_GLOBAL_IP = "93.184.216.34"
_SESSION_IFACES = [("eth0", "127.0.0.2", True), ("eth1", "127.0.0.1", False)]


def _load() -> dict:
    in_tree = _HOST_MARKER.is_dir()
    path = _HOST_PIN if in_tree else _MIRROR_PIN
    if not path.is_file():
        pytest.fail(f"EGRESS_GRAMMAR.json not found at {path}; the mirror is asserted against nothing")
    return json.loads(path.read_text())


# ─────────────────────────────────────────── parity with the generated vectors


def test_the_pinned_default_port_policy_matches_the_mirror():
    assert _load()["default_egress_ports"] == sorted(egress_policy.DEFAULT_EGRESS_PORTS)


def test_every_port_vector_agrees_with_the_mirror():
    vectors = _load()["port_vectors"]
    assert vectors, "the pin carries no port_vectors"
    for vector in vectors:
        try:
            got = (sorted(validate_egress_ports(vector["ports"])), None)
        except EgressPortsError as exc:
            got = (None, exc.code)
        assert got == (vector["valid_ports"], vector["error"]), f"vector {vector['name']!r}: {got!r}"


@pytest.mark.parametrize("port", [443.0, 1.0, 65535.0, 443.5])
def test_an_integral_float_is_not_a_port(port):
    """``443.0 == 443`` in Python, so only the type check keeps it out of the policy. Asserted here and
    not as a pinned vector, because release-please's JavaScript JSON updater rewrites the pin and
    turns ``443.0`` into ``443`` (issue 1261)."""
    with pytest.raises(EgressPortsError) as exc:
        validate_egress_ports([port])
    assert exc.value.code == "egress_ports_not_integer"


def test_every_address_vector_agrees_with_the_mirror():
    vectors = _load()["address_vectors"]
    assert vectors, "the pin carries no address_vectors"
    for vector in vectors:
        got = classify_resolved_address(vector["address"])
        assert got == vector["verdict"], f"vector {vector['name']!r}: mirror says {got!r}"
        assert got in ADDRESS_VERDICTS


def test_the_address_vectors_are_not_vacuous():
    """A mirror that only trusted ``is_global`` must disagree with the pin somewhere."""
    import ipaddress

    def naive(addr):
        try:
            return "allowed" if ipaddress.ip_address(addr).is_global else "denied"
        except ValueError:
            return "denied"

    assert any(
        (naive(v["address"]) == "allowed") != (v["verdict"] == "allowed")
        for v in _load()["address_vectors"]
    )


def test_every_match_vector_agrees_with_the_gateway_host_verdict():
    """The gateway's host step, fed the bytes the host projects, decides as the pin says."""
    for vector in _load()["match_vectors"]:
        policy = parse_egress_allow(vector["sandbox_env"])
        verdict = target_verdict(vector["host"], 443, policy, frozenset({443}))
        decision = "allow" if verdict is None else "deny"
        assert decision == vector["sandbox_decision"], f"vector {vector['name']!r}"


def test_the_shim_and_the_gateway_share_one_matcher():
    """No third copy: the shim's names ARE the decision core's."""
    assert egress_proxy.host_matches_egress_allow is egress_policy.host_matches_egress_allow
    assert egress_proxy.parse_egress_allow is egress_policy.parse_egress_allow
    assert egress_proxy.EgressPolicy is egress_policy.EgressPolicy


# ─────────────────────────────────────────── pure policy


@pytest.mark.parametrize(
    ("raw", "want"),
    [("443", {443}), ("443,8443", {443, 8443}), (" 443 , 443 ", {443})],
)
def test_parse_egress_ports_reads_the_projection(raw, want):
    assert parse_egress_ports(raw) == frozenset(want)


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (None, "egress_ports_absent"),
        ("", "egress_ports_absent"),
        ("  ", "egress_ports_absent"),
        ("443,", "egress_ports_not_integer"),
        ("443,abc", "egress_ports_not_integer"),
        ("+443", "egress_ports_not_integer"),
        ("٤٤٣", "egress_ports_not_integer"),
        ("0", "egress_ports_out_of_range"),
        ("65536", "egress_ports_out_of_range"),
    ],
)
def test_parse_egress_ports_refuses_a_malformed_projection(raw, code):
    with pytest.raises(EgressPortsError) as excinfo:
        parse_egress_ports(raw)
    assert excinfo.value.code == code


def test_port_allowed_refuses_a_bool():
    assert egress_policy.port_allowed(443, frozenset({443}))
    assert not egress_policy.port_allowed(80, frozenset({443}))
    assert not egress_policy.port_allowed(True, frozenset({1}))


@pytest.mark.parametrize(
    ("presented", "ok"),
    [
        (f"Bearer {_TOKEN}", True),
        (f"bearer {_TOKEN}", True),
        (f"Bearer  {_TOKEN} ", True),
        (None, False),
        ("", False),
        ("Bearer", False),
        ("Bearer wrong", False),
        (f"Basic {_TOKEN}", False),
        (_TOKEN, False),
        (f"Bearer {_TOKEN}x", False),
    ],
)
def test_token_matches(presented, ok):
    assert token_matches(presented, _TOKEN) is ok


def test_an_empty_expected_token_matches_nothing():
    assert not token_matches("Bearer ", "")
    assert not token_matches("Bearer x", "")


def test_addresses_verdict_requires_every_address_and_at_least_one():
    assert addresses_verdict([_GLOBAL_IP]) is None
    assert addresses_verdict([_GLOBAL_IP, "10.0.0.1"]) == "address"
    assert addresses_verdict(["::ffff:127.0.0.1"]) == "address"
    assert addresses_verdict([]) == "address"


def test_target_verdict_checks_host_before_port():
    policy = parse_egress_allow("allowed.example")
    assert target_verdict("other.example", 80, policy, frozenset({443})) == "host"
    assert target_verdict("allowed.example", 80, policy, frozenset({443})) == "port"
    assert target_verdict("ALLOWED.example.", 443, policy, frozenset({443})) is None


def test_an_ip_literal_passes_the_host_step_only_when_it_is_allowlisted():
    policy = parse_egress_allow("allowed.example,203.0.113.7")
    assert target_verdict("1.1.1.1", 443, policy, frozenset({443})) == "host"
    assert target_verdict("203.0.113.7", 443, policy, frozenset({443})) is None


# ─────────────────────────────────────────── configuration and bind selection


def _env(**overrides):
    env = {
        "VSIFY_EGRESS_TOKEN": _TOKEN,
        "VSIFY_EGRESS_PORTS": "443",
        "SANDBOX_EGRESS_ALLOW": f"allowed.example,{_GLOBAL_IP}",
    }
    env.update(overrides)
    return {k: v for k, v in env.items() if v is not None}


def test_load_config_pops_the_token_and_never_reprs_it():
    env = _env()
    config = load_config(env)
    assert "VSIFY_EGRESS_TOKEN" not in env
    assert config.token == _TOKEN and _TOKEN not in repr(config)
    assert config.ports == frozenset({443})


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"VSIFY_EGRESS_TOKEN": None}, "token_absent"),
        ({"VSIFY_EGRESS_TOKEN": "  "}, "token_absent"),
        ({"VSIFY_EGRESS_PORTS": None}, "egress_ports_absent"),
        ({"VSIFY_EGRESS_PORTS": "https"}, "egress_ports_not_integer"),
        ({"SANDBOX_EGRESS_ALLOW": "*.com"}, "egress_allow_malformed"),
        ({"SANDBOX_EGRESS_ALLOW": None}, "egress_allow_absent"),
    ],
)
def test_load_config_refuses(overrides, reason):
    with pytest.raises(GatewayConfigError) as excinfo:
        load_config(_env(**overrides))
    assert excinfo.value.reason == reason


def test_select_bind_address_picks_the_one_non_default_interface():
    ifaces = [("lo", "127.0.0.1", False), ("eth0", "172.18.0.2", True), ("eth1", "10.9.0.3", False)]
    assert select_bind_address(ifaces) == "10.9.0.3"


@pytest.mark.parametrize(
    ("ifaces", "reason"),
    [
        ([("lo", "127.0.0.1", False), ("eth1", "10.9.0.3", False)], "no_uplink_interface"),
        ([("eth0", "172.18.0.2", True), ("eth1", "10.9.0.3", True)], "multiple_uplink_interfaces"),
        ([("lo", "127.0.0.1", False), ("eth0", "172.18.0.2", True)], "no_session_interface"),
        (
            [("eth0", "172.18.0.2", True), ("eth1", "10.9.0.3", False), ("eth2", "10.8.0.3", False)],
            "multiple_session_interfaces",
        ),
        (
            [("eth0", "172.18.0.2", True), ("eth1", "10.9.0.3", False), ("eth1", "10.9.0.4", False)],
            "session_address_ambiguous",
        ),
        ([("eth0", "172.18.0.2", True), ("eth1", "0.0.0.0", False)], "session_address_invalid"),
        ([("eth0", "172.18.0.2", True), ("eth1", "not-an-ip", False)], "session_address_invalid"),
        ([], "no_uplink_interface"),
    ],
)
def test_select_bind_address_refuses_ambiguity(ifaces, reason):
    with pytest.raises(GatewayConfigError) as excinfo:
        select_bind_address(ifaces)
    assert excinfo.value.reason == reason


def test_discover_interfaces_reads_the_default_route(tmp_path, monkeypatch):
    route = tmp_path / "route"
    route.write_text(
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
        "eth0\t00000000\t010012AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
        "eth0\t000012AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"
        "eth1\t0000090A\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"
    )
    monkeypatch.setattr(egress_gateway.socket, "if_nameindex", lambda: [(1, "lo"), (2, "eth0"), (3, "eth1")])
    addrs = {"lo": "127.0.0.1", "eth0": "172.18.0.2", "eth1": "10.9.0.3"}
    monkeypatch.setattr(egress_gateway, "_ipv4_of", addrs.get)
    found = discover_interfaces(str(route))
    assert found == [("lo", "127.0.0.1", False), ("eth0", "172.18.0.2", True), ("eth1", "10.9.0.3", False)]
    assert select_bind_address(found) == "10.9.0.3"


def test_an_unreadable_route_table_is_a_config_error(tmp_path):
    with pytest.raises(GatewayConfigError) as excinfo:
        discover_interfaces(str(tmp_path / "absent"))
    assert excinfo.value.reason == "route_table_unreadable"


# ─────────────────────────────────────────── the server on loopback


class _Echo:
    """A loopback echo server standing in for the internet destination."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.received = b""
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(_TIMEOUT_S)
                try:
                    while data := conn.recv(4096):
                        self.received += data
                        conn.sendall(data)
                except OSError:
                    pass

    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


class _Gateway:
    """``egress_gateway.run`` in a thread with a pipe for stdin, a stub resolver and a dialer that
    records the validated address and connects to the local echo server instead."""

    def __init__(self, tmp_path: Path, echo: _Echo, env=None, ifaces=None, **kwargs) -> None:
        self.addr_file = str(tmp_path / "egress-gateway.addr")
        self.answers: dict[str, object] = {"allowed.example": [_GLOBAL_IP], _GLOBAL_IP: [_GLOBAL_IP]}
        self.resolved: list[tuple[str, int]] = []
        self.dialled: list[tuple[str, int]] = []
        #: The timeout each dial was GIVEN, in order (the dial phase's remaining budget).
        self.dial_timeouts: list[float] = []
        #: When set, replaces the echo connection: ``hook(address, timeout) -> socket`` or raises.
        self.dial_hook = None
        self._echo = echo
        read_fd, self._write_fd = os.pipe()
        self._stdin = os.fdopen(read_fd, "rb")
        self.rc: int | None = None
        self.env = _env() if env is None else env
        self._thread = threading.Thread(
            target=self._run,
            kwargs=dict(
                interfaces=_SESSION_IFACES if ifaces is None else ifaces,
                resolver=self._resolve,
                dialer=self._dial,
                port=0,
                addr_file=self.addr_file,
                **kwargs,
            ),
            daemon=True,
        )
        self._thread.start()

    def _run(self, **kwargs) -> None:
        self.rc = egress_gateway.run(self.env, self._stdin, **kwargs)

    def _resolve(self, host: str, port: int) -> list[str]:
        self.resolved.append((host, port))
        answer = self.answers.get(host, socket.gaierror("no such name"))
        if isinstance(answer, Exception):
            raise answer
        if callable(answer):  # a resolver that blocks, to prove the resolve step is bounded
            return list(answer(host, port))
        return list(answer)

    def _dial(self, address: tuple[str, int], timeout: float) -> socket.socket:
        self.dialled.append(address)
        self.dial_timeouts.append(timeout)
        if self.dial_hook is not None:
            return self.dial_hook(address, timeout)
        return socket.create_connection(("127.0.0.1", self._echo.port), timeout=timeout)

    def wait_ready(self) -> tuple[str, int]:
        deadline = time.monotonic() + _TIMEOUT_S
        while time.monotonic() < deadline:
            if os.path.exists(self.addr_file):
                host, _, port = Path(self.addr_file).read_text().strip().rpartition(":")
                return host, int(port)
            if not self._thread.is_alive():
                raise AssertionError(f"gateway exited rc={self.rc}")
            time.sleep(0.01)
        raise AssertionError("gateway never wrote its address file")

    def eof(self) -> int | None:
        if self._write_fd is not None:
            os.close(self._write_fd)
            self._write_fd = None
        self._thread.join(timeout=_TIMEOUT_S)
        return self.rc

    def close(self) -> None:
        self.eof()
        self._stdin.close()


@pytest.fixture
def echo():
    server = _Echo()
    yield server
    server.close()


@pytest.fixture
def gateway(tmp_path, echo):
    started: list[_Gateway] = []

    def _start(**kwargs) -> _Gateway:
        gw = _Gateway(tmp_path, echo, **kwargs)
        started.append(gw)
        return gw

    yield _start
    for gw in started:
        gw.close()


def _auth(token: str = _TOKEN) -> str:
    return f"Proxy-Authorization: Bearer {token}\r\n"


def _ask(address, request: str, *, sock: socket.socket | None = None) -> tuple[socket.socket, bytes, bytes]:
    """Send a request; return the socket, the response head through its blank line, and every byte
    read past it. A tunnel's first relayed bytes can share the recv that completes the head, so a
    caller expecting relayed bytes must start from that remainder, never from a fresh recv.

    ``sock`` replaces the dial with an already-connected socket, so a test can preload the peer's
    bytes without patching the process-wide ``socket.create_connection``."""
    client = sock if sock is not None else socket.create_connection(address, timeout=_TIMEOUT_S)
    buf = b""
    try:
        client.sendall(request.encode("latin-1"))
        while b"\r\n\r\n" not in buf:
            chunk = client.recv(4096)
            if not chunk:
                break
            buf += chunk
    except BaseException:
        client.close()
        raise
    head, blank, rest = buf.partition(b"\r\n\r\n")
    return client, head + blank, rest


def _read_to(client: socket.socket, got: bytes, n: int) -> bytes:
    """``got`` (an ``_ask`` remainder) plus further reads until ``n`` bytes have arrived or EOF."""
    while len(got) < n:
        chunk = client.recv(4096)
        if not chunk:
            break
        got += chunk
    return got


def _status(address, request: str) -> bytes:
    client, head, rest = _ask(address, request)
    client.close()
    return head + rest


def _lines(err: str) -> list[str]:
    prefix = "vsify-module-sandbox egress-gateway: "
    return [line[len(prefix):] for line in err.splitlines() if line.startswith(prefix)]


def test_an_allowed_connect_is_tunnelled_to_the_validated_ip(gateway, echo, capsys):
    gw = gateway()
    address = gw.wait_ready()
    client, response, rest = _ask(address, f"CONNECT allowed.example:443 HTTP/1.1\r\n{_auth()}\r\n")
    with client:
        assert response == b"HTTP/1.1 200 Connection Established\r\n\r\n"
        assert rest == b"", "nothing is relayed before the client sends"
        client.sendall(b"through-the-gateway")
        assert _read_to(client, rest, len(b"through-the-gateway")) == b"through-the-gateway"
    assert gw.resolved == [("allowed.example", 443)], "resolved exactly once"
    assert gw.dialled == [(_GLOBAL_IP, 443)], "dialled the validated IP, not the name"
    assert _TOKEN.encode() not in echo.received, "the token never reaches the destination"
    err = capsys.readouterr().err
    assert _lines(err) == ["allowed host=allowed.example port=443"]
    assert _TOKEN not in err and _GLOBAL_IP not in err


def test_bytes_sent_with_the_connect_head_are_forwarded(gateway, echo):
    gw = gateway()
    request = f"CONNECT allowed.example:443 HTTP/1.1\r\n{_auth()}\r\nearly"
    client, response, rest = _ask(gw.wait_ready(), request)
    with client:
        assert response == egress_gateway.RESPONSE_200
        # The echo can arrive in the same read as the head, so start from the remainder.
        assert _read_to(client, rest, len(b"early")) == b"early"


@pytest.mark.parametrize("pending", [b"", b"rly"], ids=["one_read", "split_read"])
def test_ask_returns_the_bytes_that_share_the_heads_read(pending):
    """The race behind the flaky test above, forced: the head and the first relayed bytes are already
    buffered when ``_ask`` reads, so one recv returns both. ``_ask`` must hand back what follows the
    head, and ``_read_to`` must start from it; reading afresh would wait out the timeout instead."""
    ours, theirs = socket.socketpair()
    with ours, theirs:
        ours.settimeout(_TIMEOUT_S)
        theirs.sendall(egress_gateway.RESPONSE_200 + b"early"[: 5 - len(pending)])
        client, head, rest = _ask(None, "CONNECT allowed.example:443 HTTP/1.1\r\n\r\n", sock=ours)
        assert head == egress_gateway.RESPONSE_200
        assert rest == b"early"[: 5 - len(pending)]
        theirs.sendall(pending)
        assert _read_to(client, rest, 5) == b"early"


@pytest.mark.parametrize(
    "auth",
    ["", _auth("wrong"), f"Proxy-Authorization: Basic {_TOKEN}\r\n", _auth() + _auth(),
     f"Authorization: Bearer {_TOKEN}\r\n"],
    ids=["missing", "wrong", "wrong_scheme", "duplicated", "wrong_header"],
)
def test_a_missing_or_wrong_token_is_407_before_anything_else(gateway, capsys, auth):
    gw = gateway()
    response = _status(gw.wait_ready(), f"CONNECT denied.example:80 HTTP/1.1\r\n{auth}\r\n")
    assert response == RESPONSE_407
    assert gw.resolved == [] and gw.dialled == []
    err = capsys.readouterr().err
    assert _lines(err) == ["denied status=407 reason=token"]
    assert "denied.example" not in err, "nothing about the target is logged before the token"


def test_the_token_is_checked_before_the_method(gateway, capsys):
    gw = gateway()
    response = _status(gw.wait_ready(), "GET http://allowed.example/ HTTP/1.1\r\n\r\n")
    assert response == RESPONSE_407
    assert _lines(capsys.readouterr().err) == ["denied status=407 reason=token"]


@pytest.mark.parametrize(
    ("request_line", "line"),
    [
        ("GET http://allowed.example/ HTTP/1.1", "denied status=403 reason=method"),
        ("POST / HTTP/1.1", "denied status=403 reason=method"),
        ("connect allowed.example:443 HTTP/1.1", "denied status=403 reason=method"),
        ("CONNECT allowed.example:443", "denied status=403 reason=method"),
        ("CONNECT denied.example:443 HTTP/1.1", "denied status=403 reason=host host=denied.example"),
        ("CONNECT allowed.example.evil:443 HTTP/1.1",
         "denied status=403 reason=host host=allowed.example.evil"),
        ("CONNECT 1.1.1.1:443 HTTP/1.1", "denied status=403 reason=host host=1.1.1.1"),
        ("CONNECT allowed.example HTTP/1.1", "denied status=403 reason=host host=allowed.example"),
        ("CONNECT allowed.example:80 HTTP/1.1",
         "denied status=403 reason=port host=allowed.example port=80"),
        ("CONNECT allowed.example:8443 HTTP/1.1",
         "denied status=403 reason=port host=allowed.example port=8443"),
    ],
)
def test_every_pre_resolution_denial(gateway, capsys, request_line, line):
    gw = gateway()
    response = _status(gw.wait_ready(), f"{request_line}\r\n{_auth()}\r\n")
    assert response == RESPONSE_403
    assert gw.resolved == [], "refused before any resolution"
    assert gw.dialled == []
    assert _lines(capsys.readouterr().err) == [line]


@pytest.mark.parametrize(
    "answer",
    [["10.0.0.5"], [_GLOBAL_IP, "10.0.0.5"], ["169.254.169.254"], ["::ffff:127.0.0.1"], [],
     socket.gaierror("no such name")],
    ids=["private", "one_private_of_two", "metadata", "mapped_loopback", "empty", "unresolvable"],
)
def test_an_address_refusal_resolves_once_and_never_dials(gateway, capsys, answer):
    gw = gateway()
    gw.answers["allowed.example"] = answer
    response = _status(gw.wait_ready(), f"CONNECT allowed.example:443 HTTP/1.1\r\n{_auth()}\r\n")
    assert response == RESPONSE_403
    assert gw.resolved == [("allowed.example", 443)]
    assert gw.dialled == []
    err = capsys.readouterr().err
    assert _lines(err) == ["denied status=403 reason=address host=allowed.example"]
    assert "10.0.0.5" not in err, "a resolved address is never logged"


def test_an_allowlisted_ip_literal_still_passes_the_address_policy(gateway, capsys):
    gw = gateway(env=_env(SANDBOX_EGRESS_ALLOW="10.0.0.5"))
    gw.answers["10.0.0.5"] = ["10.0.0.5"]
    response = _status(gw.wait_ready(), f"CONNECT 10.0.0.5:443 HTTP/1.1\r\n{_auth()}\r\n")
    assert response == RESPONSE_403
    assert _lines(capsys.readouterr().err) == ["denied status=403 reason=address host=10.0.0.5"]


def test_an_allowlisted_global_ip_literal_is_tunnelled(gateway):
    gw = gateway()
    client, response, _ = _ask(gw.wait_ready(), f"CONNECT {_GLOBAL_IP}:443 HTTP/1.1\r\n{_auth()}\r\n")
    client.close()
    assert response.startswith(b"HTTP/1.1 200")
    assert gw.dialled == [(_GLOBAL_IP, 443)]


class _DialClock:
    """A manual monotonic clock for the gateway's dial budget (R-24): it moves only when a dial
    consumes time, never with real time, so the budget arithmetic is exact and the test is not a
    timing test."""

    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now


_SIX_GLOBAL_ADDRESSES = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112"]


def test_the_whole_dial_phase_shares_one_budget(gateway, monkeypatch, capsys):
    """f-3: a name with several unreachable records must not hold a capacity slot for N x the
    connect timeout. Each dial here consumes up to 0.25 s of the 1.0 s budget and fails; the budget
    arithmetic is exact (a manual clock), so the attempts and the timeout each was GIVEN are exact."""
    clock = _DialClock()
    monkeypatch.setattr(egress_gateway, "time", clock)
    monkeypatch.setattr(egress_gateway, "_CONNECT_TIMEOUT_S", 1.0)
    gw = gateway()
    gw.answers["allowed.example"] = _SIX_GLOBAL_ADDRESSES

    def consume_and_fail(address, timeout):
        clock.now += min(timeout, 0.25)
        raise OSError("unreachable")

    gw.dial_hook = consume_and_fail
    response = _status(gw.wait_ready(), f"CONNECT allowed.example:443 HTTP/1.1\r\n{_auth()}\r\n")
    assert response == egress_gateway.RESPONSE_502
    assert gw.dial_timeouts == [1.0, 0.75, 0.5, 0.25], "each attempt got only what was left"
    assert gw.dialled == [(a, 443) for a in _SIX_GLOBAL_ADDRESSES[:4]], (
        "the 5th and 6th were never tried: the budget was spent")
    assert _lines(capsys.readouterr().err) == [
        "failed status=502 reason=upstream host=allowed.example port=443"]


def test_a_dial_that_succeeds_early_leaves_the_rest_of_the_budget_untouched(gateway, monkeypatch):
    clock = _DialClock()
    monkeypatch.setattr(egress_gateway, "time", clock)
    monkeypatch.setattr(egress_gateway, "_CONNECT_TIMEOUT_S", 1.0)
    gw = gateway()
    gw.answers["allowed.example"] = _SIX_GLOBAL_ADDRESSES[:3]
    attempts = []

    def fail_once_then_connect(address, timeout):
        attempts.append(address)
        clock.now += 0.25
        if len(attempts) == 1:
            raise OSError("unreachable")
        return socket.create_connection(("127.0.0.1", gw._echo.port), timeout=_TIMEOUT_S)

    gw.dial_hook = fail_once_then_connect
    client, response, _ = _ask(gw.wait_ready(), f"CONNECT allowed.example:443 HTTP/1.1\r\n{_auth()}\r\n")
    client.close()
    assert response.startswith(b"HTTP/1.1 200")
    assert gw.dial_timeouts == [1.0, 0.75]


def test_a_resolver_that_never_answers_is_refused_as_address_within_the_bound(gateway, monkeypatch, capsys):
    """f-4: ``getaddrinfo`` has no timeout of its own. A resolver that blocks must cost the handler
    at most the resolve budget; without the bound this request would hang until the client's own
    5 s socket timeout, and the test would fail."""
    release = threading.Event()
    monkeypatch.setattr(egress_gateway, "_RESOLVE_TIMEOUT_S", 0.2)
    gw = gateway()
    gw.answers["allowed.example"] = lambda host, port: release.wait(30) and [_GLOBAL_IP] or []
    try:
        response = _status(gw.wait_ready(), f"CONNECT allowed.example:443 HTTP/1.1\r\n{_auth()}\r\n")
        assert response == RESPONSE_403
        assert gw.dialled == [], "an unanswered resolution never dials"
        # The detail tells an operator the RESOLVER failed, not that the target was refused by policy.
        assert _lines(capsys.readouterr().err) == [
            "denied status=403 reason=address detail=resolve_timeout host=allowed.example"]
    finally:
        release.set()


def test_an_unexpected_resolver_error_is_refused_as_address_with_its_own_detail(gateway, capsys):
    gw = gateway()
    gw.answers["allowed.example"] = RuntimeError("resolver bug")
    response = _status(gw.wait_ready(), f"CONNECT allowed.example:443 HTTP/1.1\r\n{_auth()}\r\n")
    assert response == RESPONSE_403
    assert gw.dialled == []
    assert _lines(capsys.readouterr().err) == [
        "denied status=403 reason=address detail=resolve_error host=allowed.example"]


def test_a_name_that_does_not_resolve_carries_no_detail(gateway, capsys):
    """The ordinary refusal stays byte-identical: ``gaierror`` means "no such name", not an outage."""
    gw = gateway()
    gw.answers["allowed.example"] = socket.gaierror("no such name")
    assert _status(gw.wait_ready(), f"CONNECT allowed.example:443 HTTP/1.1\r\n{_auth()}\r\n") == RESPONSE_403
    assert _lines(capsys.readouterr().err) == ["denied status=403 reason=address host=allowed.example"]


def test_abandoned_resolutions_are_capped_and_a_full_cap_fails_closed(gateway, monkeypatch, capsys):
    """An abandoned resolver cannot be interrupted, only counted. At the in-flight cap a new
    resolution is refused as ``address`` WITHOUT starting another thread (the resolver is not
    called), and the permit comes back once the stuck resolver finally returns."""
    release = threading.Event()
    monkeypatch.setattr(egress_gateway, "_RESOLVE_TIMEOUT_S", 0.2)
    monkeypatch.setattr(egress_gateway, "_MAX_RESOLVES", 1)
    gw = gateway()
    gw.answers["allowed.example"] = lambda host, port: release.wait(30) and [_GLOBAL_IP] or []
    address = gw.wait_ready()
    request = f"CONNECT allowed.example:443 HTTP/1.1\r\n{_auth()}\r\n"
    try:
        assert _status(address, request) == RESPONSE_403  # abandons the one resolver, holds the permit
        assert len(gw.resolved) == 1
        assert _status(address, request) == RESPONSE_403  # cap reached: refused, resolver not called
        assert len(gw.resolved) == 1, "no second resolver thread was started at the cap"
    finally:
        release.set()
    gw.answers["allowed.example"] = [_GLOBAL_IP]
    deadline = time.monotonic() + _TIMEOUT_S
    while True:  # the permit is released by the worker thread, asynchronously
        client, response, _ = _ask(address, request)
        client.close()
        if response.startswith(b"HTTP/1.1 200") or time.monotonic() > deadline:
            break
        time.sleep(0.02)
    assert response.startswith(b"HTTP/1.1 200"), "the permit was never returned"
    # Distinct details are distinct coalescing keys, so both reach the log inside one window.
    assert _lines(capsys.readouterr().err)[:2] == [
        "denied status=403 reason=address detail=resolve_timeout host=allowed.example",
        "denied status=403 reason=address detail=resolve_cap host=allowed.example",
    ]


def test_a_thread_that_cannot_start_refuses_and_returns_its_permit(monkeypatch):
    """The fifth way ``resolve`` can fail: no worker thread could be started. It must refuse
    (``resolve_error``) AND give the permit back, or one failed start would leak a permit for good.
    With a cap of ONE, the next resolution succeeding is the proof the permit was returned (a
    second release would raise instead: the semaphore is bounded)."""
    monkeypatch.setattr(egress_gateway, "_MAX_RESOLVES", 1)
    server = egress_gateway.GatewayServer(
        ("127.0.0.1", 0), load_config(_env()), resolver=lambda host, port: [_GLOBAL_IP])
    try:
        def cannot_start(self):
            raise RuntimeError("can't start new thread")

        with monkeypatch.context() as patched:
            patched.setattr(threading.Thread, "start", cannot_start)
            assert server.resolve("allowed.example", 443) == ([], egress_gateway.DETAIL_RESOLVE_ERROR)
        assert server.resolve("allowed.example", 443) == ([_GLOBAL_IP], None), "the permit leaked"
    finally:
        server.server_close()


def test_resolver_outage_details_are_their_own_coalescing_keys(gateway, monkeypatch, capsys):
    """A repeated outage line is coalesced into a ``suppressed`` summary that CARRIES the detail, and an
    outage is never folded into a policy refusal's count: two ``resolve_timeout`` refusals and one
    plain ``address`` refusal inside one window give one decision line per key, plus a summary for the
    repeated outage only."""
    release = threading.Event()
    monkeypatch.setattr(egress_gateway, "_RESOLVE_TIMEOUT_S", 0.05)
    gw = gateway()
    address = gw.wait_ready()
    request = f"CONNECT allowed.example:443 HTTP/1.1\r\n{_auth()}\r\n"
    gw.answers["allowed.example"] = lambda host, port: release.wait(30) and [_GLOBAL_IP] or []
    try:
        assert _status(address, request) == RESPONSE_403
        assert _status(address, request) == RESPONSE_403
    finally:
        release.set()
    gw.answers["allowed.example"] = socket.gaierror("no such name")
    assert _status(address, request) == RESPONSE_403
    assert gw.eof() == 0  # shutdown writes every count still owed
    lines = _lines(capsys.readouterr().err)
    assert sorted(lines) == sorted([
        "denied status=403 reason=address detail=resolve_timeout host=allowed.example",
        "denied status=403 reason=address host=allowed.example",
        "suppressed count=1 status=403 reason=address detail=resolve_timeout host=allowed.example",
    ])


def test_the_port_policy_is_the_deployment_set(gateway):
    gw = gateway(env=_env(VSIFY_EGRESS_PORTS="443,8443"))
    client, response, _ = _ask(gw.wait_ready(), f"CONNECT allowed.example:8443 HTTP/1.1\r\n{_auth()}\r\n")
    client.close()
    assert response.startswith(b"HTTP/1.1 200")
    assert gw.dialled == [(_GLOBAL_IP, 8443)]


def test_refusal_bodies_are_uniform(gateway):
    gw = gateway()
    address = gw.wait_ready()
    bodies = {
        _status(address, f"{line}\r\n{_auth()}\r\n")
        for line in (
            "GET http://allowed.example/ HTTP/1.1",
            "CONNECT denied.example:443 HTTP/1.1",
            "CONNECT allowed.example:80 HTTP/1.1",
        )
    }
    gw.answers["allowed.example"] = ["10.0.0.1"]
    bodies.add(_status(address, f"CONNECT allowed.example:443 HTTP/1.1\r\n{_auth()}\r\n"))
    assert bodies == {RESPONSE_403}


def test_a_connection_that_sends_nothing_gets_no_line(gateway, capsys):
    gw = gateway()
    socket.create_connection(gw.wait_ready(), timeout=_TIMEOUT_S).close()
    assert probe(gw.addr_file) == 0
    time.sleep(0.1)
    assert _lines(capsys.readouterr().err) == []


def test_connections_beyond_the_cap_are_dropped(gateway, capsys):
    gw = gateway(max_connections=1)
    address = gw.wait_ready()
    holder = socket.create_connection(address, timeout=_TIMEOUT_S)
    try:
        holder.sendall(b"CONNECT")  # an incomplete head keeps the one slot busy
        time.sleep(0.2)
        extra = socket.create_connection(address, timeout=_TIMEOUT_S)
        with extra:
            assert extra.recv(4096) == b""
        assert "connection dropped: at capacity" in _lines(capsys.readouterr().err)
    finally:
        holder.close()


def test_a_trickling_client_is_dropped_at_the_head_deadline_with_no_line(gateway, capsys, monkeypatch):
    """Slowloris: one byte every 50 ms never trips the 10 s per-recv timeout. The overall head
    deadline drops the connection (no reply, no line) and frees its capacity slot."""
    monkeypatch.setattr(egress_gateway, "_HEAD_DEADLINE_S", 0.5)
    gw = gateway(max_connections=1)
    address = gw.wait_ready()
    stop = threading.Event()
    client = socket.create_connection(address, timeout=_TIMEOUT_S)

    def _trickle() -> None:
        head = f"CONNECT allowed.example:443 HTTP/1.1\r\n{_auth()}".encode()
        for i in range(60):  # bounded at 3 s: a gateway with no deadline fails, never hangs
            if stop.wait(0.05):
                return
            try:
                client.sendall(head[i % len(head):i % len(head) + 1])
            except OSError:
                return

    sender = threading.Thread(target=_trickle, daemon=True)
    sender.start()
    try:
        # Generous under load, and still far under what a gateway with NO head deadline would take
        # (the trickle stops at 3 s, then the 10 s per-recv timeout): such a gateway fails here.
        client.settimeout(8.0)
        try:
            reply = client.recv(4096)
        except ConnectionResetError:
            reply = b""
        assert reply == b"", "dropped with no reply"
    finally:
        stop.set()
        sender.join(timeout=_TIMEOUT_S)
        client.close()
    # The one slot is free again: a well-formed request is served, not dropped at capacity.
    assert _status(address, f"CONNECT denied.example:443 HTTP/1.1\r\n{_auth()}\r\n") == RESPONSE_403
    assert _lines(capsys.readouterr().err) == ["denied status=403 reason=host host=denied.example"]


class _Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def _decision_lines(clock, **kwargs):
    """A DecisionLines on a fake clock with NO flush timer: every flush in a test is explicit."""
    written: list[str] = []
    kwargs.setdefault("flush_interval_s", None)
    return written, egress_gateway.DecisionLines(write=written.append, clock=clock, window_s=1.0, **kwargs)


def test_decision_lines_coalesce_per_key_and_report_the_count_once():
    clock = _Clock()
    written, lines = _decision_lines(clock)
    a = ("403", "host", "a.example")
    assert lines.emit(a, "denied status=403 reason=host host=a.example") is True
    for _ in range(3):
        assert lines.emit(a, "denied status=403 reason=host host=a.example") is False
    # Another key is independent of the first.
    assert lines.emit(("407", "token", ""), "denied status=407 reason=token") is True
    clock.now += 0.999
    assert lines.emit(a, "denied status=403 reason=host host=a.example") is False
    assert lines.flush() == 0, "the window has not passed: nothing is owed yet"
    clock.now += 0.002
    # The key's next line comes first: the count is written just before it, never folded into it.
    assert lines.emit(a, "denied status=403 reason=host host=a.example") is True
    clock.now += 5
    assert lines.emit(a, "denied status=403 reason=host host=a.example") is True
    assert written == [
        "denied status=403 reason=host host=a.example",
        "denied status=407 reason=token",
        "suppressed count=4 status=403 reason=host host=a.example",
        "denied status=403 reason=host host=a.example",
        "denied status=403 reason=host host=a.example",
    ]


def test_a_decoy_host_does_not_hide_another_host():
    """N4: a module refused for a decoy once a second must not hide every other target."""
    clock = _Clock()
    written, lines = _decision_lines(clock)
    assert lines.emit(("403", "host", "decoy.example"), "denied status=403 reason=host host=decoy.example")
    assert lines.emit(("403", "host", "secret.example"), "denied status=403 reason=host host=secret.example")
    assert written == ["denied status=403 reason=host host=decoy.example",
                       "denied status=403 reason=host host=secret.example"]


def test_the_flush_writes_a_count_whose_key_never_fires_again():
    clock = _Clock()
    written, lines = _decision_lines(clock)
    key = ("403", "port", "a.example")
    for _ in range(7):
        lines.emit(key, "denied status=403 reason=port host=a.example port=80")
    clock.now += 1.0
    assert lines.flush() == 1
    assert lines.flush() == 0, "a count is reported exactly once"
    assert written == ["denied status=403 reason=port host=a.example port=80",
                       "suppressed count=6 status=403 reason=port host=a.example"]


def test_close_writes_every_count_still_owed_whatever_the_window():
    clock = _Clock()
    written, lines = _decision_lines(clock)
    for _ in range(3):
        lines.emit(("407", "token", ""), "denied status=407 reason=token")
    lines.emit(egress_gateway.KEY_CAPACITY, "connection dropped: at capacity")
    lines.emit(egress_gateway.KEY_CAPACITY, "connection dropped: at capacity")
    lines.close()
    assert written[-2:] == ["suppressed count=2 status=407 reason=token",
                            "suppressed count=1 status=none reason=capacity"]


def test_the_key_table_is_bounded_and_overflows_into_a_star_key():
    clock = _Clock()
    written, lines = _decision_lines(clock, max_keys=3)
    for name in ("a", "b", "c"):
        assert lines.emit(("403", "host", name), f"denied status=403 reason=host host={name}")
    # A fourth host at a full table is accounted under the overflow key: its first line is
    # written, the rest counted there, whatever their host.
    assert lines.emit(("403", "host", "d"), "denied status=403 reason=host host=d") is True
    assert lines.emit(("403", "host", "e"), "denied status=403 reason=host host=e") is False
    assert lines.emit(("403", "host", "f"), "denied status=403 reason=host host=f") is False
    assert len(lines._state) == 4 and lines._hosted == 3, "three hosted keys plus one overflow key"
    clock.now += 1.0
    assert lines.flush() == 1
    assert written[-1] == "suppressed count=2 status=403 reason=host host=*"
    # Idle keys are evicted, so new hosts get their own keys again.
    clock.now += 1.0
    lines.flush()
    assert lines._hosted == 0 and lines._state == {}
    assert lines.emit(("403", "host", "g"), "denied status=403 reason=host host=g") is True
    assert lines._hosted == 1


def _hosted(i: int) -> tuple[tuple[str, str, str], str]:
    return ("403", "host", f"h{i}"), f"denied status=403 reason=host host=h{i}"


def test_hosted_lines_past_the_window_budget_fold_into_the_overflow_key():
    """Q1: however many hosts a module cycles through, at most the budget of hosted lines is written
    per window; the rest is accounted under the (status, reason, *) overflow key."""
    budget = egress_gateway._HOSTED_LINE_BUDGET
    assert budget == 32
    clock = _Clock()
    written, lines = _decision_lines(clock)
    for i in range(budget):
        assert lines.emit(*_hosted(i)) is True
    # A new host past the budget: the overflow key's first line is written, the rest counted there.
    assert lines.emit(*_hosted(budget)) is True
    assert lines.emit(*_hosted(budget + 1)) is False
    assert lines.emit(*_hosted(budget + 2)) is False
    assert ("403", "host", egress_gateway.OVERFLOW_HOST) in lines._state
    assert lines._hosted == budget, "a folded host never takes a key of its own"
    assert len(written) == budget + 1
    clock.now += 1.0
    assert lines.flush() == 1
    assert written[-1] == "suppressed count=2 status=403 reason=host host=*"
    # The next window has a fresh budget: a new host gets its own key again.
    assert lines.emit(*_hosted(500)) is True
    assert ("403", "host", "h500") in lines._state


def test_an_existing_key_past_the_budget_folds_too():
    """The budget bounds the rate, not only the admissions: a tracked host whose window has passed
    is folded when the window's budget is spent, so cycling known hosts cannot exceed it either."""
    budget = egress_gateway._HOSTED_LINE_BUDGET
    clock = _Clock()
    written, lines = _decision_lines(clock)
    for i in range(budget):
        lines.emit(*_hosted(i))
    clock.now += 1.0
    for i in range(budget, 2 * budget):
        assert lines.emit(*_hosted(i)) is True
    hosted_before = lines._hosted
    assert lines.emit(*_hosted(0)) is True, "the overflow key's first line in this window"
    assert lines.emit(*_hosted(1)) is False
    assert lines._hosted == hosted_before
    assert lines._state[("403", "host", "h1")][1] == 0, "counted under the overflow key, not its own"
    assert lines._state[("403", "host", egress_gateway.OVERFLOW_HOST)][1] == 1


def test_a_decoy_spends_one_line_of_the_budget_per_window():
    """Decoy protection holds within the budget: a decoy refused at any rate costs one line per
    window, and every other host within the budget still gets its own line."""
    budget = egress_gateway._HOSTED_LINE_BUDGET
    clock = _Clock()
    written, lines = _decision_lines(clock)
    for _ in range(100):
        lines.emit(("403", "host", "decoy.example"), "denied status=403 reason=host host=decoy.example")
    for i in range(budget - 1):
        assert lines.emit(*_hosted(i)) is True
    assert written[0] == "denied status=403 reason=host host=decoy.example"
    assert written[1:] == [_hosted(i)[1] for i in range(budget - 1)]
    assert ("403", "host", egress_gateway.OVERFLOW_HOST) not in lines._state


def _decisions_reported(written: list[str]) -> int:
    """Every decision the lines account for: one per decision line, ``count`` per summary line."""
    total = 0
    for line in written:
        if line.startswith("suppressed "):
            total += int(line.split()[1].removeprefix("count="))
        else:
            total += 1
    return total


def test_hosted_summaries_spend_the_budget_so_live_keys_cannot_flood():
    """R1: many live hosted keys, each hit once per window INSIDE its own window, used to write one
    free summary per key per flush (256 lines a window at a full table). Summaries now spend the same
    budget and fold past it, so every window stays within the stated bound and no count is lost."""
    budget = egress_gateway._HOSTED_LINE_BUDGET
    max_keys = egress_gateway._MAX_LINE_KEYS
    # The ADR-P058 §7 bound: the hosted budget, plus one decision and one summary line for each of
    # the nine host-free and overflow keys.
    bound = budget + 2 * 9
    clock = _Clock()
    clock.now = 0.0
    written: list[str] = []
    stamped: list[float] = []

    def _write(line: str) -> None:
        written.append(line)
        stamped.append(clock.now)

    lines = egress_gateway.DecisionLines(write=_write, clock=clock, window_s=1.0, flush_interval_s=None)
    decisions = 0
    windows = 12
    for k in range(windows):
        clock.now = float(k)
        lines.flush()  # the timer, at the window boundary: a live key's window has just passed
        for _ in range(2):  # a hit at the boundary, then one half a window later: both inside
            for i in range(max_keys):
                lines.emit(*_hosted(i))
                decisions += 1
            clock.now = k + 0.5
    clock.now = float(windows)
    lines.close()
    per_window = [sum(1 for t in stamped if k <= t < k + 1) for k in range(windows)]
    assert max(per_window) <= bound, per_window
    # Only one (status, reason) family is in play, so its one overflow key adds at most two lines.
    assert max(per_window) <= budget + 2, per_window
    assert _decisions_reported(written) == decisions, "a folded count is never lost"


def test_close_folds_hosted_summaries_past_the_budget_and_keeps_the_count():
    budget = egress_gateway._HOSTED_LINE_BUDGET
    clock = _Clock()
    written, lines = _decision_lines(clock)
    for i in range(budget):
        lines.emit(*_hosted(i))
        lines.emit(*_hosted(i))
    lines.close()  # same window: the budget is spent, so all 32 counts fold into the overflow key
    assert written[-1] == f"suppressed count={budget} status=403 reason=host host=*"
    assert len(written) == budget + 1
    assert _decisions_reported(written) == 2 * budget


def test_a_full_table_evicts_idle_keys_before_overflowing():
    clock = _Clock()
    written, lines = _decision_lines(clock, max_keys=2)
    lines.emit(("403", "host", "a"), "denied status=403 reason=host host=a")
    lines.emit(("403", "host", "b"), "denied status=403 reason=host host=b")
    clock.now += 1.0  # both idle and owing nothing
    assert lines.emit(("403", "host", "c"), "denied status=403 reason=host host=c") is True
    assert ("403", "host", "c") in lines._state and lines._hosted == 1


def test_the_flush_timer_writes_a_pending_count_on_its_own():
    """The background timer (not a later decision) reports a burst. Deterministic: the clock is
    fake, and the wait is for the write itself, bounded."""
    clock = _Clock()
    written: list[str] = []
    seen = threading.Event()

    def _write(line: str) -> None:
        written.append(line)
        if line.startswith("suppressed "):
            seen.set()

    lines = egress_gateway.DecisionLines(write=_write, clock=clock, window_s=1.0, flush_interval_s=0.01)
    lines.emit(("403", "host", "a"), "denied status=403 reason=host host=a")
    lines.emit(("403", "host", "a"), "denied status=403 reason=host host=a")
    lines.start()
    try:
        clock.now += 1.0
        assert seen.wait(_TIMEOUT_S), "the timer never flushed the pending count"
    finally:
        lines.close()
    assert written == ["denied status=403 reason=host host=a",
                       "suppressed count=1 status=403 reason=host host=a"]


def test_decision_lines_are_thread_safe_and_count_every_suppression():
    clock = _Clock()
    written, lines = _decision_lines(clock)
    barrier = threading.Barrier(32)
    key = ("200", "allowed", "a")

    def _burst() -> None:
        barrier.wait()
        for _ in range(50):
            lines.emit(key, "allowed host=a port=443")

    threads = [threading.Thread(target=_burst) for _ in range(32)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=_TIMEOUT_S)
    assert written == ["allowed host=a port=443"]
    lines.close()
    assert written[-1] == f"suppressed count={32 * 50 - 1} status=200 reason=allowed host=a"


def test_decision_lines_never_raise():
    def _broken(line: str) -> None:
        raise RuntimeError("stderr is gone")

    lines = egress_gateway.DecisionLines(write=_broken)
    assert lines.emit(("403", "host", "a"), "denied status=403 reason=host host=a") is False
    lines.emit(("403", "host", "a"), "denied status=403 reason=host host=a")
    assert lines.flush(force=True) == 0
    lines.close()  # never raises

    def _broken_clock() -> float:
        raise RuntimeError("no clock")

    lines = egress_gateway.DecisionLines(write=lambda _: None, clock=_broken_clock, flush_interval_s=None)
    assert lines.emit(("403", "host", "a"), "x") is False
    assert lines.flush() == 0


def test_a_burst_of_refusals_writes_one_line_per_key_per_window(gateway, capsys):
    """The module chooses the decision rate and the host inherits this stderr (ADR-P058 §7). The
    clock is injected, so no assertion here depends on how fast the machine is."""
    clock = _Clock()
    lines = egress_gateway.DecisionLines(clock=clock, window_s=1.0, flush_interval_s=None)
    gw = gateway(lines=lines)
    address = gw.wait_ready()
    for _ in range(5):
        assert _status(address, f"CONNECT denied.example:443 HTTP/1.1\r\n{_auth()}\r\n") == RESPONSE_403
    # Same instant, another host: its own key, so the burst above does not hide it.
    assert _status(address, f"CONNECT other.example:443 HTTP/1.1\r\n{_auth()}\r\n") == RESPONSE_403
    assert _status(address, "CONNECT denied.example:443 HTTP/1.1\r\n\r\n") == RESPONSE_407
    assert _lines(capsys.readouterr().err) == [
        "denied status=403 reason=host host=denied.example",
        "denied status=403 reason=host host=other.example",
        "denied status=407 reason=token",
    ]
    assert lines.flush() == 0, "inside the window nothing is owed yet"
    clock.now += 1.0
    assert lines.flush() == 1
    assert _lines(capsys.readouterr().err) == [
        "suppressed count=4 status=403 reason=host host=denied.example"]


def test_stdin_eof_flushes_a_burst_that_never_fires_again(gateway, capsys):
    clock = _Clock()
    lines = egress_gateway.DecisionLines(clock=clock, window_s=1.0, flush_interval_s=None)
    gw = gateway(lines=lines)
    address = gw.wait_ready()
    for _ in range(3):
        assert _status(address, f"CONNECT allowed.example:80 HTTP/1.1\r\n{_auth()}\r\n") == RESPONSE_403
    assert gw.eof() == 0
    assert _lines(capsys.readouterr().err) == [
        "denied status=403 reason=port host=allowed.example port=80",
        "suppressed count=2 status=403 reason=port host=allowed.example",
    ]


# ─────────────────────────────────────────── bind, readiness and lifecycle


def test_the_listener_is_the_session_address_only_and_not_the_uplink(gateway):
    gw = gateway()
    host, port = gw.wait_ready()
    assert host == "127.0.0.1", "bound to the session interface's address, never a wildcard"
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.2", port), timeout=1.0).close()


def test_probe_succeeds_against_a_live_gateway_and_fails_after_eof(gateway):
    gw = gateway()
    gw.wait_ready()
    assert probe(gw.addr_file) == 0
    assert gw.eof() == 0, "stdin EOF stops the gateway with exit 0"
    assert probe(gw.addr_file) == 1


@pytest.mark.parametrize("how", ["raises", "returns"])
def test_a_serve_loop_that_ends_exits_1_while_stdin_is_still_open(tmp_path, capsys, monkeypatch, how):
    """N3: the serve loop runs on a thread while stdin stays open (the host is alive). If the loop
    ends, run() must exit non-zero, so the container stops and the host's ``docker start -a``
    returns, instead of a live container that no longer serves anything."""
    def _dead_loop(self, poll_interval=0.5):
        if how == "raises":
            raise OSError("listener gone")

    monkeypatch.setattr(egress_gateway.GatewayServer, "serve_forever", _dead_loop)
    read_fd, write_fd = os.pipe()
    stdin = os.fdopen(read_fd, "rb")
    result: list[int] = []
    runner = threading.Thread(
        target=lambda: result.append(egress_gateway.run(
            _env(), stdin, interfaces=_SESSION_IFACES, port=0, addr_file=str(tmp_path / "addr"))),
        daemon=True,
    )
    try:
        runner.start()
        runner.join(timeout=_TIMEOUT_S)
        assert not runner.is_alive(), "run() kept going after its serve loop ended"
        assert result == [1]
        assert _lines(capsys.readouterr().err) == ["fatal: listener_stopped"]
        assert probe(str(tmp_path / "addr")) == 1, "the listener is closed"
    finally:
        os.close(write_fd)  # releases run()'s stdin waiter
        stdin.close()


def test_stdin_eof_still_exits_0_with_no_fatal_line(gateway, capsys):
    gw = gateway()
    gw.wait_ready()
    assert gw.eof() == 0
    assert "fatal: listener_stopped" not in capsys.readouterr().err


def test_probe_fails_without_an_address_file(tmp_path):
    assert probe(str(tmp_path / "absent")) == 1
    (tmp_path / "garbage").write_text("not an address\n")
    assert probe(str(tmp_path / "garbage")) == 1


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        (dict(ifaces=[("eth0", "127.0.0.2", True), ("eth1", "127.0.0.1", False),
                      ("eth2", "127.0.0.3", False)]), "multiple_session_interfaces"),
        (dict(ifaces=[("eth1", "127.0.0.1", False)]), "no_uplink_interface"),
        (dict(env=_env(VSIFY_EGRESS_TOKEN=None)), "token_absent"),
        (dict(env=_env(VSIFY_EGRESS_PORTS="")), "egress_ports_absent"),
    ],
)
def test_a_config_error_exits_1_and_never_publishes_an_address(gateway, capsys, kwargs, reason):
    gw = gateway(**kwargs)
    assert gw.eof() == 1
    assert not os.path.exists(gw.addr_file), "an unhealthy gateway must never look ready"
    assert _lines(capsys.readouterr().err) == [f"config error: {reason}"]


def test_a_failed_bind_exits_1(tmp_path, capsys):
    taken = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    taken.bind(("127.0.0.1", 0))
    taken.listen(1)
    try:
        rc = egress_gateway.run(
            _env(), None, interfaces=_SESSION_IFACES, port=taken.getsockname()[1],
            addr_file=str(tmp_path / "addr"),
        )
    finally:
        taken.close()
    assert rc == 1
    assert _lines(capsys.readouterr().err) == ["config error: bind_failed"]
    assert not (tmp_path / "addr").exists()


def test_the_gateway_never_writes_stdout(gateway, capsys):
    gw = gateway()
    _status(gw.wait_ready(), "CONNECT allowed.example:443 HTTP/1.1\r\n\r\n")
    gw.eof()
    assert capsys.readouterr().out == ""


# ─────────────────────────────────────────── the shim chained to the real gateway


def test_the_shim_chains_through_the_gateway_end_to_end(gateway, echo, capsys):
    gw = gateway()
    gw_host, gw_port = gw.wait_ready()
    env = {
        "SANDBOX_EGRESS_ALLOW": "allowed.example,denied-by-gateway.example",
        "SANDBOX_EGRESS_UPSTREAM": f"{gw_host}:{gw_port}",
        "VSIFY_EGRESS_TOKEN": _TOKEN,
    }
    proxy = egress_proxy.install(env)
    try:
        assert "VSIFY_EGRESS_TOKEN" not in env
        client, response, rest = _ask(proxy.address, "CONNECT allowed.example:443 HTTP/1.1\r\n\r\n")
        with client:
            assert response == b"HTTP/1.1 200 Connection Established\r\n\r\n"
            assert rest == b"", "nothing is relayed before the client sends"
            client.sendall(b"hello")
            assert _read_to(client, rest, len(b"hello")) == b"hello"
        # The shim allows it, the gateway's port policy refuses it.
        response = _status(proxy.address, "CONNECT allowed.example:80 HTTP/1.1\r\n\r\n")
        assert response.startswith(b"HTTP/1.1 403")
    finally:
        proxy.close()
    err = capsys.readouterr().err
    assert _TOKEN not in err
    assert "denied status=403 reason=port host=allowed.example port=80" in _lines(err)


# ─────────────────────────────────────────── __main__ and the image


def test_main_dispatches_probe_first(monkeypatch):
    monkeypatch.setattr(egress_gateway, "probe", lambda: 7)
    assert sandbox_main.dispatch(["--probe"], {"VSIFY_SANDBOX_MODE": "anything"}) == 7


def test_main_branches_to_the_gateway_before_importing_the_entrypoint(monkeypatch):
    monkeypatch.delitem(sys.modules, "vsify_sandbox.entrypoint", raising=False)
    monkeypatch.setattr(egress_gateway, "main", lambda: 0)
    assert sandbox_main.dispatch([], {"VSIFY_SANDBOX_MODE": "egress-gateway"}) == 0
    assert "vsify_sandbox.entrypoint" not in sys.modules


def test_an_unknown_mode_exits_2_without_importing_the_entrypoint(monkeypatch, capsys):
    monkeypatch.delitem(sys.modules, "vsify_sandbox.entrypoint", raising=False)
    assert sandbox_main.dispatch([], {"VSIFY_SANDBOX_MODE": "serve-anything"}) == 2
    assert "vsify_sandbox.entrypoint" not in sys.modules
    err = capsys.readouterr().err
    assert "unknown VSIFY_SANDBOX_MODE" in err and "serve-anything" not in err


@pytest.mark.parametrize("environ", [{}, {"VSIFY_SANDBOX_MODE": ""}])
def test_an_absent_mode_runs_the_module_entrypoint(monkeypatch, environ):
    from vsify_sandbox import entrypoint

    monkeypatch.setattr(entrypoint, "main", lambda: 42)
    assert sandbox_main.dispatch([], environ) == 42


def _python_m(env_overrides: dict[str, str], *args: str) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("VSIFY_", "SANDBOX_"))}
    env["PYTHONPATH"] = str(_SANDBOX_ROOT)
    env.update(env_overrides)
    return subprocess.run(
        [sys.executable, "-m", "vsify_sandbox", *args], env=env, stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=30, cwd=str(_SANDBOX_ROOT),
    )


def test_python_m_refuses_an_unknown_mode():
    result = _python_m({"VSIFY_SANDBOX_MODE": "bogus"})
    assert result.returncode == 2
    assert result.stdout == ""


def test_python_m_gateway_without_a_token_is_a_config_error():
    result = _python_m({"VSIFY_SANDBOX_MODE": "egress-gateway"})
    assert result.returncode == 1
    assert "vsify-module-sandbox egress-gateway: config error: token_absent" in result.stderr
    assert result.stdout == ""


def test_the_dockerfile_has_no_healthcheck():
    """ADR-P058 §5: a Dockerfile HEALTHCHECK would run in every MODULE container. The gateway's
    health check is per-container, on its own ``docker create``."""
    dockerfile = (_SANDBOX_ROOT / "Dockerfile").read_text(encoding="utf-8")
    instructions = [
        line.strip().split(None, 1)[0].upper()
        for line in dockerfile.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert "HEALTHCHECK" not in instructions
