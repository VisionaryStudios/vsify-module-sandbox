"""
The image's egress decision core (ADR-P058 §6): pure, stdlib-only functions that both the module's
loopback shim (``egress_proxy.py``) and the session gateway (``egress_gateway.py``) decide with.

**What lives here.**

* The ``egress_allow`` host matcher (ADR-P010 grammar, ADR-P048 §7). It moved here from
  ``egress_proxy.py`` unchanged, and ``egress_proxy`` re-exports every name, so the shim's default
  path decides exactly as before.
* The deployment-wide port policy (``VSIFY_EGRESS_PORTS``, default ``{443}``).
* The resolved-address policy (:func:`classify_resolved_address`).
* The gateway's per-request verdicts: the token, then the target (host, port), then the resolved
  addresses. The server applies them in that order; nothing here does I/O.

**One grammar, two implementations, one pin.** The image cannot import the framework (ADR-P048 §7),
so the matcher, :func:`validate_egress_ports` and :func:`classify_resolved_address` are mirrors of
``vsify_enterprise_mcp/egress_grammar.py``. The mirror is mandated by the image boundary, not a
choice, and it is held to the framework mechanically: ``schemas/EGRESS_GRAMMAR.json`` is GENERATED
from the framework's own functions, and its ``grammar_vectors``, ``match_vectors``, ``port_vectors``
and ``address_vectors`` are asserted against BOTH sides (``tests/test_egress_grammar_vectors.py``
host-side; ``sandbox/tests/test_egress_proxy.py`` and ``sandbox/tests/test_egress_gateway.py``
here). There is no third copy.

Stdlib only, and nothing here writes anywhere: the callers own their diagnostics.
"""
from __future__ import annotations

import functools
import hmac
import ipaddress
import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

EGRESS_ALLOW_ENV = "SANDBOX_EGRESS_ALLOW"

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


# --------------------------------------------------------------------------- the allowlist policy


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


# --------------------------------------------------------------------------- the port policy
# Mirrors egress_grammar.DEFAULT_EGRESS_PORTS / validate_egress_ports; held by `port_vectors`.

EGRESS_PORTS_ENV = "VSIFY_EGRESS_PORTS"

#: HTTPS only. Plain HTTP (port 80) is refused under it, and so is every other port.
DEFAULT_EGRESS_PORTS: frozenset[int] = frozenset({443})

_PORT_MIN = 1
_PORT_MAX = 65535


class EgressPortsError(ValueError):
    """A malformed port policy. ``code`` is the framework's own ``KindUnsupported`` reason, so the
    pinned ``port_vectors`` can assert that both sides refuse for the SAME reason."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def validate_egress_ports(ports: Iterable[int]) -> frozenset[int]:
    """Mirror of ``egress_grammar.validate_egress_ports``: the policy as a ``frozenset``, or
    :class:`EgressPortsError` with ``egress_ports_malformed`` | ``egress_ports_empty`` |
    ``egress_ports_not_integer`` | ``egress_ports_out_of_range``. A ``bool`` is not a port."""
    if isinstance(ports, (str, bytes, bytearray, Mapping)):
        raise EgressPortsError("egress_ports_malformed")
    try:
        entries = list(ports)
    except TypeError:
        raise EgressPortsError("egress_ports_malformed") from None
    if not entries:
        raise EgressPortsError("egress_ports_empty")
    for port in entries:
        if isinstance(port, bool) or not isinstance(port, int):
            raise EgressPortsError("egress_ports_not_integer")
        if not _PORT_MIN <= port <= _PORT_MAX:
            raise EgressPortsError("egress_ports_out_of_range")
    return frozenset(entries)


def parse_egress_ports(raw: str | None) -> frozenset[int]:
    """Read the projected ``VSIFY_EGRESS_PORTS`` value (decimal ports joined with ``,``).

    Absent or blank is ``egress_ports_absent``: the gateway never invents a default the host did not
    send (ADR-P058 §3). An entry that is not plain ASCII decimal is ``egress_ports_not_integer``
    (never ``int()``'s laxer reading of ``" +443"`` or ``"٤٤٣"``); the rest is
    :func:`validate_egress_ports`."""
    if raw is None or not raw.strip():
        raise EgressPortsError("egress_ports_absent")
    ports: list[int] = []
    for text in raw.split(","):
        text = text.strip()
        if not text or not text.isascii() or not text.isdigit():
            raise EgressPortsError("egress_ports_not_integer")
        ports.append(int(text))
    return validate_egress_ports(ports)


def port_allowed(port: object, ports: frozenset[int]) -> bool:
    """Whether a CONNECT target port is in the deployment policy. A ``bool`` is never a port."""
    return isinstance(port, int) and not isinstance(port, bool) and port in ports


# --------------------------------------------------------------------------- the address policy
# Mirrors egress_grammar.classify_resolved_address and its helpers; held by `address_vectors`.

#: The verdict for a dialable address. Every other verdict is a denial reason.
ADDRESS_ALLOWED = "allowed"

#: The CLOSED verdict set, identical to the framework's ``_ADDRESS_VERDICTS``.
ADDRESS_VERDICTS = (
    ADDRESS_ALLOWED,
    "invalid_address",
    "metadata",
    "nat64",
    "loopback",
    "link_local",
    "private_address",
    "not_global",
)

_METADATA_ADDRESSES = frozenset({
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("fd00:ec2::254"),
})

_NAT64_NETWORKS = (
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
)

_PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fec0::/10"),
)

_SHARED_NETWORKS = (ipaddress.ip_network("100.64.0.0/10"),)


def _as_address(value: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Mirror of ``egress_grammar._as_address``: only a ``str`` or an address object parses (an
    ``int`` would read as a packed address); an IPv6 zone id is dropped."""
    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        address = value
    elif isinstance(value, str):
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return None
    else:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.scope_id:
        address = ipaddress.IPv6Address(int(address))
    return address


def _classify(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Mirror of ``egress_grammar._classify`` — the same rules in the same order."""
    if address in _METADATA_ADDRESSES:
        return "metadata"
    if isinstance(address, ipaddress.IPv6Address):
        if address == ipaddress.IPv6Address("::1"):
            return "loopback"
        if address == ipaddress.IPv6Address("::"):
            return "not_global"
        if address.ipv4_mapped is not None:
            return _classify(address.ipv4_mapped)
        if int(address) >> 32 == 0:  # IPv4-compatible ::a.b.c.d (deprecated)
            return _classify(ipaddress.IPv4Address(int(address) & 0xFFFFFFFF))
        if any(address in net for net in _NAT64_NETWORKS):
            return "nat64"
        embedded = address.sixtofour
        if embedded is None and address.teredo is not None:
            embedded = address.teredo[1]
        if embedded is not None:
            verdict = _classify(embedded)
            return "not_global" if verdict == ADDRESS_ALLOWED else verdict
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    if any(address in net for net in _PRIVATE_NETWORKS):
        return "private_address"
    if any(address in net for net in _SHARED_NETWORKS):
        return "not_global"
    if address.is_multicast or address.is_unspecified or address.is_reserved:
        return "not_global"
    if not address.is_global:
        return "not_global"
    return ADDRESS_ALLOWED


def classify_resolved_address(addr: object) -> str:
    """Mirror of ``egress_grammar.classify_resolved_address``: ``"allowed"`` or a denial reason from
    :data:`ADDRESS_VERDICTS`. Never raises; a bad input is ``"invalid_address"``."""
    address = _as_address(addr)
    if address is None:
        return "invalid_address"
    return _classify(address)


# --------------------------------------------------------------------------- the gateway verdicts

TOKEN_ENV = "VSIFY_EGRESS_TOKEN"

#: The ``Proxy-Authorization`` scheme the shim sends and the gateway accepts (ADR-P058 §4). The
#: token is never placed in a proxy-URL userinfo.
TOKEN_SCHEME = "Bearer"

#: The gateway's categorical denial reasons, one per ADR-P058 §7 line.
REASON_TOKEN = "token"
REASON_METHOD = "method"
REASON_HOST = "host"
REASON_PORT = "port"
REASON_ADDRESS = "address"


def proxy_authorization_value(token: str) -> str:
    """The ``Proxy-Authorization`` header value carrying ``token``."""
    return f"{TOKEN_SCHEME} {token}"


def token_matches(presented: str | None, expected: str) -> bool:
    """Whether a ``Proxy-Authorization`` value carries the session token.

    The scheme is case-insensitive (RFC 9110 §11.1); the credential is compared with
    :func:`hmac.compare_digest`. An empty expected token matches nothing, so a gateway that somehow
    started without one denies every request rather than admitting an empty credential."""
    if not expected or presented is None:
        return False
    scheme, _, credential = presented.strip().partition(" ")
    if scheme.lower() != TOKEN_SCHEME.lower():
        return False
    return hmac.compare_digest(credential.strip().encode("utf-8"), expected.encode("utf-8"))


def target_verdict(host: str, port: int, policy: EgressPolicy, ports: frozenset[int]) -> str | None:
    """The pre-resolution verdict on a CONNECT target: ``None`` to proceed, else
    :data:`REASON_HOST` or :data:`REASON_PORT`, checked in that order (ADR-P058 §6 steps 3-4).

    An IP-literal target is matched as the literal string it is, so it passes only when the
    allowlist names that exact literal; an allowlisted name never admits an address."""
    if not policy.allows(host):
        return REASON_HOST
    if not port_allowed(port, ports):
        return REASON_PORT
    return None


def addresses_verdict(addresses: Iterable[str]) -> str | None:
    """The verdict on one resolution's results: ``None`` when there is at least one address and
    EVERY one is ``"allowed"``, else :data:`REASON_ADDRESS` (an empty resolution included)."""
    seen = False
    for address in addresses:
        seen = True
        if classify_resolved_address(address) != ADDRESS_ALLOWED:
            return REASON_ADDRESS
    return None if seen else REASON_ADDRESS
