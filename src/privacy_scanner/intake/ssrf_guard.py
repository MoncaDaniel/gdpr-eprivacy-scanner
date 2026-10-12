"""SSRF guard for a service that points a real browser at user-supplied URLs.

Threat: a submitted URL (or anything the page loads, or any redirect) makes
our Chromium reach the cloud metadata server, loopback services or the private
network. This module is the policy behind the defence in depth described in
ADR-0005 and ``docs/architecture/security.md``:

1. **Pre-flight**: the target URL is resolved and every resolved address must
   be globally routable.
2. **Per-connection**: the session's egress proxy (ADR-0011) calls
   ``check_host`` for *every* connection the browser opens (redirect hops,
   sub-resources, frames, WebSockets) and connects only to an address this
   guard approved, so Chromium never resolves names itself.
3. **Post-connect**: the proxy re-checks the peer address of the socket it
   actually opened with ``address_reason``.
4. **Infrastructure** (Phase 4): VPC egress firewall denying private ranges.

The address policy is pure and exhaustively unit-tested; resolution is
injectable so tests never touch real DNS.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from privacy_scanner.domain.evidence import BlockReason
from privacy_scanner.intake.url import DEFAULT_PORTS, InvalidUrlError, canonical_host

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str, int], Awaitable[list[str]]]

_NAT64 = ipaddress.IPv6Network("64:ff9b::/96")
_FORBIDDEN_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa", ".lan", ".intranet")
_FORBIDDEN_NAMES = frozenset({"localhost", "metadata.google.internal"})


def non_public_reason(ip: IPAddress, *, allow_loopback: bool = False) -> str | None:
    """Return why ``ip`` must not be contacted, or ``None`` if it is public.

    Embedded IPv4 addresses (IPv4-mapped, NAT64, 6to4) are unwrapped first, so
    ``::ffff:169.254.169.254`` is treated exactly like the metadata address.
    """
    if isinstance(ip, ipaddress.IPv6Address):
        embedded: ipaddress.IPv4Address | None = ip.ipv4_mapped or ip.sixtofour
        if embedded is None and ip in _NAT64:
            embedded = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if embedded is not None:
            return non_public_reason(embedded, allow_loopback=allow_loopback)

    if ip.is_loopback:
        return None if allow_loopback else "loopback address"
    # Order matters only for the message: the first matching property is reported.
    for blocked, reason in (
        (ip.is_link_local, "link-local address (includes cloud metadata endpoints)"),
        (ip.is_unspecified, "unspecified address"),
        (ip.is_multicast, "multicast address"),
        (ip.is_private, "private-use address"),
        (ip.is_reserved, "reserved address"),
        (not ip.is_global, "address is not globally routable"),
    ):
        if blocked:
            return reason
    return None


async def system_resolver(host: str, port: int) -> list[str]:
    """Resolve ``host`` with the OS resolver (the one Chromium also uses)."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({str(info[4][0]) for info in infos})


@dataclass(frozen=True, slots=True)
class NetworkPolicy:
    allowed_ports: frozenset[int] | None = frozenset({80, 443})
    """``None`` allows any port (tests only: fixture servers use random ports)."""
    allow_loopback: bool = False
    """Tests only. Link-local/metadata and private ranges stay blocked regardless."""


@dataclass(frozen=True, slots=True)
class GuardDecision:
    allowed: bool
    reason: BlockReason | None = None
    detail: str | None = None
    addresses: tuple[str, ...] = ()

    @classmethod
    def allow(cls, addresses: Iterable[str] = ()) -> GuardDecision:
        return cls(allowed=True, addresses=tuple(addresses))

    @classmethod
    def block(cls, reason: BlockReason, detail: str) -> GuardDecision:
        return cls(allowed=False, reason=reason, detail=detail)


@dataclass(slots=True)
class SsrfGuard:
    policy: NetworkPolicy = field(default_factory=NetworkPolicy)
    resolver: Resolver = system_resolver
    resolve_timeout_s: float = 5.0
    cache_ttl_s: float = 30.0
    _cache: dict[tuple[str, int], tuple[float, GuardDecision]] = field(
        default_factory=dict, init=False, repr=False
    )

    async def check_url(self, url: str) -> GuardDecision:
        """Decide whether the browser may fetch ``url``."""
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError as exc:
            return GuardDecision.block(BlockReason.FORBIDDEN_HOST, f"unparseable URL: {exc}")
        scheme = parts.scheme.lower()
        if scheme in ("ws", "wss"):
            scheme = "http" if scheme == "ws" else "https"
        if scheme not in DEFAULT_PORTS:
            return GuardDecision.block(BlockReason.FORBIDDEN_SCHEME, f"scheme '{scheme}'")
        if not parts.hostname:
            return GuardDecision.block(BlockReason.FORBIDDEN_HOST, "URL has no host")
        try:
            host = canonical_host(parts.hostname)
        except InvalidUrlError as exc:
            return GuardDecision.block(BlockReason.FORBIDDEN_HOST, str(exc))
        return await self.check_host(host, port if port is not None else DEFAULT_PORTS[scheme])

    async def check_host(self, host: str, port: int) -> GuardDecision:
        """Decide whether ``host:port`` may be contacted. ``host`` must be canonical."""
        allowed_ports = self.policy.allowed_ports
        if allowed_ports is not None and port not in allowed_ports:
            return GuardDecision.block(BlockReason.FORBIDDEN_PORT, f"port {port} is not allowed")

        key = (host, port)
        cached = self._cache.get(key)
        now = time.monotonic()
        if cached is not None and now - cached[0] < self.cache_ttl_s:
            return cached[1]
        decision = await self._decide(host, port)
        self._cache[key] = (now, decision)
        return decision

    async def _decide(self, host: str, port: int) -> GuardDecision:
        try:
            literal: IPAddress | None = ipaddress.ip_address(host)
        except ValueError:
            literal = None

        if literal is None:
            if host in _FORBIDDEN_NAMES or host.endswith(_FORBIDDEN_SUFFIXES):
                return GuardDecision.block(BlockReason.FORBIDDEN_HOST, f"'{host}' is a local name")
            if "." not in host:
                return GuardDecision.block(
                    BlockReason.FORBIDDEN_HOST, f"single-label host '{host}' is not public"
                )
            try:
                addresses = await asyncio.wait_for(
                    self.resolver(host, port), timeout=self.resolve_timeout_s
                )
            except (OSError, TimeoutError) as exc:
                return GuardDecision.block(
                    BlockReason.DNS_FAILURE, f"cannot resolve '{host}': {exc}"
                )
            if not addresses:
                return GuardDecision.block(BlockReason.DNS_FAILURE, f"'{host}' has no addresses")
        else:
            addresses = [str(literal)]

        # Every address must be public: a mixed answer is a classic rebinding setup.
        for address in addresses:
            reason = self.address_reason(address)
            if reason is not None:
                return GuardDecision.block(
                    BlockReason.NON_PUBLIC_ADDRESS, f"{host} resolves to {address}: {reason}"
                )
        return GuardDecision.allow(addresses)

    def address_reason(self, address: str) -> str | None:
        """Policy check for an address actually used by the browser (layer 3)."""
        try:
            ip = ipaddress.ip_address(address.strip("[]").split("%", 1)[0])
        except ValueError:
            return f"unparseable address '{address}'"
        return non_public_reason(ip, allow_loopback=self.policy.allow_loopback)
