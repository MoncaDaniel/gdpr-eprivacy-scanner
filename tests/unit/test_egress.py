"""Egress proxy (ADR-0011): the session's only network exit."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

import pytest

from privacy_scanner.collector.clock import SessionClock
from privacy_scanner.collector.egress import EgressProxy, url_endpoint
from privacy_scanner.domain.evidence import BlockReason
from privacy_scanner.intake.ssrf_guard import GuardDecision, NetworkPolicy, SsrfGuard


async def _resolver(host: str, port: int) -> list[str]:
    if host.endswith(".test"):
        return ["127.0.0.1"]
    if host == "metadata.example":
        return ["169.254.169.254"]
    raise OSError("NXDOMAIN")


def _guard() -> SsrfGuard:
    return SsrfGuard(
        policy=NetworkPolicy(allowed_ports=None, allow_loopback=True), resolver=_resolver
    )


@dataclass
class Upstream:
    port: int
    received: list[bytes] = field(default_factory=list)


@pytest.fixture
async def upstream() -> AsyncIterator[Upstream]:
    """Echo-ish origin: records the request head and body, answers keep-alive."""
    state = Upstream(port=0)

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        head = await reader.readuntil(b"\r\n\r\n")
        length = next(
            (
                int(line.split(b":")[1])
                for line in head.split(b"\r\n")
                if line.lower().startswith(b"content-length:")
            ),
            0,
        )
        body = await reader.readexactly(length) if length else b""
        state.received.append(head + body)
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n"
            b"Keep-Alive: timeout=5\r\n\r\nok"
        )
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    state.port = server.sockets[0].getsockname()[1]
    async with server:
        yield state


async def _exchange(proxy: EgressProxy, request: bytes) -> bytes:
    host, port = proxy.server_url.removeprefix("http://").split(":")
    reader, writer = await asyncio.open_connection(host, int(port))
    writer.write(request)
    await writer.drain()
    data = await asyncio.wait_for(reader.read(), timeout=5)
    writer.close()
    return data


async def test_plain_http_is_forwarded_in_origin_form_and_connection_closed(
    upstream: Upstream,
) -> None:
    async with EgressProxy(_guard(), SessionClock()) as proxy:
        reply = await _exchange(
            proxy,
            f"POST http://site.test:{upstream.port}/form?a=1 HTTP/1.1\r\n"
            f"Host: site.test:{upstream.port}\r\nProxy-Connection: keep-alive\r\n"
            "Content-Length: 5\r\n\r\nhello".encode(),
        )

    sent = upstream.received[0]
    assert sent.startswith(b"POST /form?a=1 HTTP/1.1\r\n")
    assert b"Proxy-Connection" not in sent
    assert b"Connection: close" in sent
    assert sent.endswith(b"hello")
    assert reply.startswith(b"HTTP/1.1 200 OK")
    assert b"keep-alive" not in reply.lower()
    assert b"Connection: close" in reply
    assert reply.endswith(b"ok")
    assert proxy.log.address_for("site.test", upstream.port) == "127.0.0.1"


async def test_refused_plain_http_gets_no_response_at_all() -> None:
    async with EgressProxy(_guard(), SessionClock()) as proxy:
        reply = await _exchange(
            proxy, b"GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\n\r\n"
        )
    assert reply == b""
    block = proxy.log.block_for("169.254.169.254", 80)
    assert block is not None
    assert block.reason is BlockReason.NON_PUBLIC_ADDRESS


@pytest.mark.parametrize(
    ("target", "host", "port", "reason"),
    [
        ("metadata.example:443", "metadata.example", 443, BlockReason.NON_PUBLIC_ADDRESS),
        ("[::ffff:a9fe:a9fe]:443", "::ffff:169.254.169.254", 443, BlockReason.NON_PUBLIC_ADDRESS),
        ("LOCALHOST:443", "localhost", 443, BlockReason.FORBIDDEN_HOST),
        ("nxdomain.example:443", "nxdomain.example", 443, BlockReason.DNS_FAILURE),
    ],
)
async def test_refused_connect_gets_403_and_is_logged(
    target: str, host: str, port: int, reason: BlockReason
) -> None:
    async with EgressProxy(_guard(), SessionClock()) as proxy:
        reply = await _exchange(proxy, f"CONNECT {target} HTTP/1.1\r\n\r\n".encode())
    assert reply.startswith(b"HTTP/1.1 403")
    block = proxy.log.block_for(host, port)
    assert block is not None
    assert block.reason is reason


async def test_connect_tunnels_bytes_to_the_vetted_address(upstream: Upstream) -> None:
    async with EgressProxy(_guard(), SessionClock()) as proxy:
        reply = await _exchange(
            proxy,
            f"CONNECT site.test:{upstream.port} HTTP/1.1\r\n\r\n"
            "GET /inside-tunnel HTTP/1.1\r\nHost: x\r\n\r\n".encode(),
        )
    assert reply.startswith(b"HTTP/1.1 200 Connection Established\r\n\r\nHTTP/1.1 200 OK")
    assert upstream.received[0].startswith(b"GET /inside-tunnel")


async def test_peer_address_is_rechecked_after_connect(upstream: Upstream) -> None:
    """Layer 3: if the socket we opened is not public, nothing is relayed."""

    class LyingGuard(SsrfGuard):
        async def check_host(self, host: str, port: int) -> GuardDecision:
            return GuardDecision.allow(["127.0.0.1"])  # e.g. a resolver bug

    guard = LyingGuard(policy=NetworkPolicy(allowed_ports=None, allow_loopback=False))
    async with EgressProxy(guard, SessionClock()) as proxy:
        reply = await _exchange(
            proxy, f"CONNECT public.example:{upstream.port} HTTP/1.1\r\n\r\n".encode()
        )
    assert reply.startswith(b"HTTP/1.1 403")
    assert upstream.received == []
    [violation] = proxy.log.violations
    assert violation.server_ip == "127.0.0.1"


@pytest.mark.parametrize(
    "request_bytes",
    [b"NONSENSE\r\n\r\n", b"GET /relative HTTP/1.1\r\n\r\n", b"GET ftp://x/ HTTP/1.1\r\n\r\n"],
)
async def test_malformed_requests_get_400(request_bytes: bytes) -> None:
    async with EgressProxy(_guard(), SessionClock()) as proxy:
        reply = await _exchange(proxy, request_bytes)
    assert reply.startswith(b"HTTP/1.1 400")
    assert proxy.log.events == []


@pytest.mark.parametrize(
    ("url", "endpoint"),
    [
        ("https://Example.com/x", ("example.com", 443)),
        ("http://example.com/", ("example.com", 80)),
        ("wss://example.com/s", ("example.com", 443)),
        ("ws://example.com:8080/s", ("example.com", 8080)),
        ("http://[::1]:81/", ("::1", 81)),
        ("data:text/plain,hi", None),
    ],
)
def test_url_endpoint_matches_what_the_proxy_logs(
    url: str, endpoint: tuple[str, int] | None
) -> None:
    assert url_endpoint(url) == endpoint
