"""Egress proxy: the single network exit of a browser session (ADR-0011).

Every connection Chromium opens for a session goes through one
``EgressProxy`` instance, bound to ``127.0.0.1`` on an ephemeral port and set
as the context's HTTP proxy with loopback *not* bypassed. Because Chromium
hands an HTTP proxy the unresolved host name, the proxy is also the session's
only DNS resolver. This closes the gaps that request interception alone leaves
open:

* **Redirect hops.** Playwright's ``route`` does not see the requests Chromium
  issues while following a redirect; the proxy sees every hop.
* **DNS rebinding.** The proxy resolves through the ``SsrfGuard`` and connects
  to an address the guard approved, so Chromium never does its own lookup.
* **Anything else that opens a socket** (WebSockets, beacons, prefetches,
  workers): with a proxy configured, it all has to go through the proxy.

The proxy then checks the peer address of the socket it actually opened
(layer 3) and logs every decision, which the ``NetworkRecorder`` joins with
its per-request records.

Protocol support is deliberately minimal: ``CONNECT`` tunnels (HTTPS, WSS and
WS: Chromium tunnels all WebSockets) and absolute-form plain HTTP requests,
one request per client connection, ``Connection: close``. Refused CONNECTs
get ``403``. A refused plain HTTP request has its connection closed without a
response, so the page cannot render a proxy error page as if it were the
site's.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass, field
from types import TracebackType
from typing import Self
from urllib.parse import urlsplit

from privacy_scanner.collector.clock import SessionClock
from privacy_scanner.domain.evidence import BlockReason, GuardViolation
from privacy_scanner.intake.ssrf_guard import GuardDecision, SsrfGuard
from privacy_scanner.intake.url import DEFAULT_PORTS, InvalidUrlError, canonical_host

logger = logging.getLogger(__name__)

MAX_HEAD_BYTES = 64 * 1024
CONNECT_TIMEOUT_S = 15.0
HEAD_TIMEOUT_S = 30.0
_PIPE_CHUNK = 64 * 1024
_HOP_BY_HOP = frozenset(
    {"connection", "keep-alive", "proxy-connection", "proxy-authorization", "te", "upgrade"}
)
_FORBIDDEN_RESPONSE = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
_BAD_REQUEST_RESPONSE = (
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
)


class _ProtocolError(Exception):
    """The client sent something this proxy does not speak."""


@dataclass(frozen=True, slots=True)
class _RequestHead:
    method: str
    target: str
    version: str
    headers: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class EgressEvent:
    """One connection decision taken by the proxy."""

    at_ms: int
    host: str
    port: int
    decision: GuardDecision
    connected_ip: str | None = None


@dataclass(slots=True)
class EgressLog:
    """What a session's proxy allowed, refused and connected to."""

    events: list[EgressEvent] = field(default_factory=list)
    violations: list[GuardViolation] = field(default_factory=list)

    def block_for(self, host: str, port: int) -> GuardDecision | None:
        """The guard decision that refused ``host:port``, if the proxy refused it."""
        for event in reversed(self.events):
            if (event.host, event.port) == (host, port) and not event.decision.allowed:
                return event.decision
        return None

    def address_for(self, host: str, port: int) -> str | None:
        """The address the proxy last connected to for ``host:port``."""
        for event in reversed(self.events):
            if (event.host, event.port) == (host, port) and event.connected_ip is not None:
                return event.connected_ip
        return None


def url_endpoint(url: str) -> tuple[str, int] | None:
    """``(canonical host, port)`` of an http(s)/ws(s) URL, as the proxy logs it."""
    try:
        parts = urlsplit(url)
        port = parts.port
        if not parts.hostname:
            return None
        host = canonical_host(parts.hostname)
    except (ValueError, InvalidUrlError):
        return None
    scheme = {"ws": "http", "wss": "https"}.get(parts.scheme, parts.scheme)
    if port is None:
        if scheme not in DEFAULT_PORTS:
            return None
        port = DEFAULT_PORTS[scheme]
    return host, port


@dataclass
class EgressProxy:
    guard: SsrfGuard
    clock: SessionClock
    log: EgressLog = field(default_factory=EgressLog)
    _server: asyncio.Server | None = field(default=None, init=False, repr=False)
    _handlers: set[asyncio.Task[None]] = field(default_factory=set, init=False, repr=False)

    @property
    def server_url(self) -> str:
        if self._server is None:
            raise RuntimeError("EgressProxy is not running")
        host, port = self._server.sockets[0].getsockname()[:2]
        return f"http://{host}:{port}"

    async def __aenter__(self) -> Self:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._server is not None:
            self._server.close()
        for task in tuple(self._handlers):
            task.cancel()
        if self._handlers:
            await asyncio.gather(*self._handlers, return_exceptions=True)
        if self._server is not None:
            await self._server.wait_closed()
            self._server = None

    # ------------------------------------------------------------------ #
    # Connection handling
    # ------------------------------------------------------------------ #
    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._handlers.add(task)
        try:
            head = await asyncio.wait_for(_read_head(reader), timeout=HEAD_TIMEOUT_S)
            request = _parse_head(head)
            if request.method == "CONNECT":
                await self._tunnel(request.target, reader, writer)
            else:
                await self._forward(request, reader, writer)
        except _ProtocolError as exc:
            logger.debug("egress proxy: bad request: %s", exc)
            with contextlib.suppress(OSError):
                writer.write(_BAD_REQUEST_RESPONSE)
                await writer.drain()
        except (TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            await _close(writer)
            if task is not None:
                self._handlers.discard(task)

    async def _tunnel(
        self, target: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        endpoint = _authority_endpoint(target)
        upstream = await self._open(endpoint, url=f"https://{target}")
        if upstream is None:
            writer.write(_FORBIDDEN_RESPONSE)
            await writer.drain()
            return
        up_reader, up_writer = upstream
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await _splice(reader, writer, up_reader, up_writer)

    async def _forward(
        self, request: _RequestHead, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        target = request.target
        parts = urlsplit(target)
        if parts.scheme != "http":
            raise _ProtocolError(f"expected an absolute http:// URL, got {target!r}")
        endpoint = url_endpoint(target)
        if endpoint is None:
            raise _ProtocolError(f"unusable request target {target!r}")
        upstream = await self._open(endpoint, url=target)
        if upstream is None:
            return  # closed without a response: see module docstring
        up_reader, up_writer = upstream

        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        lines = [f"{request.method} {path} {request.version}"]
        lines += [f"{k}: {v}" for k, v in request.headers if k.lower() not in _HOP_BY_HOP]
        lines.append("Connection: close")
        up_writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
        await up_writer.drain()

        # The request body (if any) must flow while we wait for the response head.
        body = asyncio.create_task(_pump(reader, up_writer))
        try:
            # Make the browser drop the connection after this response too, so it
            # never sends a second request down a connection bound to this origin.
            response_head = await _read_head(up_reader)
            writer.write(_force_close(response_head))
            await writer.drain()
            await _pump(up_reader, writer)
        finally:
            body.cancel()
            await asyncio.gather(body, return_exceptions=True)
            await _close(up_writer)

    async def _open(
        self, endpoint: tuple[str, int] | None, *, url: str
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
        """Guard-check ``endpoint`` and connect to an approved address, or log a refusal."""
        if endpoint is None:
            decision = GuardDecision.block(BlockReason.FORBIDDEN_HOST, f"unusable target {url}")
            self._record(("", 0), decision)
            return None
        host, port = endpoint
        decision = await self.guard.check_host(host, port)
        if not decision.allowed:
            logger.info("egress refused %s:%d: %s", host, port, decision.detail)
            self._record(endpoint, decision)
            return None

        last_error: OSError | None = None
        for address in decision.addresses:
            try:
                up_reader, up_writer = await asyncio.wait_for(
                    asyncio.open_connection(address, port), timeout=CONNECT_TIMEOUT_S
                )
            except (OSError, TimeoutError) as exc:
                last_error = exc if isinstance(exc, OSError) else OSError(str(exc))
                continue
            peer = str(up_writer.get_extra_info("peername")[0])
            reason = self.guard.address_reason(peer)
            if reason is not None:  # layer 3: the socket we got is not the one we vetted
                logger.warning("egress violation: %s connected to %s (%s)", url, peer, reason)
                self.log.violations.append(GuardViolation(url=url, server_ip=peer, reason=reason))
                await _close(up_writer)
                return None
            self._record(endpoint, decision, connected_ip=peer)
            return up_reader, up_writer
        logger.info("egress could not reach %s:%d: %s", host, port, last_error)
        self._record(endpoint, decision)
        return None

    def _record(
        self, endpoint: tuple[str, int], decision: GuardDecision, connected_ip: str | None = None
    ) -> None:
        host, port = endpoint
        self.log.events.append(
            EgressEvent(
                at_ms=self.clock.now_ms(),
                host=host,
                port=port,
                decision=decision,
                connected_ip=connected_ip,
            )
        )


# ---------------------------------------------------------------------- #
# HTTP/1.1 framing helpers
# ---------------------------------------------------------------------- #
async def _read_head(reader: asyncio.StreamReader) -> bytes:
    try:
        return await reader.readuntil(b"\r\n\r\n")
    except asyncio.LimitOverrunError as exc:
        raise _ProtocolError("message head too large") from exc


def _parse_head(head: bytes) -> _RequestHead:
    if len(head) > MAX_HEAD_BYTES:
        raise _ProtocolError("message head too large")
    request_line, *header_lines = head.decode("latin-1").split("\r\n")
    try:
        method, target, version = request_line.split(" ")
    except ValueError as exc:
        raise _ProtocolError(f"malformed request line {request_line!r}") from exc
    headers: list[tuple[str, str]] = []
    for line in header_lines:
        if not line:
            continue
        name, sep, value = line.partition(":")
        if not sep:
            raise _ProtocolError(f"malformed header line {line!r}")
        headers.append((name.strip(), value.strip()))
    return _RequestHead(method.upper(), target, version, tuple(headers))


def _authority_endpoint(authority: str) -> tuple[str, int] | None:
    """``host:port`` from a CONNECT target (port is mandatory there)."""
    host, sep, port_text = authority.rpartition(":")
    if not sep or not port_text.isdigit():
        return None
    try:
        return canonical_host(host.strip("[]").lower()), int(port_text)
    except InvalidUrlError:
        return None


def _force_close(response_head: bytes) -> bytes:
    status_line, *lines = response_head.decode("latin-1").rstrip("\r\n").split("\r\n")
    kept = [
        line
        for line in lines
        if line.partition(":")[0].strip().lower() not in ("connection", "keep-alive")
    ]
    return ("\r\n".join([status_line, *kept, "Connection: close"]) + "\r\n\r\n").encode("latin-1")


async def _splice(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    up_reader: asyncio.StreamReader,
    up_writer: asyncio.StreamWriter,
) -> None:
    """Copy bytes both ways until either side closes, then close both."""
    try:
        pumps = (
            asyncio.create_task(_pump(client_reader, up_writer)),
            asyncio.create_task(_pump(up_reader, client_writer)),
        )
        try:
            await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for pump in pumps:
                pump.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)
    finally:
        await _close(up_writer)


async def _pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    with contextlib.suppress(ConnectionError, OSError):
        while chunk := await reader.read(_PIPE_CHUNK):
            writer.write(chunk)
            await writer.drain()


async def _close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    with contextlib.suppress(ConnectionError, OSError):
        await writer.wait_closed()
