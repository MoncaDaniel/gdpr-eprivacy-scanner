"""Network observation and enforcement for one browser context.

``NetworkRecorder`` does two jobs that must not drift apart:

* **Enforcement**: every request and WebSocket Playwright lets us intercept is
  checked by the ``SsrfGuard`` before it leaves the browser, so the refusal is
  attributed to the exact request. This is an *attribution* layer: the
  enforcement boundary is the session's ``EgressProxy`` (ADR-0011), which also
  sees what interception cannot (redirect hops).
* **Observation**: every request is recorded with timing, frame, redirect and
  response metadata, *including* the ones we blocked. Server addresses,
  proxy-level refusals and layer-3 violations are joined in from the
  ``EgressLog``.

Playwright delivers ``request``/``response``/``requestfailed`` events and route
callbacks in an order that is not guaranteed, so state is merged per request
object and only materialised in ``records()``.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from playwright.async_api import BrowserContext, Error, Request, Response, Route, WebSocketRoute

from privacy_scanner.collector.clock import SessionClock
from privacy_scanner.collector.egress import EgressLog, url_endpoint
from privacy_scanner.domain.evidence import GuardViolation, RequestRecord
from privacy_scanner.intake.ssrf_guard import GuardDecision, SsrfGuard

logger = logging.getLogger(__name__)

MAX_RECORDED_URL_LENGTH = 4096
_ALL = re.compile(r".*")


@dataclass(slots=True)
class _Entry:
    sequence: int
    started_ms: int
    url: str
    method: str
    resource_type: str
    frame_url: str | None
    is_navigation: bool
    redirected_from: str | None
    status: int | None = None
    failure: str | None = None
    blocked: GuardDecision | None = None


@dataclass  # no slots: Playwright caches handler wrappers as attributes on the owner
class NetworkRecorder:
    guard: SsrfGuard
    clock: SessionClock
    egress: EgressLog
    max_requests: int
    _entries: dict[Request, _Entry] = field(default_factory=dict, init=False)
    _websockets: list[_Entry] = field(default_factory=list, init=False)
    _sequence: int = field(default=0, init=False)
    dropped: int = field(default=0, init=False)

    async def install(self, context: BrowserContext) -> None:
        await context.route("**/*", self._on_route)
        await context.route_web_socket(_ALL, self._on_websocket)
        context.on("request", self._on_request)
        context.on("response", self._on_response)
        context.on("requestfailed", self._on_failed)

    # ------------------------------------------------------------------ #
    # Enforcement
    # ------------------------------------------------------------------ #
    async def _on_route(self, route: Route) -> None:
        request = route.request
        decision = await self.guard.check_url(request.url)
        try:
            if decision.allowed:
                await route.continue_()
                return
            entry = self._entry_for(request)
            if entry is not None:
                entry.blocked = decision
            logger.info("guard blocked %s: %s", request.url, decision.detail)
            await route.abort("blockedbyclient")
        except Error:
            # The page or context closed while the route was pending: nothing to do.
            logger.debug("route for %s settled after context closed", request.url)

    async def _on_websocket(self, ws: WebSocketRoute) -> None:
        decision = await self.guard.check_url(ws.url)
        entry = _Entry(
            sequence=self._next_sequence(),
            started_ms=self.clock.now_ms(),
            url=ws.url,
            method="GET",
            resource_type="websocket",
            frame_url=None,
            is_navigation=False,
            redirected_from=None,
            blocked=None if decision.allowed else decision,
        )
        self._websockets.append(entry)
        try:
            if decision.allowed:
                ws.connect_to_server()
            else:
                await ws.close(code=1008, reason="blocked by scanner network policy")
        except Error:
            logger.debug("websocket route for %s settled after context closed", ws.url)

    # ------------------------------------------------------------------ #
    # Observation
    # ------------------------------------------------------------------ #
    def _on_request(self, request: Request) -> None:
        self._entry_for(request)

    def _on_response(self, response: Response) -> None:
        entry = self._entry_for(response.request)
        if entry is None:
            return
        entry.status = response.status

    def _on_failed(self, request: Request) -> None:
        entry = self._entry_for(request)
        if entry is not None:
            entry.failure = request.failure or "unknown failure"

    def _entry_for(self, request: Request) -> _Entry | None:
        entry = self._entries.get(request)
        if entry is not None:
            return entry
        if len(self._entries) >= self.max_requests:
            self.dropped += 1
            return None
        redirected = request.redirected_from
        entry = _Entry(
            sequence=self._next_sequence(),
            started_ms=self.clock.now_ms(),
            url=request.url,
            method=request.method,
            resource_type=request.resource_type,
            frame_url=_frame_url(request),
            is_navigation=request.is_navigation_request(),
            redirected_from=redirected.url if redirected is not None else None,
        )
        self._entries[request] = entry
        return entry

    def _next_sequence(self) -> int:
        self._sequence += 1
        return self._sequence - 1

    # ------------------------------------------------------------------ #
    # Results
    # ------------------------------------------------------------------ #
    @property
    def violations(self) -> tuple[GuardViolation, ...]:
        return tuple(self.egress.violations)

    def blocked_navigation(self) -> GuardDecision | None:
        """The guard decision that stopped a main-frame navigation, if any."""
        for entry in self._entries.values():
            blocked = self._blocked(entry)
            if entry.is_navigation and blocked is not None and entry.resource_type == "document":
                return blocked
        return None

    def records(self) -> tuple[RequestRecord, ...]:
        entries = sorted([*self._entries.values(), *self._websockets], key=lambda e: e.sequence)
        return tuple(self._to_record(e) for e in entries)

    def _blocked(self, entry: _Entry) -> GuardDecision | None:
        """Interception-layer refusal, else a proxy refusal of a request that failed."""
        if entry.blocked is not None:
            return entry.blocked
        if entry.status is not None or entry.failure is None:
            return None  # it got a response (or is still pending): the proxy let it through
        endpoint = url_endpoint(entry.url)
        return self.egress.block_for(*endpoint) if endpoint is not None else None

    def _to_record(self, entry: _Entry) -> RequestRecord:
        url = entry.url
        blocked = self._blocked(entry)
        endpoint = url_endpoint(url)
        server_ip = (
            self.egress.address_for(*endpoint)
            if endpoint is not None and entry.status is not None
            else None
        )
        return RequestRecord(
            sequence=entry.sequence,
            url=url[:MAX_RECORDED_URL_LENGTH],
            url_truncated=len(url) > MAX_RECORDED_URL_LENGTH,
            method=entry.method,
            resource_type=entry.resource_type,
            started_ms=entry.started_ms,
            frame_url=entry.frame_url,
            is_navigation=entry.is_navigation,
            redirected_from=entry.redirected_from,
            status=entry.status,
            server_ip=server_ip,
            failure=entry.failure,
            blocked_by=blocked.reason if blocked is not None else None,
        )


def _frame_url(request: Request) -> str | None:
    try:
        return request.frame.url or None
    except Error:
        return None  # service-worker or detached-frame request
