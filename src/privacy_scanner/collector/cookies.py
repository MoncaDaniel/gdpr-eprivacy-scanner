"""Cookie-jar observation with first-seen timing.

Chromium does not timestamp cookies, so we poll the context's jar. A cookie's
``first_observed_ms`` is therefore an upper bound on when it was set, accurate
to the poll interval. Cookies that are set and later deleted are kept: storing
them already happened (Art. 5(3) ePrivacy covers the act of storing).
Polling the jar is invisible to the page, so it is not an interaction.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field
from datetime import UTC, datetime

from playwright.async_api import BrowserContext, Cookie, Error

from privacy_scanner.collector.clock import SessionClock
from privacy_scanner.collector.fingerprint import ValueFingerprinter
from privacy_scanner.domain.evidence import CookieRecord, SameSite

CookieKey = tuple[str, str, str]


@dataclass(slots=True)
class _Observed:
    first_observed_ms: int
    cookie: Cookie


@dataclass(slots=True)
class CookieJarObserver:
    context: BrowserContext
    clock: SessionClock
    interval_s: float
    _seen: dict[CookieKey, _Observed] = field(default_factory=dict, init=False)

    async def poll_once(self) -> None:
        try:
            cookies = await self.context.cookies()
        except Error:
            return  # context closing
        now = self.clock.now_ms()
        for cookie in cookies:
            key = (cookie.get("name", ""), cookie.get("domain", ""), cookie.get("path", "/"))
            seen = self._seen.get(key)
            if seen is None:
                self._seen[key] = _Observed(first_observed_ms=now, cookie=cookie)
            else:
                seen.cookie = cookie  # keep the latest attributes and value

    async def run(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            await self.poll_once()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=self.interval_s)

    def records(
        self, observed_at: datetime, fingerprinter: ValueFingerprinter
    ) -> tuple[CookieRecord, ...]:
        items = sorted(self._seen.items(), key=lambda kv: (kv[1].first_observed_ms, kv[0]))
        return tuple(
            to_cookie_record(seen.cookie, seen.first_observed_ms, observed_at, fingerprinter)
            for _, seen in items
        )


def to_cookie_record(
    cookie: Cookie, first_observed_ms: int, observed_at: datetime, fingerprinter: ValueFingerprinter
) -> CookieRecord:
    expires_raw = cookie.get("expires", -1)
    expires_at: datetime | None = None
    lifetime: int | None = None
    if expires_raw is not None and expires_raw >= 0:
        expires_at = datetime.fromtimestamp(expires_raw, tz=UTC)
        lifetime = round((expires_at - observed_at).total_seconds())

    same_site_raw = cookie.get("sameSite")
    same_site = SameSite(same_site_raw) if same_site_raw in {s.value for s in SameSite} else None

    return CookieRecord(
        name=cookie.get("name", ""),
        domain=cookie.get("domain", ""),
        path=cookie.get("path", "/"),
        value=fingerprinter.fingerprint(cookie.get("value", "")),
        expires_at=expires_at,
        lifetime_seconds=lifetime,
        http_only=bool(cookie.get("httpOnly", False)),
        secure=bool(cookie.get("secure", False)),
        same_site=same_site,
        first_observed_ms=first_observed_ms,
    )
