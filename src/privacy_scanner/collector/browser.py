"""Chromium launch and context profile: a first-time EU desktop visitor.

We present as an ordinary desktop Chrome (no "HeadlessChrome" token in the
user agent, an ordinary viewport and locale) because some consent platforms
skip the banner for obvious bots, which would make the baseline unrepresentative.
We do **not** use anti-detection techniques (patched ``navigator.webdriver``,
stealth plugins, CAPTCHA solving): if a site challenges us, we report that
(ADR-0010).
"""

from __future__ import annotations

from playwright.async_api import Browser, BrowserContext, Playwright

from privacy_scanner.config import ScannerSettings
from privacy_scanner.domain.evidence import BrowserEnvironment, Viewport

BASE_CHROMIUM_ARGS: tuple[str, ...] = (
    # WebRTC must not reveal or probe local interfaces (SSRF layer, ADR-0005).
    "--force-webrtc-ip-handling-policy",
    "--webrtc-ip-handling-policy=disable_non_proxied_udp",
    # Determinism: no background component updates or first-run UI.
    "--disable-background-networking",
    "--disable-component-update",
    "--no-first-run",
    "--no-default-browser-check",
)

_UA_TEMPLATE = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"
)


def desktop_user_agent(engine_version: str) -> str:
    """A reduced-UA string (as Chrome itself sends) for the running engine version."""
    major = engine_version.split(".", 1)[0]
    return _UA_TEMPLATE.format(major=major)


async def launch_browser(playwright: Playwright, settings: ScannerSettings) -> Browser:
    return await playwright.chromium.launch(
        headless=settings.headless,
        args=[*BASE_CHROMIUM_ARGS, *settings.extra_chromium_args],
    )


def browser_environment(browser: Browser, settings: ScannerSettings) -> BrowserEnvironment:
    return BrowserEnvironment(
        engine="chromium",
        engine_version=browser.version,
        user_agent=desktop_user_agent(browser.version),
        viewport=Viewport(width=settings.viewport_width, height=settings.viewport_height),
        locale=settings.locale,
        timezone=settings.timezone,
        accept_language=settings.accept_language,
        headless=settings.headless,
        vantage_point=settings.vantage_point,
    )


async def new_isolated_context(
    browser: Browser, environment: BrowserEnvironment, *, proxy_server: str
) -> BrowserContext:
    """A fresh profile: no cookies, no storage, no cache, no service workers.

    All traffic leaves through ``proxy_server`` (the session's ``EgressProxy``,
    ADR-0011). ``<-loopback>`` removes Chromium's implicit proxy bypass for
    localhost and loopback addresses, which would otherwise be a direct path
    to services on the scanner host.

    Service workers are blocked so that every request is visible to (and
    attributable by) our routing layer, and so a worker cannot replay cached
    state between sessions (ADR-0010).
    """
    return await browser.new_context(
        proxy={"server": proxy_server, "bypass": "<-loopback>"},
        user_agent=environment.user_agent,
        viewport={"width": environment.viewport.width, "height": environment.viewport.height},
        locale=environment.locale,
        timezone_id=environment.timezone,
        extra_http_headers={"Accept-Language": environment.accept_language},
        service_workers="block",
        accept_downloads=False,
        java_script_enabled=True,
        color_scheme="light",
        device_scale_factor=1,
    )
