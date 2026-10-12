"""Point-in-time captures of page state: Web Storage, DOM and screenshot.

All captures are read-only: they evaluate script that inspects state but never
writes storage, dispatches events or scrolls.
"""

from __future__ import annotations

import logging
from functools import cache
from importlib import resources
from typing import Any

from playwright.async_api import Error, Frame, Page

from privacy_scanner.collector.artifacts import ArtifactStore
from privacy_scanner.collector.fingerprint import ValueFingerprinter
from privacy_scanner.domain.evidence import ArtifactRef, FrameRecord, StorageArea, StorageRecord

logger = logging.getLogger(__name__)

MAX_STORAGE_VALUE_CHARS = 65_536
SCREENSHOT_TIMEOUT_MS = 10_000


@cache
def _script(name: str) -> str:
    source = resources.files("privacy_scanner.collector.scripts").joinpath(name).read_text("utf-8")
    return source.strip().rstrip(";")


async def capture_storage(
    page: Page, fingerprinter: ValueFingerprinter
) -> tuple[StorageRecord, ...]:
    """Read localStorage/sessionStorage of every frame (deduplicated by origin)."""
    records: dict[tuple[str, StorageArea, str], StorageRecord] = {}
    for frame in page.frames:
        result = await _evaluate(frame, _script("read_storage.js"), MAX_STORAGE_VALUE_CHARS)
        if not isinstance(result, dict) or not result.get("origin") or result["origin"] == "null":
            continue
        origin = str(result["origin"])
        for item in result.get("entries", []):
            area = StorageArea(item["area"])
            key = str(item["key"])
            records[(origin, area, key)] = StorageRecord(
                origin=origin,
                area=area,
                key=key,
                value=fingerprinter.fingerprint(str(item["value"]), length=int(item["length"])),
            )
    return tuple(records[k] for k in sorted(records))


async def capture_frames(
    page: Page, store: ArtifactStore, prefix: str, *, max_frames: int, max_dom_bytes: int
) -> tuple[FrameRecord, ...]:
    """Serialise each frame's DOM (with open shadow roots) as an artefact."""
    frames: list[FrameRecord] = []
    for index, frame in enumerate(page.frames[:max_frames]):
        html = await _evaluate(frame, _script("serialize_dom.js"))
        dom: ArtifactRef | None = None
        truncated = False
        if isinstance(html, str) and html:
            data = html.encode("utf-8", "surrogatepass")
            truncated = len(data) > max_dom_bytes
            dom = store.put(
                f"{prefix}/dom/frame-{index:02d}.html",
                data[:max_dom_bytes],
                "text/html; charset=utf-8",
            )
        frames.append(
            FrameRecord(
                url=frame.url,
                name=frame.name,
                is_main=frame is page.main_frame,
                dom=dom,
                dom_truncated=truncated,
            )
        )
    return tuple(frames)


async def capture_screenshot(page: Page, store: ArtifactStore, prefix: str) -> ArtifactRef | None:
    """Viewport screenshot: what a first-time visitor sees above the fold."""
    try:
        png = await page.screenshot(type="png", full_page=False, timeout=SCREENSHOT_TIMEOUT_MS)
    except Error as exc:
        logger.warning("screenshot failed: %s", exc)
        return None
    return store.put(f"{prefix}/screenshot.png", png, "image/png")


async def main_document_html(page: Page, limit: int = 200_000) -> str:
    """A prefix of the main document's HTML, for obstruction detection."""
    try:
        return (await page.content())[:limit]
    except Error:
        return ""


async def _evaluate(frame: Frame, script: str, arg: Any = None) -> Any:
    try:
        return await frame.evaluate(script, arg)
    except Error as exc:
        # Detached, navigating or crashed frames are expected on real sites.
        logger.debug("evaluate failed in frame %s: %s", frame.url, exc)
        return None
