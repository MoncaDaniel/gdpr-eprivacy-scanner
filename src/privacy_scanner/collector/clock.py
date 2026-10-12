"""Session-relative monotonic clock shared by all recorders of one session."""

from __future__ import annotations

import time


class SessionClock:
    def __init__(self) -> None:
        self._origin = time.monotonic()

    def reset(self) -> None:
        """Set t=0 to now (called immediately before navigation starts)."""
        self._origin = time.monotonic()

    def now_ms(self) -> int:
        return max(0, round((time.monotonic() - self._origin) * 1000))
