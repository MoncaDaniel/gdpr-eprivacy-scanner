"""Plain-language formatting shared by rule explanations and report templates."""

from __future__ import annotations

from collections.abc import Sequence

MAX_LISTED = 8
DAY_S = 86_400


def join_items(items: Sequence[str], limit: int = MAX_LISTED) -> str:
    """'a, b and c' / 'a, b, ... and 5 more'."""
    if not items:
        return "none"
    shown = list(items[:limit])
    rest = len(items) - len(shown)
    if rest:
        return ", ".join(shown) + f" and {rest} more"
    if len(shown) == 1:
        return shown[0]
    return ", ".join(shown[:-1]) + " and " + shown[-1]


def seconds(ms: int) -> str:
    return f"{ms / 1000:.1f} s"


def lifetime(value: int | None) -> str:
    if value is None:
        return "session"
    if value <= 0:
        return "expired"
    days = value / DAY_S
    if days >= 60:
        return f"{days / 30.4375:.1f} months ({days:.0f} days)"
    if days >= 1:
        return f"{days:.0f} days"
    return f"{value // 3600} h {value % 3600 // 60} min"
