"""Plain-language formatting used in explanations and reports."""

from __future__ import annotations

import pytest

from privacy_scanner.formatting import join_items, lifetime, seconds


@pytest.mark.parametrize(
    ("items", "expected"),
    [
        ([], "none"),
        (["a"], "a"),
        (["a", "b"], "a and b"),
        (["a", "b", "c"], "a, b and c"),
        ([str(i) for i in range(10)], "0, 1, 2, 3, 4, 5, 6, 7 and 2 more"),
    ],
)
def test_join_items(items: list[str], expected: str) -> None:
    assert join_items(items) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "session"),
        (0, "expired"),
        (-5, "expired"),
        (5400, "1 h 30 min"),
        (3 * 86_400, "3 days"),
        (400 * 86_400, "13.1 months (400 days)"),
    ],
)
def test_lifetime(value: int | None, expected: str) -> None:
    assert lifetime(value) == expected


def test_seconds() -> None:
    assert seconds(1500) == "1.5 s"
