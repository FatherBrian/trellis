"""The Enforcer: masks and row filters applied to result rows, failing closed."""

from __future__ import annotations

import pytest

from trellisd.enforce import MASK, RowFilterError, RowsEnforcer, compile_filter

ROWS = [
    {"id": 1, "region": "emea", "amount": 10, "email": "a@x", "note": None},
    {"id": 2, "region": "amer", "amount": 25.5, "email": "b@x", "note": "it's late"},
    {"id": 3, "region": "emea", "amount": 40, "email": "c@x", "note": "ok"},
]


def ids(text: str) -> list[int]:
    keep = compile_filter(text)
    return [r["id"] for r in ROWS if keep(r)]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("region = 'emea'", [1, 3]),
        ("region != 'emea'", [2]),
        ("region <> 'emea'", [2]),
        ("amount > 20", [2, 3]),
        ("amount <= 25.5", [1, 2]),
        ("region IN ('amer', 'apac')", [2]),
        ("region NOT IN ('amer')", [1, 3]),
        ("note IS NULL", [1]),
        ("note IS NOT NULL", [2, 3]),
        ("note = 'it''s late'", [2]),
        ("(region = 'emea') AND (amount > 20)", [3]),
        ("region = 'amer' OR amount < 15", [1, 2]),
        ("NOT region = 'emea'", [2]),
        ("note = NULL", []),
    ],
)
def test_filter_dialect(text: str, expected: list[int]) -> None:
    assert ids(text) == expected


@pytest.mark.parametrize(
    "text",
    ["region = ", "region LIKE 'e%'", "region = 'emea'; DROP TABLE x", "f(region) = 1", "(a = 1"],
)
def test_outside_the_dialect_raises(text: str) -> None:
    with pytest.raises(RowFilterError):
        compile_filter(text)


def test_a_row_missing_the_filtered_column_is_dropped() -> None:
    assert ids("country = 'fr'") == []


def test_filters_on_real_values_then_masks() -> None:
    out = RowsEnforcer().apply(
        {"mask": {"email": "pii", "region": "x"}, "row_filter": "region = 'emea'"}, ROWS
    )
    assert [r["id"] for r in out] == [1, 3]
    assert all(r["email"] == MASK and r["region"] == MASK for r in out)


def test_no_obligations_passes_rows_through() -> None:
    assert RowsEnforcer().apply({"mask": {}, "row_filter": None}, ROWS) == ROWS
