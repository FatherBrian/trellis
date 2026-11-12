from __future__ import annotations

import asyncio
from typing import Any

import pytest

from trellisd import Trellis
from trellisd.engine import MASK
from trellisd.mcp_middleware import TrellisDenied, TrellisGuard, redact

from conftest import ANA, JOURNAL

ROWS = [
    {"entry_id": 1, "amount": 10.0, "approver_email": "x@example.com"},
    {"entry_id": 2, "amount": 20.0, "approver_email": "y@example.com"},
]


def _guard(trellis: Trellis) -> TrellisGuard:
    issued = trellis.issue_grant(person=ANA, agent="report-bot", task="t", scope={"finance"})
    return TrellisGuard(trellis, token_provider=lambda: issued.token)


def test_allowed_call_runs_redacts_and_records(trellis: Trellis) -> None:
    guard = _guard(trellis)

    @guard.tool(action="read", resource=JOURNAL)
    def journal_entries() -> list[dict[str, Any]]:
        return ROWS

    rows = journal_entries()
    assert rows[0]["amount"] == 10.0
    assert rows[0]["approver_email"] == MASK
    (ev,) = trellis.ledger.query(kind="decision")
    assert ev.allowed
    assert trellis.ledger.verify().ok


def test_denied_call_never_runs_but_is_recorded(trellis: Trellis) -> None:
    guard = _guard(trellis)
    ran = False

    @guard.tool(action="read", resource=lambda table: table)
    def read_table(table: str) -> list[dict[str, Any]]:
        nonlocal ran
        ran = True
        return ROWS

    with pytest.raises(TrellisDenied) as exc:
        read_table("hr.payroll")
    assert not ran
    (ev,) = trellis.ledger.query(kind="decision")
    assert exc.value.event_id == ev.event_id
    assert exc.value.decision.denied_by == ("task",)


def test_async_tools(trellis: Trellis) -> None:
    guard = _guard(trellis)

    @guard.tool(action="read", resource=JOURNAL, columns_arg="columns")
    async def cols(columns: list[str]) -> dict[str, Any]:
        return ROWS[0]

    row = asyncio.run(cols(columns=["amount", "approver_email"]))
    assert row["approver_email"] == MASK


def test_redact_passes_other_shapes() -> None:
    assert redact("text", {"a"}) == "text"
    assert redact({"a": 1}, set()) == {"a": 1}
