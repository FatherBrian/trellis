from __future__ import annotations

import asyncio
from typing import Any

import pytest

from moat import Authorizer, GrantStore, Ledger
from moat.mcp_middleware import MASK, MoatDenied, MoatGuard

from conftest import ALICE, JOURNAL

ROWS = [
    {"entry_id": 1, "amount": 10.0, "approver_email": "x@example.com", "part_number": "P-1"},
    {"entry_id": 2, "amount": 20.0, "approver_email": "y@example.com", "part_number": "P-2"},
]


def _guard(
    authorizer: Authorizer, ledger: Ledger, grants: GrantStore, scope: set[str]
) -> MoatGuard:
    issued = grants.issue(human=ALICE, agent="report-bot", task="variance", scope=scope)
    return MoatGuard(authorizer, ledger, token_provider=lambda: issued.token)


def test_allowed_call_runs_redacts_and_records(
    authorizer: Authorizer, ledger: Ledger, grants: GrantStore
) -> None:
    guard = _guard(authorizer, ledger, grants, {"finance", "pii"})

    @guard.tool(action="read", resource=JOURNAL)
    def journal_entries() -> list[dict[str, Any]]:
        return ROWS

    rows = journal_entries()
    assert rows[0]["amount"] == 10.0
    assert rows[0]["approver_email"] == MASK
    assert rows[0]["part_number"] == MASK
    (event,) = ledger.query()
    assert event.allowed
    assert ledger.verify().ok


def test_denied_call_never_runs_but_is_recorded(
    authorizer: Authorizer, ledger: Ledger, grants: GrantStore
) -> None:
    guard = _guard(authorizer, ledger, grants, {"finance"})
    ran = False

    @guard.tool(action="read", resource=JOURNAL, columns_arg="columns")
    def journal_columns(columns: list[str]) -> list[dict[str, Any]]:
        nonlocal ran
        ran = True
        return ROWS

    with pytest.raises(MoatDenied) as exc:
        journal_columns(columns=["entry_id", "part_number"])
    assert not ran
    (event,) = ledger.query()
    assert exc.value.event_id == event.event_id
    assert not event.allowed
    assert event.columns == ("entry_id", "part_number")


def test_async_tools_are_guarded(
    authorizer: Authorizer, ledger: Ledger, grants: GrantStore
) -> None:
    guard = _guard(authorizer, ledger, grants, {"finance"})

    @guard.tool(action="read", resource=lambda table: table)
    async def read_table(table: str) -> list[dict[str, Any]]:
        return ROWS

    rows = asyncio.run(read_table(JOURNAL))
    assert rows[1]["approver_email"] == MASK
    with pytest.raises(MoatDenied):
        asyncio.run(read_table("eng.parts.bom"))
    assert len(ledger) == 2


def test_bad_token_is_denied(authorizer: Authorizer, ledger: Ledger) -> None:
    guard = MoatGuard(authorizer, ledger, token_provider=lambda: "moat_bogus")

    @guard.tool(action="read", resource=JOURNAL)
    def journal_entries() -> list[dict[str, Any]]:
        return ROWS

    with pytest.raises(MoatDenied, match="unknown token"):
        journal_entries()
