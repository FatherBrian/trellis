"""The M1 scenario: each denied call is refused by exactly the check that should refuse it."""

from __future__ import annotations

from datetime import timedelta

import pytest

from trellisd import Trellis
from trellisd.grants import IssuedGrant

from conftest import ANA, EXPORT, INSPECTIONS, JOURNAL, NOW, PAYROLL, TREASURY


@pytest.fixture
def q3(trellis: Trellis) -> IssuedGrant:
    return trellis.issue_grant(
        person=ANA, agent="report-bot", task="Q3 close", scope={"finance"}, now=NOW
    )


def answers(trellis: Trellis, token: str, resource: str) -> tuple[bool, bool, bool]:
    d = trellis.authorize(token, "read", resource, now=NOW)
    a, b, c = (ch.allowed for ch in d.checks)
    assert d.allowed == (a and b and c)
    return a, b, c


@pytest.mark.parametrize(
    ("resource", "expected"),
    [
        (JOURNAL, (True, True, True)),
        (EXPORT, (True, False, True)),  # the ceiling says never export_controlled
        (PAYROLL, (True, True, False)),  # Ana can, the bot can, the task doesn't cover hr
        (TREASURY, (False, True, True)),  # Ana herself can't
    ],
)
def test_exactly_one_key_refuses(
    trellis: Trellis, q3: IssuedGrant, resource: str, expected: tuple[bool, bool, bool]
) -> None:
    assert answers(trellis, q3.token, resource) == expected


def test_allowed_call_carries_its_obligations(trellis: Trellis, q3: IssuedGrant) -> None:
    d = trellis.authorize(q3.token, "read", JOURNAL, now=NOW)
    assert d.allowed
    assert d.masked == {"approver_email": "@mask pii on access.finance-gl"}
    assert d.row_filter == "region = 'emea'"
    assert d.policy_ids == ("access.finance-gl", "ceiling.report-bot", f"grant.{q3.grant.id}")
    assert d.apply({"amount": 5, "approver_email": "x@example.com"}) == {
        "amount": 5,
        "approver_email": "***",
    }


def test_denies_name_the_check_and_the_policy(trellis: Trellis, q3: IssuedGrant) -> None:
    d = trellis.authorize(q3.token, "read", EXPORT, now=NOW)
    assert d.denied_by == ("ceiling",)
    ceiling = d.check("ceiling")
    assert ceiling is not None
    assert ceiling.policies == ("ceiling.report-bot.never",)
    assert "export_controlled" in ceiling.reason
    assert d.reason.startswith("denied by report-bot's ceiling")

    d = trellis.authorize(q3.token, "read", TREASURY, now=NOW)
    assert d.denied_by == ("person",)
    assert "no access rule" in d.reason


def test_all_three_are_asked_even_after_a_no(trellis: Trellis) -> None:
    run = trellis.start_run(
        purpose="inspection-review",
        agent="inspector-bot",
        record="INS-7",
        started_by="quality-lead@example.com",
        now=NOW,
    )
    d = trellis.authorize(run.token, "read", JOURNAL, now=NOW)
    assert d.denied_by == ("purpose", "ceiling", "trigger")
    assert "(and 2 more)" in d.reason


def test_purpose_run_binds_rows_to_the_trigger(trellis: Trellis) -> None:
    run = trellis.start_run(
        purpose="inspection-review",
        agent="inspector-bot",
        record="INS-1042",
        started_by="quality-lead@example.com",
        now=NOW,
    )
    d = trellis.authorize(run.token, "read", INSPECTIONS, now=NOW)
    assert d.allowed
    assert [c.name for c in d.checks] == ["purpose", "ceiling", "trigger"]
    assert d.row_filter == "inspection_id = 'INS-1042'"
    # The ceiling (quality only) masks the pii column even though the purpose allows it.
    assert d.masked == {"inspector_email": "inspector-bot's ceiling doesn't allow it"}


def test_unknown_and_untagged_tables_are_denied(trellis: Trellis, q3: IssuedGrant) -> None:
    d = trellis.authorize(q3.token, "read", "finance.gl.mystery", now=NOW)
    assert not d.allowed
    assert d.denied_by == ("catalog",)
    assert d.checks == ()


def test_unknown_action_and_token(trellis: Trellis, q3: IssuedGrant) -> None:
    assert trellis.authorize(q3.token, "delete", JOURNAL, now=NOW).denied_by == ("action",)
    d = trellis.authorize("trellis_forged", "read", JOURNAL, now=NOW)
    assert d.denied_by == ("grant",)
    assert d.event_id  # still recorded


def test_actions_outside_the_grant_or_ceiling(trellis: Trellis, q3: IssuedGrant) -> None:
    d = trellis.authorize(q3.token, "export", JOURNAL, now=NOW)
    assert d.denied_by == ("person", "ceiling", "task")


def test_requested_columns_only(trellis: Trellis, q3: IssuedGrant) -> None:
    d = trellis.authorize(q3.token, "read", JOURNAL, columns=["amount", "approver_email"], now=NOW)
    assert d.columns == ("amount", "approver_email")
    assert list(d.masked) == ["approver_email"]


def test_expired_grant_fails_the_task_check_only(trellis: Trellis, q3: IssuedGrant) -> None:
    later = NOW + timedelta(hours=2)
    d = trellis.authorize(q3.token, "read", JOURNAL, now=later)
    assert d.denied_by == ("task",)
    task = d.check("task")
    assert task is not None
    assert "expired" in task.reason
