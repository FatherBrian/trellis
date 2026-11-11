"""Issuing grants: nobody can hand on more than the ceiling allows or they can reach."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from trellisd import GrantError, Trellis, load_config
from trellisd.db import Database
from trellisd.ledger import LedgerUnavailable

from conftest import ANA, JOURNAL, NOW, THREE_KEYS


def refused(trellis: Trellis, **kw: object) -> str:
    args: dict[str, object] = {
        "person": ANA,
        "agent": "report-bot",
        "task": "t",
        "scope": {"finance"},
        "now": NOW,
    }
    args.update(kw)
    with pytest.raises(GrantError) as exc:
        trellis.issue_grant(**args)  # type: ignore[arg-type]
    return str(exc.value)


def test_scope_above_the_ceiling_is_refused(trellis: Trellis) -> None:
    assert "doesn't include quality" in refused(trellis, scope={"finance", "quality"})
    assert "may never touch export_controlled" in refused(trellis, scope={"export_controlled"})
    assert "doesn't allow write" in refused(trellis, actions=("read", "write"))
    assert "no agent called ghost" in refused(trellis, agent="ghost")


def test_person_cannot_grant_what_they_cannot_reach(trellis: Trellis) -> None:
    msg = refused(trellis, person="tom@example.com", scope={"hr"})
    assert "tom@example.com can't reach anything tagged hr" in msg


def test_only_the_person_can_grant_for_themselves(trellis: Trellis) -> None:
    assert "only ana@example.com" in refused(trellis, issued_by="mallory@example.com")


def test_refusals_are_recorded(trellis: Trellis) -> None:
    refused(trellis, scope={"export_controlled"})
    (ev,) = trellis.ledger.query(kind="grant.refused")
    assert ev.agent == "report-bot"
    assert ev.body["problems"]


def test_ttl_limits(trellis: Trellis) -> None:
    assert "exceeds the maximum" in refused(trellis, ttl=timedelta(days=2))
    assert "positive" in refused(trellis, ttl=timedelta(0))


def test_purpose_run_checks(trellis: Trellis) -> None:
    with pytest.raises(GrantError, match="isn't one of the agents"):
        trellis.start_run(
            purpose="inspection-review", agent="report-bot", record="I-1", started_by="x", now=NOW
        )
    with pytest.raises(GrantError, match="no purpose called"):
        trellis.start_run(
            purpose="nope", agent="inspector-bot", record="I-1", started_by="x", now=NOW
        )


def test_receipt_is_the_hash_of_the_issue_event(trellis: Trellis) -> None:
    issued = trellis.issue_grant(
        person=ANA, agent="report-bot", task="Q3 close", scope={"finance"}, now=NOW
    )
    (ev,) = trellis.ledger.query(kind="grant.issued")
    assert issued.grant.receipt == ev.hash
    assert ev.body["scope"] == ["finance"]
    assert trellis.grants.get(issued.grant.id) == issued.grant
    d = trellis.authorize(issued.token, "read", JOURNAL, now=NOW)
    (dec,) = trellis.ledger.query(kind="decision")
    assert dec.body["receipt"] == ev.hash
    assert dec.event_id == d.event_id
    assert [c["allowed"] for c in dec.body["checks"]] == [True, True, True]


def test_revoke(trellis: Trellis) -> None:
    issued = trellis.issue_grant(
        person=ANA, agent="report-bot", task="t", scope={"finance"}, now=NOW
    )
    revoked = trellis.revoke(issued.grant.id, by=ANA, now=NOW + timedelta(minutes=1))
    assert revoked.revoked_by == ANA
    assert trellis.revoke(issued.grant.id, by=ANA) == revoked  # idempotent
    d = trellis.authorize(issued.token, "read", JOURNAL, now=NOW + timedelta(minutes=2))
    assert d.denied_by == ("task",)
    with pytest.raises(GrantError):
        trellis.revoke("g-nope", by=ANA)


def test_a_failed_ledger_write_denies(trellis: Trellis, monkeypatch: pytest.MonkeyPatch) -> None:
    issued = trellis.issue_grant(
        person=ANA, agent="report-bot", task="t", scope={"finance"}, now=NOW
    )

    def broken(*_a: object, **_k: object) -> None:
        raise LedgerUnavailable("ledger write failed: disk full")

    monkeypatch.setattr(trellis.ledger, "append", broken)
    d = trellis.authorize(issued.token, "read", JOURNAL, now=NOW)
    assert not d.allowed
    assert "ledger" in d.denied_by
    assert "won't act unrecorded" in d.reason
    assert d.masked == {}


def _persist(url: str) -> None:
    with Trellis(load_config(THREE_KEYS), Database(url)) as t:
        issued = t.issue_grant(person=ANA, agent="report-bot", task="t", scope={"finance"}, now=NOW)
        t.authorize(issued.token, "read", JOURNAL, now=NOW)
    with Trellis(load_config(THREE_KEYS), Database(url)) as t:
        d = t.authorize(issued.token, "read", JOURNAL, now=NOW)
        assert d.allowed
        assert len(t.grants.find(agent="report-bot")) == 1
        assert len(t.ledger) == 3
        assert t.ledger.verify().ok


def test_grants_and_ledger_survive_a_restart(tmp_path: Path) -> None:
    _persist(f"sqlite:///{tmp_path}/t.db")


@pytest.mark.postgres
def test_grants_and_ledger_survive_a_restart_on_postgres(postgres_url: str) -> None:
    _persist(postgres_url)
