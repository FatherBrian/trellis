"""The access report: every grant, who allowed it, and what the agent actually reached."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from click.testing import CliRunner

from trellisd import Trellis
from trellisd.cli import main
from trellisd.report import build

from conftest import ANA, JOURNAL, PAYROLL, THREE_KEYS


def seed(db: str) -> str:
    with Trellis.open(THREE_KEYS, db_url=db) as t:
        g = t.issue_grant(person=ANA, agent="report-bot", task="Q3 close", scope={"finance"})
        for _ in range(3):
            assert t.authorize(g.token, "read", JOURNAL).allowed
        assert not t.authorize(g.token, "read", PAYROLL).allowed
        t.issue_grant(person=ANA, agent="report-bot", task="Never used", scope={"finance"})
        t.revoke(g.grant.id, by=ANA)
        return g.grant.id


def test_the_report_counts_what_each_grant_reached(tmp_path: Path) -> None:
    db = f"sqlite:///{tmp_path / 't.db'}"
    gid = seed(db)
    with Trellis.open(THREE_KEYS, db_url=db) as t:
        reports = build(t.ledger)
    by_task = {r.task: r for r in reports}
    q3 = by_task["Q3 close"]
    assert q3.grant_id == gid
    assert q3.agent == "report-bot"
    assert q3.acting_for == ANA
    assert q3.granted_by == ANA
    assert q3.revoked_at  # revoked, and the report says when
    usage = {(u.resource, u.action): u for u in q3.usage}
    assert usage[(JOURNAL, "read")].allowed == 3
    assert usage[(JOURNAL, "read")].masked == {"approver_email"}
    assert usage[(PAYROLL, "read")].denied == 1
    assert by_task["Never used"].usage == []  # an unused grant still shows up


def test_trellisd_report_csv_and_json(tmp_path: Path) -> None:
    db = f"sqlite:///{tmp_path / 't.db'}"
    seed(db)
    runner = CliRunner()

    res = runner.invoke(main, ["report", "--db", db, "--since", "1d"], catch_exceptions=False)
    assert res.exit_code == 0, res.output
    rows = list(csv.DictReader(io.StringIO(res.stdout)))
    journal = next(r for r in rows if r["resource"] == JOURNAL)
    assert journal["allowed_calls"] == "3"
    assert journal["masked_fields"] == "approver_email"
    assert journal["task"] == "Q3 close"
    assert any(r["task"] == "Never used" and r["allowed_calls"] == "0" for r in rows)
    assert "ledger intact" in res.stderr

    res = runner.invoke(main, ["report", "--db", db, "--format", "json"], catch_exceptions=False)
    data = json.loads(res.stdout)
    assert data["ledger"]["ok"] is True
    assert {g["task"] for g in data["grants"]} == {"Q3 close", "Never used"}
