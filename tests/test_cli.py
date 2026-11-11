from __future__ import annotations

import sqlite3
from pathlib import Path

from click.testing import CliRunner

from writ import Authorizer, GrantStore, Ledger, Principal
from writ.cli import main

from conftest import ALICE, EXAMPLES, JOURNAL


def _ledger_with_one_event(path: Path, authorizer: Authorizer, grants: GrantStore) -> str:
    issued = grants.issue(human=ALICE, agent="report-bot", task="variance", scope={"finance"})
    principal = Principal.from_grant(issued.grant)
    with Ledger(path) as ledger:
        decision = authorizer.authorize(principal, "read", JOURNAL)
        return ledger.record(principal, "read", JOURNAL, decision).event_id


def test_trace_explain_and_verify(
    tmp_path: Path, authorizer: Authorizer, grants: GrantStore
) -> None:
    db = tmp_path / "ledger.db"
    event_id = _ledger_with_one_event(db, authorizer, grants)
    runner = CliRunner()

    trace = runner.invoke(
        main,
        ["trace", "--ledger", str(db), "--agent", "report-bot", "--for", ALICE, "--since", "1d"],
    )
    assert trace.exit_code == 0, trace.output
    assert event_id in trace.output
    assert "masked: approver_email, part_number" in trace.output

    explain = runner.invoke(main, ["explain", event_id, "--ledger", str(db)])
    assert explain.exit_code == 0, explain.output
    assert "finance-read" in explain.output
    assert '"log": "required"' in explain.output

    verify = runner.invoke(main, ["ledger", "verify", "--ledger", str(db)])
    assert verify.exit_code == 0
    assert "chain intact" in verify.output

    conn = sqlite3.connect(db)
    conn.execute("UPDATE ledger SET hash = 'f00d' WHERE seq = 1")
    conn.commit()
    conn.close()
    assert runner.invoke(main, ["ledger", "verify", "--ledger", str(db)]).exit_code == 1


def test_policy_check() -> None:
    result = CliRunner().invoke(main, ["policy", "check", str(EXAMPLES / "policies.yaml")])
    assert result.exit_code == 0
    assert "1 agents, 1 policies" in result.output


def test_unbuilt_commands_say_so() -> None:
    result = CliRunner().invoke(main, ["grant", "list"])
    assert result.exit_code != 0
    assert "not implemented yet" in result.output
