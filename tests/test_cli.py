from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from trellisd.cli import main, parse_duration

from conftest import THREE_KEYS


def run(*args: str) -> tuple[int, str]:
    result = CliRunner().invoke(main, list(args), catch_exceptions=False)
    return result.exit_code, result.output


def test_demo_three_keys() -> None:
    code, out = run("demo", "three-keys", "--config", str(THREE_KEYS))
    assert code == 0
    assert "read hr.payroll" in out
    assert "may never touch export_controlled" in out
    assert "refused: report-bot's ceiling doesn't include export_controlled" in out
    assert "inspection_id = 'INS-1042'" in out
    assert "was revoked by ana@example.com" in out
    assert "chain verified" in out


def test_issue_check_list_revoke_verify_trace(tmp_path: Path) -> None:
    db = f"sqlite:///{tmp_path}/t.db"
    base = ("--config", str(THREE_KEYS), "--db", db)
    code, out = run(
        "grant",
        "issue",
        *base,
        "--person",
        "ana@example.com",
        "--agent",
        "report-bot",
        "--task",
        "Q3 close",
        "--scope",
        "finance",
        "--json",
    )
    assert code == 0
    issued = json.loads(out)
    token, gid = issued["token"], issued["grant"]["id"]

    code, out = run("check", *base, "--token", token, "read", "finance.gl.journal_entries")
    assert code == 0
    assert "ALLOW" in out
    assert "masked approver_email" in out

    code, out = run("check", *base, "--grant", gid, "read", "hr.payroll")
    assert code == 1
    assert "DENY" in out
    assert "the task scope" in out

    code, out = run("check", *base, "--grant", gid, "--json", "read", "hr.payroll")
    assert json.loads(out)["denied_by"] == ["task"]

    code, out = run("grant", "list", *base)
    assert gid in out
    assert "live until" in out

    code, out = run("grant", "revoke", *base, gid, "--by", "ana@example.com")
    assert "Revoked" in out
    code, out = run("grant", "list", *base)
    assert "revoked" in out

    code, out = run("ledger", "verify", "--db", db)
    assert code == 0
    assert "chain intact" in out

    code, out = run("trace", "--db", db, "--agent", "report-bot")
    assert "grant.issued" in out
    assert "DENY" in out


def test_refused_grant_exits_nonzero(tmp_path: Path) -> None:
    code, out = run(
        "grant",
        "issue",
        "--config",
        str(THREE_KEYS),
        "--db",
        f"sqlite:///{tmp_path}/t.db",
        "--person",
        "ana@example.com",
        "--agent",
        "report-bot",
        "--task",
        "t",
        "--scope",
        "export_controlled",
    )
    assert code != 0
    assert "grant refused" in out


def test_purpose_run(tmp_path: Path) -> None:
    code, out = run(
        "grant",
        "run",
        "--config",
        str(THREE_KEYS),
        "--db",
        f"sqlite:///{tmp_path}/t.db",
        "--purpose",
        "inspection-review",
        "--agent",
        "inspector-bot",
        "--record",
        "INS-9",
        "--by",
        "qms",
    )
    assert code == 0
    assert "triggered by inspection INS-9" in out


def test_compile_validate_schema() -> None:
    code, out = run("compile", "--config", str(THREE_KEYS))
    assert '@id("ceiling.report-bot.never")' in out
    code, out = run("validate", "--config", str(THREE_KEYS))
    assert code == 0
    assert "Cedar validates" in out
    code, out = run("schema")
    assert "Trellis config" in out


def test_needs_config() -> None:
    result = CliRunner().invoke(main, ["grant", "list"])
    assert result.exit_code != 0
    assert "--config" in result.output


def test_parse_duration() -> None:
    assert parse_duration("90m").total_seconds() == 5400
