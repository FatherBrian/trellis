"""M5's demo, "The door": two agents, one Reef, two MCP servers.

report-bot (for Ana, task "Q3 close") and people-bot (for Ben, "Headcount review")
connect to the same Reef and see different tools. report-bot calls one outside its grant
and is denied at the door: the ledger already has the decision, and the HR server's log
is empty. Then the ledger's database goes away, and every call is denied.

Everything runs on this machine: a local IdP, Trellis, the two sample servers and Reef.
With ``--postgres URL`` the ledger is in Postgres behind a relay the demo cuts, so the
outage is real from Trellis's side, and the demo brings Postgres back at the end.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

import click
from mcp import types

from reef.agent import AgentClient
from reef.relay import Relay, relayed
from reef.stack import Stack, open_stack
from trellisd.db import Database
from trellisd.engine import Decision
from trellisd.trace import recorded_decision, trace


@dataclass
class DoorResult:
    """What the tests check."""

    tools: dict[str, list[str]]
    first: Decision
    denied: Decision
    hr_calls_before: int
    hr_calls_after: int
    down_lists: list[str]
    down_calls: list[types.CallToolResult]
    recovered: bool | None


@contextmanager
def _database(postgres: str | None) -> Iterator[tuple[Database, Relay | None]]:
    if not postgres:
        db = Database("sqlite:///:memory:")
        yield db, None
        return
    relay, url = relayed(postgres)
    db = Database(url)
    try:
        yield db, relay
    finally:
        relay.close()


def _structured(result: types.CallToolResult) -> Any:
    if result.structured_content is not None:
        return result.structured_content
    return [c.text for c in result.content if isinstance(c, types.TextContent)]


def run_the_door(postgres: str | None = None) -> DoorResult:
    from trellisd.cli import event_line, print_table, print_trace

    echo = click.echo

    def h(text: str) -> str:
        return click.style(text, bold=True)

    def dim(text: str) -> None:
        echo(click.style(text, dim=True))

    def step(n: int, text: str) -> None:
        echo("")
        echo(h(f"{n}. ") + text)

    def show_json(data: Any) -> None:
        for line in json.dumps(data, indent=2, ensure_ascii=False).splitlines():
            echo("     " + line)

    def ledger_lines(s: Stack, decision_id: str) -> None:
        for e in s.trellis.ledger.query():
            if e.event_id == decision_id or e.body.get("decision") == decision_id:
                echo("   " + event_line(e))

    with _database(postgres) as (db, relay), open_stack(db) as s:
        report = AgentClient(s.url, s.report_bot.token)
        people = AgentClient(s.url, s.people_bot.token)
        where = "Postgres (through a relay the demo can cut)" if relay else "SQLite, in memory"

        echo(h("The door:") + " two agents, one Reef, two MCP servers.")
        echo("")
        echo(f"Reef listens at {s.url}. Behind it:")
        echo(f"  ledger  {s.ledger.url}  gets the person's own token (obo, audience ledger-mcp)")
        echo(f"  hr      {s.hr.url}  gets a service credential only Reef holds (brokered)")
        echo(f"The ledger is in {where}.")

        step(1, "Two grants, each from a sign-in at the local IdP:")
        for issued in (s.report_bot, s.people_bot):
            g = issued.grant
            echo(
                f"   {g.agent} for {g.subject}: task {g.task!r}, scope {', '.join(sorted(g.scope))}"
            )
        dim("   Each agent connects to Reef with its grant token as the bearer token.")

        step(2, "Both connect to the same Reef and ask for tools:")
        tools = {"report-bot": report.list_tools(), "people-bot": people.list_tools()}
        names = {agent: [t.name for t in ts] for agent, ts in tools.items()}
        all_tools = [
            "ledger_journal_entries",
            "ledger_post_adjustment",
            "hr_headcount",
            "hr_payroll",
        ]
        rows = [["TOOL", "report-bot", "people-bot"]]
        for name in all_tools:
            rows.append([name, *("sees" if name in names[a] else "-" for a in names)])
        print_table(rows, indent=3, center=False)
        journal = next(t for t in tools["report-bot"] if t.name == "ledger_journal_entries")
        echo("   report-bot's description of ledger_journal_entries, narrowed to its grant:")
        for line in (journal.description or "").splitlines():
            if line.strip():
                dim(f"     {line}")
        dim("   Nobody wrote a persona for either agent: the lists come from the grants.")

        step(3, "report-bot reads the journal for Ana:")
        r = report.call("ledger_journal_entries")
        show_json(_structured(r))
        call = s.ledger.calls[-1]
        echo(
            f"   The ledger server saw one call, as {call.caller}, with Ana's own token."
            " Reef kept her region's rows and masked approver_email."
        )
        first_id = s.trellis.ledger.query(kind="decision", agent="report-bot")[-1].event_id

        step(4, "report-bot calls hr_payroll, which isn't in its list:")
        hr_before = len(s.hr.calls)
        r = report.call("hr_payroll")
        echo(f"   {click.style('Denied at the door.', fg='red')}")
        show_json(_structured(r))
        denied_id = str(_structured(r)["event_id"])
        echo("   The ledger already has the decision, and Reef's record that it blocked the call:")
        ledger_lines(s, denied_id)
        hr_after = len(s.hr.calls)
        echo(f"   The hr server's log: {hr_after - hr_before} calls.")
        dim(
            "   Ana may read payroll, and report-bot's ceiling covers hr. The grant Ana gave"
            " it is for the Q3 close, so the task check says no."
        )

        step(5, "people-bot calls the same tool for Ben, through the same door:")
        r = people.call("hr_payroll")
        rows_out = _structured(r).get("rows", [])
        echo(f"   {len(rows_out)} rows. The hr server saw it as {s.hr.calls[-1].caller}.")

        step(6, "Who allowed report-bot's journal read, and what did the door do with it?")
        echo(f"$ trellisd trace {first_id}")
        echo("")
        print_trace(trace(s.trellis.ledger, first_id))

        result = s.trellis.ledger.verify()
        echo("")
        echo(
            f"Ledger: {result.checked} events, chain "
            + (
                click.style("verified", fg="green")
                if result.ok
                else click.style("BROKEN", fg="red")
            )
            + "."
        )
        first = recorded_decision(s.trellis.ledger.get(first_id))  # type: ignore[arg-type]
        denied = recorded_decision(s.trellis.ledger.get(denied_id))  # type: ignore[arg-type]

        step(
            7,
            "The ledger's database goes away"
            + (" (the demo cuts Postgres off):" if relay else ":"),
        )
        if relay is not None:
            relay.cut()
        else:
            db.close()
            dim("   (The demo closes Trellis's database. With --postgres it cuts a real one.)")
        calls_before = len(s.ledger.calls) + len(s.hr.calls)
        down_lists = []
        for agent, client in (("report-bot", report), ("people-bot", people)):
            out = client.try_list_tools()
            down_lists.append(out if isinstance(out, str) else "")
            shown = out if isinstance(out, str) else f"{len(out)} tools"
            echo(f"   {agent} lists tools: {shown}")
        down_calls = []
        for agent, client, tool in (
            ("report-bot", report, "ledger_journal_entries"),
            ("people-bot", people, "hr_payroll"),
        ):
            r = client.call(tool)
            down_calls.append(r)
            verdict = click.style("denied", fg="red") if r.is_error else "ALLOWED"
            echo(f"   {agent} calls {tool}: {verdict}: {_structured(r).get('reason', '')}")
        reached = len(s.ledger.calls) + len(s.hr.calls) - calls_before
        echo(f"   Calls that reached a server while the ledger was down: {reached}.")
        dim("   Trellis won't act unrecorded, and Reef won't forward an unrecorded call.")

        recovered = None
        if relay is not None:
            step(8, "Postgres comes back, and the door opens again without a restart:")
            relay.resume()
            r = report.call("ledger_journal_entries")
            recovered = not r.is_error
            verdict = "allowed" if recovered else "denied"
            echo(f"   report-bot calls ledger_journal_entries: {verdict}")

        return DoorResult(
            tools=names,
            first=first,
            denied=denied,
            hr_calls_before=hr_before,
            hr_calls_after=hr_after,
            down_lists=down_lists,
            down_calls=down_calls,
            recovered=recovered,
        )
