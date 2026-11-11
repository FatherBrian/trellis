"""The ``trellis`` command line.

trellis trace --agent report-bot --for alice@example.com --since 7d
trellis explain <event-id>
trellis ledger verify
trellis policy check examples/policies.yaml
"""

from __future__ import annotations

import json
import re
import sys
from datetime import timedelta

import click

from trellis import __version__
from trellis.grants import utcnow
from trellis.ledger import Ledger, LedgerEvent
from trellis.policy import PolicyError, load_policies

DEFAULT_LEDGER = "trellis-ledger.db"
_DURATION = re.compile(r"^(\d+)([smhdw])$")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}

ledger_option = click.option(
    "--ledger",
    "ledger_path",
    envvar="TRELLIS_LEDGER",
    default=DEFAULT_LEDGER,
    show_default=True,
    type=click.Path(dir_okay=False),
    help="SQLite ledger file (or set TRELLIS_LEDGER).",
)


def parse_duration(text: str) -> timedelta:
    """Parse ``30m``, ``12h``, ``7d`` or ``2w``."""
    match = _DURATION.match(text.strip())
    if not match:
        raise click.BadParameter(f"expected a duration like 30m, 12h or 7d, got {text!r}")
    return timedelta(**{_UNITS[match.group(2)]: int(match.group(1))})


def _summary(ev: LedgerEvent) -> str:
    verdict = click.style("ALLOW", fg="green") if ev.allowed else click.style("DENY ", fg="red")
    masked = f"  masked: {', '.join(ev.masks)}" if ev.masks else ""
    when = f"{ev.ts:%Y-%m-%d %H:%M:%S}"
    return f"{when}  {verdict}  {ev.action:<6} {ev.resource}{masked}  [{ev.event_id}]"


@click.group()
@click.version_option(__version__, prog_name="trellis")
def main() -> None:
    """Trellis: delegated access control and audit for AI agents."""


@main.command()
@ledger_option
@click.option("--agent", help="Only events for this agent.")
@click.option("--for", "human", help="Only events where the agent acted for this person.")
@click.option("--since", default="7d", show_default=True, help="Look back this far (30m, 12h, 7d).")
@click.option("--json", "as_json", is_flag=True, help="Print events as JSON lines.")
def trace(
    ledger_path: str, agent: str | None, human: str | None, since: str, as_json: bool
) -> None:
    """List what an agent touched for a person."""
    since_ts = utcnow() - parse_duration(since)
    with Ledger(ledger_path) as ledger:
        events = ledger.query(agent=agent, human=human, since=since_ts)
    if as_json:
        for ev in events:
            click.echo(ev.model_dump_json())
        return
    if not events:
        click.echo("No matching events.")
        return
    for ev in events:
        click.echo(_summary(ev))
    # TODO(week 2): group by resource and show first/last touch and counts.


@main.command()
@ledger_option
@click.argument("event_id")
def explain(ledger_path: str, event_id: str) -> None:
    """Show why a decision came out the way it did."""
    with Ledger(ledger_path) as ledger:
        ev = ledger.get(event_id)
    if ev is None:
        raise click.ClickException(f"no event {event_id}")
    click.echo(_summary(ev))
    click.echo(f"  agent:       {ev.agent} acting for {ev.human}")
    click.echo(f"  grant:       {ev.grant_id}")
    click.echo(f"  reason:      {ev.reason}")
    if ev.policy_ids:
        click.echo(f"  policies:    {', '.join(ev.policy_ids)}")
    if ev.row_filter:
        click.echo(f"  row filter:  {ev.row_filter}")
    if ev.annotations:
        click.echo(f"  annotations: {json.dumps(ev.annotations, sort_keys=True)}")
    # TODO(week 2): re-evaluate against current grants and policies and show any drift.


@main.group()
def ledger() -> None:
    """Inspect the ledger."""


@ledger.command("verify")
@ledger_option
def ledger_verify(ledger_path: str) -> None:
    """Check the hash chain and report the first broken event."""
    with Ledger(ledger_path) as led:
        result = led.verify()
    if result.ok:
        click.echo(f"OK: {result.checked} events, chain intact.")
        return
    click.echo(f"BROKEN at event {result.broken_at}: {result.problem}", err=True)
    sys.exit(1)


@main.group()
def policy() -> None:
    """Work with policy files."""


@policy.command("check")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
def policy_check(path: str) -> None:
    """Validate a policy file."""
    try:
        bundle = load_policies(path)
    except PolicyError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"OK: {len(bundle.agents)} agents, {len(bundle.policies)} policies.")


@main.group()
def grant() -> None:
    """Issue, list and revoke grants."""


def _not_yet(feature: str) -> None:
    raise click.ClickException(f"{feature} is not implemented yet (week 1).")


@grant.command("issue")
@click.option("--agent", required=True)
@click.option("--for", "human", required=True)
@click.option("--task", required=True)
@click.option("--scope", required=True, help="Comma-separated data tags.")
@click.option("--ttl", default="1h", show_default=True)
def grant_issue(agent: str, human: str, task: str, scope: str, ttl: str) -> None:
    """Issue a task-scoped grant and print the agent token once."""
    # TODO(week 1): needs the persistent grant store.
    _not_yet("trellis grant issue")


@grant.command("list")
def grant_list() -> None:
    """List grants."""
    _not_yet("trellis grant list")


@grant.command("revoke")
@click.argument("grant_id")
def grant_revoke(grant_id: str) -> None:
    """Revoke a grant; its token stops working immediately."""
    _not_yet("trellis grant revoke")


@main.command()
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8181, show_default=True, type=int)
def serve(host: str, port: int) -> None:
    """Run the HTTP decision server."""
    _not_yet("trellis serve")


if __name__ == "__main__":
    main()
