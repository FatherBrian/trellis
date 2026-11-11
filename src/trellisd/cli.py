"""The ``trellisd`` command line.

    trellisd demo three-keys                     # the M1 demo, start to finish
    trellisd grant issue --person ana@example.com --agent report-bot \\
        --task "Q3 close" --scope finance
    trellisd check --grant g-1a2b3c read finance.gl.journal_entries
    trellisd grant list | revoke
    trellisd compile                             # the Cedar Trellis generates
    trellisd schema                              # JSON Schema for the YAML
    trellisd ledger verify
    trellisd trace --agent report-bot

``--config`` (or TRELLISD_CONFIG) is a YAML file or a directory of them; ``--db`` (or
TRELLISD_DB) is ``sqlite:///file.db`` or a ``postgresql://`` URL.
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
from collections.abc import Callable
from datetime import timedelta
from importlib import resources
from pathlib import Path
from typing import Any, TypeVar

import click

from trellisd import __version__
from trellisd.app import Trellis
from trellisd.compiler import Compiler, render
from trellisd.config import ConfigError, json_schema, load_config
from trellisd.db import DEFAULT_URL, Database, DatabaseError
from trellisd.engine import Decision, Engine
from trellisd.export import OpenTelemetrySink, backlog, drain
from trellisd.grants import Grant, GrantError, utcnow
from trellisd.ledger import Checkpoint, Ledger, LedgerEvent, VerifyResult
from trellisd.signing import DEFAULT_KEY_PATH, Signer
from trellisd.trace import Replay, Trace, TraceError, differences
from trellisd.trace import replay as replay_event
from trellisd.trace import trace as trace_event

F = TypeVar("F", bound=Callable[..., Any])

_DURATION = re.compile(r"^(\d+)([smhdw])$")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}
YES = click.style("✓", fg="green", bold=True)
NO = click.style("✗", fg="red", bold=True)


def parse_duration(text: str) -> timedelta:
    """Parse ``30m``, ``12h``, ``7d`` or ``2w``."""
    match = _DURATION.match(text.strip())
    if not match:
        raise click.BadParameter(f"expected a duration like 30m, 12h or 7d, got {text!r}")
    return timedelta(**{_UNITS[match.group(2)]: int(match.group(1))})


def example_dir(name: str) -> Path:
    """An example config: ./examples/<name> in a checkout, else the copy in the wheel."""
    local = Path("examples") / name
    if local.is_dir():
        return local
    packaged = Path(str(resources.files("trellisd"))) / "_examples" / name
    if packaged.is_dir():
        return packaged
    raise click.ClickException(f"can't find the {name} example config")


def config_option(f: F) -> F:
    return click.option(
        "--config",
        "config_paths",
        envvar="TRELLISD_CONFIG",
        multiple=True,
        type=click.Path(exists=True),
        help="YAML file or directory (repeatable; or set TRELLISD_CONFIG).",
    )(f)


def db_option(f: F) -> F:
    return click.option(
        "--db",
        "db_url",
        envvar="TRELLISD_DB",
        default=DEFAULT_URL,
        show_default=True,
        help="sqlite:///file.db or postgresql://... (or set TRELLISD_DB).",
    )(f)


def _open(config_paths: tuple[str, ...], db_url: str) -> Trellis:
    if not config_paths:
        raise click.UsageError("pass --config (or set TRELLISD_CONFIG)")
    try:
        return Trellis.open(*config_paths, db_url=db_url, signer=_signer())
    except (ConfigError, DatabaseError) as exc:
        raise click.ClickException(str(exc)) from exc


@click.group()
@click.version_option(__version__, prog_name="trellisd")
@click.option(
    "--key",
    "key_path",
    envvar="TRELLISD_KEY",
    default=DEFAULT_KEY_PATH,
    show_default=True,
    type=click.Path(dir_okay=False),
    help="Ed25519 key that signs grant entries and checkpoints (made if missing).",
)
@click.pass_context
def main(ctx: click.Context, key_path: str) -> None:
    """Trellis: delegated access control and audit for AI agents."""
    ctx.ensure_object(dict)["key_path"] = key_path


def _signer() -> Signer:
    ctx = click.get_current_context()
    root = ctx.find_root()
    path = (root.obj or {}).get("key_path", DEFAULT_KEY_PATH)
    try:
        return Signer.load_or_create(path)
    except (OSError, ValueError) as exc:
        raise click.ClickException(f"signing key {path}: {exc}") from exc


# -- grants ----------------------------------------------------------------------------------


@main.group()
def grant() -> None:
    """Issue, list and revoke grants."""


@grant.command("issue")
@config_option
@db_option
@click.option("--person", required=True, help="Who the agent acts for (and who allows it).")
@click.option("--agent", required=True)
@click.option("--task", required=True, help="What the agent is doing, in words.")
@click.option("--scope", required=True, help="Comma-separated tags the task covers.")
@click.option("--actions", default="read,query", show_default=True)
@click.option("--ttl", default="1h", show_default=True, help="30m, 8h, 1d (24h at most).")
@click.option("--json", "as_json", is_flag=True)
def grant_issue(
    config_paths: tuple[str, ...],
    db_url: str,
    person: str,
    agent: str,
    task: str,
    scope: str,
    actions: str,
    ttl: str,
    as_json: bool,
) -> None:
    """A person lets an agent act for them on one task."""
    with _open(config_paths, db_url) as t:
        try:
            issued = t.issue_grant(
                person=person,
                agent=agent,
                task=task,
                scope=_split(scope),
                actions=tuple(_split(actions)),
                ttl=parse_duration(ttl),
            )
        except GrantError as exc:
            raise click.ClickException(f"grant refused: {exc}") from exc
    _print_issued(issued.grant, issued.token, as_json)


@grant.command("run")
@config_option
@db_option
@click.option("--purpose", required=True)
@click.option("--agent", required=True)
@click.option("--record", required=True, help="The id of the record that started this run.")
@click.option("--by", "started_by", required=True, help="Who or what started the run.")
@click.option("--ttl", default="1h", show_default=True)
@click.option("--json", "as_json", is_flag=True)
def grant_run(
    config_paths: tuple[str, ...],
    db_url: str,
    purpose: str,
    agent: str,
    record: str,
    started_by: str,
    ttl: str,
    as_json: bool,
) -> None:
    """Start one run of a process agent under a purpose grant."""
    with _open(config_paths, db_url) as t:
        try:
            issued = t.start_run(
                purpose=purpose,
                agent=agent,
                record=record,
                started_by=started_by,
                ttl=parse_duration(ttl),
            )
        except GrantError as exc:
            raise click.ClickException(f"run refused: {exc}") from exc
    _print_issued(issued.grant, issued.token, as_json)


@grant.command("list")
@config_option
@db_option
@click.option("--agent")
@click.option("--for", "subject", help="Person or purpose.")
@click.option("--active", is_flag=True, help="Only grants that are live now.")
def grant_list(
    config_paths: tuple[str, ...],
    db_url: str,
    agent: str | None,
    subject: str | None,
    active: bool,
) -> None:
    """List grants."""
    with _open(config_paths, db_url) as t:
        grants = t.grants.find(agent=agent, subject=subject, active_only=active)
    if not grants:
        click.echo("No grants.")
        return
    now = utcnow()
    rows = [["GRANT", "AGENT", "FOR", "SCOPE", "TASK", "STATE"]]
    for g in grants:
        state = g.inactive_reason(now)
        rows.append(
            [
                g.id,
                g.agent,
                g.subject,
                ",".join(sorted(g.scope)),
                g.task if not g.is_purpose else f"{g.trigger_type} {g.trigger_record}",
                "live until " + f"{g.expires_at:%H:%M} UTC"
                if state is None
                else ("revoked" if g.revoked_at else "expired"),
            ]
        )
    _table(rows)


@grant.command("revoke")
@config_option
@db_option
@click.argument("grant_id")
@click.option("--by", "by", required=True, help="Who is revoking it.")
def grant_revoke(config_paths: tuple[str, ...], db_url: str, grant_id: str, by: str) -> None:
    """Revoke a grant now. Its token stops working on the next call."""
    with _open(config_paths, db_url) as t:
        try:
            g = t.revoke(grant_id, by)
        except GrantError as exc:
            raise click.ClickException(str(exc)) from exc
    click.echo(f"Revoked {g.id} ({g.describe()}).")


def _print_issued(g: Grant, token: str, as_json: bool) -> None:
    if as_json:
        click.echo(json.dumps({"grant": json.loads(g.model_dump_json()), "token": token}))
        return
    click.echo(f"Grant {click.style(g.id, bold=True)}: {g.describe()}")
    click.echo(f"  scope    {', '.join(sorted(g.scope))}   actions {', '.join(g.actions)}")
    click.echo(f"  expires  {g.expires_at:%Y-%m-%d %H:%M} UTC")
    click.echo(f"  receipt  {g.receipt}")
    click.echo(f"  token    {token}   (shown once; give it to the agent)")


# -- decisions -------------------------------------------------------------------------------


@main.command()
@config_option
@db_option
@click.option("--token", help="The agent's token.")
@click.option("--grant", "grant_id", help="Or a grant id (operators).")
@click.option("--columns", help="Comma-separated columns (default: all).")
@click.option("--json", "as_json", is_flag=True)
@click.argument("action")
@click.argument("resource")
def check(
    config_paths: tuple[str, ...],
    db_url: str,
    token: str | None,
    grant_id: str | None,
    columns: str | None,
    as_json: bool,
    action: str,
    resource: str,
) -> None:
    """Ask the three checks about one call, and record the answer."""
    if bool(token) == bool(grant_id):
        raise click.UsageError("pass exactly one of --token or --grant")
    cols = _split(columns) if columns else None
    with _open(config_paths, db_url) as t:
        if token:
            d = t.authorize(token, action, resource, cols)
        else:
            g = t.grants.get(grant_id or "")
            if g is None:
                raise click.ClickException(f"no grant {grant_id}")
            d = t.decide(g, action, resource, cols)
    if as_json:
        click.echo(d.model_dump_json())
    else:
        _print_decision(d)
    sys.exit(0 if d.allowed else 1)


def _print_decision(d: Decision) -> None:
    verdict = (
        click.style("ALLOW", fg="green", bold=True)
        if d.allowed
        else click.style("DENY", fg="red", bold=True)
    )
    click.echo(f"{verdict}  {d.action} {d.resource}")
    for c in d.checks:
        mark = YES if c.allowed else NO
        why = f"  {c.reason}" if c.reason else ""
        pol = f"  [{', '.join(c.policies)}]" if c.policies else ""
        click.echo(f"  {mark} {c.label}{pol}{why}")
    if not d.checks:
        click.echo(f"  {d.reason}")
    for col, why in d.masked.items():
        click.echo(f"  masked {col}: {why}")
    if d.row_filter:
        click.echo(f"  rows   {d.row_filter}")
    if d.event_id:
        click.echo(f"  ledger {d.event_id}")


# -- the demo --------------------------------------------------------------------------------


@main.group()
def demo() -> None:
    """Scripted demos that run start to finish."""


@demo.command("three-keys")
@click.option(
    "--config",
    "config_dir",
    type=click.Path(exists=True, file_okay=False),
    help="Defaults to the bundled examples/three-keys.",
)
@db_option
@click.option("--keep", is_flag=True, help="Use --db as given instead of a scratch database.")
def demo_three_keys(config_dir: str | None, db_url: str, keep: bool) -> None:
    """Every call needs three yeses: the person's, the agent's ceiling and the task's."""
    cfg = Path(config_dir) if config_dir else example_dir("three-keys")
    with tempfile.TemporaryDirectory() as tmp:
        url = db_url if keep else f"sqlite:///{tmp}/demo.db"
        with Trellis.open(cfg, db_url=url, signer=_signer() if keep else None) as t:
            run_three_keys(t)


def run_three_keys(t: Trellis) -> None:
    echo = click.echo

    def h(s: str) -> str:
        return click.style(s, bold=True)

    echo(h("Three keys") + ": every call an agent makes needs three yeses, asked separately.")
    echo("")
    issued = t.issue_grant(
        person="ana@example.com", agent="report-bot", task="Q3 close", scope={"finance"}
    )
    g = issued.grant
    echo(f"Ana lets report-bot work on the {h('Q3 close')}: scope finance, for an hour.")
    echo(f"  grant {g.id}, receipt {g.receipt[:12] if g.receipt else ''}…")
    echo("")
    calls = [
        ("read", "finance.gl.journal_entries"),
        ("read", "finance.gl.export_ledger"),
        ("read", "hr.payroll"),
        ("read", "finance.treasury.cash_positions"),
    ]
    _demo_table(t, issued.token, ["Ana's access", "report-bot's ceiling", "the task"], calls)

    echo("")
    echo("Ana tries to widen report-bot's scope to export_controlled:")
    try:
        t.issue_grant(
            person="ana@example.com",
            agent="report-bot",
            task="Q3 close",
            scope={"finance", "export_controlled"},
        )
    except GrantError as exc:
        echo(f"  {NO} refused: {exc}")

    echo("")
    echo(h("Process agents") + " get the same three checks, with a purpose and a trigger:")
    run = t.start_run(
        purpose="inspection-review",
        agent="inspector-bot",
        record="INS-1042",
        started_by="quality-lead@example.com",
    )
    echo(
        f"  inspection INS-1042 is filed; inspector-bot runs under purpose inspection-review"
        f" (owner quality-lead@example.com), grant {run.grant.id}"
    )
    echo("")
    _demo_table(
        t,
        run.token,
        ["the purpose", "inspector-bot's ceiling", "the trigger"],
        [("read", "quality.inspections"), ("read", "finance.gl.journal_entries")],
    )

    echo("")
    echo("Ana revokes report-bot's grant; its next call is refused by the task check:")
    t.revoke(g.id, by="ana@example.com")
    d = t.authorize(issued.token, "read", "finance.gl.journal_entries")
    task = d.check("task")
    echo(f"  {NO} read finance.gl.journal_entries: {task.reason if task else d.reason}")

    echo("")
    v = t.ledger.verify()
    decisions = len(t.ledger.query(kind="decision"))
    state = (
        click.style("chain verified", fg="green")
        if v.ok
        else click.style(f"BROKEN: {v.problem}", fg="red")
    )
    echo(
        f"Ledger: {v.checked} events ({decisions} decisions, each with all three answers), {state}."
    )


@demo.command("who-allowed-this")
@click.option(
    "--config",
    "config_dir",
    type=click.Path(exists=True, file_okay=False),
    help="Defaults to the bundled examples/three-keys.",
)
def demo_who_allowed_this(config_dir: str | None) -> None:
    """Trace a denied call to who allowed what, then catch someone editing the ledger."""
    cfg = Path(config_dir) if config_dir else example_dir("three-keys")
    with (
        tempfile.TemporaryDirectory() as tmp,
        Trellis.open(cfg, db_url=f"sqlite:///{tmp}/demo.db") as t,
    ):
        run_who_allowed_this(t)


def run_who_allowed_this(t: Trellis) -> None:
    echo = click.echo

    def h(s: str) -> str:
        return click.style(s, bold=True)

    issued = t.issue_grant(
        person="ana@example.com", agent="report-bot", task="Q3 close", scope={"finance"}
    )
    hr_event = ""
    for resource in (
        "finance.gl.journal_entries",
        "finance.gl.export_ledger",
        "hr.payroll",
        "finance.treasury.cash_positions",
    ):
        d = t.authorize(issued.token, "read", resource)
        if resource == "hr.payroll":
            hr_event = d.event_id or ""
    for i in range(10):
        cols = ["entry_id", "amount"] if i % 2 else ["entry_id", "region"]
        t.authorize(issued.token, "query", "finance.gl.journal_entries", cols)

    echo(h("Who allowed this?") + " report-bot was refused hr.payroll during the Q3 close.")
    echo(f"$ trellisd trace {hr_event}")
    echo("")
    print_trace(trace_event(t.ledger, hr_event))
    print_replay(replay_event(t.ledger, t.engine, hr_event))

    echo("")
    cp = t.ledger.checkpoint()
    echo(
        h("A signed checkpoint") + f" of the head: event {cp.seq}, hash {cp.hash[:16]}…, "
        f"key {cp.key_id}. It's published somewhere the database's admins can't edit."
    )
    echo("")
    hr = t.ledger.get(hr_event)
    if hr is None:  # pragma: no cover - the call above just wrote it
        raise click.ClickException("the HR decision is missing from the ledger")
    echo(h("Someone with database access covers their tracks:"))
    echo(f"  they rewrite event {hr.seq} to say the HR read was allowed,")
    t.db.execute(
        "UPDATE trellis_ledger SET payload = replace(payload, '\"allowed\":false', "
        "'\"allowed\":true') WHERE seq = ?",
        (hr.seq,),
    )
    echo(f"  and delete the last ten events ({cp.seq - 9} to {cp.seq}).")
    t.db.execute("DELETE FROM trellis_ledger WHERE seq > ?", (cp.seq - 10,))
    echo("")
    echo("$ trellisd ledger verify --checkpoint checkpoint.json")
    _print_verify(t.ledger.verify(cp))
    plain = t.ledger.verify()
    echo(
        click.style(
            f"  (Without the checkpoint, verify finds {len(plain.problems)} problem: the edit. "
            "The cut tail would look like a shorter, valid chain.)",
            dim=True,
        )
    )


def _demo_table(t: Trellis, token: str, heads: list[str], calls: list[tuple[str, str]]) -> None:
    rows: list[list[str]] = [["CALL", *heads, "", "RESULT"]]
    notes: list[str] = []
    for action, resource in calls:
        d = t.authorize(token, action, resource)
        marks = [YES if c.allowed else NO for c in d.checks]
        verdict = click.style("ALLOW", fg="green") if d.allowed else click.style("DENY", fg="red")
        if d.allowed:
            extra = []
            if d.masked:
                extra.append("masked " + ", ".join(d.masked))
            if d.row_filter:
                extra.append(f"rows {d.row_filter}")
            note = "; ".join(extra)
        else:
            first = next(c for c in d.checks if not c.allowed)
            note = first.reason
        rows.append([f"{action} {resource}", *marks, verdict, note])
        for col, why in d.masked.items():
            notes.append(f"    {resource}.{col} masked: {why}")
    _table(rows)
    for n in notes:
        click.echo(click.style(n, dim=True))


# -- config ----------------------------------------------------------------------------------


@main.command("compile")
@config_option
def compile_(config_paths: tuple[str, ...]) -> None:
    """Print the Cedar that Trellis generates from the YAML."""
    try:
        cfg = load_config(*config_paths)
    except ConfigError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(render(cfg))


@main.command("validate")
@config_option
def validate(config_paths: tuple[str, ...]) -> None:
    """Check the YAML and validate the generated Cedar against Trellis's schema."""
    try:
        cfg = load_config(*config_paths)
    except ConfigError as exc:
        raise click.ClickException(str(exc)) from exc
    errors = Compiler(cfg).validate()
    if errors:
        for e in errors:
            click.echo(f"{NO} {e}", err=True)
        sys.exit(1)
    click.echo(
        f"{YES} {len(cfg.people)} people, {len(cfg.agents)} agents, "
        f"{len(cfg.access)} access rules, {len(cfg.purposes)} purposes, "
        f"{len(cfg.catalog)} tables; Cedar validates."
    )


@main.command()
def schema() -> None:
    """Print the JSON Schema for Trellis's YAML."""
    click.echo(json.dumps(json_schema(), indent=2))


# -- ledger ----------------------------------------------------------------------------------


@main.group()
def ledger() -> None:
    """The hash-chained ledger: verify, checkpoint, export."""


def _ledger(db_url: str, signed: bool = False) -> Ledger:
    try:
        return Ledger(Database(db_url), _signer() if signed else None)
    except DatabaseError as exc:
        raise click.ClickException(str(exc)) from exc


@ledger.command("verify")
@db_option
@click.option(
    "--checkpoint",
    "checkpoint_file",
    type=click.Path(exists=True, dir_okay=False),
    help="A signed checkpoint (JSON) to check the chain against.",
)
def ledger_verify(db_url: str, checkpoint_file: str | None) -> None:
    """Walk the chain and report every event that doesn't check out.

    With --checkpoint it also catches a cut tail or a rewritten history.
    """
    cp = (
        Checkpoint.model_validate_json(Path(checkpoint_file).read_text())
        if checkpoint_file
        else None
    )
    led = _ledger(db_url)
    v = led.verify(cp)
    led.db.close()
    _print_verify(v)
    if not v.ok:
        sys.exit(1)


def _print_verify(v: VerifyResult) -> None:
    against = f" against the checkpoint at event {v.checkpoint.seq}" if v.checkpoint else ""
    if v.ok:
        click.echo(f"{YES} {v.checked} events, chain intact{against}.")
        return
    click.echo(f"{NO} the ledger fails verification{against}:")
    for p in v.problems:
        click.echo(f"  {NO} {p}")


@ledger.command("checkpoint")
@db_option
@click.option("--out", type=click.Path(dir_okay=False), help="Also write it to this file.")
def ledger_checkpoint(db_url: str, out: str | None) -> None:
    """Sign the current head of the chain. Keep the output somewhere else."""
    led = _ledger(db_url, signed=True)
    cp = led.checkpoint()
    led.db.close()
    text = cp.model_dump_json(indent=2)
    if out:
        Path(out).write_text(text + "\n")
    click.echo(text)


@ledger.command("export")
@db_option
@click.option("--console", is_flag=True, help="Print spans to stdout instead of OTLP.")
@click.option("--limit", default=500, show_default=True)
def ledger_export(db_url: str, console: bool, limit: int) -> None:
    """Send queued events to OpenTelemetry (one span each), at least once."""
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor

    provider = TracerProvider(resource=Resource.create({"service.name": "trellisd"}))
    if console:
        provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter(out=sys.stdout)))
    else:
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (  # type: ignore
                OTLPSpanExporter,
            )
        except ImportError as exc:
            raise click.ClickException(
                "install opentelemetry-exporter-otlp-proto-http, or pass --console"
            ) from exc
        provider.add_span_processor(SimpleSpanProcessor(OTLPSpanExporter()))
    led = _ledger(db_url)
    result = drain(led, OpenTelemetrySink(provider), limit=limit)
    left = backlog(led)
    led.db.close()
    provider.shutdown()
    msg = f"sent {result.sent}, {left} still queued"
    if result.error:
        msg += f" (stopped at an error: {result.error})"
    click.echo(msg, err=True)


@main.command()
@db_option
@click.argument("event_id", required=False)
@click.option("--agent")
@click.option("--for", "subject", help="Person or purpose.")
@click.option("--grant", "grant_id")
@click.option("--since", default="7d", show_default=True)
@click.option("--json", "as_json", is_flag=True)
def trace(
    db_url: str,
    event_id: str | None,
    agent: str | None,
    subject: str | None,
    grant_id: str | None,
    since: str,
    as_json: bool,
) -> None:
    """Walk one decision back to who allowed it, or list recent events.

    With an EVENT_ID: the grant it ran under, who issued it and when, the three answers
    and the policy behind each. Without one: what agents did, newest last.
    """
    led = _ledger(db_url)
    try:
        if event_id:
            try:
                t = trace_event(led, event_id)
            except TraceError as exc:
                raise click.ClickException(str(exc)) from exc
            print_trace(t)
            return
        events = led.query(
            agent=agent, subject=subject, grant_id=grant_id, since=utcnow() - parse_duration(since)
        )
    finally:
        led.db.close()
    if as_json:
        for ev in events:
            click.echo(ev.model_dump_json())
        return
    if not events:
        click.echo("No matching events.")
        return
    for ev in events:
        click.echo(_event_line(ev))


def print_trace(t: Trace) -> None:
    echo = click.echo
    d, ev = t.decision, t.event
    verdict = (
        click.style("ALLOWED", fg="green", bold=True)
        if d.allowed
        else click.style("DENIED", fg="red", bold=True)
    )
    echo(f"{verdict}  {d.agent} {d.action} {d.resource}")
    echo(f"  at {ev.ts:%Y-%m-%d %H:%M:%S} UTC, event {ev.seq} ({ev.event_id})")
    if t.grant is not None:
        g, issued = t.grant.grant, t.grant.issued
        sig = (
            click.style("signed", fg="green")
            if t.grant.signature_ok
            else click.style("NOT validly signed", fg="red")
        )
        echo("")
        echo(click.style("Who allowed it", bold=True))
        who = (
            f"{g.issued_by} let {g.agent} act for them"
            if not g.is_purpose
            else f"{g.issued_by} started {g.agent} under purpose {g.subject}"
        )
        echo(f"  {who}: {g.task or g.describe()}")
        if g.is_purpose:
            echo(f"  trigger: {g.trigger_type} {g.trigger_record}")
        echo(
            f"  grant {g.id}, issued {issued.ts:%Y-%m-%d %H:%M:%S} UTC (event {issued.seq}),"
            f" scope {', '.join(sorted(g.scope))}, until {g.expires_at:%H:%M} UTC"
        )
        echo(f"  receipt {issued.hash[:16]}…, {sig} by key {issued.key_id}")
        if t.grant.revoked is not None:
            r = t.grant.revoked
            echo(
                f"  revoked by {r.body.get('by')} at {r.ts:%Y-%m-%d %H:%M:%S} UTC "
                f"(event {r.seq}), before this call"
            )
    echo("")
    echo(click.style("The three checks", bold=True))
    for c in d.checks:
        mark = YES if c.allowed else NO
        if c.allowed:
            echo(f"  {mark} {c.label}: allowed by {', '.join(c.policies)}")
        else:
            if c.policies:
                behind = f"forbidden by {', '.join(c.policies)}"
            elif c.considered:
                behind = f"{', '.join(c.considered)} didn't cover it"
            else:
                behind = "no policy applies"
            echo(f"  {mark} {c.label}: {c.reason} ({behind})")
    if not d.checks:
        echo(f"  {NO} {d.reason}")
    if d.allowed and (d.masked or d.row_filter):
        echo("")
        echo(click.style("Obligations", bold=True))
        for col, why in d.masked.items():
            echo(f"  masked {col}: {why}")
        if d.row_filter:
            echo(f"  rows   {d.row_filter}")
    for w in t.warnings:
        echo(click.style(f"  warning: {w}", fg="red"))


@main.command()
@config_option
@db_option
@click.argument("event_id")
@click.option("--replay", is_flag=True, help="Re-run it at its recorded version and today.")
def explain(config_paths: tuple[str, ...], db_url: str, event_id: str, replay: bool) -> None:
    """Explain one decision; with --replay, re-run it and say whether anything changed."""
    led = _ledger(db_url)
    try:
        t = trace_event(led, event_id)
        print_trace(t)
        if not replay:
            return
        cfg = load_config(*config_paths) if config_paths else None
        if cfg is None:
            raise click.UsageError("--replay needs --config (today's policy) to compare against")
        r = replay_event(led, Engine(cfg), event_id)
    except (TraceError, ConfigError) as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        led.db.close()
    print_replay(r)


def print_replay(r: Replay) -> None:
    echo = click.echo
    echo("")
    echo(click.style("Replay", bold=True))
    if r.at_recorded_version is None:
        echo(f"  {NO} can't replay at the recorded version: {r.unavailable}")
    elif r.reproduces:
        echo(
            f"  {YES} at its recorded config and catalog snapshot: the same decision, "
            "check for check"
        )
    else:
        echo(f"  {NO} at its recorded version it comes out differently:")
        for line in differences(r.recorded, r.at_recorded_version):
            echo(f"      {line}")
    changes = r.changed_today
    if not changes:
        echo(f"  {YES} against today's policy: unchanged")
    else:
        echo(f"  {click.style('!', fg='yellow', bold=True)} against today's policy:")
        for line in changes:
            echo(f"      {line}")


def _event_line(ev: LedgerEvent) -> str:
    b = ev.body
    when = f"{ev.ts:%Y-%m-%d %H:%M:%S}"
    if ev.kind == "decision":
        verdict = (
            click.style("ALLOW", fg="green") if b.get("allowed") else click.style("DENY ", fg="red")
        )
        tail = "" if b.get("allowed") else f"  {b.get('reason', '')}"
        call = f"{ev.agent} {b.get('action')} {b.get('resource')}"
        return f"{when}  {verdict} {call}{tail}  [{ev.event_id}]"
    return f"{when}  {ev.kind:<13} {ev.agent} for {ev.subject} {ev.grant_id}  [{ev.event_id}]"


# -- helpers ---------------------------------------------------------------------------------


def _split(text: str) -> list[str]:
    return [p.strip() for p in text.split(",") if p.strip()]


def _table(rows: list[list[str]]) -> None:
    def width(s: str) -> int:
        return len(click.unstyle(s))

    widths = [max(width(r[i]) for r in rows) for i in range(len(rows[0]))]
    for n, row in enumerate(rows):
        cells = []
        for i, cell in enumerate(row):
            pad = widths[i] - width(cell)
            if n > 0 and 0 < i < len(row) - 2:  # centre the tick columns
                left = pad // 2
                cells.append(" " * left + cell + " " * (pad - left))
            else:
                cells.append(cell + " " * pad)
        line = "  ".join(cells).rstrip()
        click.echo(click.style(line, bold=True) if n == 0 else line)


if __name__ == "__main__":  # pragma: no cover
    main()
