"""``reef``: run the door in front of your MCP servers, or watch the demo."""

from __future__ import annotations

from pathlib import Path

import click

from reef.lock import Lock, LockError
from trellisd.app import Trellis
from trellisd.config import load_config
from trellisd.db import DEFAULT_URL


@click.group()
@click.version_option(package_name="reef-mcp", message="reef %(version)s")
def main() -> None:
    """Reef: Trellis enforced at the door of your MCP servers."""


@main.command()
@click.option(
    "--config",
    "reef_config",
    default="reef.yaml",
    show_default=True,
    help="The servers behind Reef.",
)
@click.option(
    "--trellis",
    "trellis_config",
    multiple=True,
    required=True,
    help="Trellis config files or dirs.",
)
@click.option("--db", default=DEFAULT_URL, show_default=True, help="Trellis's database URL.")
@click.option(
    "--key", "key_path", default=None, help="Ed25519 key for the ledger (made if missing)."
)
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8190, show_default=True)
@click.option(
    "--trellis-port",
    default=None,
    type=int,
    help="Also serve Trellis's token and AuthZEN endpoints on this port, from the same process.",
)
@click.option(
    "--lock",
    "lock_path",
    default=None,
    help="reef.lock to enforce. Default: reef.lock next to the config, if it exists.",
)
def serve(
    reef_config: str,
    trellis_config: tuple[str, ...],
    db: str,
    key_path: str | None,
    host: str,
    port: int,
    trellis_port: int | None,
    lock_path: str | None,
) -> None:
    """Serve one MCP endpoint (http://HOST:PORT/mcp) in front of the configured servers.

    Trellis runs in the same process, so a decision, its ledger entry and the forward
    happen in one place. Agents connect with their Trellis grant token as the bearer token.
    With --trellis-port, agents sign in at that same Trellis, which is what obo mode needs:
    the person's sign-in is held in memory, never in the database.
    """
    from reef.config import load_reef_config
    from reef.gateway import Reef
    from reef.server import serve as run
    from trellisd.server import TrellisServer
    from trellisd.signing import Signer

    rc = load_reef_config(reef_config)
    lock = _load_lock(reef_config, lock_path)
    signer = Signer.load_or_create(key_path) if key_path else None
    config = rc.apply_to(load_config(*trellis_config))
    with Trellis(config, db, signer=signer) as trellis:
        reef = Reef(trellis, rc, lock=lock)
        side = None
        if trellis_port is not None:
            side = TrellisServer(trellis, host, trellis_port)
            side._lock = reef._lock  # one lock: sign-in, decisions and the ledger serialize
            side.start()
            click.echo(f"Trellis at http://{host}:{trellis_port} (token, AuthZEN, /healthz)")
        click.echo(f"Reef at http://{host}:{port}/mcp in front of {', '.join(rc.servers)}")
        try:
            run(reef, host, port)
        finally:
            if side is not None:
                side.close()


@main.command()
@click.option(
    "--config",
    "reef_config",
    default="reef.yaml",
    show_default=True,
    help="The servers behind Reef (and their contracts).",
)
@click.option(
    "--trellis",
    "trellis_config",
    multiple=True,
    required=True,
    help="Trellis config files or dirs.",
)
@click.option("--db", default=DEFAULT_URL, show_default=True, help="Trellis's database URL.")
@click.option(
    "--key", "key_path", default=None, help="Ed25519 key for the ledger (made if missing)."
)
@click.option("--person", required=True, help="Who the agent acts for (and who allows it).")
@click.option("--agent", required=True)
@click.option("--task", required=True, help="What the agent is doing, in words.")
@click.option("--scope", required=True, help="Comma-separated tags the task covers.")
@click.option("--actions", default="read,query", show_default=True)
@click.option("--ttl", default="1h", show_default=True, help="30m, 8h, 1d (24h at most).")
@click.option("--json", "as_json", is_flag=True)
def grant(
    reef_config: str,
    trellis_config: tuple[str, ...],
    db: str,
    key_path: str | None,
    person: str,
    agent: str,
    task: str,
    scope: str,
    actions: str,
    ttl: str,
    as_json: bool,
) -> None:
    """A person lets an agent act for them on one task, through Reef.

    Like `trellisd grant issue`, but it also reads reef.yaml, so the servers' own contracts
    count. Give the token to the agent as its bearer token for Reef.
    """
    from reef.config import ReefConfigError, load_reef_config
    from trellisd.cli import parse_duration, print_issued
    from trellisd.config import ConfigError
    from trellisd.grants import GrantError
    from trellisd.signing import Signer

    try:
        config = load_reef_config(reef_config).apply_to(load_config(*trellis_config))
    except (ConfigError, ReefConfigError) as exc:
        raise click.ClickException(str(exc)) from exc
    signer = Signer.load_or_create(key_path) if key_path else None
    with Trellis(config, db, signer=signer) as trellis:
        try:
            issued = trellis.issue_grant(
                person=person,
                agent=agent,
                task=task,
                scope=[t.strip() for t in scope.split(",") if t.strip()],
                actions=tuple(a.strip() for a in actions.split(",") if a.strip()),
                ttl=parse_duration(ttl),
            )
        except GrantError as exc:
            raise click.ClickException(f"grant refused: {exc}") from exc
    print_issued(issued.grant, issued.token, as_json)


def _lock_file(reef_config: str, lock_path: str | None) -> Path:
    return Path(lock_path) if lock_path else Path(reef_config).with_name("reef.lock")


def _load_lock(reef_config: str, lock_path: str | None) -> Lock | None:
    path = _lock_file(reef_config, lock_path)
    if not path.exists():
        if lock_path:
            raise click.ClickException(f"{path}: no such lock (write one with `reef lock`)")
        click.echo(
            f"No {path.name}: tool descriptions aren't pinned. Run `reef lock` to pin them.",
            err=True,
        )
        return None
    try:
        lock = Lock.load(path)
    except LockError as exc:
        raise click.ClickException(str(exc)) from exc
    count = sum(len(tools) for tools in lock.servers.values())
    click.echo(f"Enforcing {path.name}: {count} pinned tools")
    return lock


@main.command("lock")
@click.option(
    "--config",
    "reef_config",
    default="reef.yaml",
    show_default=True,
    help="The servers behind Reef.",
)
@click.option(
    "--from",
    "from_client",
    default=None,
    metavar="CLIENT|PATH",
    help="Lock the servers an MCP client is set up with instead: claude-desktop, claude-code,"
    " vscode, cursor, or the path to its JSON config.",
)
@click.option(
    "--lock",
    "lock_path",
    default=None,
    help="Default: reef.lock next to reef.yaml, or in the current directory with --from.",
)
@click.option("--check", is_flag=True, help="Exit 1 if any tool differs from the lock (CI).")
@click.option("--update", is_flag=True, help="Rewrite the lock after reviewing the diff.")
def lock_command(
    reef_config: str, from_client: str | None, lock_path: str | None, check: bool, update: bool
) -> None:
    """Pin each tool's description, schemas and annotations in reef.lock.

    The first run writes the lock. After that, it shows what changed on the servers, and
    --update rewrites it once you've reviewed the diff. With a lock, `reef serve` hides
    and refuses any tool that no longer matches.

    With --from, it locks every tool of the servers in an MCP client's config (Claude
    Desktop, Claude Code, VS Code, Cursor), so `reef lock --check --from ...` works in CI
    for any MCP setup. That starts the config's stdio servers, as the client would.
    """
    import asyncio
    import os

    from reef.clients import ClientConfigError, load_client_config
    from reef.config import ReefConfigError, load_reef_config
    from reef.lock import fetch_catalog

    if check and update:
        raise click.UsageError("--check and --update don't go together")
    try:
        if from_client:
            loaded = load_client_config(from_client)
            rc = loaded.config
            click.echo(f"Servers from {loaded.path}: {', '.join(rc.servers) or 'none'}")
            for name, why in loaded.skipped.items():
                click.echo(click.style(f"Skipped {name}: it {why}", fg="yellow"))
            if not rc.servers:
                raise click.ClickException("no server in that config can be locked")
        else:
            rc = load_reef_config(reef_config)
        catalog = asyncio.run(fetch_catalog(rc, os.environ, every_tool=bool(from_client)))
    except (ReefConfigError, LockError, ClientConfigError) as exc:
        raise click.ClickException(str(exc)) from exc

    for server, spec in rc.servers.items():
        offered = {t.name for t in catalog.get(server, [])}
        for tool in sorted(set(spec.tools) - offered):
            click.echo(f"Note: reef.yaml maps {server}/{tool}, but {server} doesn't offer it")

    path = Path(lock_path or "reef.lock") if from_client else _lock_file(reef_config, lock_path)
    fresh = Lock.from_catalog(catalog)
    count = sum(len(tools) for tools in fresh.servers.values())
    if not path.exists():
        if check:
            raise click.ClickException(f"{path}: no lock yet (write one with `reef lock`)")
        fresh.save(path)
        n = len(fresh.servers)
        click.echo(f"Wrote {path}: {count} tools across {n} server{'' if n == 1 else 's'}.")
        where = "your MCP config" if from_client else "reef.yaml"
        click.echo(f"Review it, and commit it next to {where}.")
        return

    try:
        current = Lock.load(path)
    except LockError as exc:
        raise click.ClickException(str(exc)) from exc
    drifts = current.compare(catalog)
    if not drifts:
        click.echo(f"{path.name} matches: {count} tools.")
        return
    for d in drifts:
        click.echo(click.style(str(d), fg="yellow", bold=True))
        if d.diff:
            for line in d.diff.splitlines():
                color = "green" if line.startswith("+") else "red" if line.startswith("-") else None
                click.echo("    " + (click.style(line, fg=color) if color else line))
    if update:
        fresh.save(path)
        click.echo(f"Updated {path}. Review the diff above before you commit it.")
        return
    raise click.ClickException(
        f"{len(drifts)} change(s) since {path.name} was written."
        " Review them, then run `reef lock --update`."
    )


@main.command()
@click.argument("which", type=click.Choice(["ledger", "hr"]))
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=9101, show_default=True)
@click.option("--issuer", default=None, help="ledger: the IdP whose tokens it accepts.")
@click.option("--audience", default="ledger-mcp", show_default=True)
@click.option(
    "--secret-env",
    default="REEF_HR_TOKEN",
    show_default=True,
    help="hr: the environment variable that holds its service credential.",
)
def sample(
    which: str, host: str, port: int, issuer: str | None, audience: str, secret_env: str
) -> None:
    """Run one of the sample MCP servers: ledger (takes the person's token) or hr (a service
    credential). They log who called and hand back the rows; Reef applies the obligations."""
    import os

    import uvicorn

    from reef.quickstart import jwks_verifier
    from reef.samples import hr_server, ledger_server
    from reef.server import app
    from reef.stack import secret_verifier

    if which == "ledger":
        if not issuer:
            raise click.UsageError("the ledger server needs --issuer")
        srv = ledger_server(jwks_verifier(issuer, audience))
    else:
        secret = os.environ.get(secret_env, "")
        if not secret:
            raise click.UsageError(f"set {secret_env} to the hr server's service credential")
        srv = hr_server(secret_verifier(secret, "reef (hr service account)"))
    click.echo(f"sample {which} MCP server at http://{host}:{port}/mcp")
    uvicorn.run(app(srv.server(), host), host=host, port=port, log_level="warning")


@main.group()
def quickstart() -> None:
    """The pieces docker compose runs in quickstart/."""


@quickstart.command("seed")
@click.option("--catalog", required=True, help="The Iceberg REST catalog's URL.")
@click.option("--warehouse", default=None)
def quickstart_seed(catalog: str, warehouse: str | None) -> None:
    """Create finance.gl.journal_entries in the catalog and tag approver_email pii."""
    from reef.quickstart import seed

    seed(catalog, warehouse)


@quickstart.command("agent")
@click.option("--keycloak", required=True, help="The IdP realm's issuer URL.")
@click.option("--trellis", "trellis_url", required=True, help="Trellis's base URL.")
@click.option("--reef", "reef_url", required=True, help="Reef's MCP URL.")
@click.option("--db", required=True, help="The ledger's database URL, for trace and verify.")
def quickstart_agent(keycloak: str, trellis_url: str, reef_url: str, db: str) -> None:
    """The scripted agent: sign in, list, read, get denied, trace, verify."""
    from reef.quickstart import run_agent

    if not run_agent(keycloak=keycloak, trellis=trellis_url, reef=reef_url, db=db):
        raise SystemExit(1)


@main.group()
def demo() -> None:
    """Scripted demos that run on this machine."""


@demo.command("the-door")
@click.option("--postgres", default=None, help="Keep the ledger in this Postgres (URL).")
def the_door(postgres: str | None) -> None:
    """Two agents, one Reef, two MCP servers, and a ledger that goes away."""
    from reef.demo import run_the_door

    run_the_door(postgres)


if __name__ == "__main__":  # pragma: no cover
    main()
