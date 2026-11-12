"""``reef``: run the door in front of your MCP servers, or watch the demo."""

from __future__ import annotations

import click

from trellisd.app import Trellis
from trellisd.config import load_config
from trellisd.db import DEFAULT_URL


@click.group()
@click.version_option(package_name="reef-mcp", message="reef %(version)s")
def main() -> None:
    """Reef: Trellis enforced at the door of your MCP servers."""


@main.command()
@click.option("--config", "reef_config", required=True, help="reef.yaml: the servers behind Reef.")
@click.option(
    "--trellis",
    "trellis_config",
    multiple=True,
    required=True,
    help="Trellis config files or dirs.",
)
@click.option("--db", default=DEFAULT_URL, show_default=True, help="Trellis's database URL.")
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8190, show_default=True)
def serve(reef_config: str, trellis_config: tuple[str, ...], db: str, host: str, port: int) -> None:
    """Serve one MCP endpoint (http://HOST:PORT/mcp) in front of the configured servers.

    Trellis runs in the same process, so a decision, its ledger entry and the forward
    happen in one place. Agents connect with their Trellis grant token as the bearer token.
    """
    from reef.config import load_reef_config
    from reef.gateway import Reef
    from reef.server import serve as run

    rc = load_reef_config(reef_config)
    with Trellis(load_config(*trellis_config), db) as trellis:
        click.echo(f"Reef at http://{host}:{port}/mcp in front of {', '.join(rc.servers)}")
        run(Reef(trellis, rc), host, port)


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
