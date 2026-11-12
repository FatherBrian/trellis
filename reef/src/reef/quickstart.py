"""The one-command quickstart's moving parts: seeding the catalog, and the scripted agent.

``docker compose up`` in quickstart/ starts Postgres, an Iceberg REST catalog, Keycloak,
the two sample MCP servers, Trellis with Reef in front of them, and then this agent. The
agent does what a real one would, over the network:

1. Ana signs in at Keycloak, report-bot signs in as itself, and report-bot trades both
   tokens at Trellis's token endpoint for a grant (task "Q3 close", scope finance).
2. It connects to Reef with the grant token and lists its tools: only its grant's.
3. It reads the journal: Ana's region only, approver_email masked because the catalog
   tags that column pii.
4. It calls payroll, outside its task, and is denied at the door.
5. It runs ``trellisd trace`` on that deny and verifies the ledger.

It exits non-zero if anything in the story doesn't hold, which is what CI checks.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any, TypeVar

import click
from mcp import types

from reef.agent import AgentClient
from trellisd.db import Database
from trellisd.demo_idp import http
from trellisd.iceberg import IcebergRestAdmin
from trellisd.ledger import Ledger
from trellisd.server import TOKEN_EXCHANGE
from trellisd.trace import trace

T = TypeVar("T")
JOURNAL = "finance.gl.journal_entries"


def wait_for(what: str, probe: Callable[[], T], seconds: float = 180) -> T:
    """Retry ``probe`` until it returns, for services still starting."""
    deadline = time.monotonic() + seconds
    while True:
        try:
            return probe()
        except Exception as exc:
            if time.monotonic() > deadline:
                raise click.ClickException(f"{what} didn't come up: {exc}") from exc
            time.sleep(1)


def seed(catalog: str, warehouse: str | None = None) -> None:
    """Create the finance table, and tag one column pii the way a data steward would."""
    admin = IcebergRestAdmin(catalog, warehouse=warehouse)
    wait_for(f"the catalog at {catalog}", lambda: admin.create_namespace("finance.gl"))
    admin.drop_table(JOURNAL)
    admin.create_table(
        JOURNAL,
        {
            "entry_id": "string",
            "amount": "decimal(18,2)",
            "region": "string",
            "approver_email": "string",
        },
        {"trellis.tags": "finance"},
    )
    admin.tag_column(JOURNAL, "approver_email", "pii")
    click.echo(f"seeded {JOURNAL} in {catalog}: approver_email tagged pii in the catalog")


def _token(url: str, form: dict[str, str]) -> str:
    status, out = http("POST", url, form=form)
    if status != 200:
        raise RuntimeError(f"{url} answered {status}: {out}")
    return str(out["access_token"])


def _structured(result: types.CallToolResult) -> Any:
    return result.structured_content if result.structured_content is not None else {}


def run_agent(*, keycloak: str, trellis: str, reef: str, db: str) -> bool:
    from trellisd.cli import print_trace

    echo = click.echo
    failures: list[str] = []

    def h(text: str) -> str:
        return click.style(text, bold=True)

    def step(n: int, text: str) -> None:
        echo("")
        echo(h(f"{n}. ") + text)

    def expect(ok: bool, what: str) -> None:
        mark = click.style("✓", fg="green") if ok else click.style("✗", fg="red")
        echo(f"   {mark} {what}")
        if not ok:
            failures.append(what)

    issuer = keycloak.rstrip("/")
    doc = wait_for("Keycloak", lambda: _discovery(issuer))
    token_endpoint = str(doc["token_endpoint"])
    wait_for("Trellis", lambda: _ok(http("GET", f"{trellis}/healthz")))

    echo(h("Trellis and Reef quickstart:") + " an agent, its grant, and the door.")
    echo(f"IdP {issuer}, Trellis {trellis}, Reef {reef}")

    step(1, "Ana signs in at the IdP, report-bot signs in as itself, and they trade for a grant:")
    ana = wait_for(
        "Ana's sign-in",
        lambda: _token(
            token_endpoint,
            {
                "grant_type": "password",
                "client_id": "trellis-cli",
                "username": "ana",
                "password": "ana-demo",
                "scope": "openid email",
            },
        ),
    )
    bot = _token(
        token_endpoint,
        {
            "grant_type": "client_credentials",
            "client_id": "report-bot",
            "client_secret": "report-bot-demo-secret",
        },
    )
    status, out = http(
        "POST",
        f"{trellis}/token",
        form={
            "grant_type": TOKEN_EXCHANGE,
            "subject_token": ana,
            "actor_token": bot,
            "scope": "finance",
            "task": "Q3 close",
        },
    )
    if status != 200:
        raise click.ClickException(f"Trellis refused the grant: {out}")
    grant = str(out["access_token"])
    echo(
        f"   grant {out['grant_id']}: report-bot for ana@example.com,"
        " task 'Q3 close', scope finance"
    )

    agent = AgentClient(reef, grant)
    step(2, "report-bot connects to Reef with its grant token and lists its tools:")
    tools = agent.list_tools()
    for t in tools:
        first, *rest = (t.description or "").split("\n\n")
        echo(f"   {t.name}: {first}")
        for note in rest:
            echo(click.style(f"     {note}", dim=True))
    expect([t.name for t in tools] == ["ledger_journal_entries"], "only its grant's tool is listed")

    ledger = Ledger(Database(db))
    step(3, "It reads the journal:")
    r = agent.call("ledger_journal_entries")
    rows = _structured(r).get("rows", [])
    for row in rows:
        echo(f"   {json.dumps(row)}")
    expect(not r.is_error and len(rows) == 2, "two rows: Ana's region only")
    expect(all(row.get("approver_email") == "***" for row in rows), "approver_email is masked")
    allowed = [
        e
        for e in ledger.query(kind="decision")
        if e.body.get("allowed") and e.body.get("resource") == JOURNAL
    ]
    if allowed:
        tr = trace(ledger, allowed[-1].event_id)
        info = tr.table
        sources = info.column_provenance.get("approver_email", {}).get("pii", ()) if info else ()
        for src in sources:
            echo(click.style(f"   approver_email is pii because {src.source} says so", dim=True))
        expect(
            any(src.source.startswith("catalog") for src in sources),
            "the pii tag came from the catalog",
        )
        forward = [e for e in tr.enforcement if e.body.get("stage") == "forward"]
        if forward:
            echo(
                click.style(
                    f"   Reef forwarded the call with Ana's own token, exchanged for "
                    f"{forward[0].body.get('audience')} ({forward[0].body.get('credential')} mode)",
                    dim=True,
                )
            )
        expect(
            bool(forward) and forward[0].body.get("credential") == "obo", "forwarded as Ana (obo)"
        )
    else:
        expect(False, "the read is in the ledger as an allowed decision")

    step(4, "It calls hr_payroll, outside its task:")
    r = agent.call("hr_payroll")
    out = _structured(r)
    echo(f"   {r.content[0].text if r.content else ''}")  # type: ignore[union-attr]
    expect(r.is_error and out.get("denied_by") == ["task"], "denied at the door by the task check")

    step(5, f"$ trellisd trace {out.get('event_id')}")
    echo("")
    print_trace(trace(ledger, str(out.get("event_id"))))
    blocked = [
        e for e in ledger.query(kind="enforcement") if e.body.get("decision") == out.get("event_id")
    ]
    expect(len(blocked) == 1 and blocked[0].body["stage"] == "blocked", "nothing was forwarded")

    step(6, "$ trellisd ledger verify")
    result = ledger.verify()
    echo(f"   {result.checked} events, chain {'verified' if result.ok else 'BROKEN'}")
    expect(result.ok, "the ledger verifies")

    echo("")
    if failures:
        echo(click.style(f"{len(failures)} checks failed: " + "; ".join(failures), fg="red"))
        return False
    echo(click.style("Every check held.", fg="green"))
    return True


def _discovery(issuer: str) -> dict[str, Any]:
    status, doc = http("GET", issuer + "/.well-known/openid-configuration")
    if status != 200:
        raise RuntimeError(f"discovery answered {status}")
    return doc


def _ok(response: tuple[int, dict[str, Any]]) -> None:
    if response[0] != 200:
        raise RuntimeError(f"answered {response[0]}")


def jwks_verifier(issuer: str, audience: str) -> Callable[[str], str]:
    """A sample server's check on an obo token: the IdP's signature, issuer and audience."""
    import jwt

    client: list[jwt.PyJWKClient] = []

    def verify(token: str) -> str:
        if not client:
            doc = _discovery(issuer.rstrip("/"))
            client.append(jwt.PyJWKClient(str(doc["jwks_uri"])))
        try:
            key = client[0].get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256", "PS256", "ES256"],
                audience=audience,
                issuer=issuer.rstrip("/"),
            )
        except jwt.PyJWTError as exc:
            raise PermissionError(str(exc)) from exc
        return str(claims.get("email") or claims.get("sub"))

    return verify
