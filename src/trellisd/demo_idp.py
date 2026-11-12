"""M4's demo, "Bring your own IdP": sign-in from any OIDC IdP, then one AuthZEN endpoint.

Ana signs in to her IdP; report-bot signs in as itself; report-bot trades both tokens at
Trellis's token endpoint for a grant token; then plain HTTP calls to the AuthZEN endpoint
get an allow with a mask and a deny that names the check. Everything goes over HTTP, as a
curl would, to a Trellis server the demo starts in process.

By default the IdP is ``FakeIdP``, started in process. ``--keycloak`` points it at the
demo realm in ``examples/idp/keycloak`` instead, using that realm's throwaway secrets.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

import click
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from trellisd.app import Trellis
from trellisd.config import TrellisConfig
from trellisd.engine import Decision
from trellisd.identity import Identities
from trellisd.server import TOKEN_EXCHANGE, TrellisServer

#: The demo realm's throwaway credentials (examples/idp/keycloak/trellis-realm.json).
DEMO_SECRETS = {
    "trellis": "trellis-demo-secret",
    "report-bot": "report-bot-demo-secret",
    "inspector-bot": "inspector-bot-demo-secret",
    "rogue-bot": "rogue-bot-demo-secret",
}
DEMO_USERS: dict[str, dict[str, Any]] = {
    "ana": {"email": "ana@example.com", "password": "ana-demo", "groups": ["finance-analysts"]},
    "tom": {"email": "tom@example.com", "password": "tom-demo", "groups": ["treasury"]},
}


def http(
    method: str,
    url: str,
    *,
    form: dict[str, str] | None = None,
    body: Any = None,
    bearer: str | None = None,
) -> tuple[int, dict[str, Any]]:
    headers = {"Accept": "application/json"}
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


@dataclass
class Idp:
    """The IdP the demo signs in to: the in-process fake, or a Keycloak realm."""

    issuer: str
    token_endpoint: str
    fake: Any = None

    def password(self, user: str) -> str:
        status, out = http(
            "POST",
            self.token_endpoint,
            form={
                "grant_type": "password",
                "client_id": "trellis-cli",
                "username": user,
                "password": DEMO_USERS[user]["password"],
                "scope": "openid email",
            },
        )
        if status != 200:
            raise click.ClickException(f"{user} couldn't sign in at the IdP: {out}")
        return str(out["access_token"])

    def client(self, client_id: str) -> str:
        status, out = http(
            "POST",
            self.token_endpoint,
            form={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": DEMO_SECRETS[client_id],
            },
        )
        if status != 200:
            raise click.ClickException(f"{client_id} couldn't sign in at the IdP: {out}")
        return str(out["access_token"])


@contextmanager
def open_idp(keycloak: str | None) -> Iterator[Idp]:
    if keycloak:
        issuer = keycloak.rstrip("/")
        status, doc = http("GET", issuer + "/.well-known/openid-configuration")
        if status != 200:
            raise click.ClickException(f"no OIDC discovery document at {issuer} ({status})")
        yield Idp(issuer, str(doc["token_endpoint"]))
        return
    from trellisd.fake_idp import FakeIdP

    with FakeIdP(users=DEMO_USERS, clients=DEMO_SECRETS, ttl=900) as fake:
        yield Idp(fake.issuer, f"{fake.issuer}/token", fake)


def claims(token: str) -> dict[str, Any]:
    out: dict[str, Any] = jwt.decode(token, options={"verify_signature": False})
    return out


def short(token: str) -> str:
    return token[:12] + "…"


def run_bring_your_own_idp(
    config: TrellisConfig, db_url: str, keycloak: str | None = None
) -> list[Decision]:
    """The M4 demo. Returns the evaluated decisions, in order, for the tests."""
    from trellisd.cli import _table, print_trace
    from trellisd.trace import trace

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

    decisions: list[Decision] = []
    with open_idp(keycloak) as idp:
        local = config.idps["local"].model_copy(update={"issuer": idp.issuer})
        config = config.model_copy(update={"idps": {"local": local}})
        env = {local.client_secret_env or "": DEMO_SECRETS["trellis"]}
        identities = Identities.from_config(config, environ=env)
        with (
            Trellis(config, db_url, identities=identities) as t,
            TrellisServer(t) as server,
        ):
            base = server.uri
            where = "in process" if idp.fake else "the Keycloak demo realm"
            echo(h("Bring your own IdP:") + " sign in anywhere, then one AuthZEN endpoint.")
            echo("")
            echo(f"The IdP is {where}, issuer {idp.issuer}.")
            echo(f"Trellis serves AuthZEN and token exchange at {base}.")
            _, disco = http("GET", f"{base}/.well-known/authzen-configuration")
            dim(f"  discovery: access_evaluation_endpoint {disco['access_evaluation_endpoint']}")

            step(1, "Ana signs in to her IdP. Trellis never sees her password.")
            ana = idp.password("ana")
            c = claims(ana)
            echo(
                f"   Her token: iss {c['iss']}, aud {c['aud']}, email {c['email']}, sub {c['sub']}"
            )

            step(2, "report-bot signs in as itself, with client credentials.")
            bot = idp.client("report-bot")
            c = claims(bot)
            echo(f"   Its token: azp {c['azp']}, sub {c['sub']}, no person in it")

            step(3, "report-bot trades both at Trellis's token endpoint (RFC 8693):")
            echo(f"$ curl -s {base}/token \\")
            echo(f"    -d grant_type={TOKEN_EXCHANGE} \\")
            echo("    -d subject_token=$ANA_TOKEN -d actor_token=$BOT_TOKEN \\")
            echo("    -d scope=finance -d task='Q3 close'")
            status, out = http(
                "POST",
                f"{base}/token",
                form={
                    "grant_type": TOKEN_EXCHANGE,
                    "subject_token": ana,
                    "actor_token": bot,
                    "scope": "finance",
                    "task": "Q3 close",
                },
            )
            if status != 200:
                raise click.ClickException(f"the exchange was refused: {out}")
            grant_token, grant_id = str(out["access_token"]), str(out["grant_id"])
            show_json({**out, "access_token": short(grant_token)})
            echo(
                "   Trellis checked Ana's token against her IdP's keys, found her in the"
                " directory, and found report-bot's client in the agent registry."
            )

            def evaluate(resource: str, columns: list[str] | None = None) -> dict[str, Any]:
                req: dict[str, Any] = {
                    "subject": {"type": "agent", "id": "report-bot"},
                    "action": {"name": "read"},
                    "resource": {"type": "table", "id": resource},
                }
                if columns:
                    req["resource"]["properties"] = {"columns": columns}
                echo(f"$ curl -s {base}/access/v1/evaluation -H 'Authorization: Bearer $GRANT' \\")
                echo(f"    -d '{json.dumps(req)}'")
                _, out = http("POST", f"{base}/access/v1/evaluation", body=req, bearer=grant_token)
                ctx = out["context"]["trellis"]
                d = t.ledger.get(ctx["event_id"])
                if d is not None:
                    from trellisd.trace import recorded_decision

                    decisions.append(recorded_decision(d))
                shown = {
                    "decision": out["decision"],
                    "context": {
                        "reason_admin": out["context"]["reason_admin"],
                        "trellis": {
                            k: ctx[k]
                            for k in ("obligations", "denied_by", "event_id")
                            if ctx.get(k)
                        },
                    },
                }
                show_json(shown)
                return out

            step(4, "report-bot asks the AuthZEN endpoint about the journal:")
            allowed = evaluate("finance.gl.journal_entries")

            step(5, "And about payroll, which is outside the task:")
            evaluate("hr.payroll")

            step(6, "What Trellis refuses at the token endpoint:")
            rogue = idp.client("rogue-bot")
            downstream = t.exchange(grant_token, "ledger-mcp", ())
            forged = _forged(idp.issuer, claims(ana))
            cases = [
                ("rogue-bot, a client no agent in the registry lists", ana, rogue),
                ("Ana's token for another service (aud ledger-mcp)", downstream, bot),
                ("a token signed with a key her IdP never published", forged, bot),
            ]
            if idp.fake is not None:
                expired = idp.fake.mint({**claims(ana), "exp": 1_700_000_000, "iat": 1_699_999_000})
                cases.append(("Ana's token after it expired", expired, bot))
            rows = [["WHO", "TRELLIS SAYS"]]
            for label, subject, actor in cases:
                status, out = http(
                    "POST",
                    f"{base}/token",
                    form={
                        "grant_type": TOKEN_EXCHANGE,
                        "subject_token": subject,
                        "actor_token": actor,
                        "scope": "finance",
                        "task": "Q3 close",
                    },
                )
                rows.append([label, f"{status} {out.get('error_description', out)}"])
            _table(rows, indent=3, center=False)
            dim("   Each refusal is in the ledger as grant.refused, with the IdP that was asked.")

            step(7, "For a server that takes Ana's own token, Trellis exchanges it (obo mode):")
            c = claims(downstream)
            echo(
                f"   A token for {c['aud']}: sub {c['sub']} (still Ana), azp {c['azp']};"
                " the ledger records the exchange, never the token."
            )

            step(8, "Ana revokes the grant, and the same call is denied at once:")
            echo(f"$ trellisd grant revoke {grant_id}")
            t.revoke(grant_id, by="ana@example.com")
            evaluate("finance.gl.journal_entries")

            step(9, "Who allowed the first call, and who vouched for each of them?")
            event_id = allowed["context"]["trellis"]["event_id"]
            echo(f"$ trellisd trace {event_id}")
            echo("")
            print_trace(trace(t.ledger, event_id))

            result = t.ledger.verify()
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
    return decisions


def _forged(issuer: str, body: dict[str, Any]) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return jwt.encode({**body, "iss": issuer}, key, algorithm="RS256", headers={"kid": "forged"})
