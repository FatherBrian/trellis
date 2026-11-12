"""The whole door on one machine, for the demo and the tests.

``open_stack()`` starts a local IdP, Trellis, the two sample MCP servers and Reef in front
of them, and signs two agents in:

* report-bot, for Ana, task "Q3 close", scope finance;
* people-bot, for Ben, task "Headcount review", scope hr.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jwt

from reef.config import ReefConfig, load_reef_config
from reef.gateway import Reef
from reef.samples import SampleServer, hr_server, ledger_server
from reef.server import ReefServer
from trellisd.app import Trellis
from trellisd.config import TrellisConfig, load_config
from trellisd.db import Database
from trellisd.fake_idp import FakeIdP
from trellisd.grants import IssuedGrant
from trellisd.identity import Identities


def examples() -> Path:
    """reef/examples/the-door in a checkout, or the copy shipped inside the wheel."""
    here = Path(__file__).resolve()
    for base in (here.parents[2] / "examples" / "the-door", here.parent / "_examples" / "the-door"):
        if base.exists():
            return base
    raise FileNotFoundError("can't find the-door's example config")


IDP_CLIENTS = {
    "trellis": "trellis-demo-secret",
    "report-bot": "report-bot-demo-secret",
    "people-bot": "people-bot-demo-secret",
}
IDP_USERS: dict[str, dict[str, Any]] = {
    "ana": {"email": "ana@example.com", "password": "ana-demo", "groups": ["finance-analysts"]},
    "ben": {"email": "ben@example.com", "password": "ben-demo", "groups": ["hr-partners"]},
}


@dataclass
class Stack:
    idp: FakeIdP
    trellis: Trellis
    reef: Reef
    server: ReefServer
    ledger: SampleServer
    hr: SampleServer
    hr_secret: str
    report_bot: IssuedGrant
    people_bot: IssuedGrant

    @property
    def url(self) -> str:
        return self.server.url

    def sign_in(self, user: str, agent: str, task: str, scope: list[str]) -> IssuedGrant:
        """A person and an agent sign in at the IdP, and Trellis turns that into a grant."""
        return self.trellis.sign_in(
            subject_token=self.idp.sign_in(user, "trellis"),
            actor_token=self.idp.client_token(agent, "trellis"),
            task=task,
            scope=scope,
        )


def jwt_verifier(idp: FakeIdP, audience: str) -> Any:
    """What an obo- or agent-mode server does: check the IdP's signature and its audience."""

    def verify(token: str) -> str:
        try:
            claims = jwt.decode(
                token, idp.key.public_key(), algorithms=["RS256"], audience=audience
            )
        except jwt.PyJWTError as exc:
            raise PermissionError(str(exc)) from exc
        return str(claims.get("email") or claims.get("sub"))

    return verify


def secret_verifier(secret: str, name: str) -> Any:
    def verify(token: str) -> str:
        if not token or not secrets.compare_digest(token, secret):
            raise PermissionError("wrong service credential")
        return name

    return verify


@contextmanager
def open_stack(
    db: Database | str = "sqlite:///:memory:",
    *,
    config: TrellisConfig | None = None,
    reef_config: ReefConfig | None = None,
) -> Iterator[Stack]:
    base = examples()
    with ExitStack() as stack:
        idp = stack.enter_context(FakeIdP(users=IDP_USERS, clients=IDP_CLIENTS))
        rc = reef_config or load_reef_config(base / "reef.yaml")
        cfg = rc.apply_to(config or load_config(base / "trellis"))
        local = cfg.idps["local"].model_copy(update={"issuer": idp.issuer})
        cfg = cfg.model_copy(update={"idps": {"local": local}})
        identities = Identities.from_config(
            cfg, environ={local.client_secret_env or "": IDP_CLIENTS["trellis"]}
        )
        database = db if isinstance(db, Database) else Database(db)
        trellis = stack.enter_context(Trellis(cfg, database, identities=identities))
        hr_secret = "hr-svc-" + secrets.token_urlsafe(12)
        ledger = stack.enter_context(ledger_server(jwt_verifier(idp, "ledger-mcp")))
        hr = stack.enter_context(hr_server(secret_verifier(hr_secret, "reef (hr service account)")))
        urls = {"ledger": ledger.url, "hr": hr.url}
        rc = rc.model_copy(
            update={
                "servers": {
                    name: spec.model_copy(update={"url": urls.get(name, spec.url)})
                    for name, spec in rc.servers.items()
                }
            }
        )
        reef = Reef(trellis, rc, environ={"REEF_HR_TOKEN": hr_secret})
        server = stack.enter_context(ReefServer(reef))
        s = Stack(idp, trellis, reef, server, ledger, hr, hr_secret, None, None)  # type: ignore[arg-type]
        s.report_bot = s.sign_in("ana", "report-bot", "Q3 close", ["finance"])
        s.people_bot = s.sign_in("ben", "people-bot", "Headcount review", ["hr"])
        yield s
