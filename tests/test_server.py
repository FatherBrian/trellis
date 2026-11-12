"""M4: the AuthZEN endpoint and the sign-in token endpoint, over HTTP and in process."""

from __future__ import annotations

import json
import urllib.request
from collections.abc import Iterator
from typing import Any

import pytest
from click.testing import CliRunner

from trellisd import Trellis, load_config
from trellisd.cli import main
from trellisd.db import Database
from trellisd.demo_idp import DEMO_SECRETS, DEMO_USERS, http, run_bring_your_own_idp
from trellisd.fake_idp import FakeIdP
from trellisd.identity import Identities
from trellisd.server import TOKEN_EXCHANGE, TrellisServer, evaluate

from conftest import ANA, EXPORT, INSPECTIONS, JOURNAL, PAYROLL, THREE_KEYS, TREASURY

SECRET_ENV = {"TRELLIS_IDP_SECRET": DEMO_SECRETS["trellis"]}


@pytest.fixture
def stack() -> Iterator[tuple[Trellis, TrellisServer, FakeIdP]]:
    with FakeIdP(users=DEMO_USERS, clients=DEMO_SECRETS) as idp:
        cfg = load_config(THREE_KEYS)
        local = cfg.idps["local"].model_copy(update={"issuer": idp.issuer})
        cfg = cfg.model_copy(update={"idps": {"local": local}})
        ids = Identities.from_config(cfg, environ=SECRET_ENV)
        with Trellis(cfg, Database(":memory:"), identities=ids) as t, TrellisServer(t) as s:
            yield t, s, idp


def grant_token(server: TrellisServer, idp: FakeIdP) -> str:
    status, out = http(
        "POST",
        f"{server.uri}/token",
        form={
            "grant_type": TOKEN_EXCHANGE,
            "subject_token": idp.sign_in("ana", "trellis"),
            "actor_token": idp.client_token("report-bot", "trellis"),
            "scope": "finance hr",
            "task": "Q3 close",
        },
    )
    assert status == 200, out
    assert out["token_type"] == "Bearer"
    return str(out["access_token"])


def request(resource: str, action: str = "read", agent: str = "report-bot", **props: Any) -> dict:  # type: ignore[type-arg]
    body: dict[str, Any] = {
        "subject": {"type": "agent", "id": agent},
        "action": {"name": action},
        "resource": {"type": "table", "id": resource},
    }
    if props:
        body["resource"]["properties"] = props
    return body


def post(
    server: TrellisServer, body: Any, token: str | None, headers: dict[str, str] | None = None
) -> tuple[int, dict, dict]:  # type: ignore[type-arg]
    data = json.dumps(body).encode()
    h = {"Content-Type": "application/json", **(headers or {})}
    if token:
        h["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        f"{server.uri}/access/v1/evaluation", data=data, headers=h, method="POST"
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read()), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read()), dict(exc.headers)


def test_discovery(stack: tuple[Trellis, TrellisServer, FakeIdP]) -> None:
    _, s, _ = stack
    status, doc = http("GET", f"{s.uri}/.well-known/authzen-configuration")
    assert status == 200
    assert doc["policy_decision_point"] == s.uri
    assert doc["access_evaluation_endpoint"] == f"{s.uri}/access/v1/evaluation"


def test_allow_carries_obligations_and_the_ledger_event(
    stack: tuple[Trellis, TrellisServer, FakeIdP],
) -> None:
    t, s, idp = stack
    status, out, _ = post(s, request(JOURNAL), grant_token(s, idp))
    assert status == 200
    assert out["decision"] is True
    ctx = out["context"]["trellis"]
    assert ctx["obligations"] == {
        "mask": {"approver_email": "@mask pii on access.finance-gl"},
        "row_filter": "region = 'emea'",
    }
    assert ctx["on_behalf_of"] == ANA
    assert t.ledger.get(ctx["event_id"]) is not None
    assert out["context"]["id"] == ctx["event_id"]


def test_deny_names_the_check(stack: tuple[Trellis, TrellisServer, FakeIdP]) -> None:
    _, s, idp = stack
    _, out, _ = post(s, request(EXPORT), grant_token(s, idp))
    assert out["decision"] is False
    assert out["context"]["trellis"]["denied_by"] == ["ceiling"]
    assert "export_controlled" in out["context"]["reason_admin"]["en"]
    assert out["context"]["trellis"]["obligations"] == {}


def test_the_token_can_ride_in_the_subject(stack: tuple[Trellis, TrellisServer, FakeIdP]) -> None:
    _, s, idp = stack
    body = request(JOURNAL)
    body["subject"]["properties"] = {"token": grant_token(s, idp)}
    _, out, _ = post(s, body, None)
    assert out["decision"] is True


def test_no_token_and_another_agents_token_deny(
    stack: tuple[Trellis, TrellisServer, FakeIdP],
) -> None:
    _, s, idp = stack
    _, out, _ = post(s, request(JOURNAL), None)
    assert out["decision"] is False
    assert "no grant token" in out["context"]["reason_admin"]["en"]
    _, out, _ = post(s, request(JOURNAL, agent="inspector-bot"), grant_token(s, idp))
    assert out["decision"] is False
    assert "report-bot's, and inspector-bot presented it" in out["context"]["reason_admin"]["en"]


def test_a_revoked_grant_fails_at_once(stack: tuple[Trellis, TrellisServer, FakeIdP]) -> None:
    t, s, idp = stack
    token = grant_token(s, idp)
    assert post(s, request(JOURNAL), token)[1]["decision"] is True
    t.revoke(t.grants.by_token(token).id, by=ANA)  # type: ignore[union-attr]
    _, out, _ = post(s, request(JOURNAL), token)
    assert out["decision"] is False
    assert "revoked" in out["context"]["reason_admin"]["en"]


@pytest.mark.parametrize(
    "body",
    [
        {},
        {
            "subject": {"type": "agent"},
            "action": {"name": "read"},
            "resource": {"type": "t", "id": "x"},
        },
        {"subject": {"type": "agent", "id": "a"}, "resource": {"type": "t", "id": "x"}},
        {
            "subject": {"type": "agent", "id": "a"},
            "action": {"name": "read"},
            "resource": {"id": "x"},
        },
        {
            "subject": {"type": "agent", "id": "a"},
            "action": {"name": "read"},
            "resource": {"type": "t", "id": "x", "properties": {"columns": "a"}},
        },
        [1, 2],
    ],
)
def test_malformed_requests_are_400(
    stack: tuple[Trellis, TrellisServer, FakeIdP], body: Any
) -> None:
    _, s, _ = stack
    status, out, _ = post(s, body, None)
    assert status == 400
    assert out["error"] == "bad_request"


def test_request_id_is_echoed(stack: tuple[Trellis, TrellisServer, FakeIdP]) -> None:
    _, s, _ = stack
    _, _, headers = post(s, request(JOURNAL), None, {"X-Request-ID": "req-42"})
    assert headers.get("X-Request-ID") == "req-42"


# The request shapes in the AuthZEN 1.0 spec's own examples: a user, an account, can_read.
SPEC_EXAMPLES = [
    {
        "subject": {"type": "user", "id": "alice@acmecorp.com"},
        "resource": {"type": "account", "id": "123"},
        "action": {"name": "can_read", "properties": {"method": "GET"}},
        "context": {"time": "1985-10-26T01:22-07:00"},
    },
    {
        "subject": {
            "type": "user",
            "id": "alice@acmecorp.com",
            "properties": {"department": "Sales"},
        },
        "resource": {"type": "book", "id": "123", "properties": {"library_record": {"title": "x"}}},
        "action": {"name": "can_read"},
    },
]


@pytest.mark.parametrize("body", SPEC_EXAMPLES)
def test_authzen_spec_examples_get_a_well_formed_answer(
    stack: tuple[Trellis, TrellisServer, FakeIdP],
    body: dict,  # type: ignore[type-arg]
) -> None:
    _, s, _ = stack
    status, out, _ = post(s, body, None)
    assert status == 200
    assert isinstance(out["decision"], bool)
    assert out["decision"] is False  # no grant token: Trellis denies
    assert isinstance(out["context"]["reason_admin"]["en"], str)


MATRIX = [
    ("read", JOURNAL, None),
    ("read", JOURNAL, ["entry_id", "approver_email"]),
    ("query", JOURNAL, None),
    ("export", JOURNAL, None),
    ("read", EXPORT, None),
    ("read", PAYROLL, None),
    ("read", TREASURY, None),
    ("read", INSPECTIONS, None),
    ("read", "no.such.table", None),
]


def test_embedded_and_http_decide_identically(
    stack: tuple[Trellis, TrellisServer, FakeIdP],
) -> None:
    t, s, idp = stack
    token = grant_token(s, idp)

    def strip(out: dict) -> dict:  # type: ignore[type-arg]
        ctx = dict(out["context"]["trellis"])
        for k in ("event_id",):
            ctx.pop(k)
        return {"decision": out["decision"], "reason": out["context"]["reason_admin"], **ctx}

    for action, resource, cols in MATRIX:
        body = request(resource, action, **({"columns": cols} if cols else {}))
        _, over_http, _ = post(s, body, token)
        in_process = evaluate(t, body, token)
        direct = t.authorize(token, action, resource, cols)
        assert strip(over_http) == strip(in_process), (action, resource)
        assert over_http["decision"] == direct.allowed
        assert over_http["context"]["trellis"]["denied_by"] == list(direct.denied_by)


@pytest.mark.parametrize(
    ("form", "error"),
    [
        ({"grant_type": "client_credentials"}, "unsupported_grant_type"),
        ({"grant_type": TOKEN_EXCHANGE}, "invalid_request"),
        ({"grant_type": TOKEN_EXCHANGE, "subject_token": "x"}, "invalid_request"),
        ({"grant_type": TOKEN_EXCHANGE, "subject_token": "x", "actor_token": "y"}, "invalid_scope"),
        (
            {
                "grant_type": TOKEN_EXCHANGE,
                "subject_token": "x",
                "actor_token": "y",
                "scope": "finance",
            },
            "invalid_grant",
        ),
    ],
)
def test_token_endpoint_errors(
    stack: tuple[Trellis, TrellisServer, FakeIdP], form: dict[str, str], error: str
) -> None:
    _, s, _ = stack
    status, out = http("POST", f"{s.uri}/token", form=form)
    assert status == 400
    assert out["error"] == error


def test_purpose_run_over_http(stack: tuple[Trellis, TrellisServer, FakeIdP]) -> None:
    _, s, idp = stack
    status, out = http(
        "POST",
        f"{s.uri}/token",
        form={
            "grant_type": TOKEN_EXCHANGE,
            "subject_token": idp.client_token("inspector-bot", "trellis"),
            "purpose": "inspection-review",
            "trigger_record": "INS-1042",
        },
    )
    assert status == 200, out
    body = request(INSPECTIONS, agent="inspector-bot")
    _, ev, _ = post(s, body, str(out["access_token"]))
    assert ev["decision"] is True
    assert ev["context"]["trellis"]["obligations"]["row_filter"] == "inspection_id = 'INS-1042'"


def test_the_demo_runs(tmp_path) -> None:  # type: ignore[no-untyped-def]
    decisions = run_bring_your_own_idp(load_config(THREE_KEYS), f"sqlite:///{tmp_path}/d.db")
    assert [d.allowed for d in decisions] == [True, False, False]
    assert decisions[0].masked and decisions[0].row_filter
    assert decisions[1].denied_by == ("task",)
    assert "revoked" in decisions[2].reason


def test_demo_command() -> None:
    result = CliRunner().invoke(main, ["demo", "bring-your-own-idp"], catch_exceptions=False)
    assert result.exit_code == 0, result.output
    out = result.output
    assert "which no agent in the registry lists" in out
    assert "has expired" in out
    assert "ana@example.com signed in through local" in out
    assert "report-bot signed in through local" in out
    assert "chain verified" in out
