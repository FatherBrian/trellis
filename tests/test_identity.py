"""M4: sign-in from any OIDC IdP, the broker's token exchange, and downstream exchange."""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import timedelta

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from trellisd import Trellis, load_config
from trellisd.config import ConfigError, IdentityProvider, TrellisConfig
from trellisd.db import Database
from trellisd.demo_idp import DEMO_SECRETS, DEMO_USERS
from trellisd.fake_idp import FakeIdP
from trellisd.grants import GrantError
from trellisd.identity import Identities, IdentityError, OidcSource

from conftest import ANA, JOURNAL, THREE_KEYS

SECRET_ENV = {"TRELLIS_IDP_SECRET": DEMO_SECRETS["trellis"]}


@pytest.fixture
def idp() -> Iterator[FakeIdP]:
    with FakeIdP(users=DEMO_USERS, clients=DEMO_SECRETS, ttl=900) as fake:
        yield fake


def config_for(idp: FakeIdP, **changes: object) -> TrellisConfig:
    cfg = load_config(THREE_KEYS)
    local = cfg.idps["local"].model_copy(update={"issuer": idp.issuer, **changes})
    return cfg.model_copy(update={"idps": {"local": local}})


def source(idp: FakeIdP, **changes: object) -> OidcSource:
    return OidcSource("local", config_for(idp, **changes).idps["local"], environ=SECRET_ENV)


@pytest.fixture
def trellis(idp: FakeIdP) -> Iterator[Trellis]:
    cfg = config_for(idp)
    with Trellis(
        cfg, Database(":memory:"), identities=Identities.from_config(cfg, environ=SECRET_ENV)
    ) as t:
        yield t


# -- verify ---------------------------------------------------------------------------------


def test_a_person_and_an_agent(idp: FakeIdP) -> None:
    src = source(idp)
    ana = src.verify(idp.sign_in("ana", "trellis"))
    assert (ana.id, ana.kind, ana.idp, ana.subject) == (ANA, "human", "local", "u-ana")
    assert ana.groups == ("finance-analysts",)
    bot = src.verify(idp.client_token("report-bot", "trellis"))
    assert (bot.id, bot.kind) == ("report-bot", "workload")


@pytest.mark.parametrize(
    ("make", "check", "message"),
    [
        (
            lambda i: i.mint({"sub": "u", "aud": "trellis", "exp": 1_700_000_000}),
            "expired",
            "expired",
        ),
        (lambda i: i.sign_in("ana", "elsewhere"), "audience", "is for elsewhere, not for trellis"),
        (
            lambda i: i.mint({"sub": "u", "aud": "trellis", "iss": "https://other.example"}),
            "issuer",
            "wasn't issued by local",
        ),
        (
            lambda i: i.mint({"sub": "u", "aud": "trellis"}, key=_other_key()),
            "signature",
            "doesn't match",
        ),
        (
            lambda i: i.mint({"sub": "u", "aud": "trellis"}, key=_other_key(), kid="nope"),
            "signature",
            "doesn't publish",
        ),
        (
            lambda i: i.mint(
                {"sub": "u", "aud": "trellis"},
                key="a-shared-secret-of-32-bytes-or-more",
                alg="HS256",
            ),
            "signature",
            "signed with HS256",
        ),
        (lambda i: "not-a-jwt", "token", "isn't a signed JWT"),
    ],
)
def test_bad_tokens_are_refused(idp: FakeIdP, make: object, check: str, message: str) -> None:
    with pytest.raises(IdentityError, match=message) as err:
        source(idp).verify(make(idp))  # type: ignore[operator]
    assert err.value.check == check


def test_unsigned_tokens_are_refused(idp: FakeIdP) -> None:
    unsigned = jwt.encode({"iss": idp.issuer, "sub": "u", "aud": "trellis"}, None, algorithm="none")
    with pytest.raises(IdentityError, match="signed with none"):
        source(idp).verify(unsigned)


def test_an_entra_app_token_is_a_workload_even_with_a_name(idp: FakeIdP) -> None:
    token = idp.mint(
        {"sub": "x", "aud": "trellis", "idtyp": "app", "appid": "report-bot", "email": "x@y"}
    )
    p = source(idp, client_claims=("appid",)).verify(token)
    assert (p.kind, p.id) == ("workload", "report-bot")


def test_a_rotated_key_is_picked_up(idp: FakeIdP) -> None:
    src = source(idp)
    src.verify(idp.sign_in("ana", "trellis"))
    idp.key, idp.kid = _other_key(), "rotated"
    src._keys_read_at = -1e9  # as if a minute has passed
    assert src.verify(idp.sign_in("ana", "trellis")).id == ANA


def test_discovery_must_name_the_configured_issuer(idp: FakeIdP) -> None:
    src = source(idp, discovery_url=f"{idp.issuer}/.well-known/openid-configuration")
    src.settings = src.settings.model_copy(update={"issuer": "https://someone-else.example"})
    with pytest.raises(IdentityError, match="discovery document names issuer"):
        src.verify(idp.sign_in("ana", "trellis"))


def test_an_unknown_issuer_is_refused(idp: FakeIdP) -> None:
    ids = Identities.from_config(config_for(idp), environ=SECRET_ENV)
    with (
        FakeIdP(users=DEMO_USERS) as other,
        pytest.raises(IdentityError, match="no IdP Trellis trusts"),
    ):
        ids.verify(other.sign_in("ana", "trellis"))


# -- exchange -------------------------------------------------------------------------------


def test_rfc8693_exchange_keeps_the_person(idp: FakeIdP) -> None:
    out = source(idp).exchange(idp.sign_in("ana", "trellis"), "ledger-mcp", ["read"])
    c = jwt.decode(out, options={"verify_signature": False})
    assert (c["aud"], c["email"], c["azp"]) == ("ledger-mcp", ANA, "trellis")


def test_entra_on_behalf_of(idp: FakeIdP) -> None:
    src = source(idp, exchange="entra-obo")
    out = src.exchange(idp.sign_in("ana", "trellis"), "api://ledger-mcp", [])
    c = jwt.decode(out, options={"verify_signature": False})
    assert (c["aud"], c["email"]) == ("api://ledger-mcp", ANA)


def test_exchange_needs_it_configured(idp: FakeIdP) -> None:
    with pytest.raises(IdentityError, match="isn't set up to exchange"):
        source(idp, exchange="none").exchange("t", "x", [])


def test_the_idp_refusing_an_exchange_is_an_error(idp: FakeIdP) -> None:
    src = OidcSource("local", config_for(idp).idps["local"], environ={})  # no secret
    with pytest.raises(IdentityError, match="refused the exchange"):
        src.exchange(idp.sign_in("ana", "trellis"), "ledger-mcp", [])


# -- sign-in: the broker --------------------------------------------------------------------


def _sign_in(t: Trellis, idp: FakeIdP, person: str = "ana", agent: str = "report-bot"):  # type: ignore[no-untyped-def]
    return t.sign_in(
        subject_token=idp.sign_in(person, "trellis"),
        actor_token=idp.client_token(agent, "trellis"),
        task="Q3 close",
        scope={"finance"},
    )


def test_sign_in_issues_a_grant_that_records_who_vouched(trellis: Trellis, idp: FakeIdP) -> None:
    issued = _sign_in(trellis, idp)
    g = issued.grant
    assert (g.subject, g.agent, g.issued_by) == (ANA, "report-bot", ANA)
    assert g.signed_in["person"]["issuer"] == idp.issuer
    assert g.signed_in["agent"]["id"] == "report-bot"
    event = trellis.ledger.query(kind="grant.issued")[-1]
    assert event.body["signed_in"]["person"]["subject"] == "u-ana"
    assert trellis.authorize(issued.token, "read", JOURNAL).allowed


def test_a_grant_from_sign_in_ends_with_the_persons_token(trellis: Trellis, idp: FakeIdP) -> None:
    g = _sign_in(trellis, idp).grant
    assert g.expires_at - g.issued_at <= timedelta(seconds=901)


@pytest.mark.parametrize(
    ("person", "agent", "message"),
    [
        ("ana", "rogue-bot", "client rogue-bot at local, which no agent in the registry lists"),
        ("ana", None, "is for ana@example.com, a person, not an agent"),
        (None, "report-bot", "is for client report-bot, not a person"),
    ],
)
def test_sign_in_refusals_are_recorded(
    trellis: Trellis, idp: FakeIdP, person: str | None, agent: str | None, message: str
) -> None:
    subject = (
        idp.sign_in(person, "trellis") if person else idp.client_token("report-bot", "trellis")
    )
    actor = idp.client_token(agent, "trellis") if agent else idp.sign_in("ana", "trellis")
    with pytest.raises(GrantError, match=message):
        trellis.sign_in(subject_token=subject, actor_token=actor, task="t", scope={"finance"})
    refused = trellis.ledger.query(kind="grant.refused")[-1]
    assert refused.body["stage"] == "sign-in"
    assert any(message in p for p in refused.body["problems"])


def test_someone_outside_the_directory_is_refused(idp: FakeIdP) -> None:
    idp.users["eve"] = {"email": "eve@example.com", "password": "x"}
    cfg = config_for(idp)
    with (
        Trellis(cfg, Database(":memory:"), identities=Identities.from_config(cfg)) as t,
        pytest.raises(GrantError, match=r"eve@example\.com .* isn't in the directory"),
    ):
        _sign_in(t, idp, person="eve")


def test_an_idp_not_trusted_for_people(idp: FakeIdP) -> None:
    cfg = config_for(idp, people=False)
    with (
        Trellis(cfg, Database(":memory:"), identities=Identities.from_config(cfg)) as t,
        pytest.raises(GrantError, match="isn't trusted to vouch for people"),
    ):
        _sign_in(t, idp)


def test_sign_in_still_needs_the_ceiling_and_the_persons_reach(
    trellis: Trellis, idp: FakeIdP
) -> None:
    with pytest.raises(GrantError, match="may never touch export_controlled"):
        trellis.sign_in(
            subject_token=idp.sign_in("ana", "trellis"),
            actor_token=idp.client_token("report-bot", "trellis"),
            task="t",
            scope={"export_controlled"},
        )


def test_a_process_agent_starts_a_purpose_run_with_client_credentials(
    trellis: Trellis, idp: FakeIdP
) -> None:
    issued = trellis.sign_in_run(
        token=idp.client_token("inspector-bot", "trellis"),
        purpose="inspection-review",
        record="INS-1042",
    )
    assert issued.grant.is_purpose
    assert issued.grant.signed_in["agent"]["id"] == "inspector-bot"
    assert "client inspector-bot at local" in issued.grant.issued_by


def test_downstream_exchange_is_recorded_and_stops_with_the_grant(
    trellis: Trellis, idp: FakeIdP
) -> None:
    issued = _sign_in(trellis, idp)
    out = trellis.exchange(issued.token, "ledger-mcp", ["read"])
    assert jwt.decode(out, options={"verify_signature": False})["email"] == ANA
    ev = trellis.ledger.query(kind="credential.exchanged")[-1]
    assert ev.body["audience"] == "ledger-mcp"
    assert out not in str(ev.body)
    trellis.revoke(issued.grant.id, by=ANA)
    with pytest.raises(GrantError, match="revoked"):
        trellis.exchange(issued.token, "ledger-mcp")


def test_exchange_after_a_restart_asks_for_sign_in_again(idp: FakeIdP, tmp_path) -> None:  # type: ignore[no-untyped-def]
    cfg = config_for(idp)
    url = f"sqlite:///{tmp_path}/t.db"
    ids = Identities.from_config(cfg, environ=SECRET_ENV)
    with Trellis(cfg, url, identities=ids) as t:
        issued = _sign_in(t, idp)
    with Trellis(cfg, url, identities=ids) as t:
        assert t.authorize(issued.token, "read", JOURNAL).allowed
        with pytest.raises(GrantError, match="sign in again"):
            t.exchange(issued.token, "ledger-mcp")


def test_a_grant_issued_without_sign_in_cant_exchange(trellis: Trellis) -> None:
    issued = trellis.issue_grant(person=ANA, agent="report-bot", task="t", scope={"finance"})
    with pytest.raises(GrantError, match="doesn't hold"):
        trellis.exchange(issued.token, "ledger-mcp")


# -- config ---------------------------------------------------------------------------------


def test_identities_must_name_a_configured_idp(tmp_path) -> None:  # type: ignore[no-untyped-def]
    (tmp_path / "a.yaml").write_text(
        "agents:\n  bot:\n    owner: o@x\n    identities: [nowhere:bot]\n"
    )
    with pytest.raises(ConfigError, match="unknown IdP nowhere"):
        load_config(tmp_path)


def test_one_client_cant_be_two_agents(tmp_path) -> None:  # type: ignore[no-untyped-def]
    (tmp_path / "a.yaml").write_text(
        "idps:\n  local: {issuer: 'http://i', audience: trellis}\n"
        "agents:\n  a: {owner: o@x, identities: [local:bot]}\n"
        "  b: {owner: o@x, identities: [local:bot]}\n"
    )
    with pytest.raises(ConfigError, match="signs in as two agents"):
        load_config(tmp_path)


def test_audience_may_be_one_or_many() -> None:
    assert IdentityProvider(issuer="i", audience="a").audience == ("a",)  # type: ignore[arg-type]
    assert IdentityProvider(issuer="i", audience=("a", "b")).audience == ("a", "b")


def _other_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


# -- a live IdP -----------------------------------------------------------------------------

LIVE = os.environ.get("TRELLISD_TEST_KEYCLOAK")


@pytest.mark.skipif(not LIVE, reason="set TRELLISD_TEST_KEYCLOAK to the demo Keycloak realm")
def test_live_keycloak_sign_in_and_exchange() -> None:
    from trellisd.demo_idp import open_idp

    assert LIVE
    with open_idp(LIVE) as live:
        cfg = load_config(THREE_KEYS)
        local = cfg.idps["local"].model_copy(update={"issuer": live.issuer})
        cfg = cfg.model_copy(update={"idps": {"local": local}})
        with Trellis(
            cfg, Database(":memory:"), identities=Identities.from_config(cfg, environ=SECRET_ENV)
        ) as t:
            issued = t.sign_in(
                subject_token=live.password("ana"),
                actor_token=live.client("report-bot"),
                task="live",
                scope={"finance"},
            )
            assert t.authorize(issued.token, "read", JOURNAL).allowed
            out = t.exchange(issued.token, "ledger-mcp")
            c = jwt.decode(out, options={"verify_signature": False})
            assert c["aud"] == "ledger-mcp" and c["email"] == ANA
            with pytest.raises(GrantError, match="no agent in the registry"):
                t.sign_in(
                    subject_token=live.password("ana"),
                    actor_token=live.client("rogue-bot"),
                    task="live",
                    scope={"finance"},
                )
