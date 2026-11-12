"""M6: the quickstart's scripted agent, against everything started in process.

docker compose runs the same agent against Postgres, Iceberg and Keycloak (the CI job
``quickstart``); here the IdP and the catalog are the in-process fakes, so the story runs
anywhere.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import ExitStack
from pathlib import Path

import pytest
from click.testing import CliRunner

from reef.cli import main
from reef.config import load_reef_config
from reef.gateway import Reef
from reef.quickstart import jwks_verifier, run_agent, seed
from reef.samples import hr_server, ledger_server
from reef.server import ReefServer
from reef.stack import IDP_USERS, secret_verifier
from trellisd.app import Trellis
from trellisd.config import load_config
from trellisd.db import Database
from trellisd.demo_idp import DEMO_SECRETS
from trellisd.fake_iceberg import FakeIcebergCatalog
from trellisd.fake_idp import FakeIdP
from trellisd.identity import Identities
from trellisd.ledger import Ledger
from trellisd.server import TrellisServer

QUICKSTART = Path(__file__).resolve().parents[2] / "quickstart"
HR_SECRET = "hr-test-credential"


@pytest.fixture
def services(tmp_path: Path) -> Iterator[dict[str, str]]:
    db = os.environ.get("TRELLISD_TEST_POSTGRES")
    if db:
        conn = Database(db)
        conn.execute_script("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        conn.close()
    else:
        db = f"sqlite:///{tmp_path}/ledger.db"
    with ExitStack() as stack:
        idp = stack.enter_context(
            FakeIdP(users={"ana": IDP_USERS["ana"]}, clients=DEMO_SECRETS, ttl=900)
        )
        catalog = stack.enter_context(FakeIcebergCatalog())
        seed(catalog.uri)
        cfg = load_config(QUICKSTART / "trellis")
        cfg = cfg.model_copy(
            update={
                "idps": {"local": cfg.idps["local"].model_copy(update={"issuer": idp.issuer})},
                "catalogs": {
                    "lakehouse": cfg.catalogs["lakehouse"].model_copy(update={"uri": catalog.uri})
                },
            }
        )
        ids = Identities.from_config(cfg, environ={"TRELLIS_IDP_SECRET": DEMO_SECRETS["trellis"]})
        trellis = stack.enter_context(Trellis(cfg, db, identities=ids))
        ledger = stack.enter_context(ledger_server(jwks_verifier(idp.issuer, "ledger-mcp")))
        hr = stack.enter_context(hr_server(secret_verifier(HR_SECRET, "reef")))
        rc = load_reef_config(QUICKSTART / "reef.yaml")
        urls = {"ledger": ledger.url, "hr": hr.url}
        rc = rc.model_copy(
            update={
                "servers": {n: s.model_copy(update={"url": urls[n]}) for n, s in rc.servers.items()}
            }
        )
        reef = Reef(trellis, rc, environ={"REEF_HR_TOKEN": HR_SECRET})
        side = TrellisServer(trellis)
        side._lock = reef._lock
        stack.enter_context(side)
        server = stack.enter_context(ReefServer(reef))
        yield {
            "keycloak": idp.issuer,
            "trellis": side.uri,
            "reef": server.url,
            "db": db,
            "catalog": catalog.uri,
        }
        assert {c.caller for c in ledger.calls} <= {"ana@example.com"}  # obo: Ana's own token
        assert hr.calls == []  # the deny forwarded nothing


def agent_args(services: dict[str, str]) -> dict[str, str]:
    return {k: v for k, v in services.items() if k != "catalog"}


def test_the_agent_tells_the_whole_story(
    services: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_agent(**agent_args(services))
    out = capsys.readouterr().out
    assert "only its grant's tool is listed" in out
    assert '"approver_email": "***"' in out
    assert "lena@example.com" not in out
    assert "approver_email is pii because catalog lakehouse says so" in out
    assert "exchanged for ledger-mcp (obo mode)" in out
    assert "✗ the task scope" in out
    assert "nothing was forwarded to hr" in out
    assert "chain verified" in out
    assert "Every check held." in out
    assert "✗ " not in out.replace("✗ the task scope", "")


def test_the_cli_exits_non_zero_when_the_story_breaks(services: dict[str, str]) -> None:
    # The steward never tagged approver_email: the read comes back unmasked, and the agent
    # (and so CI) fails rather than call that a pass.
    from trellisd.iceberg import IcebergRestAdmin

    IcebergRestAdmin(services["catalog"]).remove_properties(
        "finance.gl.journal_entries", ["trellis.column.approver_email.tags"]
    )
    args = ["quickstart", "agent"]
    for k, v in agent_args(services).items():
        args += [f"--{k}", v]
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 1, result.output
    assert "✗ approver_email is masked" in result.output
    assert "checks failed" in result.output


def test_seed_tags_the_column_in_the_catalog() -> None:
    from trellisd.config import CatalogSource
    from trellisd.iceberg import IcebergRestTagSource

    with FakeIcebergCatalog() as catalog:
        seed(catalog.uri)
        seed(catalog.uri)  # again: it starts over
        source = IcebergRestTagSource(
            "lakehouse", CatalogSource(type="iceberg-rest", uri=catalog.uri)
        )
        info = source.tags("finance.gl.journal_entries")
        assert info is not None
        assert "pii" in info.columns["approver_email"]
        assert "finance" in info.tags


def test_it_runs_twice_on_one_ledger(services: dict[str, str]) -> None:
    assert run_agent(**agent_args(services))
    assert run_agent(**agent_args(services))
    assert Ledger(Database(services["db"])).verify().ok
