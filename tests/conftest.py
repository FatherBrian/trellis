from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from trellis import Authorizer, GrantStore, IssuedGrant, Ledger, YamlCatalog, load_policies

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
ALICE = "alice@example.com"
BOB = "bob@example.com"
JOURNAL = "finance.gl.journal_entries"


@pytest.fixture
def grants() -> GrantStore:
    return GrantStore()


@pytest.fixture
def authorizer(grants: GrantStore) -> Authorizer:
    return Authorizer(
        catalog=YamlCatalog.from_file(EXAMPLES / "catalog.yaml"),
        policies=load_policies(EXAMPLES / "policies.yaml"),
        grants=grants,
    )


@pytest.fixture
def ledger() -> Ledger:
    return Ledger(":memory:")


def issue(
    grants: GrantStore, scope: set[str], human: str = ALICE, ttl_minutes: int = 60
) -> IssuedGrant:
    return grants.issue(
        human=human,
        agent="report-bot",
        task="month-end variance report",
        scope=scope,
        ttl=timedelta(minutes=ttl_minutes),
        now=NOW,
    )
