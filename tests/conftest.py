from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from trellisd import Trellis, load_config
from trellisd.db import Database

ROOT = Path(__file__).resolve().parent.parent
THREE_KEYS = ROOT / "examples" / "three-keys"
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
ANA = "ana@example.com"
JOURNAL = "finance.gl.journal_entries"
EXPORT = "finance.gl.export_ledger"
PAYROLL = "hr.payroll"
TREASURY = "finance.treasury.cash_positions"
INSPECTIONS = "quality.inspections"


@pytest.fixture(autouse=True)
def _signing_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the CLI's default signing key out of the working folder."""
    monkeypatch.setenv("TRELLISD_KEY", str(tmp_path / "signing.key"))


@pytest.fixture(params=["sqlite", pytest.param("postgres", marks=pytest.mark.postgres)])
def db_url(request: pytest.FixtureRequest) -> str:
    """One shared suite: every test that takes this runs on SQLite and on Postgres."""
    if request.param == "sqlite":
        return ":memory:"
    url = os.environ.get("TRELLISD_TEST_POSTGRES")
    if not url:
        pytest.skip("set TRELLISD_TEST_POSTGRES to run the Postgres tests")
    reset_postgres(url)
    return url


@pytest.fixture
def trellis(db_url: str) -> Iterator[Trellis]:
    t = Trellis(load_config(THREE_KEYS), Database(db_url))
    yield t
    t.close()


TABLES = (
    "trellis_ledger",
    "trellis_grants",
    "trellis_keys",
    "trellis_checkpoints",
    "trellis_outbox",
    "trellis_snapshots",
)


def reset_postgres(url: str) -> None:
    with Database(url) as db:
        db.execute_script("".join(f"DROP TABLE IF EXISTS {t};" for t in TABLES))


@pytest.fixture
def postgres_url() -> str:
    url = os.environ.get("TRELLISD_TEST_POSTGRES")
    if not url:
        pytest.skip("set TRELLISD_TEST_POSTGRES to run the Postgres tests")
    reset_postgres(url)
    return url
