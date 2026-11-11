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


@pytest.fixture
def trellis() -> Iterator[Trellis]:
    t = Trellis(load_config(THREE_KEYS), Database(":memory:"))
    yield t
    t.close()


def reset_postgres(url: str) -> None:
    with Database(url) as db:
        db.execute_script(
            "DROP TABLE IF EXISTS trellis_ledger; DROP TABLE IF EXISTS trellis_grants;"
        )


@pytest.fixture
def postgres_url() -> str:
    url = os.environ.get("TRELLISD_TEST_POSTGRES")
    if not url:
        pytest.skip("set TRELLISD_TEST_POSTGRES to run the Postgres tests")
    reset_postgres(url)
    return url
