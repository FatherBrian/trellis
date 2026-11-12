from __future__ import annotations

import pytest

from trellisd.db import Database
from trellisd.ledger import GENESIS_HASH, Ledger, LedgerUnavailable


def _ledger(n: int = 3) -> Ledger:
    led = Ledger(Database(":memory:"))
    for i in range(n):
        led.append("decision", agent="bot", subject="ana", grant_id="g-1", body={"i": i})
    return led


def test_chain_links_and_verifies() -> None:
    led = _ledger()
    events = led.query()
    assert events[0].prev_hash == GENESIS_HASH
    assert [e.prev_hash for e in events[1:]] == [e.hash for e in events[:-1]]
    assert led.verify().ok
    assert led.head() == events[-1]
    assert led.get(events[1].event_id) == events[1]
    assert led.by_hash(events[1].hash) == events[1]
    assert len(led) == 3


def test_edit_is_detected() -> None:
    led = _ledger()
    led.db.execute(
        "UPDATE trellis_ledger SET payload = replace(payload, '\"i\":1', '\"i\":9') WHERE seq = 2"
    )
    v = led.verify()
    assert not v.ok
    assert v.broken_at == 2
    assert "changed after it was written" in (v.problem or "")


def test_deletion_is_detected() -> None:
    led = _ledger()
    led.db.execute("DELETE FROM trellis_ledger WHERE seq = 2")
    v = led.verify()
    assert v.broken_at == 2
    assert "missing" in (v.problem or "")


def test_index_columns_must_match_payload() -> None:
    led = _ledger()
    led.db.execute("UPDATE trellis_ledger SET agent = 'other' WHERE seq = 1")
    assert "disagree" in (led.verify().problem or "")


def test_write_failure_raises_unavailable() -> None:
    led = _ledger(1)
    led.db.close()
    with pytest.raises(LedgerUnavailable):
        led.append("decision", body={})
