"""The ledger is append-only and tamper-evident."""

from __future__ import annotations

import json
import sqlite3
from datetime import timedelta
from pathlib import Path

from writ import Authorizer, GrantStore, Ledger, Principal, RequestContext

from conftest import JOURNAL, NOW, issue


def _fill(path: Path, authorizer: Authorizer, grants: GrantStore, n: int = 3) -> list[str]:
    principal = Principal.from_grant(issue(grants, {"finance"}).grant)
    ids = []
    with Ledger(path) as ledger:
        for i in range(n):
            ctx = RequestContext(now=NOW + timedelta(minutes=i))
            action = "read" if i % 2 == 0 else "export"
            decision = authorizer.authorize(principal, action, JOURNAL, ctx)
            ids.append(ledger.record(principal, action, JOURNAL, decision, ctx).event_id)
    return ids


def test_events_chain_and_verify(
    tmp_path: Path, authorizer: Authorizer, grants: GrantStore
) -> None:
    db = tmp_path / "ledger.db"
    ids = _fill(db, authorizer, grants)

    with Ledger(db) as ledger:
        events = ledger.query()
        assert [e.event_id for e in events] == ids
        assert events[1].prev_hash == events[0].hash
        assert [e.allowed for e in events] == [True, False, True]
        assert events[0].annotations == {"log": "required"}
        assert ledger.verify().ok
        assert ledger.verify().checked == 3


def test_editing_an_event_breaks_the_chain(
    tmp_path: Path, authorizer: Authorizer, grants: GrantStore
) -> None:
    db = tmp_path / "ledger.db"
    _fill(db, authorizer, grants)

    # Rewrite history: turn the denied export into an allow.
    conn = sqlite3.connect(db)
    payload = json.loads(conn.execute("SELECT payload FROM ledger WHERE seq = 2").fetchone()[0])
    payload["allowed"] = True
    conn.execute("UPDATE ledger SET payload = ? WHERE seq = 2", (json.dumps(payload),))
    conn.commit()
    conn.close()

    with Ledger(db) as ledger:
        result = ledger.verify()
    assert not result.ok
    assert result.broken_at == 2
    assert "modified" in (result.problem or "")


def test_deleting_an_event_breaks_the_chain(
    tmp_path: Path, authorizer: Authorizer, grants: GrantStore
) -> None:
    db = tmp_path / "ledger.db"
    _fill(db, authorizer, grants)

    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM ledger WHERE seq = 2")
    conn.commit()
    conn.close()

    with Ledger(db) as ledger:
        result = ledger.verify()
    assert not result.ok
    assert result.broken_at == 2
    assert "missing" in (result.problem or "")


def test_recomputing_one_hash_is_not_enough(
    tmp_path: Path, authorizer: Authorizer, grants: GrantStore
) -> None:
    """A forger who fixes the edited event's hash still breaks the next link."""
    from writ.ledger import chain_hash

    db = tmp_path / "ledger.db"
    _fill(db, authorizer, grants)

    conn = sqlite3.connect(db)
    prev, raw = conn.execute("SELECT prev_hash, payload FROM ledger WHERE seq = 2").fetchone()
    payload = json.loads(raw)
    payload["reason"] = "nothing to see here"
    conn.execute(
        "UPDATE ledger SET payload = ?, hash = ? WHERE seq = 2",
        (json.dumps(payload), chain_hash(prev, payload)),
    )
    conn.commit()
    conn.close()

    with Ledger(db) as ledger:
        result = ledger.verify()
    assert not result.ok
    assert result.broken_at == 3


def test_trace_query_filters(tmp_path: Path, authorizer: Authorizer, grants: GrantStore) -> None:
    db = tmp_path / "ledger.db"
    _fill(db, authorizer, grants)
    with Ledger(db) as ledger:
        assert len(ledger.query(agent="report-bot", human="alice@example.com")) == 3
        assert ledger.query(human="bob@example.com") == []
        assert len(ledger.query(since=NOW + timedelta(minutes=1))) == 2
