"""The access ledger: an append-only, hash-chained record of every decision.

Each event carries the hash of the previous one, so editing or deleting any event
breaks the chain and ``verify()`` reports where.

v0.1 records every decision, allowed or denied. Annotations such as ``log: required``
travel with the event so downstream systems can act on them.

TODO(week 2): Postgres backend behind the same interface.
TODO(week 2): emit an OpenTelemetry span per event.
TODO(week 2): Parquet export for analysis in the lakehouse.
TODO(week 2): periodic checkpoints (signed head hash) so truncating the tail is detectable.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from moat.decision import Decision, Principal, RequestContext
from moat.grants import utcnow

GENESIS_HASH = "0" * 64

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ledger (
    seq        INTEGER PRIMARY KEY,
    event_id   TEXT NOT NULL UNIQUE,
    ts         TEXT NOT NULL,
    agent      TEXT NOT NULL,
    human      TEXT NOT NULL,
    payload    TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ledger_agent_human_ts ON ledger (agent, human, ts);
"""


class LedgerEvent(BaseModel):
    """One decision, as recorded. ``hash`` covers every other field."""

    model_config = ConfigDict(frozen=True)

    seq: int
    event_id: str
    ts: datetime
    agent: str
    human: str
    grant_id: str
    action: str
    resource: str
    allowed: bool
    reason: str
    masks: tuple[str, ...] = ()
    row_filter: str | None = None
    annotations: dict[str, str] = Field(default_factory=dict)
    policy_ids: tuple[str, ...] = ()
    columns: tuple[str, ...] | None = None
    prev_hash: str
    hash: str = ""

    def payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"hash"})

    def compute_hash(self) -> str:
        return chain_hash(self.prev_hash, self.payload())


def canonical_json(data: dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def chain_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    return hashlib.sha256((prev_hash + canonical_json(payload)).encode("utf-8")).hexdigest()


class VerifyResult(BaseModel):
    ok: bool
    checked: int
    broken_at: int | None = None
    problem: str | None = None


class Ledger:
    """SQLite-backed ledger. Pass ``":memory:"`` for tests."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self._conn = sqlite3.connect(str(path))
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Ledger:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- writing ---------------------------------------------------------------------------

    def record(
        self,
        principal: Principal,
        action: str,
        resource: str,
        decision: Decision,
        context: RequestContext | None = None,
    ) -> LedgerEvent:
        """Append one decision. Runs in a transaction so the chain cannot fork."""
        ctx = context or RequestContext()
        with self._conn:
            self._conn.execute("BEGIN IMMEDIATE")
            row = self._conn.execute(
                "SELECT seq, hash FROM ledger ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            seq, prev_hash = (row[0] + 1, row[1]) if row else (1, GENESIS_HASH)
            event = LedgerEvent(
                seq=seq,
                event_id=f"ev_{uuid.uuid4().hex}",
                ts=ctx.now or utcnow(),
                agent=principal.agent,
                human=principal.human,
                grant_id=principal.grant_id,
                action=action,
                resource=resource,
                allowed=decision.allowed,
                reason=decision.reason,
                masks=decision.masks,
                row_filter=decision.row_filter,
                annotations=decision.annotations,
                policy_ids=decision.policy_ids,
                columns=ctx.columns,
                prev_hash=prev_hash,
            )
            event = event.model_copy(update={"hash": event.compute_hash()})
            self._conn.execute(
                "INSERT INTO ledger (seq, event_id, ts, agent, human, payload, prev_hash, hash)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event.seq,
                    event.event_id,
                    event.ts.isoformat(),
                    event.agent,
                    event.human,
                    canonical_json(event.payload()),
                    event.prev_hash,
                    event.hash,
                ),
            )
        return event

    # -- reading ---------------------------------------------------------------------------

    def _rows(self, sql: str, params: tuple[Any, ...] = ()) -> Iterator[LedgerEvent]:
        for payload, hash_ in self._conn.execute(sql, params):
            yield LedgerEvent.model_validate({**json.loads(payload), "hash": hash_})

    def get(self, event_id: str) -> LedgerEvent | None:
        return next(
            self._rows("SELECT payload, hash FROM ledger WHERE event_id = ?", (event_id,)), None
        )

    def query(
        self,
        *,
        agent: str | None = None,
        human: str | None = None,
        since: datetime | None = None,
    ) -> list[LedgerEvent]:
        clauses, params = [], []
        if agent:
            clauses.append("agent = ?")
            params.append(agent)
        if human:
            clauses.append("human = ?")
            params.append(human)
        if since:
            clauses.append("ts >= ?")
            params.append(since.isoformat())
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT payload, hash FROM ledger {where} ORDER BY seq"  # noqa: S608 - fixed clauses
        return list(self._rows(sql, tuple(params)))

    def __len__(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM ledger").fetchone()[0])

    # -- tamper evidence -------------------------------------------------------------------

    def verify(self) -> VerifyResult:
        """Walk the chain from the start and report the first event that does not check out."""
        expected_prev, expected_seq, checked = GENESIS_HASH, 1, 0
        cur = self._conn.execute(
            "SELECT seq, event_id, agent, human, payload, prev_hash, hash FROM ledger ORDER BY seq"
        )
        for seq, event_id, agent, human, payload, prev_hash, stored_hash in cur:
            problem: str | None = None
            if seq != expected_seq:
                problem, seq = f"event {expected_seq} is missing", expected_seq
            elif prev_hash != expected_prev:
                problem = f"event {seq} does not link to the event before it"
            else:
                data = json.loads(payload)
                indexed = (seq, event_id, agent, human, prev_hash)
                if tuple(data.get(k) for k in _INDEXED_FIELDS) != indexed:
                    problem = f"event {seq} columns disagree with its payload"
                elif chain_hash(prev_hash, data) != stored_hash:
                    problem = f"event {seq} was modified after it was written"
            if problem:
                return VerifyResult(ok=False, checked=checked, broken_at=seq, problem=problem)
            expected_prev, expected_seq, checked = stored_hash, seq + 1, checked + 1
        return VerifyResult(ok=True, checked=checked)


_INDEXED_FIELDS = ("seq", "event_id", "agent", "human", "prev_hash")
