"""The ledger: an append-only, hash-chained record of grants and decisions.

Every event carries the hash of the one before it, so editing or deleting any event breaks
the chain, and ``verify()`` names where. Trellis writes a decision's event *before* it
answers; if the write fails, the answer is no (see ``trellisd.app``).

Event kinds:

* ``grant.issued``, ``grant.refused``, ``grant.revoked``: who allowed what, or tried to;
  the hash of ``grant.issued`` is the grant's **receipt**;
* ``decision``: one call, with all three checks, the policies that decided each, and the
  grant (by receipt) the call ran under.

SQLite and Postgres share this code (``trellisd.db``).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from trellisd.db import Database, DatabaseError
from trellisd.grants import utcnow

GENESIS_HASH = "0" * 64

_SCHEMA = """
CREATE TABLE IF NOT EXISTS trellis_ledger (
    seq        BIGINT PRIMARY KEY,
    event_id   TEXT NOT NULL UNIQUE,
    ts         TEXT NOT NULL,
    kind       TEXT NOT NULL,
    agent      TEXT NOT NULL,
    subject    TEXT NOT NULL,
    grant_id   TEXT NOT NULL,
    payload    TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS trellis_ledger_grant ON trellis_ledger (grant_id, seq);
CREATE INDEX IF NOT EXISTS trellis_ledger_agent ON trellis_ledger (agent, subject, ts);
"""


class LedgerUnavailable(Exception):
    """The ledger could not be written. Trellis denies the call rather than act unrecorded."""


class LedgerEvent(BaseModel):
    """One event, as recorded. ``hash`` covers every other field."""

    model_config = ConfigDict(frozen=True)

    seq: int
    event_id: str
    ts: datetime
    kind: str
    agent: str = ""
    #: The person or purpose the agent acted for.
    subject: str = ""
    grant_id: str = ""
    body: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str
    hash: str = ""

    def payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"hash"})

    def compute_hash(self) -> str:
        return chain_hash(self.prev_hash, self.payload())

    @property
    def allowed(self) -> bool | None:
        value = self.body.get("allowed")
        return bool(value) if value is not None else None


def canonical_json(data: dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def chain_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    return hashlib.sha256((prev_hash + canonical_json(payload)).encode("utf-8")).hexdigest()


class VerifyResult(BaseModel):
    ok: bool
    checked: int
    broken_at: int | None = None
    problem: str | None = None


_INDEXED = ("seq", "event_id", "kind", "agent", "subject", "grant_id", "prev_hash")


class Ledger:
    def __init__(self, db: Database) -> None:
        self.db = db
        db.execute_script(_SCHEMA)

    # -- writing ---------------------------------------------------------------------------

    def append(
        self,
        kind: str,
        *,
        agent: str = "",
        subject: str = "",
        grant_id: str = "",
        body: dict[str, Any] | None = None,
        ts: datetime | None = None,
        on_write: Any = None,
    ) -> LedgerEvent:
        """Append one event in a transaction that locks the chain, so it can't fork.

        ``on_write(cursor, event)`` runs inside the same transaction (used to store a grant
        together with its receipt). Raises ``LedgerUnavailable`` if anything fails.
        """
        try:
            with self.db.transaction(lock_table="trellis_ledger") as cur:
                cur.execute("SELECT seq, hash FROM trellis_ledger ORDER BY seq DESC LIMIT 1")
                row = cur.fetchone()
                seq, prev = (int(row[0]) + 1, row[1]) if row else (1, GENESIS_HASH)
                event = LedgerEvent(
                    seq=seq,
                    event_id=f"ev_{uuid.uuid4().hex[:16]}",
                    ts=ts or utcnow(),
                    kind=kind,
                    agent=agent,
                    subject=subject,
                    grant_id=grant_id,
                    body=json.loads(canonical_json(body or {})),
                    prev_hash=prev,
                )
                event = event.model_copy(update={"hash": event.compute_hash()})
                cur.execute(
                    "INSERT INTO trellis_ledger (seq, event_id, ts, kind, agent, subject,"
                    " grant_id, payload, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        event.seq,
                        event.event_id,
                        event.ts.isoformat(),
                        kind,
                        agent,
                        subject,
                        grant_id,
                        canonical_json(event.payload()),
                        event.prev_hash,
                        event.hash,
                    ),
                )
                if on_write is not None:
                    on_write(cur, event)
        except (DatabaseError, OSError) as exc:
            raise LedgerUnavailable(f"ledger write failed: {exc}") from exc
        except Exception as exc:  # the driver's own errors (sqlite3, psycopg)
            if type(exc).__module__.split(".")[0] in ("sqlite3", "psycopg"):
                raise LedgerUnavailable(f"ledger write failed: {exc}") from exc
            raise
        return event

    # -- reading ---------------------------------------------------------------------------

    def _events(self, where: str = "", params: tuple[Any, ...] = ()) -> list[LedgerEvent]:
        rows = self.db.query(
            f"SELECT payload, hash FROM trellis_ledger {where} ORDER BY seq",  # noqa: S608
            params,
        )
        return [LedgerEvent.model_validate({**json.loads(p), "hash": h}) for p, h in rows]

    def get(self, event_id: str) -> LedgerEvent | None:
        found = self._events("WHERE event_id = ?", (event_id,))
        return found[0] if found else None

    def by_hash(self, hash_: str) -> LedgerEvent | None:
        found = self._events("WHERE hash = ?", (hash_,))
        return found[0] if found else None

    def query(
        self,
        *,
        kind: str | None = None,
        agent: str | None = None,
        subject: str | None = None,
        grant_id: str | None = None,
        since: datetime | None = None,
    ) -> list[LedgerEvent]:
        clauses: list[str] = []
        params: list[Any] = []
        for col, val in (
            ("kind", kind),
            ("agent", agent),
            ("subject", subject),
            ("grant_id", grant_id),
        ):
            if val:
                clauses.append(f"{col} = ?")
                params.append(val)
        if since:
            clauses.append("ts >= ?")
            params.append(since.isoformat())
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return self._events(where, tuple(params))

    def __len__(self) -> int:
        return int(self.db.query("SELECT COUNT(*) FROM trellis_ledger")[0][0])

    def head(self) -> LedgerEvent | None:
        rows = self.db.query("SELECT payload, hash FROM trellis_ledger ORDER BY seq DESC LIMIT 1")
        if not rows:
            return None
        return LedgerEvent.model_validate({**json.loads(rows[0][0]), "hash": rows[0][1]})

    # -- tamper evidence -------------------------------------------------------------------

    def verify(self) -> VerifyResult:
        """Walk the chain from the start and report the first event that doesn't check out."""
        expected_prev, expected_seq, checked = GENESIS_HASH, 1, 0
        rows = self.db.query(
            "SELECT seq, event_id, kind, agent, subject, grant_id, payload, prev_hash, hash"
            " FROM trellis_ledger ORDER BY seq"
        )
        for seq, event_id, kind, agent, subject, grant_id, payload, prev_hash, stored in rows:
            seq = int(seq)
            problem: str | None = None
            if seq != expected_seq:
                problem = f"event {expected_seq} is missing"
                seq = expected_seq
            elif prev_hash != expected_prev:
                problem = f"event {seq} doesn't link to the event before it"
            else:
                data = json.loads(payload)
                indexed = (seq, event_id, kind, agent, subject, grant_id, prev_hash)
                if tuple(data.get(k) for k in _INDEXED) != indexed:
                    problem = f"event {seq}'s columns disagree with its payload"
                elif chain_hash(prev_hash, data) != stored:
                    problem = f"event {seq} was changed after it was written"
            if problem:
                return VerifyResult(ok=False, checked=checked, broken_at=seq, problem=problem)
            expected_prev, expected_seq, checked = stored, seq + 1, checked + 1
        return VerifyResult(ok=True, checked=checked)
