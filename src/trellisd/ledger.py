"""The ledger: an append-only, hash-chained record of grants and decisions.

Every event carries the hash of the one before it, so editing or deleting an event breaks
the chain and ``verify()`` names where. Cutting the tail leaves a valid but shorter chain,
so Trellis also signs **checkpoints** of the head hash: ``verify(checkpoint)`` then names a
missing tail or a rewritten history too.

Event kinds:

* ``grant.issued``, ``grant.refused``, ``grant.revoked``: who allowed what, or tried to.
  These are **signed** (Ed25519). The hash of ``grant.issued`` is the grant's **receipt**.
* ``decision``: one call, with all three checks, the policies that decided each, the
  grant's receipt, the config version and the catalog snapshot it ran against.

Trellis writes a decision's event *before* it answers; if the write fails it raises
``LedgerUnavailable`` and the caller denies. Each append also queues the event in an
**outbox**, drained to a sink (OpenTelemetry) outside the decision path, so a sink outage
never blocks a decision (see ``trellisd.export``).

SQLite and Postgres share this code (``trellisd.db``).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from trellisd.db import Cursor, Database
from trellisd.grants import utcnow
from trellisd.signing import Signer, key_id_for, verify_signature

GENESIS_HASH = "0" * 64
SIGNED_KINDS = frozenset({"grant.issued", "grant.refused", "grant.revoked"})

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
    hash       TEXT NOT NULL,
    key_id     TEXT NOT NULL DEFAULT '',
    sig        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS trellis_ledger_grant ON trellis_ledger (grant_id, seq);
CREATE INDEX IF NOT EXISTS trellis_ledger_agent ON trellis_ledger (agent, subject, ts);
CREATE INDEX IF NOT EXISTS trellis_ledger_hash ON trellis_ledger (hash);
CREATE TABLE IF NOT EXISTS trellis_keys (
    key_id      TEXT PRIMARY KEY,
    public_key  TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS trellis_checkpoints (
    seq         BIGINT NOT NULL,
    hash        TEXT NOT NULL,
    ts          TEXT NOT NULL,
    key_id      TEXT NOT NULL,
    public_key  TEXT NOT NULL,
    sig         TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS trellis_outbox (
    event_id      TEXT PRIMARY KEY,
    seq           BIGINT NOT NULL,
    attempts      INTEGER NOT NULL DEFAULT 0,
    delivered_at  TEXT,
    last_error    TEXT
);
CREATE TABLE IF NOT EXISTS trellis_snapshots (
    version  TEXT PRIMARY KEY,
    kind     TEXT NOT NULL,
    body     TEXT NOT NULL
);
"""


class LedgerUnavailable(Exception):
    """The ledger could not be written. Trellis denies the call rather than act unrecorded."""


class LedgerEvent(BaseModel):
    """One event, as recorded. ``hash`` covers every field except itself and the signature."""

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
    key_id: str = ""
    sig: str = ""

    def payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"hash", "key_id", "sig"})

    def compute_hash(self) -> str:
        return chain_hash(self.prev_hash, self.payload())

    @property
    def allowed(self) -> bool | None:
        value = self.body.get("allowed")
        return bool(value) if value is not None else None


class Checkpoint(BaseModel):
    """A signed statement that the chain's head was ``hash`` at ``seq``. Publish it."""

    model_config = ConfigDict(frozen=True)

    seq: int
    hash: str
    ts: datetime
    key_id: str
    public_key: str
    sig: str = ""

    def message(self) -> str:
        return canonical_json(
            {"seq": self.seq, "hash": self.hash, "ts": self.ts.isoformat(), "key_id": self.key_id}
        )

    def signature_ok(self) -> bool:
        return key_id_for(self.public_key) == self.key_id and verify_signature(
            self.public_key, self.message(), self.sig
        )


def canonical_json(data: dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def jsonable(value: Any) -> Any:
    """Plain JSON data with sets sorted, so the same content always hashes the same."""
    if isinstance(value, BaseModel):
        return jsonable(value.model_dump(mode="python"))
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, (set, frozenset)):
        return sorted(jsonable(v) for v in value)
    if isinstance(value, (list, tuple)):
        return [jsonable(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def chain_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    return hashlib.sha256((prev_hash + canonical_json(payload)).encode("utf-8")).hexdigest()


def snapshot_version(body: dict[str, Any]) -> str:
    return "v-" + hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()[:16]


class VerifyResult(BaseModel):
    ok: bool
    checked: int
    broken_at: int | None = None
    #: The first problem, for one-line reports.
    problem: str | None = None
    #: Every problem found: a broken link, a bad signature, a missing tail.
    problems: list[str] = Field(default_factory=list)
    checkpoint: Checkpoint | None = None


_INDEXED = ("seq", "event_id", "kind", "agent", "subject", "grant_id", "prev_hash")
OnWrite = Callable[[Cursor, LedgerEvent], None]


class Ledger:
    def __init__(self, db: Database, signer: Signer | None = None) -> None:
        self.db = db
        self.signer = signer
        db.execute_script(_SCHEMA)
        if signer is not None:
            self._register_key(signer)

    def _register_key(self, signer: Signer) -> None:
        if not self.db.query("SELECT 1 FROM trellis_keys WHERE key_id = ?", (signer.key_id,)):
            self.db.execute(
                "INSERT INTO trellis_keys (key_id, public_key, created_at) VALUES (?, ?, ?)",
                (signer.key_id, signer.public_key, utcnow().isoformat()),
            )

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
        on_write: OnWrite | None = None,
    ) -> LedgerEvent:
        """Append one event in a transaction that locks the chain, so it can't fork.

        ``on_write(cursor, event)`` runs inside the same transaction (used to store a grant
        together with its receipt). Raises ``LedgerUnavailable`` if the write fails.
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
                update: dict[str, str] = {"hash": event.compute_hash()}
                if kind in SIGNED_KINDS and self.signer is not None:
                    update["key_id"] = self.signer.key_id
                    update["sig"] = self.signer.sign(update["hash"])
                event = event.model_copy(update=update)
                cur.execute(
                    "INSERT INTO trellis_ledger (seq, event_id, ts, kind, agent, subject,"
                    " grant_id, payload, prev_hash, hash, key_id, sig)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                        event.key_id,
                        event.sig,
                    ),
                )
                cur.execute(
                    "INSERT INTO trellis_outbox (event_id, seq, attempts) VALUES (?, ?, 0)",
                    (event.event_id, event.seq),
                )
                if on_write is not None:
                    on_write(cur, event)
        except LedgerUnavailable:
            raise
        except Exception as exc:  # any driver or disk error: deny rather than act unrecorded
            if isinstance(exc, (TypeError, AttributeError, KeyError)):
                raise  # a bug in Trellis, not an unavailable ledger
            raise LedgerUnavailable(f"ledger write failed: {exc}") from exc
        return event

    def save_snapshot(self, kind: str, body: dict[str, Any], cur: Cursor | None = None) -> str:
        """Store a config or catalog snapshot once, keyed by its hash, for replay."""
        version = snapshot_version(body)
        sql_check = "SELECT 1 FROM trellis_snapshots WHERE version = ?"
        sql_insert = "INSERT INTO trellis_snapshots (version, kind, body) VALUES (?, ?, ?)"
        if cur is not None:
            if cur.execute(sql_check, (version,)).fetchone() is None:
                cur.execute(sql_insert, (version, kind, canonical_json(body)))
        elif not self.db.query(sql_check, (version,)):
            self.db.execute(sql_insert, (version, kind, canonical_json(body)))
        return version

    def snapshot(self, version: str) -> dict[str, Any] | None:
        rows = self.db.query("SELECT body FROM trellis_snapshots WHERE version = ?", (version,))
        return json.loads(rows[0][0]) if rows else None

    # -- checkpoints -----------------------------------------------------------------------

    def checkpoint(self, ts: datetime | None = None) -> Checkpoint:
        """Sign the current head. Keep the result somewhere the database's admins can't edit."""
        if self.signer is None:
            raise ValueError("checkpoints need a signing key")
        head = self.head()
        cp = Checkpoint(
            seq=head.seq if head else 0,
            hash=head.hash if head else GENESIS_HASH,
            ts=ts or utcnow(),
            key_id=self.signer.key_id,
            public_key=self.signer.public_key,
        )
        cp = cp.model_copy(update={"sig": self.signer.sign(cp.message())})
        self.db.execute(
            "INSERT INTO trellis_checkpoints (seq, hash, ts, key_id, public_key, sig)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (cp.seq, cp.hash, cp.ts.isoformat(), cp.key_id, cp.public_key, cp.sig),
        )
        return cp

    def checkpoints(self) -> list[Checkpoint]:
        rows = self.db.query(
            "SELECT seq, hash, ts, key_id, public_key, sig FROM trellis_checkpoints ORDER BY seq"
        )
        return [
            Checkpoint(
                seq=int(s), hash=h, ts=datetime.fromisoformat(t), key_id=k, public_key=p, sig=g
            )
            for s, h, t, k, p, g in rows
        ]

    # -- reading ---------------------------------------------------------------------------

    def _events(self, where: str = "", params: tuple[Any, ...] = ()) -> list[LedgerEvent]:
        rows = self.db.query(
            f"SELECT payload, hash, key_id, sig FROM trellis_ledger {where} ORDER BY seq",  # noqa: S608
            params,
        )
        return [
            LedgerEvent.model_validate({**json.loads(p), "hash": h, "key_id": k, "sig": s})
            for p, h, k, s in rows
        ]

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
        before_seq: int | None = None,
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
        if before_seq is not None:
            clauses.append("seq < ?")
            params.append(before_seq)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return self._events(where, tuple(params))

    def __len__(self) -> int:
        return int(self.db.query("SELECT COUNT(*) FROM trellis_ledger")[0][0])

    def head(self) -> LedgerEvent | None:
        found = self._events("WHERE seq = (SELECT MAX(seq) FROM trellis_ledger)")
        return found[0] if found else None

    def public_keys(self) -> dict[str, str]:
        return dict(self.db.query("SELECT key_id, public_key FROM trellis_keys"))

    # -- tamper evidence -------------------------------------------------------------------

    def verify(self, checkpoint: Checkpoint | None = None) -> VerifyResult:
        """Walk the chain and report what doesn't check out.

        Without a checkpoint this finds edits and gaps. With one it also finds a cut tail
        and a history rewritten with fresh hashes.
        """
        problems: list[str] = []
        broken_at: int | None = None
        keys = self.public_keys()
        expected_prev, expected_seq, checked = GENESIS_HASH, 1, 0
        hashes: dict[int, str] = {}
        rows = self.db.query(
            "SELECT seq, event_id, kind, agent, subject, grant_id, payload, prev_hash, hash,"
            " key_id, sig FROM trellis_ledger ORDER BY seq"
        )
        for (
            seq,
            event_id,
            kind,
            agent,
            subject,
            grant_id,
            payload,
            prev_hash,
            stored,
            key_id,
            sig,
        ) in rows:
            seq = int(seq)
            hashes[seq] = stored
            problem: str | None = None
            if seq != expected_seq:
                missing = (
                    f"event {expected_seq} is missing"
                    if seq == expected_seq + 1
                    else f"events {expected_seq} to {seq - 1} are missing"
                )
                problem = missing
            elif prev_hash != expected_prev:
                problem = f"event {seq} doesn't link to the event before it"
            else:
                data = json.loads(payload)
                indexed = (seq, event_id, kind, agent, subject, grant_id, prev_hash)
                if tuple(data.get(k) for k in _INDEXED) != indexed:
                    problem = f"event {seq}'s columns disagree with its payload"
                elif chain_hash(prev_hash, data) != stored:
                    problem = f"event {seq} was changed after it was written"
                elif kind in SIGNED_KINDS and sig:
                    pub = keys.get(key_id)
                    if pub is None or not verify_signature(pub, stored, sig):
                        problem = f"event {seq}'s signature doesn't check out"
            if problem:
                problems.append(problem)
                if broken_at is None:
                    broken_at = min(seq, expected_seq)
            elif broken_at is None:
                checked += 1
            expected_prev, expected_seq = stored, seq + 1
        if checkpoint is not None:
            head_seq = expected_seq - 1
            if not checkpoint.signature_ok():
                problems.append("the checkpoint's signature doesn't check out")
            elif head_seq < checkpoint.seq:
                cut = (
                    f"event {checkpoint.seq} is"
                    if head_seq + 1 == checkpoint.seq
                    else f"events {head_seq + 1} to {checkpoint.seq} are"
                )
                problems.append(
                    f"{cut} missing from the end: the checkpoint signed at "
                    f"{checkpoint.ts:%Y-%m-%d %H:%M:%S} UTC covers {checkpoint.seq} events"
                )
                broken_at = broken_at if broken_at is not None else head_seq + 1
            elif hashes.get(checkpoint.seq) != checkpoint.hash:
                problems.append(
                    f"event {checkpoint.seq} doesn't match the signed checkpoint: "
                    "history was rewritten"
                )
                broken_at = broken_at if broken_at is not None else checkpoint.seq
        return VerifyResult(
            ok=not problems,
            checked=checked,
            broken_at=broken_at,
            problem=problems[0] if problems else None,
            problems=problems,
            checkpoint=checkpoint,
        )
