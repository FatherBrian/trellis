"""Grants: who allowed an agent to act, for which person or purpose, on which task.

An agent never inherits anyone's access. It holds a grant, and its token is bound to
exactly one grant. There are two kinds:

* a **personal grant**: an agent acting for one person on one task, until a deadline;
* a **purpose grant** run: a process agent acting for a purpose (which has a named human
  owner), on the one record that started the run (the trigger).

Grants persist in the same database as the ledger (SQLite or Postgres).
"""

from __future__ import annotations

import hashlib
import json
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from trellisd.config import GrantKind, Tags
from trellisd.db import Cursor, Database

DEFAULT_TTL = timedelta(hours=1)
MAX_TTL = timedelta(hours=24)


def utcnow() -> datetime:
    return datetime.now(UTC)


class GrantError(Exception):
    """Raised when a grant cannot be issued or a token does not resolve to a live grant."""


class Grant(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str = Field(default_factory=lambda: f"g-{uuid.uuid4().hex[:10]}")
    kind: GrantKind = "personal"
    #: The person (personal grant) or the purpose (purpose grant) the agent acts for.
    subject: str
    agent: str
    #: The task, for a personal grant; what the run is for, for a purpose grant.
    task: str = ""
    trigger_type: str | None = None
    trigger_record: str | None = None
    scope: Tags = frozenset()
    actions: tuple[str, ...] = ("read", "query")
    #: Who allowed it: the person, or whoever started a purpose run.
    issued_by: str
    issued_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None
    revoked_by: str | None = None
    #: Hash of the ledger entry that recorded the issue (the grant receipt).
    receipt: str | None = None

    @property
    def is_purpose(self) -> bool:
        return self.kind == "purpose"

    def is_active(self, now: datetime | None = None) -> bool:
        return self.inactive_reason(now) is None

    def inactive_reason(self, now: datetime | None = None) -> str | None:
        now = now or utcnow()
        if self.revoked_at is not None and self.revoked_at <= now:
            by = f" by {self.revoked_by}" if self.revoked_by else ""
            return f"grant {self.id} was revoked{by}"
        if now >= self.expires_at:
            return f"grant {self.id} expired at {self.expires_at:%Y-%m-%d %H:%M} UTC"
        if now < self.issued_at:
            return f"grant {self.id} is not valid until {self.issued_at.isoformat()}"
        return None

    def describe(self) -> str:
        if self.is_purpose:
            return (
                f"{self.agent} for purpose {self.subject}, "
                f"triggered by {self.trigger_type} {self.trigger_record}"
            )
        return f"{self.agent} for {self.subject}: {self.task}"


class IssuedGrant(BaseModel):
    """What the issuer hands back. The token is shown once; only its hash is stored."""

    model_config = ConfigDict(frozen=True)

    grant: Grant
    token: str


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_token() -> str:
    return f"trellis_{secrets.token_urlsafe(32)}"


_SCHEMA = """
CREATE TABLE IF NOT EXISTS trellis_grants (
    id          TEXT PRIMARY KEY,
    body        TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    agent       TEXT NOT NULL,
    subject     TEXT NOT NULL,
    issued_at   TEXT NOT NULL
);
"""


class GrantStore:
    """Grants in the database, so they survive a restart."""

    def __init__(self, db: Database, max_ttl: timedelta = MAX_TTL) -> None:
        self.db = db
        self.max_ttl = max_ttl
        db.execute_script(_SCHEMA)

    def build(
        self,
        *,
        kind: GrantKind,
        subject: str,
        agent: str,
        scope: Tags,
        actions: tuple[str, ...],
        issued_by: str,
        task: str = "",
        trigger_type: str | None = None,
        trigger_record: str | None = None,
        ttl: timedelta = DEFAULT_TTL,
        now: datetime | None = None,
    ) -> Grant:
        """Build a grant without storing it (the caller checks it first)."""
        if not scope:
            raise GrantError("a grant needs at least one tag in its scope")
        if ttl <= timedelta(0):
            raise GrantError("ttl must be positive")
        if ttl > self.max_ttl:
            raise GrantError(f"ttl {ttl} exceeds the maximum of {self.max_ttl}")
        now = now or utcnow()
        return Grant(
            kind=kind,
            subject=subject,
            agent=agent,
            task=task,
            trigger_type=trigger_type,
            trigger_record=trigger_record,
            scope=frozenset(scope),
            actions=tuple(actions),
            issued_by=issued_by,
            issued_at=now,
            expires_at=now + ttl,
        )

    def save(self, grant: Grant, token: str, cur: Cursor | None = None) -> None:
        sql = (
            "INSERT INTO trellis_grants (id, body, token_hash, agent, subject, issued_at)"
            " VALUES (?, ?, ?, ?, ?, ?)"
        )
        params = (
            grant.id,
            grant.model_dump_json(),
            hash_token(token),
            grant.agent,
            grant.subject,
            grant.issued_at.isoformat(),
        )
        if cur is not None:
            cur.execute(sql, params)
        else:
            self.db.execute(sql, params)

    def update(self, grant: Grant, cur: Cursor | None = None) -> None:
        sql = "UPDATE trellis_grants SET body = ? WHERE id = ?"
        if cur is not None:
            cur.execute(sql, (grant.model_dump_json(), grant.id))
        else:
            self.db.execute(sql, (grant.model_dump_json(), grant.id))

    def get(self, grant_id: str) -> Grant | None:
        rows = self.db.query("SELECT body FROM trellis_grants WHERE id = ?", (grant_id,))
        return Grant.model_validate_json(rows[0][0]) if rows else None

    def by_token(self, token: str) -> Grant | None:
        rows = self.db.query(
            "SELECT body FROM trellis_grants WHERE token_hash = ?", (hash_token(token),)
        )
        return Grant.model_validate_json(rows[0][0]) if rows else None

    def resolve(self, token: str, now: datetime | None = None) -> Grant:
        """Return the live grant for a token, or raise ``GrantError``."""
        grant = self.by_token(token)
        if grant is None:
            raise GrantError("unknown token")
        reason = grant.inactive_reason(now)
        if reason:
            raise GrantError(reason)
        return grant

    def find(
        self,
        *,
        subject: str | None = None,
        agent: str | None = None,
        active_only: bool = False,
        now: datetime | None = None,
    ) -> list[Grant]:
        clauses, params = [], []
        if subject:
            clauses.append("subject = ?")
            params.append(subject)
        if agent:
            clauses.append("agent = ?")
            params.append(agent)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self.db.query(
            f"SELECT body FROM trellis_grants{where} ORDER BY issued_at",  # noqa: S608
            params,
        )
        out = [Grant.model_validate_json(r[0]) for r in rows]
        if active_only:
            out = [g for g in out if g.is_active(now)]
        return out


def grant_record(grant: Grant) -> dict[str, Any]:
    """The grant as its receipt records it: every field except the receipt itself."""
    data: dict[str, Any] = json.loads(grant.model_dump_json(exclude={"receipt"}))
    data["scope"] = sorted(grant.scope)
    return data
