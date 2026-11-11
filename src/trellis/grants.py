"""Grants: an agent acting for one human, on one task, within a tag scope, until a deadline.

An agent never inherits a person's access. It holds a grant, and its token is bound
to exactly one grant. When the grant expires or is revoked, the token stops working.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field

from trellis.catalog import Tags

DEFAULT_TTL = timedelta(hours=1)
MAX_TTL = timedelta(hours=24)


def utcnow() -> datetime:
    return datetime.now(UTC)


class GrantError(Exception):
    """Raised when a grant cannot be issued or a token does not resolve to a live grant."""


class AgentProfile(BaseModel):
    """The most an agent may ever touch, set by the agent's owner (its ceiling)."""

    model_config = ConfigDict(frozen=True)

    name: str
    owner: str = ""
    ceiling: Tags = frozenset()


class Grant(BaseModel):
    """Binds human principal, agent, task, scope (data tags) and a time limit."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(default_factory=lambda: f"g_{uuid.uuid4().hex}")
    human: str
    agent: str
    task: str
    scope: Tags
    issued_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None

    def is_active(self, now: datetime | None = None) -> bool:
        now = now or utcnow()
        return self.revoked_at is None and self.issued_at <= now < self.expires_at

    def inactive_reason(self, now: datetime | None = None) -> str | None:
        now = now or utcnow()
        if self.revoked_at is not None:
            return f"grant {self.id} was revoked"
        if now >= self.expires_at:
            return f"grant {self.id} expired at {self.expires_at.isoformat()}"
        if now < self.issued_at:
            return f"grant {self.id} is not valid until {self.issued_at.isoformat()}"
        return None


class IssuedGrant(BaseModel):
    """What the issuer hands back. The token is shown once and only its hash is stored."""

    model_config = ConfigDict(frozen=True)

    grant: Grant
    token: str


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class GrantStore:
    """In-memory grant store.

    TODO(week 1): persist grants in the same SQLite/Postgres database as the ledger,
    and record issue and revoke as ledger events.
    TODO(week 1): decide whether tokens are opaque (as here) or signed (JWT) so the
    MCP server can verify them offline. See the open question on MCP's
    enterprise-managed authorization extension.
    """

    def __init__(self, max_ttl: timedelta = MAX_TTL) -> None:
        self._grants: dict[str, Grant] = {}
        self._tokens: dict[str, str] = {}
        self._max_ttl = max_ttl

    def issue(
        self,
        *,
        human: str,
        agent: str,
        task: str,
        scope: set[str] | frozenset[str],
        ttl: timedelta = DEFAULT_TTL,
        now: datetime | None = None,
    ) -> IssuedGrant:
        if not scope:
            raise GrantError("a grant needs at least one tag in its scope")
        if ttl <= timedelta(0):
            raise GrantError("ttl must be positive")
        if ttl > self._max_ttl:
            raise GrantError(f"ttl {ttl} exceeds the maximum of {self._max_ttl}")
        now = now or utcnow()
        grant = Grant(
            human=human,
            agent=agent,
            task=task,
            scope=frozenset(scope),
            issued_at=now,
            expires_at=now + ttl,
        )
        token = f"trellis_{secrets.token_urlsafe(32)}"
        self._grants[grant.id] = grant
        self._tokens[_hash_token(token)] = grant.id
        return IssuedGrant(grant=grant, token=token)

    def get(self, grant_id: str) -> Grant | None:
        return self._grants.get(grant_id)

    def resolve(self, token: str, now: datetime | None = None) -> Grant:
        """Return the live grant for a token, or raise ``GrantError``."""
        grant_id = self._tokens.get(_hash_token(token))
        if grant_id is None:
            raise GrantError("unknown token")
        grant = self._grants[grant_id]
        reason = grant.inactive_reason(now)
        if reason:
            raise GrantError(reason)
        return grant

    def revoke(self, grant_id: str, now: datetime | None = None) -> Grant:
        grant = self._grants.get(grant_id)
        if grant is None:
            raise GrantError(f"unknown grant {grant_id}")
        revoked = grant.model_copy(update={"revoked_at": now or utcnow()})
        self._grants[grant_id] = revoked
        return revoked

    def find(
        self, *, human: str | None = None, agent: str | None = None, active_only: bool = False
    ) -> list[Grant]:
        out = [
            g
            for g in self._grants.values()
            if (human is None or g.human == human) and (agent is None or g.agent == agent)
        ]
        if active_only:
            out = [g for g in out if g.is_active()]
        return sorted(out, key=lambda g: g.issued_at)
