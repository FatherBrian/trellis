"""The Trellis facade: config, grants, the engine and the ledger together.

    trellis = Trellis.open("examples/three-keys", db_url="sqlite:///trellisd.db")
    issued = trellis.issue_grant(person="ana@example.com", agent="report-bot",
                                 task="Q3 close", scope={"finance"})
    decision = trellis.authorize(issued.token, "read", "finance.gl.journal_entries")

``authorize`` writes the decision to the ledger before it returns; if the write fails the
answer is a deny that says so.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from trellisd.catalog import (
    Catalog,
    ConfigCatalog,
    Resolver,
    SourceUnavailable,
    TableInfo,
    TagSource,
    table_snapshot,
)
from trellisd.config import TrellisConfig, load_config
from trellisd.db import DEFAULT_URL, Cursor, Database
from trellisd.engine import CheckResult, Decision, Engine
from trellisd.grants import (
    DEFAULT_TTL,
    Grant,
    GrantError,
    GrantStore,
    IssuedGrant,
    grant_record,
    new_token,
    utcnow,
)
from trellisd.ledger import Ledger, LedgerEvent, LedgerUnavailable, jsonable, snapshot_version
from trellisd.signing import Signer


class Trellis:
    def __init__(
        self,
        config: TrellisConfig,
        db: Database | str = DEFAULT_URL,
        catalog: Catalog | None = None,
        signer: Signer | None = None,
    ) -> None:
        """``signer`` signs grant entries and checkpoints; without one, Trellis makes a
        throwaway key (fine for tests, not for a ledger you'll keep)."""
        self.config = config
        self.db = db if isinstance(db, Database) else Database(db)
        self.signer = signer or Signer.generate()
        self.grants = GrantStore(self.db)
        self.ledger = Ledger(self.db, self.signer)
        self.engine = Engine(config, catalog or Resolver.from_config(config, tag_sources(config)))
        self._drift_seen: set[tuple[str, str, str]] = set()
        #: The version every decision records, so it can be replayed against this config.
        self.config_version = self.ledger.save_snapshot("config", jsonable(config))

    @property
    def catalog(self) -> Catalog:
        return self.engine.catalog

    def tags_changed(self, table: str | None = None) -> None:
        """A catalog's change hook: forget cached tags so a new restriction applies now."""
        evict = getattr(self.engine.catalog, "evict", None)
        if evict is not None:
            evict(table)

    @classmethod
    def open(
        cls, *config_paths: str | Path, db_url: str = DEFAULT_URL, signer: Signer | None = None
    ) -> Trellis:
        return cls(load_config(*config_paths), db_url, signer=signer)

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> Trellis:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- grants ----------------------------------------------------------------------------

    def issue_grant(
        self,
        *,
        person: str,
        agent: str,
        task: str,
        scope: Iterable[str],
        actions: Sequence[str] = ("read", "query"),
        ttl: timedelta = DEFAULT_TTL,
        issued_by: str | None = None,
        now: datetime | None = None,
    ) -> IssuedGrant:
        """A person lets an agent act for them on one task.

        Refused (and recorded as refused) if the scope goes beyond the agent's ceiling or
        beyond what the person can reach themselves: nobody can hand on access they lack.
        """
        issued_by = issued_by or person
        scope = frozenset(scope)
        problems = []
        if issued_by != person:
            problems.append(f"only {person} can grant access on their own behalf")
        problems += self._ceiling_problems(agent, scope, actions)
        for tag in sorted(scope):
            if not self._reaches(person, tag, actions[0] if actions else "read"):
                problems.append(f"{person} can't reach anything tagged {tag}, so can't grant it")
        return self._issue(
            problems,
            kind="personal",
            subject=person,
            agent=agent,
            task=task,
            scope=scope,
            actions=tuple(actions),
            issued_by=issued_by,
            ttl=ttl,
            now=now,
        )

    def start_run(
        self,
        *,
        purpose: str,
        agent: str,
        record: str,
        started_by: str,
        ttl: timedelta = DEFAULT_TTL,
        now: datetime | None = None,
    ) -> IssuedGrant:
        """A trigger starts one run of a process agent under a purpose grant."""
        p = self.config.purposes.get(purpose)
        problems: list[str] = []
        if p is None:
            problems.append(f"there is no purpose called {purpose}")
            scope: frozenset[str] = frozenset()
            actions: tuple[str, ...] = ("read",)
            trigger_type = None
            task = ""
        else:
            scope = frozenset(p.trigger.tags)
            actions = tuple(p.actions)
            trigger_type = p.trigger.type
            task = p.description or purpose
            if agent not in p.agents:
                problems.append(f"{agent} isn't one of the agents purpose {purpose} allows")
            problems += self._ceiling_problems(agent, scope, actions)
        return self._issue(
            problems,
            kind="purpose",
            subject=purpose,
            agent=agent,
            task=task,
            scope=scope,
            actions=actions,
            issued_by=started_by,
            trigger_type=trigger_type,
            trigger_record=record,
            ttl=ttl,
            now=now,
        )

    def revoke(self, grant_id: str, by: str, now: datetime | None = None) -> Grant:
        grant = self.grants.get(grant_id)
        if grant is None:
            raise GrantError(f"no grant {grant_id}")
        if grant.revoked_at is not None:
            return grant
        now = now or utcnow()
        revoked = grant.model_copy(update={"revoked_at": now, "revoked_by": by})

        def store(cur: Cursor, _event: LedgerEvent) -> None:
            self.grants.update(revoked, cur)

        self.ledger.append(
            "grant.revoked",
            agent=grant.agent,
            subject=grant.subject,
            grant_id=grant.id,
            body={"by": by, "receipt": grant.receipt},
            ts=now,
            on_write=store,
        )
        return revoked

    def _ceiling_problems(
        self, agent: str, scope: frozenset[str], actions: Sequence[str]
    ) -> list[str]:
        a = self.config.agents.get(agent)
        if a is None:
            return [f"there is no agent called {agent}"]
        out = []
        over = sorted(scope - self.config.at_or_below(a.ceiling.tags))
        if over:
            out.append(f"{agent}'s ceiling doesn't include {', '.join(over)}")
        never = sorted(scope & self.config.at_or_above(a.ceiling.never))
        if never:
            out.append(f"{agent} may never touch {', '.join(never)}")
        extra = sorted(set(actions) - set(a.ceiling.actions))
        if extra:
            out.append(f"{agent}'s ceiling doesn't allow {', '.join(extra)}")
        return out

    def _reaches(self, person: str, tag: str, action: str) -> bool:
        for name in self.engine.catalog.tables():
            try:
                info = self.engine.catalog.table(name)
            except SourceUnavailable:
                continue  # an unreachable catalog can't show anyone reaches the tag
            if (
                info
                and tag in info.declared_tags
                and self.engine.subject_allows(person, action, name)
            ):
                return True
        return False

    def _issue(
        self, problems: list[str], *, ttl: timedelta, now: datetime | None, **fields: Any
    ) -> IssuedGrant:
        body = {k: (sorted(v) if isinstance(v, frozenset) else v) for k, v in fields.items()}
        if problems:
            self.ledger.append(
                "grant.refused",
                agent=fields["agent"],
                subject=fields["subject"],
                body={**body, "problems": problems},
                ts=now,
            )
            raise GrantError("; ".join(problems))
        grant = self.grants.build(ttl=ttl, now=now, **fields)
        token = new_token()
        holder: dict[str, Grant] = {}

        def store(cur: Cursor, event: LedgerEvent) -> None:
            final = grant.model_copy(update={"receipt": event.hash})
            self.grants.save(final, token, cur)
            holder["grant"] = final

        self.ledger.append(
            "grant.issued",
            agent=grant.agent,
            subject=grant.subject,
            grant_id=grant.id,
            body=grant_record(grant),
            ts=grant.issued_at,
            on_write=store,
        )
        return IssuedGrant(grant=holder["grant"], token=token)

    # -- decisions -------------------------------------------------------------------------

    def authorize(
        self,
        token: str,
        action: str,
        resource: str,
        columns: Sequence[str] | None = None,
        now: datetime | None = None,
    ) -> Decision:
        grant = self.grants.by_token(token)
        if grant is None:
            decision = Decision(
                allowed=False,
                reason="the token doesn't belong to any grant",
                action=action,
                resource=resource,
                columns=tuple(columns or ()),
                denied_by=("grant",),
            )
            return self._record(decision, None, now)
        return self.decide(grant, action, resource, columns, now)

    def decide(
        self,
        grant: Grant,
        action: str,
        resource: str,
        columns: Sequence[str] | None = None,
        now: datetime | None = None,
    ) -> Decision:
        """Decide for a grant you already hold (operators and tests). Recorded like any call."""
        decision, info = self.engine.decide_with_info(grant, action, resource, columns, now)
        if info is not None and info.drift:
            self._report_drift(info, now)
        return self._record(decision, grant, now, info)

    def _report_drift(self, info: TableInfo, now: datetime | None) -> None:
        """Log each drifted column once per contract version, for the contract's owner."""
        for col in sorted(info.drift):
            key = (info.name, col, info.contract_version or "")
            if key in self._drift_seen:
                continue
            sources = sorted(
                {
                    str(s)
                    for srcs in info.provenance.values()
                    for s in srcs
                    if not s.source.startswith("contract ")
                }
            )
            try:
                self.ledger.append(
                    "catalog.drift",
                    body={
                        "table": info.name,
                        "column": col,
                        "contract": info.contract,
                        "contract_version": info.contract_version,
                        "owner": info.owner,
                        "seen_in": sources,
                        "note": "masked until the contract's owner classifies it",
                    },
                    ts=now,
                )
            except LedgerUnavailable:
                return
            self._drift_seen.add(key)

    def _record(
        self,
        decision: Decision,
        grant: Grant | None,
        now: datetime | None,
        info: TableInfo | None = None,
    ) -> Decision:
        body = decision.model_dump(mode="json", exclude={"event_id"})
        body["receipt"] = grant.receipt if grant else None
        body["config_version"] = self.config_version
        table = jsonable(table_snapshot(info)) if info else None

        def store_snapshot(cur: Cursor, _event: LedgerEvent) -> None:
            if table is not None:
                self.ledger.save_snapshot("table", table, cur)

        if table is not None:
            body["catalog_snapshot"] = snapshot_version(table)
        try:
            event = self.ledger.append(
                "decision",
                agent=decision.agent or "",
                subject=decision.subject or "",
                grant_id=decision.grant_id or "",
                body=body,
                ts=now,
                on_write=store_snapshot,
            )
        except LedgerUnavailable as exc:
            return decision.model_copy(
                update={
                    "allowed": False,
                    "reason": f"{exc}; Trellis won't act unrecorded",
                    "denied_by": (*decision.denied_by, "ledger"),
                    "masked": {},
                    "row_filter": None,
                }
            )
        return decision.model_copy(update={"event_id": event.event_id})


def tag_sources(config: TrellisConfig) -> list[TagSource]:
    """The config's ``catalog:`` section, then each configured catalog, in order."""
    from trellisd.iceberg import IcebergRestTagSource

    sources: list[TagSource] = [ConfigCatalog.from_config(config)]
    for name, settings in sorted(config.catalogs.items()):
        sources.append(IcebergRestTagSource(name, settings))
    return sources


__all__ = ["CheckResult", "Decision", "Trellis", "tag_sources"]
