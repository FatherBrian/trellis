"""The decision engine: three Cedar checks per call, all of which must say yes.

For a personal agent the checks are the person's access, the agent's ceiling and the task
scope. For a process agent they are the purpose's scope, the agent's ceiling and the
trigger scope. Each runs against its own policy set; Trellis asks all three even after a
no, so a deny names every check that refused, not just the first.

Every check also runs per column. A column one of the checks won't allow is masked, and
``@mask`` obligations on the deciding policies mask columns by tag. ``@row_filter``
obligations are ANDed and filled in from the person's attributes or the trigger record; if
a value is missing, the call is denied (fail closed).
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

import cedarpy
from pydantic import BaseModel, ConfigDict, Field

from trellisd.catalog import Catalog, ConfigCatalog, TableInfo
from trellisd.compiler import Compiler, PolicyMeta, PolicySetText
from trellisd.config import ACTIONS, TrellisConfig
from trellisd.grants import Grant

MASK = "***"
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


class CheckResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    #: person | purpose, ceiling, task | trigger
    name: str
    #: Who or what this check speaks for, in words: "ana@example.com's access".
    label: str
    allowed: bool
    #: The Cedar policies that decided it (by @id): the permits behind a yes, or the forbid
    #: behind a no. Empty when nothing permitted the call.
    policies: tuple[str, ...] = ()
    #: The policies in this check's set that applied to this principal at all, so a no
    #: with no deciding policy can still name the policy that didn't cover the call.
    considered: tuple[str, ...] = ()
    reason: str = ""


class Decision(BaseModel):
    """One authorization decision, as the ledger records it."""

    model_config = ConfigDict(frozen=True)

    allowed: bool
    reason: str
    action: str
    resource: str
    columns: tuple[str, ...] = ()
    resource_tags: tuple[str, ...] = ()
    grant_id: str | None = None
    kind: str | None = None
    agent: str | None = None
    subject: str | None = None
    checks: tuple[CheckResult, ...] = ()
    #: Names of the checks that said no (or "catalog" / "obligation").
    denied_by: tuple[str, ...] = ()
    #: column -> why it is masked
    masked: dict[str, str] = Field(default_factory=dict)
    row_filter: str | None = None
    policy_ids: tuple[str, ...] = ()
    #: The ledger event that recorded this decision (set once it is written).
    event_id: str | None = None

    def check(self, name: str) -> CheckResult | None:
        return next((c for c in self.checks if c.name == name), None)

    def apply(self, row: dict[str, Any]) -> dict[str, Any]:
        """Mask one result row as this decision requires."""
        return {k: (MASK if k in self.masked else v) for k, v in row.items()}


class ObligationError(Exception):
    pass


_TEMPLATE = re.compile(r"\{(person|trigger|grant)\.([A-Za-z_][A-Za-z0-9_]*)\}")


def sql_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


class Engine:
    """Compiles a config once and answers decisions against it."""

    def __init__(self, config: TrellisConfig, catalog: Catalog | None = None) -> None:
        self.config = config
        self.catalog = catalog or ConfigCatalog.from_config(config)
        self.compiler = Compiler(config)
        self.subject_set = self.compiler.subject_policies()
        self.ceiling_set = self.compiler.ceiling_policies()
        self._subject_cedar = self.subject_set.cedar()
        self._ceiling_cedar = self.ceiling_set.cedar()
        self._entity_map = {(e["uid"]["type"], e["uid"]["id"]): e for e in self.compiler.entities()}

    # -- public ----------------------------------------------------------------------------

    def decide(
        self,
        grant: Grant,
        action: str,
        resource: str,
        columns: Sequence[str] | None = None,
        now: datetime | None = None,
    ) -> Decision:
        base: dict[str, Any] = {
            "action": action,
            "resource": resource,
            "columns": tuple(columns or ()),
            "grant_id": grant.id,
            "kind": grant.kind,
            "agent": grant.agent,
            "subject": grant.subject,
        }
        if action not in ACTIONS:
            return Decision(
                allowed=False, reason=f"unknown action {action!r}", denied_by=("action",), **base
            )
        info = self.catalog.table(resource)
        if info is None:
            return Decision(
                allowed=False,
                reason=f"{resource} isn't in the catalog, and Trellis denies what it can't"
                " classify",
                denied_by=("catalog",),
                **base,
            )
        base["resource_tags"] = tuple(sorted(info.tags))
        if not info.tags:
            return Decision(
                allowed=False,
                reason=f"{resource} has no tags, and Trellis denies what it can't classify",
                denied_by=("catalog",),
                **base,
            )
        cols = list(columns) if columns else sorted(info.columns)
        checks, per_column, deciding = self._run_checks(grant, action, info, cols, now)
        allowed = all(c.allowed for c in checks)
        policy_ids = tuple(p for c in checks for p in c.policies)
        denied_by = tuple(c.name for c in checks if not c.allowed)
        if not allowed:
            first = next(c for c in checks if not c.allowed)
            more = len(denied_by) - 1
            reason = f"denied by {first.label}: {first.reason}" + (
                f" (and {more} more)" if more else ""
            )
            return Decision(
                allowed=False,
                reason=reason,
                checks=tuple(checks),
                denied_by=denied_by,
                policy_ids=policy_ids,
                **base,
            )

        masked: dict[str, str] = {}
        for col, denials in zip(cols, per_column, strict=True):
            if denials:
                masked[col] = f"{denials[0].label} doesn't allow it"
        for meta in deciding:
            for col in cols:
                hit = meta.mask & info.column_tags(col)
                if hit and col not in masked:
                    masked[col] = f"@mask {','.join(sorted(hit))} on {meta.id}"
        try:
            row_filter = self._row_filter(grant, [m for m in deciding if m.row_filter])
        except ObligationError as exc:
            return Decision(
                allowed=False,
                reason=str(exc),
                checks=tuple(checks),
                denied_by=("obligation",),
                policy_ids=policy_ids,
                **base,
            )
        reason = "allowed: " + "; ".join(f"{c.label} ({', '.join(c.policies)})" for c in checks)
        return Decision(
            allowed=True,
            reason=reason,
            checks=tuple(checks),
            masked=masked,
            row_filter=row_filter,
            policy_ids=policy_ids,
            **base,
        )

    def subject_allows(self, person: str, action: str, table: str) -> bool:
        """Whether the person's own access covers ``action`` on ``table`` (used at issuance)."""
        info = self.catalog.table(table)
        if info is None:
            return False
        probe = Grant(
            subject=person,
            agent="-",
            issued_by=person,
            scope=frozenset({"-"}),
            issued_at=_EPOCH,
            expires_at=_EPOCH,
        )
        entities = self._call_entities(probe, info, [])
        res = cedarpy.is_authorized(
            {
                "principal": f"Person::{_q(person)}",
                "action": f"Action::{_q(action)}",
                "resource": f"Table::{_q(table)}",
                "context": {"agent": "-"},
            },
            self._subject_cedar,
            entities,
        )
        return bool(res.allowed)

    # -- checks ----------------------------------------------------------------------------

    def labels(self, grant: Grant) -> list[tuple[str, str]]:
        if grant.is_purpose:
            return [
                ("purpose", f"purpose {grant.subject}"),
                ("ceiling", f"{grant.agent}'s ceiling"),
                ("trigger", f"the {grant.trigger_type or 'trigger'} {grant.trigger_record} scope"),
            ]
        return [
            ("person", f"{grant.subject}'s access"),
            ("ceiling", f"{grant.agent}'s ceiling"),
            ("task", "the task scope"),
        ]

    def _call_entities(
        self, grant: Grant, info: TableInfo, cols: list[str]
    ) -> list[dict[str, Any]]:
        """The config's entities, with this call's grant, and the table and its columns
        exactly as the catalog classifies them now (the catalog wins over the config)."""

        def ent(
            type_: str,
            id_: str,
            attrs: dict[str, Any] | None = None,
            parents: list[tuple[str, str]] | None = None,
        ) -> dict[str, Any]:
            return {
                "uid": {"type": type_, "id": id_},
                "attrs": attrs or {},
                "parents": [{"type": t, "id": i} for t, i in parents or []],
            }

        prefix = info.name + "."
        out = [
            e
            for k, e in self._entity_map.items()
            if not (k[0] in ("Table", "Column") and (k[1] == info.name or k[1].startswith(prefix)))
        ]
        out.append(ent("Grant", grant.id))
        if not grant.is_purpose and ("Person", grant.subject) not in self._entity_map:
            out.append(ent("Person", grant.subject))
        if ("Agent", grant.agent) not in self._entity_map:
            out.append(ent("Agent", grant.agent))
        parts = info.dataset.split(".")
        for n in range(1, len(parts) + 1):
            ds = ".".join(parts[:n])
            if ("Dataset", ds) not in self._entity_map:
                parent = [("Dataset", ".".join(parts[: n - 1]))] if n > 1 else []
                out.append(ent("Dataset", ds, None, parent))
        out.append(
            ent("Table", info.name, {"tags": sorted(info.tags)}, [("Dataset", info.dataset)])
        )
        for col in dict.fromkeys([*info.columns, *cols]):
            out.append(
                ent(
                    "Column",
                    f"{info.name}.{col}",
                    {"tags": sorted(info.column_tags(col))},
                    [("Table", info.name)],
                )
            )
        return out

    def _run_checks(
        self, grant: Grant, action: str, info: TableInfo, cols: list[str], now: datetime | None
    ) -> tuple[list[CheckResult], list[list[CheckResult]], list[PolicyMeta]]:
        entities = self._call_entities(grant, info, cols)
        resources = [f"Table::{_q(info.name)}"] + [
            f"Column::{_q(f'{info.name}.{c}')}" for c in cols
        ]
        subject_principal = (
            f"Purpose::{_q(grant.subject)}" if grant.is_purpose else f"Person::{_q(grant.subject)}"
        )
        scope_set = self.compiler.scope_policy(grant)
        plan: list[tuple[str, PolicySetText, Any]] = [
            (subject_principal, self.subject_set, self._subject_cedar),
            (f"Agent::{_q(grant.agent)}", self.ceiling_set, self._ceiling_cedar),
            (f"Grant::{_q(grant.id)}", scope_set, scope_set.cedar()),
        ]
        inactive = grant.inactive_reason(now)
        labels = self.labels(grant)
        checks: list[CheckResult] = []
        per_column: list[list[CheckResult]] = [[] for _ in cols]
        deciding: list[PolicyMeta] = []
        for idx, ((principal, ps, cedar_ps), (name, label)) in enumerate(
            zip(plan, labels, strict=True)
        ):
            if idx == 2 and inactive:
                checks.append(
                    CheckResult(
                        name=name,
                        label=label,
                        allowed=False,
                        considered=(f"grant.{grant.id}",),
                        reason=inactive,
                    )
                )
                continue
            requests = [
                {
                    "principal": principal,
                    "action": f"Action::{_q(action)}",
                    "resource": r,
                    "context": {"agent": grant.agent},
                }
                for r in resources
            ]
            results = cedarpy.is_authorized_batch(requests, cedar_ps, entities)
            table_res = results[0]
            metas = [m for m in (ps.lookup(r) for r in table_res.diagnostics.reasons) if m]
            pids = tuple(m.id for m in metas)
            if table_res.allowed:
                deciding += metas
                reason = ""
            else:
                reason = self._why_not(name, grant, action, info, metas)
            checks.append(
                CheckResult(
                    name=name,
                    label=label,
                    allowed=table_res.allowed,
                    policies=pids,
                    considered=self._considered(name, grant, ps),
                    reason=reason,
                )
            )
            for i, res in enumerate(results[1:]):
                if not res.allowed:
                    per_column[i].append(checks[-1])
        return checks, per_column, deciding

    def _considered(self, name: str, grant: Grant, ps: PolicySetText) -> tuple[str, ...]:
        if name == "person":
            groups = set(self.config.groups_of(grant.subject))
            ids = []
            for rule in self.config.access:
                for i, who in enumerate(rule.who):
                    kind, value = who.split(":", 1)
                    if (kind == "group" and value in groups) or (
                        kind == "user" and value == grant.subject
                    ):
                        ids.append(f"access.{rule.id}" + (f".{i}" if len(rule.who) > 1 else ""))
            return tuple(ids)
        if name == "purpose":
            prefix = f"purpose.{grant.subject}"
        elif name == "ceiling":
            prefix = f"ceiling.{grant.agent}"
        else:
            prefix = f"grant.{grant.id}"
        return tuple(m.id for m in ps.meta if m.id == prefix or m.id.startswith(prefix + "."))

    def _why_not(
        self, name: str, grant: Grant, action: str, info: TableInfo, metas: list[PolicyMeta]
    ) -> str:
        tags = ", ".join(sorted(info.tags))
        forbids = [m.id for m in metas if m.effect == "forbid"]
        if name == "person":
            return f"no access rule lets {grant.subject} {action} {info.name} ({tags})"
        if name == "purpose":
            purpose = self.config.purposes.get(grant.subject)
            if purpose is None:
                return f"there is no purpose called {grant.subject}"
            if grant.agent not in purpose.agents:
                return f"{grant.agent} isn't one of the agents purpose {grant.subject} allows"
            return f"purpose {grant.subject} doesn't cover {action} on {info.name} ({tags})"
        if name == "ceiling":
            agent = self.config.agents.get(grant.agent)
            if agent is None:
                return f"{grant.agent} has no ceiling, so it may touch nothing"
            if forbids:
                never = sorted(info.tags & agent.ceiling.never)
                return f"it may never touch {', '.join(never)}"
            if action not in agent.ceiling.actions:
                return f"it doesn't allow {action}"
            missing = sorted(info.tags - agent.ceiling.tags)
            return f"it doesn't include {', '.join(missing)}"
        scope = ", ".join(sorted(grant.scope))
        if action not in grant.actions:
            return f"the grant doesn't allow {action}"
        return f"the grant covers {scope}, and {info.name} is {tags}"

    # -- obligations -----------------------------------------------------------------------

    def _row_filter(self, grant: Grant, metas: list[PolicyMeta]) -> str | None:
        parts: list[str] = []
        for meta in metas:
            if meta.row_filter:
                parts.append(self._fill(meta.row_filter, grant, meta.id))
        unique = list(dict.fromkeys(parts))
        if not unique:
            return None
        return unique[0] if len(unique) == 1 else " AND ".join(f"({p})" for p in unique)

    def _fill(self, template: str, grant: Grant, pid: str) -> str:
        def value(m: re.Match[str]) -> str:
            ns, key = m.group(1), m.group(2)
            v: str | None = None
            if ns == "person" and not grant.is_purpose:
                person = self.config.people.get(grant.subject)
                v = person.attributes.get(key) if person else None
            elif ns == "trigger" and key == "record":
                v = grant.trigger_record
            elif ns == "trigger" and key == "type":
                v = grant.trigger_type
            elif ns == "grant" and key in ("subject", "agent", "id"):
                v = getattr(grant, key)
            if v is None:
                raise ObligationError(
                    f"row filter on {pid} needs {{{ns}.{key}}}, which isn't known,"
                    " so the call is denied"
                )
            return sql_quote(v)

        return _TEMPLATE.sub(value, template)


def _q(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
