"""The decision API.

``authorize(principal, action, resource, context)`` answers one question: may this agent,
acting for this human under this grant, take this action on this resource right now?

Effective access is the intersection of three limits, and everything outside it is
denied by default::

    effective access = human access ∩ agent ceiling ∩ task scope

Inside that boundary, YAML policies decide which actions are allowed, which columns are
masked, which rows are filtered, and which annotations (such as ``log: required``) the
decision carries.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from moat.catalog import Catalog, Column, Human, Resource, Tags
from moat.grants import AgentProfile, Grant, GrantStore, utcnow
from moat.policy import Policy, PolicyBundle


class Principal(BaseModel):
    """Who acts: an agent, for a human, under exactly one grant."""

    model_config = ConfigDict(frozen=True)

    agent: str
    human: str
    grant_id: str

    @classmethod
    def from_grant(cls, grant: Grant) -> Principal:
        return cls(agent=grant.agent, human=grant.human, grant_id=grant.id)


class RequestContext(BaseModel):
    """Extra facts about one request."""

    model_config = ConfigDict(frozen=True)

    #: Columns the caller explicitly asked for. ``None`` means "whatever the tool returns".
    columns: tuple[str, ...] | None = None
    #: Evaluation time. Defaults to now; tests pin it.
    now: datetime | None = None
    #: Free-form request attributes, recorded in the ledger. Not yet used by conditions.
    attributes: dict[str, str] = Field(default_factory=dict)


class Decision(BaseModel):
    """The answer, with everything needed to enforce and explain it."""

    model_config = ConfigDict(frozen=True)

    allowed: bool
    reason: str
    masks: tuple[str, ...] = ()
    row_filter: str | None = None
    annotations: dict[str, str] = Field(default_factory=dict)
    policy_ids: tuple[str, ...] = ()
    effective_tags: Tags = frozenset()

    @property
    def decision(self) -> str:
        return "allow" if self.allowed else "deny"


def _deny(reason: str, effective: Tags = frozenset()) -> Decision:
    return Decision(allowed=False, reason=reason, effective_tags=effective)


def _fmt(tags: Iterable[str]) -> str:
    return ", ".join(sorted(tags)) or "(none)"


def explain_missing(tag: str, human: Human, agent: AgentProfile, grant: Grant) -> str:
    """Name which of the three limits removed a tag."""
    limits = []
    if tag not in human.clearances:
        limits.append(f"{human.id} is not cleared for it")
    if tag not in agent.ceiling:
        limits.append(f"it is above {agent.name}'s ceiling")
    if tag not in grant.scope:
        limits.append(f"the task '{grant.task}' did not request it")
    return f"'{tag}': " + "; ".join(limits)


class Authorizer:
    """Evaluates requests against grants, agent ceilings, catalog tags and policies.

    TODO(week 1): expose this over a small HTTP server (see ``moat.server``).
    TODO(week 1): add explicit ``effect: deny`` policies if the format needs them.
    """

    def __init__(self, catalog: Catalog, policies: PolicyBundle, grants: GrantStore) -> None:
        self.catalog = catalog
        self.policies = policies
        self.grants = grants

    def authorize(
        self,
        principal: Principal,
        action: str,
        resource: str,
        context: RequestContext | None = None,
    ) -> Decision:
        ctx = context or RequestContext()
        now = ctx.now or utcnow()

        # 1. The grant must exist, match the principal, and be live.
        grant = self.grants.get(principal.grant_id)
        if grant is None:
            return _deny(f"no grant {principal.grant_id}")
        if (grant.agent, grant.human) != (principal.agent, principal.human):
            return _deny(
                f"grant {grant.id} is for {grant.agent} acting for {grant.human}, "
                f"not {principal.agent} acting for {principal.human}"
            )
        if (inactive := grant.inactive_reason(now)) is not None:
            return _deny(inactive)

        # 2. The agent needs a registered ceiling, and the human must be known.
        agent = self.policies.agents.get(principal.agent)
        if agent is None:
            return _deny(f"agent {principal.agent} has no registered ceiling")
        human = self.catalog.human(principal.human)
        if human is None:
            return _deny(f"{principal.human} is not known to the catalog")

        # 3. Effective access is the intersection of the three limits.
        effective = human.clearances & agent.ceiling & grant.scope

        # 4. The resource must be known and classified, and all its tags inside the boundary.
        res = self.catalog.resource(resource)
        if res is None:
            return _deny(f"{resource} is not in the catalog, so it is denied by default", effective)
        if not res.tags:
            return _deny(f"{resource} has no tags, so it is denied by default", effective)
        missing = res.tags - effective
        if missing:
            details = "; ".join(explain_missing(t, human, agent, grant) for t in sorted(missing))
            return _deny(
                f"{resource} is tagged {_fmt(missing)} outside this grant: {details}", effective
            )

        # 5. Explicitly requested columns must exist and sit inside the boundary.
        requested = self._requested_columns(res, ctx)
        if isinstance(requested, Decision):
            return requested.model_copy(update={"effective_tags": effective})
        explicit = requested if ctx.columns is not None else ()
        for col in explicit:
            if not col.tags <= effective:
                details = "; ".join(
                    explain_missing(t, human, agent, grant) for t in sorted(col.tags - effective)
                )
                return _deny(
                    f"column {resource}.{col.name} is outside this grant: {details}", effective
                )

        # 6. At least one policy must allow the action. Deny by default.
        facts: dict[str, Tags] = {
            "grant.scope": grant.scope,
            "resource.tags": res.tags,
            "human.groups": human.groups,
            "human.clearances": human.clearances,
        }
        matched = [
            p
            for p in self.policies.policies
            if action in p.action
            and p.principal.matches(principal.agent, principal.human, human.groups)
            and p.resource.matches(res.tags)
            and all(c.holds(facts) for c in p.request_conditions)
        ]
        if not matched:
            return _deny(
                f"no policy allows {principal.agent} acting for {principal.human} "
                f"to {action} {resource}",
                effective,
            )

        # 7. Shape the answer. When several policies match, the most restrictive result wins:
        #    masks are unioned, row filters are ANDed, annotations are merged.
        masks, mask_reasons = self._masks(requested, effective, matched)
        filters = [p.row_filter for p in matched if p.row_filter]
        annotations: dict[str, str] = {}
        for p in matched:
            annotations.update(p.annotations)

        reason = f"allowed by {', '.join(p.id for p in matched)}"
        if mask_reasons:
            reason += "; masked " + "; ".join(mask_reasons)
        return Decision(
            allowed=True,
            reason=reason,
            masks=tuple(masks),
            row_filter=" AND ".join(f"({f})" for f in filters) if filters else None,
            annotations=annotations,
            policy_ids=tuple(p.id for p in matched),
            effective_tags=effective,
        )

    @staticmethod
    def _requested_columns(res: Resource, ctx: RequestContext) -> tuple[Column, ...] | Decision:
        if ctx.columns is None:
            return res.columns
        cols = []
        for name in ctx.columns:
            col = res.column(name)
            if col is None:
                return _deny(f"column {res.name}.{name} is not in the catalog")
            cols.append(col)
        return tuple(cols)

    @staticmethod
    def _masks(
        columns: Iterable[Column], effective: Tags, matched: list[Policy]
    ) -> tuple[list[str], list[str]]:
        masks: list[str] = []
        reasons: list[str] = []
        for col in columns:
            if not col.tags <= effective:
                masks.append(col.name)
                reasons.append(f"{col.name} (tagged {_fmt(col.tags - effective)} outside grant)")
                continue
            facts = {"column.tags": col.tags}
            failed = [str(c) for p in matched for c in p.column_conditions if not c.holds(facts)]
            if failed:
                masks.append(col.name)
                reasons.append(f"{col.name} ({'; '.join(dict.fromkeys(failed))})")
        return masks, reasons
