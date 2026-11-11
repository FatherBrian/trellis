"""Compile the YAML config to Cedar: three policy sets and the entities they run against.

Trellis keeps the three limits on a call in three *separate* policy sets, so a permit
written for one limit can never satisfy another:

* ``subject``: what the person may access (access rules), or the purpose's standing
  scope for a process agent;
* ``ceiling``: the most each agent may ever touch, set by its owner;
* ``scope``: what this grant's task or trigger covers. Grants are issued at run time, so
  this set is compiled per grant (``scope_policy``).

Every policy carries ``@id``; ``@mask`` and ``@row_filter`` ride along as annotations and
come back as obligations when the policy decides.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

import cedarpy

from trellisd.config import AccessRule, Purpose, Tags, TrellisConfig
from trellisd.grants import Grant

CEDAR_SCHEMA = """\
entity Group;
entity Person in [Group];
entity Agent;
entity Purpose;
entity Grant;
entity Dataset in [Dataset];
entity Table in [Dataset] { tags: Set<String> };
entity Column in [Table] { tags: Set<String> };
action read, query, export, write appliesTo {
  principal: [Person, Purpose, Agent, Grant],
  resource: [Table, Column],
  context: { agent: String }
};
"""


def _lit(value: str) -> str:
    return json.dumps(value)


def _set(values: Iterable[str]) -> str:
    return "[" + ", ".join(_lit(v) for v in sorted(values)) + "]"


def _actions(actions: Iterable[str]) -> str:
    return "[" + ", ".join(f"Action::{_lit(a)}" for a in actions) + "]"


def _annotations(pid: str, mask: Tags = frozenset(), row_filter: str | None = None) -> str:
    out = f"@id({_lit(pid)})"
    if mask:
        out += f" @mask({_lit(','.join(sorted(mask)))})"
    if row_filter:
        out += f" @row_filter({_lit(row_filter)})"
    return out


@dataclass(frozen=True)
class PolicyMeta:
    id: str
    effect: str
    mask: Tags = frozenset()
    row_filter: str | None = None


@dataclass(frozen=True)
class PolicySetText:
    """Cedar text plus, for each positional id Cedar reports (policy0...), our metadata."""

    name: str
    text: str
    meta: tuple[PolicyMeta, ...]

    def lookup(self, cedar_id: str) -> PolicyMeta | None:
        if cedar_id.startswith("policy"):
            idx = int(cedar_id[len("policy") :])
            if 0 <= idx < len(self.meta):
                return self.meta[idx]
        return None

    def cedar(self) -> cedarpy.PolicySet:
        return cedarpy.PolicySet.from_str(self.text)


def _build(name: str, items: list[tuple[str, PolicyMeta]]) -> PolicySetText:
    text = "\n\n".join(t for t, _ in items)
    meta = tuple(m for _, m in items)
    # Cross-check our positional metadata against what Cedar parsed.
    if text:
        parsed = json.loads(cedarpy.policies_to_json_str(text))["staticPolicies"]
        for i, m in enumerate(meta):
            got = parsed[f"policy{i}"]["annotations"].get("id")
            if got != m.id:  # pragma: no cover - a compiler bug, not a user error
                raise AssertionError(f"policy order mismatch: {got} != {m.id}")
    return PolicySetText(name, text + ("\n" if text else ""), meta)


class Compiler:
    def __init__(self, config: TrellisConfig) -> None:
        self.config = config
        self.tables = set(config.catalog)

    # -- resources -------------------------------------------------------------------------

    def _resource_scope(self, resources: tuple[str, ...]) -> str | None:
        if not resources:
            return None
        parts = []
        for r in resources:
            kind = "Table" if r in self.tables else "Dataset"
            parts.append(f"resource in {kind}::{_lit(r)}")
        return parts[0] if len(parts) == 1 else "(" + " || ".join(parts) + ")"

    def _conditions(self, resources: tuple[str, ...], tags: Tags) -> list[str]:
        conds = []
        scope = self._resource_scope(resources)
        if scope:
            conds.append(scope)
        if tags:
            conds.append(f"resource.tags.containsAny({_set(tags)})")
        return conds

    @staticmethod
    def _policy(
        effect: str, principal: str, actions: Iterable[str] | None, conds: list[str]
    ) -> str:
        act = "action" if actions is None else f"action in {_actions(actions)}"
        body = f"{effect} (\n  {principal},\n  {act},\n  resource\n)"
        if conds:
            body += "\nwhen {\n  " + " &&\n  ".join(conds) + "\n}"
        return body + ";"

    # -- the three sets --------------------------------------------------------------------

    def _access_rule(self, rule: AccessRule) -> list[tuple[str, PolicyMeta]]:
        out = []
        for i, who in enumerate(rule.who):
            kind, name = who.split(":", 1)
            principal = (
                f"principal in Group::{_lit(name)}"
                if kind == "group"
                else f"principal == Person::{_lit(name)}"
            )
            pid = f"access.{rule.id}" + (f".{i}" if len(rule.who) > 1 else "")
            text = (
                _annotations(pid, rule.mask, rule.row_filter)
                + "\n"
                + self._policy(
                    "permit", principal, rule.actions, self._conditions(rule.resources, rule.tags)
                )
            )
            out.append((text, PolicyMeta(pid, "permit", rule.mask, rule.row_filter)))
        return out

    def _purpose(self, name: str, p: Purpose) -> tuple[str, PolicyMeta]:
        pid = f"purpose.{name}"
        conds = [
            f"{_set(p.agents)}.contains(context.agent)",
            *self._conditions(p.resources, p.tags),
        ]
        text = (
            _annotations(pid, p.mask)
            + "\n"
            + self._policy("permit", f"principal == Purpose::{_lit(name)}", p.actions, conds)
        )
        return text, PolicyMeta(pid, "permit", p.mask)

    def subject_policies(self) -> PolicySetText:
        items: list[tuple[str, PolicyMeta]] = []
        for rule in self.config.access:
            items += self._access_rule(rule)
        for name, p in sorted(self.config.purposes.items()):
            items.append(self._purpose(name, p))
        return _build("subject", items)

    def ceiling_policies(self) -> PolicySetText:
        items: list[tuple[str, PolicyMeta]] = []
        for name, agent in sorted(self.config.agents.items()):
            c = agent.ceiling
            principal = f"principal == Agent::{_lit(name)}"
            if c.tags:
                pid = f"ceiling.{name}"
                conds = [f"{_set(c.tags)}.containsAll(resource.tags)"]
                items.append(
                    (
                        _annotations(pid)
                        + "\n"
                        + self._policy("permit", principal, c.actions, conds),
                        PolicyMeta(pid, "permit"),
                    )
                )
            if c.never:
                pid = f"ceiling.{name}.never"
                conds = [f"resource.tags.containsAny({_set(c.never)})"]
                items.append(
                    (
                        _annotations(pid) + "\n" + self._policy("forbid", principal, None, conds),
                        PolicyMeta(pid, "forbid"),
                    )
                )
        return _build("ceiling", items)

    def scope_policy(self, grant: Grant) -> PolicySetText:
        """The task scope (personal) or trigger scope (purpose) of one grant."""
        row_filter = None
        if grant.is_purpose:
            purpose = self.config.purposes.get(grant.subject)
            row_filter = purpose.trigger.row_filter if purpose else None
        pid = f"grant.{grant.id}"
        conds = [f"resource.tags.containsAny({_set(grant.scope)})"]
        text = (
            _annotations(pid, row_filter=row_filter)
            + "\n"
            + self._policy("permit", f"principal == Grant::{_lit(grant.id)}", grant.actions, conds)
        )
        return _build("scope", [(text, PolicyMeta(pid, "permit", row_filter=row_filter))])

    # -- entities --------------------------------------------------------------------------

    def entities(self, extra: Iterable[dict[str, Any]] = ()) -> list[dict[str, Any]]:
        cfg = self.config
        ents: dict[tuple[str, str], dict[str, Any]] = {}

        def add(
            type_: str,
            id_: str,
            attrs: dict[str, Any] | None = None,
            parents: Iterable[tuple[str, str]] = (),
        ) -> None:
            ents[(type_, id_)] = {
                "uid": {"type": type_, "id": id_},
                "attrs": attrs or {},
                "parents": [{"type": t, "id": i} for t, i in parents],
            }

        groups = {g for p in cfg.people.values() for g in p.groups}
        for rule in cfg.access:
            groups |= {w.split(":", 1)[1] for w in rule.who if w.startswith("group:")}
        for g in sorted(groups):
            add("Group", g)
        for email, person in cfg.people.items():
            add("Person", email, None, [("Group", g) for g in person.groups])
        for name in cfg.agents:
            add("Agent", name)
        for name in cfg.purposes:
            add("Purpose", name)
        datasets: set[str] = set()
        for table, info in cfg.catalog.items():
            ns = table.rsplit(".", 1)[0] if "." in table else table
            parts = ns.split(".")
            for i in range(1, len(parts) + 1):
                datasets.add(".".join(parts[:i]))
            add("Table", table, {"tags": sorted(info.tags)}, [("Dataset", ns)])
            for col, ctags in info.columns.items():
                add(
                    "Column",
                    f"{table}.{col}",
                    {"tags": sorted(info.tags | ctags)},
                    [("Table", table)],
                )
        for ds in sorted(datasets):
            parent = ds.rsplit(".", 1)[0] if "." in ds else None
            add("Dataset", ds, None, [("Dataset", parent)] if parent else [])
        out = list(ents.values())
        out.extend(extra)
        return out

    def validate(self) -> list[str]:
        """Validate the compiled policy sets against Trellis's Cedar schema."""
        errors: list[str] = []
        for ps in (self.subject_policies(), self.ceiling_policies()):
            if not ps.text:
                continue
            result = cedarpy.validate_policies(ps.text, CEDAR_SCHEMA)
            if not result.validation_passed:
                errors += [f"{ps.name}: {e}" for e in result.errors]
        return errors


def render(config: TrellisConfig) -> str:
    """All of the static Cedar Trellis generates, for ``trellisd compile``."""
    c = Compiler(config)
    out = []
    for ps in (c.subject_policies(), c.ceiling_policies()):
        out.append(f"// ---- {ps.name} ----\n{ps.text}")
    return "\n".join(out)
