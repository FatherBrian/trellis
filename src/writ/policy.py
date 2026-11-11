"""Policies as code.

Every policy states that a principal takes an action on a resource, given conditions,
and creates annotations. Policies are YAML; see ``examples/policies.yaml``.

The syntax here is the illustrative one from the design doc.
TODO(week 1): settle the syntax, then publish a JSON Schema for editor support.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from writ.catalog import Tags
from writ.grants import AgentProfile

Operator = Literal["contains", "excludes"]

#: Subjects a condition may reference. Anything else fails at load time (fail closed).
REQUEST_SUBJECTS = frozenset({"grant.scope", "resource.tags", "human.groups", "human.clearances"})
COLUMN_SUBJECTS = frozenset({"column.tags"})
SUBJECTS = REQUEST_SUBJECTS | COLUMN_SUBJECTS


class PolicyError(ValueError):
    """Raised when a policy file is malformed."""


class Condition(BaseModel):
    """``<subject> <contains|excludes> <tag>``, for example ``column.tags excludes pii``.

    Request conditions decide whether a policy applies at all. Column conditions are
    checked per column; a column that fails one is masked.
    """

    model_config = ConfigDict(frozen=True)

    subject: str
    op: Operator
    value: str

    @classmethod
    def parse(cls, text: str) -> Condition:
        parts = text.split()
        if len(parts) != 3:
            raise PolicyError(f"condition must be '<subject> <op> <tag>': {text!r}")
        subject, op, value = parts
        if subject not in SUBJECTS:
            raise PolicyError(f"unknown condition subject {subject!r} in {text!r}")
        if op not in ("contains", "excludes"):
            raise PolicyError(f"unknown condition operator {op!r} in {text!r}")
        return cls(subject=subject, op=op, value=value)

    @property
    def is_column_condition(self) -> bool:
        return self.subject in COLUMN_SUBJECTS

    def holds(self, facts: Mapping[str, Tags]) -> bool:
        present = self.value in facts.get(self.subject, frozenset())
        return present if self.op == "contains" else not present

    def __str__(self) -> str:
        return f"{self.subject} {self.op} {self.value}"


class PrincipalMatch(BaseModel):
    """Which agent, acting for whom.

    ``on_behalf_of`` is ``user:<id>``, ``group:<name>`` or ``*``.
    """

    model_config = ConfigDict(frozen=True)

    agent: str = "*"
    on_behalf_of: str = "*"

    @field_validator("on_behalf_of")
    @classmethod
    def _check_on_behalf_of(cls, v: str) -> str:
        if v != "*" and not v.startswith(("user:", "group:")):
            raise ValueError("on_behalf_of must be '*', 'user:<id>' or 'group:<name>'")
        return v

    def matches(self, agent: str, human: str, groups: Tags) -> bool:
        if self.agent not in ("*", agent):
            return False
        if self.on_behalf_of == "*":
            return True
        kind, _, ident = self.on_behalf_of.partition(":")
        return ident == human if kind == "user" else ident in groups


class ResourceMatch(BaseModel):
    """The resource tags a policy covers. Matches when all of its tags are on the resource."""

    model_config = ConfigDict(frozen=True)

    tags: Tags = frozenset()

    def matches(self, resource_tags: Tags) -> bool:
        return self.tags <= resource_tags


class Policy(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    description: str = ""
    principal: PrincipalMatch = Field(default_factory=PrincipalMatch)
    action: tuple[str, ...]
    resource: ResourceMatch = Field(default_factory=ResourceMatch)
    conditions: tuple[Condition, ...] = ()
    annotations: dict[str, str] = Field(default_factory=dict)
    # TODO(week 1): template row filters with principal attributes, e.g. region = {human.region}.
    row_filter: str | None = None

    @field_validator("action", mode="before")
    @classmethod
    def _coerce_action(cls, v: Any) -> Any:
        return (v,) if isinstance(v, str) else v

    @field_validator("conditions", mode="before")
    @classmethod
    def _parse_conditions(cls, v: Any) -> Any:
        if v is None:
            return ()
        return tuple(Condition.parse(c) if isinstance(c, str) else c for c in v)

    @field_validator("annotations", mode="before")
    @classmethod
    def _stringify_annotations(cls, v: Any) -> Any:
        return {str(k): str(val) for k, val in (v or {}).items()}

    @property
    def request_conditions(self) -> tuple[Condition, ...]:
        return tuple(c for c in self.conditions if not c.is_column_condition)

    @property
    def column_conditions(self) -> tuple[Condition, ...]:
        return tuple(c for c in self.conditions if c.is_column_condition)


class PolicyBundle(BaseModel):
    """Agent ceilings plus the policies that apply to them, loaded from one YAML file."""

    model_config = ConfigDict(frozen=True)

    agents: dict[str, AgentProfile] = Field(default_factory=dict)
    policies: tuple[Policy, ...] = ()

    @model_validator(mode="after")
    def _unique_ids(self) -> PolicyBundle:
        seen: set[str] = set()
        for p in self.policies:
            if p.id in seen:
                raise ValueError(f"duplicate policy id {p.id!r}")
            seen.add(p.id)
        return self

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> PolicyBundle:
        agents = {
            name: AgentProfile(name=name, **(spec or {}))
            for name, spec in (raw.get("agents") or {}).items()
        }
        policies = []
        for i, spec in enumerate(raw.get("policies") or []):
            spec = dict(spec)
            spec.setdefault("id", f"policy-{i + 1}")
            policies.append(Policy.model_validate(spec))
        return cls(agents=agents, policies=tuple(policies))


def load_policies(path: str | Path) -> PolicyBundle:
    """Load and validate a policy file. Raises ``PolicyError`` on any problem."""
    try:
        with Path(path).open(encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        return PolicyBundle.from_dict(raw)
    except PolicyError:
        raise
    except Exception as exc:
        raise PolicyError(f"{path}: {exc}") from exc
