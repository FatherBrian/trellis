"""The YAML authoring surface: people, agents and their ceilings, access rules, purposes.

People write YAML; Trellis compiles it to Cedar (see ``trellis.compiler``), so nobody has to
write Cedar. A config is a directory of YAML files, each holding one or more of these
top-level keys::

    people:    the directory (groups and attributes); an IdP replaces it in M4
    agents:    each agent's owner and ceiling
    access:    what people may read (contracts add to this in M3)
    purposes:  purpose grants for process agents, each with a named owner
    catalog:   tables, their tags and their columns' tags

``trellis schema`` prints the JSON Schema for this format.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

Tags = frozenset[str]
ACTIONS = ("read", "query", "export", "write")


class ConfigError(ValueError):
    """Raised when a config file is malformed. Trellis refuses to start on one (fail closed)."""


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Person(_Model):
    """A human in the directory: groups and string attributes (used by row filters)."""

    groups: tuple[str, ...] = ()
    attributes: dict[str, str] = Field(default_factory=dict)


class Ceiling(_Model):
    actions: tuple[str, ...] = ("read", "query")
    tags: Tags = frozenset()
    never: Tags = frozenset()


class Agent(_Model):
    """The most an agent may ever touch, set by its owner."""

    owner: str
    description: str = ""
    ceiling: Ceiling = Ceiling()


class AccessRule(_Model):
    """What a group or person may do with some data. Compiles to one Cedar permit."""

    id: str
    who: tuple[str, ...] = Field(description="group:<name> or user:<email>")
    actions: tuple[str, ...] = ("read", "query")
    resources: tuple[str, ...] = Field(
        default=(), description="Dataset (namespace) or table names. Empty means any."
    )
    tags: Tags = Field(
        default=frozenset(), description="The resource must carry at least one of these."
    )
    mask: Tags = Field(default=frozenset(), description="Columns carrying these tags are masked.")
    row_filter: str | None = Field(
        default=None, description="SQL predicate; {person.<attr>} is filled from the directory."
    )
    description: str = ""

    @field_validator("who")
    @classmethod
    def _who(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for w in value:
            if not w.startswith(("group:", "user:")):
                raise ValueError(f"'who' entries must start with group: or user:, got {w!r}")
        return value


class Trigger(_Model):
    """What one run of a process agent is about: the record that started it."""

    type: str = Field(description="Kind of record, for example 'inspection'.")
    tags: Tags = Field(description="The run may touch resources carrying any of these.")
    row_filter: str | None = Field(
        default=None, description="Binds rows to the record; {trigger.record} is its id."
    )


class Purpose(_Model):
    """A purpose grant's standing scope, approved by a named owner."""

    owner: str
    description: str = ""
    agents: tuple[str, ...] = Field(description="Process agents allowed to run under it.")
    actions: tuple[str, ...] = ("read",)
    resources: tuple[str, ...] = ()
    tags: Tags = frozenset()
    mask: Tags = frozenset()
    trigger: Trigger
    review_every_days: int = 90


class Table(_Model):
    tags: Tags = frozenset()
    columns: dict[str, Tags] = Field(default_factory=dict)


class TrellisConfig(_Model):
    people: dict[str, Person] = Field(default_factory=dict)
    agents: dict[str, Agent] = Field(default_factory=dict)
    access: tuple[AccessRule, ...] = ()
    purposes: dict[str, Purpose] = Field(default_factory=dict)
    catalog: dict[str, Table] = Field(default_factory=dict)

    def merged(self, other: TrellisConfig) -> TrellisConfig:
        def union(a: dict[str, Any], b: dict[str, Any], what: str) -> dict[str, Any]:
            clash = set(a) & set(b)
            if clash:
                raise ConfigError(f"{what} defined twice: {', '.join(sorted(clash))}")
            return {**a, **b}

        rules = self.access + other.access
        ids = [r.id for r in rules]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            raise ConfigError(f"access rule ids defined twice: {', '.join(sorted(dupes))}")
        return TrellisConfig(
            people=union(dict(self.people), dict(other.people), "people"),
            agents=union(dict(self.agents), dict(other.agents), "agents"),
            access=rules,
            purposes=union(dict(self.purposes), dict(other.purposes), "purposes"),
            catalog=union(dict(self.catalog), dict(other.catalog), "tables"),
        )

    # -- lookups ---------------------------------------------------------------------------

    def groups_of(self, person: str) -> tuple[str, ...]:
        p = self.people.get(person)
        return p.groups if p else ()


def _load_file(path: Path) -> TrellisConfig:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    known = {"people", "agents", "access", "purposes", "catalog"}
    data = {k: v for k, v in raw.items() if k in known}
    if not data:
        return TrellisConfig()
    try:
        return TrellisConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"{path}: {exc}") from exc


def load_config(*paths: str | Path) -> TrellisConfig:
    """Load and merge YAML files or directories of them (``*.yaml``, ``*.yml``)."""
    config = TrellisConfig()
    files: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            files += sorted([*p.glob("*.yaml"), *p.glob("*.yml")])
        elif p.exists():
            files.append(p)
        else:
            raise ConfigError(f"{p}: no such file or directory")
    for f in files:
        config = config.merged(_load_file(f))
    _check_references(config)
    return config


def _check_references(config: TrellisConfig) -> None:
    for name, purpose in config.purposes.items():
        for agent in purpose.agents:
            if agent not in config.agents:
                raise ConfigError(f"purpose {name} names unknown agent {agent}")


def json_schema() -> dict[str, Any]:
    schema = TrellisConfig.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["title"] = "Trellis config"
    return schema


GrantKind = Literal["personal", "purpose"]
