"""The YAML authoring surface: people, agents and their ceilings, access rules, purposes.

People write YAML; Trellis compiles it to Cedar (see ``trellis.compiler``), so nobody has to
write Cedar. A config is a directory of YAML files, each holding one or more of these
top-level keys::

    people:    the directory (groups and attributes); an IdP replaces it in M4
    agents:    each agent's owner and ceiling
    access:    what people may read (contracts add to this in M3)
    purposes:  purpose grants for process agents, each with a named owner
    catalog:   tables, their tags and their columns' tags (for development and demos)
    catalogs:  catalogs Trellis reads tags from, such as an Iceberg REST catalog
    levels:    the ranked classification scale, lowest first

Contracts live one per file (a top-level ``contract:`` key), in the config directory or
its ``contracts/`` folder. ODCS v3 contracts there are read through the ODCS adapter.

``trellisd schema`` prints the JSON Schema for this format, and
``trellisd schema --contract`` the one for contracts.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

Tags = frozenset[str]
ACTIONS = ("read", "query", "export", "write")
#: The default ranked scale. A resource carries at most one level: the highest any
#: source gives it.
DEFAULT_LEVELS = ("public", "internal", "confidential", "restricted")


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


def _check_who(value: tuple[str, ...]) -> tuple[str, ...]:
    for w in value:
        if not w.startswith(("group:", "user:")):
            raise ValueError(f"'who' entries must start with group: or user:, got {w!r}")
    return value


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
        return _check_who(value)


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


def _canonical(value: Any) -> Any:
    """Sets sorted, so a hash doesn't depend on Python's set order."""
    if isinstance(value, dict):
        return {k: _canonical(v) for k, v in value.items()}
    if isinstance(value, (set, frozenset)):
        return sorted(_canonical(v) for v in value)
    if isinstance(value, (list, tuple)):
        return [_canonical(v) for v in value]
    return value


ContractKind = Literal["table", "mcp_tool", "api", "document", "model", "dashboard"]


class ContractAccess(_Model):
    """One role on a contract: who may use the resource, and what's masked for them."""

    who: tuple[str, ...] = Field(description="group:<name> or user:<email>")
    actions: tuple[str, ...] = ("read", "query")
    mask: Tags = Field(default=frozenset(), description="Elements carrying these are masked.")

    @field_validator("who")
    @classmethod
    def _who(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _check_who(value)


class Contract(_Model):
    """What a resource is and who may use it, set by its owner. The source of truth.

    A catalog can add tags to what a contract declares, never remove them; only an
    owner-approved change to the contract widens access.
    """

    contract: str = Field(description="Stable URN, for example urn:contract:finance.gl")
    version: str = "1"
    kind: ContractKind = "table"
    description: str = ""
    bindings: tuple[str, ...] = Field(
        description="Addresses it governs: a table name (finance.gl.journal_entries) or a"
        " URI such as mcp://ledger/journal_entries. Each address has one contract."
    )
    owner: str
    steward: str | None = None
    tags: Tags = frozenset()
    elements: dict[str, Tags] = Field(
        default_factory=dict,
        description="Every column or field, with its tags. A column the catalog has and the"
        " contract lacks is drift: masked until the owner classifies it.",
    )
    purposes: Tags = frozenset()
    access: dict[str, ContractAccess] = Field(default_factory=dict)
    rows: tuple[str, ...] = Field(
        default=(),
        description="Row filters that always apply to people reading through this contract,"
        " templated with {person.<attr>}.",
    )
    #: Where it was read from: "trellis", or "odcs" for one mapped by the ODCS adapter.
    origin: str = "trellis"

    @field_validator("version", mode="before")
    @classmethod
    def _version(cls, value: object) -> str:
        return str(value)

    @property
    def name(self) -> str:
        """The URN's last part, used in policy ids (contract.<name>.<role>)."""
        return self.contract.rsplit(":", 1)[-1]

    @property
    def digest(self) -> str:
        body = json.dumps(_canonical(self.model_dump()), sort_keys=True)
        return hashlib.sha256(body.encode()).hexdigest()[:12]

    @property
    def version_id(self) -> str:
        """The version every decision records: the owner's number plus a content hash."""
        return f"v{self.version}@{self.digest}"

    @property
    def tables(self) -> tuple[str, ...]:
        return tuple(b for b in self.bindings if "://" not in b)


class CatalogSource(_Model):
    """A catalog Trellis reads tags from. Read-only: Trellis never writes to it."""

    type: Literal["iceberg-rest"] = "iceberg-rest"
    uri: str
    warehouse: str | None = None
    namespaces: tuple[str, ...] = Field(
        default=(), description="Answer only for tables under these. Empty means every table."
    )
    ttl_seconds: float = 300
    not_found_ttl_seconds: float = 30
    stale_after_seconds: float = Field(
        default=900,
        description="Past this, with the catalog unreachable, Trellis denies (fail closed).",
    )
    token_env: str | None = Field(
        default=None, description="An environment variable holding a bearer token."
    )
    tag_property: str = "trellis.tags"
    column_property: str = "trellis.column.{column}.tags"


class TrellisConfig(_Model):
    people: dict[str, Person] = Field(default_factory=dict)
    agents: dict[str, Agent] = Field(default_factory=dict)
    access: tuple[AccessRule, ...] = ()
    purposes: dict[str, Purpose] = Field(default_factory=dict)
    catalog: dict[str, Table] = Field(default_factory=dict)
    catalogs: dict[str, CatalogSource] = Field(default_factory=dict)
    contracts: dict[str, Contract] = Field(default_factory=dict)
    levels: tuple[str, ...] | None = None

    @property
    def scale(self) -> tuple[str, ...]:
        return self.levels if self.levels is not None else DEFAULT_LEVELS

    def at_or_below(self, tags: Tags) -> Tags:
        """A ceiling that allows a level allows every level under it."""
        out = set(tags)
        for i, level in enumerate(self.scale):
            if level in tags:
                out |= set(self.scale[:i])
        return frozenset(out)

    def at_or_above(self, tags: Tags) -> Tags:
        """A never-list or mask on a level covers every level over it."""
        out = set(tags)
        for i, level in enumerate(self.scale):
            if level in tags:
                out |= set(self.scale[i:])
        return frozenset(out)

    def contract_for(self, address: str) -> Contract | None:
        for c in self.contracts.values():
            if address in c.bindings:
                return c
        return None

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
        if self.levels is not None and other.levels is not None and self.levels != other.levels:
            raise ConfigError("levels defined twice, differently")
        return TrellisConfig(
            people=union(dict(self.people), dict(other.people), "people"),
            agents=union(dict(self.agents), dict(other.agents), "agents"),
            access=rules,
            purposes=union(dict(self.purposes), dict(other.purposes), "purposes"),
            catalog=union(dict(self.catalog), dict(other.catalog), "tables"),
            catalogs=union(dict(self.catalogs), dict(other.catalogs), "catalogs"),
            contracts=union(dict(self.contracts), dict(other.contracts), "contracts"),
            levels=self.levels if self.levels is not None else other.levels,
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
    if "contract" in raw:
        try:
            contract = Contract.model_validate(raw)
        except ValidationError as exc:
            raise ConfigError(f"{path}: {exc}") from exc
        return TrellisConfig(contracts={contract.contract: contract})
    if raw.get("kind") == "DataContract" and "apiVersion" in raw:
        from trellisd.odcs import OdcsError, to_contracts

        try:
            mapped = to_contracts(raw)
        except OdcsError as exc:
            raise ConfigError(f"{path}: {exc}") from exc
        return TrellisConfig(contracts={c.contract: c for c in mapped.contracts})
    known = {"people", "agents", "access", "purposes", "catalog", "catalogs", "levels"}
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
            files += sorted([*p.glob("contracts/*.yaml"), *p.glob("contracts/*.yml")])
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
    claimed: dict[str, str] = {}
    for urn, contract in sorted(config.contracts.items()):
        for address in contract.bindings:
            if address in claimed:
                raise ConfigError(
                    f"{address} is claimed by two contracts, {claimed[address]} and {urn};"
                    " each address has one contract"
                )
            claimed[address] = urn
    if len(set(config.scale)) != len(config.scale):
        raise ConfigError("levels repeat a level")


def contract_schema() -> dict[str, Any]:
    schema = Contract.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["title"] = "Trellis contract"
    schema["properties"].pop("origin", None)
    return schema


def json_schema() -> dict[str, Any]:
    schema = TrellisConfig.model_json_schema()
    # Contracts are files of their own (see ``contract_schema``), not a config section.
    schema["properties"].pop("contracts", None)
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["title"] = "Trellis config"
    return schema


GrantKind = Literal["personal", "purpose"]
