"""What Trellis knows about data: contracts, the tags catalogs observe, and how they merge.

Contracts say what a resource is and who may use it; catalogs (an Iceberg REST catalog,
or the config's ``catalog:`` section in development) supply the tags they observe on real
objects. The ``Resolver`` merges them before every decision, strictest first:

* **Tags are a union.** A tag from any source applies; no source removes another's.
* **Ranked levels take the higher.** A resource keeps one level: the highest given.
* **Selectors come from the contract.** Grant scopes and access rules match a resource's
  *declared* tags: the contract's, or (with no contract) only the tags every source
  agrees on. So a tag a catalog adds can only ever take access away: it can trip a
  ceiling, a never-list or a mask, but never make a grant or rule match.
* **Owners come from the contract.** A catalog's owner is shown, not used.
* **Drift is masked.** A column the catalog has and the contract lacks is unclassified.
* **Every tag carries its source** and version, kept in the ledger for replay.
* **Fail closed.** A source that can't answer past its staleness bound raises
  ``SourceUnavailable``, and the call is denied.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from trellisd.config import DEFAULT_LEVELS, Contract, Tags, TrellisConfig


@dataclass(frozen=True)
class TagSourceInfo:
    """Where a restriction came from, kept in the ledger so decisions can be replayed."""

    source: str
    version: str = ""

    def __str__(self) -> str:
        return f"{self.source} {self.version}".strip()


Provenance = dict[str, tuple[TagSourceInfo, ...]]


def normalize(tags: Iterable[str], levels: Sequence[str]) -> Tags:
    """Keep only the highest level on the scale; other tags pass through."""
    out = set(tags)
    present = [lvl for lvl in levels if lvl in out]
    for lvl in present[:-1]:
        out.discard(lvl)
    return frozenset(out)


@dataclass(frozen=True)
class TableInfo:
    name: str
    tags: Tags
    columns: dict[str, Tags] = field(default_factory=dict)
    #: tag -> the sources that added it (for explanations and replay)
    provenance: Provenance = field(default_factory=dict)
    #: The contract that governs this table, if any.
    contract: str | None = None
    contract_version: str | None = None
    #: Who may declassify or approve access: the contract owner.
    owner: str | None = None
    stale: bool = False
    #: What grants and access rules match on (see the module docstring). None: ``tags``.
    declared: Tags | None = None
    declared_columns: dict[str, Tags] = field(default_factory=dict)
    #: column -> tag -> sources
    column_provenance: dict[str, Provenance] = field(default_factory=dict)
    #: Columns a catalog has that the contract lacks: masked until the owner classifies them.
    drift: frozenset[str] = frozenset()
    #: Owners catalogs report, shown in explanations and never used in decisions.
    catalog_owners: dict[str, str] = field(default_factory=dict)
    levels: tuple[str, ...] = DEFAULT_LEVELS

    @property
    def dataset(self) -> str:
        return self.name.rsplit(".", 1)[0] if "." in self.name else self.name

    @property
    def declared_tags(self) -> Tags:
        return self.tags if self.declared is None else self.declared

    def column_tags(self, column: str) -> Tags:
        """A column carries its own tags plus its table's."""
        return normalize(self.columns.get(column, frozenset()) | self.tags, self.levels)

    def column_declared(self, column: str) -> Tags:
        if self.declared is None:
            return self.column_tags(column)
        own = self.declared_columns.get(column, frozenset())
        return normalize(own | self.declared, self.levels)

    def sources_of(self, column: str, tag: str) -> tuple[TagSourceInfo, ...]:
        own = self.column_provenance.get(column, {}).get(tag, ())
        return own or self.provenance.get(tag, ())


class Catalog(Protocol):
    def table(self, name: str) -> TableInfo | None: ...

    def tables(self) -> list[str]: ...


@dataclass(frozen=True)
class ObservedTags:
    """What one catalog sees on one table, right now."""

    address: str
    tags: Tags
    #: Every column it sees, with the tags it puts on each (often none).
    columns: dict[str, Tags]
    source: TagSourceInfo
    owner: str | None = None
    #: Served from cache because the catalog couldn't be reached (within the bound).
    stale: bool = False


class SourceUnavailable(Exception):
    """A tag source can't answer and has nothing fresh enough cached: deny."""

    def __init__(self, source: str, message: str) -> None:
        super().__init__(message)
        self.source = source


class TagSource(Protocol):
    """A catalog connector: read-only, side-effect free."""

    name: str

    def tags(self, address: str) -> ObservedTags | None: ...

    def addresses(self) -> list[str]: ...


class ConfigCatalog:
    """The ``catalog:`` section of the YAML config. For development and demos."""

    name = "config"

    def __init__(
        self, tables: dict[str, tuple[Tags, dict[str, Tags]]], levels: Sequence[str] = ()
    ) -> None:
        self._tables = tables
        self._levels = tuple(levels) or DEFAULT_LEVELS

    @classmethod
    def from_config(cls, config: TrellisConfig) -> ConfigCatalog:
        return cls({n: (t.tags, dict(t.columns)) for n, t in config.catalog.items()}, config.scale)

    # TagSource

    def tags(self, address: str) -> ObservedTags | None:
        if address not in self._tables:
            return None
        tags, cols = self._tables[address]
        return ObservedTags(address, frozenset(tags), dict(cols), TagSourceInfo("config"))

    def addresses(self) -> list[str]:
        return sorted(self._tables)

    # Catalog (used alone, without contracts)

    def table(self, name: str) -> TableInfo | None:
        return Resolver({}, [self], self._levels).table(name)

    def tables(self) -> list[str]:
        return self.addresses()


def _add(prov: dict[str, list[TagSourceInfo]], tags: Iterable[str], src: TagSourceInfo) -> None:
    for t in tags:
        if src not in prov.setdefault(t, []):
            prov[t].append(src)


class Resolver:
    """Merges contracts and tag sources into one ``TableInfo`` per table (a ``Catalog``)."""

    def __init__(
        self,
        contracts: dict[str, Contract],
        sources: Sequence[TagSource],
        levels: Sequence[str] = DEFAULT_LEVELS,
    ) -> None:
        self.contracts = contracts
        self.sources = list(sources)
        self.levels = tuple(levels)
        self._index: dict[str, Contract] = {}
        for c in contracts.values():
            for b in c.bindings:
                self._index[b] = c

    @classmethod
    def from_config(
        cls, config: TrellisConfig, sources: Sequence[TagSource] | None = None
    ) -> Resolver:
        srcs = list(sources) if sources is not None else [ConfigCatalog.from_config(config)]
        return cls(dict(config.contracts), srcs, config.scale)

    def contract(self, address: str) -> Contract | None:
        return self._index.get(address)

    def tables(self) -> list[str]:
        # Every address a contract binds: tables and MCP tools alike.
        names = {b for c in self.contracts.values() for b in c.bindings}
        for s in self.sources:
            names |= set(s.addresses())
        return sorted(names)

    def evict(self, address: str | None = None) -> None:
        for s in self.sources:
            ev = getattr(s, "evict", None)
            if ev is not None:
                ev(address)

    def table(self, name: str) -> TableInfo | None:
        contract = self._index.get(name)
        observed = [o for o in (s.tags(name) for s in self.sources) if o is not None]
        if contract is None and not observed:
            return None
        prov: dict[str, list[TagSourceInfo]] = {}
        colprov: dict[str, dict[str, list[TagSourceInfo]]] = {}
        columns: dict[str, set[str]] = {}

        if contract is not None:
            csrc = TagSourceInfo(f"contract {contract.contract}", contract.version_id)
            _add(prov, contract.tags, csrc)
            for col, ctags in contract.elements.items():
                columns.setdefault(col, set()).update(ctags)
                _add(colprov.setdefault(col, {}), ctags, csrc)
        for o in observed:
            _add(prov, o.tags, o.source)
            for col, otags in o.columns.items():
                columns.setdefault(col, set()).update(otags)
                _add(colprov.setdefault(col, {}), otags, o.source)

        tags = normalize(prov, self.levels)
        if contract is not None:
            declared = normalize(contract.tags, self.levels)
            declared_columns = {c: frozenset(t) for c, t in contract.elements.items()}
            seen = {c for o in observed for c in o.columns}
            drift = frozenset(seen - set(contract.elements))
        else:
            declared = normalize(frozenset.intersection(*(o.tags for o in observed)), self.levels)
            declared_columns = {}
            for col in columns:
                having = [o.columns[col] for o in observed if col in o.columns]
                declared_columns[col] = frozenset.intersection(*having) if having else frozenset()
            drift = frozenset()

        return TableInfo(
            name=name,
            tags=tags,
            columns={c: frozenset(t) for c, t in columns.items()},
            provenance={t: tuple(prov[t]) for t in sorted(tags)},
            contract=contract.contract if contract else None,
            contract_version=contract.version_id if contract else None,
            owner=contract.owner if contract else None,
            stale=any(o.stale for o in observed),
            declared=declared,
            declared_columns=declared_columns,
            column_provenance={
                c: {t: tuple(s) for t, s in sorted(p.items())} for c, p in sorted(colprov.items())
            },
            drift=drift,
            catalog_owners={o.source.source: o.owner for o in observed if o.owner},
            levels=self.levels,
        )


# -- snapshots, for replay -------------------------------------------------------------------


def _prov_json(p: Provenance) -> dict[str, list[dict[str, str]]]:
    return {
        tag: [{"source": s.source, "version": s.version} for s in srcs]
        for tag, srcs in sorted(p.items())
    }


def _prov_from(body: dict[str, Any]) -> Provenance:
    return {
        tag: tuple(TagSourceInfo(s["source"], s.get("version", "")) for s in srcs)
        for tag, srcs in body.items()
    }


def table_snapshot(info: TableInfo) -> dict[str, Any]:
    """What the ledger keeps of a table's classification at decision time (for replay)."""
    return {
        "name": info.name,
        "tags": sorted(info.tags),
        "columns": {c: sorted(t) for c, t in sorted(info.columns.items())},
        "provenance": _prov_json(info.provenance),
        "contract": info.contract,
        "contract_version": info.contract_version,
        "owner": info.owner,
        "stale": info.stale,
        "declared": None if info.declared is None else sorted(info.declared),
        "declared_columns": {c: sorted(t) for c, t in sorted(info.declared_columns.items())},
        "column_provenance": {c: _prov_json(p) for c, p in sorted(info.column_provenance.items())},
        "drift": sorted(info.drift),
        "catalog_owners": dict(sorted(info.catalog_owners.items())),
        "levels": list(info.levels),
    }


def table_from_snapshot(body: dict[str, Any]) -> TableInfo:
    declared = body.get("declared")
    return TableInfo(
        name=body["name"],
        tags=frozenset(body["tags"]),
        columns={c: frozenset(t) for c, t in body["columns"].items()},
        provenance=_prov_from(body.get("provenance", {})),
        contract=body.get("contract"),
        contract_version=body.get("contract_version"),
        owner=body.get("owner"),
        stale=bool(body.get("stale", False)),
        declared=None if declared is None else frozenset(declared),
        declared_columns={c: frozenset(t) for c, t in body.get("declared_columns", {}).items()},
        column_provenance={c: _prov_from(p) for c, p in body.get("column_provenance", {}).items()},
        drift=frozenset(body.get("drift", [])),
        catalog_owners=dict(body.get("catalog_owners", {})),
        levels=tuple(body.get("levels") or DEFAULT_LEVELS),
    )


class SnapshotCatalog:
    """Tables exactly as a past decision saw them, for replay."""

    def __init__(self, tables: list[TableInfo]) -> None:
        self._tables = {t.name: t for t in tables}

    def table(self, name: str) -> TableInfo | None:
        return self._tables.get(name)

    def tables(self) -> list[str]:
        return sorted(self._tables)
