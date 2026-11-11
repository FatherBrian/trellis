"""What Trellis knows about data: tables, their tags and their columns' tags.

In M1 the catalog comes from the YAML config. M3 adds contracts and the Iceberg REST
catalog behind the same ``Catalog`` protocol, merged by the resolver.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from trellisd.config import Tags, TrellisConfig


@dataclass(frozen=True)
class TagSourceInfo:
    """Where a restriction came from, kept in the ledger so decisions can be replayed."""

    source: str
    version: str = ""


@dataclass(frozen=True)
class TableInfo:
    name: str
    tags: Tags
    columns: dict[str, Tags] = field(default_factory=dict)
    #: tag -> the sources that added it (for explanations and replay)
    provenance: dict[str, tuple[TagSourceInfo, ...]] = field(default_factory=dict)
    #: The contract that governs this table, if any (M3).
    contract: str | None = None
    contract_version: str | None = None
    #: Who may declassify or approve access: the contract owner (M3).
    owner: str | None = None
    stale: bool = False

    @property
    def dataset(self) -> str:
        return self.name.rsplit(".", 1)[0] if "." in self.name else self.name

    def column_tags(self, column: str) -> Tags:
        """A column carries its own tags plus its table's."""
        return frozenset(self.columns.get(column, frozenset())) | self.tags


class Catalog(Protocol):
    def table(self, name: str) -> TableInfo | None: ...

    def tables(self) -> list[str]: ...


def table_snapshot(info: TableInfo) -> dict[str, Any]:
    """What the ledger keeps of a table's classification at decision time (for replay)."""
    return {
        "name": info.name,
        "tags": sorted(info.tags),
        "columns": {c: sorted(t) for c, t in sorted(info.columns.items())},
        "provenance": {
            tag: [{"source": s.source, "version": s.version} for s in srcs]
            for tag, srcs in sorted(info.provenance.items())
        },
        "contract": info.contract,
        "contract_version": info.contract_version,
        "owner": info.owner,
        "stale": info.stale,
    }


def table_from_snapshot(body: dict[str, Any]) -> TableInfo:
    return TableInfo(
        name=body["name"],
        tags=frozenset(body["tags"]),
        columns={c: frozenset(t) for c, t in body["columns"].items()},
        provenance={
            tag: tuple(TagSourceInfo(s["source"], s.get("version", "")) for s in srcs)
            for tag, srcs in body.get("provenance", {}).items()
        },
        contract=body.get("contract"),
        contract_version=body.get("contract_version"),
        owner=body.get("owner"),
        stale=bool(body.get("stale", False)),
    )


class SnapshotCatalog:
    """Tables exactly as a past decision saw them, for replay."""

    def __init__(self, tables: list[TableInfo]) -> None:
        self._tables = {t.name: t for t in tables}

    def table(self, name: str) -> TableInfo | None:
        return self._tables.get(name)

    def tables(self) -> list[str]:
        return sorted(self._tables)


class ConfigCatalog:
    """The ``catalog:`` section of the YAML config. For development and demos."""

    def __init__(self, tables: dict[str, tuple[Tags, dict[str, Tags]]]) -> None:
        self._tables = tables

    @classmethod
    def from_config(cls, config: TrellisConfig) -> ConfigCatalog:
        return cls({n: (t.tags, dict(t.columns)) for n, t in config.catalog.items()})

    def table(self, name: str) -> TableInfo | None:
        if name not in self._tables:
            return None
        tags, cols = self._tables[name]
        src: tuple[TagSourceInfo, ...] = (TagSourceInfo("config"),)
        prov = {t: src for t in tags}
        return TableInfo(name=name, tags=frozenset(tags), columns=cols, provenance=prov)

    def tables(self) -> list[str]:
        return sorted(self._tables)
