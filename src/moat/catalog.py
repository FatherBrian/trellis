"""Where Moat learns what data is tagged with and what humans may see.

Moat does not own data classification or identity. It reads tags from a catalog
(Unity Catalog OSS first, with a YAML file as the fallback) and a human's
clearances from the same source or an IdP.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol, runtime_checkable

import yaml
from pydantic import BaseModel, ConfigDict

Tags = frozenset[str]


class Column(BaseModel):
    """A column and the data tags on it, such as ``pii`` or ``export_controlled``."""

    model_config = ConfigDict(frozen=True)

    name: str
    tags: Tags = frozenset()


class Resource(BaseModel):
    """A table (or other addressable dataset) with its own tags and its columns."""

    model_config = ConfigDict(frozen=True)

    name: str
    tags: Tags = frozenset()
    columns: tuple[Column, ...] = ()

    def column(self, name: str) -> Column | None:
        return next((c for c in self.columns if c.name == name), None)


class Human(BaseModel):
    """A delegating person: their group memberships and the tags they are cleared for."""

    model_config = ConfigDict(frozen=True)

    id: str
    groups: Tags = frozenset()
    clearances: Tags = frozenset()


@runtime_checkable
class Catalog(Protocol):
    """Read-only view of data tags and human access. Implementations must be side-effect free."""

    def resource(self, name: str) -> Resource | None: ...

    def human(self, human_id: str) -> Human | None: ...


class YamlCatalog:
    """Catalog backed by a YAML file. Used by tests, the demo, and teams without a catalog.

    Format::

        humans:
          alice@example.com:
            groups: [finance-analysts]
            clearances: [finance, pii]
        resources:
          finance.gl.journal_entries:
            tags: [finance]
            columns:
              amount: [finance]
              approver_email: [finance, pii]
    """

    def __init__(self, resources: dict[str, Resource], humans: dict[str, Human]) -> None:
        self._resources = resources
        self._humans = humans

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> YamlCatalog:
        resources: dict[str, Resource] = {}
        for name, spec in (raw.get("resources") or {}).items():
            spec = spec or {}
            columns = tuple(
                Column(name=col, tags=frozenset(tags or ()))
                for col, tags in (spec.get("columns") or {}).items()
            )
            resources[name] = Resource(
                name=name, tags=frozenset(spec.get("tags") or ()), columns=columns
            )
        humans = {
            hid: Human(
                id=hid,
                groups=frozenset((spec or {}).get("groups") or ()),
                clearances=frozenset((spec or {}).get("clearances") or ()),
            )
            for hid, spec in (raw.get("humans") or {}).items()
        }
        return cls(resources, humans)

    @classmethod
    def from_file(cls, path: str | Path) -> YamlCatalog:
        with Path(path).open(encoding="utf-8") as fh:
            return cls.from_dict(yaml.safe_load(fh) or {})

    def resource(self, name: str) -> Resource | None:
        return self._resources.get(name)

    def human(self, human_id: str) -> Human | None:
        return self._humans.get(human_id)


class UnityCatalogOSS:
    """Catalog adapter for Unity Catalog OSS.

    TODO(week 3): read table and column tags through the Unity Catalog OSS REST API,
    cache them with a short TTL, and resolve human clearances from grants in the
    catalog or from the IdP. Keep this read-only.
    """

    def __init__(self, base_url: str, token: str | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self._token = token

    def resource(self, name: str) -> Resource | None:
        raise NotImplementedError("Unity Catalog OSS adapter lands in week 3")

    def human(self, human_id: str) -> Human | None:
        raise NotImplementedError("Unity Catalog OSS adapter lands in week 3")
