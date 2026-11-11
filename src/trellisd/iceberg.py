"""Tags from an Iceberg REST catalog: read-only, cached, and fail closed.

The Iceberg REST protocol carries table properties, not tags, so Trellis reads tags from a
property naming convention (configurable per catalog)::

    trellis.tags                         = finance, confidential    (the table)
    trellis.column.approver_email.tags   = pii                      (one column)

The same adapter reaches any catalog that serves the Iceberg REST API: Apache Polaris,
Unity Catalog, AWS Glue, Nessie and the Iceberg reference server. It only ever reads
(``GET /v1/config`` and ``loadTable``), and it never writes.

Caching follows the plan: answers are kept for ``ttl_seconds`` (a table that isn't there
for ``not_found_ttl_seconds``). If the catalog can't be reached, a cached answer younger
than ``stale_after_seconds`` is used and marked stale; past that, or with nothing cached,
the source raises ``SourceUnavailable`` and the call is denied.

``IcebergRestAdmin`` is a small writing client for demos and tests (create a table, tag a
column, add a column); Trellis itself never uses it.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from trellisd.catalog import ObservedTags, SourceUnavailable, TagSourceInfo
from trellisd.config import CatalogSource

#: A function that performs one HTTP request: (method, url, headers, body) ->
#: (status, body). Swappable so tests can replay recorded responses.
Transport = Callable[[str, str, dict[str, str], bytes | None], tuple[int, bytes]]


def urllib_transport(timeout: float = 5.0) -> Transport:
    def send(
        method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> tuple[int, bytes]:
        req = urllib.request.Request(url, data=body, method=method, headers=headers)  # noqa: S310
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    return send


def split_address(address: str) -> tuple[list[str], str]:
    if "." not in address:
        raise ValueError(f"{address} isn't namespace.table")
    ns, table = address.rsplit(".", 1)
    return ns.split("."), table


def _ns_path(namespace: list[str]) -> str:
    # Multi-level namespaces are joined with the unit separator, then URL-encoded.
    return urllib.parse.quote("\x1f".join(namespace), safe="")


def _split_tags(value: str | None) -> frozenset[str]:
    if not value:
        return frozenset()
    return frozenset(t.strip().lower() for t in value.split(",") if t.strip())


@dataclass
class _Entry:
    value: ObservedTags | None
    fetched: float


class _Client:
    def __init__(
        self, uri: str, warehouse: str | None, token: str | None, transport: Transport | None
    ) -> None:
        self.uri = uri.rstrip("/")
        self.warehouse = warehouse
        self.token = token
        self.transport = transport or urllib_transport()
        self._prefix: str | None = None

    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def request(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        data = json.dumps(body).encode() if body is not None else None
        try:
            status, raw = self.transport(method, self.uri + path, self._headers(), data)
        except (OSError, urllib.error.URLError) as exc:
            raise ConnectionError(str(getattr(exc, "reason", exc))) from exc
        try:
            parsed = json.loads(raw) if raw else None
        except ValueError:
            parsed = None
        return status, parsed

    def prefix(self) -> str:
        if self._prefix is None:
            query = f"?warehouse={urllib.parse.quote(self.warehouse)}" if self.warehouse else ""
            status, body = self.request("GET", f"/v1/config{query}")
            if status != 200 or not isinstance(body, dict):
                raise ConnectionError(f"GET /v1/config answered {status}")
            overrides = body.get("overrides") or {}
            defaults = body.get("defaults") or {}
            prefix = overrides.get("prefix") or defaults.get("prefix") or ""
            self._prefix = f"/{prefix}" if prefix else ""
        return self._prefix

    def table_path(self, address: str) -> str:
        ns, table = split_address(address)
        return f"/v1{self.prefix()}/namespaces/{_ns_path(ns)}/tables/{urllib.parse.quote(table)}"


class IcebergRestTagSource:
    """A ``TagSource`` reading one Iceberg REST catalog."""

    def __init__(
        self,
        name: str,
        settings: CatalogSource,
        *,
        transport: Transport | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.name = name
        self.settings = settings
        token = os.environ.get(settings.token_env) if settings.token_env else None
        self.client = _Client(settings.uri, settings.warehouse, token, transport)
        self.clock = clock
        self._cache: dict[str, _Entry] = {}

    # -- TagSource -------------------------------------------------------------------------

    def addresses(self) -> list[str]:
        return []

    def covers(self, address: str) -> bool:
        if not self.settings.namespaces:
            return "." in address
        return any(address.startswith(ns + ".") for ns in self.settings.namespaces)

    def tags(self, address: str) -> ObservedTags | None:
        if not self.covers(address):
            return None
        now = self.clock()
        entry = self._cache.get(address)
        if entry is not None:
            ttl = (
                self.settings.ttl_seconds
                if entry.value is not None
                else self.settings.not_found_ttl_seconds
            )
            if now - entry.fetched < ttl:
                return entry.value
        try:
            value = self._fetch(address)
        except ConnectionError as exc:
            if entry is not None and now - entry.fetched <= self.settings.stale_after_seconds:
                if entry.value is None:
                    return None
                return ObservedTags(
                    address=entry.value.address,
                    tags=entry.value.tags,
                    columns=entry.value.columns,
                    source=entry.value.source,
                    owner=entry.value.owner,
                    stale=True,
                )
            age = (
                f"for {int((now - entry.fetched) // 60)} minutes"
                if entry is not None
                else "and nothing is cached"
            )
            raise SourceUnavailable(
                self.name,
                f"catalog {self.name} can't be reached ({exc}) {age}, past the"
                f" {int(self.settings.stale_after_seconds // 60)}-minute staleness bound",
            ) from exc
        self._cache[address] = _Entry(value, now)
        return value

    def evict(self, address: str | None = None) -> None:
        """Forget cached answers (all, or one table's): a pushed change applies at once."""
        if address is None:
            self._cache.clear()
        else:
            self._cache.pop(address, None)

    # -- reading ---------------------------------------------------------------------------

    def _fetch(self, address: str) -> ObservedTags | None:
        status, body = self.client.request("GET", self.client.table_path(address))
        if status == 404:
            return None
        if status != 200 or not isinstance(body, dict):
            raise ConnectionError(f"loadTable answered {status}")
        return observed_from_load_table(address, body, self.name, self.settings)


def observed_from_load_table(
    address: str, body: dict[str, Any], source: str, settings: CatalogSource
) -> ObservedTags:
    """Turn a ``LoadTableResult`` into the tags Trellis needs."""
    meta = body.get("metadata") or {}
    props: dict[str, str] = meta.get("properties") or {}
    schema_id = meta.get("current-schema-id")
    schemas = meta.get("schemas") or []
    schema = next((s for s in schemas if s.get("schema-id") == schema_id), None)
    if schema is None and schemas:
        schema = schemas[-1]
    columns: dict[str, frozenset[str]] = {}
    for f in (schema or {}).get("fields", []):
        col = str(f["name"])
        columns[col] = _split_tags(props.get(settings.column_property.format(column=col)))
    location = str(body.get("metadata-location") or "")
    # The metadata file's sequence number and the start of its id: 00003-47a78f6c.
    version = location.rsplit("/", 1)[-1].removesuffix(".metadata.json")[:14] or str(
        meta.get("last-updated-ms", "")
    )
    return ObservedTags(
        address=address,
        tags=_split_tags(props.get(settings.tag_property)),
        columns=columns,
        source=TagSourceInfo(f"catalog {source}", version),
        owner=props.get("owner"),
    )


class IcebergRestAdmin:
    """Writes to an Iceberg REST catalog, for demos and tests. Trellis never calls this."""

    def __init__(
        self,
        uri: str,
        *,
        warehouse: str | None = None,
        token: str | None = None,
        transport: Transport | None = None,
    ) -> None:
        self.client = _Client(uri, warehouse, token, transport)

    def _ok(self, what: str, status: int, body: Any) -> Any:
        if status >= 300:
            msg = (body or {}).get("error", {}).get("message", "") if isinstance(body, dict) else ""
            raise RuntimeError(f"{what}: {status} {msg}".strip())
        return body

    def create_namespace(self, namespace: str) -> None:
        parts = namespace.split(".")
        for i in range(1, len(parts) + 1):
            status, body = self.client.request(
                "POST", f"/v1{self.client.prefix()}/namespaces", {"namespace": parts[:i]}
            )
            if status != 409:
                self._ok(f"create namespace {'.'.join(parts[:i])}", status, body)

    def create_table(
        self, address: str, columns: dict[str, str], properties: dict[str, str] | None = None
    ) -> Any:
        ns, table = split_address(address)
        fields = [
            {"id": i, "name": name, "required": False, "type": typ}
            for i, (name, typ) in enumerate(columns.items(), start=1)
        ]
        body = {
            "name": table,
            "schema": {"type": "struct", "schema-id": 0, "fields": fields},
            "properties": properties or {},
        }
        status, out = self.client.request(
            "POST", f"/v1{self.client.prefix()}/namespaces/{_ns_path(ns)}/tables", body
        )
        return self._ok(f"create table {address}", status, out)

    def load_table(self, address: str) -> Any:
        status, out = self.client.request("GET", self.client.table_path(address))
        return self._ok(f"load table {address}", status, out)

    def drop_table(self, address: str) -> None:
        self.client.request("DELETE", self.client.table_path(address))

    def set_properties(self, address: str, updates: dict[str, str]) -> Any:
        return self._commit(address, [{"action": "set-properties", "updates": updates}])

    def remove_properties(self, address: str, removals: list[str]) -> Any:
        return self._commit(address, [{"action": "remove-properties", "removals": removals}])

    def tag_table(self, address: str, *tags: str) -> Any:
        return self.set_properties(address, {"trellis.tags": ",".join(tags)})

    def tag_column(self, address: str, column: str, *tags: str) -> Any:
        return self.set_properties(address, {f"trellis.column.{column}.tags": ",".join(tags)})

    def add_column(self, address: str, name: str, typ: str = "string") -> Any:
        meta = self.load_table(address)["metadata"]
        current = meta["current-schema-id"]
        schema = next(s for s in meta["schemas"] if s["schema-id"] == current)
        new_id = int(meta["last-column-id"]) + 1
        new_schema = {
            "type": "struct",
            "schema-id": current + 1,
            "fields": [
                *schema["fields"],
                {"id": new_id, "name": name, "required": False, "type": typ},
            ],
        }
        return self._commit(
            address,
            [
                {"action": "add-schema", "schema": new_schema, "last-column-id": new_id},
                {"action": "set-current-schema", "schema-id": -1},
            ],
            [{"type": "assert-current-schema-id", "current-schema-id": current}],
        )

    def _commit(
        self, address: str, updates: list[dict[str, Any]], requirements: list[Any] | None = None
    ) -> Any:
        status, out = self.client.request(
            "POST",
            self.client.table_path(address),
            {"requirements": requirements or [], "updates": updates},
        )
        return self._ok(f"update {address}", status, out)
