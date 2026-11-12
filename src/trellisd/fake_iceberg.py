"""A small in-process Iceberg REST catalog, for demos and tests that run without Docker.

It speaks the part of the Iceberg REST protocol Trellis reads and the demo writes:
``GET /v1/config``, create namespace, create and load table, and commits with
``set-properties``, ``remove-properties``, ``add-schema`` and ``set-current-schema``. The
responses have the shape the Iceberg reference server returns (see the recorded
responses under ``tests/fixtures/iceberg``). It keeps metadata only: there are no data
files.

    with FakeIcebergCatalog() as catalog:
        uri = catalog.uri          # http://127.0.0.1:<port>
        catalog.down()             # every request now fails, as if the catalog were down
"""

from __future__ import annotations

import json
import threading
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class FakeIcebergCatalog:
    def __init__(self, prefix: str = "") -> None:
        self.prefix = prefix
        self.namespaces: set[tuple[str, ...]] = set()
        self.tables: dict[tuple[tuple[str, ...], str], dict[str, Any]] = {}
        self._up = True
        self._lock = threading.Lock()
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        self._thread.start()

    @property
    def uri(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host!s}:{port}"

    def down(self) -> None:
        self._up = False

    def up(self) -> None:
        self._up = True

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def __enter__(self) -> FakeIcebergCatalog:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- the protocol ----------------------------------------------------------------------

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        catalog = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                return

            def _send(self, status: int, body: Any) -> None:
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _body(self) -> Any:
                n = int(self.headers.get("Content-Length") or 0)
                return json.loads(self.rfile.read(n)) if n else None

            def _route(self, method: str) -> None:
                if not catalog._up:
                    self.send_response(503)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                path = urllib.parse.urlsplit(self.path).path
                with catalog._lock:
                    status, body = catalog._dispatch(method, path, self._body())
                self._send(status, body)

            def do_GET(self) -> None:
                self._route("GET")

            def do_POST(self) -> None:
                self._route("POST")

            def do_DELETE(self) -> None:
                self._route("DELETE")

        return Handler

    @staticmethod
    def _error(status: int, kind: str, message: str) -> tuple[int, Any]:
        return status, {"error": {"message": message, "type": kind, "code": status}}

    def _dispatch(self, method: str, path: str, body: Any) -> tuple[int, Any]:
        parts = [urllib.parse.unquote(p) for p in path.strip("/").split("/")]
        if parts[:2] == ["v1", "config"]:
            overrides = {"prefix": self.prefix} if self.prefix else {}
            return 200, {"defaults": {}, "overrides": overrides, "endpoints": []}
        if parts[:1] != ["v1"]:
            return self._error(404, "NotFound", path)
        rest = parts[1:]
        if self.prefix:
            if not rest or rest[0] != self.prefix:
                return self._error(404, "NotFound", path)
            rest = rest[1:]
        if rest == ["namespaces"] and method == "POST":
            ns = tuple(body["namespace"])
            if ns in self.namespaces:
                return self._error(409, "AlreadyExistsException", f"Namespace exists: {ns}")
            self.namespaces.add(ns)
            return 200, {"namespace": list(ns), "properties": {}}
        if len(rest) >= 3 and rest[0] == "namespaces" and rest[2] == "tables":
            ns = tuple(rest[1].split("\x1f"))
            if ns not in self.namespaces:
                return self._error(
                    404, "NoSuchNamespaceException", f"Namespace does not exist: {'.'.join(ns)}"
                )
            if len(rest) == 3 and method == "POST":
                return self._create(ns, body)
            if len(rest) == 4:
                key = (ns, rest[3])
                if key not in self.tables:
                    return self._error(
                        404,
                        "NoSuchTableException",
                        f"Table does not exist: {'.'.join(ns)}.{rest[3]}",
                    )
                if method == "GET":
                    return 200, self._result(key)
                if method == "POST":
                    return self._commit(key, body)
                if method == "DELETE":
                    del self.tables[key]
                    return 204, None
        return self._error(404, "NotFound", path)

    def _create(self, ns: tuple[str, ...], body: dict[str, Any]) -> tuple[int, Any]:
        key = (ns, body["name"])
        if key in self.tables:
            return self._error(409, "AlreadyExistsException", f"Table already exists: {key}")
        schema = dict(body["schema"])
        schema.setdefault("schema-id", 0)
        location = f"file:///warehouse/{'/'.join(ns)}/{body['name']}"
        self.tables[key] = {
            "n": 0,
            "location": location,
            "metadata": {
                "format-version": 2,
                "table-uuid": str(uuid.uuid4()),
                "location": location,
                "last-sequence-number": 0,
                "last-updated-ms": int(time.time() * 1000),
                "last-column-id": max((f["id"] for f in schema["fields"]), default=0),
                "current-schema-id": schema["schema-id"],
                "schemas": [schema],
                "default-spec-id": 0,
                "partition-specs": [{"spec-id": 0, "fields": []}],
                "last-partition-id": 999,
                "default-sort-order-id": 0,
                "sort-orders": [{"order-id": 0, "fields": []}],
                "properties": {
                    **(body.get("properties") or {}),
                    "write.parquet.compression-codec": "zstd",
                },
                "current-snapshot-id": -1,
                "refs": {},
                "snapshots": [],
                "statistics": [],
                "partition-statistics": [],
                "snapshot-log": [],
                "metadata-log": [],
            },
        }
        return 200, self._result(key)

    def _result(self, key: tuple[tuple[str, ...], str]) -> dict[str, Any]:
        t = self.tables[key]
        version = uuid.uuid5(uuid.NAMESPACE_URL, t["location"] + str(t["n"]))
        loc = f"{t['location']}/metadata/{t['n']:05d}-{version}.metadata.json"
        return {"metadata-location": loc, "metadata": t["metadata"]}

    def _commit(self, key: tuple[tuple[str, ...], str], body: dict[str, Any]) -> tuple[int, Any]:
        t = self.tables[key]
        meta = t["metadata"]
        for req in body.get("requirements") or []:
            if (
                req.get("type") == "assert-current-schema-id"
                and req["current-schema-id"] != meta["current-schema-id"]
            ):
                return self._error(409, "CommitFailedException", "schema changed")
        last_added: int | None = None
        for u in body.get("updates") or []:
            action = u["action"]
            if action == "set-properties":
                meta["properties"].update(u["updates"])
            elif action == "remove-properties":
                for k in u["removals"]:
                    meta["properties"].pop(k, None)
            elif action == "add-schema":
                meta["schemas"].append(u["schema"])
                last_added = u["schema"]["schema-id"]
                meta["last-column-id"] = u.get("last-column-id", meta["last-column-id"])
            elif action == "set-current-schema":
                sid = u["schema-id"]
                meta["current-schema-id"] = last_added if sid == -1 else sid
            else:
                return self._error(400, "BadRequestException", f"unsupported update {action}")
        meta["last-updated-ms"] = int(time.time() * 1000)
        t["n"] += 1
        return 200, self._result(key)
