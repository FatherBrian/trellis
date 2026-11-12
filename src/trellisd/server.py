"""The decision server: AuthZEN evaluation and the sign-in token endpoint.

``trellisd serve`` answers three things over HTTP, all from the same ``Trellis`` object an
application can embed (Reef calls the same code in process):

``POST /access/v1/evaluation``
    The OpenID AuthZEN Authorization API 1.0 evaluation endpoint. The caller sends the
    grant token as a bearer token (or as ``subject.properties.token``); the subject is the
    agent, the resource a table or tool address, the action a verb. Every decision is in
    the ledger before the answer goes out. The response carries ``decision`` and a
    ``context`` with the reason, Trellis's obligations profile (masks and row filter),
    which check denied, and the ledger event id.

``GET /.well-known/authzen-configuration``
    The AuthZEN discovery document.

``POST /token``
    RFC 8693 token exchange, Trellis as the broker: the person's token from their IdP as
    ``subject_token``, the agent's own as ``actor_token``, the grant scope as ``scope`` and
    the task as ``task`` (a Trellis parameter). The answer's ``access_token`` is a grant
    token. A process agent sends only its own token, with ``purpose`` and
    ``trigger_record``, for a purpose run.

It uses the standard library's threaded HTTP server: v0.1 is one process, and the ledger
write serializes decisions anyway.
"""

from __future__ import annotations

import json
import threading
import urllib.parse
from collections.abc import Mapping
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from trellisd.app import Trellis
from trellisd.engine import Decision
from trellisd.grants import GrantError, utcnow

OBLIGATIONS_PROFILE = "trellis-obligations-v1"
TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"  # noqa: S105 (a grant type)
ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"  # noqa: S105 (a token type)


class RequestError(ValueError):
    """A request that isn't a well-formed AuthZEN evaluation (HTTP 400)."""


def _entity(body: Mapping[str, Any], key: str, id_key: str) -> dict[str, Any]:
    value = body.get(key)
    if not isinstance(value, dict):
        raise RequestError(f"{key} is required and must be an object")
    for name in ("type", id_key) if key != "action" else (id_key,):
        if not isinstance(value.get(name), str) or not value[name]:
            raise RequestError(f"{key}.{name} is required and must be a string")
    if not isinstance(value.get("properties", {}), dict):
        raise RequestError(f"{key}.properties must be an object")
    return value


def parse_evaluation(
    body: Any, bearer: str | None = None
) -> tuple[str, str, str, list[str] | None, str]:
    """(token, agent, action, columns, resource) from an AuthZEN evaluation request."""
    if not isinstance(body, dict):
        raise RequestError("the request body must be a JSON object")
    subject = _entity(body, "subject", "id")
    resource = _entity(body, "resource", "id")
    action = _entity(body, "action", "name")
    sprops = subject.get("properties", {})
    rprops = resource.get("properties", {})
    token = bearer or sprops.get("token") or ""
    columns = rprops.get("columns", rprops.get("elements"))
    if columns is not None and (
        not isinstance(columns, list) or not all(isinstance(c, str) for c in columns)
    ):
        raise RequestError("resource.properties.columns must be a list of strings")
    return str(token), subject["id"], action["name"], columns, resource["id"]


def evaluation_response(d: Decision) -> dict[str, Any]:
    """The AuthZEN response for a decision, with Trellis's obligations profile."""
    return {
        "decision": d.allowed,
        "context": {
            "id": d.event_id,
            "reason_admin": {"en": d.reason},
            "trellis": {
                "profile": OBLIGATIONS_PROFILE,
                "event_id": d.event_id,
                "grant_id": d.grant_id,
                "on_behalf_of": d.subject,
                "obligations": d.obligations if d.allowed else {},
                "denied_by": list(d.denied_by),
                "checks": [
                    {
                        "check": c.name,
                        "label": c.label,
                        "allowed": c.allowed,
                        "reason": c.reason,
                        "policies": list(c.policies),
                    }
                    for c in d.checks
                ],
                "contract": d.contract,
                "contract_version": d.contract_version,
                "stale": d.stale,
            },
        },
    }


def evaluate(trellis: Trellis, body: Any, bearer: str | None = None) -> dict[str, Any]:
    """One AuthZEN evaluation, in process: what ``POST /access/v1/evaluation`` returns."""
    token, agent, action, columns, resource = parse_evaluation(body, bearer)
    d = trellis.authorize(token, action, resource, columns, agent=agent)
    return evaluation_response(d)


def discovery(base: str) -> dict[str, Any]:
    return {
        "policy_decision_point": base,
        "access_evaluation_endpoint": f"{base}/access/v1/evaluation",
        "trellis_token_endpoint": f"{base}/token",
        "trellis_obligations_profile": OBLIGATIONS_PROFILE,
    }


def token_exchange(trellis: Trellis, form: Mapping[str, str]) -> tuple[int, dict[str, Any]]:
    """``POST /token``: RFC 8693 with Trellis as the broker. Errors follow RFC 6749."""

    def error(code: str, why: str) -> tuple[int, dict[str, Any]]:
        return 400, {"error": code, "error_description": why}

    if form.get("grant_type") != TOKEN_EXCHANGE:
        return error("unsupported_grant_type", f"use grant_type={TOKEN_EXCHANGE}")
    subject = form.get("subject_token", "")
    if not subject:
        return error("invalid_request", "subject_token is required")
    try:
        ttl = timedelta(seconds=int(form.get("expires_in", "3600")))
    except ValueError:
        return error("invalid_request", "expires_in must be a number of seconds")
    try:
        if form.get("actor_token"):
            scope = form.get("scope", "").split()
            if not scope:
                return error("invalid_scope", "scope must name the grant's tags")
            issued = trellis.sign_in(
                subject_token=subject,
                actor_token=form["actor_token"],
                task=form.get("task", ""),
                scope=scope,
                actions=tuple(form.get("actions", "read query").split()),
                ttl=ttl,
            )
        elif form.get("purpose"):
            issued = trellis.sign_in_run(
                token=subject,
                purpose=form["purpose"],
                record=form.get("trigger_record", ""),
                ttl=ttl,
            )
        else:
            return error(
                "invalid_request",
                "send the agent's token as actor_token (or purpose, for a process agent)",
            )
    except GrantError as exc:
        return error("invalid_grant", str(exc))
    g = issued.grant
    return 200, {
        "access_token": issued.token,
        "issued_token_type": ACCESS_TOKEN,
        "token_type": "Bearer",
        "expires_in": max(0, int((g.expires_at - utcnow()).total_seconds())),
        "scope": " ".join(sorted(g.scope)),
        "grant_id": g.id,
    }


class TrellisServer:
    """``trellisd serve`` in a thread: ``with TrellisServer(trellis) as s: s.uri``."""

    def __init__(self, trellis: Trellis, host: str = "127.0.0.1", port: int = 0) -> None:
        self.trellis = trellis
        self._lock = threading.Lock()
        self._server = ThreadingHTTPServer((host, port), self._handler())
        self._thread: threading.Thread | None = None

    @property
    def uri(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host!s}:{port}"

    def start(self) -> TrellisServer:
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        self._thread.start()
        return self

    def serve_forever(self) -> None:
        self._server.serve_forever()

    def close(self) -> None:
        if self._thread is not None:
            self._server.shutdown()
        self._server.server_close()

    def __enter__(self) -> TrellisServer:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        srv = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "trellisd"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def _send(self, status: int, body: Any) -> None:
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                rid = self.headers.get("X-Request-ID")
                if rid:
                    self.send_header("X-Request-ID", rid)
                if self.path == "/token":
                    self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(data)

            def _raw(self) -> bytes:
                n = int(self.headers.get("Content-Length") or 0)
                return self.rfile.read(n) if n else b""

            def do_GET(self) -> None:
                path = urllib.parse.urlsplit(self.path).path
                if path == "/.well-known/authzen-configuration":
                    self._send(200, discovery(srv.uri))
                elif path == "/healthz":
                    self._send(200, {"ok": True})
                else:
                    self._send(404, {"error": "not_found"})

            def do_POST(self) -> None:
                path = urllib.parse.urlsplit(self.path).path
                raw = self._raw()
                if path == "/access/v1/evaluation":
                    auth = self.headers.get("Authorization", "")
                    bearer = auth[7:].strip() if auth.lower().startswith("bearer ") else None
                    try:
                        body = json.loads(raw or b"null")
                        with srv._lock:
                            out = evaluate(srv.trellis, body, bearer)
                    except (ValueError, RequestError) as exc:
                        self._send(400, {"error": "bad_request", "message": str(exc)})
                        return
                    self._send(200, out)
                elif path == "/token":
                    form = {k: v[0] for k, v in urllib.parse.parse_qs(raw.decode()).items()}
                    with srv._lock:
                        status, out = token_exchange(srv.trellis, form)
                    self._send(status, out)
                else:
                    self._send(404, {"error": "not_found"})

        return Handler


def serve(trellis: Trellis, host: str = "127.0.0.1", port: int = 8180) -> None:
    server = TrellisServer(trellis, host, port)
    try:
        server.serve_forever()
    finally:
        server.close()
