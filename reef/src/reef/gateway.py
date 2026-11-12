"""Reef's door: the grant-shaped tool list, and a call decided and recorded before it goes.

``Reef`` holds no MCP plumbing of its own (``reef.server`` puts it behind MCP), so the
whole flow is testable in process:

``list_tools(token)``
    Every tool the downstream servers offer and the config maps, each run through the
    three checks for the grant without a ledger entry per tool, then one ``tools.listed``
    event naming what was shown and hidden. A tool the grant can't use never appears. If
    that event can't be written, the agent gets an error and no tools.

``call_tool(token, name, arguments)``
    1. Trellis decides (the decision event is written first, or the answer is a deny).
    2. A deny returns the check that refused and who to ask; Reef records that it blocked
       the call, and nothing reaches the server.
    3. Reef gets the credential the server's mode calls for: the person's own token (obo),
       the agent's own (agent), or a service credential Reef holds (brokered).
    4. Reef writes the enforcement event, and forwards only once that write succeeds.
    5. It applies the obligations (masks, then the row filter) to the result, and writes
       the outcome before the agent sees it. If that write fails, the result is held back.
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, TypeVar

import anyio
from mcp import types
from mcp.shared.exceptions import MCPError

from reef.config import ReefConfig
from reef.downstream import Downstream, HttpDownstream
from trellisd.app import Trellis
from trellisd.enforce import RowFilterError, compile_filter
from trellisd.engine import MASK, Decision
from trellisd.grants import Grant, GrantError
from trellisd.identity import IdentityError
from trellisd.ledger import LedgerUnavailable

T = TypeVar("T")
META_KEY = "trellis"


@dataclass(frozen=True)
class Route:
    server: str
    tool: str
    action: str
    resource: str


class Reef:
    def __init__(
        self,
        trellis: Trellis,
        config: ReefConfig,
        *,
        downstream: Callable[[str, str], Downstream] | None = None,
        environ: Mapping[str, str] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """``downstream(server_name, url)`` makes the client for one server (tests pass
        fakes); ``environ`` holds the brokered credentials."""
        self.trellis = trellis
        self.config = config
        self.environ = environ if environ is not None else os.environ
        self.clock = clock
        make = downstream or (lambda _name, url: HttpDownstream(url))
        self.servers: dict[str, Downstream] = {
            name: make(name, spec.url) for name, spec in config.servers.items()
        }
        self.routes: dict[str, Route] = {
            config.tool_name(server, tool): Route(
                server, tool, t.action, config.resource(server, tool)
            )
            for server, spec in config.servers.items()
            for tool, t in spec.tools.items()
        }
        self._catalog: dict[str, tuple[float, list[types.Tool]]] = {}
        # Trellis is synchronous and its ledger serializes writes anyway.
        self._lock = threading.Lock()

    async def _trellis(self, fn: Callable[[], T]) -> T:
        def locked() -> T:
            with self._lock:
                return fn()

        return await anyio.to_thread.run_sync(locked)

    # -- the tool list ---------------------------------------------------------------------

    async def _server_tools(self, server: str) -> list[types.Tool]:
        """A server's tool catalog (names, descriptions, schemas), cached for a while."""
        cached = self._catalog.get(server)
        if cached is not None and self.clock() - cached[0] < self.config.catalog_ttl_seconds:
            return cached[1]
        spec = self.config.servers[server]
        env = spec.credential_env if spec.credential == "brokered" else spec.list_credential_env
        tools = await self.servers[server].list_tools(self.environ.get(env) if env else None)
        self._catalog[server] = (self.clock(), tools)
        return tools

    def forget_catalog(self, server: str | None = None) -> None:
        if server is None:
            self._catalog.clear()
        else:
            self._catalog.pop(server, None)

    async def list_tools(self, token: str) -> list[types.Tool]:
        if not token:
            raise MCPError(
                types.INVALID_REQUEST, "connect with your grant token as the bearer token"
            )
        try:
            grant = await self._trellis(lambda: self.trellis.grants.resolve(token))
        except GrantError as exc:
            raise MCPError(types.INVALID_REQUEST, f"Trellis refused the grant: {exc}") from exc
        except Exception as exc:
            raise MCPError(
                types.INTERNAL_ERROR,
                f"Trellis can't read its grants ({exc}), so Reef shows no tools",
            ) from exc

        offered: list[tuple[str, Route, types.Tool]] = []
        unreachable: list[str] = []
        for server in self.config.servers:
            try:
                tools = await self._server_tools(server)
            except Exception:
                unreachable.append(server)
                continue
            for tool in tools:
                name = self.config.tool_name(server, tool.name)
                route = self.routes.get(name)
                if route is not None:
                    offered.append((name, route, tool))

        def decide() -> tuple[list[types.Tool], list[dict[str, Any]]]:
            shown: list[types.Tool] = []
            hidden: list[dict[str, Any]] = []
            for name, route, tool in offered:
                d = self.trellis.engine.decide(grant, route.action, route.resource)
                if d.allowed:
                    shown.append(_narrowed(name, tool, d, grant))
                else:
                    hidden.append({"tool": name, "denied_by": list(d.denied_by)})
            self.trellis.ledger.append(
                "tools.listed",
                agent=grant.agent,
                subject=grant.subject,
                grant_id=grant.id,
                body={
                    "enforced_by": "reef",
                    "shown": [t.name for t in shown],
                    "hidden": hidden,
                    "unreachable": unreachable,
                    "receipt": grant.receipt,
                    "config_version": self.trellis.config_version,
                },
            )
            return shown, hidden

        try:
            shown, _ = await self._trellis(decide)
        except LedgerUnavailable as exc:
            raise MCPError(
                types.INTERNAL_ERROR,
                f"{exc}; Reef shows no tools while it can't record what it showed",
            ) from exc
        return shown

    # -- a call ----------------------------------------------------------------------------

    async def call_tool(
        self, token: str, name: str, arguments: dict[str, Any] | None = None
    ) -> types.CallToolResult:
        arguments = arguments or {}
        route = self.routes.get(name) or Route("", name, "query", f"mcp://reef/{name}")
        d = await self._trellis(lambda: self.trellis.authorize(token, route.action, route.resource))
        if not d.allowed:
            await self._enforcement(d, route, "blocked", {"forwarded": False})
            return self._deny(d)

        spec = self.config.servers[route.server]
        try:
            credential = await self._credential(route.server, token)
        except (GrantError, IdentityError, KeyError) as exc:
            why = (
                f"Reef couldn't get a credential for {route.server} ({exc}),"
                " so it forwarded nothing"
            )
            await self._enforcement(d, route, "refused", {"forwarded": False, "reason": why})
            return _error(why, {"event_id": d.event_id})

        forward = await self._enforcement(
            d,
            route,
            "forward",
            {
                "forwarded": True,
                "credential": spec.credential,
                "audience": spec.audience,
                "obligations": d.obligations,
            },
        )
        if forward is None:
            return _error(
                "Trellis allowed the call, but Reef couldn't write the enforcement event,"
                " so it forwarded nothing",
                {"event_id": d.event_id, "denied_by": ["ledger"]},
            )

        started = time.monotonic()
        meta = {META_KEY: {"event_id": d.event_id, "obligations": d.obligations}}
        try:
            result = await self.servers[route.server].call_tool(
                route.tool, arguments, credential, meta
            )
        except Exception as exc:
            await self._enforcement(
                d,
                route,
                "result",
                {"forwarded_as": forward, "outcome": "unreachable", "error": str(exc)},
            )
            return _error(f"{route.server} couldn't be reached: {exc}", {"event_id": d.event_id})

        enforced, summary = enforce(d, result)
        summary |= {"forwarded_as": forward, "ms": round((time.monotonic() - started) * 1000)}
        if await self._enforcement(d, route, "result", summary) is None:
            return _error(
                "Reef couldn't record the result, so it holds it back",
                {"event_id": d.event_id, "denied_by": ["ledger"]},
            )
        return enforced

    async def _credential(self, server: str, token: str) -> str | None:
        spec = self.config.servers[server]
        if spec.credential == "brokered":
            env = spec.credential_env or ""
            if not self.environ.get(env):
                raise KeyError(f"{env} isn't set")
            return self.environ[env]
        if spec.credential in ("obo", "agent"):
            audience = spec.audience or ""
            as_agent = spec.credential == "agent"
            return await self._trellis(
                lambda: self.trellis.exchange(token, audience, spec.scopes, as_agent=as_agent)
            )
        return None

    async def _enforcement(
        self, d: Decision, route: Route, stage: str, body: dict[str, Any]
    ) -> str | None:
        """Write one enforcement event; its id, or None if the ledger couldn't take it."""

        def write() -> str:
            return self.trellis.ledger.append(
                "enforcement",
                agent=d.agent or "",
                subject=d.subject or "",
                grant_id=d.grant_id or "",
                body={
                    "enforced_by": "reef",
                    "decision": d.event_id,
                    "stage": stage,
                    "server": route.server,
                    "tool": route.tool,
                    "resource": route.resource,
                    **body,
                },
            ).event_id

        try:
            return await self._trellis(write)
        except LedgerUnavailable:
            return None

    def _deny(self, d: Decision) -> types.CallToolResult:
        ask = request_access(self.trellis, d)
        text = f"Denied at the door: {d.reason}."
        if ask:
            text += f" {ask['how']}"
        return _error(
            text,
            {
                "denied_by": list(d.denied_by),
                "reason": d.reason,
                "event_id": d.event_id,
                "request_access": ask,
            },
        )


def request_access(trellis: Trellis, d: Decision) -> dict[str, Any] | None:
    """Who could change the answer, and what to ask them for."""
    contract = trellis.config.contracts.get(d.contract or "")
    base: dict[str, Any] = {
        "contract": d.contract,
        "contract_owner": contract.owner if contract else None,
    }
    first = d.denied_by[0] if d.denied_by else ""
    levels = set(trellis.config.scale)
    tags = ", ".join(t for t in d.resource_tags if t not in levels) or "it"
    if first == "person" and contract is not None:
        return base | {
            "ask": contract.owner,
            "how": f"To ask for access, ask {contract.owner}, who owns {contract.contract}.",
        }
    if first == "ceiling" and d.agent in trellis.config.agents:
        owner = trellis.config.agents[d.agent].owner
        return base | {
            "ask": owner,
            "how": f"{owner} sets {d.agent}'s ceiling and would have to raise it.",
        }
    if first == "task" and d.subject:
        return base | {
            "ask": d.subject,
            "how": f"{d.subject} would have to give {d.agent} a grant whose task covers {tags}.",
        }
    if first == "purpose" and d.subject in trellis.config.purposes:
        owner = trellis.config.purposes[d.subject].owner
        return base | {"ask": owner, "how": f"{owner} owns purpose {d.subject}."}
    if first == "catalog":
        if contract is None:
            return base | {
                "ask": None,
                "how": f"No contract classifies {d.resource}, and Trellis denies what it can't"
                " classify; its owner would have to bind it to one.",
            }
        return base | {"ask": contract.owner, "how": f"{contract.owner} owns {contract.contract}."}
    if first == "grant":
        return base | {"ask": None, "how": "Sign in again for a live grant."}
    if first == "ledger":
        return base | {
            "ask": None,
            "how": "There's nothing to ask for: Trellis denies every call it can't record.",
        }
    return None


def enforce(
    d: Decision, result: types.CallToolResult
) -> tuple[types.CallToolResult, dict[str, Any]]:
    """Apply the decision's masks and row filter to a tool result. Fails closed."""
    summary: dict[str, Any] = {"outcome": "error" if result.is_error else "ok"}
    if not d.masked and not d.row_filter:
        return result, summary
    if result.is_error:
        return result, summary
    data: Any = result.structured_content
    if data is None:
        texts = [c.text for c in result.content if isinstance(c, types.TextContent)]
        try:
            data = json.loads(texts[0]) if len(texts) == 1 else None
        except ValueError:
            data = None
    try:
        keep = compile_filter(d.row_filter) if d.row_filter else None
    except RowFilterError as exc:
        return _withheld(f"Reef can't apply the row filter ({exc})"), summary | {
            "outcome": "withheld"
        }
    counts = {"rows_in": 0, "rows_out": 0}
    masked: set[str] = set()

    def rows(value: list[Any]) -> list[Any] | None:
        if not all(isinstance(r, dict) for r in value):
            return None
        out = []
        for row in value:
            counts["rows_in"] += 1
            if keep is not None and not keep(row):
                continue
            counts["rows_out"] += 1
            masked.update(k for k in row if k in d.masked)
            out.append({k: (MASK if k in d.masked else v) for k, v in row.items()})
        return out

    enforced: Any = None
    if isinstance(data, list):
        enforced = rows(data)
    elif isinstance(data, dict):
        enforced = {}
        for key, value in data.items():
            if isinstance(value, list) and value and isinstance(value[0], dict):
                kept = rows(value)
                if kept is None:
                    enforced = None
                    break
                enforced[key] = kept
            elif key in d.masked:
                masked.add(key)
                enforced[key] = MASK
            else:
                enforced[key] = value
        if enforced is not None and counts["rows_in"] == 0 and d.row_filter:
            enforced = None  # a row filter with no rows to apply it to: don't guess
    if enforced is None:
        return _withheld(
            "Reef can't apply this call's masks and row filter to the result's shape"
        ), summary | {"outcome": "withheld"}
    if isinstance(enforced, list):
        structured: dict[str, Any] = {"rows": enforced}
    else:
        structured = enforced
    out = types.CallToolResult(
        content=[types.TextContent(type="text", text=json.dumps(enforced, default=str))],
        structured_content=structured,
        is_error=False,
    )
    return out, summary | counts | {"masked": sorted(masked), "row_filter": d.row_filter}


def _withheld(why: str) -> types.CallToolResult:
    return _error(f"{why}, so it holds the result back", {"withheld": True})


def _error(text: str, structured: dict[str, Any]) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=text)],
        structured_content=structured,
        is_error=True,
    )


def _narrowed(name: str, tool: types.Tool, d: Decision, grant: Grant) -> types.Tool:
    """The downstream tool under its Reef name, its description narrowed to the grant."""
    notes = []
    if d.row_filter:
        notes.append(f"only rows where {d.row_filter}")
    if d.masked:
        verb = "comes" if len(d.masked) == 1 else "come"
        notes.append(f"{', '.join(sorted(d.masked))} {verb} back as {MASK}")
    description = tool.description or ""
    who = f"for {grant.subject} ({grant.task})" if grant.task else f"for {grant.subject}"
    if notes:
        description = f"{description}\n\nThrough Reef {who}: {'; '.join(notes)}.".strip()
    return tool.model_copy(update={"name": name, "description": description})
