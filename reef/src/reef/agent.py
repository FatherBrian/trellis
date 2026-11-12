"""A minimal MCP client for scripts and demos: an agent holding a grant token."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

import httpx2
from mcp import Client, types
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import MCPError

T = TypeVar("T")


class AgentClient:
    """``AgentClient(reef_url, grant_token).list_tools()`` and ``.call(name, args)``."""

    def __init__(self, url: str, token: str) -> None:
        self.url = url
        self.token = token

    def _run(self, fn: Callable[[Client], Awaitable[T]]) -> T:
        async def go() -> T:
            headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
            http = httpx2.AsyncClient(headers=headers)
            failed: MCPError | None = None
            async with Client(streamable_http_client(self.url, http_client=http)) as client:
                try:
                    return await fn(client)
                except MCPError as exc:  # raise it plainly, not wrapped in a task group's
                    failed = exc
            raise failed

        return asyncio.run(go())

    def list_tools(self) -> list[types.Tool]:
        """The agent's tool list. Raises ``MCPError`` when Reef refuses to list."""

        async def go(c: Client) -> list[types.Tool]:
            return (await c.list_tools(cache_mode="refresh")).tools

        return self._run(go)

    def try_list_tools(self) -> list[types.Tool] | str:
        try:
            return self.list_tools()
        except MCPError as exc:
            return str(exc)

    def call(self, name: str, arguments: dict[str, Any] | None = None) -> types.CallToolResult:
        async def go(c: Client) -> types.CallToolResult:
            return await c.call_tool(name, arguments or {})

        return self._run(go)
