"""Talking to the MCP servers behind Reef, over streamable HTTP."""

from __future__ import annotations

from typing import Any, Protocol, cast

import httpx2
from mcp import Client, types
from mcp.client.streamable_http import streamable_http_client


class Downstream(Protocol):
    """One MCP server behind Reef. ``credential`` is the bearer token to send, if any."""

    async def list_tools(self, credential: str | None) -> list[types.Tool]: ...

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        credential: str | None,
        meta: dict[str, Any],
    ) -> types.CallToolResult: ...


class HttpDownstream:
    """A streamable HTTP MCP server. One short session per request: Reef holds no state."""

    def __init__(self, url: str, timeout: float = 30) -> None:
        self.url = url
        self.timeout = timeout

    def _client(self, credential: str | None) -> Client:
        headers = {"Authorization": f"Bearer {credential}"} if credential else {}
        http = httpx2.AsyncClient(headers=headers, timeout=self.timeout)
        return Client(streamable_http_client(self.url, http_client=http))

    async def list_tools(self, credential: str | None) -> list[types.Tool]:
        async with self._client(credential) as client:
            tools: list[types.Tool] = []
            cursor: str | None = None
            while True:
                page = await client.list_tools(cursor=cursor)
                tools += page.tools
                cursor = page.next_cursor
                if not cursor:
                    return tools

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        credential: str | None,
        meta: dict[str, Any],
    ) -> types.CallToolResult:
        async with self._client(credential) as client:
            return await client.call_tool(name, arguments, meta=cast(types.RequestParamsMeta, meta))
