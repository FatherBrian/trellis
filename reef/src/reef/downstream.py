"""Talking to the MCP servers behind Reef: over streamable HTTP, or as a local stdio process."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Protocol, cast

import httpx2
from mcp import Client, types
from mcp.client.stdio import StdioServerParameters
from mcp.client.streamable_http import streamable_http_client

if TYPE_CHECKING:
    from reef.config import ServerSpec


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

    async def read_resource(
        self, uri: str, credential: str | None
    ) -> list[types.TextResourceContents | types.BlobResourceContents]: ...


async def _all_tools(client: Client) -> list[types.Tool]:
    tools: list[types.Tool] = []
    cursor: str | None = None
    while True:
        page = await client.list_tools(cursor=cursor)
        tools += page.tools
        cursor = page.next_cursor
        if not cursor:
            return tools


class HttpDownstream:
    """A streamable HTTP MCP server. One short session per request: Reef holds no state."""

    def __init__(
        self, url: str, timeout: float = 30, headers: Mapping[str, str] | None = None
    ) -> None:
        self.url = url
        self.timeout = timeout
        self.headers = dict(headers or {})

    def _client(self, credential: str | None) -> Client:
        headers = dict(self.headers)
        if credential:
            headers["Authorization"] = f"Bearer {credential}"
        http = httpx2.AsyncClient(headers=headers, timeout=self.timeout)
        return Client(streamable_http_client(self.url, http_client=http))

    async def list_tools(self, credential: str | None) -> list[types.Tool]:
        async with self._client(credential) as client:
            return await _all_tools(client)

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        credential: str | None,
        meta: dict[str, Any],
    ) -> types.CallToolResult:
        async with self._client(credential) as client:
            return await client.call_tool(name, arguments, meta=cast(types.RequestParamsMeta, meta))

    async def read_resource(
        self, uri: str, credential: str | None
    ) -> list[types.TextResourceContents | types.BlobResourceContents]:
        async with self._client(credential) as client:
            return list((await client.read_resource(uri)).contents)


class StdioDownstream:
    """A local MCP server Reef starts as a process and talks to over stdin and stdout.

    One process per request, like the HTTP client's one session per request. Its secrets
    come from ``env``, not a bearer token, so ``credential`` is ignored.
    """

    def __init__(
        self,
        command: str,
        args: list[str] | tuple[str, ...] = (),
        env: Mapping[str, str] | None = None,
        cwd: str | None = None,
    ) -> None:
        self.params = StdioServerParameters(
            command=command, args=list(args), env=dict(env) if env else None, cwd=cwd
        )

    async def list_tools(self, credential: str | None) -> list[types.Tool]:
        async with Client(self.params) as client:
            return await _all_tools(client)

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        credential: str | None,
        meta: dict[str, Any],
    ) -> types.CallToolResult:
        async with Client(self.params) as client:
            return await client.call_tool(name, arguments, meta=cast(types.RequestParamsMeta, meta))

    async def read_resource(
        self, uri: str, credential: str | None
    ) -> list[types.TextResourceContents | types.BlobResourceContents]:
        async with Client(self.params) as client:
            return list((await client.read_resource(uri)).contents)


_VAR = re.compile(r"\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)\}")


class ExpansionError(ValueError):
    pass


def expand(value: str, environ: Mapping[str, str]) -> str:
    """Fill ``${VAR}`` and ``${env:VAR}`` from the environment, as MCP client configs do.

    A variable that isn't set is an error rather than an empty string, so a missing
    secret fails loudly. ``${input:...}`` (VS Code's prompt-for-a-value) can't be filled.
    """
    if "${input:" in value:
        raise ExpansionError(f"{value!r} asks for an interactive ${{input:...}} value")

    def one(m: re.Match[str]) -> str:
        name = m.group(1)
        if name not in environ:
            raise ExpansionError(f"environment variable {name} isn't set")
        return environ[name]

    return _VAR.sub(one, value)


def downstream_for(spec: ServerSpec, environ: Mapping[str, str] | None = None) -> Downstream:
    """The client for one server in reef.yaml, HTTP or stdio, with variables filled in."""
    env = environ if environ is not None else os.environ
    if spec.command:
        return StdioDownstream(
            expand(spec.command, env),
            [expand(a, env) for a in spec.args],
            {k: expand(v, env) for k, v in spec.env.items()},
            expand(spec.cwd, env) if spec.cwd else None,
        )
    if spec.url is None:  # the config validator makes this unreachable
        raise ValueError("a server needs a url or a command")
    return HttpDownstream(
        expand(spec.url, env), headers={k: expand(v, env) for k, v in spec.headers.items()}
    )
