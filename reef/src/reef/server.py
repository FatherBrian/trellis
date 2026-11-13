"""Reef behind MCP: one streamable HTTP endpoint that agents connect to with a grant token.

The agent sends its Trellis grant token as the bearer token, the same one it would send
to the AuthZEN endpoint. ``tools/list`` and ``tools/call`` go to ``Reef``; everything else
an MCP client may ask is answered by the SDK.
"""

from __future__ import annotations

import threading
import time
from typing import Any

import uvicorn
from mcp import types
from mcp.server.lowlevel import Server

from reef import __version__
from reef.gateway import Reef


def bearer(ctx: Any) -> str:
    request = getattr(ctx, "request", None)
    auth = request.headers.get("authorization", "") if request is not None else ""
    return auth[7:].strip() if auth.lower().startswith("bearer ") else ""


def mcp_server(reef: Reef) -> Server[Any]:
    async def on_list_tools(
        ctx: Any, params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        return types.ListToolsResult(tools=await reef.list_tools(bearer(ctx)))

    async def on_call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        return await reef.call_tool(bearer(ctx), params.name, params.arguments)

    return Server(
        "reef",
        version=__version__,
        instructions="Reef shows you the tools your Trellis grant allows, and nothing else.",
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


class HttpServer:
    """An ASGI app on uvicorn in a thread: ``with HttpServer(app) as s: s.url``."""

    def __init__(self, app: Any, host: str = "127.0.0.1", port: int = 0, path: str = "/mcp"):
        self._server = uvicorn.Server(
            uvicorn.Config(app, host=host, port=port, log_level="warning", lifespan="on")
        )
        self.path = path
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        host, port = self._server.servers[0].sockets[0].getsockname()[:2]
        return f"http://{host}:{port}{self.path}"

    def start(self) -> HttpServer:
        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self._thread.start()
        deadline = time.monotonic() + 10
        while not self._server.started:
            if time.monotonic() > deadline or not self._thread.is_alive():
                raise RuntimeError("the MCP server didn't start")
            time.sleep(0.02)
        return self

    def close(self) -> None:
        self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=5)

    def __enter__(self) -> HttpServer:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.close()


def app(server: Server[Any], host: str = "127.0.0.1") -> Any:
    """The ASGI app. Bound to a loopback host, the SDK checks the Host header (DNS
    rebinding protection); bound to 0.0.0.0, as in a container, it serves any host name."""
    return server.streamable_http_app(stateless_http=True, json_response=True, host=host)


class ReefServer(HttpServer):
    """Reef on a local port, for demos and tests."""

    def __init__(self, reef: Reef, host: str = "127.0.0.1", port: int = 0) -> None:
        super().__init__(app(mcp_server(reef)), host, port)
        self.reef = reef


def serve(reef: Reef, host: str = "127.0.0.1", port: int = 8190) -> None:
    uvicorn.run(app(mcp_server(reef), host), host=host, port=port, log_level="info")
