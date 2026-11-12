"""Two small MCP servers to put behind Reef: a general ledger and an HR system.

Each one checks the bearer token it's given and keeps a log of every call that reached
it, so a demo can show that a call denied at the door never arrived. They return every
row they hold; filtering to the grant is Reef's job (they could also push down the row
filter Reef passes in ``_meta``).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from mcp import types
from mcp.server.lowlevel import Server

from reef.server import HttpServer, app, bearer

Rows = list[dict[str, Any]]
#: Checks a bearer token and says who it names, or raises PermissionError.
Verifier = Callable[[str], str]

JOURNAL: Rows = [
    {
        "entry_id": "JE-1001",
        "amount": 1250.00,
        "region": "emea",
        "approver_email": "lena@example.com",
    },
    {
        "entry_id": "JE-1002",
        "amount": -310.50,
        "region": "amer",
        "approver_email": "raj@example.com",
    },
    {
        "entry_id": "JE-1003",
        "amount": 980.00,
        "region": "emea",
        "approver_email": "lena@example.com",
    },
    {
        "entry_id": "JE-1004",
        "amount": 4400.00,
        "region": "apac",
        "approver_email": "mei@example.com",
    },
]
HEADCOUNT: Rows = [
    {"region": "emea", "headcount": 142},
    {"region": "amer", "headcount": 201},
    {"region": "apac", "headcount": 88},
]
PAYROLL: Rows = [
    {"employee": "E-17", "region": "emea", "salary": 81000},
    {"employee": "E-42", "region": "amer", "salary": 95000},
    {"employee": "E-63", "region": "amer", "salary": 72000},
]


@dataclass
class Call:
    tool: str
    arguments: dict[str, Any]
    caller: str
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class SampleTool:
    description: str
    rows: Rows | None = None
    schema: dict[str, Any] = field(default_factory=lambda: {"type": "object", "properties": {}})


class SampleServer:
    def __init__(self, name: str, tools: dict[str, SampleTool], verify: Verifier) -> None:
        self.name = name
        self.tools = tools
        self.verify = verify
        self.calls: list[Call] = []
        self.http: HttpServer | None = None

    def server(self) -> Server[Any]:
        async def on_list_tools(
            ctx: Any, params: types.PaginatedRequestParams | None
        ) -> types.ListToolsResult:
            return types.ListToolsResult(
                tools=[
                    types.Tool(name=n, description=t.description, input_schema=t.schema)
                    for n, t in self.tools.items()
                ]
            )

        async def on_call_tool(
            ctx: Any, params: types.CallToolRequestParams
        ) -> types.CallToolResult:
            try:
                caller = self.verify(bearer(ctx))
            except PermissionError as exc:
                return types.CallToolResult(
                    content=[types.TextContent(type="text", text=f"unauthorized: {exc}")],
                    is_error=True,
                )
            meta = dict(params.meta or {})
            self.calls.append(Call(params.name, dict(params.arguments or {}), caller, meta))
            tool = self.tools.get(params.name)
            if tool is None:
                return types.CallToolResult(
                    content=[types.TextContent(type="text", text=f"no tool {params.name}")],
                    is_error=True,
                )
            if tool.rows is None:
                out: Any = {"ok": True, "by": caller, **dict(params.arguments or {})}
            else:
                out = {"rows": tool.rows}
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=json.dumps(out))],
                structured_content=out,
            )

        return Server(self.name, on_list_tools=on_list_tools, on_call_tool=on_call_tool)

    def start(self) -> SampleServer:
        self.http = HttpServer(app(self.server())).start()
        return self

    @property
    def url(self) -> str:
        if self.http is None:
            raise RuntimeError(f"{self.name} isn't running")
        return self.http.url

    def close(self) -> None:
        if self.http is not None:
            self.http.close()

    def __enter__(self) -> SampleServer:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.close()


def ledger_server(verify: Verifier) -> SampleServer:
    return SampleServer(
        "ledger",
        {
            "journal_entries": SampleTool("Posted journal entries, one row per line.", JOURNAL),
            "post_adjustment": SampleTool(
                "Post an adjusting journal entry.",
                schema={
                    "type": "object",
                    "properties": {"amount": {"type": "number"}, "memo": {"type": "string"}},
                },
            ),
        },
        verify,
    )


def hr_server(verify: Verifier) -> SampleServer:
    return SampleServer(
        "hr",
        {
            "headcount": SampleTool("Headcount by region.", HEADCOUNT),
            "payroll": SampleTool("Salaries, one row per employee.", PAYROLL),
        },
        verify,
    )
