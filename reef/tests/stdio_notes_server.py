"""A tiny stdio MCP server for tests: `python stdio_notes_server.py`.

NOTES_DESC sets the search tool's description, so a test can change what the server
says between runs (a rug pull) and check that reef lock notices.
"""

import os

from mcp.server import MCPServer

server = MCPServer("notes")

NOTES = ["buy milk", "ship reef lock", "write the lockfile post"]


@server.tool(description=os.environ.get("NOTES_DESC", "Search your notes."))
def search(query: str) -> list[str]:
    return [n for n in NOTES if query.lower() in n.lower()]


@server.tool(description="Count your notes.")
def count() -> int:
    return len(NOTES)


if __name__ == "__main__":
    server.run("stdio")
