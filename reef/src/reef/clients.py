"""The MCP servers an agent client is set up with, read from that client's own config.

So ``reef lock --from`` can pin the tools of any MCP setup, not only servers behind Reef:

    claude-desktop   Claude Desktop's claude_desktop_config.json
    claude-code      .mcp.json in the current directory (Claude Code's project servers)
    vscode           .vscode/mcp.json in the current directory
    cursor           .cursor/mcp.json in the current directory

or the path to any of those files. Each holds ``mcpServers`` (``servers`` for VS Code) mapping
a name to a stdio command (``command``, ``args``, ``env``) or an HTTP ``url`` (with ``headers``).
VS Code's files may carry comments. ``${VAR}`` and ``${env:VAR}`` are filled from the
environment when the server is reached.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reef.config import ReefConfig, ServerSpec

CLIENTS = ("claude-desktop", "claude-code", "vscode", "cursor")


class ClientConfigError(ValueError):
    pass


@dataclass
class ClientServers:
    """What a client config gave us: the servers Reef can reach, and the ones it can't."""

    path: Path
    config: ReefConfig
    skipped: dict[str, str] = field(default_factory=dict)  # name -> why


def client_path(name: str) -> Path:
    """Where a known client keeps its MCP config."""
    if name == "claude-desktop":
        if sys.platform == "win32":
            return Path(os.environ.get("APPDATA", "")) / "Claude" / "claude_desktop_config.json"
        if sys.platform == "darwin":
            base = Path.home() / "Library" / "Application Support"
            return base / "Claude" / "claude_desktop_config.json"
        return Path.home() / ".config" / "Claude" / "claude_desktop_config.json"
    return {
        "claude-code": Path(".mcp.json"),
        "vscode": Path(".vscode") / "mcp.json",
        "cursor": Path(".cursor") / "mcp.json",
    }[name]


def strip_jsonc(text: str) -> str:
    """Drop // and /* */ comments and trailing commas, leaving strings alone."""
    out: list[str] = []
    i, n = 0, len(text)
    in_string = False
    while i < n:
        c = text[i]
        if in_string:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_string = False
            i += 1
        elif c == '"':
            in_string = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
        else:
            out.append(c)
            i += 1
    cleaned = "".join(out)
    # Trailing commas before } or ], outside strings.
    result: list[str] = []
    in_string = False
    j, m = 0, len(cleaned)
    while j < m:
        c = cleaned[j]
        if in_string:
            result.append(c)
            if c == "\\" and j + 1 < m:
                result.append(cleaned[j + 1])
                j += 2
                continue
            if c == '"':
                in_string = False
        elif c == '"':
            in_string = True
            result.append(c)
        elif c == "," and cleaned[j + 1 :].lstrip()[:1] in ("}", "]"):
            pass
        else:
            result.append(c)
        j += 1
    return "".join(result)


def _servers_block(raw: dict[str, Any]) -> dict[str, Any]:
    for key in ("mcpServers", "servers"):
        block = raw.get(key)
        if isinstance(block, dict):
            return block
    nested = raw.get("mcp")  # VS Code user settings keep them under "mcp": {"servers": ...}
    if isinstance(nested, dict) and isinstance(nested.get("servers"), dict):
        return dict(nested["servers"])
    raise ClientConfigError("no mcpServers (or servers) block")


def _spec(entry: dict[str, Any]) -> ServerSpec:
    kind = str(entry.get("type", "")).lower()
    if kind == "sse":
        raise ClientConfigError("uses the old SSE transport, which Reef doesn't speak")
    if entry.get("url"):
        if kind not in ("", "http", "streamable-http", "streamablehttp"):
            raise ClientConfigError(f"has transport type {kind!r}")
        return ServerSpec(
            url=str(entry["url"]),
            headers={str(k): str(v) for k, v in (entry.get("headers") or {}).items()},
            credential="none",
        )
    if entry.get("command"):
        return ServerSpec(
            command=str(entry["command"]),
            args=tuple(str(a) for a in entry.get("args") or ()),
            env={str(k): str(v) for k, v in (entry.get("env") or {}).items()},
            cwd=str(entry["cwd"]) if entry.get("cwd") else None,
        )
    raise ClientConfigError("has neither a command nor a url")


def load_client_config(source: str | Path) -> ClientServers:
    """The servers in a client config, by known client name or by path."""
    path = client_path(str(source)) if str(source) in CLIENTS else Path(source)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ClientConfigError(f"{path}: {exc}") from exc
    try:
        raw = json.loads(strip_jsonc(text))
    except json.JSONDecodeError as exc:
        raise ClientConfigError(f"{path}: not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ClientConfigError(f"{path}: the top level must be an object")
    try:
        block = _servers_block(raw)
    except ClientConfigError as exc:
        raise ClientConfigError(f"{path}: {exc}") from exc

    servers: dict[str, ServerSpec] = {}
    skipped: dict[str, str] = {}
    for name, entry in block.items():
        if not isinstance(entry, dict):
            skipped[name] = "isn't an object"
            continue
        if entry.get("disabled") is True:
            skipped[name] = "is disabled"
            continue
        if any("${input:" in json.dumps(v) for v in entry.values()):
            skipped[name] = "needs an interactive ${input:...} value"
            continue
        try:
            servers[name] = _spec(entry)
        except (ClientConfigError, ValueError) as exc:
            skipped[name] = str(exc)
    return ClientServers(path, ReefConfig(servers=servers), skipped)
