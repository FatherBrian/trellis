"""reef.lock: what each tool said when someone reviewed it.

An MCP server can change a tool's description or schema at any time, and the model reads
whatever it's sent. A changed description is a changed instruction to the model ("tool
poisoning"), and nothing in MCP pins it. ``reef.lock`` does, like a package lockfile:

    reef lock            write reef.lock from the servers in reef.yaml (first time)
    reef lock --check    exit 1 if any tool differs from reef.lock (for CI), with the diff
    reef lock --update   rewrite reef.lock after you've reviewed the diff

With a lock, ``reef serve`` shows a tool only while it matches: a drifted tool is hidden
from the list and refused if called, and a tool reef.yaml maps but the lock lacks never
appears. Both are recorded in the ledger. Review a lock change like a code change.

Pinned per tool: ``title``, ``description``, ``inputSchema``, ``outputSchema`` and
``annotations``, which is everything the model reads or that changes what a call does.
"""

from __future__ import annotations

import difflib
import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml
from mcp import types

from reef.downstream import Downstream, ExpansionError, downstream_for

if TYPE_CHECKING:
    from reef.config import ReefConfig

LOCK_VERSION = 1
PINNED = ("title", "description", "inputSchema", "outputSchema", "annotations")

HEADER = """\
# reef.lock: what each tool said when it was reviewed. Written by `reef lock`.
# Reef hides and refuses a tool that no longer matches. Review changes like code.
"""


class LockError(ValueError):
    pass


def pinned(tool: types.Tool) -> dict[str, Any]:
    """The parts of a tool the lock pins, as plain JSON."""
    dumped = tool.model_dump(mode="json", by_alias=True, exclude_none=True)
    return {k: dumped[k] for k in PINNED if k in dumped}


def digest(entry: Mapping[str, Any]) -> str:
    """sha256 of the pinned fields in canonical JSON (sorted keys, no whitespace)."""
    body = {k: entry[k] for k in PINNED if k in entry}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


@dataclass(frozen=True)
class Drift:
    """How one tool differs from the lock."""

    server: str
    tool: str
    kind: str  # "changed", "added" (offered, not in the lock), "removed" (locked, not offered)
    diff: str = ""

    def __str__(self) -> str:
        what = {
            "changed": "changed since it was locked",
            "added": "isn't in reef.lock",
            "removed": "is in reef.lock but the server no longer offers it",
        }[self.kind]
        return f"{self.server}/{self.tool} {what}"


@dataclass
class Lock:
    """server -> tool -> pinned fields plus their digest."""

    servers: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)

    @classmethod
    def from_catalog(cls, catalog: Mapping[str, list[types.Tool]]) -> Lock:
        lock = cls()
        for server, tools in sorted(catalog.items()):
            entries: dict[str, dict[str, Any]] = {}
            for tool in sorted(tools, key=lambda t: t.name):
                entry = pinned(tool)
                entries[tool.name] = {"sha256": digest(entry), **entry}
            lock.servers[server] = entries
        return lock

    @classmethod
    def load(cls, path: str | Path) -> Lock:
        p = Path(path)
        try:
            raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:
            raise LockError(f"{p}: {exc}") from exc
        if not isinstance(raw, dict) or raw.get("version") != LOCK_VERSION:
            raise LockError(f"{p}: not a version {LOCK_VERSION} reef.lock")
        servers = raw.get("servers") or {}
        if not isinstance(servers, dict):
            raise LockError(f"{p}: servers must be a mapping")
        lock = cls()
        for server, tools in servers.items():
            if not isinstance(tools, dict):
                raise LockError(f"{p}: {server} must map tool names to entries")
            for name, entry in tools.items():
                if not isinstance(entry, dict) or "sha256" not in entry:
                    raise LockError(f"{p}: {server}/{name} has no sha256")
                # Fail closed on a hand edit or a bad merge: the text must match its digest.
                if digest(entry) != entry["sha256"]:
                    raise LockError(
                        f"{p}: {server}/{name}'s pinned fields don't match its sha256;"
                        " run `reef lock --update` rather than editing reef.lock by hand"
                    )
            lock.servers[str(server)] = {str(k): dict(v) for k, v in tools.items()}
        return lock

    def dump(self) -> str:
        body = {"version": LOCK_VERSION, "servers": self.servers}
        return HEADER + yaml.safe_dump(
            body, sort_keys=True, allow_unicode=True, default_flow_style=False, width=100
        )

    def save(self, path: str | Path) -> None:
        Path(path).write_text(self.dump(), encoding="utf-8")

    # -- checking --------------------------------------------------------------------------

    def matches(self, server: str, tool: types.Tool) -> Drift | None:
        """None if the tool is exactly as locked; otherwise how it differs."""
        locked = self.servers.get(server, {}).get(tool.name)
        if locked is None:
            return Drift(server, tool.name, "added")
        now = pinned(tool)
        if digest(now) == locked["sha256"]:
            return None
        return Drift(server, tool.name, "changed", _diff(locked, now))

    def compare(self, catalog: Mapping[str, list[types.Tool]]) -> list[Drift]:
        """Every difference between this lock and what the servers offer now."""
        drifts: list[Drift] = []
        for server in sorted(set(self.servers) | set(catalog)):
            offered = {t.name: t for t in catalog.get(server, [])}
            for name in sorted(set(self.servers.get(server, {})) | set(offered)):
                if name not in offered:
                    drifts.append(Drift(server, name, "removed"))
                    continue
                d = self.matches(server, offered[name])
                if d is not None:
                    drifts.append(d)
        return drifts


async def fetch_catalog(
    config: ReefConfig,
    environ: Mapping[str, str],
    make: Callable[[str, str], Downstream] | None = None,
    *,
    every_tool: bool = False,
) -> dict[str, list[types.Tool]]:
    """The tools each server offers now: the ones reef.yaml maps, or with ``every_tool``,
    all of them (for a client config, where nothing is mapped).

    Lists with the same credential ``reef serve`` would. A server that can't be reached
    is an error: a partial lock would silently drop its tools.
    """
    catalog: dict[str, list[types.Tool]] = {}
    for server, spec in config.servers.items():
        env = spec.credential_env if spec.credential == "brokered" else spec.list_credential_env
        try:
            client = make(server, spec.where) if make else downstream_for(spec, environ)
            tools = await client.list_tools(environ.get(env) if env else None)
        except ExpansionError as exc:
            raise LockError(f"{server}: {exc}") from exc
        except Exception as exc:
            raise LockError(f"couldn't list {server}'s tools ({spec.where}): {exc}") from exc
        catalog[server] = tools if every_tool else [t for t in tools if t.name in spec.tools]
    return catalog


def _diff(locked: Mapping[str, Any], now: Mapping[str, Any]) -> str:
    def lines(entry: Mapping[str, Any]) -> list[str]:
        body = {k: entry[k] for k in PINNED if k in entry}
        text = yaml.safe_dump(body, sort_keys=True, allow_unicode=True, width=100)
        return text.splitlines(keepends=True)

    return "".join(
        difflib.unified_diff(lines(locked), lines(now), fromfile="reef.lock", tofile="server")
    )
