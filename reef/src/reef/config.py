"""Reef's config: the MCP servers it fronts, and how it gets each one a credential.

    reef:
      servers:
        ledger:
          url: http://127.0.0.1:9101/mcp
          credential: obo              # Ana's own token, exchanged for this audience
          audience: ledger-mcp
          tools:
            journal_entries: {action: query}
            post_adjustment: {action: write}
        hr:
          url: http://127.0.0.1:9102/mcp
          credential: brokered         # a service credential Reef holds, never the agent
          credential_env: REEF_HR_TOKEN
          tools:
            headcount: {}
            payroll: {}

A tool's resource is ``mcp://<server>/<tool>`` unless it names another. The contract that
binds that address classifies it, so a tool no contract binds is denied and never listed.
Tools the server offers and this file doesn't name are hidden: Reef forwards nothing it
can't map to a resource.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from trellisd.config import ACTIONS

CredentialMode = Literal["obo", "brokered", "agent", "none"]


class ReefConfigError(ValueError):
    pass


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ToolSpec(_Model):
    action: str = Field(
        default="query", description="The verb Trellis checks: " + ", ".join(ACTIONS)
    )
    resource: str | None = Field(
        default=None, description="The address Trellis classifies. Default mcp://<server>/<tool>."
    )

    @model_validator(mode="after")
    def _known_action(self) -> ToolSpec:
        if self.action not in ACTIONS:
            raise ValueError(f"action {self.action!r} isn't one of {', '.join(ACTIONS)}")
        return self


class ServerSpec(_Model):
    url: str
    credential: CredentialMode = Field(
        description="obo: the person's own token, exchanged for audience. brokered: a service"
        " credential Reef holds (credential_env). agent: the agent's own token, exchanged for"
        " audience. none: no credential (local test servers only)."
    )
    audience: str | None = None
    scopes: tuple[str, ...] = ()
    credential_env: str | None = Field(
        default=None, description="brokered: the environment variable holding the credential."
    )
    list_credential_env: str | None = Field(
        default=None,
        description="A credential Reef uses to read the server's tool catalog, if it wants one.",
    )
    tools: dict[str, ToolSpec] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _mode_needs(self) -> ServerSpec:
        if self.credential in ("obo", "agent") and not self.audience:
            raise ValueError(f"credential {self.credential} needs an audience")
        if self.credential == "brokered" and not self.credential_env:
            raise ValueError("credential brokered needs credential_env")
        return self


class ReefConfig(_Model):
    servers: dict[str, ServerSpec] = Field(default_factory=dict)
    #: How long Reef keeps a server's tool catalog (names, descriptions, schemas).
    catalog_ttl_seconds: float = 60

    def tool_name(self, server: str, tool: str) -> str:
        return f"{server}_{tool}"

    def resource(self, server: str, tool: str) -> str:
        spec = self.servers[server].tools.get(tool)
        return (spec.resource if spec and spec.resource else None) or f"mcp://{server}/{tool}"

    @model_validator(mode="after")
    def _unique_names(self) -> ReefConfig:
        seen: dict[str, str] = {}
        for server, spec in self.servers.items():
            for tool in spec.tools:
                name = self.tool_name(server, tool)
                if name in seen:
                    raise ValueError(f"{server}/{tool} and {seen[name]} both become {name}")
                seen[name] = f"{server}/{tool}"
        return self


def load_reef_config(path: str | Path) -> ReefConfig:
    p = Path(path)
    try:
        data = yaml.safe_load(p.read_text()) or {}
    except OSError as exc:
        raise ReefConfigError(f"{p}: {exc}") from exc
    if not isinstance(data, dict) or set(data) - {"reef"}:
        raise ReefConfigError(f"{p}: expected one top-level key, reef")
    try:
        return ReefConfig.model_validate(data.get("reef") or {})
    except ValueError as exc:
        raise ReefConfigError(f"{p}: {exc}") from exc
