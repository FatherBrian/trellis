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

A server can carry its own contract, so its tools need no contract files: give it an
``owner`` and its ``tags``, ``access`` and ``elements`` apply to every tool it lists. A tool
adds to them where it differs. Its tags join the server's, and its elements and access
roles replace the server's of the same name:

        hr:
          url: http://127.0.0.1:9102/mcp
          credential: brokered
          credential_env: REEF_HR_TOKEN
          owner: hr-lead@example.com
          tags: [hr]
          access:
            partners: {who: [group:hr-partners], actions: [read]}
          tools:
            headcount: {action: read, tags: [internal]}
            payroll:
              action: read
              tags: [confidential]
              elements: {salary: [pii]}

Each tool then gets a contract of its own, ``urn:contract:<server>.<tool>``, exactly as if
it had been written as a file, so decisions and ``trellisd trace`` name it the same way. A
server without an owner carries none, and its tools need contract files as before.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from trellisd.config import ACTIONS, Contract, ContractAccess, Tags, TrellisConfig

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
    tags: Tags = Field(default=frozenset(), description="Added to the server's tags.")
    elements: dict[str, Tags] = Field(
        default_factory=dict, description="Result fields and their tags, over the server's."
    )
    access: dict[str, ContractAccess] = Field(
        default_factory=dict, description="Access roles, replacing the server's of the same name."
    )

    @property
    def classifies(self) -> bool:
        return bool(self.tags or self.elements or self.access)

    @model_validator(mode="after")
    def _known_action(self) -> ToolSpec:
        if self.action not in ACTIONS:
            raise ValueError(f"action {self.action!r} isn't one of {', '.join(ACTIONS)}")
        return self


class ServerSpec(_Model):
    # Where the server is: a streamable HTTP url, or a local command Reef runs over stdio.
    # Values may use ${VAR} for environment variables, as MCP client configs do.
    url: str | None = None
    headers: dict[str, str] = Field(
        default_factory=dict, description="http: headers sent with every request."
    )
    command: str | None = Field(default=None, description="stdio: the program to run.")
    args: tuple[str, ...] = ()
    env: dict[str, str] = Field(
        default_factory=dict, description="stdio: environment for the process (its secrets)."
    )
    cwd: str | None = None
    credential: CredentialMode | None = Field(
        default=None,
        description="http servers: obo, the person's own token, exchanged for audience;"
        " brokered, a service credential Reef holds (credential_env); agent, the agent's own"
        " token, exchanged for audience; none, no credential (local test servers only)."
        " stdio servers take none: their secrets come from env.",
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
    # The server's own contract (optional): see the module docstring.
    owner: str | None = Field(
        default=None, description="Who owns this server's tools. Setting it makes the contract."
    )
    version: str = "1"
    tags: Tags = frozenset()
    elements: dict[str, Tags] = Field(default_factory=dict)
    access: dict[str, ContractAccess] = Field(default_factory=dict)

    @property
    def where(self) -> str:
        """The server's url, or its command line, for messages."""
        return self.url or " ".join([self.command or "", *self.args]).strip()

    @model_validator(mode="after")
    def _transport(self) -> ServerSpec:
        if bool(self.url) == bool(self.command):
            raise ValueError("a server needs a url (http) or a command (stdio), not both")
        if self.command:
            if self.credential not in (None, "none"):
                raise ValueError(
                    f"credential {self.credential} sends a bearer token, which a stdio server"
                    " can't take; give it its secrets in env instead"
                )
            if self.headers:
                raise ValueError("headers are for http servers; a stdio server takes env")
        elif self.credential is None:
            raise ValueError("an http server needs a credential: obo, agent, brokered or none")
        if self.url and (self.args or self.env or self.cwd):
            raise ValueError("args, env and cwd are for stdio servers (a command)")
        return self

    @model_validator(mode="after")
    def _mode_needs(self) -> ServerSpec:
        if self.credential in ("obo", "agent") and not self.audience:
            raise ValueError(f"credential {self.credential} needs an audience")
        if self.credential == "brokered" and not self.credential_env:
            raise ValueError("credential brokered needs credential_env")
        return self

    @model_validator(mode="after")
    def _contract_needs_owner(self) -> ServerSpec:
        # Fail closed and loud: tags or access with no owner would otherwise be ignored.
        if self.owner is None:
            if self.tags or self.elements or self.access:
                raise ValueError("tags, elements and access need an owner for the server")
            named = sorted(t for t, spec in self.tools.items() if spec.classifies)
            if named:
                raise ValueError(
                    f"tools {', '.join(named)} set tags, elements or access, which need an"
                    " owner for the server"
                )
        return self

    def contract(self, server: str, tool: str, resource: str) -> Contract | None:
        """The contract this server gives one of its tools, or None without an owner."""
        if self.owner is None:
            return None
        spec = self.tools.get(tool) or ToolSpec()
        return Contract(
            contract=f"urn:contract:{server}.{tool}",
            version=self.version,
            kind="mcp_tool",
            bindings=(resource,),
            owner=self.owner,
            tags=self.tags | spec.tags,
            elements={**self.elements, **spec.elements},
            access={**self.access, **spec.access},
        )


class ReefConfig(_Model):
    servers: dict[str, ServerSpec] = Field(default_factory=dict)
    #: How long Reef keeps a server's tool catalog (names, descriptions, schemas).
    catalog_ttl_seconds: float = 60

    def tool_name(self, server: str, tool: str) -> str:
        return f"{server}_{tool}"

    def resource(self, server: str, tool: str) -> str:
        spec = self.servers[server].tools.get(tool)
        return (spec.resource if spec and spec.resource else None) or f"mcp://{server}/{tool}"

    def contracts(self) -> dict[str, Contract]:
        """Every contract a server in this file gives its tools, by URN."""
        out: dict[str, Contract] = {}
        for server, spec in self.servers.items():
            for tool in spec.tools:
                c = spec.contract(server, tool, self.resource(server, tool))
                if c is not None:
                    out[c.contract] = c
        return out

    def apply_to(self, config: TrellisConfig) -> TrellisConfig:
        """Trellis's config with this file's server contracts added.

        An address keeps one contract: a server contract for a tool that a contract file
        already binds is an error, not a silent override.
        """
        mine = self.contracts()
        for urn, c in sorted(mine.items()):
            for address in c.bindings:
                other = config.contract_for(address)
                if other is not None:
                    raise ReefConfigError(
                        f"{address} has a contract file ({other.contract}) and a server"
                        f" contract in reef.yaml ({urn}); keep one"
                    )
        if not mine:
            return config
        try:
            return config.merged(TrellisConfig(contracts=mine))
        except ValueError as exc:
            raise ReefConfigError(str(exc)) from exc

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
