# Writ

**Delegated access control and a tamper-evident audit ledger for AI agents.**

Writ gives an AI agent only the data access its current task needs, on behalf of one
specific person, and records a tamper-evident proof of every decision. It pairs
delegated attribute-based access control (ABAC) with an append-only access ledger, and
ships MCP middleware so any MCP tool can adopt it in a few lines.

> Status: pre-alpha scaffold. The decision core, grants and ledger work and are tested;
> the HTTP server, persistence, Unity Catalog adapter and demo are still to come.
> See [docs/roadmap.md](docs/roadmap.md).

## Why

Most organizations have a written policy for what agents may read. Far fewer can enforce
it at the moment an agent reads data, expire the access when the task ends, or produce
a complete record of what an agent touched for whom. IAM issues identities, catalogs tag
data, and OPA or Cedar evaluate policies, but none of them models *an agent acting for a
human on a task*, and none ties each decision to an audit record by construction.

## The idea

An agent never inherits a person's access. It holds a **grant**, which binds five things:
the human, the agent, the task, a scope expressed as data tags, and a time limit. The
agent's token is bound to exactly one grant.

```
effective access = human access ∩ agent ceiling ∩ task scope
```

- **Human access**: what the delegating person may read, from the catalog or IdP.
- **Agent ceiling**: the most this agent may ever touch, set by its owner.
- **Task scope**: the tags this task needs, declared when the grant is issued.

Everything outside the intersection is denied by default. Inside it, policies decide which
actions are allowed and shape the answer. Every decision returns allow or deny, column
masks, a row filter, annotations, and a plain-language reason, and every decision lands
in a hash-chained ledger.

## Policies

```yaml
agents:
  report-bot:
    owner: group:finance-platform
    ceiling: [finance, pii]          # never export_controlled

policies:
  - id: finance-read
    principal: { agent: report-bot, on_behalf_of: group:finance-analysts }
    action: [read, query]
    resource: { tags: [finance] }
    conditions:
      - grant.scope contains finance
      - column.tags excludes pii     # column conditions mask, they don't deny
    annotations:
      log: required
```

## Quickstart

```bash
git clone https://github.com/OWNER/writ && cd writ
uv sync --extra dev          # or: python -m pip install -e ".[dev]"
uv run pytest
uv run writ policy check examples/policies.yaml
```

Use it as a library:

```python
from datetime import timedelta
from writ import Authorizer, GrantStore, Ledger, Principal, YamlCatalog, load_policies

grants = GrantStore()
authorizer = Authorizer(
    catalog=YamlCatalog.from_file("examples/catalog.yaml"),
    policies=load_policies("examples/policies.yaml"),
    grants=grants,
)
issued = grants.issue(
    human="alice@example.com", agent="report-bot",
    task="month-end variance report", scope={"finance"}, ttl=timedelta(hours=1),
)

principal = Principal.from_grant(issued.grant)
decision = authorizer.authorize(principal, "read", "finance.gl.journal_entries")
print(decision.allowed, decision.masks, decision.reason)
# True ('approver_email', 'part_number') allowed by finance-read; masked approver_email ...

with Ledger("writ-ledger.db") as ledger:
    ledger.record(principal, "read", "finance.gl.journal_entries", decision)
```

Then ask what happened:

```bash
writ trace --agent report-bot --for alice@example.com --since 7d
writ explain <event-id>
writ ledger verify
```

Guard an MCP tool:

```python
from writ.mcp_middleware import WritGuard

guard = WritGuard(authorizer, ledger, token_provider=current_request_token)

@mcp.tool()
@guard.tool(action="read", resource="finance.gl.journal_entries")
def journal_entries(limit: int = 100) -> list[dict]:
    ...
```

## v0.1 scope

| # | Feature | State |
|---|---------|-------|
| 1 | Grants: issue, list, revoke; expiring agent tokens | Library done; CLI and persistence to do |
| 2 | Policies as code (YAML) | Done, syntax to settle |
| 3 | Decision API: `authorize(principal, action, resource, context)` | Library done; HTTP server to do |
| 4 | Ledger: hash-chained, SQLite/Postgres, OpenTelemetry, Parquet | SQLite and verify done; rest to do |
| 5 | Trace CLI: `writ trace`, `writ explain` | Basic versions work |
| 6 | MCP middleware for the Python MCP SDK, Unity Catalog OSS tags | Guard done; SDK wiring and UC adapter to do |
| 7 | `docker compose up` demo | Placeholder |

Non-goals for v0.1: enforcement inside query engines, a web UI, multi-tenancy, Cedar or
OPA backends, and identity issuance (Writ consumes identities from your IdP).

## Layout

```
src/writ/
  grants.py          grants, agent ceilings, tokens
  policy.py          YAML policy model and loader
  catalog.py         data tags and human clearances (YAML fallback, Unity Catalog OSS stub)
  decision.py        Authorizer.authorize(): the intersection, deny by default
  ledger.py          append-only hash-chained ledger and verify()
  mcp_middleware.py  WritGuard for MCP tool calls
  cli.py             the writ command
  server.py          HTTP decision server (stub)
examples/            example policies and catalog
demo/                docker compose demo (placeholder)
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
