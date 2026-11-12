# Trellis

**Delegated access control and a tamper-evident audit ledger for AI agents.**

Trellis gives an AI agent only the data access its current task needs, on behalf of one
specific person, and records a tamper-evident proof of every decision. It pairs
delegated attribute-based access control (ABAC) with an append-only access ledger. **Reef** (`reef-mcp`, in [reef/](https://github.com/FatherBrian/trellis/blob/main/reef/README.md)),
its tool aggregator, puts it at the door of your MCP servers: an agent sees only the tools
its grant allows, and every call is decided and recorded before it's forwarded. The
package, import and command are all `trellisd`.

> Status: pre-alpha. v0.1's six milestones work and are tested: grants on Cedar and the
> three checks, the ledger, contracts and Iceberg catalogs, sign-in from any OIDC IdP with
> an AuthZEN endpoint, Reef, and a one-command quickstart.
> See [docs/roadmap.md](https://github.com/FatherBrian/trellis/blob/main/docs/roadmap.md).

## Quickstart

```bash
cd quickstart
docker compose up --build
```

Postgres, an Iceberg REST catalog, Keycloak, two MCP servers, Reef with Trellis, and a
scripted agent. The agent signs in for Ana, sees only the tool its grant allows, reads a
masked result, is denied a tool outside its task, and traces the deny to the check that
said no and who allowed it. See [quickstart/](https://github.com/FatherBrian/trellis/blob/main/quickstart/README.md) and
[demo/M6.md](https://github.com/FatherBrian/trellis/blob/main/demo/M6.md).

## Why

Most organizations have a written policy for what agents may read. Far fewer can enforce
it at the moment an agent reads data, expire the access when the task ends, or produce
a complete record of what an agent touched for whom. IAM issues identities, catalogs tag
data, and OPA or Cedar evaluate policies, but none of them models *an agent acting for a
person on a task*, and none ties each decision to an audit record by construction.

## The idea: three keys

An agent never inherits a person's access. It holds a **grant** that records who allowed
it, for which person or purpose, on which task, until when. Every call then needs three
yeses, each asked separately in [Cedar](https://www.cedarpolicy.com/):

| | Personal agent | Process agent |
|---|---|---|
| 1 | the person's access | the purpose's scope (with a named human owner) |
| 2 | the agent's ceiling | the agent's ceiling |
| 3 | the task scope | the trigger scope (the record that started the run) |

The three limits live in three separate Cedar policy sets, so a permit written for one can
never satisfy another. Trellis asks all three even after a no, and a deny names every check
that refused and the policy behind it. `@mask` and `@row_filter` annotations on the
deciding policies come back as obligations. Everything is deny by default, and every grant
and decision lands in a hash-chained ledger before the answer goes out.

```bash
python -m pip install -e .
trellisd demo three-keys
trellisd demo who-allowed-this    # trace a deny to its grant, then catch a ledger edit
trellisd demo catalog-says-pii    # a catalog tags a column pii; the next query is masked
trellisd demo bring-your-own-idp  # sign in at any OIDC IdP, then one AuthZEN endpoint
reef demo the-door                # two agents, one Reef: each sees only its grant's tools
```

```
CALL                                  Ana's access  report-bot's ceiling  the task         RESULT
read finance.gl.journal_entries            ✓                 ✓               ✓      ALLOW  masked approver_email; rows region = 'emea'
read finance.gl.export_ledger              ✓                 ✗               ✓      DENY   it may never touch export_controlled
read hr.payroll                            ✓                 ✓               ✗      DENY   the grant covers finance, and hr.payroll is hr, pii
read finance.treasury.cash_positions       ✗                 ✓               ✓      DENY   no access rule lets ana@example.com read ...
```

[demo/M1.md](https://github.com/FatherBrian/trellis/blob/main/demo/M1.md) walks through it.

## Writing policy

People write YAML; Trellis compiles it to Cedar (`trellisd compile` shows the output and
`trellisd validate` checks it against Trellis's Cedar schema).

```yaml
agents:
  report-bot:
    owner: ana@example.com
    ceiling:
      tags: [finance, pii, hr]
      never: [export_controlled]

access:
  - id: finance-gl
    who: [group:finance-analysts]
    resources: [finance.gl]
    tags: [finance]
    mask: [pii]
    row_filter: "region = {person.region}"

purposes:
  inspection-review:
    owner: quality-lead@example.com
    agents: [inspector-bot]
    tags: [quality]
    trigger: {type: inspection, tags: [quality], row_filter: "inspection_id = {trigger.record}"}
```

`trellisd schema` prints the JSON Schema. See [examples/three-keys](https://github.com/FatherBrian/trellis/tree/main/examples/three-keys).

## As a library

```python
from trellisd import Trellis

trellis = Trellis.open("examples/three-keys", db_url="sqlite:///trellisd.db")
issued = trellis.issue_grant(person="ana@example.com", agent="report-bot",
                             task="Q3 close", scope={"finance"})
decision = trellis.authorize(issued.token, "read", "finance.gl.journal_entries")
print(decision.allowed, decision.masked, decision.row_filter)
for check in decision.checks:
    print(check.label, check.allowed, check.policies, check.reason)
```

Put Reef in front of your MCP servers ([your own server in three commands](https://github.com/FatherBrian/trellis/blob/main/reef/README.md#your-own-server)), or guard a
tool inside a server that can't sit behind Reef:

```python
from trellisd.mcp_middleware import TrellisGuard

guard = TrellisGuard(trellis, token_provider=current_request_token)

@mcp.tool()
@guard.tool(action="read", resource="finance.gl.journal_entries")
def journal_entries(limit: int = 100) -> list[dict]:
    ...
```

## Commands

```bash
trellisd grant issue | run | list | revoke
trellisd check --token <token> read finance.gl.journal_entries
trellisd compile | validate | schema
trellisd trace [EVENT_ID]            # who allowed this call, or recent events
trellisd explain EVENT_ID --replay   # re-run it at its recorded version and today's
trellisd ledger checkpoint --out checkpoint.json
trellisd ledger verify [--checkpoint checkpoint.json]
trellisd ledger export [--console]   # OpenTelemetry spans from the outbox
trellisd contracts list | import-odcs FILE
trellisd catalog tags TABLE          # merged tags, each with its source
trellisd serve [--port 8180]         # AuthZEN evaluation and sign-in token exchange
```

`--config` (or `TRELLISD_CONFIG`) is a YAML file or directory; `--db` (or `TRELLISD_DB`)
is `sqlite:///file.db` or a `postgresql://` URL. Grants and the ledger share the database.
`--key` (or `TRELLISD_KEY`) is the Ed25519 signing key for grant entries and checkpoints,
made with mode 0600 on first use.

## Layout

```
src/trellisd/
  config.py          the YAML format and its JSON Schema
  compiler.py        YAML to Cedar: three policy sets, entities, the Cedar schema
  engine.py          the three checks, obligations, Decision
  grants.py          grants and tokens, stored in the database
  ledger.py          the hash-chained ledger, outbox, snapshots and verify()
  signing.py         Ed25519 keys for grant entries and checkpoints
  trace.py           who allowed this: trace a decision, replay it
  export.py          the outbox to OpenTelemetry
  app.py             Trellis: issue, revoke, authorize (ledger before the answer)
  catalog.py         the resolver: contracts and catalogs merged, strictest tag wins
  iceberg.py         the Iceberg REST tag source (and a small admin client)
  fake_iceberg.py    an in-process Iceberg REST catalog for demos and tests
  odcs.py            the ODCS v3 contract adapter
  enforce.py         applying masks and row filters to rows
  identity.py        sign-in from any OIDC IdP; RFC 8693 and Entra on-behalf-of
  server.py          trellisd serve: AuthZEN evaluation and the token endpoint
  fake_idp.py        an in-process OIDC IdP for demos and tests
  db.py              SQLite or Postgres
  mcp_middleware.py  TrellisGuard for MCP tool calls
  cli.py             the trellisd command
reef/                Reef (reef-mcp): the grant-shaped MCP gateway, its tests and demo
examples/three-keys  the M1 and M2 demo config
examples/lakehouse   contracts and an Iceberg REST catalog (M3)
examples/idp         a Keycloak demo realm (M4)
quickstart/          docker compose up: the whole story (M6)
demo/                one note per milestone demo
```

## Contributing

See [CONTRIBUTING.md](https://github.com/FatherBrian/trellis/blob/main/CONTRIBUTING.md).

## License

Apache License 2.0. See [LICENSE](https://github.com/FatherBrian/trellis/blob/main/LICENSE).
