# Roadmap to v0.1

v0.1 is a thin version of all five capabilities, built for demos. Each milestone ends with
a demo that runs start to finish (see [demo/](../demo/README.md)). The full plan is in the
design doc.

| | Milestone | Demo | State |
|---|---|---|---|
| M1 | Grants on Cedar: the three checks, obligations, grants in the database | Three keys | Done |
| M2 | Ledger v1: Postgres, grant receipts, signed checkpoints, OpenTelemetry, `trellisd trace` and `explain --replay` | Who allowed this? | Done |
| M3 | Contracts and the Iceberg REST catalog; ODCS adapter; the strictest tag wins | The catalog says pii | Done |
| M4 | Sign-in from any OIDC IdP; RFC 8693 and Entra OBO; one AuthZEN endpoint | Bring your own IdP | Done |
| M5 | Reef (`reef-mcp`): tools/list filtered by the grant, enforcement and the ledger | The door | Done |
| M6 | `docker compose up` quickstart, CI, [launch post](launch-post.md) | The whole story in one command | Done |

## Open questions

- Should grants follow MCP's enterprise-managed authorization extension directly, or wrap it?
- Python-only core, or a Go decision core once latency matters?
