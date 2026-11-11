# Roadmap to v0.1

Roughly 3–4 weeks of evenings. `TODO(week N)` comments in the code mark where each piece goes.

## Week 1: grant and policy model, decision API

- Settle the policy syntax and publish a JSON Schema.
- Persist grants (same database as the ledger) and record issue and revoke as events.
- Opaque or signed tokens; decide how grants relate to MCP's enterprise-managed
  authorization extension.
- `writ grant issue | list | revoke`.
- HTTP decision server (`writ serve`).
- Row filter templating; explicit deny policies if needed.

## Week 2: ledger and trace CLI

- Postgres backend; OpenTelemetry span per decision; Parquet export.
- Signed checkpoints of the head hash so truncation is detectable.
- Record rejected tokens.
- Richer `writ trace` (grouping, counts) and `writ explain` (drift against current policy).

## Week 3: MCP middleware and demo

- FastMCP token provider and registration helper.
- Unity Catalog OSS adapter for tags and clearances.
- `docker compose up` demo: masked PII, denied export-controlled column, trace shows why.

## Week 4: docs, README and launch post

## Open questions

- Does the name Writ clash with an existing project or trademark?
- Should grants follow MCP's enterprise-managed authorization extension directly, or wrap it?
- Python-only core, or a Go decision core once latency matters?
- Does the ledger record every decision, or only those whose annotations require logging?
  (The scaffold records every decision.)
