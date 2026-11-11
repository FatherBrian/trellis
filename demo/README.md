# Moat demo (placeholder)

TODO(week 3): `docker compose up` starts a sample dataset and an agent. The run shows:

1. PII in `finance.gl.journal_entries` is masked for report-bot.
2. A request for the export-controlled `part_number` column is denied.
3. `moat trace` and `moat explain` show what happened and why.

Planned contents:

- `seed/`: the sample dataset and `catalog.yaml`
- `agent.py`: a scripted agent calling a Moat-guarded MCP server
- `server.py`: the MCP server with `MoatGuard` around its tools

Goal: a stranger runs it from a clean machine in under five minutes.
