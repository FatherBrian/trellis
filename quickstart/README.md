# Quickstart: the whole story in one command

```bash
cd quickstart
docker compose up --build
```

That starts, on your machine:

| Service | What it is |
|---|---|
| `postgres` | The ledger and the grants |
| `iceberg` | An Iceberg REST catalog; `seed` creates `finance.gl.journal_entries` and tags `approver_email` pii there |
| `keycloak` | The IdP, with the demo realm from [examples/idp/keycloak](../examples/idp/keycloak) |
| `ledger-mcp`, `hr-mcp` | Two sample MCP servers: one takes the person's own token, one a service credential |
| `trellis` | Reef on `:8190/mcp`, with Trellis in the same process on `:8180` (`/token`, AuthZEN, `/healthz`) |
| `agent` | report-bot, scripted |

`up` shows only the agent. It:

1. signs Ana in at Keycloak, signs itself in, and trades both tokens at Trellis for a grant
   (task "Q3 close", scope finance);
2. lists its tools through Reef, and sees only the one its grant allows;
3. reads the journal: Ana's region only, `approver_email` masked because the catalog says
   it's pii, forwarded with Ana's own token;
4. calls `hr_payroll`, outside its task, and is denied at the door;
5. runs `trellisd trace` on the deny: the check that said no, the grant, and who allowed it;
6. runs `trellisd ledger verify`.

It prints a ✓ for each check and exits non-zero if any fails, which is what CI runs. The
services keep running; press Ctrl+C, then `docker compose down -v` to clear them.

## Poke at it

```bash
docker compose run --rm --no-deps agent          # again: a new grant on the same ledger
docker compose exec trellis trellisd --db postgresql://trellis:trellis@postgres:5432/trellis \
    trace                                         # the last events
docker compose logs trellis ledger-mcp hr-mcp     # what the servers saw
```

The config is all here: [reef.yaml](reef.yaml) and [trellis/](trellis). Every secret in
[docker-compose.yml](docker-compose.yml) and the realm is a throwaway for a laptop.
