# Reef

Reef is the door in front of your MCP servers. An agent connects once, with its Trellis
grant token, and sees only the tools its grant allows. Every call it makes is decided by
Trellis's three checks and written to the Trellis ledger before anything is forwarded.

Package: `reef-mcp`. It depends on [`trellisd`](../README.md) and runs Trellis in the same
process.

```
pip install reef-mcp
reef demo the-door
```

## What it does

| | A persona-based gateway | Reef |
|---|---|---|
| Tool list | A fixed bundle per persona | Built per request from what the grant allows |
| A tool outside the grant | Listed, then fails | Never listed; a call is denied at the door |
| Downstream credentials | A secret per server, often the agent's | Per server: the person's own token (obo), the agent's own (agent), or a service credential only Reef holds (brokered) |
| Masks and row filters | The server's problem | Applied by Reef to the result, and passed to the server in `_meta` so it can push them down |
| Audit | Per server, if at all | Every list and call in one hash-chained ledger |

On `tools/list`, Reef runs the three checks for every tool it fronts (without a ledger
entry each) and writes one `tools.listed` event naming what it showed and what it hid.

On `tools/call`:

1. Trellis decides. The decision event is written first; if it can't be, the answer is a deny.
2. A deny returns the check that refused and who to ask: the contract's owner, the agent's
   owner, or the person who gave the grant. Reef records that it blocked the call, and
   nothing reaches the server.
3. Reef gets the credential the server's mode calls for. The ledger records the exchange,
   never the token.
4. Reef writes the enforcement event, and forwards only once that write succeeds.
5. It masks columns and filters rows in the result, and writes the outcome before the
   agent sees it. A result it can't record, or can't apply the obligations to, is held back.

`trellisd trace <event>` shows a decision together with what the door did with it.

## Configure

`reef.yaml` lists the servers behind Reef:

```yaml
reef:
  servers:
    ledger:
      url: https://ledger.internal/mcp
      credential: obo              # the person's own token, exchanged at their IdP
      audience: ledger-mcp
      tools:
        journal_entries: {action: query}
        post_adjustment: {action: write}
    hr:
      url: https://hr.internal/mcp
      credential: brokered         # a service credential Reef holds
      credential_env: REEF_HR_TOKEN
      tools:
        headcount: {action: read}
        payroll: {action: read}
```

Each tool's address is `mcp://<server>/<tool>` unless it names another `resource`. A
Trellis contract binds that address, so the contract says what the tool is, who may use it
and what gets masked. A tool no contract binds is denied and never listed; a tool the
server offers and `reef.yaml` doesn't name is hidden.

Agents see each tool as `<server>_<tool>`, a name every MCP client accepts.

```
reef serve --config reef.yaml --trellis trellis/ --db postgresql://...
```

Agents get their grant token from Trellis's token endpoint (`trellisd serve`, `POST
/token`) and send it to Reef as `Authorization: Bearer <grant token>`.

## Limits in v0.1

- Trellis runs inside Reef. A Reef in front of a remote Trellis, over AuthZEN, comes later.
- Reef applies masks and row filters to results shaped as rows: a list of objects, or an
  object holding one. Any other shape, when there's something to apply, is held back.
- The person's sign-in is held in memory for obo mode, so a restart means signing in again.
