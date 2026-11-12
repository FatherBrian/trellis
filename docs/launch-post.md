<!-- Draft. Not published. Title from the v0.1 plan; links point at the repo once it's public. -->

# Agents need delegated ABAC

An AI agent that drafts the quarter-end report for Ana doesn't need Ana's access. It needs
the part of her access that the quarter-end report needs, for as long as the report takes,
and a record afterwards of what it touched for her.

Today it usually gets one of two things. It gets a service account, which is everyone's
access and no one's, or it borrows the person's own token and can do anything they can.
Neither one says *this agent, for this person, on this task*. And when someone asks a week
later "who let the agent read that?", the answer is spread across an IdP log, a gateway
log and an application log that were never meant to agree.

Trellis is an open-source attempt at that missing piece: two ideas, and a door that enforces them.

## The grant: three keys

Every call an agent makes has to pass three checks, and all three must say yes:

1. **The person.** Would Ana be allowed this herself? Her groups and attributes, against
   the data contract's access rules.
2. **The agent's ceiling.** The most this agent may ever touch, whoever it works for, set
   by the agent's owner.
3. **The task.** What Ana handed it for this job: "Q3 close", scope finance, until it ends.

The grant is the intersection. An agent can never hold more than its person, more than its
owner allows, or more than the task asked for. The checks are compiled to Cedar, so the
evaluation is a well-understood engine and the policy is something you can read.

The task key is the one most systems leave out. Ana may read payroll this quarter; her
report-bot, working on the close, may not. In the quickstart that's exactly what
happens, and the deny names the task check, not a vague "forbidden".

## The ledger: decided and recorded, in that order

Every decision is written to a hash-chained ledger before the answer goes out. Grant
issuance is signed. If the ledger can't be written, the answer is no. A tool result is
recorded before the agent sees it, and a result whose masks can't be applied is held back
rather than passed through.

So "who allowed this?" is one command:

```
$ trellisd trace ev_105a3392327a4b3f
DENIED  report-bot read mcp://hr/payroll
Who allowed it
  ana@example.com let report-bot act for them: Q3 close
  ana@example.com signed in through local (http://keycloak:8080/realms/trellis, …)
The three checks
  ✓ ana@example.com's access
  ✓ report-bot's ceiling
  ✗ the task scope: the grant covers finance, and mcp://hr/payroll is confidential, hr
```

`trellisd ledger verify` walks the chain and finds an edited or deleted entry, and a
signed checkpoint catches a cut tail. `trellisd explain --replay` re-runs a decision at
the config and tags it was made with, and at today's.

## Reef: the door

Policy that an agent can route around isn't policy. **Reef** is an MCP gateway that sits in
front of your MCP servers and enforces Trellis there:

- **Tool lists are grant-shaped.** An agent asks for its tools and sees only the ones its
  grant allows, with descriptions that say what it will get back ("only rows where region =
  'emea'; approver_email comes back as ***"). Nobody writes a persona per agent.
- **Every call is decided first.** The decision and an enforcement event are in the ledger
  before anything is forwarded; a deny forwards nothing.
- **Results are enforced.** Masks and row filters are applied to what the server returns.
- **Credentials stay out of the agent.** A server can take the person's own token
  (exchanged at their IdP), the agent's, or a service credential only Reef holds.

## What plugs in

Sign-in comes from any OIDC IdP (Keycloak, Okta, Entra, Ping), with RFC 8693 token
exchange and Entra on-behalf-of. Tags come from data contracts and from your catalog: an
Iceberg REST catalog today, and the strictest tag wins, so a steward tagging a column pii
masks it on the next query. There's an OpenID AuthZEN endpoint for anything that isn't
behind Reef, and a read-only adapter for ODCS contracts.

## Try it

```bash
git clone <repo> && cd trellis/quickstart
docker compose up --build
```

That's Postgres, an Iceberg catalog, Keycloak, two MCP servers, Reef and a scripted
agent. You'll watch the agent see one tool, read a masked result, get denied a tool outside
its task, and trace the deny. CI runs the same thing on every change.

## What it isn't, yet

v0.1 is one process and pre-alpha. Reef speaks streamable HTTP; result enforcement covers
row-shaped results; Iceberg REST is the one catalog. The roadmap is in the repo, and so are
some good first issues: quickstart troubleshooting docs, a recorded terminal session, and a
run on Windows.

Others have built pieces of this: on-behalf-of tokens, task-scoped authorization, layered
Cedar checks, hash-chained agent audit logs. Trellis's bet is that the three keys and the
ledger belong together, enforced at the door, so that every answer to "may it?" is also the
answer to "who said so?".

Apache-2.0. Issues and pull requests welcome.
