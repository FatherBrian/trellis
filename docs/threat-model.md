# Trellis threat model

What Trellis protects against, what it doesn't, and what it assumes. Written for the 0.2
scope: grants over IdP identities, data-aware checks, and an anchored decision ledger. Read
this before relying on Trellis for anything.

## In one paragraph

Trellis limits what an agent can do to the overlap of three things: what the person it acts
for may do, what its owner allows it ever to do, and what the current task needs. It decides
each call it's asked about, denies by default, and records every grant and decision in a
hash-chained ledger before the answer goes out. It **contains damage and proves what
happened**. It does **not** stop an agent from misusing access it was legitimately given,
and it can only decide calls that something actually asks it about.

## What Trellis is in the system

```
 person ──signs in──► IdP ──token──► agent ──call──► enforcement point ──► tool / data
                                                       │      ▲
                                            "may it?"  ▼      │ yes / no + obligations
                                                     Trellis ──► ledger ──► anchor
```

- **IdP** (Entra, Okta, Keycloak, ...): says who the person and the agent are. Trellis trusts
  its signed tokens and nothing else for identity.
- **Enforcement point**: Reef, `TrellisGuard` inside an MCP server, or another gateway that
  asks Trellis (agentgateway or Envoy external authorization, an AuthZEN client). It enforces
  what Trellis decides. Trellis can't stop a call that bypasses it.
- **Trellis**: grants, the three checks, the ledger. One process, its database, its signing key.
- **Anchor**: somewhere the operator of Trellis can't rewrite, holding signed checkpoints of
  the ledger (object storage with a retention lock, a transparency log, a second party).

## Assets

| Asset | Why it matters |
|---|---|
| Data and tools the agent reaches | What an attacker or a confused agent wants |
| Grant tokens | Bearer tokens: whoever holds one acts as that agent for that person |
| The decision ledger | The record of who allowed what; only worth something if trustworthy |
| The signing key | Signs grants and checkpoints; with it, someone can forge a convincing history |
| Policy config (agents, contracts, templates) | Decides what's allowed; a bad change widens access |

## Threats Trellis addresses

| Threat | How Trellis handles it | Holds as long as |
|---|---|---|
| **An agent reaches beyond what its person may do** ("borrowed admin") | The person check runs against the person's own access, from their verified IdP token | Groups are read correctly (see the limits below) |
| **An agent reaches beyond its owner's limits** | The ceiling check, including `never` tags, which no grant can override | The agent's config is reviewed |
| **An agent uses access outside its task** | The task check: the grant's scope and actions; anything else is denied | Task scopes are narrower than the person's access |
| **Access outlives the task** | Grants expire (24 hours at most) and can be revoked; a dead grant denies everything | Clocks are roughly right |
| **Unclassified data or tools** | Deny by default: no contract or no tags means no access | Contracts are the only way to classify |
| **Sensitive fields leak in allowed results** | Fields a contract tags are masked unless every check allows them | The contract lists the fields (undeclared shapes are held back by Reef) |
| **"Who allowed this?" can't be answered** | Every grant and decision is in the ledger, linked to the grant, its issuer and the policy versions | The ledger is written first: no write, no answer |
| **Someone edits or deletes ledger entries** | Hash chain plus signed checkpoints; `trellisd ledger verify` finds edits, deletions and a cut tail | Checkpoints are anchored outside the operator's reach |
| **A grant token is replayed by another agent** | A token is bound to its agent; presenting it as anyone else is denied and logged | The enforcement point passes the caller's agent identity |
| **The agent sees downstream credentials** | With Reef, the agent never holds the server's credential; Reef brokers it per call | The deployment uses Reef's brokered or on-behalf-of modes |
| **A dependency is down** (database, catalog, IdP keys) | Every failure is a deny, never an allow | — |

## What Trellis does not protect against

Say these out loud. Claiming otherwise would mislead people.

1. **Prompt injection inside allowed scope.** If a document the agent reads tells it to do
   something its grant allows, Trellis allows it. Research has repeatedly broken published
   injection defences; Trellis doesn't try to detect injection.
2. **Exfiltration through allowed channels.** Each call is checked on its own. "Read private
   data, then send it to an allowed destination" passes if both calls are allowed. The fix is
   session-level rules (no external send after a private read), which Trellis doesn't have yet.
3. **Calls that never reach an enforcement point.** An agent with direct network access, or a
   tool that doesn't ask Trellis, is outside its control.
4. **A compromised IdP.** If the IdP issues a token for the wrong person, Trellis believes it.
5. **A compromised Trellis host or signing key.** An attacker with the key and the database can
   write a new, valid-looking history. Anchoring limits this to entries after the last anchored
   checkpoint.
6. **Wrong classification.** If a column holding salaries isn't tagged pii, it isn't masked.
   Trellis enforces the tags it's given; it doesn't find sensitive data.
7. **Over-broad tasks.** A task template that covers everything gives the task check nothing
   to do. Narrow templates are the operator's job; Trellis can only report how broad they are.
8. **What the agent remembers.** Grants cover calls, not the agent's memory or context. A shared
   agent can leak one person's results to another through its own memory.
9. **Write side effects.** Trellis can deny a write, but it doesn't undo one or require a human to
   confirm it yet.

## Assumptions

- The IdP's signing keys and the tokens' audience are configured correctly, and the person's
  groups reach Trellis completely, or Trellis can tell they didn't (see
  [enforcement and identity](design/enforcement-and-identity.md)).
- The enforcement point is the only network path from the agent to the tools it fronts.
- Policy changes go through review (the config lives in git, with owners per directory).
- The host clock is within a few minutes of real time.
- The ledger database and the anchor are separately controlled, or the anchor is append-only.

## Failure modes (all fail closed)

| What fails | What Trellis does |
|---|---|
| Ledger write | Deny; nothing is forwarded or returned |
| Grant store unreadable | Deny, with "Trellis can't read its grants" |
| A contract or tags missing for the resource | Deny, naming the resource |
| The person's groups incomplete (token overage, too many groups) | Deny the person check until the groups are looked up |
| An obligation can't be applied (a mask on a shape Reef can't read) | Hold the result back |
| Config invalid at startup | Refuse to start |
| IdP keys unreachable | Refuse new sign-ins; existing grants keep working until they expire |

## Residual risks and what would reduce them

| Risk | Mitigation | State |
|---|---|---|
| Allowed-channel exfiltration | Session rules over what a session has read and where it sends | Not built |
| Operator rewrites history | Anchor checkpoints outside the operator's control | Designed for 0.2 |
| Over-broad templates | Report each template's reach; track denial rates | Experiment in `docs/experiments/` |
| Tool descriptions change under the agent | `reef lock` | Shipped in reef-mcp 0.1.1 |
| Shared-agent memory leaks | Declare memory isolation in the agent config; enforce at the platform | Not built |
