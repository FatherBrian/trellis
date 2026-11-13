# Enforcement and identity

Two practical questions for Trellis 0.2: **what asks Trellis for a decision**, and **how
Trellis learns the person's groups** from the IdP a team already uses. As of November 2026.

## 1. What asks Trellis

Trellis decides; something in the request path has to ask it, and enforce the answer. Four
routes, from most complete to most portable:

| Route | Who it suits | Tool list filtered per grant | Masks results | Brokers credentials | Ledger |
|---|---|---|---|---|---|
| **Reef** (Trellis in-process) | Teams that can put one gateway in front of their MCP servers | Yes | Yes | Yes (obo, agent, brokered) | Full: list, decision, forward, result |
| **`TrellisGuard`** in an MCP server | One server you control, no gateway | No (the server lists its own tools) | Yes, inside the server | No | Decision |
| **External authorizer** behind agentgateway or Envoy | Teams already running one of those | No | No | No (the gateway's job) | Decision |
| **AuthZEN** from any client | Anything that speaks the OpenID AuthZEN API | No | No | No | Decision |

### External authorizer: agentgateway and Envoy

[agentgateway's external authorization](https://agentgateway.dev/docs/standalone/latest/configuration/security/external-authz/)
calls out on every request, over Envoy's gRPC `ext_authz` API or plain HTTP (2xx allows,
anything else denies). It can include the request body, which for an MCP `tools/call` holds
the tool name and arguments, and send JWT claims as metadata. Its failure mode defaults to deny,
and its timeout defaults to 2 seconds. Cerbos integrates with it this way: upstream server as
the resource, tool name as the action, arguments as attributes
([Cerbos](https://cerbos.dev/blog/authorizing-mcp-tool-calls-at-the-gateway-or-inside-the-proxy)).
Envoy's own `ext_authz` filter works the same way
([Cerbos on Envoy](https://www.cerbos.dev/blog/envoy-ext-authz-enforcing-one-authorization-policy-at-gateway-in-service)).

**Plan for 0.2:** a `POST /ext-authz` endpoint on `trellisd serve`, in agentgateway's HTTP mode:

1. Read the grant token from `Authorization: Bearer`.
2. Parse the JSON-RPC body. For `tools/call`, map `server + params.name` to the tool's address
   (`mcp://<server>/<tool>`); the server comes from a header or path the gateway sets.
3. Decide with the three checks, write the ledger, and answer `200` or `403` with the reason.
4. For `tools/list`, `initialize` and other methods, answer `200` (the gateway can't filter
   lists, so the tools stay visible but calls to them are denied).

**What this route gives up**, as Cerbos's write-up says of any gate in the path: it's a yes or
no. It can't filter the tool list, mask a result, or apply a row filter. Use Reef when those
matter.

### AuthZEN

Trellis already serves AuthZEN's evaluation endpoint. AuthZEN 1.0 has been an OpenID Final
Specification since January 2026. Secondary sources list Kong, Envoy, Tyk, Zuplo and WSO2
among gateways that can act as AuthZEN enforcement points
([source](https://andrewdoering.org/blog/2026/authzen-shared-signals-framework-part-1-fundamentals/));
check each product's own docs before relying on that.

## 2. How Trellis learns the person's groups

The person check needs the person's groups. Teams keep those in their IdP, so Trellis 0.2
reads them from the person's verified token, and stops needing a `people.yaml`. The catch is
that both major IdPs cap the groups in a token.

### Entra ID

- A JWT carries at most **200** group memberships, nested ones included (SAML: 150). Above
  that, Entra leaves the `groups` claim out and sends an **overage** marker:
  `"_claim_names": {"groups": "src1"}` with a `_claim_sources` entry pointing at Microsoft
  Graph. The implicit flow signals it with `hasgroups` instead
  ([Microsoft Learn](https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles),
  [troubleshooting](https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/app-integration/get-signed-in-users-groups-in-access-token)).
- Microsoft's guidance: check for the marker's **presence**, never treat a missing `groups`
  claim as "no groups", and prefer **Groups assigned to the application** so tokens only carry
  the groups that matter. Group filtering only applies to users in 1,000 groups or fewer.

### Okta

- The groups claim is capped at **100**. When a filter matches more, Okta returns an error
  ("The groups claim matched too many groups") rather than a truncated list
  ([Okta support](https://support.okta.com/help/s/article/error-the-groups-claim-matched-too-many-groups-and-must-be-configured-to-match-fewer-groups)).
  Community reports disagree on details (Token Preview versus real tokens), so test with a real
  token.
- The fix is a narrower filter (`startsWith`, a regex) that only includes the groups Trellis
  policies name, or a lookup through Okta's API.

### The rule Trellis follows

1. **Claim first.** Use the `groups` claim when it's present and complete.
2. **Detect incompleteness.** Entra's `_claim_names.groups` or `hasgroups`, or a configured
   provider that's known to cap, means the claim can't be trusted as complete.
3. **Look up, then cache.** With a configured lookup (Microsoft Graph, with
   `GroupMember.Read.All` granted to Trellis's app; Okta's `/users/{id}/groups`), fetch the
   person's groups and cache them for a few minutes. Record in the ledger that the groups came
   from a lookup.
4. **Otherwise, deny.** With no lookup configured, the person check denies with "the IdP didn't
   send all of this person's groups", and never falls back to treating them as having none, or
   to trusting a partial list.
5. **Recommend the configuration** that avoids the problem: groups assigned to the application
   (Entra), or a filter limited to the groups Trellis policies use (Okta).

Only groups that a Trellis policy names matter, so in most deployments a filtered claim keeps
tokens small and lookups rare.
