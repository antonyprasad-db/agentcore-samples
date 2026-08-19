# Databricks Per-User Delegation with AgentCore Gateway Interceptor

Per-user identity propagation from Entra ID to Databricks via AgentCore Gateway REQUEST interceptor and RFC 8693 OAuth Token Exchange.

## Overview

The [existing Databricks DBSQL sample](../databricks-dbsql-agentcore-gateway) demonstrates M2M (service principal) authentication. This sample extends it with **per-user delegation** — each request carries the individual user's identity through to Databricks, enabling Unity Catalog to enforce per-user ACL.

### The Problem

AgentCore Gateway supports `CLIENT_CREDENTIALS` (M2M) and `AUTHORIZATION_CODE` for outbound auth. Databricks on AWS requires [RFC 8693 Token Exchange](https://docs.databricks.com/aws/en/dev-tools/auth/oauth-federation-exchange) to convert an external JWT into a Databricks user token — a grant type Gateway doesn't support natively.

### The Solution

A Gateway **REQUEST interceptor** (Lambda, ~30 lines) bridges the gap:

1. Gateway validates the inbound Entra ID JWT
2. Interceptor reads the `Authorization` header (Entra JWT)
3. Interceptor calls Databricks `/oidc/v1/token` with RFC 8693 token exchange
4. Databricks returns a user-scoped token
5. Interceptor overrides the outbound `Authorization` header
6. Gateway forwards the MCP request to Databricks with the user's token
7. `current_user()` returns the actual user's email, not a service principal

## Prerequisites

1. AWS credentials configured with permissions for AgentCore, IAM, Lambda, Cognito
2. Databricks workspace on AWS with Unity Catalog enabled
3. Databricks service principal with OAuth secret (for tool sync fallback)
4. Microsoft Entra ID tenant with an app registration
5. Databricks [federation policy](https://docs.databricks.com/aws/en/dev-tools/auth/oauth-federation-policy) trusting the Entra tenant
6. Databricks user matching the Entra `email` claim (via SCIM or manual)
7. Python 3.10+

### Databricks Federation Policy

Create in the Databricks account console (Settings → Authentication → Federation policies):

| Field | Value |
|---|---|
| Issuer | `https://sts.windows.net/<entra-tenant-id>/` (trailing slash required) |
| Audiences | `<entra-app-client-id>` |
| Subject claim | `email` |

> **Important:** The issuer must match the `iss` claim in the Entra JWT exactly. Device code flow with `/.default` scope returns v1.0 tokens with issuer `https://sts.windows.net/<tenant-id>/`, not `https://login.microsoftonline.com/<tenant-id>/v2.0`.

## Getting Started

The notebook covers:

1. Configure Databricks and Entra ID credentials
2. Create Gateway with Entra ID as inbound JWT authorizer
3. Create OAuth2 credential provider for Databricks (M2M fallback for tool sync)
4. Deploy the interceptor Lambda (RFC 8693 token exchange)
5. Add Databricks DBSQL MCP server as gateway target
6. Test: `SELECT current_user()` returns the Entra user's email
7. Verify via CloudWatch logs (step-by-step interceptor trace)

## Architecture

### Under the Hood: Control Plane vs Data Plane

Two separate token flows. The SP token discovers tools. The user token executes queries.

#### Control Plane (setup time, runs once)

```
Admin                          AgentCore                    Databricks
  │                               │                            │
  │── create_gateway_target ─────▶│                            │
  │   type: mcpServer             │                            │
  │   creds: CLIENT_CREDENTIALS   │                            │
  │   endpoint: /api/2.0/mcp/sql  │                            │
  │                               │                            │
  │── synchronize_gateway_targets▶│                            │
  │                               │── POST /oidc/v1/token ────▶│
  │                               │   grant_type=              │
  │                               │   client_credentials       │
  │                               │   client_id=<SP>           │
  │                               │   client_secret=<secret>   │
  │                               │◀─ { access_token: SP_TOK }─│
  │                               │                            │
  │                               │── POST /api/2.0/mcp/sql ──▶│
  │                               │   Authorization: SP_TOK    │
  │                               │   method: tools/list       │
  │                               │◀─ tools: [execute_sql,    ─│
  │                               │   execute_sql_read_only,   │
  │                               │   poll_sql_result]         │
  │◀─ tools synced ────────────── │                            │

  SP token used. No interceptor. Gateway discovers tools from
  Databricks managed MCP using the credential provider.
```

#### Data Plane (every agent request)

```
Agent          Gateway         Interceptor       Databricks       Databricks
(Entra JWT)    (validates)     (Lambda)          OIDC             MCP
  │               │               │               │               │
  │── POST /mcp ─▶│               │               │               │
  │  Auth: Bearer │               │               │               │
  │  <ENTRA_JWT>  │               │               │               │
  │  body:        │               │               │               │
  │   tools/call  │               │               │               │
  │   execute_sql │               │               │               │
  │               │               │               │               │
  │               │── VALIDATE    │               │               │
  │               │  sig/exp/     │               │               │
  │               │  aud/iss ✅   │               │               │
  │               │               │               │               │
  │               │  Gateway would normally fetch SP token here   │
  │               │  from credential provider (CLIENT_CREDENTIALS)│
  │               │  BUT interceptor runs first ↓                 │
  │               │               │               │               │
  │               │── invoke ────▶│               │               │
  │               │  headers:     │               │               │
  │               │   Auth: Bearer│               │               │
  │               │   <ENTRA_JWT> │               │               │
  │               │  body:        │               │               │
  │               │   tools/call  │               │               │
  │               │               │               │               │
  │               │               │── POST ──────▶│               │
  │               │               │  /oidc/v1/    │               │
  │               │               │  token        │               │
  │               │               │  grant_type=  │               │
  │               │               │  token-       │               │
  │               │               │  exchange     │               │
  │               │               │  subject_token│               │
  │               │               │  =<ENTRA_JWT> │               │
  │               │               │               │               │
  │               │               │◀─ {          ─│               │
  │               │               │  access_token:│               │
  │               │               │  <USER_TOK> } │               │
  │               │               │               │               │
  │               │◀─ return ──── │               │               │
  │               │  headers:     │               │               │
  │               │   Auth: Bearer│               │               │
  │               │   <USER_TOK>  │  ← OVERRIDES SP TOKEN         │
  │               │  body:        │               │               │
  │               │   tools/call  │               │               │
  │               │               │               │               │
  │               │── POST /api/2.0/mcp/sql ─────────────────────▶│
  │               │  Authorization: Bearer <USER_TOK>             │
  │               │  method: tools/call                           │
  │               │  name: execute_sql                            │
  │               │  arguments: {query: "SELECT ..."}             │
  │               │               │               │               │
  │               │               │               │  Resolves     │
  │               │               │               │  USER_TOK to  │
  │               │               │               │  user@co.com  │
  │               │               │               │               │
  │               │◀─ SQL results ────────────────────────────────│
  │◀─ results ─── │               │               │               │

  USER token used. SP token never sent on data plane.
  Interceptor swapped it before the request left Gateway.
```

### Control Plane vs Data Plane

| | Control Plane (tool sync) | Data Plane (every request) |
|---|---|---|
| When | `synchronizeGatewayTargets` | Agent calls `tools/call` |
| Token | SP via credential provider (M2M) | User via interceptor (RFC 8693) |
| Identity | Service principal | Actual user |
| Interceptor | Not involved | Reads JWT, exchanges, overrides header |

### Security

| Layer | What | How |
|---|---|---|
| Inbound auth | Gateway validates Entra JWT | Signature, expiry, audience, issuer |
| Tool-level ACL | Cedar policies (optional) | Permit/deny per caller per tool |
| Identity swap | Interceptor Lambda | RFC 8693 token exchange |
| Data-level ACL | Unity Catalog | Per-user permissions |
| Secrets | SP creds in Secrets Manager | Encrypted at rest, auto-refreshed |
| User token | Exists only in Lambda memory | Never stored, never logged, never returned |

## Widening to the other Managed MCP servers

The interceptor does not inspect the MCP path — it only swaps the outbound `Authorization` header — so the same Lambda works for any Databricks Managed MCP server. Adding a surface means adding a gateway target that points at a different path.

It is also not tied to Microsoft Entra. The interceptor decodes claims and performs an RFC 8693 exchange, so any OIDC issuer works in principle. Verified as far as decoding: driving the interceptor with an Amazon Cognito ID token, it read the `email` claim and attempted the exchange exactly as it does for an Entra token. Switching issuers is not free, though — it needs both a new `authorizerConfiguration` on the gateway (the walkthrough pins Entra's `discoveryUrl` and `allowedAudience`) and a Databricks federation policy for the new issuer.

> **What is verified here, and what is not.** Three rows of the governance table were measured; the AI Search row is from Databricks documentation, and Genie's Unity Catalog layer is inferred. Each row is labelled. Crucially, those measurements were taken **calling the Managed MCP endpoints directly** with each principal's own token — **not** through an AgentCore Gateway. [What changes behind a Gateway](#what-changes-behind-a-gateway) covers the difference, which is significant for the functions surface. The gateway wiring for the additional surfaces has not been exercised end to end; treat the registration snippet as the pattern to follow, not as run code.

| Surface | MCP path | OAuth scope |
|---|---|---|
| DBSQL | `/api/2.0/mcp/sql` | `sql` |
| Unity Catalog functions | `/api/2.0/mcp/functions/{catalog}/{schema}` or `.../{schema}/{function_name}` | `unity-catalog` |
| Genie, one space | `/api/2.0/mcp/genie/{genie_space_id}` | `genie` |
| Genie One, workspace-wide | `/api/2.0/mcp/genie` | `genie` |
| AI Search (formerly Vector Search) | `/api/2.0/mcp/ai-search/{catalog}/{schema}/{index_name}` | `ai-search` |

Paths and scopes are from the Databricks reference table. The DBSQL, functions and per-space Genie paths were additionally exercised directly; Genie One and AI Search were not.

The per-server scope applies to the **user token** obtained for that surface, not to the M2M credential provider — the `scopes: ["all-apis"]` in the snippet below and in the interceptor's exchange are the provider and OBO requests respectively, and narrowing those to a single surface is a separate change from anything in this table.

Two details on the paths:

- **AI Search** is the current prefix, but the former `/api/2.0/mcp/vector-search/` prefix and `vector-search` scope still work. No need to rewrite a working target; prefer `ai-search` in new code to match the docs.
- **Unity Catalog functions accepts two path forms.** The reference table documents the per-function form; the schema-level form also works and returns every function in the schema that the caller may execute. Both were exercised — see [How the table was established](#how-the-table-was-established).

### Registering the additional targets

Each surface is its own gateway target sharing the one credential provider and the one interceptor. `agentcore` (the `bedrock-agentcore-control` boto3 client), `gateway_id`, `provider_arn`, `DATABRICKS_HOST` and `import time` all come from the walkthrough above:

```python
CATALOG, SCHEMA = "my_catalog", "my_schema"
GENIE_SPACE_ID  = "01f0a1b2c3d4e5f60718293a4b5c6d7e"   # Genie space to expose
INDEX_NAME      = "my_index"                           # AI Search index (managed embeddings)

# The walkthrough already created the databricks-sql target — these are the additions.
surfaces = {
    # Schema-level, so one target covers every function the caller may execute.
    # Append /{function_name} instead to scope a target to a single function.
    "databricks-functions": f"/api/2.0/mcp/functions/{CATALOG}/{SCHEMA}",
    "databricks-genie":     f"/api/2.0/mcp/genie/{GENIE_SPACE_ID}",
    "databricks-ai-search": f"/api/2.0/mcp/ai-search/{CATALOG}/{SCHEMA}/{INDEX_NAME}",
}

target_ids = []
for name, path in surfaces.items():
    try:
        target = agentcore.create_gateway_target(
            gatewayIdentifier=gateway_id,
            name=name,
            description=f"Databricks Managed MCP ({name}) — per-user via interceptor",
            targetConfiguration={"mcp": {"mcpServer": {"endpoint": f"{DATABRICKS_HOST}{path}"}}},
            credentialProviderConfigurations=[
                {
                    "credentialProviderType": "OAUTH",
                    "credentialProvider": {
                        "oauthCredentialProvider": {
                            "providerArn": provider_arn,
                            "grantType": "CLIENT_CREDENTIALS",
                            "scopes": ["all-apis"],
                        }
                    },
                }
            ],
        )
        target_ids.append(target["targetId"])
    except agentcore.exceptions.ConflictException:
        # Re-runnable: adopt the existing target instead of aborting the rest.
        existing = next(
            t for t in agentcore.list_gateway_targets(gatewayIdentifier=gateway_id)["items"]
            if t["name"] == name
        )
        target_ids.append(existing["targetId"])

# Wait for READY. Status values are upper case; these are the transient ones, and
# anything else that is not READY is terminal.
TRANSIENT = {
    "CREATING", "UPDATING", "SYNCHRONIZING",
    "CREATE_PENDING_AUTH", "UPDATE_PENDING_AUTH", "SYNCHRONIZE_PENDING_AUTH",
}
for name, target_id in zip(surfaces, target_ids):
    status = None
    for _ in range(24):
        t = agentcore.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)
        status = t.get("status")
        if status not in TRANSIENT:
            break
        time.sleep(5)
    if status != "READY":
        raise RuntimeError(f"{name} is {status}: {t.get('statusReasons')}")

agentcore.synchronize_gateway_targets(
    gatewayIdentifier=gateway_id, targetIdList=target_ids
)
```

The service principal behind `provider_arn` is what performs `tools/list` at sync time, so it needs enough grant to *see* each surface: `EXECUTE` on the functions you want listed, and `CAN_READ` or better on the Genie space. A surface the SP cannot see should sync no tools for that target; I have not exercised the sync path, so I cannot say whether that surfaces as an empty tool list, a `SYNCHRONIZE_UNSUCCESSFUL` target status, or an error — check the target's `status` and `statusReasons` rather than assuming.

### Where governance is enforced differs per surface

**Measured by calling the Managed MCP endpoints directly**, with each principal presenting its own token. See the next section for how a Gateway changes this.

| Surface | `tools/list` gated by | Call gated by | Basis |
|---|---|---|---|
| Unity Catalog functions | **`EXECUTE` grant** — an ungranted function is *absent* from the list | `EXECUTE` grant | measured |
| DBSQL | nothing — the same three tools (`execute_sql`, `execute_sql_read_only`, `poll_sql_result`) go to every caller | **row filters and column masks**, applied at query time | measured |
| Genie, one space | **the Genie space ACL** — `CAN_READ` is sufficient — checked before Unity Catalog | space ACL, then Unity Catalog on the underlying tables | ACL measured; Unity Catalog layer inferred |
| AI Search | index-level grant | index-level grant only — no row or column enforcement | Databricks docs, not measured |

Called directly, the functions surface has a useful property: a caller without `EXECUTE` never learns the tool exists, so a model driving it cannot attempt the call and no denial has to be explained. Genie is the opposite shape — a workspace object ACL is checked first, so a caller without space permission fails at `tools/list` with `PERMISSION_DENIED` rather than receiving an empty list. The Genie row describes the per-space server; Genie One is workspace-wide and has no single space ACL to key on.

### What changes behind a Gateway

The visibility column above does **not** survive a gateway, and this is worth designing around rather than discovering.

Two mechanisms combine:

- **Tool listing is served from an SP-built cache.** `mcpServer.listingMode` defaults to `DEFAULT`, documented as: *"MCP resources for default targets are cached at the control plane for faster access. MCP resources for dynamic targets will be dynamically retrieved when listing tools."* The cache is populated by `synchronize_gateway_targets`, which authenticates as the credential provider's service principal — the walkthrough's own control-plane diagram says exactly this.
- **The interceptor deliberately does not touch listing.** It returns early for `tools/list` without swapping the header, so even with `listingMode="DYNAMIC"` the upstream list is fetched with the SP's token, never the caller's.

So every caller sees the tools the *service principal* can see. On the functions surface a user with no `EXECUTE` is still offered the tool and gets a denial when the call reaches Unity Catalog — the inverse of the direct-call behaviour. In effect a gateway collapses the functions surface into the DBSQL shape: no visibility gate, enforcement at call time.

Call-time enforcement is unaffected, because that is the leg the interceptor rewrites. Per-user *data* access still holds on every surface. It is only per-user *tool visibility* that does not.

Getting visibility back would take `listingMode="DYNAMIC"` **and** an interceptor that exchanges the token for `tools/list` too, instead of passing it through. I have not tried that combination, and whether it is supported is a question for the AgentCore team rather than an assumption to build on.

### AI Search: row and column permissions are not part of the picture

Two documented constraints that work together rather than leaving a gap:

- **You cannot create an AI Search index from a table that has row filters or column masks applied.** Index creation is refused, so this is caught up front rather than in production.
- **Row and column level permissions are not supported on an index.** The documented alternative is application-level ACLs via the filter API.

The design consequence: on this surface there is no way to push per-user row scoping down to Unity Catalog. If the corpus needs row scoping, keep the sensitive columns behind a Unity Catalog function or a governed table — where filters and masks do apply — or scope retrieval yourself.

Scoping it yourself means the `_meta` block on the tool call, which Databricks documents as *"configuration parameters that you can preset in your agent code to set behavior deterministically"*:

```json
{
  "name": "<ai-search tool name>",
  "arguments": { "query": "unusual card activity last week" },
  "_meta": {
    "filters": "{\"region\": \"EMEA\"}",
    "num_results": 5,
    "columns": ["chunk", "region"]
  }
}
```

Note where that can be set. There is no target-registration field that injects `_meta` into forwarded calls — `mcpServer` takes only `endpoint`, `mcpToolSchema`, `listingMode` and `resourcePriority`, and `mcpToolSchema` is *"supported only when the credential provider is configured with an authorization code grant type"*, which this sample is not. So behind a gateway the choices are trusted agent code or an interceptor that rewrites the request body. Whichever you pick, the value filtered on has to come from the verified caller identity: derived from anything the model can influence, it stops being a control. Querying an index through this server also requires Databricks managed embeddings.

### How the table was established

The measured rows were produced with two Databricks service principals holding differential grants, each calling the endpoints **directly** with its own token, on a workspace running Managed MCP:

- **Functions** — one principal held `EXECUTE` on two functions, the other on one. On the schema-level path, `tools/list` returned two tools and one tool respectively; the ungranted function was absent rather than present-and-denied. On the per-function path for the ungranted function, the same principal received `BAD_REQUEST: Function '…' not found` — reported as nonexistent rather than forbidden, the same visibility property expressed as an error.
- **Both functions path forms** — schema-level returned every `EXECUTE`-granted function in the schema; the per-function form returned exactly the one named. Both are live.
- **DBSQL** — both principals received the identical three tools. A `SELECT` over the same table then returned disjoint row sets, with a masked column for one principal and the raw value for the other.
- **Genie** — with no space grant, both principals failed `tools/list` with `PERMISSION_DENIED`. Granting `CAN_RUN` to one and `CAN_READ` to the other gave both the same two tools: `CAN_READ` is enough to list. The user-facing "Can View" wording in the denial corresponds to `CAN_READ` at the permissions API, which has no `CAN_VIEW` level.

The AI Search row is from Databricks' documentation rather than measurement. Genie's second layer — Unity Catalog grants on the tables behind the space — is the same mechanism demonstrated on DBSQL but was not separately measured. Genie One was not exercised. The gateway behaviour in [What changes behind a Gateway](#what-changes-behind-a-gateway) is derived from the AgentCore API contract and the interceptor's source, not from a running gateway.

Managed MCP is in Public Preview at the time of writing; treat surface behaviour as subject to change.

## Gotchas

1. **Token version matters.** Entra v1.0 tokens use `iss: sts.windows.net`. Use v1.0 discovery URL for Gateway. Use `sts.windows.net` issuer for the Databricks federation policy.

2. **`allowedClients` breaks v1.0 tokens.** Entra v1.0 uses `appid` not `client_id`. Omit `allowedClients` from Gateway authorizer, use `allowedAudience` only.

3. **App tokens can't do per-user.** `client_credentials` tokens have no `email` claim. Per-user requires a user token (device code, auth code, or SSO).

4. **Tool sync needs SP.** `synchronizeGatewayTargets` uses the M2M credential provider. The interceptor only overrides auth on `tools/call`.

5. **Databricks user must exist.** The `email` in the Entra JWT must match a Databricks user with workspace access and SQL warehouse CAN USE permission.

## Resources

- [Databricks managed MCP servers](https://docs.databricks.com/aws/en/generative-ai/mcp/managed-mcp)
- [Databricks OAuth token federation (RFC 8693)](https://docs.databricks.com/aws/en/dev-tools/auth/oauth-federation-exchange)
- [Databricks federation policy configuration](https://docs.databricks.com/aws/en/dev-tools/auth/oauth-federation-policy)
- [AgentCore Gateway interceptors](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-interceptors.html)
- [AgentCore Gateway header propagation](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-headers.html)
- [Microsoft Entra ID as AgentCore IdP](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity-idp-microsoft.html)
- [Existing M2M sample](../databricks-dbsql-agentcore-gateway)
