# Azure Code-Mode MCP Server — Design Spec

**Status:** reviewed draft / implementation plan
**Working name:** `armctl` (placeholder)

---

## 1. Motivation

The Azure CLI maintains ambient, mutable, process-global state that must be internally
consistent across at least three files, and only one code path reconciles them:

| State | File | Written by |
|---|---|---|
| Active cloud | `~/.azure/config` → `[cloud] name` | `az cloud set`; process override: `AZURE_CLOUD_NAME` |
| Active subscription | `~/.azure/azureProfile.json` → `isDefault: true` | `az account set`, `az login` |
| Per-cloud remembered subscription | `~/.azure/clouds.config` → `[<Cloud>] subscription` | `az cloud set`, `az account set` |

`switch_active_cloud()` calls `_set_active_subscription()`, which reads `clouds.config` and
moves the single global `isDefault` flag. Any other route to changing the active cloud —
`AZURE_CLOUD_NAME`, hand-editing `config` — skips that reconciliation, leaving `isDefault`
pointed at a subscription that `load_cached_subscriptions()` will then filter out entirely
(it filters on `environmentName == active_cloud.name` before looking for `isDefault`).

Consequences we are designing around:

- A single `az` process can target exactly one cloud. Commercial + Government in one
  operation is impossible without serializing through global mutation.
- Workflows that switch clouds or subscriptions through profile-mutating commands race on
  shared files. A process-local cloud override avoids that write but can leave the default
  subscription inconsistent with the selected cloud.
- The subscription in play is implicit, so a command's meaning depends on invisible state.

The one part of `az`'s state that is *already correctly partitioned* is credential caching:
MSAL entries are keyed by authority host + `home_account_id` + client ID, so commercial and
Government identities coexist. The cache's persistence format is an Azure CLI
implementation detail. **We reuse Azure CLI as the credential broker and discard its
ambient profile-selection semantics.**

### 1.1 Goals

- **Cloud is explicit on every call.** One token to write, and the axis where a mistake is
  most expensive.
- **Subscription and tenant are bound per-cloud, once, immutably** — declared at session
  open or in config, never mutated mid-session, always echoed in the call log.
- One session can address multiple clouds concurrently.
- Reuse credentials the user already has cached via `az login` without running Azure
  resource commands or mutating Azure CLI profile state.
- Default to the fail-closed `inspect` tier; recommend a read-scoped principal when the
  interceptor must be backed by a real authorization boundary.
- Expose the full ARM surface without enumerating it as MCP tools.
- Make every effective authority, tenant, subscription, identity, API version, and policy
  decision visible at the request boundary.

### 1.2 Non-goals

- Not a replacement for `az` as an interactive human CLI.
- No tenant/customer/business-object modeling. Pure Azure. Callers supply their own
  subscription↔tenant↔customer mapping from their own context.
- Not a sandbox hardened against adversarial code (see §3.3).
- No remote or multi-user transport in v0. The first deployment is a local stdio MCP
  server running with the user's OS permissions.
- No Azure Stack Hub / Azure Stack HCI specific handling in v1, though the cloud metadata
  design does not preclude it.

---

## 2. Cloud Model

### 2.1 Clouds are values

Every request carries a cloud identifier. There is no active cloud, no default cloud, no
process state that can be wrong.

```js
const [commercial, gov] = await Promise.all([
  az.cloud('AzureCloud').graph(q),
  az.cloud('AzureUSGovernment').graph(q),
]);
```

Shorthand accessors `az.com` and `az.gov` bind to `AzureCloud` and `AzureUSGovernment`.

Cloud is the one axis that is **never** defaulted. It costs one token to write, it is the
axis where a wrong guess is most expensive (wrong-cloud writes, wrong-cloud endpoints), and
there is no sensible tiebreak between two clouds a user is logged into.

### 2.2 Subscription binding

Subscription and tenant *are* defaulted — per cloud, declared once, immutable for the
session.

```toml
# ~/.config/armctl/config.toml
[clouds.AzureUSGovernment]
subscription = "…"
tenant       = "…"

[clouds.AzureCloud]
subscription = "…"
```

Overridable at session open, and per-call within the session's fixed subscription
allowlist for the exceptional case:

```js
await az.gov.list({ type: 'Microsoft.Sql/servers' })
await az.gov.sub(OTHER).list({ type: 'Microsoft.Sql/servers' })
```

By default the allowlist contains only each cloud's binding. A session may declare more
subscription/tenant pairs. Resource Graph's broader `allAccessible` mode is a separate
session option and does not widen L0/L1. `.sub(OTHER)` never widens the allowlist at
runtime.

**Auto-binding:** if a cloud has exactly one enabled cached subscription candidate in
`azureProfile.json`, bind it automatically with no configuration. A candidate is keyed by
`(environmentName, tenantId, subscriptionId, user.name)`, not only subscription ID.
Duplicate tenant or account routes to the same subscription, disabled subscriptions,
tenant-level pseudo-accounts, and more than one candidate are ambiguous and require
configuration.

A pleasant side effect: generated code can use bindings rather than reproducing GUIDs.
Resolved IDs still appear in structured session results and audit records, but the model
does not need to invent or copy them into every call.

#### 2.2.1 Invariants that make this safe

This is not the `az` failure mode, and the difference is mechanical rather than stylistic:

| `az` | Here |
|---|---|
| Single `isDefault` flag shared across all clouds | One binding **per cloud**, no shared slot |
| Mutated by any concurrent process writing `~/.azure` | Immutable for the session's lifetime |
| Effective value invisible at call time | Resolved subscription in every call-log entry |
| Cloud and subscription can silently disagree | Binding is keyed by cloud; disagreement is unrepresentable |
| Requires `_set_active_subscription()` reconciliation | Nothing to reconcile — one source |

Enforced rules:

1. **No mutation API.** There is no `az.setSubscription()`. Nothing a script does can change
   what a later statement in that script means. This is the specific property `az` violates
   and the actual source of the original bug.
2. **Resolution is always logged.** Every call-log entry records the effective subscription
   and its provenance (`binding` | `explicit` | `auto`).
3. **Ambiguity fails loud.** A cloud with no binding and more than one cached subscription
   is an error that lists the candidates. Never pick one.
4. **Bindings are validated live.** `azureProfile.json` is a discovery cache, not an
   authority. Before the first arbitrary request for a binding, acquire a token using the
   binding's cloud and tenant and call `GET /subscriptions/{id}` on that cloud's ARM
   endpoint. A missing, inaccessible, or wrong-cloud subscription is a hard error. Cache
   successful validation for the session.
5. **Explicit overrides are explicit triples.** The GUID must be in the session's fixed
   allowlist. `.sub(guid)` may reuse a unique cached
   tenant for that cloud. If the cache has no match or multiple tenant routes, require
   `.sub(guid, { tenant })`; never guess a tenant.

#### 2.2.2 Resource Graph is deliberately asymmetric

Resource Graph can query every accessible subscription, but doing that by default would
reintroduce invisible scope. `az.gov.graph(q)` queries the bound subscription.
Cross-subscription scope is explicit:

```js
await az.gov.graph(q, { subscriptions: [SUB_A, SUB_B] });
await az.gov.graph(q, { scope: 'allAccessible' });
```

`allAccessible` is logged distinctly and is available only when the session's
`graphScopes` declared that scope for the cloud. This preserves ARG's fleet-query value
without making an omitted argument mean "the whole estate."

### 2.3 Endpoint resolution

Endpoint discovery has a bootstrap problem: the metadata URL itself needs a trusted host.
Ship reviewed manifests for `AzureCloud` and `AzureUSGovernment`, including the metadata
URL and the minimum endpoints needed to authenticate and reach ARM. Refresh metadata from
that pinned URL with a TTL, validate it against the manifest's allowed authority and DNS
suffixes, and swap it atomically. A refresh failure retains the last known-good manifest.

Custom, USSec, USNat, and air-gapped clouds require an explicit manifest or an
`ARM_CLOUD_METADATA_URL` equivalent in configuration. A metadata response is not assumed
to contain every data-plane endpoint; configuration may fill missing values. No endpoint
is inferred by string substitution.

Resolved per cloud: `resourceManager`, `activeDirectory` (authority),
`authentication.audiences`, `suffixes.*`, and the explicitly supported data-plane
endpoints. The manifest version and source are recorded in the call log.

### 2.4 API version resolution

Azure Government and commercial Azure expose different resource-provider API-version
sets, and Government often receives versions later. A version literal that works in
`AzureCloud` may 404 or return a different schema in `AzureUSGovernment`. Therefore:

- Live availability is **per (cloud, subscription, resource type)**, sourced from
  `GET /subscriptions/{id}/providers/{namespace}?api-version=2021-04-01`, cached with TTL.
- L1 default: the reviewed non-preview version pinned in the shipped schema index for the
  target cloud. A live provider-metadata lookup verifies availability but does not silently
  advance the default.
- L0 `az.request` requires `apiVersion`; raw requests never guess.
- Overridable per call: `{ apiVersion: '2023-08-01' }`.
- The schema index (§7) returns cloud-specific available versions so the model does not
  guess.

---

## 3. Runtime

### 3.1 Choice

**Rust + `deno_core`.** One `JsRuntime` (V8 isolate) per session, hosted in a worker
process behind the MCP front end.

Rationale:

- V8 isolates: real JS, real async, models write it well, `for await` maps naturally onto
  paged ARM APIs.
- `deno_core` gives promise/microtask/module plumbing, an `op` layer for host functions,
  and startup snapshots. Actual startup and RSS are measurement gates (§12.4).
- **Capabilities are opt-in by linking extensions.** The worker does not link `deno_fetch`,
  `deno_net`, `deno_fs`, or `deno_process`. The isolate therefore has no I/O primitive of
  any kind. The injected `az` object is the only door out.
- Native tokio integration: ARM calls are ordinary async ops on the host runtime.

The process boundary is for crash containment, not for treating generated code as hostile.
The front end owns credentials, policy, plans, and durable logs. The worker receives only
normalized request intents and opaque session-scoped handles; it never receives a token.

Rejected: raw `rusty_v8` (rebuild all the plumbing); Node + `isolated-vm` (workable, but
Node hosting and fiddlier per-isolate heap accounting); Go + `goja` (ES5.1-era, slow);
Python (`RestrictedPython` is not a sandbox; a real Python sandbox costs a container per
invocation, which the ergonomics do not justify).

### 3.2 Resource governance

| Control | Mechanism |
|---|---|
| Wall-clock timeout | Per `azure_run` call, default 60s; cancel host ops and call V8 `TerminateExecution` |
| CPU / runaway loops | Worker watchdog terminates execution; kills the worker if V8 does not yield |
| Heap ceiling | Per-isolate heap limits plus an OS RSS limit on the worker process |
| Session lifetime | Idle TTL (default 30m) + absolute max, LRU eviction under memory pressure |
| Concurrent sessions | Configurable cap; each is a full isolate |
| Host-op input | Per-request path/header/body limits before allocation or network I/O |

An ordinary timeout kills the session and returns a structured error. A V8 fatal OOM may
kill the worker; the front end reports all sessions in that worker as evicted and starts a
fresh worker. An in-process isolate alone cannot honestly promise that a V8 OOM leaves its
host process healthy.

### 3.3 Explicit security posture

**A V8 isolate is a capability boundary, not a security boundary.** V8 escapes exist. The
worker process limits the blast radius of crashes, but is not an adversarial-code sandbox.
This design is for *a well-intentioned model making mistakes*. If generated code becomes
untrusted, the worker needs an OS sandbox or microVM with network access restricted to the
front-end IPC channel.

The token never enters the isolate. Request signing happens host-side, after policy
evaluation.

---

## 4. Identity and Credentials

### 4.1 Two identities, resolved by availability

```js
azure_session_open({
  identity: 'reader' | 'user',
  armTier: 'inspect' | 'read' | 'write',
  dataPlanes: [],
  bindings,
  allowedSubscriptions,
  graphScopes,
})
```

| Identity | Source | Purpose |
|---|---|---|
| `reader` | Dedicated service principal with a read-scoped role | The actual security boundary |
| `user` | MSAL cache from `az login` | Zero-config default; scopes the SP lacks |

If identity is omitted, resolve `reader` only when a reader principal is configured for
every requested cloud/tenant binding; otherwise resolve `user` for the whole session.
Report the resolution and reason before opening the session. An explicitly requested but
incomplete identity is an error. Never fall back from `reader` to `user` for one request or
one cloud.

The resolved principal mapping by `(cloud, tenant)` and all capability ceilings are
**session-fixed**. A persistent isolate may retain
globals, closures, console output, and refs derived from earlier calls. Allowing a later
call to claim a lower tier or a different identity does not unsee those values and creates
a privilege-laundering path. Open a separate session to use another principal or capability
profile.

The resolved identity, ARM tier, data-plane grants, and reason are reported at session open
and echoed in every `azure_run` result:

```
identity=user  (no reader SP configured)   tier ceiling: inspect
```

### 4.2 Ceremony attaches to escalation, not to the fallback

Both identities default to ARM tier `inspect` with no data-plane grants. The difference is
**what stands behind the ceiling**:

| | `reader` | `user` |
|---|---|---|
| Default tier | `inspect` | `inspect` |
| `read` (secrets) | opt-in per session | opt-in per session, **flagged** |
| `write` | opt-in + plan/apply, bounded by the SP's RBAC | opt-in + plan/apply, bounded by **nothing but the interceptor** |
| Backstop if the interceptor has a bug | Azure RBAC denies | Nothing |

So the escalation ceremony scales with `(tier × identity)`. Under `reader`, opening a
`read` session is routine — RBAC will deny anything the interceptor mistakenly allows.
Under `user`, the same request is the moment a policy bug can become a real `listKeys`
against production, so it is opt-in, logged distinctly, and surfaced in every result
summary rather than buried in the call log.

Opening a `read` session also authorizes secret-bearing response data to enter the isolate
and, if generated code returns or prints it, the MCP result and model context. The
interceptor is not a confidentiality boundary. Secret routes suppress automatic previews
and durable response logging, but they cannot make a string secret after arbitrary JS has
handled it. Use `read` only when that exposure is intended.

`write` under `user` is permitted rather than blocked. Plan/apply (§6.5) puts a human in
front of every mutation, and blocking it outright would just send people back to `az` with
no interceptor and no audit trail at all — strictly worse.

### 4.3 Privilege disclosure at session open

When resolving to `user`, decode the token's tenant and object ID and make a best-effort
query for visible role assignments at each bound subscription scope. Surface only what was
actually observed:

```
identity=user  observed roles: Owner @ /subscriptions/…
role visibility: incomplete  interceptor is the only guardrail
```

Role-assignment enumeration is not an effective-permissions calculator: group membership,
PIM activation, inherited assignments, deny assignments, and visibility permissions can
make the result incomplete. Never print `roles: Reader` as proof that the user is
read-only. Failure to enumerate is a warning, not a hard error.

v0 reports the resolved principal and `effective roles: unknown`; best-effort observed
role names arrive in v1. The unconditional `user`-identity guardrail warning is present in
both.

### 4.4 Graduating to a reader SP

The tool must **not** create the SP or role assignment itself — that is precisely the class
of privileged mutation it exists to avoid. Instead, `azure_accounts()` may return a
declarative setup checklist and versioned example commands for creating a certificate
credential and assigning built-in roles at an explicit scope. The output must name cloud,
tenant, scope, and resulting privilege; it is guidance, never an execution path.

### 4.5 Why a second principal rather than downscoping

Azure has no mechanism to mint a less-privileged ARM session for the same principal:

- ARM publishes exactly **one** delegated permission,
  `https://management.azure.com/user_impersonation`. All or nothing.
- Authorization is RBAC evaluated against the principal at request time. The token carries
  identity, not capability — there is no field to narrow.
- **On-behalf-of** narrows *API scopes*; ARM has one scope, so OBO yields nothing here.
- There is **no analog to `sts:AssumeRole` + inline session policy.** The primitive does
  not exist.
- **Deny assignments** cannot be created by customers; they are authored only by Azure via
  deployment stacks, managed applications, and (retiring) Blueprints. They are also
  scope-attached, not session-attached.
- **Azure Policy `deny`/`denyAction`** has no principal context — it blocks everyone.
- **ABAC role assignment conditions** are narrow (mostly storage data actions).

Holding less privilege therefore requires *being a different principal*.

### 4.6 Credential acquisition for the `reader` SP

In descending order of preference:

1. **User-assigned managed identity** — requires the host to run on an Azure resource (jump
   VM, Container App). No secret material anywhere. Preferred for regulated environments.
2. **Certificate credential in the OS keystore** (Keychain / DPAPI). The realistic
   workstation option; MSAL confidential client.
3. **Workload identity federation** — for CI-driven use; impractical locally.
4. **Client secret** — supported, discouraged.

### 4.7 Credential acquisition for the `user` identity

Use Azure CLI as a **credential broker** in v0. This is deliberately narrower than using it
as the resource client:

```text
env AZURE_CLOUD_NAME=<cloud> COPILOT_AGENT_SESSION_ID=<agent-correlation-id>
az account get-access-token
  --subscription <subscription-id>
  --resource <audience>
  --output json
  --only-show-errors
```

Spawn the configured `az` binary directly with an argv array; do not invoke a shell. Set
the cloud in the child environment and pass subscription and audience explicitly. Never
run `az cloud set`, `az account set`, `az rest`, or an Azure resource command. This path
does not depend on `isDefault`, does not mutate cloud/profile selection, lets Azure CLI own
its cache format and lock protocol, and preserves its current agent-session token handling.

Requirements:

- Require a tested Azure CLI version and probe the command shape at startup. Agent-session
  attribution via `COPILOT_AGENT_SESSION_ID` is version-gated; report whether it is active.
- Forward a validated inherited `COPILOT_AGENT_SESSION_ID` when the MCP host supplied one;
  otherwise generate a separate non-secret agent correlation ID. Never expose or reuse the
  bearer `sessionId` as telemetry or an environment value passed to another process.
- Apply a short subprocess timeout. Treat stdout and stderr as sensitive, parse the
  documented JSON fields, zero buffers after parsing where practical, and never include raw
  subprocess output or the token in an error or log. Map known CLI errors to sanitized
  structured codes and retain raw diagnostics only behind an explicit local debug sink.
- Single-flight acquisition by `(cloud, tenant, audience, identity)`, and serialize all
  Azure CLI broker subprocesses behind one process-wide mutex. Token refresh is infrequent;
  serializing it avoids cross-key contention on Azure CLI's shared MSAL persistence while
  ARM requests remain concurrent. Cache access tokens in memory until five minutes before
  `expires_on`.
- Verify that the returned tenant and subscription match the requested binding before
  using the token. Pin the token's principal and client claims in the session's resolved
  principal mapping. Every refresh must match; if `az login` changed the account
  mid-session, evict the session rather than switching identity silently.
- On authentication failure, return a targeted
  `AZURE_CLOUD_NAME=<cloud> az login --tenant <tenant>` instruction. Do not start an
  interactive login from the MCP server.

`azureProfile.json` remains the discovery source. Decode an optional UTF-8 BOM rather than
requiring one, index the full subscription list by `(environmentName, tenantId,
subscriptionId, user.name)`, and ignore `isDefault`.

Direct MSAL-cache import is deferred. Azure CLI can use plaintext JSON, platform-protected
binary persistence, Keychain, DPAPI, or libsecret depending on version and configuration.
MSAL silent acquisition also updates cache state and does not provide a stable "copy this
refresh token" interface. Reimplementing those details in Rust is a compatibility project,
not a harmless read-only optimization.

**Audit attribution caveat.** The broker still uses the Azure CLI client ID. Current Azure
CLI versions can mark an agentic session, but sign-in logs still identify the client
application as *Microsoft Azure CLI*. A CMMC/FedRAMP deployment should use a dedicated app
registration so Conditional Access and sign-in attribution can target this tool separately.
That is a change-control and consent conversation, so it is not the zero-config v0 path.

Note that graduating to the `reader` SP (§4.6) sidesteps the whole question — a certificate
credential can be rotated independently and never needs an interactive user login.

### 4.8 Token axis: audience, not tenant

Multi-tenant acquisition is **not the real multiplicity here**, and is probably a non-issue
for this deployment:

- An ARM token's `tid` must match the tenant owning the subscription. If every subscription
  in a cloud lives in one tenant, that is **one token per cloud**, acquired lazily on first
  use. The eager-vs-lazy question dissolves.
- Commercial and Government subscriptions live in *separate* Entra directories anyway, so
  "two clouds, two tenants, two tokens" is the expected steady state — not a fan-out.
- Genuine multi-tenant only arrives with Azure Lighthouse delegated subscriptions or B2B
  guest access into customer directories. Keep the cache keyed by tenant so that works
  later; build no eager warm-up for it now.

The axis that actually multiplies is **audience**, because each data plane (§9) has its own:

| Surface | Audience (commercial → Gov) |
|---|---|
| ARM control plane | `management.azure.com` → `management.usgovcloudapi.net` |
| Log Analytics | `api.loganalytics.io` → `api.loganalytics.us` |
| Key Vault | `vault.azure.net` → `vault.usgovcloudapi.net` |
| Storage | `storage.azure.com` (same in Gov) |
| Azure SQL | `database.windows.net` → `database.usgovcloudapi.net` |

Cache key is therefore `(cloud, tenant, audience, identity)`. Audiences resolve from a
validated cloud manifest (§2.3), never by hostname substitution.

### 4.9 Credential discovery tool

`azure_accounts()` enumerates every cached subscription candidate across all clouds — the
thing `az` makes structurally hard. Returns `{cloud, tenantId, subscriptionId, name, user,
state, tokenStatus}` with no notion of "current". `tokenStatus` is `unknown` until this
server has attempted acquisition; enumeration must not fan out token requests merely to
populate a status field.

---

## 5. Interaction Tiers

### 5.1 Three tiers, not two

Method-based filtering fails in both directions on ARM. `POST` is a read verb throughout
(Resource Graph queries, metrics, `checkNameAvailability`), while `POST .../listKeys` is a
read that surrenders a storage account.

| Tier | Grants |
|---|---|
| `inspect` *(default)* | All `*/read` control-plane actions; explicitly allowlisted non-mutating `/action` operations |
| `read` | `inspect` + secret-bearing list operations (`listKeys`, `listSecrets`, `listConnectionStrings`, …); results are secret-labeled |
| `write` | Mutations, gated by two-phase plan/apply (§6.5) |

`isDataAction: true` is a **separate axis**, not a tier. Data-plane operations are where
customer data actually lives. A session therefore has two fixed capability dimensions:

```text
armTier: inspect | read | write
dataPlanes: [] | [logs.query, keyvault.metadata, keyvault.secrets,
                  blob.metadata, blob.read, ...]
```

ARM tiers authorize only ARM routes. Every data-plane route names an exact required grant;
all such requests are denied unless that grant was named when the session opened. A
data-plane mutation additionally requires `armTier: 'write'` and uses the same plan/apply
ceremony. The familiar `inspect` / `read` / `write` labels remain useful risk descriptions,
but they do not silently grant another data plane.

### 5.2 Deriving the tier table

The surface is largely self-labeling, because RBAC action names carry the verb as a suffix
— which is why built-in Reader is expressible as `*/read`.

**Source of truth:**
`GET /providers/Microsoft.Authorization/providerOperations?api-version=2022-04-01&$expand=resourceTypes`,
fetched **per cloud** and snapshotted.

> Do **not** use per-provider `/providers/{ns}/operations` endpoints. They are inconsistent
> about whether `isDataAction` is present, their api-version metadata is frequently wrong,
> and some providers do not expose the endpoint at all.

Classification pipeline for producing a candidate policy bundle:

1. **Suffix → tier** for `/read`, `/write`, `/delete`.
2. **`isDataAction: true`** → data-plane axis, independent of verb.
3. **`/action` residue** → case-insensitive regex on the action leaf:
   - non-mutating → `inspect`: `^(list|get|read|check|validate|query|fetch|resolve|preview|test|calculate|estimate)`
   - secret-bearing → `read`:
     `(?i)(key|secret|credential|sas|token|password|connectionstring|adminpassword|callbackurl)`
     — catches `listKeys`, `listAdminKeys`, `listConnectionStrings`, and
     `listCallbackUrl` (Logic Apps callback URLs embed a SAS)
   - mutating → `write`: `^(start|stop|restart|failover|restore|export|import|move|regenerate|rotate|purge|cancel|approve|reject|deploy|scale|set|create|update|write|generate|invoke|run|execute)`
4. **Unmatched → deny.** Unmatched operations enter a review queue. Treating them as
   `write` would make them executable in a write session before review.
5. **Override file** — hand-maintained, layered last.

The generator never publishes its output directly. The shipped policy bundle is a
reviewed artifact with a content hash. Newly observed operations remain denied until the
bundle is regenerated, its diff reviewed, and the new bundle shipped.

### 5.3 Why the override file is not optional

The derived labels are useful but imperfect. Microsoft's own metadata contains mislabels:
`Microsoft.Help/diagnostics/read` is described as *"Created and Reads a diagnostic
resource."* That is a `/read` operation with a write side effect. Route-to-operation joins
also have ambiguities that names alone cannot resolve.

Budget for a small, reviewed override list. This is a very different maintenance posture
from curating 15–20k operations by hand.

### 5.4 Maintenance model

Refresh snapshots on a regular release cadence. **Review the diff, not the corpus.** New
operations are grouped by derived class, with unmatched and newly `inspect` operations
receiving explicit review.

**Distribution:** ship a snapshot with the release so the tool works offline and in
air-gapped clouds from first run; optionally fetch **signed, reviewed release bundles** in
the background on a TTL and swap atomically to the newest trusted version. Never turn live
provider metadata directly into an allow decision. Never block startup on a fetch or
hard-fail on a fetch error. The policy hash is fixed per session and recorded in the call
log so a surprising denial can be explained against a specific table rather than a moving
target.

### 5.5 The security-critical component: request → reviewed route

Provider-operations metadata names RBAC permissions, but it does not provide a complete
HTTP method/path-template mapping. The runtime must not invent that mapping from path shape
alone.

Build a route policy offline by joining:

1. HTTP method and normalized path templates from `azure-rest-api-specs`.
2. Provider namespace, Swagger operation ID, resource type, and API versions.
3. Candidate RBAC actions from provider-operations metadata.
4. Reviewed overrides for ambiguous, exceptional, or mismatched routes.

The shipped row is conceptually:

```text
(cloud, method, pathTemplate, apiVersionRange)
  -> (rbacAction, armTier, isDataAction, reviewStatus)
```

At runtime, parse and canonicalize the URL, match the most-specific reviewed route, and
then enforce its capability. **No reviewed route means deny**, including in a `write`
session. The path-shape algorithm remains useful for generating candidates and diagnostics,
not for granting access.

Known edge cases requiring route fixtures and explicit handling:

- Extension resources (`/providers/Microsoft.Authorization/roleAssignments` at arbitrary scope)
- Management-group and tenant scopes
- Nested providers
- `Microsoft.Resources/deployments` — a PUT that performs arbitrary writes; must be `write`
  tier despite its declarative framing
- Tenant-level POSTs such as `/providers/Microsoft.ResourceGraph/resources`

Note that Resource Graph queries map to `Microsoft.ResourceGraph/resources/read` despite
being POSTs. **HTTP method and RBAC verb disagree.** This route must be present explicitly
in the reviewed table; neither the HTTP verb nor an action-leaf regex proves it.

**Test strategy:** fuzz URL parsing and canonicalization against the full path-template
corpus from `azure-rest-api-specs`; run every shipped route through allow/deny golden tests;
and maintain hand-written adversarial fixtures for nested providers, encoded separators,
duplicate slashes, dot segments, query confusion, and conflicting templates. The REST
spec corpus is input coverage, not ground truth for RBAC mapping; ambiguous joins must fail
the policy build.

### 5.6 RBAC for the `reader` SP: built-in roles, additively

**Built-in Reader is the baseline and is expected to be sufficient.** Reader is `*/read`,
which excludes every `/action` — so `listKeys` and friends are already denied, Resource
Graph still works, and Azure Monitor metrics (`Microsoft.Insights/metrics/read`) work. That
is very nearly the `inspect` tier with zero authoring.

Reader covers the **control plane only**. Each data plane (§9) has its own RBAC and must be
granted additively:

| Surface | Additional built-in role |
|---|---|
| Log Analytics / App Insights queries | `Log Analytics Reader` |
| Key Vault secrets (values) | `Key Vault Secrets User` |
| Blob content | `Storage Blob Data Reader` |
| Azure SQL | *not RBAC* — a database-level principal (§9.4) |

This is the single most common surprise: **Reader at subscription scope grants no blob
content access and no Key Vault secret access.** They are `isDataAction` operations and
are deliberately outside `*/read`.

A composed assignment of `Reader` + `Log Analytics Reader` (+ the others as needed) is the
recommended production configuration.

#### 5.6.1 Custom role (optional escape hatch)

The tier table *is* a role definition, so it can be emitted if Reader ever proves too tight
or too loose:

```jsonc
{
  "roleName": "MCP Inspect",
  "actions": ["*/read", /* allowlisted non-mutating /action operations */],
  "notActions": [ /* secret-bearing list operations */ ],
  "notDataActions": ["*"],
  "assignableScopes": ["/providers/Microsoft.Management/managementGroups/<mg>"]
}
```

Generating it from the same source as the interceptor means the two cannot drift. But it is
**not on the critical path** — custom-role limits and propagation are operational concerns;
`assignableScopes` must be enumerated explicitly; and `notActions` **subtracts** rather
than denies, so a second role assignment granting the action still wins. Ship the
generator, default to built-ins.

### 5.7 Relationship between the interceptor and RBAC

- **RBAC on the `reader` SP is the boundary.** It is what actually holds.
- **The interceptor is a guardrail.** Its value is fast, legible, pre-flight failures
  ("`listKeys` is tier `read`, session is `inspect`") instead of an opaque
  `AuthorizationFailed` forty seconds into a fan-out — and it is the *only* protection in
  `identity: 'user'` mode — which, since that is the zero-config default (§4.1), is the
  mode most sessions will actually run in.

Because `user` has no RBAC backstop, only reviewed routes are executable. A new provider
operation appearing in live metadata does not become available automatically, even when
its name ends in `/read`.

State this in the README. Do not let it read as a security boundary.

---

## 6. Interaction Model

### 6.1 MCP and deployment contract

Target the stable MCP protocol revision `2025-11-25`. v0 serves stdio only and assumes one
local OS user. Every tool has an `inputSchema`, `outputSchema`, and structured result;
domain failures are returned as stable error codes rather than prose parsing.

Tool annotations are descriptive hints, not authorization. Mark discovery and inspect-only
tools `readOnlyHint: true`; mark `azure_apply` destructive and non-idempotent. A client may
use those hints to choose an approval UI, but the server does not rely on it.

Remote Streamable HTTP is out of scope until the design has authenticated users, session
tenancy, CSRF/origin controls, and a plan-approval binding appropriate for a multi-user
server.

### 6.2 Tool surface

Deliberately small — the API surface lives in the code, not in the tool list.

| Tool | Purpose |
|---|---|
| `azure_session_open` | Resolve immutable identity, capability, and cloud bindings |
| `azure_session_close` | Dispose the isolate and all session refs immediately |
| `azure_run` | Execute JS in a session isolate; returns value + logs + call log |
| `azure_accounts` | Enumerate cached subscription/account candidates across all clouds |
| `azure_schema_search` | Keyword search over resource types / operations |
| `azure_schema_get` | Full request/response schema for a type + api-version |
| `azure_apply` | Elicit human approval, then replay an immutable mutation plan |

### 6.3 Sessions are persistent

A session holds a live isolate. Globals persist across `azure_run` calls, so the model can
fetch once and interrogate repeatedly without re-paying for the ARM round trip.

```
azure_session_open({ identity?, armTier?, dataPlanes?, bindings?,
                     allowedSubscriptions?, graphScopes? })
  → { sessionId, identity, armTier, dataPlanes, resolvedBindings,
      allowedSubscriptions, graphScopes }
azure_run({ sessionId, code, timeoutMs? })
azure_session_close({ sessionId })
```

Sessions are evicted on idle TTL, absolute max age, or memory pressure. Eviction is
reported so the model knows its state is gone rather than silently observing `undefined`.

Session IDs are at least 256 bits of cryptographic randomness and are bearer capabilities.
They are scoped to the originating MCP connection in v0, never written to logs, and become
invalid on close or eviction. One run may execute at a time in an isolate; concurrent calls
to the same session return `session_busy` rather than interleave JavaScript turns.

Identity, ARM tier, data-plane grants, bindings, subscription allowlist, graph scopes, and
policy bundle are fixed when the session opens. Refs and persistent JS state inherit that
context. There is no per-call downgrade claim: a value fetched in a `read` session remains
read-sensitive even if later code only performs arithmetic.

### 6.4 Return protocol: refs, not truncation

ARM responses are enormous. **Never truncate JSON** — a truncated array is useless to a
model, whereas a structural summary is genuinely informative.

Anything exceeding the return cap (default 64 KB) is auto-converted to a ref:

```js
globalThis.dbs = await az.gov.graph(
  `Resources | where type =~ 'microsoft.sql/servers/databases'`
);
// → { __ref: "ref_7Jm2…", type: "Array<Object>", length: 4211,
//     keys: ["id","name","tier","elasticPoolId","subscriptionId"],
//     sample: [ {...}, {...} ] }

globalThis.dbs.filter(d => d.tier === 'BusinessCritical').length
// next call — one integer crosses the wire
```

There are two related mechanisms:

- Values retained in JS globals stay in the isolate and can be queried by later runs.
- An oversized value crossing the MCP boundary is serialized once into an immutable,
  session-scoped host ref. `await az.ref('ref_7Jm2…')` rehydrates it into the isolate when
  the original JS value was not retained. `az.peek(x)` forces a structural summary on
  demand.

Ref IDs are random opaque handles, not sequential authority. Stored values carry content
labels such as `secret` or `customerData`; secret-labeled values receive shape-only
previews with no samples. Rehydrating one is allowed only in the same `read` session and
marks the whole run secret-sensitive. Cyclic or non-serializable values return a typed
summary or a serialization error, never partial JSON.

This is the single largest determinant of whether code mode feels good or drowns the
context window.

v0, before refs exist, returns `result_too_large` with a shape-only summary and asks the
caller to reduce the value in JS. It never returns a truncated success value.

### 6.5 Write mode: plan / apply

The model never holds the write capability.

1. `azure_run` in a session opened with `armTier: 'write'` executes but **intercepts
   mutations**, collecting exact canonical request intents as a plan rather than issuing
   them. Read dependencies may execute normally.
2. The plan is returned as a rendered diff (scope, action, target, body delta) with a
   `planId`.
3. `azure_apply({ planId })` requests structured MCP elicitation from the client and shows
   the exact plan hash, identity, cloud, subscriptions, operations, and material body
   changes. It replays only after an `accept` response tied to that tool call.
4. If the client lacks elicitation, `azure_apply` returns `approval_unavailable`. The only
   fallback is a separate local operator command that renders and applies the stored plan;
   the model cannot mint or relay an approval token.
5. Apply performs no JS execution and no re-planning. It revalidates the plan and replays
   the recorded requests.

MCP tool annotations alone are never approval. Plans expire (default 15m), are one-shot,
and are bound to the session, identity, cloud manifest, policy hash, subscriptions, and
canonical request hash that produced them. Store plan bodies with user-only permissions;
they may contain secrets even when logs do not.

Every request is reclassified at apply time. Hostnames, API versions, identity, and policy
must still match. Use `If-Match` or an equivalent service precondition when available;
drift causes failure, not an implicit re-plan. Do not automatically retry a non-idempotent
mutation. Execute in recorded order, stop on first failure by default, and return an exact
partial-apply ledger.

Planning code cannot depend on a mutation response that does not exist. An intercepted
mutation returns a `PlannedResponse` handle; attempts to read service-generated fields from
it fail with `plan_dependency_unavailable`. This limitation must be explicit rather than
filled with fake values.

A body delta is shown only when a reviewed route provides a safe current-state read and a
schema-aware comparison. Otherwise the plan shows the canonical request body, with secret
fields redacted and separately counted. Do not manufacture a diff against an assumed
default resource.

### 6.6 The `az` object

Three layers:

```js
// L0 — escape hatch; everything else is sugar over this
await az.request({ cloud: 'AzureUSGovernment', subscription: SUB, method: 'GET',
                   path: `/resourceGroups/${rg}/providers/Microsoft.Sql/servers`,
                   apiVersion: '2023-08-01' });

// L1 — reviewed-route helpers, auto-paging
for await (const db of az.gov.list({
  scope: `/subscriptions/${SUB}/resourceGroups/prod/providers/Microsoft.Sql/servers/sql-1`,
  type: 'databases',
})) { … }

// L2 — Resource Graph. First-class.
await az.gov.graph(`
  Resources
  | where type =~ 'microsoft.sql/servers/elasticpools'
  | project id, name, tier = tostring(sku.tier), subscriptionId
`);
```

For L0, `path` is relative to the selected subscription when `subscription` is present or
resolved from the binding; the front end prepends `/subscriptions/{id}`. Tenant,
management-group, and full resource-ID scopes use a separate explicit `scope` field. A
caller may not smuggle a second scope into `path`; after joining, the canonical subscription
must equal the resolved binding or explicit override.

L1 does not pretend every nested resource type is listable at subscription or resource
group scope. The caller supplies a legal parent scope; the reviewed route index resolves
the path template and pinned API version.

**Resource Graph should be the default recommendation in the tool description.** It
collapses an N-subscription × M-resource crawl into a single cross-subscription call, and
it is where most fleet-inventory questions actually belong. Cross-subscription scope is
still explicit (§2.2.2). L1 is the fallback for what ARG does not index.

### 6.7 v0 result and error contract

Successful tools return `structuredContent` conforming to their declared output schema.
`azure_run` returns:

```text
{
  value | summary,
  console: [...],
  calls: [...],
  session: { identity, armTier, dataPlanes, bindings, policyHash },
  sensitivity: public | customerData | secret,
  correlationId
}
```

Console and call arrays are independently bounded and report omitted entry counts. A
secret-sensitive run is labeled even when its final value is innocuous; labels are
conservative and never treated as proof that an unlabeled arbitrary JS string is safe.

Expected domain failures return an MCP tool result with `isError: true` and structured
`{ code, message, retryable, details?, correlationId }`. v0 reserves at least:
`invalid_request`, `account_ambiguous`, `authentication_required`,
`subscription_mismatch`, `route_denied`, `capability_denied`, `session_busy`,
`session_evicted`, `execution_timeout`, `worker_crashed`, `result_too_large`, and
`upstream_error`. JSON-RPC errors are reserved for malformed protocol messages and server
failures outside the tool's domain contract.

---

## 7. Schema Discovery

The full surface is far too large to inline, so discovery is search-based.

### 7.1 Index

One document per `(resourceType, operation)`:

| Field | Source |
|---|---|
| RBAC action name | `providerOperations` |
| HTTP method + path template | `azure-rest-api-specs` |
| Available api-versions **per cloud** | provider metadata, per cloud |
| `az` CLI equivalent command | az command reference |
| Display name, description | `providerOperations` |
| Derived tier | §5.2 pipeline |

BM25 is sufficient — this is keyword-shaped retrieval, not semantic.

### 7.2 Alignment with `az` naming

Index on **both** the ARM identifier (`Microsoft.Sql/servers/databases`) and the CLI form
(`az sql db list`), so either phrasing retrieves. Models carry strong priors on both from
pretraining; the index should let those priors transfer rather than forcing translation.

### 7.3 Returning tier with each hit

Every search result carries its tier, so the model learns *before writing code* that
`listKeys` will not run under `inspect`. Far better than a runtime denial.

### 7.4 Size

The `azure-rest-api-specs` corpus is too large to ship raw. Record its exact input revision,
source size, generated route count, and index size as build metrics. Ship a compact index
of paths, methods, versions, and metadata; fetch full schemas lazily from a local checkout
or a content-addressed cache via `azure_schema_get`. Set a distribution-size budget after
measuring the first generated index.

---

## 8. Transport Layer

Every request from the isolate — ARM or data plane — crosses into Rust as a struct, is
matched to a reviewed route (§5.5), classified, and only then signed. Responsibilities:

- **Signing** — token selected by `(cloud, tenant, audience, identity)`; never exposed to
  the isolate.
- **Subscription resolution** — binding lookup or explicit override, recorded with provenance
  before the request is signed (§2.2).
- **Paging** — transparent `nextLink` following, surfaced as async iteration. Cap total
  pages per call with an override.
- **Retry** — exponential backoff on 429/5xx, honoring `Retry-After`, for idempotent reads.
  A POST is retryable only when its reviewed route is read-only or the service provides an
  idempotency contract. Mutations are not retried generically.
- **Rate-limit accounting** — surface `x-ms-ratelimit-remaining-subscription-reads` in the
  call log. A naive `Promise.all` across many subscriptions can exhaust service budgets
  while ordinary latency still looks healthy.
- **Concurrency cap** — default 8 in-flight requests per session, adjustable only up to a
  server ceiling. Prevents 429 storms and bounds host memory.
- **Long-running operations** — `Azure-AsyncOperation` / `Location` polling, only reachable
  in a session opened with `armTier: 'write'`.

### 8.1 Request-target safety

`az.request` accepts a relative path, never an arbitrary URL. Before policy lookup or
signing, the front end:

1. Parses once with a single URL implementation and rejects userinfo, fragments, invalid
   percent encoding, encoded path separators, dot segments, duplicate authority syntax,
   and conflicting `api-version` values.
2. Joins the path to the selected cloud manifest's exact origin.
3. Rejects caller-supplied `Authorization`, `Host`, forwarding, and hop-by-hop headers.
4. Disables redirects by default.
5. Repeats origin and route validation for every `nextLink`, LRO polling URL, and
   service-provided continuation before sending credentials.

Data-plane helpers use the same rule with a plane-specific origin allowlist. A response can
never turn paging or polling into a signed request to another host. Request and response
body limits apply before logging or ref conversion.

### 8.2 Call log

Every request records: correlation ID, cloud, subscription and provenance, tenant,
identity, session capability, method, redacted path template, resolved RBAC action, policy
bundle hash, API version and source, decision (allow/deny + reason), HTTP status, duration,
retry count, and remaining rate limit.

Because subscription resolution happens here and is recorded per request, the invisibility
that makes `az`'s ambient state dangerous does not reproduce: every call states which
subscription it used and why.

Paths, query strings, headers, and bodies are structured and redacted before formatting.
Never log tokens, cookies, SAS parameters, secret values, raw plan bodies, or raw
subprocess stdout. Record hashes when correlation is useful.

A bounded call log is returned with every `azure_run` result for debugging. The front end
also writes an append-only, user-readable structured **request** log with user-only
permissions, rotation, and retention controls. JS console output and returned values are
not written to that durable log. The returned log alone is not a durable audit trail, and
the local file is not tamper-evident.

---

## 9. Data Planes

Control plane alone does not cover the actual daily workload. Each data plane is a distinct
audience (§4.8), a distinct RBAC model, and a distinct policy classification — they do not
inherit the ARM tier table, and each needs its own small ruleset.

### 9.1 Log Analytics / Application Insights (primary driver)

KQL is a first-class citizen, not an afterthought:

```js
await az.gov.logs(WORKSPACE_ID, `
  AppServiceHTTPLogs
  | where TimeGenerated > ago(1h)
  | summarize p95 = percentile(TimeTaken, 95) by CsHost
`, { timespan: 'PT1H' });
```

Two possible routes, and they trade off:

| Route | Pros | Cons |
|---|---|---|
| **Direct data plane** — `POST {api.loganalytics.*}/v1/workspaces/{id}/query` | Real query limits, `Prefer: wait=600` for long queries, cross-workspace `workspaces()` | Second audience, second token, own policy path |
| **ARM-proxied** — `POST …/Microsoft.OperationalInsights/workspaces/{n}/api/query` | Reuses the ARM token and route-policy path | Tighter throttling and shorter timeouts |

**Recommendation: direct data plane**, with the ARM-proxied path as a fallback when the
Log Analytics audience is unavailable. The query limits matter for anything fleet-shaped.

Policy: a KQL query requires the `logs.query` data-plane grant and is non-mutating within
that plane. KQL is read-only by construction, so unlike SQL (§9.4) no statement
classification is required. Enforce both response-byte and row caps, then route overflow
into the ref store (§6.4). Do not inject `take` into the user's query; silently rewriting
query semantics violates the design's visibility rule.

The `logs.query` grant authorizes log data reachable by the resolved Azure principal; a
workspace parameter is routing, not a security boundary. The helper requires
`scope: 'allAccessible'` or an explicit workspace list for the cross-workspace forms it can
observe, and logs that scope distinctly, but generated KQL can contain `workspace()` and
`resource()` references. Do not claim a workspace allowlist without a complete KQL parser
and enforcement strategy. Deployments that need a real workspace boundary use a dedicated
principal with workspace-scoped `Log Analytics Reader` assignments.

Workspace-based Application Insights is Log Analytics; same path, `AppRequests` /
`AppDependencies` tables. Classic AI resources use `api.applicationinsights.io` and should
be treated as a separate endpoint if any remain.

### 9.2 Azure Monitor metrics

Already control plane, already covered by Reader — this is the `az rest` usage that
disappears first.

- Single resource: `GET …/providers/Microsoft.Insights/metrics` (`Microsoft.Insights/metrics/read`)
- **Multi-resource batch**: `POST …/Microsoft.Insights/metrics:getBatch` — one call across
  many resource IDs in a subscription+region. For pulling App Service platform metrics
  across a fleet this is dramatically better than N single-resource calls, and it is a POST
  that maps to a `/read` action, so it lands in `inspect` correctly via the metadata table
  rather than via a method heuristic.

Sugar: `az.gov.metrics(resourceIds, ['CpuTime','Http5xx'], { interval: 'PT5M' })`, batching
transparently.

### 9.3 Key Vault

Audience `vault.*`, RBAC role `Key Vault Secrets User` (RBAC-mode vaults; access-policy
vaults need a policy entry instead).

The split is clean and worth enforcing explicitly after the corresponding Key Vault
data-plane grant is enabled:

| Operation | Required grant | Rationale |
|---|---|---|
| `GET /secrets` (list names, versions, metadata) | `keyvault.metadata` | Names are inventory, not values |
| `GET /secrets/{name}` (value) | `keyvault.secrets` | Actual secret material |
| `GET /keys`, `/certificates` metadata | `keyvault.metadata` | |
| Any write/rotate/purge | `keyvault.write` + write plan | |

Secret **values returned into the isolate must never enter ref previews or the call log** —
log the identifier and a hash, never the value. A value may exist in the read-capable
isolate or a session-scoped ref labeled `secret`, but is never persisted beyond session
close and is never sampled into a structural summary.

### 9.4 Azure SQL — deliberately out of scope for v1

Different transport (TDS, not HTTP), different policy model, and the tier system does not
map onto SQL statements. Statement parsing as a safety mechanism is a losing game.

If it lands later, the honest design is *not* a query classifier:

- AAD token auth against `database.*` audience — the credential broker already supports it
- Read-only enforced by a **dedicated database principal with `db_datareader` only**
- An explicitly configured read-only replica or geo-secondary for workload isolation;
  `ApplicationIntent=ReadOnly` is a routing hint, not the authorization boundary

That is a real security boundary, unlike statement inspection. Until it exists, `sqlcmd`
stays where it is.

### 9.5 Blob storage

"Storage" meaning blob content specifically — useful for reading diagnostic logs, exported
artifacts, and bacpacs that other tooling drops there.

- Audience `storage.azure.com`; endpoint from cloud metadata suffixes
- Requires `Storage Blob Data Reader` — **Reader does not grant this**
- Container/blob enumeration requires `blob.metadata`; blob content requires `blob.read`,
  with a size cap routing large objects into the ref store rather than the response
- Writes and SAS minting require plane-specific write grants + a write plan

### 9.6 Uniform treatment

Every data plane routes through the same host-side interceptor, call log, retry, and ref
store as ARM. Each plane ships a versioned, reviewed route table in the same signed policy
bundle as the ARM table. What differs is the capability vocabulary and audience. An
unrecognized method/path/version is denied — the same fail-closed rule as §5.5.

---

## 10. Failure Modes to Design For

| Failure | Mitigation |
|---|---|
| Context flooding from large ARM responses | Ref store + structural summaries (§6.4) |
| 429 from naive fan-out | Concurrency cap, backoff, rate-limit visibility |
| Gov/commercial API-version skew | Reviewed per-cloud defaults + live availability check (§2.4) |
| Stale/expired cached tokens | Explicit Azure CLI credential broker; targeted `az login` instruction on failure (§4.7) |
| Azure CLI profile race | Never invoke profile-mutating commands; child cloud and subscription are explicit (§4.7) |
| Azure CLI token-cache contention | Process-wide serialization of broker subprocesses; ARM traffic remains concurrent (§4.7) |
| User runs `az login` during a session | Pin principal/client claims; evict on refresh mismatch (§4.7) |
| Credential subprocess leaks a token | Treat stdout as secret; parse, zero, and exclude it from every error/log path |
| Reader grants no blob/KV data access | Additive built-in roles documented in §5.6; denial message names the missing role |
| KQL result explosion | Byte + row caps into the ref store; no query rewriting (§9.1) |
| Automatic secret leakage through request logs or ref previews | Content labels + shape-only secret previews; JS output remains an explicit `read`-session exposure (§4.2, §9.3) |
| Unknown or ambiguous route | Fail closed in every tier, including `write` (§5.5) |
| Redirect/continuation credential theft | Exact-origin allowlists and revalidation for every service-provided URL (§8.1) |
| Wrong cloud assumed | Cloud is never defaulted; an omitted cloud is an error, not a fallback |
| Wrong subscription assumed | Immutable per-cloud binding, live validation, and provenance in every request (§2.2.1) |
| Late principal or capability switch | Resolved principal mapping and capabilities are fixed per isolate/session (§6.3) |
| Running under Owner without noticing | Identity + incomplete-role warning disclosed at session open (§4.3) |
| Session evicted mid-workflow | Explicit eviction notice in the next call's result |
| V8 fatal OOM takes down runtime | Isolate runs in a replaceable worker process (§3.2) |
| Model calls apply without human review | Elicitation-bound approval or separate local operator command; hints are insufficient (§6.5) |
| Partial mutation apply | Ordered one-shot replay, stop-on-failure, exact partial ledger (§6.5) |

---

## 11. Phasing

**v0 — prove the core**

- Local stdio MCP server targeting protocol revision `2025-11-25`.
- `azure_accounts`, `azure_session_open`, `azure_session_close`, and `azure_run` with
  persistent isolates; no refs yet.
- Reviewed `AzureCloud` and `AzureUSGovernment` manifests.
- Per-cloud subscription binding from config plus unambiguous single-subscription
  auto-binding and live validation.
- `identity: 'user'` through the explicit Azure CLI credential broker (§4.7).
- `az.request` and `az.graph` only, `inspect` only, no data-plane grants.
- A deliberately small reviewed route bundle: subscription validation, Resource Graph,
  provider metadata, and the ARM GET routes needed by the first real scenarios.
- Structured per-call results, bounded returned call log, durable redacted log, timeout,
  body limits, and exact-origin enforcement.

### 11.1 v0 acceptance criteria

1. Unit tests prove that URL canonicalization, route matching, capability checks, and log
   redaction fail closed for malformed and unknown inputs.
2. Credential tests use a fake `az` executable to assert exact argv/environment handling
   and prove stdout/token material never reaches JS, logs, or structured errors.
3. An authenticated opt-in integration test runs commercial and Government queries in
   parallel and asserts each request's origin, tenant, subscription, and audience.
4. The integration test snapshots `config`, `azureProfile.json`, and `clouds.config` before
   and after. They remain byte-identical. Azure CLI's own token cache may change.
5. A session cannot change identity, ARM tier, data-plane grants, binding, subscription
   allowlist, graph scope, or policy hash.
6. Unknown hosts, absolute user URLs, redirects, unknown routes, and mismatched
   subscription validation are denied before signing.
7. Infinite-loop, wall-timeout, and heap-pressure tests evict the affected session or
   worker and leave the MCP front end responsive.
8. A real inventory scenario returns a correct small result from a much larger ARM/ARG
   response without truncating JSON.

**v1 — usable**

- Host ref store + structural summaries
- **Log Analytics KQL** (§9.1) and **Monitor metrics batch** (§9.2) — the two surfaces that
  retire existing `az rest` usage, and the reason to reach for the tool daily
- Full reviewed route-policy generator, schema search index, and coverage report
- L1 reviewed-route API and auto-paging
- `identity: 'reader'` SP support (certificate credential) + setup-guidance emission
- Privilege disclosure at session open (§4.3)
- `read` tier; explicit Log Analytics and Key Vault grants (§9.3)

**v2 — mutations and hardening**

- Plan/apply with two-phase approval
- Dedicated app registration for distinct sign-in-log attribution (§12.2)
- Managed identity credential path
- Blob storage (§9.5)
- LRO polling
- Custom role generator (optional; built-ins remain the default)
- Remote transport only if its separate authentication and tenancy design is complete

**Deferred indefinitely**

- Azure SQL / TDS (§9.4) — pending a read-replica + `db_datareader` design, not statement parsing

---

## 12. Open Questions

Cache ownership, session/identity mixing, API-version drift, KQL size limits,
cross-workspace scope, and data-plane fail-closed behavior are resolved above. What remains:

### 12.1 Route-policy coverage

The route table is the largest unknown in the implementation. Before claiming "full ARM
surface," measure:

- REST path/method/version templates discovered;
- templates joined unambiguously to an RBAC operation;
- templates requiring an override;
- provider operations with no REST template;
- routes denied because review is incomplete.

The release gate should be explicit. v0 does not need high corpus coverage; it needs 100%
reviewed coverage of the routes it exposes.

### 12.2 Dedicated app registration

Using the Azure CLI client ID needs no setup but attributes all activity to *Microsoft
Azure CLI* in Entra sign-in logs and makes the tool untargetable by Conditional Access
independently of `az` itself. A dedicated registration with `user_impersonation` on ARM
fixes both and is the better fit for a CMMC-audited tenant — at the cost of a change-control
conversation and admin consent in each tenant. Worth doing; the question is when, and
whether the tool should ship the app manifest.

### 12.3 Custom-cloud bootstrap

What is the minimum signed/configured manifest for USSec, USNat, Azure Stack, and air-gapped
deployments, and which endpoint fields may metadata refresh replace? Do not answer this by
guessing DNS suffixes from public or Government cloud.

### 12.4 Worker containment

Is one worker process per session acceptable, or should several isolates share a worker
with an OS RSS ceiling? Measure V8 startup snapshot size, steady-state isolate RSS, and
worker restart latency before choosing. Crash containment is required; one-process-per-
session is not assumed without measurement.

### 12.5 Direct authentication backend

The Azure CLI broker is the v0 baseline. Replace it only if a Rust authentication stack can
reuse an account through a supported cache/broker API, preserve agent-session and claims-
challenge behavior, and pass the same multi-cloud integration suite. Reading private cache
formats is not that API.

---

## 13. Primary references

- [Azure CLI `az account get-access-token`](https://learn.microsoft.com/cli/azure/account#az-account-get-access-token)
- [Azure CLI 2.89 agent-session handling](https://github.com/Azure/azure-cli/blob/azure-cli-2.89.0/src/azure-cli-core/azure/cli/core/auth/agentic_session.py)
- [Azure CLI 2.89 user credential flow](https://github.com/Azure/azure-cli/blob/azure-cli-2.89.0/src/azure-cli-core/azure/cli/core/auth/msal_credentials.py)
- [MCP 2025-11-25 tool schema and annotations](https://modelcontextprotocol.io/specification/2025-11-25/schema)
- [MCP elicitation](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation)
- [Azure provider-operations metadata](https://learn.microsoft.com/rest/api/authorization/provider-operations-metadata/list)
- [Azure resource-provider types and API versions](https://learn.microsoft.com/azure/azure-resource-manager/management/resource-providers-and-types)
- [Azure Resource Graph scope behavior](https://learn.microsoft.com/azure/governance/resource-graph/samples/starter)
