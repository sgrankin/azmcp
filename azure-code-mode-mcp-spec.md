# Azure Code-Mode MCP Server — Design Spec

**Status:** draft / design brainstorm
**Working name:** `armctl` (placeholder)

---

## 1. Motivation

The Azure CLI maintains ambient, mutable, process-global state that must be internally
consistent across at least three files, and only one code path reconciles them:

| State | File | Written by |
|---|---|---|
| Active cloud | `~/.azure/config` → `[cloud] name` | `az cloud set`, `AZURE_CLOUD_NAME` |
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
- Parallel invocations against different clouds or subscriptions race on shared files.
- The subscription in play is implicit, so a command's meaning depends on invisible state.

The one part of `az`'s state that is *already correct* is the MSAL token cache: entries are
keyed by authority host + `home_account_id` + client ID, so commercial and Gov identities
coexist in `msal_token_cache.bin` without conflict. **We keep the token cache and discard
the profile semantics.**

### 1.1 Goals

- **Cloud is explicit on every call.** One token to write, and the axis where a mistake is
  most expensive.
- **Subscription and tenant are bound per-cloud, once, immutably** — declared at session
  open or in config, never mutated mid-session, always echoed in the call log.
- One session can address multiple clouds concurrently.
- Reuse credentials the user already has cached via `az login`, without invoking `az`.
- Read-only by default, safe to point at a highly-privileged identity.
- Expose the full ARM surface without enumerating it as MCP tools.

### 1.2 Non-goals

- Not a replacement for `az` as an interactive human CLI.
- No tenant/customer/business-object modeling. Pure Azure. Callers supply their own
  subscription↔tenant↔customer mapping from their own context.
- Not a sandbox hardened against adversarial code (see §3.3).
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

Subscription and tenant *are* defaulted — per cloud, declared once, immutable.

```toml
# ~/.config/armctl/config.toml
[clouds.AzureUSGovernment]
subscription = "…"
tenant       = "…"

[clouds.AzureCloud]
subscription = "…"
```

Overridable at session open, and per-call for the exceptional case:

```js
await az.gov.type('Microsoft.Sql/servers')              // uses the gov binding
await az.gov.sub(OTHER).type('Microsoft.Sql/servers')   // explicit, this call only
```

**Auto-binding:** if a cloud has exactly one cached subscription in `azureProfile.json`,
bind it automatically with no configuration at all. This is the common case and it should
require zero setup.

A pleasant side effect: with bindings in config, GUIDs never enter the model's context
unless it explicitly asks for them. Fewer opaque identifiers in context means fewer
hallucinated ones.

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
4. **Cross-cloud GUIDs are rejected.** An explicit `.sub(guid)` is validated against that
   cloud's subscription list; a commercial GUID under `az.gov` is a hard error before any
   request is signed. (`az` gets this one right, via the `environmentName` filter.)

#### 2.2.2 Resource Graph is deliberately asymmetric

`az.gov.graph(q)` queries **all subscriptions accessible in that cloud**, not just the
bound one — that is ARG's native semantics and the whole reason to reach for it. Narrow
explicitly with `az.gov.graph(q, { subscriptions: [...] })`. Called out here because it is
the one place the binding does not apply, and a silent surprise otherwise.

### 2.3 Endpoint resolution

Cloud definitions are **fetched, not hardcoded**, from the ARM metadata endpoint
(`/metadata/endpoints?api-version=<v>`) per cloud, cached to disk with a TTL, and
overridable via config for air-gapped or Stack environments. This mirrors the role of
`ARM_CLOUD_METADATA_URL` and means USSec / USNat / custom clouds require configuration,
not code.

Resolved per cloud: `resourceManager`, `activeDirectory` (authority), `authentication.audiences`,
`suffixes.*`, plus data-plane endpoints for Key Vault, Storage, Log Analytics.

### 2.4 API version resolution

**Azure Government consistently lags commercial on resource provider API versions.** A
version literal that works in `AzureCloud` may 404 or silently omit fields in
`AzureUSGovernment`. Therefore:

- Version resolution is **per (cloud, resource type)**, sourced from
  `GET /providers/{namespace}?api-version=<providers-api-version>`, cached with TTL.
- Default: latest **non-preview** version available *in the target cloud*.
- Overridable per call: `{ apiVersion: '2023-08-01' }`.
- The schema index (§7) returns cloud-specific available versions so the model does not
  guess.

---

## 3. Runtime

### 3.1 Choice

**Rust + `deno_core`.** One `JsRuntime` (V8 isolate) per session.

Rationale:

- V8 isolates: real JS, real async, models write it well, `for await` maps naturally onto
  paged ARM APIs.
- `deno_core` gives promise/microtask/module plumbing, an `op` layer for host functions,
  and startup snapshots (new session ≈ 1ms with the `az` shim pre-baked).
- **Capabilities are opt-in by linking extensions.** We do not link `deno_fetch`,
  `deno_net`, `deno_fs`, or `deno_process`. The isolate therefore has no I/O primitive of
  any kind. The injected `az` object is the only door out.
- Native tokio integration: ARM calls are ordinary async ops on the host runtime.

Rejected: raw `rusty_v8` (rebuild all the plumbing); Node + `isolated-vm` (workable, but
Node hosting and fiddlier per-isolate heap accounting); Go + `goja` (ES5.1-era, slow);
Python (`RestrictedPython` is not a sandbox; a real Python sandbox costs a container per
invocation, which the ergonomics do not justify).

### 3.2 Resource governance

| Control | Mechanism |
|---|---|
| Wall-clock timeout | Per `azure_run` call, default 60s, terminate isolate handle |
| CPU / runaway loops | V8 interrupt callback on a watchdog thread |
| Heap ceiling | `--max-heap-size` + `near_heap_limit` callback → dispose session, never abort process |
| Session lifetime | Idle TTL (default 30m) + absolute max, LRU eviction under memory pressure |
| Concurrent sessions | Configurable cap; each is a full isolate |

An OOM or timeout must kill the *session*, return a structured error, and leave the host
process healthy.

### 3.3 Explicit security posture

**A V8 isolate is a capability boundary, not a security boundary.** V8 escapes exist. This
design is correct because the threat model is *a well-intentioned model making mistakes* —
not adversarial code. If the threat model changes, the answer is a process or microVM
boundary, not a better isolate.

The token never enters the isolate. Request signing happens host-side, after policy
evaluation.

---

## 4. Identity and Credentials

### 4.1 Two identities, resolved by availability

```
azure_run({ code, identity?: 'reader' | 'user', mode?, ... })
```

| Identity | Source | Purpose |
|---|---|---|
| `reader` | Dedicated service principal with a read-scoped role | The actual security boundary |
| `user` | MSAL cache from `az login` | Zero-config default; scopes the SP lacks |

**Resolution order:** `reader` if a reader SP is configured, otherwise `user`. Unconfigured
is not an error. The tool's core value proposition is reusing credentials the user already
has; refusing to start until an SP exists would make the common path the broken one, and
would push people back to `az`.

The resolved identity and the reason are reported at session open and echoed in the first
`azure_run` result:

```
identity=user  (no reader SP configured)   tier ceiling: inspect
```

### 4.2 Ceremony attaches to escalation, not to the fallback

Both identities default to tier `inspect`. The difference is **what stands behind the
ceiling**:

| | `reader` | `user` |
|---|---|---|
| Default tier | `inspect` | `inspect` |
| `read` (secrets) | opt-in per call | opt-in per call, **flagged** |
| `write` | opt-in + plan/apply, bounded by the SP's RBAC | opt-in + plan/apply, bounded by **nothing but the interceptor** |
| Backstop if the interceptor has a bug | Azure RBAC denies | Nothing |

So the escalation ceremony scales with `(tier × identity)`. Under `reader`, requesting
`read` is routine — RBAC will deny anything the interceptor mistakenly allows. Under
`user`, the same request is the moment a bug in the normalizer (§5.5) becomes a real
`listKeys` against production, so it is opt-in, logged distinctly, and surfaced in the
result summary rather than buried in the call log.

`write` under `user` is permitted rather than blocked. Plan/apply (§6.4) puts a human in
front of every mutation, and blocking it outright would just send people back to `az` with
no interceptor and no audit trail at all — strictly worse.

### 4.3 Privilege disclosure at session open

When resolving to `user`, issue one cheap query for the principal's role assignments at the
bound subscription scope (`Microsoft.Authorization/roleAssignments/read`, which Reader
holds) and surface the result:

```
identity=user  roles: Owner @ /subscriptions/…  ⚠ interceptor is the only guardrail
```

This makes §5.7's "guardrail, not boundary" caveat concrete at the moment it matters
instead of leaving it as a README claim. Failure to read role assignments is a warning, not
a hard error.

### 4.4 Graduating to a reader SP

The tool must **not** create the SP or role assignment itself — that is precisely the class
of privileged mutation it exists to avoid. Instead, `azure_accounts()` emits ready-to-run
setup commands (`az ad sp create-for-rbac` with a certificate credential, plus the role
assignment at the intended management-group scope) so the upgrade path is a copy-paste
rather than a research project.

### 4.5 Why a second principal rather than downscoping

Azure has no downscoping and no impersonation for ARM:

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

Do **not** shell out to `az account get-access-token`; that reintroduces exactly the global
state this project exists to avoid.

- Parse `~/.azure/azureProfile.json` directly (UTF-8 **with BOM** — decode as `utf-8-sig`).
  Take the complete subscription list and index by `(environmentName, tenantId,
  subscriptionId)`. **Ignore `isDefault` entirely.**
- MSAL public client using the well-known Azure CLI client ID
  `04b07795-8ddb-461a-bbee-02f9e1bf7b46`. Authority derived from the target cloud's
  `activeDirectory` endpoint + the subscription's `tenantId`. Silent acquisition against
  `<resourceManager>/.default`.
- **Never write to `~/.azure/msal_token_cache.bin`.** Instead, **seed our own cache from
  it.** On first use, silent-acquire against az's cache read-only, then persist the
  resulting refresh token in our own store (OS keychain; file with `0600` as fallback). All
  subsequent rotation happens in our store. az's file is never opened for write, so we can
  never corrupt it and never contend on the `CrossPlatLock` that produces azure-cli
  #20273 / #21744.
- **Self-healing re-seed.** Entra rotates refresh tokens on every use, and independent
  rotation from a shared ancestor RT means one side can eventually hold a dead token. On
  silent-acquire failure, re-read az's cache and re-seed automatically. The worst case
  degrades to today's behavior — "run `az login`" — but only after the automatic path has
  been tried, rather than every time a token expires.
- Memoize in-process by `(cloud, tenant, audience)` for the session lifetime.

**Audit attribution caveat.** Using the Azure CLI client ID means Entra sign-in logs
attribute this tool's activity to *Microsoft Azure CLI*. It works and requires no setup,
but in a CMMC/FedRAMP context you generally want the tool to appear distinctly in sign-in
logs, and you want it independently targetable by Conditional Access. The clean endpoint is
a **dedicated app registration** with `user_impersonation` on ARM (§11). That is a
change-control conversation in a regulated tenant, which is why it is v2 and not v1.

Note that graduating to the `reader` SP (§4.6) sidesteps the whole question — a certificate
credential is good for a year and never needs an interactive login at all.

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

Cache key is therefore `(cloud, tenant, audience)`. Audiences resolve from cloud metadata
(§2.3), never hardcoded.

### 4.9 Credential discovery tool

`azure_accounts()` enumerates every cached identity across all clouds — the thing `az`
makes structurally hard. Returns `{cloud, tenantId, subscriptionId, name, user, state,
tokenStatus}` with no notion of "current".

---

## 5. Interaction Tiers

### 5.1 Three tiers, not two

Method-based filtering fails in both directions on ARM. `POST` is a read verb throughout
(Resource Graph queries, metrics, `checkNameAvailability`), while `POST .../listKeys` is a
read that surrenders a storage account.

| Tier | Grants |
|---|---|
| `inspect` *(default)* | All `*/read` control-plane actions; explicitly allowlisted non-mutating `/action` operations |
| `read` | `inspect` + secret-bearing list operations (`listKeys`, `listSecrets`, `listConnectionStrings`, …) |
| `write` | Mutations, gated by two-phase plan/apply (§6.4) |

`isDataAction: true` is a **separate axis**, not a tier. Data-plane operations are where
customer data actually lives. All data actions are denied in `inspect` regardless of verb;
enabling them is a distinct opt-in.

### 5.2 Deriving the tier table

The surface is largely self-labeling, because RBAC action names carry the verb as a suffix
— which is why built-in Reader is expressible as `*/read`.

**Source of truth:** `GET /providers/Microsoft.Authorization/providerOperations?api-version=2022-04-01&$expand=resourceTypes/operations`, fetched **per cloud** and snapshotted.

> Do **not** use per-provider `/providers/{ns}/operations` endpoints. They are inconsistent
> about whether `isDataAction` is present, their api-version metadata is frequently wrong,
> and some providers do not expose the endpoint at all.

Classification pipeline:

1. **Suffix → tier** for `/read`, `/write`, `/delete`. Roughly 75% of the surface, zero
   ongoing maintenance.
2. **`isDataAction: true`** → data-plane axis, independent of verb.
3. **`/action` residue** (~20–25%) → regex on the action leaf:
   - non-mutating → `inspect`: `^(list|get|read|check|validate|query|fetch|resolve|preview|test|calculate|estimate)`
   - secret-bearing → `read`: `(?i)(key|secret|credential|sas|token|password|connectionstring|adminpassword)`
     — catches `listKeys`, `listAdminKeys`, `listConnectionStrings`, and
     `listCallbackUrl` (Logic Apps callback URLs embed a SAS)
   - mutating → `write`: `^(start|stop|restart|failover|restore|export|import|move|regenerate|rotate|purge|cancel|approve|reject|deploy|scale|set|create|update|write|generate|invoke|run|execute)`
4. **Unmatched → `write`.** Fail closed. Unmatched operations enter a review queue.
5. **Override file** — hand-maintained, layered last.

### 5.3 Why the override file is not optional

The derived labels are good but imperfect:

- `Microsoft.Sql/servers/databases/export/action` reads as non-mutating and is not — it
  writes a bacpac to a storage account.
- Microsoft's own metadata contains mislabels: `Microsoft.Help/diagnostics/read` is
  described as *"Created and Reads a diagnostic resource."* A `/read` that creates.

Budget for a small, reviewed override list. This is a very different maintenance posture
from curating 15–20k operations by hand.

### 5.4 Maintenance model

Refresh snapshots monthly. **Review the diff, not the corpus.** New `/action` names arrive
at a rate of tens per month, and only the unmatched ones need human attention.

**Distribution:** ship a snapshot with the release so the tool works offline and in
air-gapped clouds from first run; fetch updates in the background on a TTL and swap
atomically to the newest available. Never block startup on a fetch, never hard-fail on a
fetch error. The snapshot version is recorded in the call log so a surprising denial can be
explained against a specific table rather than a moving target.

### 5.5 The security-critical component: request → action normalization

Given `POST /subscriptions/{s}/resourceGroups/{rg}/providers/Microsoft.Sql/servers/{n}/databases/{d}/export?api-version=…`
the normalizer must yield `Microsoft.Sql/servers/databases/export/action`.

Algorithm: strip scope prefix → locate `/providers/{namespace}` → alternate type/name
segments discarding names → derive verb (GET→`read`, PUT/PATCH→`write`, DELETE→`delete`,
POST→`/{leaf}/action`) → look up in the tier table.

**Any path the normalizer cannot parse must deny.** Fail closed, no exceptions.

Known edge cases requiring explicit handling:

- Extension resources (`/providers/Microsoft.Authorization/roleAssignments` at arbitrary scope)
- Management-group and tenant scopes
- Nested providers
- `Microsoft.Resources/deployments` — a PUT that performs arbitrary writes; must be `write`
  tier despite its declarative framing
- Tenant-level POSTs such as `/providers/Microsoft.ResourceGraph/resources`

Note that Resource Graph queries map to `Microsoft.ResourceGraph/resources/read` despite
being POSTs. **HTTP method and RBAC verb disagree**, and RBAC follows the metadata — which
is precisely why the normalizer must resolve through the operations table rather than
inferring from the method.

**Test strategy:** fuzz the normalizer against the full path-template corpus from
`azure-rest-api-specs`. Ground truth exists; this is testable rather than hopeful.

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
**not on the critical path** — it costs real maintenance (~5000 custom roles per tenant;
`assignableScopes` must be enumerated explicitly; `notActions` **subtracts** rather than
denies, so a second role assignment granting the action still wins; propagation takes
minutes) and buys little over composed built-ins. Ship the generator, default to built-ins.

### 5.7 Relationship between the interceptor and RBAC

- **RBAC on the `reader` SP is the boundary.** It is what actually holds.
- **The interceptor is a guardrail.** Its value is fast, legible, pre-flight failures
  ("`listKeys` is tier `read`, session is `inspect`") instead of an opaque
  `AuthorizationFailed` forty seconds into a fan-out — and it is the *only* protection in
  `identity: 'user'` mode — which, since that is the zero-config default (§4.1), is the
  mode most sessions will actually run in.

State this in the README. Do not let it read as a security boundary.

---

## 6. Interaction Model

### 6.1 Tool surface

Deliberately small — the API surface lives in the code, not in the tool list.

| Tool | Purpose |
|---|---|
| `azure_run` | Execute JS in a session isolate; returns value + logs + call log |
| `azure_accounts` | Enumerate cached identities across all clouds |
| `azure_schema_search` | Keyword search over resource types / operations |
| `azure_schema_get` | Full request/response schema for a type + api-version |
| `azure_apply` | Execute a previously approved mutation plan |

### 6.2 Sessions are persistent

A session holds a live isolate. Globals persist across `azure_run` calls, so the model can
fetch once and interrogate repeatedly without re-paying for the ARM round trip.

```
azure_session_open({ bindings? }) → { sessionId, resolvedBindings }
azure_run({ sessionId, code, identity, mode })
```

Sessions are evicted on idle TTL, absolute max age, or memory pressure. Eviction is
reported so the model knows its state is gone rather than silently observing `undefined`.

**Identity is per-call, not per-session.** A session may mix `reader` and `user` calls
freely; each call records its identity in the call log. Refs are inert data that has already
been fetched, so there is no privilege-laundering path through the ref store. The one
constraint: a mutation **plan executes under a single identity**, fixed at plan creation and
re-validated at `azure_apply` time.

### 6.3 Return protocol: refs, not truncation

ARM responses are enormous. **Never truncate JSON** — a truncated array is useless to a
model, whereas a structural summary is genuinely informative.

Anything exceeding the return cap (default 64 KB) is auto-converted to a ref:

```js
const dbs = await az.gov.graph(`Resources | where type =~ 'microsoft.sql/servers/databases'`);
// → { __ref: "r3", type: "Array<Object>", length: 4211,
//     keys: ["id","name","tier","elasticPoolId","subscriptionId"],
//     sample: [ {...}, {...} ] }

dbs.filter(d => d.tier === 'BusinessCritical').length   // next call — one integer crosses the wire
```

The ref store is implemented **host-side in Rust**, not in JS, so generated code cannot
clobber it. `az.peek(x)` forces a structural summary on demand.

This is the single largest determinant of whether code mode feels good or drowns the
context window.

### 6.4 Write mode: plan / apply

The model never holds the write capability.

1. `azure_run` with `mode: 'write'` executes but **intercepts mutations**, collecting them
   as a plan rather than issuing them.
2. The plan is returned as a rendered diff (scope, action, target, body delta) with a
   `planId`.
3. Human approves out of band.
4. `azure_apply({ planId })` executes with no model in the loop and no code execution —
   just replay of the recorded requests.

Plans expire (default 15m) and are bound to the session and identity that produced them.

### 6.5 The `az` object

Three layers:

```js
// L0 — escape hatch; everything else is sugar over this
await az.request({ cloud: 'AzureUSGovernment', subscription: SUB, method: 'GET',
                   path: `/resourceGroups/${rg}/providers/Microsoft.Sql/servers`,
                   apiVersion: '2023-08-01' });

// L1 — Proxy-based, schema-free, auto-paging
for await (const db of az.gov.sub(SUB).rg('prod').type('Microsoft.Sql/servers/databases')) { … }

// L2 — Resource Graph. First-class.
await az.gov.graph(`
  Resources
  | where type =~ 'microsoft.sql/servers/elasticpools'
  | project id, name, tier = tostring(sku.tier), subscriptionId
`);
```

**Resource Graph should be the default recommendation in the tool description.** It
collapses an N-subscription × M-resource crawl into a single cross-subscription call, and
it is where most fleet-inventory questions actually belong. L1 is the fallback for what ARG
does not index.

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

The `azure-rest-api-specs` corpus is ~2 GB of JSON. Ship a compact index (< 100 MB) of
paths, methods, versions, and metadata; fetch full schemas lazily from a local checkout or
HTTP cache via `azure_schema_get`.

---

## 8. Transport Layer

Every request from the isolate — ARM or data plane — crosses into Rust as a struct, is
normalized (§5.5), classified, and only then signed. Responsibilities:

- **Signing** — token selected by `(cloud, tenant, identity)`; never exposed to the isolate.
- **Subscription resolution** — binding lookup or explicit override, recorded with provenance
  before the request is signed (§2.2).
- **Paging** — transparent `nextLink` following, surfaced as async iteration. Cap total
  pages per call with an override.
- **Retry** — exponential backoff on 429/5xx, honoring `Retry-After`.
- **Rate-limit accounting** — surface `x-ms-ratelimit-remaining-subscription-reads` in the
  call log. ARM read limits (~12k/hr/subscription) are trivially exhausted by
  `Promise.all` across 40 subscriptions.
- **Concurrency cap** — default 8 in-flight requests per session. Prevents both 429 storms
  and MSAL cache lock contention.
- **Long-running operations** — `Azure-AsyncOperation` / `Location` polling, only reachable
  in `write` mode.

### 8.1 Call log

Every request records: cloud, subscription, tenant, identity, method, path, resolved RBAC
action, tier, decision (allow/deny + reason), HTTP status, duration, remaining rate limit.

Because subscription resolution happens here and is recorded per request, the invisibility
that makes `az`'s ambient state dangerous does not reproduce: every call states which
subscription it used and why.

The call log is returned with every `azure_run` result. It is simultaneously the audit
trail, the debugging surface, and the thing that makes a high-privilege tool reviewable.

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
| **ARM-proxied** — `POST …/Microsoft.OperationalInsights/workspaces/{n}/api/query` | Reuses the ARM token and the existing normalizer | Tighter throttling and shorter timeouts |

**Recommendation: direct data plane**, with the ARM-proxied path as a fallback when the
Log Analytics audience is unavailable. The query limits matter for anything fleet-shaped.

Policy: a KQL query is `inspect`. KQL is read-only by construction — there is no mutating
statement — so unlike SQL (§9.4) no statement classification is required. The one control
worth having is a **result-row cap** feeding the ref store (§6.3), since a careless
`| take 1000000` is a context-flooding event rather than a security one.

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

The tier split is clean and worth enforcing explicitly:

| Operation | Tier | Rationale |
|---|---|---|
| `GET /secrets` (list names, versions, metadata) | `inspect` | Names are inventory, not secrets |
| `GET /secrets/{name}` (value) | `read` | Actual secret material |
| `GET /keys`, `/certificates` metadata | `inspect` | |
| Any write/rotate/purge | `write` | |

Secret **values returned into the isolate must never enter the ref store's summaries or
the call log** — log the identifier and a hash, never the value.

### 9.4 Azure SQL — deliberately out of scope for v1

Different transport (TDS, not HTTP), different policy model, and the tier system does not
map onto SQL statements. Statement parsing as a safety mechanism is a losing game.

If it lands later, the honest design is *not* a query classifier:

- AAD token auth against `database.*` audience — the credential broker already supports it
- Read-only enforced by a **dedicated database principal with `db_datareader` only**, plus
  `ApplicationIntent=ReadOnly` routed to a geo-secondary
- The read-replica route also removes the risk of an exploratory query affecting the
  primary's workload

That is a real security boundary, unlike statement inspection. Until it exists, `sqlcmd`
stays where it is.

### 9.5 Blob storage

"Storage" meaning blob content specifically — useful for reading diagnostic logs, exported
artifacts, and bacpacs that other tooling drops there.

- Audience `storage.azure.com`; endpoint from cloud metadata suffixes
- Requires `Storage Blob Data Reader` — **Reader does not grant this**
- Container/blob enumeration → `inspect`; blob content read → `inspect` for text/JSON,
  with a size cap routing large objects into the ref store rather than the response
- Writes and SAS minting → `write`

### 9.6 Uniform treatment

Every data plane routes through the same host-side interceptor, call log, retry, and ref
store as ARM. What differs is only the classification ruleset and the audience. A data
plane that cannot be classified is denied — the same fail-closed rule as §5.5.

---

## 10. Failure Modes to Design For

| Failure | Mitigation |
|---|---|
| Context flooding from large ARM responses | Ref store + structural summaries (§6.3) |
| 429 from naive fan-out | Concurrency cap, backoff, rate-limit visibility |
| Gov/commercial api-version skew | Per-cloud version resolution (§2.4) |
| Stale/expired cached tokens | Own cache + automatic re-seed from az's cache (§4.7); `az login` only as last resort |
| Seeded RT killed by independent rotation | Re-seed on silent-acquire failure; degrades to today's behavior, no worse |
| Reader grants no blob/KV data access | Additive built-in roles documented in §5.6; denial message names the missing role |
| KQL result explosion | Row cap into the ref store (§9.1) |
| Secret values in logs | Values never enter ref summaries or call log (§9.3) |
| MSAL lockfile contention | az's cache is never opened for write (§4.7) |
| Normalizer parse failure | Fail closed; deny and log |
| Wrong cloud assumed | Cloud is never defaulted; an omitted cloud is an error, not a fallback |
| Wrong subscription assumed | Binding is per-cloud and immutable; resolution + provenance in every call-log entry (§2.2.1) |
| Running under Owner without noticing | Identity + role assignments disclosed at session open (§4.3); escalation to `read`/`write` flagged distinctly under `user` |
| Session evicted mid-workflow | Explicit eviction notice in the next call's result |

---

## 11. Phasing

**v0 — prove the core**
- deno_core isolate, no persistence, `az.request` + `az.graph` only
- Per-cloud subscription binding from config + auto-bind on single-subscription clouds
- `identity: 'user'` from the MSAL cache — the zero-config default path
- Own token cache seeded from az's, with automatic re-seed (§4.7)
- Tier enforcement from a shipped `providerOperations` snapshot, `inspect` only
- Call log

**v1 — usable**
- Persistent sessions + ref store
- **Log Analytics KQL** (§9.1) and **Monitor metrics batch** (§9.2) — the two surfaces that
  retire existing `az rest` usage, and the reason to reach for the tool daily
- Schema search index
- L1 Proxy API, auto-paging
- `identity: 'reader'` SP support (certificate credential) + setup-command emission
- Privilege disclosure at session open (§4.3)
- `read` tier; Key Vault (§9.3)

**v2 — mutations and hardening**
- Plan/apply with two-phase approval
- Dedicated app registration for distinct sign-in-log attribution (§12.1)
- Managed identity credential path
- Blob storage (§9.5)
- LRO polling
- Custom role generator (optional; built-ins remain the default)

**Deferred indefinitely**
- Azure SQL / TDS (§9.4) — pending a read-replica + `db_datareader` design, not statement parsing

---

## 12. Open Questions

Prior questions on cache write-back, session/identity mixing, multi-tenant acquisition,
custom roles, snapshot distribution, and data-plane scope are resolved in §4.7, §6.2, §4.8,
§5.6, §5.4, and §9 respectively. What remains:

### 12.1 Dedicated app registration

Using the Azure CLI client ID needs no setup but attributes all activity to *Microsoft
Azure CLI* in Entra sign-in logs and makes the tool untargetable by Conditional Access
independently of `az` itself. A dedicated registration with `user_impersonation` on ARM
fixes both and is the better fit for a CMMC-audited tenant — at the cost of a change-control
conversation and admin consent in each tenant. Worth doing; the question is when, and
whether the tool should ship the app manifest.

### 12.2 KQL result-size policy

`| take 1000000` is a context-flooding event, not a security one, but the mitigation is
unclear at the edges. Hard row cap, byte cap, or automatic `| take N` injection into
submitted queries? Injection is the most protective and the most surprising — it silently
changes query semantics, which is exactly the kind of invisible behavior this design has
otherwise avoided.

### 12.3 Cross-workspace Log Analytics scope

`workspaces()` and `resource()` in KQL reach beyond the bound workspace. Does the binding
model (§2.2) constrain that, or is it treated like Resource Graph (§2.2.2) — deliberately
unbound, since cross-workspace correlation is the point? Leaning unbound, but the
asymmetry should be deliberate rather than emergent.

### 12.4 Data-plane tier tables

ARM's tiers derive from `providerOperations`. The data planes have no equivalent metadata —
their rulesets are hand-written and small (a dozen rules each). Where do they live, how are
they versioned alongside the ARM snapshot, and what is the fail-closed default for an
unrecognized data-plane path?
