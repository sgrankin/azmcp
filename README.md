# azmcp

`azmcp` is a modern, stateless MCP `2026-07-28` server for bounded Azure
inspection from persistent JavaScript contexts.

The MCP transport has no session lifecycle. Application state is explicit: a
caller opens an opaque context, runs one serialized JavaScript turn at a time,
and closes the context. Each context fixes its identity, cloud bindings,
subscription allowlist, Resource Graph scope, Azure-inspect-only capability,
optional managed local capabilities, policy bundle, and isolated V8 worker.

v0 is deliberately small. It exposes:

- `azure_accounts`
- `azure_context_open`
- `azure_run`
- `azure_context_close`
- `azure_schema_search`
- `azure_schema_get`

Schema discovery is offline and tied to the reviewed route policy. The catalog
includes the executable surfaces for `az.request`, `az.metrics.single`,
`az.metrics.batch`, and `az.logs.query`; helper argument schemas are closed and
separate from host-owned HTTP body schemas. Response schemas remain
`metadataOnly` because no response fixtures are checked in.

Inside `azure_run`, JavaScript has only `console`, `az.request`, `az.graph`,
the reviewed `az.metrics` and `az.logs` helpers, the context-scoped
`az.ref`/`az.peek` result helpers, and the explicitly granted managed artifact
writer described below. There is no general filesystem access, `fetch`,
`Deno`, token access, ambient cloud, or ambient subscription.

The metrics signatures are explicit and closed:

```js
az.metrics.single({
  cloud, resourceId, metricNames, timespan?, interval?, aggregation?, top?,
  orderBy?, filter?, resultType?, metricNamespace?, autoAdjustTimegrain?,
  validateDimensions?, rollupBy?
})
az.metrics.batch({
  cloud, region, resourceIds, metricNamespace, metricNames, startTime?, endTime?,
  interval?, aggregation?, top?, orderBy?, filter?, rollupBy?
})
```

Both helpers require an explicit `cloud`. Batch requires an explicit validated
regional endpoint, accepts at most 50 same-type resource IDs, and accepts at
most 20 metric names.

Direct Log Analytics and workspace-backed Application Insights queries use:

```js
await az.logs.query({
  cloud: "AzureUSGovernment",
  workspaceId: "00000000-0000-0000-0000-000000000000",
  query: "AppRequests | take 10",
  timespan: "PT1H",
});
```

The zero GUID is a placeholder for a Log Analytics Workspace ID.
Resource Graph exposes that GUID as `properties.customerId` on a
`Microsoft.OperationalInsights/workspaces` resource.
It is not the workspace name or ARM resource ID, and it is not an Application
Insights `appId`.
If starting from an Application Insights component, use Resource Graph to
follow its `properties.WorkspaceResourceId` to the workspace, then use that
workspace resource's `properties.customerId`.

Every helper call must pass exactly `"AzureCloud"` for commercial Azure or
`"AzureUSGovernment"` for US Government.
azmcp does not infer cloud from `az cloud set` or other mutable CLI state.

The context must explicitly grant `logs.query` and opt each cloud into the
initial non-porous Logs scope:

```json
{
  "dataPlanes": ["logs.query"],
  "logsScopes": {
    "AzureUSGovernment": {"scope": "allAccessible"}
  }
}
```

`allAccessible` is deliberate: a workspace allowlist would not bound KQL that
uses cross-workspace references or stored functions. The v0 `az.request`
surface accepts no caller headers or body. The reviewed route bundle contains
subscription validation, provider metadata, Resource Graph, metrics, and Logs
Query operations for Azure commercial and US Government clouds, plus the pinned
`StorageAccounts_GetProperties` ARM GET for both clouds.

### Managed JSON artifacts

A context can explicitly grant one local capability for handing a generated
value to a local CLI or visualization script without returning the JSON through
MCP:

```json
{
  "localCapabilities": ["artifacts.write"]
}
```

```js
const receipt = await az.artifacts.writeJson({
  name: "metrics.json",
  value: result
})
// {path, bytes, sha256, logicalBytes, mediaType, sensitivity}

const arrayReceipt = await az.artifacts.writeJsonArray({
  name: "metrics.json.lz4",
  compression: "lz4",
  values: asyncMetricBatches
})

const linesReceipt = await az.artifacts.writeJsonLines({
  name: "metrics.jsonl",
  values: metricRows
})
```

`name` is one conservative ASCII filename ending in `.json`, never a path.
The streamed helpers also accept `.jsonl`; compressed names add a `.lz4`
suffix, producing `.json.lz4` or `.jsonl.lz4`.
`values` may be an iterable or async iterable and is transferred in bounded,
acknowledged chunks rather than one giant worker message.
`writeJsonArray` produces one conventional top-level JSON array;
`writeJsonLines` writes one compact JSON value per line.
Compression is opt-in with `compression: "lz4"` and uses an LZ4 frame with a
content checksum.

Writes are create-only and confined to a fresh random directory owned by that
context. A single-value `writeJson` file is limited to 480 KiB.
A streamed artifact is limited to 64 MiB of logical JSON and 65 MiB of stored
bytes, allowing bounded LZ4 framing overhead for incompressible input.
A context can create at most 32 files and retain 128 MiB of stored bytes; one
artifact root can hold at most 256 files and 512 MiB.
Directories are mode `0700` and files mode `0600` on Unix. Symlinks,
non-regular destinations, traversal, overwrite, and cross-context addressing
fail closed.

Receipt `bytes` and `sha256` describe the file actually stored at `path`.
`logicalBytes` describes the decoded JSON size, and compressed receipts add
`contentEncoding: "lz4"`.
The media type is `application/json` for arrays and
`application/x-ndjson` for JSON Lines.

The managed artifact store currently requires Unix file identities and private
mode semantics (macOS or Linux). Other platforms fail server startup until an
equivalent exact file-identity and private-ACL implementation is reviewed.
The boundary isolates JavaScript/MCP callers and other OS users; it does not
treat another hostile process running as the same OS user as a separate
principal. Do not share or concurrently rewrite the artifact root from an
untrusted same-UID process.

Writes are staged privately and published only if the complete `azure_run`
succeeds. A failed, timed-out, closed, or cancelled run returns no receipt and
removes its staged files, including a file whose publication raced with
cancellation. The audit decision `authorized` records the content-free write
attempt; it does not claim that a later run commit succeeded.

Abrupt process or host termination at the publication boundary is different
from cancellation: the local file may have committed even if the MCP response
was lost. azmcp removes stale unpublished temporary files on the next locked
transaction, but cannot infer whether a durable create-only artifact was
received by the client. Such an orphan remains subject to the normal root
quota and ordinary local-shell cleanup.

Artifacts deliberately survive context close, expiry, and server restart so a
local process can consume the returned path. azmcp exposes no artifact read,
list, delete, or arbitrary filesystem API; cleanup is an ordinary local-shell
operation. The durable audit log records only the correlation ID, operation,
stored and logical byte counts, encoding, media type, and sensitivity—not the
path, filename, or JSON content.

## Build and test

The workspace pins Rust 1.97.1 and `rmcp` 3.0.1.

```sh
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release
cargo run -p azmcp-routegen -- --check
```

The reviewed runtime manifest at
`fixtures/reviewed-routes/v1-observability-1.json` is regenerated from the
immutable 16-route seed at
`fixtures/reviewed-routes/v1-observability-seed-v2.json` plus the pinned,
normalized Storage OpenAPI catalog and separate RBAC evidence in
`fixtures/upstream/`. The explicit routegen import check compares those inputs
to the checked-in 18-route/12-schema output. `azmcp-routegen --check` rejects
malformed, unpinned, non-canonical, or incomplete route/schema data;
`--write` canonicalizes the reviewed fixture deterministically. Request,
metrics, and Logs Query rows feed schema discovery under their exact execution
surfaces. Resource Graph and internal rows remain undiscoverable, and helper
routes are never advertised as generic `az.request` capabilities.

Tests use synthetic Azure profiles, fake `az` executables, and loopback HTTP
servers. They must not use an ambient Azure login.

## Configuration

The default azmcp configuration path is
`$XDG_CONFIG_HOME/azmcp/config.toml`, or
`$HOME/.config/azmcp/config.toml` when `XDG_CONFIG_HOME` is unset.
No azmcp-specific environment variables are required for a normal installation.
`AZMCP_CONFIG` is an optional override for tests and nonstandard layouts.

```toml
[clouds.AzureCloud]
subscription = "11111111-1111-1111-1111-111111111111"
tenant = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

[[clouds.AzureCloud.allowed_subscriptions]]
subscription = "22222222-2222-2222-2222-222222222222"
tenant = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

[clouds.AzureUSGovernment]
subscription = "33333333-3333-3333-3333-333333333333"
tenant = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

# Optional. Defaults to the standard user data directory described below.
[artifacts]
root = "/absolute/private/path/to/azmcp-artifacts"
```

An omitted primary tenant is resolved only when the cached Azure profile has
exactly one matching tenant candidate. With no configured or caller-supplied
bindings, auto-binding succeeds only for a cloud with exactly one candidate;
ambiguity fails closed.

The managed artifact root defaults to
`$XDG_DATA_HOME/azmcp/artifacts`, or
`$HOME/.local/share/azmcp/artifacts` when `XDG_DATA_HOME` is unset.
The optional `[artifacts] root` setting must be an absolute path. The root is
created lazily on the first explicitly granted artifact write; startup and
ordinary Azure inspection do not create it. An existing root must already be a
private dedicated azmcp artifact root (or an empty private directory); azmcp
never changes permissions on an unrelated directory. One server holds the
root lock while it has staged writes, releasing it after the last commit or
rollback. This makes create-only checks and the documented quotas root-wide
without monopolizing the standard root across Codex processes.

Profile discovery uses `AZMCP_AZURE_PROFILE`, then
`$AZURE_CONFIG_DIR/azureProfile.json`, then
`$HOME/.azure/azureProfile.json`. The credential subprocess is selected with
`AZMCP_AZ_EXECUTABLE`, defaulting to `az`. MCP startup, discovery, tool listing,
and cached profile discovery do not invoke Azure CLI. The first operation that
needs a token runs the bounded, non-authenticating
`az version --output json --only-show-errors` probe and requires Azure CLI
2.89.0 or newer. A successful probe is cached; a failure is not, so the caller
can repair the CLI or run the instructed `az login` externally and retry without
restarting the MCP server. The server never performs login or changes Azure CLI
configuration.

The durable, redacted JSONL request log defaults to
`$XDG_STATE_HOME/azmcp/requests.jsonl`, or
`$HOME/.local/state/azmcp/requests.jsonl`. Its active file is mode `0600` on
Unix. Configure it with:

- `AZMCP_AUDIT_LOG`
- `AZMCP_AUDIT_MAX_BYTES` (default 10 MiB, minimum 64 KiB)
- `AZMCP_AUDIT_RETAINED_FILES` (default 10, maximum 100)

Audit records contain reviewed path templates and structured metadata, never
raw paths, queries, headers, request or response bodies, JavaScript source,
console output, context handles, subprocess output, or bearer tokens. An
unavailable audit sink fails an Azure request before credential acquisition or
network I/O.

## Codex

Codex CLI 0.147.0 has source-verified support for MCP `2026-07-28` behind the
`mcp_2026_07_28` feature. A stdio server also needs Codex's out-of-band protocol
selection marker:

```toml
[features]
mcp_2026_07_28 = true

[mcp_servers.azmcp]
command = "/absolute/path/to/azmcp"

[mcp_servers.azmcp.env]
CODEX_MCP_PROTOCOL_VERSION = "2026-07-28"
```

The feature can instead be enabled for one invocation with
`codex --enable mcp_2026_07_28`. Codex consumes
`CODEX_MCP_PROTOCOL_VERSION` before it launches the child; `azmcp` neither
expects nor receives that variable. The server finds its configuration, Azure
CLI profile, `az` executable, and audit destination through the standard paths
described above. Legacy `initialize` is intentionally not implemented.

With the feature enabled, the equivalent CLI registration is:

```sh
codex mcp add azmcp \
  --env CODEX_MCP_PROTOCOL_VERSION=2026-07-28 \
  -- /absolute/path/to/azmcp
```

## Safety model

Every Azure request selects a cloud explicitly, resolves a subscription only
from the immutable context allowlist, matches a reviewed method/path/API-version
row before signing, disables redirects, and enforces an exact cloud origin.
The Azure CLI broker validates the returned subscription, tenant, ARM JWT
tenant, principal (`oid`), and client (`appid` or `azp`). A principal change
during a context lifetime fails authentication and evicts the context. Token
cache entries are context-scoped, so a newly opened context establishes its
own current CLI principal.

One worker process is retained per context. JavaScript turns default to 60
seconds, the V8 heap is capped at 64 MiB, and the parent enforces a 256 MiB
resident-set ceiling by sampling the child every 50 ms and hard-killing it on
breach. Synthetic local workers measured roughly 28–32 MiB RSS after startup
and roughly 67–80 MiB under heap pressure across recent runs on this macOS
arm64 host, so the process ceiling leaves room for the configured V8 heap and
runtime overhead. These are diagnostic samples, not a portability guarantee.
Inline serialized results are capped at 64 KiB. Larger serializable values up
to the bounded 480 KiB worker-reference ceiling become immutable, context-scoped
refs with a structural preview; JavaScript can rehydrate one with
`await az.ref(refId)` only in that context, and `az.peek(value)` returns a
shape-only summary. Large object previews stop after bounded key sampling and
iteration, then report `keyCountAtLeast`, `keysSampled`, and `hasMore` instead
of claiming an exact count or omitted-key total. Cyclic, non-serializable, or over-hard-cap
values fail closed with shape-only diagnostics, never truncated JSON. Reference IDs and
stored values are disposed with context close, expiry, or capacity eviction;
previews contain no value samples. Key names and string lengths are
`customerData` metadata; this slice does not infer or propagate secret labels.
At most eight host calls run concurrently.
Cancellation, timeout, heap pressure, RSS pressure, worker death, close, TTL
expiry, or credential-identity change dispose the affected context. The RSS
sampler uses OS process APIs through `sysinfo`; it does not invoke `ps` or
another shell command.

Do not point development tests at a real Azure profile, credential cache, or
subscription. Authenticated acceptance testing belongs in a separately
authorized non-production environment.
