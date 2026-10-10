# azmcp

`azmcp` is an MCP stdio server for bounded Azure
inspection from persistent JavaScript contexts.

The MCP transport detects initialize-based and stateless clients.
Application state is explicit: a
caller opens an opaque context, runs one serialized JavaScript turn at a time,
and closes the context. Each context fixes its identity, cloud bindings,
subscription allowlist, Resource Graph scope, Azure-inspect-only capability,
optional managed local capabilities, policy bundle, and isolated QuickJS worker.

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

The JavaScript surface is synchronous.
A helper waits for its host operation and returns the result directly.
Use ordinary loops and functions; promises and async functions are unsupported.

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
az.logs.query({
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

Every Azure helper call must pass exactly `"AzureCloud"` for commercial Azure or
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
const receipt = az.artifacts.writeJson({
  name: "metrics.json",
  value: result
})
// {path, bytes, sha256, logicalBytes, mediaType, sensitivity}

const arrayReceipt = az.artifacts.writeJsonArray({
  name: "metrics.json.lz4",
  compression: "lz4",
  values: metricBatches
})

const linesReceipt = az.artifacts.writeJsonLines({
  name: "metrics.jsonl",
  values: metricRows
})
```

`name` is one conservative ASCII filename ending in `.json`, never a path.
`writeJsonArray` requires `.json`; `writeJsonLines` requires `.jsonl`.
Compressed names add a `.lz4` suffix, producing `.json.lz4` or `.jsonl.lz4`.
`values` is a synchronous iterable and is transferred in bounded,
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

The managed artifact store requires Unix file identities and private mode
semantics on macOS or Linux.
Other platforms require an equivalent reviewed file-identity and private-ACL
implementation before they can be supported.
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

Go 1.26 or newer is required.
The pinned `modernc.org/quickjs` runtime builds without a C compiler.

```sh
CGO_ENABLED=0 go build -o target/go/azmcp ./cmd/azmcp
go test ./internal/... ./cmd/...
go vet ./internal/... ./cmd/...
go run ./cmd/azmcp-routegen --check
```

The managed artifact implementation supports macOS and Linux.
Worker performance measurements are described in [benchmarks/worker](benchmarks/worker/README.md).

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

## MCP clients

Register the built binary as a regular stdio server:

```toml
[mcp_servers.azmcp]
command = "/absolute/path/to/azmcp"
```

Or use the Codex CLI:

```sh
codex mcp add azmcp -- /absolute/path/to/azmcp
```

The server supports these protocol revisions:

| Revision | Lifecycle | Tool results |
| --- | --- | --- |
| `2025-06-18` | `initialize` / `notifications/initialized` | Structured content plus JSON text |
| `2025-11-25` | `initialize` / `notifications/initialized` | Structured content plus JSON text |
| `2026-07-28` | `server/discover` and per-request metadata | Structured content, JSON text, and caching metadata |

Codex and pi can use the ordinary stdio configuration above without experimental flags.
Remove any old `CODEX_MCP_PROTOCOL_VERSION` entry to use Codex's default handshake.
Configure pi with the same stdio command using its MCP integration.
The server echoes each supported initialize revision and rejects unsupported revisions.
Modern clients must supply the required protocol and client-capability metadata on every
request; older clients use their negotiated session information.
Earlier revisions are unsupported.
JSON-RPC batches are unsupported.
Application context handles work the same way for every revision.

For Codex's optional `2026-07-28` client, retain the `mcp_2026_07_28` feature
and set `CODEX_MCP_PROTOCOL_VERSION = "2026-07-28"` in this server's configured
`env` table.
Codex consumes that selection marker before launching the child.
Application config and Azure profile discovery use the standard paths described above.

## Safety model

Every Azure request selects a cloud explicitly, resolves a subscription only
from the immutable context allowlist, matches a reviewed method/path/API-version
row before signing, disables redirects, and enforces an exact cloud origin.
The Azure CLI broker validates the returned subscription, tenant, ARM JWT
tenant, principal (`oid`), and client (`appid` or `azp`). A principal change
during a context lifetime fails authentication and evicts the context. Token
cache entries are context-scoped, so a newly opened context establishes its
own current CLI principal.

One QuickJS worker process is retained per context.
JavaScript turns default to 60 seconds, QuickJS allocations are capped at
64 MiB, and the parent samples child RSS every 50 ms with a 256 MiB ceiling.
The sampler uses native OS interfaces and hard-kills a worker on breach.
A timeout, cancellation, worker failure, context close or expiry, or credential
identity change disposes the affected context.
An allocation error caught inside JavaScript can leave the context usable;
the process RSS limit provides a separate bound on native memory.

Host helpers return ordinary values synchronously:

```js
const response = az.request({
  cloud: "AzureCloud",
  method: "GET",
  path: "/providers/Microsoft.Storage",
  apiVersion: "2021-04-01"
});
response.body
```

Calls within a turn run in order.
Returning a promise or thenable, or executing queued promise jobs, rejects the
turn and evicts the context.
There is no implicit promise-resolution transformation.
Persistent lexical bindings and ordinary synchronous functions remain available
across turns.
Values use JavaScript `JSON.stringify` semantics, including `toJSON` methods.

Inline serialized results are capped at 64 KiB.
Larger serializable values up to 480 KiB become immutable, context-scoped refs
with a structural preview; `az.ref(refId)` rehydrates one in that context.
`az.peek(value)` returns a shape-only summary.
For large objects, `az.peek` stops after bounded key sampling and iteration, then
reports `keyCountAtLeast`, `keysSampled`, and `hasMore`.
Reference and size-error previews describe the bounded serialized JSON value.
Size errors include structural diagnostics; cycles and BigInt produce a generic
`invalid_request` error.
Top-level undefined and functions serialize as null.
References last up to five minutes, with at most 32 entries and 4 MiB per context;
capacity pressure evicts the oldest entries sooner.
They are removed on context close or expiry.
Previews contain no value samples.
Key names and string lengths are `customerData` metadata; this version does not
infer or propagate secret labels.

Do not point development tests at a real Azure profile, credential cache, or
subscription. Authenticated acceptance testing belongs in a separately
authorized non-production environment.
