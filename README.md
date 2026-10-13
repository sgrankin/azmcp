# azmcp

`azmcp` is a Go MCP stdio server for bounded Azure inspection.
Clients compose typed operations with their own code mode or ordinary tool calls.
The server owns cloud selection, immutable authorization scopes, credential identity,
reviewed routes, HTTP limits, audit, and optional managed JSON exports.

## Tools

| Tool | Purpose |
| --- | --- |
| `azure_accounts` | Read cached subscription candidates without invoking Azure CLI |
| `azure_context_open` | Resolve and validate an immutable authorization context |
| `azure_context_close` | Revoke the context and cancel its active calls |
| `azure_request` | Execute a reviewed subscription-relative ARM GET |
| `azure_graph` | Query Resource Graph within the context scope |
| `azure_metrics_single` | Read metrics for one allowed resource |
| `azure_metrics_batch` | Read metrics for up to 50 same-type resources in an explicit region |
| `azure_logs_query` | Query an explicitly granted Log Analytics workspace data plane |
| `azure_export` | Run one Azure operation and publish its JSON to a private local file |
| `azure_schema_search` | Search the offline reviewed request/metrics/logs catalog |
| `azure_schema_get` | Retrieve a reviewed entry and its closed tool argument schema |

Each Azure operation takes `contextId`, explicit `cloud`, and its typed arguments.
Cloud is exactly `AzureCloud` or `AzureUSGovernment`.
The server does not infer it from `az cloud set`.
An authorization context fixes user identity, the inspect tier, subscription/tenant
bindings and allowlists, Graph scope, optional Logs grant, policy identity, and identity pins.
It permits up to eight concurrent operations; saturation returns retryable `context_busy`.
Request cancellation affects that call.
Close, expiry, and a credential identity change revoke the entire context.
There are at most 32 retained contexts, with 30-minute idle and 24-hour absolute expiry.

Ordinary operation results contain `value`, content-free `calls`, `callsOmitted`,
`sensitivity: "customerData"`, and `correlationId`.
ARM, Graph, and Metrics values have `{status, headers, body}`.
Logs values contain the validated `tables` result directly.
MCP returns structured content and a JSON text mirror for each result.

A client with programmatic tool calling can compose calls and return only an aggregate.
For example, in a client exposing the normalized `tools.mcp__azmcp__*` functions:

```js
const response = await tools.mcp__azmcp__azure_graph({
  contextId,
  cloud: "AzureCloud",
  query: "Resources | summarize count() by type"
});
text(response.structuredContent.value.body);
```

JavaScript runs in the client's runtime.
Each ordinary result crosses MCP before the client processes it.
Use Azure query projections/aggregation to reduce data at its source, or `azure_export`
to keep a response local and return a receipt.
See [Programmatic Tool Calling](https://developers.openai.com/api/docs/guides/tools-programmatic-tool-calling).

## Operation arguments

`azure_request` takes `contextId`, `cloud`, optional `subscription`, `method: "GET"`,
`path`, and `apiVersion`.
The path is relative to the selected subscription, for example `/providers/Microsoft.Storage`.
Full subscription paths, arbitrary headers/bodies, and unreviewed routes are rejected.

`azure_graph` takes `contextId`, `cloud`, `query`, and optional `subscriptions` or
`scope: "allAccessible"`.
Any requested subscription outside a restricted context scope rejects the entire call.
An all-accessible Graph scope must have been granted when opening the context.

`azure_metrics_single` takes `contextId`, `cloud`, `resourceId`, `metricNames`, and the
optional time/filter/aggregation controls listed in its closed input schema.
`azure_metrics_batch` takes `contextId`, `cloud`, `region`, `resourceIds`,
`metricNamespace`, `metricNames`, and its optional time/filter controls.
Batch accepts at most 50 same-type resources in one allowed subscription and 20 metric names.
Every resource subscription must be allowed by the context.

`azure_logs_query` takes `contextId`, `cloud`, optional `subscription`, `workspaceId`,
`query`, and `timespan`.
The workspace ID is the Log Analytics GUID exposed as `properties.customerId` on a
`Microsoft.OperationalInsights/workspaces` resource.
It is not a workspace name, ARM ID, or Application Insights `appId`.
For an Application Insights component, follow `properties.WorkspaceResourceId` to its workspace.

Logs requires `dataPlanes: ["logs.query"]` and a per-cloud Logs scope:

```json
{
  "dataPlanes": ["logs.query"],
  "logsScopes": {
    "AzureUSGovernment": {"scope": "allAccessible"}
  }
}
```

This scope is explicit because KQL may use cross-workspace references or stored functions.
The server does not rewrite KQL or promise a workspace allowlist boundary.
A response is limited to 50,000 total rows, including exports.

## Managed JSON exports

Open the context with `localCapabilities: ["artifacts.write"]`, then call:

```json
{
  "contextId": "<context handle>",
  "operation": "azure_logs_query",
  "arguments": {
    "cloud": "AzureUSGovernment",
    "workspaceId": "00000000-0000-0000-0000-000000000000",
    "query": "AppRequests | take 10",
    "timespan": "PT1H"
  },
  "name": "requests.json.lz4",
  "compression": "lz4"
}
```

The zero GUID is a placeholder for the intended workspace ID.
`operation` selects one of the five Azure operations, and `arguments` has that operation's
closed input shape without `contextId`.
The complete helper value is written as JSON, including the normal response envelope
for ARM, Graph, and Metrics.
The tool returns `receipt` with `path`, `bytes`, `logicalBytes`, `sha256`, `mediaType`,
`sensitivity`, and optional `contentEncoding: "lz4"`, plus call metadata and correlation ID.

Names are conservative ASCII filenames, never paths.
Identity compression uses `.json`; LZ4 uses `.json.lz4` with a content checksum.
Writes are create-only inside a random namespace owned by the context.
Directories are mode `0700`, files mode `0600`; symlinks and traversal fail.
The store supports macOS and Linux and requires an absolute root without symlink components.

Ordinary Azure response bodies are capped at 1 MiB; export bodies at 8 MiB.
The complete MCP tool result is independently capped at 1 MiB, including its text mirror.
HTTP body overflow fails with `result_too_large`.
MCP serialization overflow also supplies structural diagnostics and query/export guidance.
Exports avoid that transport limit by returning only a receipt.
The artifact store bounds JSON to 64 MiB logical and 65 MiB stored bytes,
with 32 files / 128 MiB per context and 256 files / 512 MiB per root.

An export stages a private file, then Commit makes the complete final path visible.
Finalize verifies the publication before accepting a receipt while the request and
authorization context remain live.
A file can briefly be visible before acceptance; failure or cancellation before acceptance
removes the staged file and revokes publication.
Separate exports have separate transactions; a later client-program failure does not
roll back an already accepted export.
The content-free audit decision `authorized` records the attempt, not a later commit.
Published files survive close, expiry, and restart.
An abrupt host failure can leave an orphan if the receipt was lost; stale unpublished
stages are scavenged on the next locked transaction.
Cleanup uses ordinary local filesystem tools; MCP exposes no artifact read/list/delete API.

## Build and test

Go 1.26 or newer is required; macOS and Linux are supported.

```sh
CGO_ENABLED=0 go build -o target/go/azmcp ./cmd/azmcp
CGO_ENABLED=0 go install ./cmd/azmcp
go test ./internal/... ./cmd/...
go vet ./internal/... ./cmd/...
go run ./cmd/azmcp-routegen --check
```

The reviewed runtime manifest contains 18 routes and 12 discoverable schemas.
It is regenerated from the immutable seed plus pinned Storage OpenAPI and RBAC evidence
in `fixtures/upstream/`.
Routegen checks canonical bytes, content pins, selector overlap, and complete schema joins.
Discovery maps those reviewed entries to typed MCP tools and adds their `contextId` input.
It copies schema documents; the embedded manifest and policy hash remain unchanged.
Graph and internal validation rows remain excluded from discovery.
Response schemas stay `metadataOnly` without reviewed response fixtures.

Tests use injected synthetic Azure profiles, fake CLI executables, and literal loopback HTTP.
They never use an ambient Azure login.

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
created lazily on the first explicitly granted export; startup and
ordinary Azure inspection do not create it. An existing root must already be a
private dedicated azmcp artifact root (or an empty private directory); azmcp
never changes permissions on an unrelated directory. One server holds the
root lock while it has staged writes, releasing it after the last finalized commit or
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

Register the installed binary as a stdio server:

```toml
[mcp_servers.azmcp]
command = "/Users/your-user/go/bin/azmcp"
```

The server supports `2025-06-18` and `2025-11-25` through initialize/initialized,
and `2026-07-28` through stateless discovery and per-request metadata.
Unknown revisions and JSON-RPC batches are unsupported.
Modern clients provide both protocol-version and client-capability metadata on every request.
Tool schemas and authorization handles have the same meaning in all three revisions.
Client code mode is optional; ordinary MCP clients can call the same typed tools.

## Safety model

Credentials and policy remain server-owned for every call, including client-generated programs.
The CLI broker validates cloud, subscription, tenant, audience, principal, and client identity.
Context identity pins and credential-cache scopes remain independent across contexts.
Redirects and environment proxies are disabled; exact reviewed origins and audiences are enforced.
Reviewed read retries and HTTP body/time limits remain bounded.

The audit sink is private, append-only, synced, bounded, and rotated.
Records contain reviewed templates and decisions, not raw paths, queries, bodies,
headers, bearer tokens, filenames, artifact contents, or context handles.
Audit failure blocks a request before credential/network I/O when preparation fails,
and withholds a result or receipt when append fails.
An identity change still revokes the context if its audit append also fails.

Authenticated acceptance belongs in a separately approved non-production environment.
