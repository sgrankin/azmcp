# Azure code mode

This document describes the implemented Go server.
The executable contract is the tool catalog, reviewed route fixtures, and regression tests.

## Execution model

The MCP front end owns policy, credentials, HTTP, audit, context references, and artifacts.
Each context has one separate QuickJS worker process.
The worker receives authorized JSON results over bounded tagged NDJSON pipes.
It receives no tokens, Azure profile, or general filesystem or network API.

The runtime uses pinned `modernc.org/quickjs` and builds with `CGO_ENABLED=0`.
JavaScript host calls are synchronous:

```js
const response = az.graph({
  cloud: "AzureCloud",
  query: "Resources | project id, type | take 10"
});
response.body
```

A call blocks while its parent performs the operation and returns an ordinary value.
Turns execute serially within a context.
Different contexts can execute independently.
Persistent lexical bindings survive successful turns and ordinary JavaScript exceptions.
Returning a promise or thenable, or executing queued promise jobs, evicts the context.
The private worker reports `async_not_supported`; MCP returns `invalid_request`.
There is no source transformation or implicit resolution on property access.

The worker captures its bootstrap intrinsics and host bridge privately.
The public surface consists of `console`, `az.request`, `az.graph`,
`az.metrics.single`, `az.metrics.batch`, `az.logs.query`, `az.ref`, `az.peek`,
and the three managed artifact writers.
Host authorization checks context grants even when a helper is present on `az`.
Values are serialized with JavaScript `JSON.stringify` semantics, including `toJSON`.

QuickJS and process isolation bound ordinary model-generated code.
They do not provide an OS sandbox against a native engine exploit or a hostile same-user process.

## MCP lifecycle

The server exposes six tools:

| Tool | Purpose |
| --- | --- |
| `azure_accounts` | Read cached account candidates without invoking the CLI |
| `azure_context_open` | Resolve and validate immutable cloud bindings, then start a worker |
| `azure_run` | Execute one synchronous JavaScript turn |
| `azure_context_close` | Cancel work, stop the worker, and dispose the context |
| `azure_schema_search` | Search offline schema metadata within context grants |
| `azure_schema_get` | Retrieve a reviewed executable entry and helper input schema |

The first message selects the connection lifecycle.
`initialize` and a pre-initialization `ping` without protocol-version metadata select the session lifecycle.
Other first requests select the stateless lifecycle.
A notification as the first message selects the session lifecycle and fails its initialize handshake.
An unsupported or malformed session initialize also terminates that handshake.

| Protocol revision | Lifecycle |
| --- | --- |
| `2025-06-18` | `initialize` and `notifications/initialized` |
| `2025-11-25` | `initialize` and `notifications/initialized` |
| `2026-07-28` | `server/discover` and metadata on every request |

Stateless requests carry both
`io.modelcontextprotocol/protocolVersion` and
`io.modelcontextprotocol/clientCapabilities` in `_meta`.
Inline supported revisions choose the wire envelope for that request.
Unknown revisions fail explicitly.
Modern results include server information and the appropriate result/caching metadata.
Session results omit modern caching fields.
Tool results provide structured content and its JSON text mirror.
JSON-RPC batches and unreviewed protocol revisions are unsupported.
Cancellation notifications match decoded JSON-RPC IDs and cancel active tool calls.

## Context data

A context fixes:

- User identity and the `inspect` ARM tier.
- Primary subscription/tenant bindings for each enabled cloud.
- An immutable subscription/tenant allowlist, including each primary pair.
- Resource Graph scopes and explicitly granted Metrics or Logs data planes.
- Optional `artifacts.write` local capability.
- Reviewed policy version/hash and pinned credential identities.

Configuration and tool argument schemas are closed.
Unsupported identities, tiers, grants, scopes, clouds, and input fields fail.
Cloud names are exactly `AzureCloud` and `AzureUSGovernment`.
A cloud is explicit on every Azure helper call.

Bindings resolve in order: caller override, configured binding, then cached account candidates.
An omitted tenant resolves only from exactly one matching cached candidate.
Auto-binding requires exactly one candidate for a cloud.
Duplicate or ambiguous candidates fail; the mutable CLI default subscription is never consulted.
Every allowed pair is live-validated before a context is retained.
Failed or cancelled context creation stops its worker and releases its reserved capacity.

The registry retains at most 32 contexts.
Opaque context IDs are random 256-bit handles encoded as canonical base64url.
Only one operation leases a context at a time; concurrent use returns `context_busy`.
Idle expiry is 30 minutes and absolute expiry is 24 hours.
Close, expiry, cancellation, fatal worker errors, and identity changes cancel associated work.
Published artifacts survive context disposal.

## Azure boundary

The credential broker invokes a bounded, explicitly selected Azure CLI executable.
It uses the configured profile directory without logging in or changing CLI configuration.
The first token request probes the supported CLI version.
Subprocess stdout/stderr is bounded and never forwarded into tool errors or audit.

Token requests specify cloud, tenant, subscription, and exact audience.
Credential results validate returned subscription/tenant and JWT identity claims.
Cache keys include the context identity scope, cloud, tenant, subscription, and audience.
Identity pins are checked for each cloud/tenant/audience.
A changed principal or client identity fails authentication and disposes the context.
Closing a broker prevents further acquisition and cache repopulation.

Each outbound request must:

1. Resolve its subscription through the immutable context allowlist.
2. Match a reviewed method, decoded path selector, API version, and query allowlist.
3. Satisfy the operation's ARM/data-plane grant and scope.
4. Prepare the durable audit sink before acquiring credentials or opening a socket.
5. Use the exact cloud origin and audience, without redirects or environment proxies.
6. Apply timeout, body, response, retry, and paging bounds.
7. Append a content-free audit decision before releasing the result.

Unknown routes and ambiguous selectors fail closed.
Reviewed reads retry HTTP 429 and 5xx responses within bounded attempts and elapsed time.
Paging reauthorizes each target and rejects changed origins or unsupported selectors.
The JavaScript API does not advertise a general list/paging iterator.

## Helpers and discovery

`az.request` accepts the reviewed GET routes with no caller headers or body.
`az.graph` owns its Resource Graph POST body and rejects the entire call if any
explicit subscription falls outside the restricted context scope.
The context can instead explicitly select `allAccessible`.
ARM, Graph, and Metrics helpers return `{status, headers, body}`.

Metrics single uses a reviewed ARM route.
Metrics batch uses a reviewed regional data-plane endpoint, requires an explicit region,
and accepts at most 50 same-type resources and 20 metric names.
Each resource subscription must be allowed by the context.

Logs Query requires `logs.query` and a per-cloud `allAccessible` Logs scope.
A workspace ID is the Log Analytics GUID, not a resource name or ARM ID.
This scope is deliberately explicit because KQL can reference other workspaces or stored functions.
The helper validates and returns the tables result directly.
It does not rewrite KQL or infer a narrower workspace boundary.

The embedded runtime manifest contains 18 routes and 12 discoverable entries.
Schema discovery is offline and restricted by the same context capabilities as execution.
Helper arguments and host-owned HTTP body schemas are distinct.
Response schemas remain `metadataOnly` without reviewed response fixtures.
Graph and internal validation rows are excluded from schema discovery.

Route generation combines an immutable seed, a content-pinned normalized OpenAPI catalog,
and independently pinned RBAC review evidence.
Canonicalization and policy identity are deterministic.
Generation rejects overlapping route selectors, missing review joins, incorrect hashes,
and output aliases that would overwrite the immutable seed.

## Output and references

| Limit | Bound |
| --- | --- |
| JavaScript code | 256 KiB |
| Turn duration | 60 seconds by default; at most one hour |
| QuickJS allocations | 64 MiB |
| Parent-observed worker RSS | 256 MiB, sampled every 50 ms |
| Host calls per turn | 256, executed in order |
| Worker input/output frames | 512 KiB / 1 MiB |
| Inline serialized value | 64 KiB |
| Reference candidate | 480 KiB |
| Console | 256 entries / 64 KiB |
| Complete MCP tool result | 1 MiB |

An allocation error caught by JavaScript may leave its context usable.
The process RSS ceiling separately bounds memory outside QuickJS allocations.
Timeouts and unsupported async work dispose the worker.

Larger serializable results become immutable context-owned references.
References last up to five minutes and are bounded to 32 entries and 4 MiB per context.
Capacity pressure evicts the oldest references sooner.
`az.ref(refId)` rehydrates a reference; `az.peek(value)` gives bounded structural metadata.
Previews expose keys, lengths, and counts without value samples.
Size failures include structural diagnostics.
Cycles and BigInt produce generic `invalid_request` errors; top-level undefined and functions become null.
No response truncates a JSON value into a plausible partial result.

## Managed artifacts

A context must explicitly grant `artifacts.write`.
`writeJson` accepts one value up to 480 KiB.
`writeJsonArray` and `writeJsonLines` consume synchronous iterables in acknowledged bounded chunks.
Compression is optional LZ4 framing with a content checksum.
A streamed file is bounded to 64 MiB logical and 65 MiB stored bytes.
Context quotas are 32 files / 128 MiB; root quotas are 256 files / 512 MiB.

Names are conservative ASCII filenames with the required JSON and optional LZ4 suffix.
Writes are create-only within an opaque random context namespace.
Directories use mode `0700` and files mode `0600`.
The implementation verifies held directory/file identities, refuses symlinks and traversal,
and requires an absolute canonical root on macOS or Linux.
Startup, namespace allocation, and write-free turns create no artifact files or directories.

The first write acquires the private root lock.
The lock remains held while a turn has staged streams or publication rollback tickets.
Commit publishes files; final acceptance revalidates ownership, size, and hash before releasing tickets.
Failed, cancelled, closed, or expired turns roll back their own exact staged/published files.
A caught audit failure discards the corresponding stage before returning the error.
Receipt fields describe stored bytes/hash, logical bytes, encoding, media type, and `customerData` sensitivity.

The last finalized commit, abort, discard, or rollback releases the root lock.
Several idle servers can therefore share the configured root.
A competing active writer fails with a bounded error instead of waiting indefinitely.
Durable artifacts survive context close and server restart.
Abrupt host failure can leave a published orphan if its receipt was lost.
Stale unpublished stages are removed on the next locked transaction.
Artifact reading, listing, deletion, and arbitrary filesystem access are not MCP capabilities.

## Audit and verification

The append-only JSONL sink is private, bounded, rotated, and synced.
Records contain reviewed templates and structured decisions, not raw paths, queries,
source code, console text, bodies, headers, tokens, filenames, or artifact contents.
Audit failure prevents release of an upstream result or artifact receipt.

Tests inject synthetic profiles, absolute fake CLI executables, and literal loopback HTTP simulators.
A test must prove those injections before spawning a credential process or opening a socket.
Ambient Azure state and production endpoints are outside development scope.
Authenticated acceptance requires a separate environment and explicit approval.

See [README.md](README.md) for configuration and build commands,
and [benchmarks/worker](benchmarks/worker/README.md) for the reproducible worker measurements.
