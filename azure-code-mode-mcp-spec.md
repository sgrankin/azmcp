# Azure inspection MCP design

The server exposes typed Azure operations.
Client runtimes can compose them using programmatic tool calling or ordinary MCP requests.
The tool catalog and tests define the executable contract; [README.md](README.md) describes inputs.

## Authorization contexts

A context is an immutable authorization scope with a random 256-bit handle.
It fixes user identity, inspect tier, cloud bindings, subscription/tenant allowlist,
Graph and Logs scopes, optional local export grant, and reviewed policy identity.
Credential identity pins survive across calls in that context.
Bindings resolve from caller overrides, configured bindings, or an unambiguous synthetic/cached profile.
Every allowed pair is validated before context retention.

The registry holds at most 32 contexts, expiring after 30 minutes idle or 24 hours absolute.
Up to eight calls can lease one context concurrently.
Saturation returns retryable `context_busy`.
Request cancellation returns `request_cancelled` and leaves the authorization context usable.
Close, expiry, and identity mismatch cancel all calls and revoke the handle.
Context revocation and export receipt acceptance linearize under the registry lock.

## Operations

The catalog contains accounts, context open/close, schema search/get,
request, Graph, Metrics single/batch, Logs Query, and export: eleven tools.
All five Azure operations have closed typed inputs with contextId and explicit cloud.
Their existing Go host validation selects approved routes, subscriptions, scopes and audiences.
Unknown operations, fields, grants and ambiguous selectors fail before signing.

Each operation creates its own host with shared immutable context options and identity pin.
HTTP and CLI work honor request cancellation and absolute context expiry.
Call metadata and redacted durable audit use the public operation names.
Ordinary results contain value/calls/callsOmitted/sensitivity/correlationId.
No credentials reach the client.

Client program control flow is outside the server.
Every returned ordinary tool value crosses MCP before client filtering.
Use query-side projection/aggregation or an export to keep large data local.
There is no server JavaScript evaluator, worker process protocol, or retained script/reference state.

## Managed exports

`azure_export` requires artifacts.write and selects one of the five ordinary Azure operations.
Its arguments use the same closed shape without contextId.
The host admits at most 8 MiB of upstream body instead of the ordinary 1 MiB ceiling.
That per-host limit never mutates the shared HTTP client.

The full helper JSON value is written with one trailing newline, optionally compressed with
checksummed LZ4, into a private create-only .json/.json.lz4 file.
The tool returns receipt/calls/callsOmitted/sensitivity/correlationId.
Receipt size/hash describe stored bytes; logicalBytes describe decoded JSON.

Namespace allocation and root creation stay lazy.
A root lock covers active staged files and publication tickets, with root-wide quotas.
Commit publishes; Finalize revalidates held identities, permissions, size and hash before acceptance.
Failure, request cancellation, or context revocation before acceptance rolls back exact ownership.
An audit append failure withholds the receipt and rolls back that export.
Each export is its own transaction, independent of later client-program outcomes.

The store keeps the existing root marker, namespace and temporary-file formats.
Historical JSON/JSON Lines and LZ4 files continue counting against quotas.
New exports produce conventional JSON only.
Published files survive context/server lifetime; abrupt termination may leave a committed orphan.
Private filesystem identities require macOS or Linux.
The boundary does not isolate hostile processes running as the same OS user.

## Limits

| Boundary | Limit |
| --- | --- |
| Retained authorization contexts | 32 |
| Concurrent calls per context | 8 |
| Ordinary/export upstream body | 1 MiB / 8 MiB |
| Complete MCP tool result, including JSON text mirror | 1 MiB |
| Export store logical/stored JSON | 64 MiB / 65 MiB |
| Context export quota | 32 files / 128 MiB |
| Root export quota | 256 files / 512 MiB |
| Metrics batch resources / names | 50 in one allowed subscription / 20 |
| Logs total rows, including exports | 50,000 |

Response overflow fails without truncation.
MCP serialization overflow supplies structural diagnostics without value samples;
HTTP body overflow returns a size error without a decoded preview.
The ordinary-result transport ceiling is independent of HTTP admission.

## Protocol and discovery

The server retains the three reviewed MCP revisions and their version-specific envelopes.
Initialize-based revisions are 2025-06-18 and 2025-11-25;
2026-07-28 uses stateless discovery and typed per-request metadata.
First-message lifecycle detection, decoded request-ID cancellation, strict Unicode/duplicate JSON,
and cancellation of idle input/blocked output remain regression-tested.
The server implementation version is 0.2.0.

Offline discovery maps reviewed request/metrics/logs entries to MCP tool names and adds contextId.
Schema documents are deep-copied before adaptation.
Policy hash and embedded reviewed fixture bytes remain unchanged.
Graph and internal rows are not added without reviewed metadata.

## Credential, audit and test boundary

Explicit cloud names choose exact origins, subprocess cloud, tenant/subscription and token audience.
The broker validates returned identity and pins principal/client per cloud/tenant/audience.
An identity mismatch remains fatal even when its durable audit append fails.
The server never logs in or mutates CLI cloud/configuration.

Audit preparation precedes credentials and sockets; append precedes result/receipt release.
Records contain reviewed templates and metadata, never raw content or bearer credentials.
CLI output, HTTP request/response sizes, retry attempts, backoffs and elapsed time remain bounded.
Redirects and environment proxies remain disabled.

Tests inject temporary synthetic profiles, absolute fake CLI executables and literal loopback HTTP.
Ambient production Azure profiles, token caches, CLI invocation and Azure/Entra traffic are excluded.
Authenticated acceptance requires a separately approved non-production environment.
