# azmcp implementation journal

## Current plan

1. Broaden `az.request` from pinned Azure specifications and provider-operation data.
2. Add bounded paging and large-result references; keep existing result caps and retries.
3. Preserve the synthetic-only local test boundary and run the complete modern MCP gate.
4. Run authenticated Commercial/Government acceptance only in a separately authorized
   non-production environment.

## Verified facts

- The repository uses JJ. The reviewed spec is change `osxsoxzm`.
- Codex CLI `0.147.0` contains modern discovery and MRTR support behind
  `mcp_2026_07_28`; modern stdio selection also requires the Codex-only
  `CODEX_MCP_PROTOCOL_VERSION=2026-07-28` server configuration marker.
- Local Rust is `1.97.1`; Azure CLI is `2.89.0`.
- The built server completes interleaved `server/discover`, deterministic `tools/list`, and
  `azure_accounts` requests over real stdio using a synthetic temporary home, the standard
  config/profile/state paths, and an explicitly injected fake Azure executable.
- The core test suite uses only synthetic profiles, fake executables, and loopback HTTP.
  The current workspace gate is 149 tests plus formatting and warning-free clippy.
- The six modern tools are now the exact advertised catalog. A modern-protocol lifecycle test
  covers accounts, context open, persistent run, close, and structured domain failure.
- `azure_schema_search` and `azure_schema_get` are implemented as context-scoped,
  offline tools tied to the executable reviewed route policy. The bootstrap catalog
  exposes exact route metadata only; it does not invent request or response schemas.
- The schema checkpoint is change `vxkvytws`. Its isolated and integrated test gate is
  118 tests plus formatting and warning-free clippy.
- The metrics checkpoint is change `uvwwumps`. It exposes explicit single-resource and
  same-type regional batch helpers for Commercial and Government clouds, resolves every
  resource subscription through the immutable context allowlist, and is loopback-tested.
- The Logs Query checkpoint is change `wqrmmlyt`. It exposes direct Commercial and
  Government workspace queries with exact data-plane audiences, explicit context grants,
  bounded table responses, and redacted audit records. The integrated observability gate is
  133 tests plus formatting and warning-free clippy.
- The retry checkpoint is change `qwpoksmw`. It retries only reviewed read routes on
  HTTP 429 and 5xx responses, with hard attempt, elapsed-time, and backoff ceilings.
  Retry counts are preserved in both helper and context-validation audit records.
- The reviewed-manifest checkpoint is change `wxtpqzxx`. The checked-in canonical
  fixture is now the runtime source for all 16 executable routes and all 10 discoverable
  Commercial/Government request, metrics, and Logs Query entries. The checker rejects
  malformed, stale, unjoined, purpose-confused, referenced, or non-canonical schemas.
- One current-thread V8 worker process is retained per context. Subprocess tests cover
  persistence, hard close and MCP cancellation, abort poisoning, timeout poisoning, heap/RSS
  pressure, TTL disposal, and an eight-call concurrency bound under `Promise.all`.
- Modern cancellation is fail-closed for both context creation and execution. A cancelled
  context-open future rolls back registry authority, while a cancelled run terminates and
  evicts its retained worker.
- The parent samples each worker's OS RSS every 50 ms through `sysinfo` and hard-kills it
  above the 256 MiB ceiling. Recent synthetic local workers measured roughly 28–32 MiB RSS
  after startup and roughly 67–80 MiB under heap pressure on macOS arm64; these are diagnostic
  samples rather than a portability guarantee. A deterministic subprocess regression uses a
  one-byte test ceiling and observes the typed `RssLimit` failure without any Azure process
  or endpoint.
- `az.request` and `az.graph` cross closed semantic schemas, immutable per-cloud binding and
  graph-scope checks, reviewed route policy, exact-origin HTTP, bounded returned call records,
  and a rotated user-only JSONL request log.
- Credential acquisition parses ARM JWT `tid`, `oid`, and `appid`/`azp` claims. It pins the
  principal/client from live validation across subscriptions and later refreshes in one
  context-owned pin; a mismatch fails authentication and evicts only that context.
- Identity-change failures preserve sanitized cloud/tenant login guidance instead of degrading
  to a generic account-discovery error.
- Broker token-cache entries are scoped to that context pin, so opening a new context after
  `az login` cannot silently inherit another context's cached principal.
- Startup probes only the configured executable's bounded `az version` JSON and requires
  Azure CLI 2.89.0 or newer. It does not inspect account state or acquire a token.
- Oversized results return a deterministic shape-only summary and JavaScript reduction
  guidance. No truncated JSON or sample value crosses the MCP boundary.
- Codex CLI `0.147.0` completed an actual modern-mode `azure_accounts` tool call against the
  local binary and returned the synthetic subscription. Codex labels the feature under
  development. The final smoke used a version-aware fake Azure executable and proved that no
  credential command or audit request was made.
- An independent adversarial review identified sensitivity, close cancellation, heap-limit,
  RSS, MCP/abort cancellation, TTL disposal, provenance, account-schema, per-context identity,
  request-header, oversized-result, and audit gaps; each checkpoint blocker was fixed and
  regression-tested.

## Decisions

- v0 is modern-only. Legacy MCP is deferred until a concrete host requirement justifies a
  second lifecycle.
- Schema discovery covers `az.request`, `az.metrics.single`, `az.metrics.batch`, and
  `az.logs.query` under their exact execution surfaces. It leases the caller's context
  without starting a worker, acquiring a credential, or making an HTTP request. Search
  results report non-executable rows when the context tier, data-plane grant, or scope is
  insufficient.
- The first metrics surface will expose explicit `az.metrics.single` and
  `az.metrics.batch` helpers. Batch requires an explicit reviewed region, groups at most
  50 resources from one subscription/region/resource type, and uses the regional Monitor
  audience rather than ARM.
- The first Logs Query surface uses only `POST /v1/workspaces/{workspaceId}/query` and a
  `logs.query` context grant. Its initial scope is deliberately `allAccessible`: an
  apparent workspace allowlist would be porous through KQL cross-workspace references and
  stored functions.
- A normal installation needs no azmcp-specific environment variables. Codex's stdio protocol
  marker remains in the client registration, but Codex consumes it before launching azmcp.
- This machine's Azure CLI session targets real production. Development and validation
  must not inspect accounts, acquire tokens, or call Azure endpoints. Use only synthetic
  profile fixtures, fake `az` executables, and loopback Azure simulators.
- Production startup parses azmcp config, resolves paths, and performs only the non-authenticating
  Azure CLI version probe. Azure profile reads, token acquisition, and network calls remain lazy
  tool actions.
- Context IDs redact both `Debug` and `Display`; only the explicit accessor emits the bearer.
- Context graph scope and normalized subscription allowlist are fixed at open. `allAccessible`
  widens only Resource Graph and never `az.request`.
- `rmcp` is pinned to `3.0.1`; the Rust toolchain is pinned to `1.97.1`.
- Credential acquisition accepts only typed reviewed clouds and manifest-derived ARM
  audiences. Route rows are cloud-specific and query parameters default-deny.
- The credential child environment is cleared and selectively rebuilt. Token output is
  bounded and zeroized; the cache is bounded and rejects stale or malformed expiry and JWT
  identity claims.
- Every run is conservatively labeled `customerData`; arbitrary JavaScript output is never
  claimed public merely because no known secret helper ran.
- An unavailable durable audit destination fails before credential acquisition or network I/O.
  Audit rows contain reviewed path templates, never raw paths, queries, bodies, handles, or
  token material.

## Open risks

- The reviewed route bundle intentionally exposes only subscription validation, provider
  metadata, and Resource Graph until real ARM scenario rows have golden tests.
- Portable process-tree termination for timed-out credential subprocess descendants remains
  unresolved; the direct child is killed and pipe readers are bounded/aborted.
- Generic paging, exact-origin continuation handling, large-result references, and automatic
  first-real-scenario ARM route generation from pinned upstream sources are not implemented.
- Helper argument and request-body schemas are checked in and closed, while response bodies
  remain `metadataOnly`. Generic `az.request` still exposes only the Commercial/Government
  subscription and provider metadata routes; the current `azmcp-routegen` canonicalizes and
  validates the reviewed fixture but does not yet ingest the Azure REST specification corpus.
- The RSS implementation currently targets macOS and Linux through `sysinfo`; other targets
  must add an equivalent OS process sampler before relying on the documented ceiling.
- The local Codex repository contains a pinned official MCP client-conformance driver, not an
  official server-conformance gate for azmcp. The server gate remains unrun.
- Authenticated two-cloud acceptance is explicitly deferred on this machine because its Azure
  login is production. No ambient Azure profile, token, or endpoint was touched.
