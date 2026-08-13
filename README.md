# azmcp

`azmcp` is a modern, stateless MCP `2026-07-28` server for bounded Azure
inspection from persistent JavaScript contexts.

The MCP transport has no session lifecycle. Application state is explicit: a
caller opens an opaque context, runs one serialized JavaScript turn at a time,
and closes the context. Each context fixes its identity, cloud bindings,
subscription allowlist, Resource Graph scope, inspect-only capability, policy
bundle, and isolated V8 worker.

v0 is deliberately small. It exposes:

- `azure_accounts`
- `azure_context_open`
- `azure_run`
- `azure_context_close`

Inside `azure_run`, JavaScript has only `console`, `az.request`, and `az.graph`.
There is no `fetch`, `Deno`, token access, ambient cloud, or ambient
subscription. The v0 `az.request` surface accepts no caller headers or body;
the reviewed route bundle currently contains subscription
validation, provider metadata, and Resource Graph for Azure commercial and US
Government clouds.

## Build and test

The workspace pins Rust 1.97.1 and `rmcp` 3.0.1.

```sh
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release
```

Tests use synthetic Azure profiles, fake `az` executables, and loopback HTTP
servers. They must not use an ambient Azure login.

## Configuration

The default azmcp configuration path is
`$XDG_CONFIG_HOME/azmcp/config.toml`, or
`$HOME/.config/azmcp/config.toml` when `XDG_CONFIG_HOME` is unset.
`AZMCP_CONFIG` selects an explicit file.

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
```

An omitted primary tenant is resolved only when the cached Azure profile has
exactly one matching tenant candidate. With no configured or caller-supplied
bindings, auto-binding succeeds only for a cloud with exactly one candidate;
ambiguity fails closed.

Profile discovery uses `AZMCP_AZURE_PROFILE`, then
`$AZURE_CONFIG_DIR/azureProfile.json`, then
`$HOME/.azure/azureProfile.json`. The credential subprocess is selected with
`AZMCP_AZ_EXECUTABLE`, defaulting to `az`. Startup runs only the bounded,
non-authenticating `az version --output json --only-show-errors` probe and
requires Azure CLI 2.89.0 or newer. The server never performs login or changes
Azure CLI configuration.

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
AZMCP_CONFIG = "/absolute/path/to/azmcp.toml"
AZMCP_AZURE_PROFILE = "/absolute/path/to/azureProfile.json"
AZMCP_AUDIT_LOG = "/absolute/path/to/azmcp-requests.jsonl"
```

The feature can instead be enabled for one invocation with
`codex --enable mcp_2026_07_28`. Codex consumes
`CODEX_MCP_PROTOCOL_VERSION` before it launches the child; `azmcp` neither
expects nor receives that variable. Legacy `initialize` is intentionally not
implemented.

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
Serialized results are capped at 64 KiB; oversized values return a shape-only
summary and reduction guidance, never truncated JSON. At most eight host calls
run concurrently. Cancellation, timeout, heap pressure, RSS pressure, worker
death, close, TTL expiry, or credential-identity change dispose the affected
context. The RSS sampler uses OS process APIs through `sysinfo`; it does not
invoke `ps` or another shell command.

Do not point development tests at a real Azure profile, credential cache, or
subscription. Authenticated acceptance testing belongs in a separately
authorized non-production environment.
