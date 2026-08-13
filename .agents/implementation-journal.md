# azmcp implementation journal

## Current plan

1. Build and test the modern MCP `2026-07-28` stdio shell.
2. Add cloud/config/account discovery and a fake-tested Azure CLI broker.
3. Add reviewed route policy, target canonicalization, and the HTTP signing boundary.
4. Add one V8 worker per explicit context and wire the four v0 tools.
5. Run conformance, Codex-host, authenticated multi-cloud, and adversarial validation.

## Verified facts

- The repository uses JJ. The reviewed spec is change `osxsoxzm`.
- Codex CLI `0.147.0` contains modern discovery and MRTR support behind
  `mcp_2026_07_28`; modern stdio selection also requires the Codex-only
  `CODEX_MCP_PROTOCOL_VERSION=2026-07-28` server configuration marker.
- Local Rust is `1.97.1`; Azure CLI is `2.89.0`.
- The modern protocol shell completes `server/discover`, deterministic `tools/list`, and a
  structured tool call over the built stdio binary.
- The core test suite uses only synthetic profiles, fake executables, and loopback HTTP.
  The current workspace gate is 52 tests plus warning-free clippy.

## Decisions

- v0 is modern-only. Legacy MCP is deferred until a concrete host requirement justifies a
  second lifecycle.
- This machine's Azure CLI session targets real production. Development and validation
  must not inspect accounts, acquire tokens, or call Azure endpoints. Use only synthetic
  profile fixtures, fake `az` executables, and loopback Azure simulators.
- The first implementation change contains the protocol shell, closed cloud/config/account
  types, a fake-tested credential broker, opaque context lifecycle, route/target policy, and
  a loopback-tested HTTP signing boundary. V8 and real Azure operations come later.
- `rmcp` is pinned to `3.0.1`; the Rust toolchain is pinned to `1.97.1`.
- Credential acquisition accepts only typed reviewed clouds and manifest-derived ARM
  audiences. Route rows are cloud-specific and query parameters default-deny.
- The credential child environment is cleared and selectively rebuilt. Token output is
  bounded and zeroized; the cache is bounded and rejects stale or malformed expiry.

## Open risks

- The protocol status tool is an implementation-order probe, not part of the eventual v0
  four-tool surface. Replace it only as real handlers land.
- The first route bundle and worker memory budget remain unresolved implementation gates.
- Portable process-tree termination for timed-out credential subprocess descendants remains
  unresolved; the direct child is killed and pipe readers are bounded/aborted.
- A closed context invalidates registry access immediately, but the future worker layer must
  connect close and eviction to process termination.
