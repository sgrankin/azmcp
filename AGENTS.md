# Repository instructions

## Production Azure safety

The host machine's Azure CLI session is authenticated to a real production environment.
Treat all ambient Azure state and credentials as out of scope for development and tests.

- Do not read `~/.azure` or any default Azure CLI profile or token-cache path.
- Do not invoke the real `az` executable for account discovery, token acquisition, login,
  resource reads, or mutations. `az version` is the only harmless exception.
- Do not send requests to Azure or Entra endpoints.
- Tests must use temporary synthetic profile directories, an explicitly injected fake `az`
  executable, and loopback HTTP simulators.
- A test that cannot prove it is using those injected fakes must fail before spawning a
  process or opening a socket.
- Authenticated integration requires a separate environment and explicit user approval.

## Workflow

- This repository uses JJ. Never run Git commands here.
- Support the reviewed MCP revisions through shared lifecycle detection and version-specific
  wire results. Add revisions only with protocol regression coverage.
- Do not advertise tools, input values, or capabilities that are not implemented.
