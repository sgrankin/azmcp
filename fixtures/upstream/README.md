# Offline upstream import fixtures

These files define the import contract and review join used by
`azmcp-routegen --seed base.json --upstream ... --review ... --manifest output.json`.

The v1 files are deliberately synthetic contract data.  They are not a claim
that the checked-in operation rows were fetched from Azure's REST repository,
and they are not loaded by the running MCP server.  `sourceSha256` is therefore
a synthetic sentinel, while `catalogSha256` and `reviewSha256` are real hashes
of their respective canonical inputs with the self-referential field cleared.

Before any generated rows are enabled in runtime discovery, replace the source
fixture with an exact upstream file revision and raw file SHA-256, add a
separately pinned provider-operations export for RBAC actions, and review the
resulting route/schema manifest.  The importer will continue to require both
source hashes and the review content hash to match at every generation.
