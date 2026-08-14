# Offline upstream import fixtures

These files define the import contract and review join used by
`azmcp-routegen --upstream ... --review ...`.

The v1 files are deliberately synthetic contract data.  They are not a claim
that the checked-in operation rows were fetched from Azure's REST repository,
and they are not loaded by the running MCP server.  `sourceSha256` is therefore
a synthetic sentinel, while `catalogSha256` is a real hash of the canonical
export content with that field cleared.

Before any generated rows are enabled in runtime discovery, replace the source
fixture with an exact upstream file revision and raw file SHA-256, add a
separately pinned provider-operations export for RBAC actions, and review the
resulting route/schema manifest.  The importer will continue to require both
hashes to match between the export and review join.
