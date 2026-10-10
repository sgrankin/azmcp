// Package reviewed contains the checked-in policy and provenance fixtures.
package reviewed

import "embed"

//go:embed reviewed-routes/*.json upstream/*
var Files embed.FS

//go:embed reviewed-routes/v1-observability-1.json
var Manifest []byte

//go:embed reviewed-routes/v1-observability-seed-v2.json
var SeedManifest []byte
