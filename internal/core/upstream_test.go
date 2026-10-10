package core

import (
	"bytes"
	"strings"
	"testing"

	reviewed "azmcp/fixtures"
)

func fixture(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := reviewed.Files.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestPinnedRealUpstreamReproducesExactRuntimeFixture(t *testing.T) {
	seed, err := ParseManifestForGeneration(reviewed.SeedManifest)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := ParseCatalog(fixture(t, "upstream/azure-rest-storage-2023-05-01.json"))
	if err != nil {
		t.Fatal(err)
	}
	review, err := ParseReview(fixture(t, "upstream/azure-rest-storage-review-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	generated, err := GenerateManifest(seed, catalog, review)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalManifest(generated)
	if err != nil || !bytes.Equal(canonical, reviewed.Manifest) {
		t.Fatal("real upstream import differs from reviewed runtime bytes")
	}
	if generated.PolicyHash != PolicyHash {
		t.Fatalf("policy identity changed: %s", generated.PolicyHash)
	}
	catalog.Operations[0].APIVersions = []string{"2023-05-02"}
	_, err = GenerateManifest(seed, catalog, review)
	errorCode(t, err, "invalid_request")
}
func TestSyntheticImportOnlyIncludesExplicitReviewedGETs(t *testing.T) {
	seed, err := ParseManifestForGeneration(reviewed.SeedManifest)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := ParseCatalog(fixture(t, "upstream/azure-rest-operations-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	review, err := ParseReview(fixture(t, "upstream/azure-rest-review-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	generated, err := GenerateManifest(seed, catalog, review)
	if err != nil {
		t.Fatal(err)
	}
	if len(generated.Routes) != 18 || len(generated.Schemas) != 12 {
		t.Fatal("synthetic import counts disagree with review")
	}
	for _, schema := range generated.Schemas {
		if schema.Operation == "list" {
			t.Fatal("unreviewed list operation was imported")
		}
	}
	for _, mutation := range []string{"method", "body", "tier", "collision", "pin"} {
		c, r := catalog, review
		c.Operations = append([]CatalogOperation{}, catalog.Operations...)
		r.Operations = append([]ReviewOperation{}, review.Operations...)
		id := r.Operations[0].OperationID
		for i := range c.Operations {
			if c.Operations[i].OperationID == id {
				switch mutation {
				case "method":
					c.Operations[i].Method = "POST"
				case "body":
					c.Operations[i].RequestBodySchema = map[string]any{"type": "object"}
				}
			}
		}
		if mutation == "tier" {
			r.Operations[0].ArmTier = "read"
		}
		if mutation == "collision" {
			r.Operations[0].EntryID = seed.Schemas[0].EntryID
		}
		if mutation == "pin" {
			r.Upstream.SourceSHA256 = "sha256:" + strings.Repeat("0", 64)
		}
		c.Source.CatalogSHA256, _ = catalogHash(c)
		r.Upstream.CatalogSHA256 = c.Source.CatalogSHA256
		r.ReviewSHA256, _ = reviewHash(r)
		_, err = GenerateManifest(seed, c, r)
		errorCode(t, err, "invalid_request")
	}
}
func TestClosedJSONRejectsDuplicatesAndCaseAliases(t *testing.T) {
	for _, replacement := range []string{`"formatVersion":1,"formatVersion":1`, `"FormatVersion":1`} {
		raw := bytes.Replace(reviewed.Manifest, []byte(`"formatVersion": 1`), []byte(replacement), 1)
		_, err := ParseManifest(raw)
		errorCode(t, err, "invalid_request")
	}
	_, err := ParseAzureProfile([]byte(`{"subscriptions":[],"subscriptions":[]}`))
	errorCode(t, err, "authentication_required")
}
