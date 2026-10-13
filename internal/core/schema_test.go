package core

import (
	"bytes"
	"strings"
	"testing"

	reviewed "azmcp/fixtures"
)

func TestSchemaDiscoveryDescribesTypedInputsWithoutChangingReviewedDocuments(t *testing.T) {
	manifest, err := ParseManifest(reviewed.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	policy, _, err := LoadReviewed()
	if err != nil {
		t.Fatal(err)
	}
	index, err := NewSchemaIndex(policy, manifest.Schemas)
	if err != nil {
		t.Fatal(err)
	}
	commercial, err := (Binding{Subscription: sub, Tenant: tenant}).Resolve(Commercial, nil)
	if err != nil {
		t.Fatal(err)
	}
	government, err := (Binding{Subscription: extra, Tenant: tenant}).Resolve(Government, nil)
	if err != nil {
		t.Fatal(err)
	}
	context := DefaultOptions([]ResolvedBinding{commercial, government})
	context.PolicyHash, context.PolicyVersion = policy.Hash, policy.Version
	tools := map[string]string{"request": "azure_request", "metricsSingle": "azure_metrics_single", "metricsBatch": "azure_metrics_batch", "logsQuery": "azure_logs_query"}
	for _, source := range manifest.Schemas {
		details, err := index.Get(context, source.EntryID, source.APIVersions[0])
		if err != nil {
			t.Fatal(err)
		}
		if details.ExecutionSurface != tools[source.Purpose] {
			t.Fatalf("wrong execution tool for %s: %s", source.EntryID, details.ExecutionSurface)
		}
		arguments := details.ArgumentSchema.(map[string]any)
		properties := arguments["properties"].(map[string]any)
		contextID := properties["contextId"].(map[string]any)
		if contextID["type"] != "string" || contextID["pattern"] != "^[A-Za-z0-9_-]{43}$" || arguments["additionalProperties"] != false {
			t.Fatal("schema omitted the closed context input", arguments)
		}
		required := arguments["required"].([]any)
		if len(required) == 0 || required[0] != "contextId" {
			t.Fatal("context ID is not required", arguments)
		}
		if raw := string(mustJSON(t, arguments)); strings.Contains(raw, "az.request") || strings.Contains(raw, "az.metrics") || strings.Contains(raw, "az.logs") {
			t.Fatal("schema advertises a removed execution surface", raw)
		}
		// A caller may retain and change discovery documents without changing policy inputs.
		properties["cloud"].(map[string]any)["enum"].([]any)[0] = "unreviewed"
		contextID["pattern"] = ".*"
		if body, ok := details.RequestBodySchema.(map[string]any); ok {
			body["type"] = "unreviewed"
		}
		again, err := index.Get(context, source.EntryID, source.APIVersions[0])
		if err != nil {
			t.Fatal(err)
		}
		fresh := again.ArgumentSchema.(map[string]any)["properties"].(map[string]any)
		if fresh["cloud"].(map[string]any)["enum"].([]any)[0] != string(source.Cloud) || fresh["contextId"].(map[string]any)["pattern"] != "^[A-Za-z0-9_-]{43}$" {
			t.Fatal("discovery documents share mutable storage")
		}
	}
	canonical, err := CanonicalManifest(manifest)
	if err != nil || !bytes.Equal(canonical, reviewed.Manifest) || manifest.PolicyHash != PolicyHash {
		t.Fatal("public schema adaptation changed the reviewed manifest", err)
	}
	results, err := index.Search(context, "azure_metrics_single", nil, 50)
	if err != nil || len(results.Results) == 0 {
		t.Fatal("new MCP tool name is not searchable", err)
	}
	for _, result := range results.Results {
		if !strings.HasPrefix(result.ExecutionSurface, "azure_") {
			t.Fatal("search advertises removed script surface", result)
		}
	}
}
