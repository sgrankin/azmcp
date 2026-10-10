package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	reviewed "azmcp/fixtures"
)

const sub = "11111111-1111-1111-1111-111111111111"
const tenant = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
const extra = "22222222-2222-2222-2222-222222222222"

func errorCode(t *testing.T, err error, want string) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Code != want {
		t.Fatalf("got %v, wanted %s", err, want)
	}
}
func options(t *testing.T) ContextOptions {
	t.Helper()
	binding, err := (Binding{Subscription: sub, Tenant: tenant, AllowedSubscriptions: []Pair{{extra, tenant}}}).Resolve(Commercial, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := DefaultOptions([]ResolvedBinding{binding})
	if err = result.Validate(); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestReviewedManifestHashCanonicalBytesAndJoin(t *testing.T) {
	policy, index, err := LoadReviewed()
	if err != nil {
		t.Fatal(err)
	}
	if policy.Hash != PolicyHash || policy.Version != PolicyVersion || len(policy.Routes) != 18 || len(index.entries) != 12 {
		t.Fatalf("reviewed identity/count mismatch: %#v", policy)
	}
	m, err := ParseManifest(reviewed.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalManifest(m)
	if err != nil || !bytes.Equal(canonical, reviewed.Manifest) {
		t.Fatal("Go canonical form disagrees with checked-in Rust fixture")
	}
	m.Routes[0].RBACAction = "malicious/read"
	_, err = LoadPolicy(mustJSON(t, m))
	errorCode(t, err, "invalid_request")
}
func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestConfigAndAccountAmbiguity(t *testing.T) {
	config, err := ParseConfig(`[clouds.AzureCloud]
subscription="11111111-1111-1111-1111-111111111111"
tenant="AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"
[[clouds.AzureCloud.allowed_subscriptions]]
subscription="22222222-2222-2222-2222-222222222222"
tenant="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
`)
	if err != nil {
		t.Fatal(err)
	}
	if config.Clouds[Commercial].Tenant != tenant {
		t.Fatal("config UUID was not normalized")
	}
	for _, input := range []string{`cloud="AzureCloud"`, `[clouds.AzureChinaCloud]`, "[artifacts]\nroot=\"relative\"", "[clouds.AzureCloud]\nsubscription=\"not-a-guid\""} {
		_, err = ParseConfig(input)
		errorCode(t, err, "invalid_request")
	}
	row := map[string]any{"id": sub, "name": "synthetic", "state": "Enabled", "tenantId": tenant, "environmentName": "AzureCloud", "user": map[string]any{"name": "alice", "type": "user"}, "isDefault": true}
	raw := append([]byte{0xef, 0xbb, 0xbf}, mustJSON(t, map[string]any{"subscriptions": []any{row, row}})...)
	index, err := ParseAzureProfile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Candidates) != 2 {
		t.Fatal("duplicate account evidence was overwritten")
	}
	_, err = index.Resolve(Commercial)
	errorCode(t, err, "account_ambiguous")
	_, err = (Binding{Subscription: sub}).Resolve(Commercial, index.Candidates)
	errorCode(t, err, "account_ambiguous")
	resolved, err := (Binding{Subscription: sub, Tenant: tenant}).Resolve(Commercial, index.Candidates)
	if err != nil || resolved.Tenant != tenant {
		t.Fatalf("fixed tenant requires no discovery guess: %v", err)
	}
	row["state"] = "Disabled"
	index, err = ParseAzureProfile(mustJSON(t, map[string]any{"subscriptions": []any{row}}))
	if err != nil || len(index.Candidates) != 0 {
		t.Fatal("disabled profile record was retained")
	}
}
func TestContextScopeDoesNotWidenRequestAllowlist(t *testing.T) {
	o := options(t)
	o.GraphScopes[Commercial] = GraphScope{AllAccessible: true}
	if err := o.Validate(); err != nil {
		t.Fatal(err)
	}
	_, err := o.AllowsSubscription(Commercial, "33333333-3333-3333-3333-333333333333")
	errorCode(t, err, "subscription_mismatch")
	o.GraphScopes[Commercial] = GraphScope{Subscriptions: []string{sub, sub}}
	errorCode(t, o.Validate(), "invalid_request")
	o = options(t)
	o.LogsScopes[Commercial] = "allAccessible"
	errorCode(t, o.Validate(), "invalid_request")
	o.DataPlanes = []string{"logs.query"}
	if err := o.Validate(); err != nil {
		t.Fatal(err)
	}
	o.DataPlanes = append(o.DataPlanes, "logs.query")
	errorCode(t, o.Validate(), "invalid_request")
}
func TestTargetCanonicalizationAndSmugglingDenials(t *testing.T) {
	parsed, err := ParseTarget("/subscriptions/sub/providers/%4dicr%6fsoft.Sql?name=a+b&name=x%7Ey")
	if err != nil {
		t.Fatal(err)
	}
	if parsed.String() != "/subscriptions/sub/providers/Microsoft.Sql?name=a+b&name=x%7Ey" {
		t.Fatalf("canonical target: %s", parsed.String())
	}
	for _, target := range []string{"https://management.azure.com/", "//other/a", "/a/", "/a//b", "/a/%2e%2e", "/a/%2f/b", "/a/%252f", "/a/%FF", "/a?%61pi-version=x", "/a#fragment", "/a\\b", "/a?name=%00"} {
		_, err = ParseTarget(target)
		errorCode(t, err, "invalid_request")
	}
}
func TestPolicyUsesPurposeVersionQueriesAndRepeatedParameterSemantics(t *testing.T) {
	policy, _, err := LoadReviewed()
	if err != nil {
		t.Fatal(err)
	}
	path := "/subscriptions/" + sub + "/resourceGroups/demo/providers/Microsoft.Storage/storageAccounts/account?$expand=properties"
	target, err := ParseTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, cloud := range []Cloud{Commercial, Government} {
		route, err := policy.Classify(cloud, "request", "GET", target, "2023-05-01")
		if err != nil || route.RBACAction != "Microsoft.Storage/storageAccounts/read" {
			t.Fatalf("storage route: %v", err)
		}
	}
	for _, selector := range []struct{ purpose, method, version string }{{"request", "POST", "2023-05-01"}, {"request", "GET", "2024-01-01"}, {"metricsSingle", "GET", "2023-05-01"}} {
		_, err = policy.Classify(Commercial, selector.purpose, selector.method, target, selector.version)
		errorCode(t, err, "route_denied")
	}
	metrics, _ := ParseTarget("/subscriptions/" + sub + "/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm/providers/Microsoft.Insights/metrics?metricnames=CPU")
	if _, err = policy.Classify(Commercial, "metricsSingle", "GET", metrics, MetricsAPIVersion); err != nil {
		t.Fatal(err)
	}
	_, err = policy.Classify(Commercial, "request", "GET", metrics, MetricsAPIVersion)
	errorCode(t, err, "route_denied")
	repeat := Route{Commercial, "request", "GET", "/x/{same}/{same}", []string{"1"}, "x/read", "inspect", []string{}}
	p := Policy{Version: "test", Routes: []Route{repeat}}
	target, _ = ParseTarget("/x/A/a")
	if _, err = p.Classify(Commercial, "request", "GET", target, "1"); err != nil {
		t.Fatal(err)
	}
	target, _ = ParseTarget("/x/A/b")
	_, err = p.Classify(Commercial, "request", "GET", target, "1")
	errorCode(t, err, "route_denied")
	other := repeat
	other.PathTemplate = "/x/{first}/{second}"
	p.Routes = append(p.Routes, other)
	errorCode(t, p.Validate(), "invalid_request")
}
func TestOfflineSchemaHonorsCloudScopeGrantsAndPolicyIdentity(t *testing.T) {
	_, index, err := LoadReviewed()
	if err != nil {
		t.Fatal(err)
	}
	o := options(t)
	result, err := index.Search(o, "logs query", nil, 20)
	if err != nil || len(result.Results) == 0 {
		t.Fatalf("search: %v", err)
	}
	details, err := index.Get(o, "AzureCloud.logs.query", "v1")
	if err != nil {
		t.Fatal(err)
	}
	if details.Access.Executable || details.Access.DenialReason == nil || *details.Access.DenialReason != "data_plane_grant_required" {
		t.Fatal("logs grant denial missing")
	}
	o.DataPlanes = []string{"logs.query"}
	details, err = index.Get(o, "AzureCloud.logs.query", "v1")
	if err != nil || details.Access.DenialReason == nil || *details.Access.DenialReason != "data_scope_required" {
		t.Fatal("logs scope denial missing")
	}
	o.LogsScopes[Commercial] = "allAccessible"
	details, err = index.Get(o, "AzureCloud.logs.query", "v1")
	if err != nil || !details.Access.Executable || details.Audience != "https://api.loganalytics.io" {
		t.Fatalf("granted logs access: %v", err)
	}
	_, err = index.Get(o, "AzureUSGovernment.logs.query", "v1")
	errorCode(t, err, "schema_cloud_not_bound")
	_, err = index.Get(o, "AzureCloud.logs.query", "wrong")
	errorCode(t, err, "schema_version_not_found")
	o.PolicyHash = "changed"
	_, err = index.Search(o, "logs", nil, 20)
	errorCode(t, err, "schema_unavailable")
}
func TestInlineSchemaAndRouteOverlapCannotBypassHashReview(t *testing.T) {
	m, err := ParseManifest(reviewed.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	m.Schemas[0].ArgumentSchema.(map[string]any)["$ref"] = "https://unreviewed.invalid/schema"
	errorCode(t, m.Validate(false), "invalid_request")
	for _, pair := range [][2]string{{"/{resourceUri}/providers/X/metrics", "/subscriptions/{subscription}/providers/{namespace}/metrics"}, {"/a/{same}/{same}", "/a/x/y"}} {
		overlap := templatesOverlap(pair[0], pair[1])
		if pair[0] == "/a/{same}/{same}" && overlap {
			t.Fatal("conflicting repeated parameter constraints were ignored")
		}
	}
	if _, err := ParseManifest([]byte(strings.Replace(string(reviewed.Manifest), `"formatVersion": 1`, `"formatVersion": 1, "unknown": true`, 1))); err == nil {
		t.Fatal("unknown manifest field accepted")
	}
}
