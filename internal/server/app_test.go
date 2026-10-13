package server

import (
	"azmcp/internal/artifact"
	"azmcp/internal/azure"
	"azmcp/internal/core"
	"context"
	"encoding/json"
	"fmt"
	"github.com/pierrec/lz4/v4"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testSubscription = "11111111-1111-1111-1111-111111111111"
const testTenant = "22222222-2222-2222-2222-222222222222"
const testOtherSubscription = "33333333-3333-3333-3333-333333333333"
const testWorkspace = "44444444-4444-4444-4444-444444444444"
const testPrincipal = "55555555-5555-5555-5555-555555555555"
const testClientID = "66666666-6666-6666-6666-666666666666"

type syntheticCredentials struct {
	mu       sync.Mutex
	requests []azure.TokenRequest
	changed  atomic.Bool
}

func (c *syntheticCredentials) Acquire(ctx context.Context, r azure.TokenRequest) (azure.Credential, error) {
	if ctx.Err() != nil {
		return azure.Credential{}, ctx.Err()
	}
	c.mu.Lock()
	c.requests = append(c.requests, r)
	c.mu.Unlock()
	principal := testPrincipal
	if c.changed.Load() {
		principal = testWorkspace
	}
	return azure.Credential{Token: []byte("synthetic-token"), Principal: principal, ClientID: testClientID, ExpiresAt: time.Now().Add(time.Hour)}, nil
}

type syntheticAudit struct {
	mu           sync.Mutex
	records      []any
	failPrepare  bool
	failArtifact bool
	failAzure    bool
	onArtifact   func()
}

func (a *syntheticAudit) Prepare() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failPrepare {
		return errAudit
	}
	return nil
}
func (a *syntheticAudit) Append(record any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, artifact := record.(artifactAuditRecord); artifact {
		if a.onArtifact != nil {
			a.onArtifact()
		}
		if a.failArtifact {
			return errAudit
		}
	}
	if _, azureCall := record.(azure.CallRecord); azureCall && a.failAzure {
		return errAudit
	}
	a.records = append(a.records, record)
	return nil
}
func canonicalTemp(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return path
}
func newSyntheticApp(t *testing.T, handler http.HandlerFunc) (*Application, *syntheticAudit, *syntheticCredentials, *atomic.Int64) {
	t.Helper()
	count := &atomic.Int64{}
	if handler == nil {
		handler = func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.Header.Get("Authorization") != "Bearer synthetic-token" {
				t.Error("unexpected credential boundary")
				w.WriteHeader(401)
				return
			}
			switch {
			case strings.Contains(r.URL.Path, "/metrics:getBatch"):
				fmt.Fprint(w, `{"values":[{"resourceid":"synthetic-resource","value":[]}]}`)
			case strings.HasSuffix(r.URL.Path, "/Microsoft.Insights/metrics"):
				fmt.Fprint(w, `{"value":[{"name":{"value":"Requests"},"timeseries":[]}]}`)
			case strings.Contains(r.URL.Path, "/workspaces/"):
				fmt.Fprint(w, `{"tables":[{"name":"PrimaryResult","columns":[{"name":"Count","type":"long"}],"rows":[[7]]}]}`)
			case strings.HasSuffix(r.URL.Path, "/Microsoft.ResourceGraph/resources"):
				fmt.Fprint(w, `{"data":[{"name":"synthetic-item"}],"totalRecords":1}`)
			case strings.Count(r.URL.Path, "/") == 2 && strings.HasPrefix(r.URL.Path, "/subscriptions/"):
				fmt.Fprintf(w, `{"subscriptionId":%q}`, strings.TrimPrefix(r.URL.Path, "/subscriptions/"))
			default:
				fmt.Fprint(w, `{"value":[{"name":"synthetic-provider"}]}`)
			}
		}
	}
	loopback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { count.Add(1); handler(w, r) }))
	t.Cleanup(loopback.Close)
	policy, schema, err := core.LoadReviewed()
	if err != nil {
		t.Fatal(err)
	}
	credentials := &syntheticCredentials{}
	client, err := azure.NewLoopbackClient(credentials, &policy, loopback.URL)
	if err != nil {
		t.Fatal(err)
	}
	root := canonicalTemp(t)
	artifacts, err := artifact.NewStore(filepath.Join(root, "artifacts"), artifact.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	audit := &syntheticAudit{}
	profile := []byte(fmt.Sprintf(`{"subscriptions":[{"id":%q,"tenantId":%q,"environmentName":"AzureCloud","name":"synthetic","state":"Enabled","user":{"name":"synthetic@example.invalid","type":"user"}}]}`, testSubscription, testTenant))
	app, err := NewApplication(AppConfig{Policy: policy, Schema: schema, Profile: func(ctx context.Context) ([]byte, error) { return profile, ctx.Err() }, Client: client, Audit: audit, Artifacts: artifacts})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := app.Close(); err != nil {
			t.Error(err)
		}
	})
	return app, audit, credentials, count
}
func openSynthetic(t *testing.T, app *Application, extra map[string]any) string {
	t.Helper()
	args := map[string]any{"bindings": map[string]any{"AzureCloud": map[string]string{"subscription": testSubscription, "tenant": testTenant}}}
	for key, value := range extra {
		args[key] = value
	}
	raw, _ := marshalJSON(args)
	result, err := app.Call(context.Background(), "azure_context_open", raw)
	if err != nil {
		t.Fatal(err)
	}
	id := result.(map[string]any)["contextId"].(string)
	if !validContextID(id) {
		t.Fatal("noncanonical context handle")
	}
	return id
}

func callSynthetic(t *testing.T, app *Application, name string, args map[string]any) (map[string]any, error) {
	t.Helper()
	raw, err := marshalJSON(args)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = parseArguments(name, raw); err != nil {
		return nil, failure("invalid_request")
	}
	result, err := app.Call(context.Background(), name, raw)
	if err != nil {
		return nil, err
	}
	return result.(map[string]any), nil
}
func requestArgs(id string) map[string]any {
	return map[string]any{"contextId": id, "cloud": "AzureCloud", "method": "GET", "path": "/providers/Microsoft.Storage", "apiVersion": "2021-04-01"}
}
func assertCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil || publicError(err).Code != code {
		t.Fatalf("wanted %s, got %v (%+v)", code, err, publicError(err))
	}
}
func TestAccountsAndSchemaStayOffline(t *testing.T) {
	app, _, _, count := newSyntheticApp(t, nil)
	accounts, err := callSynthetic(t, app, "azure_accounts", map[string]any{})
	if err != nil || len(accounts["accounts"].([]any)) != 1 || count.Load() != 0 {
		t.Fatal(accounts, err, count.Load())
	}
	id := openSynthetic(t, app, nil)
	before := count.Load()
	search, err := callSynthetic(t, app, "azure_schema_search", map[string]any{"contextId": id, "query": "storage"})
	if err != nil {
		t.Fatal(err)
	}
	hits := search["results"].([]core.SchemaSearchHit)
	if len(hits) == 0 || hits[0].ExecutionSurface != "azure_request" {
		t.Fatal(hits)
	}
	_, err = callSynthetic(t, app, "azure_schema_get", map[string]any{"contextId": id, "entryId": hits[0].EntryID, "apiVersion": hits[0].APIVersions[0]})
	if err != nil || count.Load() != before {
		t.Fatal(err, count.Load())
	}
	if err = app.close(id); err != nil {
		t.Fatal(err)
	}
	_, err = callSynthetic(t, app, "azure_request", requestArgs(id))
	assertCode(t, err, "context_evicted")
}
func TestAllTypedHelpersEnforceCloudAndScope(t *testing.T) {
	app, audit, credentials, count := newSyntheticApp(t, nil)
	id := openSynthetic(t, app, map[string]any{"bindings": map[string]any{"AzureCloud": map[string]string{"subscription": testSubscription, "tenant": testTenant}, "AzureUSGovernment": map[string]string{"subscription": testSubscription, "tenant": testTenant}}, "dataPlanes": []string{"logs.query"}, "logsScopes": map[string]any{"AzureCloud": map[string]string{"scope": "allAccessible"}, "AzureUSGovernment": map[string]string{"scope": "allAccessible"}}})
	resource := "/subscriptions/" + testSubscription + "/resourceGroups/synthetic/providers/Microsoft.Storage/storageAccounts/synthetic"
	for _, cloud := range []core.Cloud{core.Commercial, core.Government} {
		for name, args := range map[string]map[string]any{
			"azure_request":        {"method": "GET", "path": "/providers/Microsoft.Storage", "apiVersion": "2021-04-01"},
			"azure_graph":          {"query": "Resources | project id | take 1"},
			"azure_metrics_single": {"resourceId": resource, "metricNames": []string{"Requests"}},
			"azure_metrics_batch":  {"region": "eastus", "resourceIds": []string{resource}, "metricNamespace": "Microsoft.Storage/storageAccounts", "metricNames": []string{"Requests"}},
			"azure_logs_query":     {"workspaceId": testWorkspace, "query": "print Count=7", "timespan": "PT1H"},
		} {
			args["contextId"] = id
			args["cloud"] = cloud
			result, err := callSynthetic(t, app, name, args)
			if err != nil {
				t.Fatalf("%s %s: %v", cloud, name, err)
			}
			var value map[string]any
			if json.Unmarshal(result["value"].(json.RawMessage), &value) != nil {
				t.Fatal("invalid value")
			}
			if name == "azure_logs_query" {
				if value["tables"] == nil {
					t.Fatal(value)
				}
			} else if value["status"] != float64(200) || value["body"] == nil {
				t.Fatal(value)
			}
			records := result["calls"].([]azure.CallRecord)
			if len(records) != 1 || records[0].Operation != name {
				t.Fatal(records)
			}
		}
	}
	before := count.Load()
	args := requestArgs(id)
	delete(args, "cloud")
	_, err := callSynthetic(t, app, "azure_request", args)
	assertCode(t, err, "invalid_request")
	args = requestArgs(id)
	args["method"] = "DELETE"
	_, err = callSynthetic(t, app, "azure_request", args)
	assertCode(t, err, "invalid_request")
	args = requestArgs(id)
	args["subscription"] = testOtherSubscription
	_, err = callSynthetic(t, app, "azure_request", args)
	assertCode(t, err, "subscription_mismatch")
	if count.Load() != before {
		t.Fatal("denied request reached HTTP")
	}
	credentials.mu.Lock()
	defer credentials.mu.Unlock()
	seen := map[string]bool{}
	for _, r := range credentials.requests {
		seen[string(r.Cloud)+"|"+r.Audience] = true
	}
	for _, c := range []core.Cloud{core.Commercial, core.Government} {
		for _, purpose := range []string{"request", "metricsBatch", "logsQuery"} {
			if !seen[string(c)+"|"+c.Audience(purpose)] {
				t.Fatal("missing audience", c, purpose)
			}
		}
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	encoded, _ := json.Marshal(audit.records)
	if strings.Contains(string(encoded), "synthetic-token") || strings.Contains(string(encoded), "print Count=7") {
		t.Fatal("audit leaked content")
	}
}
func TestParallelCallsCancellationCapacityCloseAndIdentity(t *testing.T) {
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	app, _, credentials, _ := newSyntheticApp(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Count(r.URL.Path, "/") == 2 {
			fmt.Fprintf(w, `{"subscriptionId":%q}`, testSubscription)
			return
		}
		entered <- struct{}{}
		select {
		case <-r.Context().Done():
			return
		case <-release:
			fmt.Fprint(w, `{"value":[]}`)
		}
	})
	id := openSynthetic(t, app, nil)
	raw, _ := marshalJSON(requestArgs(id))
	done := make(chan error, 8)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _, err := app.Call(ctx, "azure_request", raw); done <- err }()
	<-entered
	for range 7 {
		go func() { _, err := app.Call(context.Background(), "azure_request", raw); done <- err }()
		<-entered
	}
	_, err := app.Call(context.Background(), "azure_request", raw)
	assertCode(t, err, "context_busy")
	cancel()
	assertCode(t, <-done, "request_cancelled")
	if err = app.close(id); err != nil {
		t.Fatal(err)
	}
	for range 7 {
		assertCode(t, <-done, "context_evicted")
	}
	other := openSynthetic(t, app, nil)
	credentials.changed.Store(true)
	raw, _ = marshalJSON(requestArgs(other))
	_, err = app.Call(context.Background(), "azure_request", raw)
	assertCode(t, err, "authentication_required")
	_, err = app.Call(context.Background(), "azure_request", raw)
	assertCode(t, err, "context_evicted")
	close(release)
}
func TestCancellationLeavesAuthorizationContextUsable(t *testing.T) {
	app, _, _, _ := newSyntheticApp(t, nil)
	id := openSynthetic(t, app, nil)
	raw, _ := marshalJSON(requestArgs(id))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := app.Call(ctx, "azure_request", raw)
	assertCode(t, err, "request_cancelled")
	if _, err = app.Call(context.Background(), "azure_request", raw); err != nil {
		t.Fatal("cancellation revoked context", err)
	}
}
func TestExportPublishesFullJSONAndPreservesItAfterClose(t *testing.T) {
	payload := `{"value":[{"data":"` + strings.Repeat("x", 2*1024*1024) + `"}]}`
	app, audit, _, _ := newSyntheticApp(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Count(r.URL.Path, "/") == 2 {
			fmt.Fprintf(w, `{"subscriptionId":%q}`, testSubscription)
			return
		}
		fmt.Fprint(w, payload)
	})
	id := openSynthetic(t, app, map[string]any{"localCapabilities": []string{"artifacts.write"}})
	_, err := callSynthetic(t, app, "azure_request", requestArgs(id))
	assertCode(t, err, "result_too_large")
	arguments := requestArgs(id)
	delete(arguments, "contextId")
	export := map[string]any{"contextId": id, "operation": "azure_request", "arguments": arguments, "name": "full.json.lz4", "compression": "lz4"}
	result, err := callSynthetic(t, app, "azure_export", export)
	if err != nil {
		t.Fatal(err)
	}
	receipt := result["receipt"].(artifact.Receipt)
	file, err := os.Open(receipt.Path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(lz4.NewReader(file))
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]json.RawMessage
	if json.Unmarshal(raw, &value) != nil {
		t.Fatal("invalid exported JSON")
	}
	var body any
	json.Unmarshal(value["body"], &body)
	var wanted any
	json.Unmarshal([]byte(payload), &wanted)
	if !reflect.DeepEqual(body, wanted) {
		t.Fatal("export content changed")
	}
	if err = app.close(id); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(receipt.Path); err != nil {
		t.Fatal("published export disappeared", err)
	}
	other := openSynthetic(t, app, map[string]any{"localCapabilities": []string{"artifacts.write"}})
	export["contextId"] = other
	export["name"] = "rejected.json"
	export["compression"] = "identity"
	audit.mu.Lock()
	audit.failArtifact = true
	audit.mu.Unlock()
	_, err = callSynthetic(t, app, "azure_export", export)
	assertCode(t, err, "upstream_error")
	app.mu.Lock()
	ns := app.contexts[other].namespace
	app.mu.Unlock()
	_, _, readErr := app.config.Artifacts.Read(context.Background(), ns, "rejected.json")
	if readErr == nil {
		t.Fatal("failed audit published artifact")
	}
}
func TestExportRequiresGrantAndRejectsInvalidInputsBeforeHTTP(t *testing.T) {
	app, _, _, count := newSyntheticApp(t, nil)
	id := openSynthetic(t, app, nil)
	args := requestArgs(id)
	delete(args, "contextId")
	before := count.Load()
	_, err := callSynthetic(t, app, "azure_export", map[string]any{"contextId": id, "operation": "azure_request", "arguments": args, "name": "x.json"})
	assertCode(t, err, "invalid_request")
	id = openSynthetic(t, app, map[string]any{"localCapabilities": []string{"artifacts.write"}})
	before = count.Load()
	for _, name := range []string{"../x.json", "x.jsonl", "x.json.lz4"} {
		_, err = callSynthetic(t, app, "azure_export", map[string]any{"contextId": id, "operation": "azure_request", "arguments": args, "name": name})
		assertCode(t, err, "invalid_request")
	}
	if count.Load() != before {
		t.Fatal("invalid export reached HTTP")
	}
}
func TestAuditFailureBlocksBindingValidationBeforeHTTP(t *testing.T) {
	app, audit, _, count := newSyntheticApp(t, nil)
	audit.failPrepare = true
	raw, _ := marshalJSON(map[string]any{"bindings": map[string]any{"AzureCloud": map[string]string{"subscription": testSubscription, "tenant": testTenant}}})
	_, err := app.Call(context.Background(), "azure_context_open", raw)
	assertCode(t, err, "upstream_error")
	if count.Load() != 0 {
		t.Fatal("audit failure reached HTTP")
	}
}
func TestContextExpiryAndCapacity(t *testing.T) {
	app, _, _, _ := newSyntheticApp(t, nil)
	app.config.MaxContexts = 1
	app.config.AbsoluteTTL = 30 * time.Millisecond
	id := openSynthetic(t, app, nil)
	raw, _ := marshalJSON(map[string]any{"bindings": map[string]any{"AzureCloud": map[string]string{"subscription": testSubscription, "tenant": testTenant}}})
	_, err := app.Call(context.Background(), "azure_context_open", raw)
	assertCode(t, err, "upstream_error")
	deadline := time.Now().Add(time.Second)
	for {
		app.mu.Lock()
		_, live := app.contexts[id]
		app.mu.Unlock()
		if !live {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("expired context retained")
		}
		time.Sleep(time.Millisecond)
	}
	_, err = app.Call(context.Background(), "azure_request", mustJSON(t, requestArgs(id)))
	assertCode(t, err, "context_evicted")
}
func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := marshalJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestExportCancellationAndCloseRollbackOnlyThatExport(t *testing.T) {
	for _, closeContext := range []bool{false, true} {
		t.Run(fmt.Sprint(closeContext), func(t *testing.T) {
			app, audit, _, _ := newSyntheticApp(t, nil)
			id := openSynthetic(t, app, map[string]any{"localCapabilities": []string{"artifacts.write"}})
			staged := make(chan struct{})
			resume := make(chan struct{})
			audit.onArtifact = func() { close(staged); <-resume }
			args := requestArgs(id)
			delete(args, "contextId")
			raw := mustJSON(t, map[string]any{"contextId": id, "operation": "azure_request", "arguments": args, "name": "cancelled.json"})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := app.Call(ctx, "azure_export", raw); done <- err }()
			select {
			case <-staged:
			case <-time.After(time.Second):
				t.Fatal("export did not stage")
			}
			app.mu.Lock()
			ns := app.contexts[id].namespace
			app.mu.Unlock()
			if closeContext {
				if err := app.close(id); err != nil {
					t.Fatal(err)
				}
			} else {
				cancel()
			}
			close(resume)
			err := <-done
			if closeContext {
				assertCode(t, err, "context_evicted")
			} else {
				assertCode(t, err, "request_cancelled")
			}
			if _, _, err := app.config.Artifacts.Read(context.Background(), ns, "cancelled.json"); err == nil {
				t.Fatal("canceled export published")
			}
			if !closeContext {
				app.mu.Lock()
				n := len(app.contexts[id].exports)
				app.mu.Unlock()
				if n != 0 {
					t.Fatal("turn retained")
				}
				if _, err = app.Call(context.Background(), "azure_request", mustJSON(t, requestArgs(id))); err != nil {
					t.Fatal("export cancellation revoked context", err)
				}
			}
		})
	}
}
func TestConcurrentCreateOnlyExportsAndNamespaceIsolation(t *testing.T) {
	app, _, _, _ := newSyntheticApp(t, nil)
	grant := map[string]any{"localCapabilities": []string{"artifacts.write"}}
	id := openSynthetic(t, app, grant)
	args := requestArgs(id)
	delete(args, "contextId")
	request := map[string]any{"contextId": id, "operation": "azure_request", "arguments": args, "name": "same.json"}
	raw := mustJSON(t, request)
	type outcome struct {
		value any
		err   error
	}
	results := make(chan outcome, 2)
	for range 2 {
		go func() {
			value, err := app.Call(context.Background(), "azure_export", raw)
			results <- outcome{value, err}
		}()
	}
	success, denied := 0, 0
	for range 2 {
		r := <-results
		if r.err == nil {
			success++
		} else {
			assertCode(t, r.err, "invalid_request")
			denied++
		}
	}
	if success != 1 || denied != 1 {
		t.Fatal("create-only export race", success, denied)
	}
	other := openSynthetic(t, app, grant)
	request["contextId"] = other
	if _, err := app.Call(context.Background(), "azure_export", mustJSON(t, request)); err != nil {
		t.Fatal("names leaked across namespaces", err)
	}
}
func TestIdentityRevocationSurvivesFailedAuditAppend(t *testing.T) {
	app, audit, credentials, _ := newSyntheticApp(t, nil)
	id := openSynthetic(t, app, nil)
	audit.failAzure = true
	credentials.changed.Store(true)
	_, err := app.Call(context.Background(), "azure_request", mustJSON(t, requestArgs(id)))
	assertCode(t, err, "upstream_error")
	_, err = app.Call(context.Background(), "azure_request", mustJSON(t, requestArgs(id)))
	assertCode(t, err, "context_evicted")
}

func TestCancelledContextOpenRetainsNoAuthorizationHandle(t *testing.T) {
	entered := make(chan struct{})
	app, _, _, _ := newSyntheticApp(t, func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done() })
	raw := mustJSON(t, map[string]any{"bindings": map[string]any{"AzureCloud": map[string]string{"subscription": testSubscription, "tenant": testTenant}}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := app.Call(ctx, "azure_context_open", raw); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("binding validation did not start")
	}
	cancel()
	assertCode(t, <-done, "request_cancelled")
	app.mu.Lock()
	defer app.mu.Unlock()
	if len(app.contexts) != 0 {
		t.Fatal("canceled open retained handle")
	}
}
