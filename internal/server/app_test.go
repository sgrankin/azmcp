package server

import (
	"azmcp/internal/artifact"
	"azmcp/internal/azure"
	"azmcp/internal/core"
	"azmcp/internal/worker"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	if _, artifact := record.(artifactAuditRecord); artifact && a.failArtifact {
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
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	app, err := NewApplication(AppConfig{Policy: policy, Schema: schema, Profile: func(ctx context.Context) ([]byte, error) { return profile, ctx.Err() }, Client: client, Audit: audit, Artifacts: artifacts, Worker: func(ctx context.Context) (WorkerHandle, error) { return StartWorker(ctx, executable) }})
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
func runSynthetic(t *testing.T, app *Application, id, code string) (map[string]any, error) {
	t.Helper()
	raw, _ := marshalJSON(map[string]any{"contextId": id, "code": code})
	result, err := app.Call(context.Background(), "azure_run", raw)
	if err != nil {
		return nil, err
	}
	return result.(map[string]any), nil
}
func valueJSON(t *testing.T, result map[string]any) any {
	t.Helper()
	var value any
	if err := json.Unmarshal(result["value"].(json.RawMessage), &value); err != nil {
		t.Fatal(err)
	}
	return value
}
func assertCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil || publicError(err).Code != code {
		t.Fatalf("error=%v; want %s", err, code)
	}
}

func TestAccountsAndSchemaStayOfflineAndRunsRetainState(t *testing.T) {
	app, _, _, requests := newSyntheticApp(t, nil)
	result, err := app.Call(context.Background(), "azure_accounts", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	accounts := result.(map[string]any)["accounts"].([]any)
	if len(accounts) != 1 || requests.Load() != 0 {
		t.Fatal("account discovery acquired a credential or sent a request")
	}
	id := openSynthetic(t, app, nil)
	before := requests.Load()
	search, _ := marshalJSON(map[string]any{"contextId": id, "query": "storage"})
	found, err := app.Call(context.Background(), "azure_schema_search", search)
	if err != nil {
		t.Fatal(err)
	}
	hits := found.(map[string]any)["results"].([]core.SchemaSearchHit)
	if len(hits) == 0 {
		t.Fatal("missing reviewed storage route")
	}
	get, _ := marshalJSON(map[string]any{"contextId": id, "entryId": hits[0].EntryID, "apiVersion": hits[0].APIVersions[0]})
	if _, err = app.Call(context.Background(), "azure_schema_get", get); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != before {
		t.Fatal("offline schema discovery sent HTTP")
	}
	first, err := runSynthetic(t, app, id, `let retained = 40; console.log("hello\nworld"); retained += 1`)
	if err != nil {
		t.Fatal(err)
	}
	if valueJSON(t, first) != float64(41) || first["console"].([]string)[0] != "hello\nworld" {
		t.Fatalf("unexpected first turn: %#v", first)
	}
	second, err := runSynthetic(t, app, id, `retained += 1`)
	if err != nil {
		t.Fatal(err)
	}
	if valueJSON(t, second) != float64(42) {
		t.Fatal("lexical state was lost")
	}
	_, err = runSynthetic(t, app, id, `throw new Error("private source detail")`)
	assertCode(t, err, "invalid_request")
	recovered, err := runSynthetic(t, app, id, `retained`)
	if err != nil || valueJSON(t, recovered) != float64(42) {
		t.Fatal("ordinary exception disposed a usable worker")
	}
	if err = app.close(id); err != nil {
		t.Fatal(err)
	}
	_, err = runSynthetic(t, app, id, `1`)
	assertCode(t, err, "context_evicted")
}
func TestHelpersAreSynchronousAndCloudAudienceRemainsExplicit(t *testing.T) {
	app, audit, credentials, requests := newSyntheticApp(t, nil)
	id := openSynthetic(t, app, map[string]any{"bindings": map[string]any{"AzureCloud": map[string]string{"subscription": testSubscription, "tenant": testTenant}, "AzureUSGovernment": map[string]string{"subscription": testOtherSubscription, "tenant": testTenant}}, "dataPlanes": []string{"logs.query"}, "logsScopes": map[string]any{"AzureCloud": map[string]string{"scope": "allAccessible"}, "AzureUSGovernment": map[string]string{"scope": "allAccessible"}}})
	for _, cloud := range []string{"AzureCloud", "AzureUSGovernment"} {
		sub := testSubscription
		if cloud == "AzureUSGovernment" {
			sub = testOtherSubscription
		}
		code := fmt.Sprintf(`const h%s = az.request({cloud:%q,method:"GET",path:"/providers/Microsoft.Storage",apiVersion:"2021-04-01"}); const g%s=az.graph({cloud:%q,query:"Resources | project name"}); const m%s=az.metrics.single({cloud:%q,resourceId:%q,metricNames:["Requests"]}); const b%s=az.metrics.batch({cloud:%q,region:"eastus",resourceIds:[%q],metricNamespace:"Microsoft.Storage/storageAccounts",metricNames:["Requests"]}); const l%s=az.logs.query({cloud:%q,workspaceId:%q,query:"AppRequests | count",timespan:"PT1H"}); [Array.isArray(h%s.body.value),g%s.body.data[0].name,m%s.body.value.length,b%s.body.values.length,l%s.tables[0].rows[0][0]]`, cloud, cloud, cloud, cloud, cloud, cloud, "/subscriptions/"+sub+"/resourceGroups/group/providers/Microsoft.Storage/storageAccounts/account", cloud, cloud, "/subscriptions/"+sub+"/resourceGroups/group/providers/Microsoft.Storage/storageAccounts/account", cloud, cloud, testWorkspace, cloud, cloud, cloud, cloud, cloud)
		result, err := runSynthetic(t, app, id, code)
		if err != nil {
			t.Fatal(err)
		}
		value := valueJSON(t, result).([]any)
		if value[0] != true || value[1] != "synthetic-item" || value[4] != float64(7) {
			t.Fatalf("ordinary helper values: %#v", value)
		}
		if len(result["calls"].([]azure.CallRecord)) != 5 {
			t.Fatal("missing host call records")
		}
	}
	before := requests.Load()
	_, err := runSynthetic(t, app, id, `az.request({method:"GET",path:"/providers/Microsoft.Storage",apiVersion:"2021-04-01"})`)
	assertCode(t, err, "invalid_request")
	_, err = runSynthetic(t, app, id, `az.request({cloud:"AzureCloud",method:"DELETE",path:"/providers/Microsoft.Storage",apiVersion:"2021-04-01"})`)
	assertCode(t, err, "route_denied")
	if requests.Load() != before {
		t.Fatal("denied call reached HTTP")
	}
	credentials.mu.Lock()
	defer credentials.mu.Unlock()
	audiences := map[string]bool{}
	for _, r := range credentials.requests {
		audiences[string(r.Cloud)+"|"+r.Audience] = true
	}
	for _, cloud := range []core.Cloud{core.Commercial, core.Government} {
		for _, audience := range []string{cloud.Manifest().ResourceManager, cloud.Audience("metricsBatch"), cloud.Audience("logsQuery")} {
			if !audiences[string(cloud)+"|"+audience] {
				t.Fatal("missing explicit cloud audience", cloud, audience)
			}
		}
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	encoded, _ := marshalJSON(audit.records)
	for _, private := range []string{"synthetic-token", "Resources | project name", "AppRequests | count", "synthetic-item"} {
		if strings.Contains(string(encoded), private) {
			t.Fatal("audit leaked private content", private)
		}
	}
}
func TestReferencesAreContextScopedAndBounded(t *testing.T) {
	app, _, _, _ := newSyntheticApp(t, nil)
	id := openSynthetic(t, app, nil)
	other := openSynthetic(t, app, nil)
	result, err := runSynthetic(t, app, id, `({records:Array.from({length:6000},(_,i)=>({i,value:"abc"}))})`)
	if err != nil {
		t.Fatal(err)
	}
	envelope := valueJSON(t, result).(map[string]any)
	token := envelope["__ref"].(string)
	if envelope["type"] != "object" || envelope["sensitivity"] != "customerData" {
		t.Fatal(envelope)
	}
	result, err = runSynthetic(t, app, id, fmt.Sprintf(`az.ref(%q).records.length`, token))
	if err != nil || valueJSON(t, result) != float64(6000) {
		t.Fatal("reference rehydration failed", err)
	}
	_, err = runSynthetic(t, app, other, fmt.Sprintf(`az.ref(%q)`, token))
	assertCode(t, err, "invalid_request")
	_, err = runSynthetic(t, app, id, `"x".repeat(600000)`)
	assertCode(t, err, "result_too_large")
	result, err = runSynthetic(t, app, id, `2`)
	if err != nil || valueJSON(t, result) != float64(2) {
		t.Fatal("oversized JSON poisoned healthy worker", err)
	}
}
func TestArtifactsPublishOnlyAfterSuccessfulTurnAndPersist(t *testing.T) {
	app, audit, _, _ := newSyntheticApp(t, nil)
	id := openSynthetic(t, app, map[string]any{"localCapabilities": []string{"artifacts.write"}})
	result, err := runSynthetic(t, app, id, `const receipt = az.artifacts.writeJson({name:"result.json",value:{answer:42}}); receipt`)
	if err != nil {
		t.Fatal(err)
	}
	receipt := valueJSON(t, result).(map[string]any)
	path := receipt["path"].(string)
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "{\"answer\":42}\n" {
		t.Fatal("committed artifact mismatch", err, string(raw))
	}
	result, err = runSynthetic(t, app, id, `az.artifacts.writeJsonLines({name:"rows.jsonl.lz4",compression:"lz4",values:[{n:1},{n:2}]})`)
	if err != nil {
		t.Fatal(err)
	}
	lines := valueJSON(t, result).(map[string]any)
	if lines["contentEncoding"] != "lz4" || lines["logicalBytes"] != float64(16) {
		t.Fatal(lines)
	}
	app.mu.Lock()
	slot := app.contexts[id]
	app.mu.Unlock()
	decoded, _, err := app.config.Artifacts.Read(context.Background(), slot.namespace, "rows.jsonl.lz4")
	if err != nil || string(decoded) != "{\"n\":1}\n{\"n\":2}\n" {
		t.Fatal("LZ4 artifact read mismatch", err, string(decoded))
	}
	_, err = runSynthetic(t, app, id, `az.artifacts.writeJson({name:"failed.json",value:{private:1}}); throw new Error("failed")`)
	assertCode(t, err, "invalid_request")
	if _, err = os.Stat(filepath.Join(filepath.Dir(path), "failed.json")); !os.IsNotExist(err) {
		t.Fatal("failed turn published an artifact", err)
	}
	audit.mu.Lock()
	audit.failArtifact = true
	audit.mu.Unlock()
	_, err = runSynthetic(t, app, id, `try { az.artifacts.writeJson({name:"caught.json",value:{private:1}}) } catch (_) {} 7`)
	if err != nil {
		t.Fatal("caught audit rejection unexpectedly failed script", err)
	}
	if _, err = os.Stat(filepath.Join(filepath.Dir(path), "caught.json")); !os.IsNotExist(err) {
		t.Fatal("caught audit error left a publishable artifact", err)
	}
	audit.mu.Lock()
	audit.failArtifact = false
	audit.mu.Unlock()
	_, err = runSynthetic(t, app, id, `az.artifacts.writeJson({name:"result.json",value:{answer:0}})`)
	assertCode(t, err, "invalid_request")
	_, err = runSynthetic(t, app, id, `az.artifacts.writeJson({name:"../escape.json",value:0})`)
	assertCode(t, err, "invalid_request")
	if err = app.close(id); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(path); err != nil {
		t.Fatal("context close deleted durable artifact", err)
	}
}
func TestCancellationBusyCloseAndIdentityChangeDisposeWorkers(t *testing.T) {
	entered := make(chan struct{}, 1)
	app, _, credentials, _ := newSyntheticApp(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Count(r.URL.Path, "/") == 2 {
			fmt.Fprintf(w, `{"subscriptionId":%q}`, testSubscription)
			return
		}
		select {
		case entered <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	})
	id := openSynthetic(t, app, map[string]any{"localCapabilities": []string{"artifacts.write"}})
	ctx, cancel := context.WithCancel(context.Background())
	raw, _ := marshalJSON(map[string]any{"contextId": id, "code": `az.artifacts.writeJson({name:"cancelled.json",value:1}); az.request({cloud:"AzureCloud",method:"GET",path:"/providers/Microsoft.Storage",apiVersion:"2021-04-01"})`})
	completed := make(chan error, 1)
	go func() { _, err := app.Call(ctx, "azure_run", raw); completed <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("host request did not start")
	}
	_, err := runSynthetic(t, app, id, `1`)
	assertCode(t, err, "context_busy")
	app.mu.Lock()
	slot := app.contexts[id]
	app.mu.Unlock()
	cancel()
	select {
	case err = <-completed:
		assertCode(t, err, "context_evicted")
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled run did not stop")
	}
	if _, _, err = app.config.Artifacts.Read(context.Background(), slot.namespace, "cancelled.json"); err == nil {
		t.Fatal("cancelled turn committed staged artifact")
	}
	_, err = runSynthetic(t, app, id, `1`)
	assertCode(t, err, "context_evicted")
	other := openSynthetic(t, app, nil)
	credentials.changed.Store(true)
	_, err = runSynthetic(t, app, other, `az.request({cloud:"AzureCloud",method:"GET",path:"/providers/Microsoft.Storage",apiVersion:"2021-04-01"})`)
	assertCode(t, err, "authentication_required")
	_, err = runSynthetic(t, app, other, `1`)
	assertCode(t, err, "context_evicted")
}
func TestTimeoutAndAsyncDisposeContext(t *testing.T) {
	app, _, _, _ := newSyntheticApp(t, nil)
	for _, test := range []struct{ code, expected string }{{`while(true){}`, "execution_timeout"}, {`Promise.resolve(1)`, "invalid_request"}, {`Promise.resolve().then(()=>globalThis.leak=1); 7`, "invalid_request"}} {
		id := openSynthetic(t, app, nil)
		raw, _ := marshalJSON(map[string]any{"contextId": id, "code": test.code, "timeoutMs": 100})
		_, err := app.Call(context.Background(), "azure_run", raw)
		assertCode(t, err, test.expected)
		_, err = runSynthetic(t, app, id, `1`)
		assertCode(t, err, "context_evicted")
	}
}
func TestAuditFailureBlocksBindingValidationBeforeHTTP(t *testing.T) {
	app, audit, _, requests := newSyntheticApp(t, nil)
	audit.failPrepare = true
	raw, _ := marshalJSON(map[string]any{"bindings": map[string]any{"AzureCloud": map[string]string{"subscription": testSubscription, "tenant": testTenant}}})
	_, err := app.Call(context.Background(), "azure_context_open", raw)
	assertCode(t, err, "upstream_error")
	if requests.Load() != 0 {
		t.Fatal("audit failure allowed upstream request")
	}
	app.mu.Lock()
	defer app.mu.Unlock()
	if len(app.contexts) != 0 {
		t.Fatal("failed open retained a context")
	}
}
func TestReferenceFIFOExpiryAndMetadataRemainBounded(t *testing.T) {
	var store refStore
	now := time.Now()
	var first, last string
	for i := 0; i < 80; i++ {
		id, err := store.put(json.RawMessage(`{"n":1}`), now)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = id
		}
		last = id
	}
	if len(store.entries) != 32 {
		t.Fatal("FIFO metadata grew without bound")
	}
	if _, err := store.get(first, now); err == nil {
		t.Fatal("oldest reference survived eviction")
	}
	if _, err := store.get(last, now); err != nil {
		t.Fatal(err)
	}
	store.sweep(now.Add(5 * time.Minute))
	if len(store.entries) != 0 || store.bytes != 0 {
		t.Fatal("expired values were retained")
	}
}

func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "--worker" {
		if err := worker.RunWorker(os.Stdin, os.Stdout); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}
