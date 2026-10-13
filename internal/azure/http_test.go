package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"azmcp/internal/core"
)

type fakeCredentials struct {
	mu        sync.Mutex
	requests  []TokenRequest
	principal string
}

func (f *fakeCredentials) Acquire(ctx context.Context, r TokenRequest) (Credential, error) {
	if _, err := core.ParseCloud(string(r.Cloud)); err != nil || !validAudience(r.Cloud, r.Audience) || !validID(r.Subscription) || !validID(r.Tenant) {
		return Credential{}, credentialError("invalid_request")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r)
	principal := f.principal
	if principal == "" {
		principal = testPrincipal
	}
	return Credential{Token: []byte("synthetic-http-token"), Principal: principal, ClientID: testClientID, ExpiresAt: time.Now().Add(time.Hour)}, nil
}
func (f *fakeCredentials) calls() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.requests) }
func simulator(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	// The literal listener address proves loopback before opening the socket.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &httptest.Server{Listener: listener, Config: &http.Server{Handler: handler}}
	server.Start()
	t.Cleanup(server.Close)
	return server
}
func reviewedPolicy(t *testing.T) *core.Policy {
	t.Helper()
	policy, _, err := core.LoadReviewed()
	if err != nil {
		t.Fatal(err)
	}
	return &policy
}
func loopbackClient(t *testing.T, credentials *fakeCredentials, server *httptest.Server) *Client {
	t.Helper()
	client, err := NewLoopbackClientWithLimits(credentials, reviewedPolicy(t), server.URL, Limits{1024 * 1024, 8 * 1024 * 1024, time.Second, RetryPolicy{3, time.Second, 0, 0}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}
func binding(cloud core.Cloud) core.ResolvedBinding {
	return core.ResolvedBinding{Cloud: cloud, Subscription: testSubscription, Tenant: testTenant, AllowedSubscriptions: []core.Pair{{Subscription: testSubscription, Tenant: testTenant}}}
}
func subscriptionRequest(t *testing.T, cloud core.Cloud) Request {
	t.Helper()
	target, err := core.ParseTarget("/subscriptions/" + testSubscription)
	if err != nil {
		t.Fatal(err)
	}
	return Request{Binding: binding(cloud), Purpose: "request", Method: "GET", Target: target, APIVersion: core.SubscriptionsAPIVersion, Pin: NewIdentityPin()}
}
func hostFor(t *testing.T, client *Client, options core.ContextOptions) *Host {
	t.Helper()
	host, err := NewHost(HostConfig{Context: options, Client: client, CorrelationID: "azmcp-test-synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	return host
}
func argsJSON(value any) json.RawMessage {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}
func assertHostCode(t *testing.T, err error, code string) {
	t.Helper()
	var failure *HostError
	if !errors.As(err, &failure) || failure.Code != code {
		t.Fatalf("got %v, want %s", err, code)
	}
}

func TestHTTPExplicitIdentityAudienceAndHeaders(t *testing.T) {
	credentials := &fakeCredentials{}
	server := simulator(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-http-token" || r.URL.Query().Get("api-version") != core.SubscriptionsAPIVersion {
			t.Error("request not signed with explicit audience/version")
		}
		w.Header().Set("Set-Cookie", "secret")
		w.Header().Set("X-Ms-Request-Id", "synthetic-request")
		io.WriteString(w, `{"ok":true}`)
	})
	client := loopbackClient(t, credentials, server)
	response, err := client.Execute(context.Background(), subscriptionRequest(t, core.Government))
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != 200 || response.Headers["set-cookie"] != "" || response.Headers["x-ms-request-id"] != "synthetic-request" {
		t.Fatal(response)
	}
	if credentials.calls() != 1 || credentials.requests[0].Audience != core.Government.Audience("request") {
		t.Fatal(credentials.requests)
	}
}
func TestHTTPDenialsBeforeCredentialsOrNetwork(t *testing.T) {
	credentials := &fakeCredentials{}
	var requests atomic.Int32
	server := simulator(t, func(w http.ResponseWriter, r *http.Request) { requests.Add(1); io.WriteString(w, `{}`) })
	client := loopbackClient(t, credentials, server)
	for _, mutate := range []func(*Request){func(r *Request) { r.APIVersion = "wrong" }, func(r *Request) { r.Headers = map[string]string{"Authorization": "inject"} }, func(r *Request) { r.Binding.Subscription = testWorkspace }, func(r *Request) {
		r.Target, _ = core.ParseTarget("/subscriptions/" + testSubscription + "/notReviewed")
	}, func(r *Request) { r.Target.Query = []core.QueryPair{{Name: "api-version", Value: "override"}} }} {
		r := subscriptionRequest(t, core.Commercial)
		mutate(&r)
		if _, err := client.Execute(context.Background(), r); err == nil {
			t.Fatal("accepted denied request")
		}
	}
	if credentials.calls() != 0 || requests.Load() != 0 {
		t.Fatal("local denial reached credential or socket")
	}
	if _, err := NewLoopbackClient(credentials, reviewedPolicy(t), "https://management.azure.com/"); err == nil {
		t.Fatal("production origin accepted as simulator")
	}
}

func TestHTTPCanceledCallDoesNotAcquireCredentials(t *testing.T) {
	credentials := &fakeCredentials{}
	var requests atomic.Int32
	server := simulator(t, func(w http.ResponseWriter, r *http.Request) { requests.Add(1) })
	client := loopbackClient(t, credentials, server)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Execute(ctx, subscriptionRequest(t, core.Commercial)); err == nil {
		t.Fatal("canceled call succeeded")
	}
	if credentials.calls() != 0 || requests.Load() != 0 {
		t.Fatal("canceled call reached credentials or socket")
	}
}
func TestHTTPRetriesRedirectCapsAndCancellation(t *testing.T) {
	var attempts atomic.Int32
	credentials := &fakeCredentials{}
	server := simulator(t, func(w http.ResponseWriter, r *http.Request) {
		attempt := attempts.Add(1)
		w.Header().Set("Retry-After", "0")
		if attempt < 3 {
			w.WriteHeader(503)
		}
		io.WriteString(w, `{"ok":true}`)
	})
	client := loopbackClient(t, credentials, server)
	response, err := client.Execute(context.Background(), subscriptionRequest(t, core.Commercial))
	if err != nil || response.RetryCount != 2 || attempts.Load() != 3 || credentials.calls() != 1 {
		t.Fatalf("retry lifecycle: %#v %v", response, err)
	}
	redirect := simulator(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://127.0.0.1:1/never")
		w.WriteHeader(302)
	})
	client = loopbackClient(t, &fakeCredentials{}, redirect)
	if _, err := client.Execute(context.Background(), subscriptionRequest(t, core.Commercial)); err == nil {
		t.Fatal("followed redirect")
	}
	large := simulator(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		io.WriteString(w, strings.Repeat("x", 1000))
	})
	limits := DefaultLimits()
	limits.ResponseBytes = 128
	client, err = NewLoopbackClientWithLimits(&fakeCredentials{}, reviewedPolicy(t), large.URL, limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	if _, err := client.Execute(context.Background(), subscriptionRequest(t, core.Commercial)); err == nil {
		t.Fatal("response cap ignored")
	}
	slow := simulator(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		io.WriteString(w, `{}`)
	})
	client = loopbackClient(t, &fakeCredentials{}, slow)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := client.Execute(ctx, subscriptionRequest(t, core.Commercial)); err == nil || time.Since(started) > time.Second {
		t.Fatal("HTTP cancellation ignored")
	}
}
func TestHostHelpersShapeScopeAndAudience(t *testing.T) {
	credentials := &fakeCredentials{}
	var mu sync.Mutex
	var requests []struct{ path, query, body string }
	server := simulator(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		requests = append(requests, struct{ path, query, body string }{r.URL.Path, r.URL.RawQuery, string(body)})
		mu.Unlock()
		if strings.Contains(r.URL.Path, "/workspaces/") {
			io.WriteString(w, `{"tables":[{"name":"PrimaryResult","columns":[{"name":"Value","type":"long"}],"rows":[[42]]}]}`)
		} else {
			io.WriteString(w, `{"value":[42]}`)
		}
	})
	options := core.DefaultOptions([]core.ResolvedBinding{binding(core.Commercial)})
	options.DataPlanes = []string{"logs.query"}
	options.LogsScopes[core.Commercial] = "allAccessible"
	host := hostFor(t, loopbackClient(t, credentials, server), options)
	resource := "/subscriptions/" + testSubscription + "/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
	cases := []struct {
		method       string
		arguments    any
		wantAudience string
	}{
		{"azure_request", map[string]any{"cloud": "AzureCloud", "method": "GET", "path": "/", "apiVersion": core.SubscriptionsAPIVersion}, core.Commercial.Audience("request")},
		{"azure_graph", map[string]any{"cloud": "AzureCloud", "query": "secret-query"}, core.Commercial.Audience("resourceGraph")},
		{"azure_metrics_single", map[string]any{"cloud": "AzureCloud", "resourceId": resource, "metricNames": []string{"CPU"}, "timespan": "PT1H", "filter": "Name eq 'x'"}, core.Commercial.Audience("metricsSingle")},
		{"azure_metrics_batch", map[string]any{"cloud": "AzureCloud", "region": "EASTUS", "resourceIds": []string{resource}, "metricNames": []string{"CPU"}, "metricNamespace": "Microsoft.Compute/virtualMachines"}, core.Commercial.Audience("metricsBatch")},
		{"azure_logs_query", map[string]any{"cloud": "AzureCloud", "workspaceId": testWorkspace, "query": "secret-log-query", "timespan": "PT1H"}, core.Commercial.Audience("logsQuery")},
	}
	for _, test := range cases {
		raw, err := host.Call(context.Background(), test.method, argsJSON(test.arguments))
		if err != nil {
			t.Fatalf("%s: %v", test.method, err)
		}
		if !json.Valid(raw) {
			t.Fatal("helper returned invalid JSON")
		}
	}
	for i, test := range cases {
		if credentials.requests[i].Audience != test.wantAudience {
			t.Fatalf("%s wrong audience: %#v", test.method, credentials.requests[i])
		}
		if host.Records().Calls[i].Operation != test.method {
			t.Fatalf("%s audit operation did not retain the public tool name", test.method)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Contains(requests[4].query, "api-version") {
		t.Fatal("logs data plane inherited ARM API query")
	}
	if !strings.Contains(requests[1].body, testSubscription) || !strings.Contains(requests[3].body, "resourceids") {
		t.Fatal("scope or metrics body omitted")
	}
	records, _ := json.Marshal(host.Records())
	if strings.Contains(string(records), "secret-query") || strings.Contains(string(records), "secret-log-query") || strings.Contains(string(records), "Bearer") {
		t.Fatal("audit records contain query or bearer")
	}
}

func TestHostRejectsLegacyOperationAliases(t *testing.T) {
	credentials := &fakeCredentials{}
	server := simulator(t, func(w http.ResponseWriter, r *http.Request) { t.Error("unknown operation reached socket") })
	host := hostFor(t, loopbackClient(t, credentials, server), core.DefaultOptions([]core.ResolvedBinding{binding(core.Commercial)}))
	for _, method := range []string{"az.request", "az.graph", "az.metrics.single", "az.metrics.batch", "az.logs.query"} {
		_, err := host.Call(context.Background(), method, json.RawMessage(`{}`))
		assertHostCode(t, err, "protocol_error")
	}
	if credentials.calls() != 0 || len(host.Records().Calls) != 0 {
		t.Fatal("legacy aliases entered the authorized operation path")
	}
}

func TestHostDenialsAndAuditGate(t *testing.T) {
	credentials := &fakeCredentials{}
	var requests atomic.Int32
	server := simulator(t, func(w http.ResponseWriter, r *http.Request) { requests.Add(1); io.WriteString(w, `{}`) })
	client := loopbackClient(t, credentials, server)
	options := core.DefaultOptions([]core.ResolvedBinding{binding(core.Commercial)})
	host := hostFor(t, client, options)
	for _, test := range []struct {
		method string
		raw    string
		code   string
	}{
		{"azure_request", `{"method":"GET","path":"/","apiVersion":"2020-01-01"}`, "cloud_required"},
		{"azure_request", `{"cloud":"AzureCloud","method":"GET","path":"/","apiVersion":"2020-01-01","headers":{"Authorization":"x"}}`, "invalid_request"},
		{"azure_graph", `{"cloud":"AzureCloud","query":"q","scope":"allAccessible"}`, "capability_denied"},
		{"azure_logs_query", fmt.Sprintf(`{"cloud":"AzureCloud","workspaceId":"%s","query":"q","timespan":"PT1H"}`, testWorkspace), "capability_denied"},
		{"azure_request", `{"cloud":"AzureCloud","method":"GET","path":"/","apiVersion":"2020-01-01","unknown":true}`, "invalid_request"},
	} {
		_, err := host.Call(context.Background(), test.method, json.RawMessage(test.raw))
		assertHostCode(t, err, test.code)
	}
	if credentials.calls() != 0 || requests.Load() != 0 {
		t.Fatal("denials crossed transport")
	}
	host, err := NewHost(HostConfig{Context: options, Client: client, CorrelationID: "azmcp-test-synthetic", PrepareAudit: func() error { return errors.New("disk unavailable") }})
	if err != nil {
		t.Fatal(err)
	}
	_, err = host.Call(context.Background(), "azure_request", argsJSON(map[string]any{"cloud": "AzureCloud", "method": "GET", "path": "/", "apiVersion": core.SubscriptionsAPIVersion}))
	assertHostCode(t, err, "audit_unavailable")
	if credentials.calls() != 0 {
		t.Fatal("audit prepare failure reached credentials")
	}
}
func TestBindingValidationChecksResponseAndAudits(t *testing.T) {
	credentials := &fakeCredentials{}
	server := simulator(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, fmt.Sprintf(`{"subscriptionId":"%s"}`, testWorkspace))
	})
	options := core.DefaultOptions([]core.ResolvedBinding{binding(core.Commercial)})
	var records []CallRecord
	host, err := NewHost(HostConfig{Context: options, Client: loopbackClient(t, credentials, server), CorrelationID: "azmcp-test-synthetic", Audit: func(record CallRecord) error { records = append(records, record); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	err = host.ValidateBinding(context.Background(), binding(core.Commercial))
	assertHostCode(t, err, "subscription_mismatch")
	if len(records) != 1 || records[0].Operation != "context.validate" || records[0].Reason == nil || *records[0].Reason != "validation_failed" {
		t.Fatalf("wrong validation audit: %#v", records)
	}
}
func TestHostPrincipalChangeIsFatalContextSignal(t *testing.T) {
	credentials := &fakeCredentials{}
	server := simulator(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{}`) })
	host := hostFor(t, loopbackClient(t, credentials, server), core.DefaultOptions([]core.ResolvedBinding{binding(core.Commercial)}))
	args := argsJSON(map[string]any{"cloud": "AzureCloud", "method": "GET", "path": "/", "apiVersion": core.SubscriptionsAPIVersion})
	if _, err := host.Call(context.Background(), "azure_request", args); err != nil {
		t.Fatal(err)
	}
	credentials.mu.Lock()
	credentials.principal = testWorkspace
	credentials.mu.Unlock()
	_, err := host.Call(context.Background(), "azure_request", args)
	assertHostCode(t, err, "authentication_required")
	if !host.PrincipalMismatch() || host.LastError() == nil || !host.LastError().IdentityMismatch {
		t.Fatal("principal mismatch signal omitted")
	}
}

func TestHostPrincipalChangeSignalSurvivesAuditFailure(t *testing.T) {
	credentials := &fakeCredentials{}
	server := simulator(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{}`) })
	failAudit := false
	host, err := NewHost(HostConfig{
		Context: core.DefaultOptions([]core.ResolvedBinding{binding(core.Commercial)}),
		Client:  loopbackClient(t, credentials, server), CorrelationID: "azmcp-test-synthetic",
		Audit: func(CallRecord) error {
			if failAudit {
				return errors.New("audit unavailable")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	args := argsJSON(map[string]any{"cloud": "AzureCloud", "method": "GET", "path": "/", "apiVersion": core.SubscriptionsAPIVersion})
	if _, err = host.Call(context.Background(), "azure_request", args); err != nil {
		t.Fatal(err)
	}
	credentials.mu.Lock()
	credentials.principal = testWorkspace
	credentials.mu.Unlock()
	failAudit = true
	_, err = host.Call(context.Background(), "azure_request", args)
	assertHostCode(t, err, "audit_unavailable")
	if !host.PrincipalMismatch() {
		t.Fatal("audit failure erased the fatal principal-mismatch signal")
	}
}

func TestLogsTimespanAndResponseShape(t *testing.T) {
	for _, value := range []string{"PT1H", "P30D", "P1DT2H3M4S"} {
		if !validTimespan(value) {
			t.Fatalf("valid timespan rejected: %s", value)
		}
	}
	for _, value := range []string{"P", "PT", "PT0S", "P31D", "P1M", "P1DT", " PT1H", "PT18446744073709551616S"} {
		if validTimespan(value) {
			t.Fatalf("invalid timespan accepted: %s", value)
		}
	}
	for _, raw := range []string{`{}`, `{"tables":null}`, `{"tables":[{"columns":[{"name":"x","type":"long"}],"rows":[[]]}]}`, `{"tables":[{"columns":[{"name":null,"type":"long"}],"rows":[]}]}`} {
		if validateLogsResponse([]byte(raw)) == nil {
			t.Fatalf("invalid logs response accepted: %s", raw)
		}
	}
}

func TestMetricsRegionRejectsUnicodeCaseAliases(t *testing.T) {
	if _, err := normalizeRegion("eastusK"); err == nil {
		t.Fatal("Unicode case folding produced an unadvertised regional origin")
	}
}

func TestMetricsBatchRejectsUnicodeMixedResourceTypes(t *testing.T) {
	credentials := &fakeCredentials{}
	server := simulator(t, func(w http.ResponseWriter, r *http.Request) { t.Error("mixed resource types reached socket") })
	host := hostFor(t, loopbackClient(t, credentials, server), core.DefaultOptions([]core.ResolvedBinding{binding(core.Commercial)}))
	_, err := host.Call(context.Background(), "azure_metrics_batch", argsJSON(map[string]any{
		"cloud": "AzureCloud", "region": "eastus", "metricNamespace": "Microsoft.Custom/kinds", "metricNames": []string{"Count"},
		"resourceIds": []string{
			"/subscriptions/" + testSubscription + "/providers/Microsoft.Custom/kinds/one",
			"/subscriptions/" + testSubscription + "/providers/Microsoft.Custom/Kinds/two",
		},
	}))
	assertHostCode(t, err, "invalid_request")
	if credentials.calls() != 0 {
		t.Fatal("mixed resource types reached credentials")
	}
}

func TestReviewedCloudOriginsAndAudiences(t *testing.T) {
	credentials := &fakeCredentials{}
	client, err := NewClient(credentials, reviewedPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, test := range []struct {
		cloud    core.Cloud
		purpose  string
		origin   string
		audience string
	}{
		{core.Commercial, "request", "https://management.azure.com/", "https://management.azure.com/"},
		{core.Commercial, "resourceGraph", "https://management.azure.com/", "https://management.azure.com/"},
		{core.Commercial, "metricsSingle", "https://management.azure.com/", "https://management.azure.com/"},
		{core.Commercial, "metricsBatch", "https://eastus.metrics.monitor.azure.com/", "https://metrics.monitor.azure.com/"},
		{core.Commercial, "logsQuery", "https://api.loganalytics.azure.com/", "https://api.loganalytics.io"},
		{core.Government, "request", "https://management.usgovcloudapi.net/", "https://management.usgovcloudapi.net/"},
		{core.Government, "resourceGraph", "https://management.usgovcloudapi.net/", "https://management.usgovcloudapi.net/"},
		{core.Government, "metricsSingle", "https://management.usgovcloudapi.net/", "https://management.usgovcloudapi.net/"},
		{core.Government, "metricsBatch", "https://eastus.metrics.monitor.azure.us/", "https://metrics.monitor.azure.us/"},
		{core.Government, "logsQuery", "https://api.loganalytics.us/", "https://api.loganalytics.us"},
	} {
		origin, err := client.origin(Request{Binding: binding(test.cloud), Purpose: test.purpose, Region: "EASTUS"})
		if err != nil || origin.String() != test.origin || test.cloud.Audience(test.purpose) != test.audience {
			t.Fatalf("%s/%s origin or token audience changed: %v %v", test.cloud, test.purpose, origin, err)
		}
	}
	if credentials.calls() != 0 {
		t.Fatal("origin construction acquired credentials")
	}
}

func TestHostWithholdsResultWhenAuditAppendFails(t *testing.T) {
	credentials := &fakeCredentials{}
	server := simulator(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"sensitive":"result"}`) })
	host, err := NewHost(HostConfig{
		Context: core.DefaultOptions([]core.ResolvedBinding{binding(core.Commercial)}),
		Client:  loopbackClient(t, credentials, server), CorrelationID: "azmcp-test-synthetic",
		Audit: func(CallRecord) error { return errors.New("disk unavailable") },
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := host.Call(context.Background(), "azure_request", argsJSON(map[string]any{"cloud": "AzureCloud", "method": "GET", "path": "/", "apiVersion": core.SubscriptionsAPIVersion}))
	assertHostCode(t, err, "audit_unavailable")
	if len(raw) != 0 {
		t.Fatal("audit failure exposed the successful upstream result")
	}
}
