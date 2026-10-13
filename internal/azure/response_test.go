package azure

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"azmcp/internal/core"
)

func responseHost(t *testing.T, client *Client, limit int, options core.ContextOptions) *Host {
	t.Helper()
	host, err := NewHost(HostConfig{Context: options, Client: client, ResponseBytes: limit, CorrelationID: "synthetic-response-budget"})
	if err != nil {
		t.Fatal(err)
	}
	return host
}

func TestHostResponseBudgetsAreIndependent(t *testing.T) {
	body := `{"value":"` + strings.Repeat("x", 2*1024*1024) + `"}`
	server := simulator(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "must-not-release")
		io.WriteString(w, body)
	})
	credentials := &fakeCredentials{}
	client := loopbackClient(t, credentials, server)
	options := core.DefaultOptions([]core.ResolvedBinding{binding(core.Government)})
	ordinary := responseHost(t, client, 0, options)
	export := responseHost(t, client, 8*1024*1024, options)
	args := argsJSON(map[string]any{"cloud": "AzureUSGovernment", "method": "GET", "path": "/", "apiVersion": core.SubscriptionsAPIVersion})
	type result struct {
		host *Host
		raw  json.RawMessage
		err  error
	}
	results := make(chan result, 2)
	for _, host := range []*Host{ordinary, export} {
		go func() {
			raw, err := host.Call(context.Background(), "azure_request", args)
			results <- result{host, raw, err}
		}()
	}
	for range 2 {
		r := <-results
		if r.host == ordinary {
			assertHostCode(t, r.err, "response_too_large")
			if len(r.raw) != 0 {
				t.Fatal("ordinary call released an oversized response")
			}
		} else {
			if r.err != nil {
				t.Fatal("export response rejected:", r.err)
			}
			var decoded struct {
				Status  int               `json:"status"`
				Headers map[string]string `json:"headers"`
				Body    json.RawMessage   `json:"body"`
			}
			if json.Unmarshal(r.raw, &decoded) != nil || decoded.Status != 200 || string(decoded.Body) != body || decoded.Headers["set-cookie"] != "" {
				t.Fatal("export response shape or safe headers changed")
			}
		}
		records := r.host.Records()
		if len(records.Calls) != 1 || records.Calls[0].PathTemplate != "/subscriptions/{subscription}" || records.Calls[0].Decision != "allowed" {
			t.Fatalf("response budget bypassed reviewed audit: %#v", records)
		}
	}
	credentials.mu.Lock()
	defer credentials.mu.Unlock()
	if len(credentials.requests) != 2 {
		t.Fatal("wrong number of credential requests")
	}
	for _, request := range credentials.requests {
		if request.Cloud != core.Government || request.Audience != core.Government.Audience("request") {
			t.Fatal("response budget changed cloud or audience", request)
		}
	}
}

func TestHostExportResponseCeilingAndJSONValidation(t *testing.T) {
	for _, test := range []struct {
		name, body, code string
	}{
		{"exact ceiling", `"` + strings.Repeat("x", 8*1024*1024-2) + `"`, ""},
		{"over ceiling", `"` + strings.Repeat("x", 8*1024*1024-1) + `"`, "response_too_large"},
		{"malformed JSON", strings.Repeat("x", 2*1024*1024), "invalid_response"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := simulator(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", strconv.Itoa(len(test.body)))
				io.WriteString(w, test.body)
			})
			host := responseHost(t, loopbackClient(t, &fakeCredentials{}, server), 8*1024*1024, core.DefaultOptions([]core.ResolvedBinding{binding(core.Commercial)}))
			raw, err := host.Call(context.Background(), "azure_request", argsJSON(map[string]any{"cloud": "AzureCloud", "method": "GET", "path": "/", "apiVersion": core.SubscriptionsAPIVersion}))
			if test.code != "" {
				assertHostCode(t, err, test.code)
				if len(raw) != 0 {
					t.Fatal("invalid response released")
				}
			} else if err != nil || !json.Valid(raw) {
				t.Fatal("exact export ceiling rejected", err)
			}
		})
	}
}

func TestHostExportBudgetKeepsAuthorizationAndAuditGates(t *testing.T) {
	credentials := &fakeCredentials{}
	var requests atomic.Int32
	server := simulator(t, func(w http.ResponseWriter, r *http.Request) { requests.Add(1); io.WriteString(w, `{}`) })
	client := loopbackClient(t, credentials, server)
	options := core.DefaultOptions([]core.ResolvedBinding{binding(core.Commercial)})
	host := responseHost(t, client, 8*1024*1024, options)
	for _, test := range []struct {
		method string
		args   any
		code   string
	}{
		{"azure_request", map[string]any{"cloud": "AzureCloud", "method": "GET", "path": "/unreviewed", "apiVersion": core.SubscriptionsAPIVersion}, "route_denied"},
		{"azure_request", map[string]any{"cloud": "AzureCloud", "subscription": testWorkspace, "method": "GET", "path": "/", "apiVersion": core.SubscriptionsAPIVersion}, "subscription_mismatch"},
		{"azure_graph", map[string]any{"cloud": "AzureCloud", "query": "q", "scope": "allAccessible"}, "capability_denied"},
		{"azure_logs_query", map[string]any{"cloud": "AzureCloud", "workspaceId": testWorkspace, "query": "q", "timespan": "PT1H"}, "capability_denied"},
	} {
		_, err := host.Call(context.Background(), test.method, argsJSON(test.args))
		assertHostCode(t, err, test.code)
	}
	config := HostConfig{Context: options, Client: client, ResponseBytes: 8 * 1024 * 1024, CorrelationID: "synthetic-response-budget", PrepareAudit: func() error { return errors.New("unavailable") }}
	host, err := NewHost(config)
	if err != nil {
		t.Fatal(err)
	}
	args := argsJSON(map[string]any{"cloud": "AzureCloud", "method": "GET", "path": "/", "apiVersion": core.SubscriptionsAPIVersion})
	_, err = host.Call(context.Background(), "azure_request", args)
	assertHostCode(t, err, "audit_unavailable")
	if credentials.calls() != 0 || requests.Load() != 0 {
		t.Fatal("export budget bypassed a local denial")
	}
	config.PrepareAudit = nil
	config.Audit = func(CallRecord) error { return errors.New("unavailable") }
	host, err = NewHost(config)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := host.Call(context.Background(), "azure_request", args)
	assertHostCode(t, err, "audit_unavailable")
	if len(raw) != 0 || credentials.calls() != 1 || requests.Load() != 1 {
		t.Fatal("export budget bypassed durable result acceptance")
	}
}

func TestHostExportBudgetPreservesLogsResponseValidation(t *testing.T) {
	value := strings.Repeat("x", 2*1024*1024)
	for _, valid := range []bool{true, false} {
		t.Run(strconv.FormatBool(valid), func(t *testing.T) {
			body := `{"tables":[{"columns":[{"name":"Value","type":"string"}],"rows":[["` + value + `"]]}]}`
			if !valid {
				body = `{"tables":[{"rows":[["` + value + `"]]}]}`
			}
			server := simulator(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) })
			credentials := &fakeCredentials{}
			options := core.DefaultOptions([]core.ResolvedBinding{binding(core.Government)})
			options.DataPlanes = []string{"logs.query"}
			options.LogsScopes[core.Government] = "allAccessible"
			host := responseHost(t, loopbackClient(t, credentials, server), 8*1024*1024, options)
			raw, err := host.Call(context.Background(), "azure_logs_query", argsJSON(map[string]any{"cloud": "AzureUSGovernment", "workspaceId": testWorkspace, "query": "synthetic", "timespan": "PT1H"}))
			if !valid {
				assertHostCode(t, err, "invalid_response")
				if len(raw) != 0 {
					t.Fatal("invalid Logs table shape released")
				}
			} else if err != nil || string(raw) != body {
				t.Fatal("valid large Logs result rejected or wrapped", err)
			}
			credentials.mu.Lock()
			defer credentials.mu.Unlock()
			if len(credentials.requests) != 1 || credentials.requests[0].Audience != core.Government.Audience("logsQuery") {
				t.Fatal("export changed the Logs audience")
			}
		})
	}
}

func TestHostResponseBudgetRejectsInvalidLimits(t *testing.T) {
	server := simulator(t, func(w http.ResponseWriter, r *http.Request) { t.Error("invalid budget reached socket") })
	limits := DefaultLimits()
	limits.ResponseBytes = 2 * 1024 * 1024
	credentials := &fakeCredentials{}
	client, err := NewLoopbackClientWithLimits(credentials, reviewedPolicy(t), server.URL, limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	for _, limit := range []int{-1, 2*1024*1024 + 1, 8*1024*1024 + 1} {
		_, err := NewHost(HostConfig{Context: core.DefaultOptions([]core.ResolvedBinding{binding(core.Commercial)}), Client: client, ResponseBytes: limit, CorrelationID: "synthetic-response-budget"})
		assertHostCode(t, err, "invalid_request")
	}
	if credentials.calls() != 0 {
		t.Fatal("invalid response budget reached credentials")
	}
}

func TestHostWrapperKeepsHTMLHeavyJSONCompact(t *testing.T) {
	body := `{"value":"` + strings.Repeat("<>&", 32000) + `"}`
	wrapped, err := decodeResponse(Response{Status: 200, Headers: map[string]string{"content-type": "application/json"}, Body: []byte(body)}, false, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(wrapped) > len(body)+256 {
		t.Fatalf("response wrapper expanded a %d-byte JSON body to %d bytes", len(body), len(wrapped))
	}
	t.Logf("JSON body: %d bytes; response wrapper: %d bytes", len(body), len(wrapped))
	var response struct {
		Status  int               `json:"status"`
		Headers map[string]string `json:"headers"`
		Body    json.RawMessage   `json:"body"`
	}
	if json.Unmarshal(wrapped, &response) != nil || response.Status != 200 || response.Headers["content-type"] != "application/json" || string(response.Body) != body {
		t.Fatal("compact response wrapper changed JSON content or response metadata")
	}
}
