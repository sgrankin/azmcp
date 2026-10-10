package server

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

type callerFunc func(context.Context, string, json.RawMessage) (any, error)

func (f callerFunc) Call(ctx context.Context, name string, args json.RawMessage) (any, error) {
	return f(ctx, name, args)
}

type wireClient struct {
	input  *io.PipeWriter
	output *bufio.Reader
	done   chan error
}

func newWire(t *testing.T, caller ToolCaller) *wireClient {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	go func() { err := Serve(context.Background(), inR, outW, caller); outW.Close(); done <- err }()
	client := &wireClient{inW, bufio.NewReader(outR), done}
	t.Cleanup(func() {
		inW.Close()
		outR.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("MCP server did not stop")
		}
	})
	return client
}
func (c *wireClient) send(t *testing.T, request any) {
	t.Helper()
	raw, err := marshalJSON(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.input.Write(append(raw, '\n')); err != nil {
		t.Fatal(err)
	}
}
func (c *wireClient) receive(t *testing.T) map[string]any {
	t.Helper()
	type received struct {
		raw []byte
		err error
	}
	ready := make(chan received, 1)
	go func() { raw, err := c.output.ReadBytes('\n'); ready <- received{raw, err} }()
	select {
	case r := <-ready:
		if r.err != nil {
			t.Fatal(r.err)
		}
		var response map[string]any
		if json.Unmarshal(r.raw, &response) != nil {
			t.Fatal("invalid response JSON")
		}
		return response
	case <-time.After(3 * time.Second):
		t.Fatal("MCP response timed out")
		return nil
	}
}
func modernMeta(version string) map[string]any {
	return map[string]any{protocolKey: version, capabilitiesKey: map[string]any{}, "io.modelcontextprotocol/clientInfo": map[string]string{"name": "synthetic", "version": "1"}}
}
func request(id int, method string, params any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}
}
func initializeWire(t *testing.T, c *wireClient, version string) {
	c.send(t, request(1, "initialize", map[string]any{"protocolVersion": version, "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "synthetic", "version": "1"}}))
	response := c.receive(t)
	if response["error"] != nil {
		t.Fatal(response)
	}
	if response["result"].(map[string]any)["protocolVersion"] != version {
		t.Fatal("negotiated revision changed")
	}
	c.send(t, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
}
func TestMCPReviewedRevisionsHaveVersionSpecificEnvelopes(t *testing.T) {
	for _, version := range supportedVersions {
		t.Run(version, func(t *testing.T) {
			c := newWire(t, callerFunc(func(ctx context.Context, name string, args json.RawMessage) (any, error) {
				return map[string]any{"accounts": []any{}}, nil
			}))
			modern := version == "2026-07-28"
			if modern {
				c.send(t, request(1, "server/discover", map[string]any{"_meta": modernMeta(version)}))
				discovery := c.receive(t)["result"].(map[string]any)
				if discovery["resultType"] != "complete" || discovery["ttlMs"] != float64(60000) || discovery["cacheScope"] != "public" || len(discovery["supportedVersions"].([]any)) != 3 {
					t.Fatal(discovery)
				}
			} else {
				initializeWire(t, c, version)
			}
			params := map[string]any{}
			if modern {
				params["_meta"] = modernMeta(version)
			}
			c.send(t, request(2, "tools/list", params))
			tools := c.receive(t)["result"].(map[string]any)
			if len(tools["tools"].([]any)) != 6 || tools["_meta"] == nil {
				t.Fatal(tools)
			}
			_, cache := tools["ttlMs"]
			_, complete := tools["resultType"]
			if cache != modern || complete != modern {
				t.Fatal("incorrect catalog envelope", tools)
			}
			call := map[string]any{"name": "azure_accounts", "arguments": map[string]any{}}
			if modern {
				call["_meta"] = modernMeta(version)
			}
			c.send(t, request(3, "tools/call", call))
			result := c.receive(t)["result"].(map[string]any)
			if result["isError"] != false || result["structuredContent"] == nil || result["_meta"] == nil {
				t.Fatal(result)
			}
			_, complete = result["resultType"]
			if complete != modern {
				t.Fatal("incorrect call envelope", result)
			}
			var text map[string]any
			if json.Unmarshal([]byte(result["content"].([]any)[0].(map[string]any)["text"].(string)), &text) != nil || text["accounts"] == nil {
				t.Fatal("structured content text disagrees")
			}
		})
	}
}
func TestMCPStatelessLifecycleRequiresMetadataForEveryRequest(t *testing.T) {
	c := newWire(t, callerFunc(func(context.Context, string, json.RawMessage) (any, error) { return nil, nil }))
	c.send(t, request(1, "server/discover", map[string]any{}))
	response := c.receive(t)
	if response["error"].(map[string]any)["code"] != float64(-32602) {
		t.Fatal(response)
	}
	c.send(t, request(2, "tools/list", map[string]any{"_meta": modernMeta("2025-06-18")}))
	result := c.receive(t)["result"].(map[string]any)
	if result["ttlMs"] != nil || result["resultType"] != nil {
		t.Fatal("inline older revision got modern fields")
	}
	c.send(t, request(3, "tools/list", map[string]any{}))
	response = c.receive(t)
	if response["error"].(map[string]any)["code"] != float64(-32602) {
		t.Fatal(response)
	}
	c.send(t, request(4, "tools/list", map[string]any{"_meta": modernMeta("2099-01-01")}))
	response = c.receive(t)
	if response["error"].(map[string]any)["code"] != float64(-32022) {
		t.Fatal(response)
	}
	c.send(t, request(5, "initialize", map[string]any{"protocolVersion": "2025-06-18"}))
	response = c.receive(t)
	if response["error"].(map[string]any)["code"] != float64(-32600) {
		t.Fatal(response)
	}
	c.send(t, request(6, "server/discover", map[string]any{"_meta": modernMeta("2025-11-25")}))
	response = c.receive(t)
	if response["error"].(map[string]any)["code"] != float64(-32601) {
		t.Fatal(response)
	}
}
func TestMCPLegacyPingAndRejectedInitializeTerminatesHandshake(t *testing.T) {
	for _, version := range []string{"2026-07-28", "2024-11-05", "2099-01-01"} {
		t.Run(version, func(t *testing.T) {
			c := newWire(t, callerFunc(func(context.Context, string, json.RawMessage) (any, error) { return nil, nil }))
			c.send(t, request(0, "ping", map[string]any{}))
			if c.receive(t)["result"] == nil {
				t.Fatal("legacy pre-initialize ping failed")
			}
			c.send(t, request(1, "initialize", map[string]any{"protocolVersion": version, "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "synthetic", "version": "1"}}))
			response := c.receive(t)
			if response["error"].(map[string]any)["code"] != float64(-32602) {
				t.Fatal(response)
			}
			if _, err := c.output.ReadByte(); err != io.EOF {
				t.Fatalf("rejected legacy handshake remained open: %v", err)
			}
		})
	}
	c := newWire(t, callerFunc(func(context.Context, string, json.RawMessage) (any, error) { return nil, nil }))
	c.send(t, request(0, "ping", map[string]any{}))
	c.receive(t)
	initializeWire(t, c, "2025-11-25")
}
func TestMCPClosedArgumentsRejectCaseAliasesDuplicatesAndUnsupportedGrants(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	c := newWire(t, callerFunc(func(context.Context, string, json.RawMessage) (any, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		return nil, nil
	}))
	initializeWire(t, c, "2025-06-18")
	for _, raw := range []string{
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"azure_accounts","arguments":{"anything":1}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"azure_context_open","arguments":{"bindings":{"AzureChinaCloud":{"subscription":"11111111-1111-1111-1111-111111111111"}}}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"azure_context_open","arguments":{"dataPlanes":["storage.read"]}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"azure_context_close","arguments":{"ContextId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"azure_context_close","arguments":{"contextId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","contextId":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
	} {
		if _, err := c.input.Write([]byte(raw + "\n")); err != nil {
			t.Fatal(err)
		}
		response := c.receive(t)
		if response["error"] == nil {
			t.Fatal("invalid args reached caller", response)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 0 {
		t.Fatal("rejected inputs executed tools")
	}
}
func TestMCPFirstStatelessToolCallCanBeCancelledWhileReaderContinues(t *testing.T) {
	entered := make(chan struct{})
	c := newWire(t, callerFunc(func(ctx context.Context, name string, args json.RawMessage) (any, error) {
		close(entered)
		<-ctx.Done()
		return nil, failure("context_evicted")
	}))
	c.send(t, request(1, "tools/call", map[string]any{"_meta": modernMeta("2026-07-28"), "name": "azure_accounts", "arguments": map[string]any{}}))
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first stateless call did not start")
	}
	c.send(t, map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": 1}})
	result := c.receive(t)["result"].(map[string]any)
	if result["isError"] != true || result["structuredContent"].(map[string]any)["code"] != "context_evicted" {
		t.Fatal(result)
	}
	c.send(t, request(2, "tools/list", map[string]any{"_meta": modernMeta("2026-07-28")}))
	if c.receive(t)["result"] == nil {
		t.Fatal("cancellation stopped unrelated requests")
	}
}
func TestMCPBoundedResultsContainOnlyShapeOfOversizedValue(t *testing.T) {
	value := map[string]any{"records": strings.Repeat("PRIVATE-VALUE", 100000)}
	result, rpcErr := toolResult(value, nil, "2026-07-28")
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	raw, _ := marshalJSON(result)
	if len(raw) > maxToolResultBytes || strings.Contains(string(raw), "PRIVATE-VALUE") {
		t.Fatal("oversized value escaped bounded transport")
	}
	fields := result.(map[string]any)
	if fields["isError"] != true || fields["structuredContent"].(map[string]any)["code"] != "result_too_large" {
		t.Fatal(result)
	}
}

func TestMCPRequestIDsUseSignedIntegersOrDecodedStrings(t *testing.T) {
	for _, raw := range []string{`-0`, `1.0`, `1.5`, `1e0`, `9223372036854775808`, `-9223372036854775809`, `null`, `true`, `{}`} {
		if validRequestID(json.RawMessage(raw)) {
			t.Errorf("unsupported request ID accepted: %s", raw)
		}
	}
	for _, raw := range []string{`0`, `9223372036854775807`, `-9223372036854775808`, `""`, `"a"`} {
		if !validRequestID(json.RawMessage(raw)) {
			t.Errorf("supported request ID rejected: %s", raw)
		}
	}
	if requestIDKey(json.RawMessage(`"a"`)) != requestIDKey(json.RawMessage(`"\u0061"`)) {
		t.Fatal("equivalent request IDs differ")
	}
	if requestIDKey(json.RawMessage(`"0"`)) == requestIDKey(json.RawMessage(`0`)) {
		t.Fatal("string and numeric IDs share a namespace")
	}
}

func TestMCPUsesExactProtocolFieldNamesAndOpenExtensions(t *testing.T) {
	c := newWire(t, callerFunc(func(_ context.Context, _ string, args json.RawMessage) (any, error) {
		return map[string]any{"arguments": args}, nil
	}))
	initializeWire(t, c, "2025-11-25")
	for _, raw := range []string{
		`{"JSONRPC":"2.0","id":2,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":2,"METHOD":"ping"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"Name":"azure_accounts","arguments":{}}}`,
	} {
		c.send(t, json.RawMessage(raw))
		if response := c.receive(t); response["error"] == nil {
			t.Fatal("case alias accepted", response)
		}
	}
	c.send(t, json.RawMessage(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"azure_accounts","Arguments":{"ignored":true},"future":1},"future":1}`))
	response := c.receive(t)
	if response["error"] != nil {
		t.Fatal("open extension rejected", response)
	}
	arguments := response["result"].(map[string]any)["structuredContent"].(map[string]any)["arguments"].(map[string]any)
	if len(arguments) != 0 {
		t.Fatal("case alias replaced optional canonical arguments", arguments)
	}
	// An ID alias is an ignored extension, so this message remains a notification.
	c.send(t, json.RawMessage(`{"jsonrpc":"2.0","ID":4,"method":"ping"}`))
	c.send(t, request(5, "ping", nil))
	if response := c.receive(t); response["id"] != float64(5) {
		t.Fatal("ID alias became a request", response)
	}
}

func TestMCPInitializeUsesExactKnownFieldNames(t *testing.T) {
	for _, params := range []string{
		`{"ProtocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"synthetic","version":"1"}}`,
		`{"protocolVersion":"2025-11-25","Capabilities":{},"clientInfo":{"name":"synthetic","version":"1"}}`,
		`{"protocolVersion":"2025-11-25","capabilities":{},"ClientInfo":{"name":"synthetic","version":"1"}}`,
		`{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"Name":"synthetic","version":"1"}}`,
	} {
		c := newWire(t, callerFunc(func(context.Context, string, json.RawMessage) (any, error) { return nil, nil }))
		c.send(t, request(1, "initialize", json.RawMessage(params)))
		if response := c.receive(t); response["error"] == nil {
			t.Fatal("initialize case alias accepted", response)
		}
	}
	c := newWire(t, callerFunc(func(context.Context, string, json.RawMessage) (any, error) { return nil, nil }))
	c.send(t, request(1, "initialize", json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"","version":"","future":1},"future":1}`)))
	if response := c.receive(t); response["error"] != nil {
		t.Fatal("valid empty client strings or open extension rejected", response)
	}
}

func TestMCPJSONRejectsInvalidUnicodeBeforeDispatch(t *testing.T) {
	var calls int
	c := newWire(t, callerFunc(func(context.Context, string, json.RawMessage) (any, error) {
		calls++
		return map[string]any{}, nil
	}))
	initializeWire(t, c, "2025-11-25")
	for _, value := range []string{`"\ud800"`, `"\udc00"`, "\"\xff\""} {
		raw := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"azure_run","arguments":{"contextId":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","code":` + value + `}}}` + "\n")
		if _, err := c.input.Write(raw); err != nil {
			t.Fatal(err)
		}
		if response := c.receive(t); response["error"] == nil || response["error"].(map[string]any)["code"] != float64(-32700) {
			t.Fatal("invalid JSON Unicode accepted", response)
		}
	}
	if calls != 0 {
		t.Fatal("invalid JSON reached the tool caller")
	}
	for _, value := range []string{`"\ud83d\ude00"`, `"'\\ud800'"`} {
		c.send(t, json.RawMessage(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"azure_run","arguments":{"contextId":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","code":`+value+`}}}`))
		if response := c.receive(t); response["error"] != nil {
			t.Fatal("valid Unicode or escaped JS source rejected", response)
		}
	}
}

type blockedMCPWriter struct {
	io.WriteCloser
	entered chan struct{}
	once    sync.Once
}

func (w *blockedMCPWriter) Write(raw []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	return w.WriteCloser.Write(raw)
}

func TestMCPServeCancellationInterruptsBlockedOutput(t *testing.T) {
	input, inputWriter := io.Pipe()
	outputReader, outputWriter := io.Pipe()
	defer input.Close()
	defer inputWriter.Close()
	defer outputReader.Close()
	defer outputWriter.Close()
	output := &blockedMCPWriter{WriteCloser: outputWriter, entered: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, input, output, callerFunc(func(context.Context, string, json.RawMessage) (any, error) { return nil, nil }))
	}()
	if _, err := inputWriter.Write([]byte("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-output.entered:
	case <-time.After(time.Second):
		t.Fatal("control never reached blocked output")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		outputReader.Close()
		<-done
		t.Fatal("canceled server remained blocked on output")
	}
}

func TestMCPNotificationCannotOpenLegacyHandshake(t *testing.T) {
	for _, preinitPing := range []bool{false, true} {
		c := newWire(t, callerFunc(func(context.Context, string, json.RawMessage) (any, error) { return nil, nil }))
		if preinitPing {
			c.send(t, request(1, "ping", nil))
			c.receive(t)
		}
		c.send(t, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
		ready := make(chan error, 1)
		go func() { _, err := c.output.ReadByte(); ready <- err }()
		select {
		case err := <-ready:
			if err != io.EOF {
				t.Fatal("invalid legacy opener did not close the handshake", err)
			}
		case <-time.After(time.Second):
			t.Fatal("notification left legacy handshake open")
		}
	}
}

func TestMCPClientCapabilitiesRetainKnownTypesAndOpenExtensions(t *testing.T) {
	c := newWire(t, callerFunc(func(context.Context, string, json.RawMessage) (any, error) { return nil, nil }))
	invalid := []string{
		`{"roots":{"listChanged":"yes"}}`,
		`{"sampling":{"tools":false}}`,
		`{"extensions":{"io.test":[1]}}`,
		`{"experimental":{"io.test":null}}`,
		`{"elicitation":{"form":{"schemaValidation":1}}}`,
	}
	for i, caps := range invalid {
		meta := modernMeta("2026-07-28")
		meta[capabilitiesKey] = json.RawMessage(caps)
		c.send(t, request(i+1, "server/discover", map[string]any{"_meta": meta}))
		response := c.receive(t)
		if response["error"] == nil || response["error"].(map[string]any)["code"] != float64(-32602) {
			t.Fatal("malformed capability accepted", response)
		}
	}
	valid := []string{
		`{"roots":null,"sampling":null,"elicitation":null,"extensions":null,"experimental":null}`,
		`{"roots":{"listChanged":true,"future":"open"},"sampling":{"tools":{},"context":null}}`,
		`{"extensions":{"io.test":{"any":[1,true]}},"future":1,"ROOTS":false}`,
		`{"elicitation":{"form":{"schemaValidation":null},"url":{}}}`,
	}
	for i, caps := range valid {
		meta := modernMeta("2026-07-28")
		meta[capabilitiesKey] = json.RawMessage(caps)
		c.send(t, request(i+100, "server/discover", map[string]any{"_meta": meta}))
		if response := c.receive(t); response["error"] != nil {
			t.Fatal("valid capability extension rejected", response)
		}
	}
}

func TestMCPPingWithEmptyVersionSelectsStatelessLifecycle(t *testing.T) {
	c := newWire(t, callerFunc(func(context.Context, string, json.RawMessage) (any, error) { return nil, nil }))
	c.send(t, request(1, "ping", map[string]any{"_meta": modernMeta("")}))
	if response := c.receive(t); response["error"] == nil || response["error"].(map[string]any)["code"] != float64(-32022) {
		t.Fatal("empty advertised revision selected legacy ping", response)
	}
	c.send(t, request(2, "initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "synthetic", "version": "1"}}))
	if response := c.receive(t); response["error"] == nil || response["error"].(map[string]any)["code"] != float64(-32600) {
		t.Fatal("stateless lifecycle switched to initialize", response)
	}
}

func TestMCPServeCancellationInterruptsIdleInput(t *testing.T) {
	input, writer := io.Pipe()
	defer input.Close()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, input, io.Discard, callerFunc(func(context.Context, string, json.RawMessage) (any, error) { return nil, nil }))
	}()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		writer.Close()
		<-done
		t.Fatal("canceled server remained blocked on idle input")
	}
}
