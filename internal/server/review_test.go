package server

import (
	"azmcp/internal/worker"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMCPCancellationMatchesDecodedStringRequestID(t *testing.T) {
	entered := make(chan struct{})
	cancelled := make(chan struct{})
	c := newWire(t, callerFunc(func(ctx context.Context, _ string, _ json.RawMessage) (any, error) {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		return nil, failure("context_evicted")
	}))
	c.send(t, map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(`"\u0061"`), "method": "tools/call", "params": map[string]any{"_meta": modernMeta("2026-07-28"), "name": "azure_accounts", "arguments": map[string]any{}}})
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("request did not start")
	}
	c.send(t, map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": "a"}})
	select {
	case <-cancelled:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("semantically identical JSON request ID did not cancel the call")
	}
	if c.receive(t)["result"] == nil {
		t.Fatal("missing cancellation result")
	}
}

func TestWorkerTerminationReapsProcessWithUndrainedFrames(t *testing.T) {
	path := filepath.Join(canonicalTemp(t), "synthetic-worker")
	script := "#!/bin/sh\n" +
		"printf '%s\\n' '{\"type\":\"ready\",\"protocol\":1}'\n" +
		"printf '%s\\n' '{\"type\":\"closed\",\"id\":1}' '{\"type\":\"closed\",\"id\":2}' '{\"type\":\"closed\",\"id\":3}'\n" +
		"exec /bin/sleep 30\n"
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	handle, err := StartWorker(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handle.Terminate() })
	process := handle.(*ProcessWorker)
	limit := time.After(time.Second)
	for len(process.frames) == 0 {
		select {
		case <-limit:
			t.Fatal("synthetic worker did not queue a frame")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	started := time.Now()
	if err = handle.Terminate(); err != nil {
		t.Fatalf("termination did not reap the process: %v after %s", err, time.Since(started))
	}
	if time.Since(started) > time.Second {
		t.Fatal("termination waited for an undrained frame")
	}
}

func TestClosedAuditCannotBeReopenedByLateHostCompletion(t *testing.T) {
	path := filepath.Join(canonicalTemp(t), "requests.jsonl")
	audit, err := NewFileAudit(path, 64*1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err = audit.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = audit.Close() })
	if err = audit.Append(map[string]string{"operation": "synthetic"}); err == nil {
		t.Fatal("late host completion reopened the closed audit sink")
	}
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("closed audit created its destination", err)
	}
}

func TestFatalHostFailureCannotBeCaughtByJavaScript(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	handle, err := StartWorker(context.Background(), executable)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handle.Terminate() })
	_, err = handle.Execute(context.Background(), `try { az.artifacts.writeJson({name:"x.json", value:1}) } catch(_) {} 42`, time.Second, func(context.Context, worker.HostCallRequest) (json.RawMessage, error) {
		return nil, &Error{Code: "upstream_error", Message: messages["upstream_error"], Fatal: true}
	})
	if err == nil || !publicError(err).Fatal {
		t.Fatal("JavaScript caught a fatal host failure", err)
	}
}

func TestContextCloseRevokesReferencesHeldByInflightWork(t *testing.T) {
	app, _, _, _ := newSyntheticApp(t, nil)
	id := openSynthetic(t, app, nil)
	if _, err := runSynthetic(t, app, id, `"x".repeat(100000)`); err != nil {
		t.Fatal(err)
	}
	app.mu.Lock()
	slot := app.contexts[id]
	if slot.refs.bytes == 0 {
		app.mu.Unlock()
		t.Fatal("reference was not retained")
	}
	app.mu.Unlock()
	if err := app.close(id); err != nil {
		t.Fatal(err)
	}
	app.mu.Lock()
	defer app.mu.Unlock()
	if len(slot.refs.entries) != 0 || slot.refs.bytes != 0 {
		t.Fatal("closed context retained reference payloads in an in-flight slot")
	}
}

func TestArtifactValueAtSizeLimitFitsHostCallFrame(t *testing.T) {
	app, _, _, _ := newSyntheticApp(t, nil)
	id := openSynthetic(t, app, map[string]any{"localCapabilities": []string{"artifacts.write"}})
	result, err := runSynthetic(t, app, id, `az.artifacts.writeJson({name:"max.json",value:"x".repeat(480*1024-3)})`)
	if err != nil {
		t.Fatal("supported maximum artifact value did not fit the host frame", err)
	}
	receipt := valueJSON(t, result).(map[string]any)
	if receipt["bytes"] != float64(480*1024) {
		t.Fatal("artifact size limit changed", receipt)
	}
}

func TestArtifactStreamRejectsChangedHelperAndUnknownFields(t *testing.T) {
	app, _, _, _ := newSyntheticApp(t, nil)
	id := openSynthetic(t, app, map[string]any{"localCapabilities": []string{"artifacts.write"}})
	app.mu.Lock()
	namespace := app.contexts[id].namespace
	app.mu.Unlock()
	turn, err := app.config.Artifacts.BeginTurn(context.Background(), namespace)
	if err != nil {
		t.Fatal(err)
	}
	call := func(method string, args map[string]any) (json.RawMessage, error) {
		raw, err := marshalJSON(args)
		if err != nil {
			t.Fatal(err)
		}
		return app.artifactCall(context.Background(), turn, worker.HostCallRequest{Method: method, Arguments: raw}, "synthetic")
	}
	result, err := call("az.artifacts.writeJsonLines", map[string]any{"phase": "begin", "name": "rows.jsonl", "compression": "identity"})
	if err != nil {
		t.Fatal(err)
	}
	var started struct {
		StreamID string `json:"streamId"`
	}
	if json.Unmarshal(result, &started) != nil || started.StreamID == "" {
		t.Fatal("stream did not start")
	}
	for _, test := range []struct {
		method string
		args   map[string]any
	}{
		{"az.artifacts.writeJsonArray", map[string]any{"phase": "append", "streamId": started.StreamID, "sequence": 0, "values": []any{1}}},
		{"az.artifacts.writeJsonArray", map[string]any{"phase": "finish", "streamId": started.StreamID, "chunks": 0, "items": 0}},
		{"az.artifacts.writeJsonLines", map[string]any{"phase": "append", "streamId": started.StreamID, "Sequence": 0, "values": []any{1}}},
		{"az.artifacts.writeJsonLines", map[string]any{"phase": "append", "streamId": started.StreamID, "sequence": nil, "values": []any{1}}},
		{"az.artifacts.writeJsonLines", map[string]any{"phase": "finish", "streamId": started.StreamID, "chunks": nil, "items": 0}},
	} {
		if _, err := call(test.method, test.args); err == nil || publicError(err).Code != "invalid_request" {
			t.Fatal("stream accepted changed helper or field shape", test, err)
		}
	}
	if _, err := call("az.artifacts.writeJsonLines", map[string]any{"phase": "append", "streamId": started.StreamID, "sequence": 0, "values": []any{1}}); err != nil {
		t.Fatal("invalid attempts corrupted the stream", err)
	}
	if _, err := call("az.artifacts.writeJsonLines", map[string]any{"phase": "finish", "streamId": started.StreamID, "chunks": 1, "items": 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := call("az.artifacts.writeJsonLines", map[string]any{"phase": "abort", "streamId": started.StreamID}); err != nil {
		t.Fatal("stream abort stopped being idempotent", err)
	}
}
