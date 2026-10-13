package server

import (
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
