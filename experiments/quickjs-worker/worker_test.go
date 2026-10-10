package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func testEngine(t *testing.T) (*engine, chan inbound, chan []byte) {
	t.Helper()
	in := make(chan inbound, maxHostCalls+2)
	out := make(chan []byte, maxHostCalls+2)
	e, err := newEngine(in, out, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.close)
	return e, in, out
}

func executeTest(e *engine, id uint64, code string) (response, bool) {
	return e.execute(request{Type: "execute", ID: id, Code: code, TimeoutMS: 1000})
}

func resultValue(t *testing.T, r response) string {
	t.Helper()
	if r["type"] != "result" {
		t.Fatalf("expected result, got %#v", r)
	}
	return string(r["value"].(json.RawMessage))
}

func TestPersistentStateAndAwait(t *testing.T) {
	e, _, _ := testEngine(t)
	r, fatal := executeTest(e, 1, "let answer = 41; answer")
	if fatal || resultValue(t, r) != "41" {
		t.Fatalf("state initialization: %#v", r)
	}
	r, fatal = executeTest(e, 2, "++answer")
	if fatal || resultValue(t, r) != "42" {
		t.Fatalf("persistent lexical binding: %#v", r)
	}
	r, fatal = executeTest(e, 3, "await Promise.resolve({answer})")
	if fatal || resultValue(t, r) != `{"answer":42}` {
		t.Fatalf("await expression: %#v", r)
	}
	r, fatal = executeTest(e, 4, "const increment = await Promise.resolve(1); return answer + increment;")
	if fatal || resultValue(t, r) != "43" {
		t.Fatalf("async body: %#v", r)
	}
}

func TestThrownSyntaxErrorRunsOnce(t *testing.T) {
	e, _, _ := testEngine(t)
	r, _ := executeTest(e, 1, "globalThis.runs = 0; 0")
	resultValue(t, r)
	r, fatal := executeTest(e, 2, "runs++; throw new SyntaxError('intentional')")
	if fatal || r["code"] != "execution_error" {
		t.Fatalf("expected recoverable error: %#v", r)
	}
	r, _ = executeTest(e, 3, "runs")
	if resultValue(t, r) != "1" {
		t.Fatalf("script ran repeatedly: %#v", r)
	}
}

func TestNoAmbientGlobalsOrBridgeHandles(t *testing.T) {
	e, _, _ := testEngine(t)
	r, fatal := executeTest(e, 1, `['Deno','process','require','fetch','setTimeout','std','os','__azmcpSend','__azmcpComplete','__azmcpConsole','__azmcpHostCall','__azmcpSyncTransport'].map(k=>typeof globalThis[k])`)
	if fatal {
		t.Fatal(r)
	}
	var types []string
	if err := json.Unmarshal(r["value"].(json.RawMessage), &types); err != nil {
		t.Fatal(err)
	}
	for _, kind := range types {
		if kind != "undefined" {
			t.Fatalf("ambient global exposed: %#v", r)
		}
	}
}

func TestConcurrentHostCallsOutOfOrder(t *testing.T) {
	e, in, out := testEngine(t)
	hostDone := make(chan error, 1)
	go func() {
		var first, second struct {
			ID     uint64 `json:"id"`
			CallID uint64 `json:"call_id"`
			Method string `json:"method"`
		}
		if err := json.Unmarshal(<-out, &first); err != nil {
			hostDone <- err
			return
		}
		if err := json.Unmarshal(<-out, &second); err != nil {
			hostDone <- err
			return
		}
		if first.Method != "az.graph" || second.Method != "az.request" || first.CallID == second.CallID {
			hostDone <- fmt.Errorf("unexpected calls: %#v %#v", first, second)
			return
		}
		in <- inbound{request: request{Type: "host_call_result", ID: second.ID, CallID: second.CallID, OK: true, Value: json.RawMessage(`{"value":2}`)}}
		in <- inbound{request: request{Type: "host_call_result", ID: first.ID, CallID: first.CallID, OK: true, Value: json.RawMessage(`{"value":1}`)}}
		hostDone <- nil
	}()
	r, fatal := executeTest(e, 1, "await Promise.all([az.graph({query:'first'}), az.request({route:'second'})])")
	if err := <-hostDone; err != nil {
		t.Fatal(err)
	}
	if fatal || resultValue(t, r) != `[{"value":1},{"value":2}]` {
		t.Fatalf("host completion ordering: %#v", r)
	}
}

func TestHostProtocolPoisonCannotBeCaught(t *testing.T) {
	e, in, out := testEngine(t)
	go func() {
		<-out
		in <- inbound{request: request{Type: "host_call_result", ID: 1, CallID: 99, OK: true, Value: json.RawMessage(`{}`)}}
	}()
	r, fatal := executeTest(e, 1, "try { await az.graph({query:'x'}); } catch (_) { } return 'caught';")
	if !fatal || r["code"] != "protocol_error" {
		t.Fatalf("protocol failure was catchable: %#v", r)
	}
}

func TestDeadlineCoversCPUPromiseAndMicrotasks(t *testing.T) {
	for name, code := range map[string]string{
		"cpu":     "while (true) {}",
		"promise": "new Promise(() => {})",
		"jobs":    "Promise.resolve().then(function again(){ Promise.resolve().then(again); }); new Promise(() => {})",
	} {
		t.Run(name, func(t *testing.T) {
			e, _, _ := testEngine(t)
			start := time.Now()
			r, fatal := e.execute(request{Type: "execute", ID: 1, Code: code, TimeoutMS: 40})
			if !fatal || r["code"] != "execution_timeout" {
				t.Fatalf("deadline failure: %#v", r)
			}
			if time.Since(start) > time.Second {
				t.Fatal("deadline failed to bound execution")
			}
		})
	}
}

func TestUncaughtAllocationLimitIsFatal(t *testing.T) {
	e, _, _ := testEngine(t)
	r, fatal := executeTest(e, 1, "new Uint8Array(128 * 1024 * 1024)")
	if !fatal || r["code"] != "heap_limit" {
		t.Fatalf("allocation limit failure: %#v", r)
	}
}

func TestSerializationAllocationLimitIsFatal(t *testing.T) {
	e, _, _ := testEngine(t)
	r, fatal := executeTest(e, 1, "({toJSON(){return new Uint8Array(128 * 1024 * 1024)}})")
	if !fatal || r["code"] != "heap_limit" {
		t.Fatalf("allocation during serialization recovered: %#v", r)
	}
}

func TestPendingHostCallPreventsErrorRecovery(t *testing.T) {
	e, _, _ := testEngine(t)
	r, fatal := executeTest(e, 1, "az.request({route:'x'}); throw new Error('boom')")
	if !fatal || r["code"] != "protocol_error" {
		t.Fatalf("pending host call survived recoverable error: %#v", r)
	}
}

func TestResultStringNormalization(t *testing.T) {
	e, _, _ := testEngine(t)
	r, fatal := executeTest(e, 1, `['\ud800','\udc00','\ud83d\ude00','\u0000', '\u2028']`)
	if fatal || resultValue(t, r) != "[\"�\",\"�\",\"😀\",\"\\u0000\",\"\u2028\"]" {
		t.Fatalf("result Unicode normalization: %#v", r)
	}
}

func TestLogsAndResultLimits(t *testing.T) {
	e, _, _ := testEngine(t)
	r, fatal := executeTest(e, 1, "for(let i=0;i<300;i++) console.log('hello'); 'x'.repeat(70000)")
	if fatal || r["type"] != "result_ref" || r["encoded_bytes"] != 70002 || len(r["logs"].([]string)) != maxLogEntries || r["logs_omitted"] != 44 {
		t.Fatalf("bounded logs/reference result: %#v", r)
	}
	r, fatal = executeTest(e, 2, fmt.Sprintf("'x'.repeat(%d)", maxRefCandidateBytes+1))
	if fatal || r["code"] != "result_too_large" {
		t.Fatalf("oversized result: %#v", r)
	}
	details := r["details"].(response)
	if details["type"] != "string" || details["length"] != maxRefCandidateBytes+1 {
		t.Fatalf("oversized result summary: %#v", details)
	}
	r, _ = executeTest(e, 3, "1")
	if resultValue(t, r) != "1" || len(r["logs"].([]string)) != 0 {
		t.Fatal("worker did not recover/reset after oversized result")
	}
}

func TestFloatNumberSpellingsMatchRustProtocol(t *testing.T) {
	for input, expected := range map[string]string{
		"0.000001": "1e-6", "0.00001": "0.00001", "1e+21": "1e+21", "1e-7": "1e-7",
		"-0.000001": "-1e-6", "1.25": "1.25", "1e+15": "1000000000000000.0",
		"1e+16": "1e+16", "18446744073709551615": "18446744073709551615",
		"100000000000000000000": "1e+20", "1e+0": "1.0", "-0.0": "-0.0",
	} {
		actual, err := canonicalNumber(input)
		if err != nil || actual != expected {
			t.Fatalf("%s: got %s %v, want %s", input, actual, err, expected)
		}
	}
	e, _, _ := testEngine(t)
	r, fatal := executeTest(e, 1, "Array(16000).fill(0.000001)")
	if fatal || r["type"] != "result_ref" || r["encoded_bytes"] != 80001 {
		t.Fatalf("reference float size mismatch: %#v", r)
	}
}

func TestClosedRequestSchema(t *testing.T) {
	for _, frame := range []string{
		`{"type":"execute","id":1,"code":"1","timeout_ms":1,"extra":true}`,
		`{"type":"execute","id":1,"id":2,"code":"1","timeout_ms":1}`,
		`{"type":"execute","id":1,"code":null,"timeout_ms":1}`,
		`{"type":"host_call_result","id":1,"call_id":1,"ok":true}`,
		`{"type":"host_call_result","id":1,"call_id":1,"ok":true,"value":{},"error":"bad"}`,
		`{"type":"host_call_result","id":1,"call_id":1,"ok":false,"value":{},"error":"bad"}`,
	} {
		if _, err := parseRequest([]byte(frame)); err == nil {
			t.Fatalf("accepted invalid frame %s", frame)
		}
	}
}

func TestInputFramesAreBoundedAndTerminated(t *testing.T) {
	for _, frame := range []string{strings.Repeat("x", maxInputBytes+1) + "\n", `{"type":"close","id":1}`, "\xff\n"} {
		ch := make(chan inbound, 1)
		readRequests(strings.NewReader(frame), ch)
		if incoming := <-ch; incoming.err == nil {
			t.Fatal("accepted invalid input frame")
		}
	}
}

func TestWorkerLifecycleProtocol(t *testing.T) {
	var output bytes.Buffer
	input := "{\"type\":\"execute\",\"id\":1,\"code\":\"41+1\",\"timeout_ms\":1000}\n{\"type\":\"close\",\"id\":2}\n"
	if err := runWorker(strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte{'\n'})
	if len(lines) != 3 {
		t.Fatalf("unexpected frame count: %s", output.Bytes())
	}
	var result map[string]any
	if err := json.Unmarshal(lines[1], &result); err != nil {
		t.Fatal(err)
	}
	if result["type"] != "result" || result["value"] != float64(42) {
		t.Fatal(result)
	}
}
