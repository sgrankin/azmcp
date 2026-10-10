package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"modernc.org/quickjs"
)

func syncTestEngine(t *testing.T) (*engine, chan inbound, chan []byte) {
	t.Helper()
	input := make(chan inbound, maxHostCalls+2)
	output := make(chan []byte, maxHostCalls+2)
	e, err := newEngine(input, output, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.close)
	return e, input, output
}

func TestSyncHostCallsReturnOrdinaryValues(t *testing.T) {
	e, input, output := syncTestEngine(t)
	hostDone := make(chan struct{})
	go func() {
		defer close(hostDone)
		for range 2 {
			var frame struct {
				ID     uint64 `json:"id"`
				CallID uint64 `json:"call_id"`
			}
			if err := json.Unmarshal(<-output, &frame); err != nil {
				input <- inbound{err: err}
				return
			}
			input <- inbound{request: request{Type: "host_call_result", ID: frame.ID, CallID: frame.CallID, OK: true, Value: json.RawMessage(`[null,{"value":41}]`)}}
		}
	}()
	r, fatal := executeTest(e, 1, `const rows = az.logs.query({query:'synthetic'}); const other = az.request({}); [Array.isArray(rows), rows[0] === null, typeof rows[1].value, rows[1].value + other[1].value]`)
	<-hostDone
	if fatal || resultValue(t, r) != `[true,true,"number",82]` {
		t.Fatalf("host values need no implicit proxy resolution: %#v", r)
	}
	r, fatal = executeTest(e, 2, "rows.length")
	if fatal || resultValue(t, r) != "2" {
		t.Fatalf("synchronous values persist: %#v", r)
	}
}

func TestSyncStreamsAnOrdinaryGenerator(t *testing.T) {
	e, input, output := syncTestEngine(t)
	phases := make(chan []string, 1)
	go func() {
		var seen []string
		for range 3 {
			var frame struct {
				ID        uint64         `json:"id"`
				CallID    uint64         `json:"call_id"`
				Arguments map[string]any `json:"arguments"`
			}
			if err := json.Unmarshal(<-output, &frame); err != nil {
				input <- inbound{err: err}
				phases <- nil
				return
			}
			phase := frame.Arguments["phase"].(string)
			seen = append(seen, phase)
			value := json.RawMessage(`{"items":2}`)
			if phase == "begin" {
				value = json.RawMessage(`{"streamId":"synthetic-stream"}`)
			}
			if phase == "append" {
				values, _ := json.Marshal(frame.Arguments["values"])
				if string(values) != `[{"index":1},{"index":2}]` {
					input <- inbound{request: request{Type: "host_call_result", ID: frame.ID, CallID: frame.CallID, Error: "unexpected streamed values"}}
					phases <- seen
					return
				}
				value = json.RawMessage(`{"acceptedSequence":0}`)
			}
			input <- inbound{request: request{Type: "host_call_result", ID: frame.ID, CallID: frame.CallID, OK: true, Value: value}}
		}
		phases <- seen
	}()
	r, fatal := executeTest(e, 1, `function* metricRows() { yield {index:1}; yield {toJSON(){return {index:2};}}; } az.artifacts.writeJsonArray({name:'synthetic.json', values:metricRows()})`)
	seen := <-phases
	if strings.Join(seen, ",") != "begin,append,finish" || fatal || resultValue(t, r) != `{"items":2}` {
		t.Fatalf("synchronous streamed artifact: phases=%v response=%#v", seen, r)
	}
}

func TestSyncRejectsAwaitPromisesAndAsyncIterables(t *testing.T) {
	for name, source := range map[string]string{
		"await":        "await Promise.resolve(1)",
		"promise":      "Promise.resolve(1)",
		"async stream": "az.artifacts.writeJsonArray({name:'synthetic.json', values:(async function*(){yield 1;})()})",
	} {
		t.Run(name, func(t *testing.T) {
			e, _, output := syncTestEngine(t)
			r, fatal := executeTest(e, 1, source)
			if fatal || r["code"] != "execution_error" {
				t.Fatalf("expected recoverable synchronous surface error: %#v", r)
			}
			if len(output) != 0 {
				t.Fatal("unsupported async iterable emitted a host call")
			}
			r, fatal = executeTest(e, 2, "41+1")
			if fatal || resultValue(t, r) != "42" {
				t.Fatalf("ordinary turn after unsupported async code: %#v", r)
			}
		})
	}
}

func TestSyncProtocolFailureCannotBeCaught(t *testing.T) {
	e, input, output := syncTestEngine(t)
	go func() {
		<-output
		input <- inbound{request: request{Type: "host_call_result", ID: 1, CallID: 99, OK: true, Value: json.RawMessage(`null`)}}
	}()
	r, fatal := executeTest(e, 1, "try { az.request({}); } catch (_) { } 'caught'")
	if !fatal || r["code"] != "protocol_error" {
		t.Fatalf("protocol failure was swallowed: %#v", r)
	}
}

func TestSyncHostWaitDeadlineCannotBeCaught(t *testing.T) {
	e, _, _ := syncTestEngine(t)
	r, fatal := e.execute(request{Type: "execute", ID: 1, TimeoutMS: 40, Code: "try { az.request({}); } catch (_) { } 'caught'"})
	if !fatal || r["code"] != "execution_timeout" {
		t.Fatalf("host wait deadline was swallowed: %#v", r)
	}
}

func TestSyncDeadlineIncludesResultSerialization(t *testing.T) {
	e, _, _ := syncTestEngine(t)
	started := time.Now()
	r, fatal := e.execute(request{
		Type: "execute", ID: 1, TimeoutMS: 200,
		Code: "const stop = Date.now()+160; while(Date.now()<stop){}; ({toJSON(){while(true){}}})",
	})
	if !fatal || r["code"] != "execution_timeout" {
		t.Fatalf("serialization deadline failure: %#v", r)
	}
	if elapsed := time.Since(started); elapsed > 300*time.Millisecond {
		t.Fatalf("serialization restarted the turn's deadline: %v", elapsed)
	}
}

func TestSyncSerializationUsesCapturedIntrinsics(t *testing.T) {
	e, _, _ := syncTestEngine(t)
	r, fatal := executeTest(e, 1, "JSON.stringify = () => 'forged'; ({value:42})")
	if fatal || resultValue(t, r) != `{"value":42}` {
		t.Fatalf("caller replaced the result serializer: %#v", r)
	}
	// Exposed helper functions retain their host hooks without global entrypoints.
	if value, err := e.vm.EvalValue("typeof __azmcpSyncTransport + ':' + typeof __azmcpHostCall", quickjs.EvalGlobal); err != nil {
		t.Fatal(err)
	} else {
		defer value.Free()
		actual, err := value.Any()
		if err != nil || actual != "undefined:undefined" {
			t.Fatalf("private host hooks exposed: %v %v", actual, err)
		}
	}
}
