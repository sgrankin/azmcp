package worker

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testEngine(t *testing.T) (*engine, chan inbound, chan []byte) {
	t.Helper()
	input := make(chan inbound, maxHostCalls+2)
	output := make(chan []byte, maxHostCalls+2)
	e, err := newEngine(input, output)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.close)
	return e, input, output
}
func run(e *engine, id uint64, code string) (response, bool) {
	return e.execute(request{Type: "execute", ID: id, Code: code, TimeoutMS: 1000})
}
func value(t *testing.T, r response) string {
	t.Helper()
	if r["type"] != "result" {
		t.Fatalf("not a result: %#v", r)
	}
	return string(r["value"].(json.RawMessage))
}

func TestPersistentBindingsAndBody(t *testing.T) {
	e, _, _ := testEngine(t)
	r, fatal := run(e, 1, "let answer=41; answer")
	if fatal || value(t, r) != "41" {
		t.Fatal(r)
	}
	r, fatal = run(e, 2, "++answer")
	if fatal || value(t, r) != "42" {
		t.Fatal(r)
	}
	r, fatal = run(e, 3, "return answer + 1;")
	if fatal || value(t, r) != "43" {
		t.Fatal(r)
	}
	r, fatal = run(e, 4, "throw new SyntaxError('intentional')")
	if fatal || r["code"] != "execution_error" {
		t.Fatal(r)
	}
}

func TestPlainHostValuesAndProtocolFailure(t *testing.T) {
	t.Run("plain", func(t *testing.T) {
		e, in, out := testEngine(t)
		go func() {
			var request HostCallRequest
			json.Unmarshal(<-out, &request)
			in <- inbound{request: structRequest(request.ID, request.CallID)}
		}()
		r, fatal := run(e, 1, "const response=az.request({query:'synthetic'}); ({value:response.value, promise: typeof response.then})")
		if fatal || value(t, r) != `{"value":42,"promise":"undefined"}` {
			t.Fatal(r)
		}
	})
	t.Run("correlation", func(t *testing.T) {
		e, in, out := testEngine(t)
		go func() { <-out; in <- inbound{request: structRequest(1, 99)} }()
		r, fatal := run(e, 1, "try {az.request({});} catch(e){}; 42")
		if !fatal || r["code"] != "protocol_error" {
			t.Fatal(r)
		}
	})
}
func structRequest(id, callID uint64) request {
	return request{Type: "host_call_result", ID: id, CallID: callID, OK: true, Value: json.RawMessage(`{"value":42}`)}
}

func TestAsynchronousWorkIsFatalOnAllCompletionPaths(t *testing.T) {
	for _, code := range []string{"Promise.resolve(42)", "Promise.resolve().then(()=>42); 42", "Promise.resolve().then(()=>42); throw new Error('boom')", "({toJSON(){Promise.resolve().then(()=>42); return 42}})", "({toJSON(){Promise.resolve().then(()=>42); throw new Error('boom')}})"} {
		t.Run(code, func(t *testing.T) {
			e, _, _ := testEngine(t)
			r, fatal := run(e, 1, code)
			if !fatal || r["code"] != "async_not_supported" {
				t.Fatalf("async work survived: %#v", r)
			}
		})
	}
}

func TestDeadlineIncludesSerializationAndRegExp(t *testing.T) {
	for _, code := range []string{"while(true){}", "/(a+)+$/.test('a'.repeat(32)+'!')", "({toJSON(){while(true){}}})", "throw {toString(){while(true){}}}"} {
		t.Run(code, func(t *testing.T) {
			e, _, _ := testEngine(t)
			r, fatal := e.execute(request{Type: "execute", ID: 1, Code: code, TimeoutMS: 40})
			if !fatal || r["code"] != "execution_timeout" {
				t.Fatal(r)
			}
		})
	}
	e, _, _ := testEngine(t)
	started := time.Now()
	r, fatal := e.execute(request{Type: "execute", ID: 1, Code: "let start=Date.now();while(Date.now()-start<160){};({toJSON(){while(true){}}})", TimeoutMS: 200})
	if !fatal || r["code"] != "execution_timeout" || time.Since(started) > 300*time.Millisecond {
		t.Fatalf("serialization restarted deadline: %#v in %s", r, time.Since(started))
	}
}

func TestAllocationLimitAndHiddenGlobals(t *testing.T) {
	for _, code := range []string{"new Uint8Array(128*1024*1024)", "({toJSON(){return new Uint8Array(128*1024*1024)}})"} {
		e, _, _ := testEngine(t)
		r, fatal := run(e, 1, code)
		if !fatal || r["code"] != "heap_limit" {
			t.Fatal(r)
		}
	}
	e, _, _ := testEngine(t)
	r, fatal := run(e, 1, `['Deno','process','require','fetch','std','os','__azmcpTransport','__azmcpHostCall','__azmcpConsole'].map(k=>typeof globalThis[k])`)
	if fatal || value(t, r) != `["undefined","undefined","undefined","undefined","undefined","undefined","undefined","undefined","undefined"]` {
		t.Fatal(r)
	}
	r, fatal = run(e, 2, "function recurse(){recurse()}; recurse()")
	if fatal || r["code"] != "execution_error" {
		t.Fatal(r)
	}
}

func TestRawJSONCandidateSizeAndLogs(t *testing.T) {
	for _, code := range []string{`'<>&\u2028\u2029😀\ud800'.repeat(10000)`, `Array(16000).fill(1e-7)`, `Array(16000).fill(1e21)`} {
		e, _, _ := testEngine(t)
		r, fatal := run(e, 1, code)
		if fatal || r["type"] != "result_ref" {
			t.Fatal(r)
		}
		frame, err := encodeResponse(r)
		if err != nil {
			t.Fatal(err)
		}
		var decoded Response
		if err = json.Unmarshal(frame, &decoded); err != nil {
			t.Fatal(err)
		}
		if len(decoded.Value) != decoded.EncodedBytes {
			t.Fatalf("raw JSON size mismatch %d != %d; raw escaped=%d actual=%d; frame escaped=%d actual=%d; decoded escaped=%d actual=%d", len(decoded.Value), decoded.EncodedBytes, bytes.Count(r["value"].(json.RawMessage), []byte(`\u2028`)), bytes.Count(r["value"].(json.RawMessage), []byte{0xe2, 0x80, 0xa8}), bytes.Count(frame, []byte(`\u2028`)), bytes.Count(frame, []byte{0xe2, 0x80, 0xa8}), bytes.Count(decoded.Value, []byte(`\u2028`)), bytes.Count(decoded.Value, []byte{0xe2, 0x80, 0xa8}))
		}
	}
	e, _, _ := testEngine(t)
	r, fatal := run(e, 1, "for(let n=0;n<300;n++) console.log('hello');42")
	if fatal || value(t, r) != "42" || len(r["logs"].([]string)) != 256 || r["logs_omitted"] != 44 {
		t.Fatal(r)
	}
}

func TestClosedIPCAndLifecycle(t *testing.T) {
	for _, frame := range []string{`{"type":"execute","id":1,"id":2,"code":"42","timeout_ms":1000}`, `{"type":"host_call_result","id":1,"call_id":1,"ok":true}`, `{"type":"close","id":1,"unknown":true}`} {
		if _, err := parseRequest([]byte(frame)); err == nil {
			t.Fatal("accepted", frame)
		}
	}
	var output bytes.Buffer
	if err := RunWorker(strings.NewReader("{\"type\":\"execute\",\"id\":1,\"code\":\"42\",\"timeout_ms\":1000}\n{\"type\":\"close\",\"id\":2}\n"), &output); err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte{'\n'})
	if len(lines) != 3 {
		t.Fatal(output.String())
	}
	var r Response
	json.Unmarshal(lines[1], &r)
	if string(r.Value) != "42" {
		t.Fatal(output.String())
	}
}

func TestRequestWireDoesNotExpandHTMLValues(t *testing.T) {
	value := json.RawMessage(`"` + strings.Repeat("<>&", 150000) + `"`)
	request := Request{Type: "host_call_result", ID: 1, CallID: 1, OK: true, Value: value}
	var frame bytes.Buffer
	encoder := json.NewEncoder(&frame)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(request); err != nil {
		t.Fatal(err)
	}
	if frame.Len() > MaxInputBytes {
		t.Fatalf("bounded host value expanded beyond the worker input limit: %d", frame.Len())
	}
	parsed, err := parseRequest(frame.Bytes())
	if err != nil || !bytes.Equal(parsed.Value, value) {
		t.Fatalf("host value changed on the wire: %v", err)
	}
}
