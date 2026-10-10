package worker

import (
	"encoding/json"
	"testing"
	"time"
)

func TestUnicodeLogLimitConsumesBudgetWithoutEllipsis(t *testing.T) {
	e, _, _ := testEngine(t)
	r, fatal := run(e, 1, `console.log('😀'.repeat(20000));console.log('omitted');42`)
	logs := r["logs"].([]string)
	if fatal || len(logs) != 1 || len(logs[0]) != maxLogBytes || r["logs_omitted"] != 1 {
		t.Fatalf("Unicode log limit changed: lines=%d bytes=%d omitted=%v fatal=%v", len(logs), len(logs[0]), r["logs_omitted"], fatal)
	}
}

func TestHostCallsFromSerializationAreCorrelatedAndBounded(t *testing.T) {
	e, in, out := testEngine(t)
	go func() {
		var call HostCallRequest
		if err := json.Unmarshal(<-out, &call); err != nil {
			return
		}
		in <- inbound{request: structRequest(call.ID, call.CallID)}
	}()
	r, fatal := run(e, 1, `({toJSON(){ return az.request({}).value; }})`)
	if fatal || value(t, r) != "42" {
		t.Fatal(r)
	}
}

func TestCapturedSerializerSurvivesCallerBuiltinChanges(t *testing.T) {
	e, _, _ := testEngine(t)
	r, fatal := run(e, 1, `JSON.stringify=()=>"forged";JSON.parse=()=>"forged";TypeError=()=>"forged";({value:42})`)
	if fatal || value(t, r) != `{"value":42}` {
		t.Fatal(r)
	}
}

func TestPendingJobsQueuedDuringThrownErrorFormattingAreFatal(t *testing.T) {
	e, _, _ := testEngine(t)
	r, fatal := run(e, 1, `throw {toString(){Promise.resolve().then(()=>globalThis.escaped=1);return 'boom'}}`)
	if !fatal || r["code"] != "async_not_supported" {
		t.Fatalf("jobs escaped error formatting: %#v", r)
	}
}

func TestSelfReplenishingJobsAreDeadlineBounded(t *testing.T) {
	e, _, _ := testEngine(t)
	started := time.Now()
	r, fatal := e.execute(request{Type: "execute", ID: 1, Code: `const replenish=()=>Promise.resolve().then(replenish);replenish();42`, TimeoutMS: 40})
	if !fatal || (r["code"] != "execution_timeout" && r["code"] != "async_not_supported") || time.Since(started) > 500*time.Millisecond {
		t.Fatalf("jobs exceeded deadline: %#v in %s", r, time.Since(started))
	}
}
