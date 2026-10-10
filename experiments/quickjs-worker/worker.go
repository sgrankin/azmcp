package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"

	"modernc.org/quickjs"
)

//go:embed bridge.js
var bridgeSource string

//go:embed bootstrap.js
var bootstrapSource string

type engine struct {
	vm                              *quickjs.VM
	control                         quickjs.Value
	input                           <-chan inbound
	output                          chan<- []byte
	synchronous                     bool
	id, nextCallID                  uint64
	callCount                       int
	pending                         map[uint64]bool
	deadline                        time.Time
	poison                          error
	done                            bool
	result                          json.RawMessage
	completionError, completionKind string
	logs                            []string
	logBytes, logsOmitted           int
}

func newEngine(input <-chan inbound, output chan<- []byte, synchronous bool) (*engine, error) {
	vm, err := quickjs.NewVM()
	if err != nil {
		return nil, err
	}
	e := &engine{vm: vm, input: input, output: output, synchronous: synchronous, nextCallID: 1, pending: make(map[uint64]bool)}
	vm.SetMemoryLimit(maxHeapBytes)
	vm.SetMaxStackSize(4096)
	vm.SetCanBlock(false)
	if err := vm.RegisterFunc("__azmcpConsole", func(message string) { e.log(message) }, false); err != nil {
		e.close()
		return nil, err
	}
	if synchronous {
		if err := e.installSync(); err != nil {
			e.close()
			return nil, err
		}
		return e, nil
	}
	if err := vm.RegisterFunc("__azmcpSend", e.sendHost, false); err != nil {
		e.close()
		return nil, err
	}
	if err := vm.RegisterFunc("__azmcpComplete", func(encoded, message, kind string) {
		if e.done {
			e.poison = errors.New("duplicate execution completion")
			return
		}
		e.done, e.result, e.completionError, e.completionKind = true, json.RawMessage(encoded), message, kind
	}, false); err != nil {
		e.close()
		return nil, err
	}
	e.control, err = vm.EvalValue(bridgeSource, quickjs.EvalGlobal)
	if err != nil {
		e.close()
		return nil, err
	}
	v, err := vm.EvalValue(bootstrapSource, quickjs.EvalGlobal)
	if err != nil {
		e.close()
		return nil, err
	}
	v.Free()
	return e, nil
}

func (e *engine) close() {
	if e.control.VM() != nil {
		e.control.Free()
	}
	if e.vm != nil {
		e.vm.Close()
		e.vm = nil
	}
}

func (e *engine) log(message string) {
	if len(e.logs) >= maxLogEntries || e.logBytes >= maxLogBytes {
		e.logsOmitted++
		return
	}
	message = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, message)
	message = truncate(message, maxLogBytes-e.logBytes)
	e.logs = append(e.logs, message)
	e.logBytes += len(message)
}

func (e *engine) sendHost(method, encoded string) uint64 {
	if e.poison != nil {
		return 0
	}
	if e.id == 0 {
		e.poison = errors.New("host call outside an active execution")
		return 0
	}
	if !validMethod(method) {
		e.poison = errors.New("unknown host-call method")
		return 0
	}
	if e.callCount >= maxHostCalls {
		e.poison = errors.New("host-call count limit exceeded")
		return 0
	}
	if len(encoded) > maxInputBytes || !json.Valid([]byte(encoded)) {
		e.poison = errors.New("host-call arguments exceed the input limit or are not JSON")
		return 0
	}
	canonical, err := canonicalResultJSON([]byte(encoded))
	if err != nil {
		e.poison = err
		return 0
	}
	encoded = string(canonical)
	if err := validateStream(method, []byte(encoded)); err != nil {
		e.poison = err
		return 0
	}
	id := e.nextCallID
	if id == 0 || id > 1<<53-1 {
		e.poison = errors.New("host-call ID exhausted JavaScript integer precision")
		return 0
	}
	frame, err := encodeResponse(response{"type": "host_call", "id": e.id, "call_id": id, "method": method, "arguments": json.RawMessage(encoded)})
	if err != nil {
		e.poison = err
		return 0
	}
	e.nextCallID++
	e.callCount++
	e.pending[id] = true
	e.output <- frame
	return id
}

func (e *engine) awaitHost(r request) error {
	if r.Type != "host_call_result" {
		return errors.New("unexpected worker request while execution was pending")
	}
	if r.ID != e.id || !e.pending[r.CallID] {
		return errors.New("duplicate or mismatched host-call response ID")
	}
	delete(e.pending, r.CallID)
	value := string(r.Value)
	if !r.OK {
		value = sanitize(r.Error, maxErrorBytes)
	}
	v, err := e.control.CallValue(quickjs.UndefinedValue, "settle", r.CallID, r.OK, value)
	if err != nil {
		return err
	}
	v.Free()
	return nil
}

func (e *engine) failure(code, message string) response {
	logs, omitted := e.logs, e.logsOmitted
	if code != "execution_error" {
		logs, omitted = []string{}, 0
	}
	return response{"type": "error", "id": e.id, "code": code, "message": sanitize(message, maxErrorBytes), "logs": logs, "logs_omitted": omitted}
}

func (e *engine) resultResponse(raw json.RawMessage) (response, bool) {
	var err error
	raw, err = canonicalResultJSON(raw)
	if err != nil {
		return e.failure("worker_error", "worker serialization error: result is not JSON"), false
	}
	if len(raw) > maxRefCandidateBytes {
		summary, err := resultSummary(raw)
		if err != nil {
			return e.failure("worker_error", err.Error()), false
		}
		r := e.failure("result_too_large", "result exceeds the 64 KiB limit")
		r["details"] = summary
		return r, false
	}
	r := response{"type": "result", "id": e.id, "value": raw, "logs": e.logs, "logs_omitted": e.logsOmitted}
	if len(raw) > maxResultBytes {
		r["type"], r["encoded_bytes"] = "result_ref", len(raw)
	}
	return r, false
}

func (e *engine) prepare(r request) (response, bool) {
	e.id, e.callCount, e.poison = r.ID, 0, nil
	e.done, e.result, e.completionError, e.completionKind = false, nil, "", ""
	e.logs, e.logBytes, e.logsOmitted = []string{}, 0, 0
	if len(r.Code) > maxCodeBytes {
		return e.failure("worker_error", "worker code limit exceeded"), false
	}
	if r.TimeoutMS == 0 || r.TimeoutMS > maxTimeoutMS {
		return e.failure("worker_error", "worker timeout limit exceeded"), false
	}
	e.deadline = time.Now().Add(time.Duration(r.TimeoutMS) * time.Millisecond)
	return nil, false
}

func (e *engine) armDeadline() error {
	remaining := time.Until(e.deadline)
	if remaining <= 0 {
		return errors.New("execution deadline exceeded")
	}
	return e.vm.SetEvalTimeout(remaining)
}

func (e *engine) executionFailure(err error, timeoutMS uint64) (response, bool) {
	if e.poison != nil {
		return e.failure("protocol_error", e.poison.Error()), true
	}
	if !time.Now().Before(e.deadline) {
		return e.failure("execution_timeout", fmt.Sprintf("execution timed out after %d ms", timeoutMS)), true
	}
	var jsError *quickjs.Error
	if !errors.As(err, &jsError) && strings.HasPrefix(err.Error(), "quickjs: aborted draining after ") {
		return e.failure("worker_error", "worker pending-job limit exceeded"), true
	}
	if isOOM(err) {
		return e.failure("heap_limit", "worker heap limit exceeded"), true
	}
	if len(e.pending) != 0 {
		return e.failure("protocol_error", "worker completed with pending host calls"), true
	}
	return e.failure("execution_error", err.Error()), false
}

func isOOM(err error) bool {
	var jsError *quickjs.Error
	return errors.As(err, &jsError) && jsError.Name == "InternalError" && jsError.Message == "out of memory" || err.Error() == "OOM"
}

func isSyntax(err error) bool {
	var jsError *quickjs.Error
	return errors.As(err, &jsError) && jsError.Name == "SyntaxError"
}

func (e *engine) evalSource(code string) (quickjs.Value, error) {
	// Only parser errors trigger the expression/body fallback; thrown SyntaxError
	// objects must not repeat script side effects.
	source := code
	_, err := e.vm.Compile(source, quickjs.EvalGlobal)
	if err != nil && isSyntax(err) {
		source = "(async function() { return await (" + code + "\n); })()"
		_, err = e.vm.Compile(source, quickjs.EvalGlobal)
		if err != nil && isSyntax(err) {
			source = "(async function() {\n" + code + "\n})()"
		} else if err != nil {
			return quickjs.Value{}, err
		}
	} else if err != nil {
		return quickjs.Value{}, err
	}
	if err := e.armDeadline(); err != nil {
		return quickjs.Value{}, err
	}
	return e.vm.EvalValue(source, quickjs.EvalGlobal)
}

func (e *engine) execute(r request) (response, bool) {
	if failure, fatal := e.prepare(r); failure != nil {
		return failure, fatal
	}
	if e.synchronous {
		return e.executeSync(r)
	}
	if err := e.armDeadline(); err != nil {
		return e.executionFailure(err, r.TimeoutMS)
	}
	v, err := e.evalSource(r.Code)
	if err != nil {
		return e.executionFailure(err, r.TimeoutMS)
	}
	if err := e.armDeadline(); err != nil {
		v.Free()
		return e.executionFailure(err, r.TimeoutMS)
	}
	watched, err := e.control.CallValue(quickjs.UndefinedValue, "watch", v)
	v.Free()
	if err != nil {
		return e.executionFailure(err, r.TimeoutMS)
	}
	watched.Free()
	for {
		if err := e.armDeadline(); err != nil {
			return e.executionFailure(err, r.TimeoutMS)
		}
		if _, err := e.vm.ExecutePendingJobs(); err != nil {
			return e.executionFailure(err, r.TimeoutMS)
		}
		if e.poison != nil {
			return e.executionFailure(e.poison, r.TimeoutMS)
		}
		if !time.Now().Before(e.deadline) {
			return e.executionFailure(errors.New("execution deadline exceeded"), r.TimeoutMS)
		}
		if e.done {
			if len(e.pending) != 0 {
				e.poison = errors.New("worker completed with pending host calls")
				return e.executionFailure(e.poison, r.TimeoutMS)
			}
			// The engine exposes no sticky allocator-failure flag. An uncaught
			// OOM is identifiable here, including while encoding a result; a
			// script that catches one remains a prototype limitation.
			if e.completionError == "InternalError: out of memory" {
				return e.failure("heap_limit", "worker heap limit exceeded"), true
			}
			switch e.completionKind {
			case "execution":
				return e.failure("execution_error", e.completionError), false
			case "serialization":
				return e.failure("worker_error", "worker serialization error: "+e.completionError), false
			default:
				return e.resultResponse(e.result)
			}
		}
		timer := time.NewTimer(time.Until(e.deadline))
		select {
		case received, ok := <-e.input:
			timer.Stop()
			if !ok {
				e.poison = errors.New("worker input closed during execution")
				return e.executionFailure(e.poison, r.TimeoutMS)
			}
			if received.err != nil {
				e.poison = received.err
				return e.executionFailure(e.poison, r.TimeoutMS)
			}
			if err := e.armDeadline(); err != nil {
				return e.executionFailure(err, r.TimeoutMS)
			}
			if err := e.awaitHost(received.request); err != nil {
				e.poison = err
				return e.executionFailure(err, r.TimeoutMS)
			}
		case <-timer.C:
			return e.executionFailure(errors.New("execution deadline exceeded"), r.TimeoutMS)
		}
	}
}

func runWorker(reader io.Reader, writer io.Writer) error {
	return runWorkerMode(reader, writer, false)
}

func runWorkerMode(reader io.Reader, writer io.Writer, synchronous bool) error {
	input := make(chan inbound, maxHostCalls+2)
	output := make(chan []byte, maxHostCalls+2)
	written := make(chan error, 1)
	go readRequests(reader, input)
	go func() {
		for frame := range output {
			if _, err := writer.Write(frame); err != nil {
				written <- err
				return
			}
		}
		written <- nil
	}()
	e, err := newEngine(input, output, synchronous)
	if err != nil {
		close(output)
		<-written
		return err
	}
	defer e.close()
	ready, err := encodeResponse(response{"type": "ready", "protocol": protocolVersion})
	if err != nil {
		close(output)
		<-written
		return err
	}
	output <- ready
	var lastID uint64
loop:
	for incoming := range input {
		if incoming.err != nil {
			err = incoming.err
			break
		}
		r := incoming.request
		if r.Type == "host_call_result" {
			err = errors.New("unexpected host-call result")
			break
		}
		if r.ID == 0 || r.ID <= lastID {
			err = errors.New("worker request ID is not strictly increasing")
			break
		}
		lastID = r.ID
		var result response
		fatal := false
		switch r.Type {
		case "close":
			result = response{"type": "closed", "id": r.ID}
		case "execute":
			result, fatal = e.execute(r)
		}
		frame, frameErr := encodeResponse(result)
		if frameErr != nil {
			err = frameErr
			break
		}
		output <- frame
		e.id = 0
		if fatal {
			err = errors.New("worker execution stopped")
			break loop
		}
		if r.Type == "close" {
			break loop
		}
	}
	close(output)
	select {
	case writeErr := <-written:
		if writeErr != nil {
			return writeErr
		}
	case <-time.After(5 * time.Second):
		return errors.New("worker output shutdown timed out")
	}
	return err
}
