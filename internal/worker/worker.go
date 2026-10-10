package worker

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"modernc.org/quickjs"
)

//go:embed bootstrap.js
var bootstrapSource string

const bridgeSource = `(() => {
 const transport = globalThis.__azmcpTransport;
 const stringify = JSON.stringify;
 const parse = JSON.parse;
 const TypeErrorType = TypeError;
 delete globalThis.__azmcpTransport;
 globalThis.__azmcpHostCall = (method, arguments) => {
  const encoded = stringify(arguments);
  if (encoded === undefined) throw new TypeErrorType("host-call arguments are not JSON serializable");
  return parse(transport(method, encoded));
 };
 return (value) => {
  if (value !== null && (typeof value === "object" || typeof value === "function") && typeof value.then === "function") {
   throw new TypeErrorType("asynchronous results are not supported");
  }
  const encoded = stringify(value);
  return encoded === undefined ? "null" : encoded;
 };
})()`

type engine struct {
	vm                    *quickjs.VM
	control               quickjs.Value
	input                 <-chan inbound
	output                chan<- []byte
	id, nextCallID        uint64
	callCount             int
	deadline              time.Time
	poison                error
	logs                  []string
	logBytes, logsOmitted int
}

func newEngine(input <-chan inbound, output chan<- []byte) (*engine, error) {
	vm, err := quickjs.NewVM()
	if err != nil {
		return nil, err
	}
	e := &engine{vm: vm, input: input, output: output, nextCallID: 1}
	vm.SetMemoryLimit(maxHeapBytes)
	vm.SetMaxStackSize(4096)
	vm.SetCanBlock(false)
	if err = vm.RegisterFunc("__azmcpConsole", func(message string) { e.log(message) }, false); err != nil {
		e.close()
		return nil, err
	}
	if err = vm.RegisterHostFunc("__azmcpTransport", e.host); err != nil {
		e.close()
		return nil, err
	}
	e.control, err = vm.EvalValue(bridgeSource, quickjs.EvalGlobal)
	if err != nil {
		e.close()
		return nil, err
	}
	value, err := vm.EvalValue(bootstrapSource, quickjs.EvalGlobal)
	if err != nil {
		e.close()
		return nil, err
	}
	value.Free()
	return e, nil
}

func (e *engine) close() {
	if e.vm != nil {
		if e.control.VM() != nil {
			e.control.Free()
		}
		e.vm.Close()
		e.vm = nil
	}
}

func (e *engine) log(message string) {
	if len(e.logs) >= maxLogEntries || e.logBytes >= maxLogBytes {
		e.logsOmitted++
		return
	}
	message = truncate(filterControls(message), maxLogBytes-e.logBytes)
	e.logs = append(e.logs, message)
	e.logBytes += len(message)
}

func (e *engine) host(args []any) (any, error) {
	if len(args) != 2 {
		e.poison = errors.New("invalid host-call arguments")
		return nil, e.poison
	}
	method, ok := args[0].(string)
	encoded, encodedOK := args[1].(string)
	encoded = string(wireJSON([]byte(encoded)))
	if !ok || !encodedOK || e.id == 0 || !validMethod(method) || e.callCount >= maxHostCalls {
		e.poison = errors.New("invalid host call or host-call limit exceeded")
		return nil, e.poison
	}
	if len(encoded) > maxInputBytes || !json.Valid([]byte(encoded)) {
		e.poison = errors.New("invalid or oversized host-call JSON")
		return nil, e.poison
	}
	if err := validateStream(method, []byte(encoded)); err != nil {
		e.poison = err
		return nil, err
	}
	callID := e.nextCallID
	if callID == 0 || callID > 1<<53-1 {
		e.poison = errors.New("host-call ID exhausted JavaScript precision")
		return nil, e.poison
	}
	frame, err := encodeResponse(response{"type": "host_call", "id": e.id, "call_id": callID, "method": method, "arguments": json.RawMessage(encoded)})
	if err != nil {
		e.poison = err
		return nil, err
	}
	e.nextCallID++
	e.callCount++
	e.output <- frame
	timer := time.NewTimer(time.Until(e.deadline))
	defer timer.Stop()
	select {
	case incoming, ok := <-e.input:
		if !ok {
			e.poison = errors.New("worker input closed during host call")
			return nil, e.poison
		}
		if incoming.err != nil {
			e.poison = incoming.err
			return nil, e.poison
		}
		r := incoming.request
		if r.Type != "host_call_result" || r.ID != e.id || r.CallID != callID {
			e.poison = errors.New("unexpected or mismatched host-call result")
			return nil, e.poison
		}
		if !r.OK {
			return nil, errors.New(sanitize(r.Error, maxErrorBytes))
		}
		return string(r.Value), nil
	case <-timer.C:
		return nil, errors.New("execution deadline exceeded")
	}
}

func (e *engine) failure(code, message string) response {
	logs, omitted := e.logs, e.logsOmitted
	if code != "execution_error" {
		logs, omitted = []string{}, 0
	}
	return response{"type": "error", "id": e.id, "code": code, "message": sanitize(message, maxErrorBytes), "logs": logs, "logs_omitted": omitted}
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
	var jsErr *quickjs.Error
	if errors.As(err, &jsErr) {
		if jsErr.Name == "InternalError" && jsErr.Message == "out of memory" {
			return e.failure("heap_limit", "worker heap limit exceeded"), true
		}
		if jsErr.Name == "TypeError" && jsErr.Message == "asynchronous results are not supported" {
			return e.failure("async_not_supported", jsErr.Message), true
		}
	} else if err.Error() == "OOM" {
		return e.failure("heap_limit", "worker heap limit exceeded"), true
	} else if strings.HasPrefix(err.Error(), "quickjs: aborted draining after ") {
		return e.failure("async_not_supported", "asynchronous JavaScript jobs are not supported"), true
	}
	return e.failure("execution_error", err.Error()), false
}

func (e *engine) evalSource(code string) (quickjs.Value, error) {
	_, err := e.vm.Compile(code, quickjs.EvalGlobal)
	var jsError *quickjs.Error
	if err != nil {
		if !errors.As(err, &jsError) || jsError.Name != "SyntaxError" {
			return quickjs.Value{}, err
		}
		code = "(function(){\n" + code + "\n})()"
	}
	if err = e.armDeadline(); err != nil {
		return quickjs.Value{}, err
	}
	return e.vm.EvalValue(code, quickjs.EvalGlobal)
}

func (e *engine) execute(r request) (response, bool) {
	e.id, e.callCount, e.poison = r.ID, 0, nil
	e.logs, e.logBytes, e.logsOmitted = []string{}, 0, 0
	if len(r.Code) > maxCodeBytes {
		return e.failure("worker_error", "worker code limit exceeded"), false
	}
	if r.TimeoutMS == 0 || r.TimeoutMS > maxTimeoutMS {
		return e.failure("worker_error", "worker timeout limit exceeded"), false
	}
	e.deadline = time.Now().Add(time.Duration(r.TimeoutMS) * time.Millisecond)
	if err := e.armDeadline(); err != nil {
		return e.executionFailure(err, r.TimeoutMS)
	}
	value, evalErr := e.evalSource(r.Code)
	if evalErr == nil {
		defer value.Free()
	}
	// Drain on both paths so a throwing script cannot retain jobs for another turn.
	if err := e.armDeadline(); err != nil {
		return e.executionFailure(err, r.TimeoutMS)
	}
	jobs, jobErr := e.vm.ExecutePendingJobs()
	if jobErr != nil {
		return e.executionFailure(jobErr, r.TimeoutMS)
	}
	if e.poison != nil {
		return e.executionFailure(e.poison, r.TimeoutMS)
	}
	if jobs != 0 {
		return e.failure("async_not_supported", "asynchronous JavaScript jobs are not supported"), true
	}
	if evalErr != nil {
		return e.executionFailure(evalErr, r.TimeoutMS)
	}
	if err := e.armDeadline(); err != nil {
		return e.executionFailure(err, r.TimeoutMS)
	}
	encoded, err := e.control.Call(quickjs.UndefinedValue, value)
	if deadlineErr := e.armDeadline(); deadlineErr != nil {
		return e.executionFailure(deadlineErr, r.TimeoutMS)
	}
	jobs, jobErr = e.vm.ExecutePendingJobs()
	if jobErr != nil {
		return e.executionFailure(jobErr, r.TimeoutMS)
	}
	if jobs != 0 {
		return e.failure("async_not_supported", "asynchronous JavaScript jobs are not supported"), true
	}
	if err != nil {
		return e.executionFailure(err, r.TimeoutMS)
	}
	if e.poison != nil {
		return e.executionFailure(e.poison, r.TimeoutMS)
	}
	if !time.Now().Before(e.deadline) {
		return e.executionFailure(errors.New("execution deadline exceeded"), r.TimeoutMS)
	}
	text, ok := encoded.(string)
	if !ok {
		panic("worker serializer returned a non-string")
	}
	raw := json.RawMessage(wireJSON([]byte(text)))
	if !json.Valid(raw) {
		return e.failure("worker_error", "worker result is not JSON"), true
	}
	if len(raw) > maxRefCandidateBytes {
		summary, err := resultSummary(raw)
		if err != nil {
			return e.failure("worker_error", err.Error()), true
		}
		result := e.failure("result_too_large", "result exceeds the 64 KiB limit")
		result["details"] = summary
		return result, false
	}
	result := response{"type": "result", "id": e.id, "value": raw, "logs": e.logs, "logs_omitted": e.logsOmitted}
	if len(raw) > maxResultBytes {
		result["type"], result["encoded_bytes"] = "result_ref", len(raw)
	}
	return result, false
}

// Go's JSON codec escapes line separators independently of its HTML option.
// Normalize them before measuring JSON that will cross that codec boundary.
func wireJSON(raw []byte) []byte {
	raw = bytes.ReplaceAll(raw, []byte{0xe2, 0x80, 0xa8}, []byte(`\u2028`))
	return bytes.ReplaceAll(raw, []byte{0xe2, 0x80, 0xa9}, []byte(`\u2029`))
}

func RunWorker(reader io.Reader, writer io.Writer) error {
	input := make(chan inbound, maxHostCalls+2)
	output := make(chan []byte, maxHostCalls+2)
	written := make(chan error, 1)
	go readRequests(reader, input)
	go func() {
		for frame := range output {
			if n, err := writer.Write(frame); err != nil || n != len(frame) {
				if err == nil {
					err = io.ErrShortWrite
				}
				written <- err
				return
			}
		}
		written <- nil
	}()
	e, err := newEngine(input, output)
	if err != nil {
		close(output)
		<-written
		return err
	}
	defer e.close()
	ready, _ := encodeResponse(response{"type": "ready", "protocol": protocolVersion})
	output <- ready
	var lastID uint64
	for incoming := range input {
		if incoming.err != nil {
			err = incoming.err
			break
		}
		r := incoming.request
		if r.Type == "host_call_result" || r.ID == 0 || r.ID <= lastID {
			err = errors.New("invalid worker request lifecycle")
			break
		}
		lastID = r.ID
		var result response
		fatal := false
		if r.Type == "close" {
			result = response{"type": "closed", "id": r.ID}
		} else {
			result, fatal = e.execute(r)
		}
		frame, encodeErr := encodeResponse(result)
		if encodeErr != nil {
			err = encodeErr
			break
		}
		output <- frame
		e.id = 0
		if fatal {
			err = errors.New("worker execution stopped")
			break
		}
		if r.Type == "close" {
			break
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
