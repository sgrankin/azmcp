package server

import (
	"azmcp/internal/worker"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type HostHandler func(context.Context, worker.HostCallRequest) (json.RawMessage, error)
type WorkerHandle interface {
	Execute(context.Context, string, time.Duration, HostHandler) (worker.Response, error)
	Terminate() error
}
type WorkerFactory func(context.Context) (WorkerHandle, error)

type workerFrame struct {
	response worker.Response
	err      error
}
type ProcessWorker struct {
	cmd      *exec.Cmd
	input    io.WriteCloser
	frames   chan workerFrame
	done     chan struct{}
	stopping chan struct{}
	writeMu  sync.Mutex
	stopOnce sync.Once
	sequence uint64
}

func StartWorker(ctx context.Context, executable string) (WorkerHandle, error) {
	cmd := exec.Command(executable, "--worker")
	cmd.Env = []string{}
	for _, name := range []string{"PATH", "LANG"} {
		if value, ok := os.LookupEnv(name); ok {
			cmd.Env = append(cmd.Env, name+"="+value)
		}
	}
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, failure("worker_crashed")
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		input.Close()
		return nil, failure("worker_crashed")
	}
	cmd.Stderr = io.Discard
	if err = cmd.Start(); err != nil {
		input.Close()
		return nil, failure("worker_crashed")
	}
	p := &ProcessWorker{cmd: cmd, input: input, frames: make(chan workerFrame, 1), done: make(chan struct{}), stopping: make(chan struct{})}
	go p.read(output)
	startup, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	select {
	case <-startup.Done():
		p.Terminate()
		return nil, failure("worker_crashed")
	case frame := <-p.frames:
		if frame.err != nil || frame.response.Type != "ready" || frame.response.Protocol != worker.ProtocolVersion {
			p.Terminate()
			return nil, failure("worker_crashed")
		}
	}
	go p.monitor()
	return p, nil
}
func (p *ProcessWorker) monitor() {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			return
		case <-p.stopping:
			return
		case <-ticker.C:
			rss, err := residentBytes(p.cmd.Process.Pid)
			if err != nil || rss > worker.RSSLimitBytes {
				p.Terminate()
				return
			}
		}
	}
}
func (p *ProcessWorker) read(output io.Reader) {
	defer func() { _ = p.cmd.Wait(); close(p.done) }()
	scanner := bufio.NewScanner(output)
	scanner.Buffer(make([]byte, 64*1024), worker.MaxOutputBytes+1)
	for scanner.Scan() {
		frame, err := decodeWorkerFrame(scanner.Bytes())
		select {
		case p.frames <- workerFrame{frame, err}:
		case <-p.stopping:
			return
		}
		if err != nil {
			return
		}
	}
	err := scanner.Err()
	if err == nil {
		err = io.EOF
	}
	select {
	case p.frames <- workerFrame{err: err}:
	default:
	}
}
func decodeWorkerFrame(raw []byte) (worker.Response, error) {
	var response worker.Response
	fields, err := closedJSONObject(raw)
	if err != nil {
		return response, err
	}
	var kind string
	if json.Unmarshal(fields["type"], &kind) != nil {
		return response, errors.New("invalid worker frame")
	}
	allowed := map[string][]string{
		"ready": {"type", "protocol"}, "closed": {"type", "id"},
		"host_call":  {"type", "id", "call_id", "method", "arguments"},
		"result":     {"type", "id", "value", "logs", "logs_omitted"},
		"result_ref": {"type", "id", "value", "encoded_bytes", "logs", "logs_omitted"},
		"error":      {"type", "id", "code", "message", "logs", "logs_omitted", "details"},
	}
	keys, ok := allowed[kind]
	if !ok {
		return response, errors.New("unknown worker frame")
	}
	for key := range fields {
		found := false
		for _, k := range keys {
			if key == k {
				found = true
				break
			}
		}
		if !found {
			return response, errors.New("unknown worker frame field")
		}
	}
	for _, key := range keys {
		if key == "details" {
			continue
		}
		if _, ok := fields[key]; !ok {
			return response, errors.New("missing worker frame field")
		}
	}
	if err = json.Unmarshal(raw, &response); err != nil {
		return response, err
	}
	if kind == "host_call" {
		if !validHostMethod(response.Method) || len(raw)+1 > worker.MaxInputBytes || len(response.Arguments) == 0 || response.Arguments[0] != '{' {
			return response, errors.New("invalid host call")
		}
	}
	if kind == "result" || kind == "result_ref" || kind == "error" {
		if response.Logs == nil || len(response.Logs) > worker.MaxLogEntries || response.LogsOmitted < 0 {
			return response, errors.New("invalid worker logs")
		}
		n := 0
		for _, line := range response.Logs {
			n += len(line)
			if strings.ContainsFunc(line, func(r rune) bool { return (r < 32 || r == 127) && r != '\n' && r != '\t' }) {
				return response, errors.New("invalid worker logs")
			}
		}
		if n > worker.MaxLogBytes {
			return response, errors.New("worker logs exceed limit")
		}
	}
	return response, nil
}
func validHostMethod(method string) bool {
	switch method {
	case "az.request", "az.graph", "az.metrics.single", "az.metrics.batch", "az.logs.query", "az.ref", "az.artifacts.writeJson", "az.artifacts.writeJsonArray", "az.artifacts.writeJsonLines":
		return true
	}
	return false
}
func closedJSONObject(raw []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("expected JSON object")
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return nil, err
		}
		key := token.(string)
		if _, exists := fields[key]; exists {
			return nil, errors.New("duplicate JSON field")
		}
		var value json.RawMessage
		if err = decoder.Decode(&value); err != nil {
			return nil, err
		}
		fields[key] = value
	}
	if _, err = decoder.Token(); err != nil {
		return nil, err
	}
	if _, err = decoder.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON input")
	}
	return fields, nil
}
func (p *ProcessWorker) send(request worker.Request) error {
	raw, err := marshalJSON(request)
	if err != nil || len(raw) > worker.MaxInputBytes {
		return failure("worker_crashed")
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	frame := append(raw, '\n')
	n, err := p.input.Write(frame)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	return err
}
func (p *ProcessWorker) Terminate() error {
	var err error
	p.stopOnce.Do(func() {
		close(p.stopping)
		_ = p.input.Close()
		err = p.cmd.Process.Kill()
	})
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		return failure("worker_crashed")
	}
	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	return err
}
func (p *ProcessWorker) Execute(ctx context.Context, code string, timeout time.Duration, handler HostHandler) (worker.Response, error) {
	p.sequence++
	id := p.sequence
	deadline, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := p.send(worker.Request{Type: "execute", ID: id, Code: code, TimeoutMS: uint64(timeout / time.Millisecond)}); err != nil {
		p.Terminate()
		return worker.Response{}, failure("worker_crashed")
	}
	lastCall := uint64(0)
	calls := 0
	for {
		select {
		case <-deadline.Done():
			p.Terminate()
			if ctx.Err() != nil {
				return worker.Response{}, &Error{Code: "context_evicted", Message: messages["context_evicted"], Fatal: true}
			}
			e := failure("execution_timeout")
			e.Fatal = true
			return worker.Response{}, e
		case frame := <-p.frames:
			r := frame.response
			if frame.err != nil || r.ID != id {
				p.Terminate()
				e := failure("worker_crashed")
				e.Fatal = true
				return r, e
			}
			switch r.Type {
			case "host_call":
				calls++
				if r.CallID <= lastCall || calls > worker.MaxHostCalls {
					p.Terminate()
					e := failure("worker_crashed")
					e.Fatal = true
					return r, e
				}
				lastCall = r.CallID
				request := worker.HostCallRequest{ID: r.ID, CallID: r.CallID, Method: r.Method, Arguments: r.Arguments}
				var value json.RawMessage
				var err error
				if handler == nil {
					err = failure("capability_denied")
				} else {
					type hostReply struct {
						value json.RawMessage
						err   error
					}
					completed := make(chan hostReply, 1)
					go func() { v, e := handler(deadline, request); completed <- hostReply{v, e} }()
					select {
					case reply := <-completed:
						value, err = reply.value, reply.err
					case <-deadline.Done():
						p.Terminate()
						e := failure("execution_timeout")
						if ctx.Err() != nil {
							e = failure("context_evicted")
						}
						e.Fatal = true
						return r, e
					case <-p.done:
						e := failure("worker_crashed")
						e.Fatal = true
						return r, e
					}
				}
				if err != nil && publicError(err).Fatal {
					p.Terminate()
					return r, publicError(err)
				}
				reply := worker.Request{Type: "host_call_result", ID: id, CallID: r.CallID, OK: err == nil, Value: value}
				if err != nil {
					reply.Error = publicError(err).Message
					if reply.Error == "" {
						reply.Error = "host call failed"
					}
				}
				if len(value) > worker.MaxRefCandidateBytes {
					reply.OK = false
					reply.Value = nil
					reply.Error = "host result exceeds the worker input limit"
				}
				if err = p.send(reply); err != nil {
					p.Terminate()
					e := failure("worker_crashed")
					e.Fatal = true
					return r, e
				}
			case "result", "result_ref":
				if !json.Valid(r.Value) || (r.Type == "result" && len(r.Value) > worker.MaxResultBytes) || (r.Type == "result_ref" && (len(r.Value) != r.EncodedBytes || len(r.Value) <= worker.MaxResultBytes || len(r.Value) > worker.MaxRefCandidateBytes)) {
					p.Terminate()
					e := failure("worker_crashed")
					e.Fatal = true
					return r, e
				}
				return r, nil
			case "error":
				e := failure("invalid_request")
				switch r.Code {
				case "execution_error":
				case "result_too_large":
					e = failure("result_too_large")
					if len(r.Details) > 0 {
						var summary any
						if json.Unmarshal(r.Details, &summary) == nil {
							e.Details = map[string]any{"summary": summary, "guidance": "Reduce the value in JavaScript before returning it: project needed fields, filter rows, or aggregate counts."}
						}
					}
				case "execution_timeout":
					e = failure("execution_timeout")
					e.Fatal = true
				case "async_not_supported":
					e.Message = "promises and async functions are unsupported; Azure host calls return ordinary values"
					e.Fatal = true
				default:
					e = failure("worker_crashed")
					e.Fatal = true
				}
				if e.Fatal {
					p.Terminate()
				}
				return r, e
			default:
				p.Terminate()
				e := failure("worker_crashed")
				e.Fatal = true
				return r, e
			}
		case <-p.done:
			// Drain a terminal frame already written before the process exited.
			select {
			case frame := <-p.frames:
				if frame.err == nil && frame.response.ID == id && frame.response.Type == "error" {
					r := frame.response
					e := failure("worker_crashed")
					if r.Code == "execution_timeout" {
						e = failure("execution_timeout")
					}
					if r.Code == "async_not_supported" {
						e = failure("invalid_request")
						e.Message = "promises and async functions are unsupported; Azure host calls return ordinary values"
					}
					e.Fatal = true
					return r, e
				}
			default:
			}
			e := failure("worker_crashed")
			e.Fatal = true
			return worker.Response{}, e
		}
	}
}
