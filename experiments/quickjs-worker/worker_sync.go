package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"time"

	"modernc.org/quickjs"
)

//go:embed bootstrap_sync.js
var synchronousBootstrap string

// The transport waits in Go, so JavaScript receives an ordinary value without
// a promise resolver table or a microtask loop. Capture the JSON intrinsics
// before caller code can replace them.
const synchronousBridge = `(() => {
  const transport = globalThis.__azmcpSyncTransport;
  const stringify = JSON.stringify;
  const parse = JSON.parse;
  const TypeErrorType = TypeError;
  delete globalThis.__azmcpSyncTransport;
  globalThis.__azmcpHostCall = (method, arguments) => {
    const encoded = stringify(arguments);
    if (encoded === undefined) throw new TypeErrorType("host-call arguments are not JSON serializable");
    return parse(transport(method, encoded));
  };
  return (value) => {
    if (value !== null && (typeof value === "object" || typeof value === "function")
        && typeof value.then === "function") {
      throw new TypeErrorType("synchronous mode cannot return a promise");
    }
    const encoded = stringify(value);
    return encoded === undefined ? "null" : encoded;
  };
})()`

func (e *engine) installSync() error {
	if err := e.vm.RegisterHostFunc("__azmcpSyncTransport", func(args []any) (any, error) {
		if len(args) != 2 {
			return nil, errors.New("invalid synchronous host-call arguments")
		}
		method, methodOK := args[0].(string)
		encoded, encodedOK := args[1].(string)
		if !methodOK || !encodedOK {
			return nil, errors.New("invalid synchronous host-call arguments")
		}
		callID := e.sendHost(method, encoded)
		if e.poison != nil {
			return nil, e.poison
		}
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
				e.poison = errors.New("unexpected or mismatched synchronous host-call response")
				return nil, e.poison
			}
			delete(e.pending, callID)
			if !r.OK {
				return nil, errors.New(sanitize(r.Error, maxErrorBytes))
			}
			return string(r.Value), nil
		case <-timer.C:
			return nil, errors.New("execution deadline exceeded")
		}
	}); err != nil {
		return err
	}
	var err error
	e.control, err = e.vm.EvalValue(synchronousBridge, quickjs.EvalGlobal)
	if err != nil {
		return err
	}
	value, err := e.vm.EvalValue(synchronousBootstrap, quickjs.EvalGlobal)
	if err == nil {
		value.Free()
	}
	return err
}

func (e *engine) executeSync(r request) (response, bool) {
	if err := e.armDeadline(); err != nil {
		return e.executionFailure(err, r.TimeoutMS)
	}
	value, err := e.vm.EvalValue(r.Code, quickjs.EvalGlobal)
	if err != nil {
		return e.executionFailure(err, r.TimeoutMS)
	}
	if err := e.armDeadline(); err != nil {
		value.Free()
		return e.executionFailure(err, r.TimeoutMS)
	}
	encoded, err := e.control.Call(quickjs.UndefinedValue, value)
	value.Free()
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
		panic("synchronous result serializer returned a non-string")
	}
	return e.resultResponse(json.RawMessage(text))
}
