package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
)

const Version = "0.1.0"
const maxToolResultBytes = 1024 * 1024
const protocolKey = "io.modelcontextprotocol/protocolVersion"
const capabilitiesKey = "io.modelcontextprotocol/clientCapabilities"

var supportedVersions = []string{"2025-06-18", "2025-11-25", "2026-07-28"}

type ToolCaller interface {
	Call(context.Context, string, json.RawMessage) (any, error)
}
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *rpcError) Error() string { return e.Message }

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

func (r *rpcRequest) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	*r = rpcRequest{ID: fields["id"], Params: fields["params"]}
	if value := fields["jsonrpc"]; len(value) > 0 {
		if err := json.Unmarshal(value, &r.JSONRPC); err != nil {
			return err
		}
	}
	if value := fields["method"]; len(value) > 0 {
		return json.Unmarshal(value, &r.Method)
	}
	return nil
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type protocolState struct {
	selected    bool
	legacy      bool
	initialized bool
	version     string
}

func serverMeta() map[string]any {
	return map[string]any{"io.modelcontextprotocol/serverInfo": map[string]string{"name": "azmcp", "version": Version}}
}
func isSupported(version string) bool {
	for _, v := range supportedVersions {
		if v == version {
			return true
		}
	}
	return false
}
func marshalJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
}

func requestMeta(params json.RawMessage) map[string]json.RawMessage {
	var fields, meta map[string]json.RawMessage
	_ = json.Unmarshal(params, &fields)
	_ = json.Unmarshal(fields["_meta"], &meta)
	return meta
}
func metadataVersion(params json.RawMessage) (string, bool) {
	var version *string
	if json.Unmarshal(requestMeta(params)[protocolKey], &version) != nil || version == nil {
		return "", false
	}
	return *version, true
}

func (s *protocolState) protocol(request rpcRequest) (string, *rpcError) {
	if !s.selected {
		s.selected = true
		_, hasVersion := metadataVersion(request.Params)
		s.legacy = request.Method == "initialize" || (request.Method == "ping" && !hasVersion)
	}
	if !s.legacy {
		if request.Method == "initialize" {
			return "", &rpcError{-32600, "stateless clients must use server/discover", nil}
		}
		meta := requestMeta(request.Params)
		version, hasVersion := metadataVersion(request.Params)
		if hasVersion && !isSupported(version) {
			return "", &rpcError{-32022, "Unsupported protocol version", map[string]any{"requested": version, "supported": supportedVersions}}
		}
		missing := []string{}
		if !hasVersion {
			missing = append(missing, protocolKey)
		}
		if !validClientCapabilities(meta[capabilitiesKey]) {
			missing = append(missing, capabilitiesKey)
		}
		if len(missing) > 0 {
			return "", &rpcError{-32602, "request _meta is missing or malformed: " + strings.Join(missing, ", "), map[string]any{"missing": missing}}
		}
		return version, nil
	}
	if request.Method == "ping" {
		return s.version, nil
	}
	if request.Method == "initialize" {
		if s.initialized {
			return "", &rpcError{-32600, "connection is already initialized", nil}
		}
		params, ok := capabilityObject(request.Params)
		client, clientOK := capabilityObject(params["clientInfo"])
		var version, clientName, clientVersion *string
		if !ok || !clientOK || json.Unmarshal(params["protocolVersion"], &version) != nil || version == nil ||
			!validClientCapabilities(params["capabilities"]) || json.Unmarshal(client["name"], &clientName) != nil || clientName == nil ||
			json.Unmarshal(client["version"], &clientVersion) != nil || clientVersion == nil {
			return "", &rpcError{-32602, "invalid initialize parameters", nil}
		}
		if *version != "2025-06-18" && *version != "2025-11-25" {
			return "", &rpcError{-32602, "unsupported initialize protocol version; use an initialize-based revision or server/discover for 2026-07-28", map[string]any{"supportedVersions": supportedVersions}}
		}
		s.version = *version
		s.initialized = true
		return s.version, nil
	}
	if !s.initialized {
		return "", &rpcError{-32600, "initialize is required before requests", nil}
	}
	return s.version, nil
}

func capabilityObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil, false
	}
	return fields, true
}
func optionalCapabilityObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, true
	}
	return capabilityObject(raw)
}
func capabilityFlag(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	var flag *bool
	return json.Unmarshal(raw, &flag) == nil
}

// Capability extensions stay open; known fields retain their reviewed JSON
// types, including null for absent optional capabilities.
func validClientCapabilities(raw json.RawMessage) bool {
	caps, ok := capabilityObject(raw)
	if !ok {
		return false
	}
	for _, name := range []string{"experimental", "extensions"} {
		entries, ok := optionalCapabilityObject(caps[name])
		if !ok {
			return false
		}
		for _, value := range entries {
			if _, ok := capabilityObject(value); !ok {
				return false
			}
		}
	}
	roots, ok := optionalCapabilityObject(caps["roots"])
	if !ok || !capabilityFlag(roots["listChanged"]) {
		return false
	}
	sampling, ok := optionalCapabilityObject(caps["sampling"])
	if !ok {
		return false
	}
	for _, name := range []string{"tools", "context"} {
		if _, ok := optionalCapabilityObject(sampling[name]); !ok {
			return false
		}
	}
	elicitation, ok := optionalCapabilityObject(caps["elicitation"])
	if !ok {
		return false
	}
	form, ok := optionalCapabilityObject(elicitation["form"])
	if !ok || !capabilityFlag(form["schemaValidation"]) {
		return false
	}
	_, ok = optionalCapabilityObject(elicitation["url"])
	return ok
}

// Serve owns a closable input so cancellation also interrupts idle reads.
// It reads continuously while independent tool calls execute.
func Serve(ctx context.Context, input io.ReadCloser, output io.Writer, application ToolCaller) error {
	parentCtx := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopRead := context.AfterFunc(ctx, func() { _ = input.Close() })
	defer stopRead()
	stopWrite := context.AfterFunc(parentCtx, func() {
		if closer, ok := output.(io.Closer); ok {
			_ = closer.Close()
		}
	})
	defer stopWrite()
	var writeMu sync.Mutex
	send := func(response rpcResponse) error {
		raw, err := marshalJSON(response)
		if err != nil {
			return err
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		_, err = output.Write(append(raw, '\n'))
		return err
	}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), maxToolResultBytes+1)
	state := protocolState{}
	var activeMu sync.Mutex
	active := map[string]context.CancelFunc{}
	var calls sync.WaitGroup
	var outputErr error
	var handshakeErr error
	var errMu sync.Mutex
	remember := func(err error) {
		if err != nil && parentCtx.Err() == nil {
			errMu.Lock()
			if outputErr == nil {
				outputErr = err
				cancel()
			}
			errMu.Unlock()
		}
	}
	for scanner.Scan() {
		if ctx.Err() != nil {
			break
		}
		var request rpcRequest
		if _, jsonErr := uniqueJSON(scanner.Bytes()); jsonErr != nil || json.Unmarshal(scanner.Bytes(), &request) != nil {
			remember(send(rpcResponse{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "Parse error", nil}}))
			continue
		}
		if request.JSONRPC != "2.0" || request.Method == "" || !validRequestID(request.ID) {
			remember(send(rpcResponse{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32600, "Invalid Request", nil}}))
			continue
		}
		if len(request.ID) == 0 {
			if !state.selected {
				state.selected = true
				state.legacy = true
			}
			if state.legacy && !state.initialized {
				handshakeErr = fmt.Errorf("initialize failed: expected initialize request")
				break
			}
			if request.Method == "notifications/cancelled" {
				if args, ok := capabilityObject(request.Params); ok {
					key := requestIDKey(args["requestId"])
					activeMu.Lock()
					stop := active[key]
					activeMu.Unlock()
					if stop != nil {
						stop()
					}
				}
			}
			continue
		}
		version, protocolErr := state.protocol(request)
		if protocolErr != nil {
			remember(send(rpcResponse{JSONRPC: "2.0", ID: request.ID, Error: protocolErr}))
			if state.legacy && !state.initialized && request.Method == "initialize" {
				handshakeErr = fmt.Errorf("initialize failed: %s", protocolErr.Message)
				break
			}
			continue
		}
		// Resolve lifecycle changes in input order; independent tool calls may then run concurrently.
		if request.Method != "tools/call" {
			value, rpcErr := protocolResult(request, version, state.legacy)
			remember(send(rpcResponse{JSONRPC: "2.0", ID: request.ID, Result: value, Error: rpcErr}))
			continue
		}
		args, ok := capabilityObject(request.Params)
		var name string
		if !ok || json.Unmarshal(args["name"], &name) != nil || name == "" {
			remember(send(rpcResponse{JSONRPC: "2.0", ID: request.ID, Error: &rpcError{-32602, "invalid tools/call parameters", nil}}))
			continue
		}
		known := false
		for _, tool := range catalog {
			if tool.Name == name {
				known = true
				break
			}
		}
		if !known {
			remember(send(rpcResponse{JSONRPC: "2.0", ID: request.ID, Error: &rpcError{-32601, "unknown tool: " + name, nil}}))
			continue
		}
		arguments, err := parseArguments(name, args["arguments"])
		if err != nil {
			remember(send(rpcResponse{JSONRPC: "2.0", ID: request.ID, Error: &rpcError{-32602, errArguments.Error(), nil}}))
			continue
		}
		callCtx, stop := context.WithCancel(ctx)
		key := requestIDKey(request.ID)
		activeMu.Lock()
		if _, exists := active[key]; exists {
			activeMu.Unlock()
			stop()
			remember(send(rpcResponse{JSONRPC: "2.0", ID: request.ID, Error: &rpcError{-32600, "duplicate active request ID", nil}}))
			continue
		}
		active[key] = stop
		activeMu.Unlock()
		calls.Add(1)
		go func(id json.RawMessage, version, name string, arguments json.RawMessage) {
			defer calls.Done()
			defer stop()
			value, err := application.Call(callCtx, name, arguments)
			result, rpcErr := toolResult(value, err, version)
			remember(send(rpcResponse{JSONRPC: "2.0", ID: id, Result: result, Error: rpcErr}))
			activeMu.Lock()
			delete(active, key)
			activeMu.Unlock()
		}(append(json.RawMessage(nil), request.ID...), version, name, append(json.RawMessage(nil), arguments...))
	}
	readErr, cancelled := scanner.Err(), ctx.Err() != nil
	cancel()
	calls.Wait()
	errMu.Lock()
	err := outputErr
	errMu.Unlock()
	if err != nil {
		return err
	}
	if handshakeErr != nil {
		return handshakeErr
	}
	if cancelled {
		return nil
	}
	return readErr
}

func validRequestID(id json.RawMessage) bool {
	if len(id) == 0 {
		return true
	}
	return requestIDKey(id) != ""
}

func requestIDKey(id json.RawMessage) string {
	id = bytes.TrimSpace(id)
	if len(id) == 0 {
		return ""
	}
	if id[0] == '"' {
		var value string
		if json.Unmarshal(id, &value) != nil {
			return ""
		}
		return "string:" + value
	}
	var number int64
	if json.Unmarshal(id, &number) != nil || bytes.Equal(id, []byte("null")) || bytes.Equal(id, []byte("-0")) {
		return ""
	}
	return "number:" + strconv.FormatInt(number, 10)
}

func protocolResult(request rpcRequest, version string, legacy bool) (any, *rpcError) {
	switch request.Method {
	case "initialize":
		return map[string]any{"protocolVersion": version, "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]string{"name": "azmcp", "version": Version}}, nil
	case "server/discover":
		if version != "2026-07-28" {
			return nil, &rpcError{-32601, "server/discover requires protocol version 2026-07-28", nil}
		}
		return map[string]any{"resultType": "complete", "supportedVersions": supportedVersions, "capabilities": map[string]any{"tools": map[string]any{}}, "ttlMs": 60000, "cacheScope": "public", "_meta": serverMeta()}, nil
	case "tools/list":
		var p map[string]json.RawMessage
		if len(request.Params) > 0 && json.Unmarshal(request.Params, &p) != nil {
			return nil, &rpcError{-32602, "invalid tools/list parameters", nil}
		}
		result := map[string]any{"tools": catalog, "_meta": serverMeta()}
		if version == "2026-07-28" {
			result["resultType"] = "complete"
			result["ttlMs"] = 60000
			result["cacheScope"] = "public"
		}
		return result, nil
	case "ping":
		if legacy {
			return map[string]any{}, nil
		}
	}
	return nil, &rpcError{-32601, request.Method, nil}
}

func toolResult(value any, err error, version string) (any, *rpcError) {
	isError := err != nil
	if err != nil {
		value = errorValue(err)
	}
	encoded, encodeErr := marshalJSON(value)
	if encodeErr != nil {
		return nil, &rpcError{-32603, "tool result serialization failed", nil}
	}
	makeResult := func(value any, encoded []byte, isError bool) map[string]any {
		result := map[string]any{"content": []any{map[string]string{"type": "text", "text": string(encoded)}}, "structuredContent": value, "isError": isError, "_meta": serverMeta()}
		if version == "2026-07-28" {
			result["resultType"] = "complete"
		}
		return result
	}
	result := makeResult(value, encoded, isError)
	wire, encodeErr := marshalJSON(result)
	if encodeErr != nil {
		return nil, &rpcError{-32603, "tool result serialization failed", nil}
	}
	if len(wire) > maxToolResultBytes {
		size := len(wire)
		value = errorValue(&Error{Code: "result_too_large", Message: "structured tool result exceeded the 1 MiB transport limit", Details: shapeDetails(value, size, maxToolResultBytes)})
		encoded, _ = marshalJSON(value)
		result = makeResult(value, encoded, true)
	}
	return result, nil
}

func errorValue(err error) any {
	e := publicError(err)
	correlation, randomErr := randomHex(16)
	if randomErr != nil {
		panic(fmt.Errorf("generate error correlation ID: %w", randomErr))
	}
	result := map[string]any{"code": e.Code, "message": e.Message, "retryable": e.Retryable, "correlationId": correlation}
	if e.Details != nil {
		result["details"] = e.Details
	}
	return result
}
