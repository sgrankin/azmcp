package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	protocolVersion       = 1
	maxHeapBytes          = 64 * 1024 * 1024
	maxCodeBytes          = 256 * 1024
	maxInputBytes         = 512 * 1024
	maxOutputBytes        = 1024 * 1024
	maxResultBytes        = 64 * 1024
	maxRefCandidateBytes  = 480 * 1024
	maxLogBytes           = 64 * 1024
	maxLogEntries         = 256
	maxErrorBytes         = 8 * 1024
	maxTimeoutMS          = 60 * 60 * 1000
	maxHostCalls          = 256
	maxArtifactChunkBytes = 384 * 1024
	maxArtifactChunks     = 192
)

type request struct {
	Type      string
	ID        uint64
	Code      string
	TimeoutMS uint64
	CallID    uint64
	OK        bool
	Value     json.RawMessage
	Error     string
}

type response map[string]any

type inbound struct {
	request request
	err     error
}

func parseRequest(frame []byte) (request, error) {
	var r request
	fields, err := objectFields(frame)
	if err != nil {
		return r, err
	}
	if err = field(fields, "type", &r.Type); err != nil {
		return r, err
	}
	var allowed []string
	switch r.Type {
	case "execute":
		allowed = []string{"type", "id", "code", "timeout_ms"}
		if err = field(fields, "code", &r.Code); err != nil {
			return r, err
		}
		if err = field(fields, "timeout_ms", &r.TimeoutMS); err != nil {
			return r, err
		}
	case "close":
		allowed = []string{"type", "id"}
	case "host_call_result":
		allowed = []string{"type", "id", "call_id", "ok", "value", "error"}
		if err = field(fields, "call_id", &r.CallID); err != nil {
			return r, err
		}
		if err = field(fields, "ok", &r.OK); err != nil {
			return r, err
		}
		r.Value = fields["value"]
		if raw, ok := fields["error"]; ok && !bytes.Equal(raw, []byte("null")) {
			if err = json.Unmarshal(raw, &r.Error); err != nil {
				return r, err
			}
		}
		if r.OK {
			if r.Value == nil || r.Error != "" || (fields["error"] != nil && !bytes.Equal(fields["error"], []byte("null"))) {
				return r, errors.New("invalid successful host-call result")
			}
		} else {
			if (r.Value != nil && !bytes.Equal(r.Value, []byte("null"))) || r.Error == "" || len(r.Error) > maxErrorBytes {
				return r, errors.New("invalid rejected host-call result")
			}
		}
	default:
		return r, errors.New("unknown worker request type")
	}
	if err = field(fields, "id", &r.ID); err != nil {
		return r, err
	}
	if err = closedFields(fields, allowed); err != nil {
		return r, err
	}
	return r, nil
}

func objectFields(raw []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return nil, errors.New("expected JSON object")
	}
	fields := make(map[string]json.RawMessage)
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return nil, err
		}
		name := key.(string)
		if _, exists := fields[name]; exists {
			return nil, errors.New("duplicate JSON field")
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, err
		}
		fields[name] = value
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing JSON input")
	}
	return fields, nil
}

func field(fields map[string]json.RawMessage, name string, target any) error {
	value, ok := fields[name]
	if !ok || bytes.Equal(value, []byte("null")) {
		return fmt.Errorf("missing field %s", name)
	}
	return json.Unmarshal(value, target)
}

func closedFields(fields map[string]json.RawMessage, allowed []string) error {
	for name := range fields {
		found := false
		for _, a := range allowed {
			if name == a {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("unknown field %s", name)
		}
	}
	return nil
}

func readRequests(reader io.Reader, requests chan<- inbound) {
	defer close(requests)
	r := bufio.NewReaderSize(reader, 4096)
	for {
		var frame []byte
		for {
			part, err := r.ReadSlice('\n')
			if len(frame)+len(part) > maxInputBytes {
				requests <- inbound{err: errors.New("worker input limit exceeded")}
				return
			}
			frame = append(frame, part...)
			if errors.Is(err, bufio.ErrBufferFull) {
				continue
			}
			if err != nil && !errors.Is(err, io.EOF) {
				requests <- inbound{err: err}
				return
			}
			if errors.Is(err, io.EOF) && len(frame) == 0 {
				return
			}
			if len(frame) == 0 || frame[len(frame)-1] != '\n' {
				requests <- inbound{err: errors.New("unterminated worker frame")}
				return
			}
			break
		}
		if !utf8.Valid(frame) {
			requests <- inbound{err: errors.New("worker input is not UTF-8")}
			return
		}
		request, err := parseRequest(frame)
		requests <- inbound{request: request, err: err}
		if err != nil {
			return
		}
	}
}

func encodeResponse(value response) ([]byte, error) {
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	if err := e.Encode(value); err != nil {
		return nil, err
	}
	limit := maxOutputBytes
	if value["type"] == "host_call" {
		limit = maxInputBytes
	}
	if buf.Len() > limit {
		return nil, errors.New("worker output limit exceeded")
	}
	return buf.Bytes(), nil
}

func validMethod(method string) bool {
	switch method {
	case "az.request", "az.graph", "az.metrics.single", "az.metrics.batch", "az.logs.query", "az.artifacts.writeJson", "az.artifacts.writeJsonArray", "az.artifacts.writeJsonLines", "az.ref":
		return true
	}
	return false
}

func validateStream(method string, raw []byte) error {
	if method != "az.artifacts.writeJsonArray" && method != "az.artifacts.writeJsonLines" {
		return nil
	}
	fields, err := objectFields(raw)
	if err != nil {
		return errors.New("artifact stream arguments do not match the closed schema")
	}
	var phase string
	if err := field(fields, "phase", &phase); err != nil {
		return err
	}
	var allowed []string
	if phase != "begin" {
		var streamID string
		if err := field(fields, "streamId", &streamID); err != nil {
			return err
		}
		if streamID == "" || len(streamID) > 128 || strings.IndexFunc(streamID, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_')
		}) != -1 {
			return errors.New("artifact stream ID is invalid")
		}
	}
	switch phase {
	case "begin":
		allowed = []string{"phase", "name", "compression"}
		var name, compression string
		if err := field(fields, "name", &name); err != nil {
			return err
		}
		if err := field(fields, "compression", &compression); err != nil {
			return err
		}
		if name == "" || compression != "identity" && compression != "lz4" {
			return errors.New("invalid artifact stream begin")
		}
	case "append":
		allowed = []string{"phase", "streamId", "sequence", "values"}
		var sequence uint16
		var values []json.RawMessage
		if err := field(fields, "sequence", &sequence); err != nil {
			return err
		}
		if err := field(fields, "values", &values); err != nil {
			return err
		}
		if sequence >= maxArtifactChunks || len(values) == 0 || len(fields["values"]) > maxArtifactChunkBytes {
			return errors.New("artifact stream chunk limit exceeded")
		}
	case "finish":
		allowed = []string{"phase", "streamId", "chunks", "items"}
		var chunks uint16
		var items uint64
		if err := field(fields, "chunks", &chunks); err != nil {
			return err
		}
		if err := field(fields, "items", &items); err != nil {
			return err
		}
		if chunks > maxArtifactChunks || (chunks == 0) != (items == 0) {
			return errors.New("artifact stream totals are invalid")
		}
	case "abort":
		allowed = []string{"phase", "streamId"}
	default:
		return errors.New("unknown artifact stream phase")
	}
	return closedFields(fields, allowed)
}

func truncate(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	for limit > 0 && !utf8.RuneStart(text[limit]) {
		limit--
	}
	return text[:limit]
}

func sanitize(text string, limit int) string {
	text = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, text)
	if len(text) > limit {
		return truncate(text, limit-3) + "…"
	}
	return text
}

func typeName(value any) string {
	switch value.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case json.Number:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	default:
		return "object"
	}
}

func resultSummary(raw []byte) (response, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value any
	if err := d.Decode(&value); err != nil {
		return nil, err
	}
	s := response{"type": typeName(value), "encodedBytes": len(raw), "limitBytes": maxResultBytes}
	counts := make(map[string]int)
	add := func(value any) { counts[typeName(value)]++ }
	switch v := value.(type) {
	case string:
		s["length"] = utf8.RuneCountInString(v)
	case []any:
		s["length"] = len(v)
		for _, child := range v[:min(len(v), 32)] {
			add(child)
		}
		s["counts"] = counts
		if len(v) > 32 {
			s["countsOmitted"] = len(v) - 32
		}
	case map[string]any:
		all := make([]string, 0, len(v))
		for key := range v {
			all = append(all, key)
		}
		sort.Strings(all)
		keys := make([]string, 0, min(len(v), 32))
		for _, key := range all[:min(len(v), 32)] {
			keys = append(keys, truncate(key, 128))
			add(v[key])
		}
		sort.Strings(keys)
		s["keyCount"], s["keys"], s["counts"] = len(v), keys, counts
		if len(v) > 32 {
			s["keysOmitted"], s["keysSampled"], s["countsOmitted"] = len(v)-32, true, len(v)-32
		}
	}
	return s, nil
}
