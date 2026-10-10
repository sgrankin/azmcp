package worker

import (
	"bytes"
	"encoding/json"
	"fmt"
)

const (
	ProtocolVersion       = protocolVersion
	MaxHeapBytes          = maxHeapBytes
	MaxCodeBytes          = maxCodeBytes
	MaxInputBytes         = maxInputBytes
	MaxOutputBytes        = maxOutputBytes
	MaxResultBytes        = maxResultBytes
	MaxRefCandidateBytes  = maxRefCandidateBytes
	MaxLogBytes           = maxLogBytes
	MaxLogEntries         = maxLogEntries
	MaxErrorBytes         = maxErrorBytes
	MaxTimeoutMS          = maxTimeoutMS
	MaxHostCalls          = maxHostCalls
	MaxArtifactChunkBytes = maxArtifactChunkBytes
	MaxArtifactChunks     = maxArtifactChunks
	RSSLimitBytes         = 256 * 1024 * 1024
)

type Request struct {
	Type      string          `json:"type"`
	ID        uint64          `json:"id"`
	Code      string          `json:"code,omitempty"`
	TimeoutMS uint64          `json:"timeout_ms,omitempty"`
	CallID    uint64          `json:"call_id,omitempty"`
	OK        bool            `json:"ok,omitempty"`
	Value     json.RawMessage `json:"value,omitempty"`
	Error     string          `json:"error,omitempty"`
}

func (r Request) MarshalJSON() ([]byte, error) {
	var fields map[string]any
	switch r.Type {
	case "execute":
		fields = map[string]any{"type": r.Type, "id": r.ID, "code": r.Code, "timeout_ms": r.TimeoutMS}
	case "close":
		fields = map[string]any{"type": r.Type, "id": r.ID}
	case "host_call_result":
		fields = map[string]any{"type": r.Type, "id": r.ID, "call_id": r.CallID, "ok": r.OK}
		if r.OK {
			fields["value"] = r.Value
		} else {
			fields["error"] = r.Error
		}
	default:
		return nil, fmt.Errorf("unknown worker request type %q", r.Type)
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(fields); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'}), nil
}

type Response struct {
	Type         string          `json:"type"`
	Protocol     uint16          `json:"protocol,omitempty"`
	ID           uint64          `json:"id,omitempty"`
	Value        json.RawMessage `json:"value,omitempty"`
	EncodedBytes int             `json:"encoded_bytes,omitempty"`
	Logs         []string        `json:"logs"`
	LogsOmitted  int             `json:"logs_omitted"`
	Code         string          `json:"code,omitempty"`
	Message      string          `json:"message,omitempty"`
	Details      json.RawMessage `json:"details,omitempty"`
	CallID       uint64          `json:"call_id,omitempty"`
	Method       string          `json:"method,omitempty"`
	Arguments    json.RawMessage `json:"arguments,omitempty"`
}

type HostCallRequest struct {
	ID        uint64          `json:"id"`
	CallID    uint64          `json:"call_id"`
	Method    string          `json:"method"`
	Arguments json.RawMessage `json:"arguments"`
}

type HostCallResult struct {
	ID     uint64          `json:"id"`
	CallID uint64          `json:"call_id"`
	OK     bool            `json:"ok"`
	Value  json.RawMessage `json:"value,omitempty"`
	Error  string          `json:"error,omitempty"`
}
