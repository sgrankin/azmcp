package server

import (
	"azmcp/internal/azure"
	"azmcp/internal/core"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"unicode/utf8"
)

type Error struct {
	Code      string
	Message   string
	Retryable bool
	Details   any
}

func (e *Error) Error() string { return e.Code }
func failure(code string) *Error {
	return &Error{Code: code, Message: messages[code], Retryable: code == "authentication_required" || code == "context_busy" || code == "upstream_error"}
}

var messages = map[string]string{
	"request_cancelled":        "the operation was canceled",
	"invalid_request":          "request is outside the implemented v0 contract",
	"account_ambiguous":        "Azure account binding is missing or ambiguous",
	"authentication_required":  "Azure CLI account profile is unavailable; authenticate the intended cloud and tenant with az login, then retry",
	"subscription_mismatch":    "subscription binding validation failed",
	"context_busy":             "context concurrent operation limit reached; retry after an active call completes",
	"context_evicted":          "the authorization context no longer exists",
	"result_too_large":         "the result exceeds the transport size limit",
	"artifact_capacity":        "managed artifact storage capacity is exhausted",
	"schema_unavailable":       "the offline schema index is unavailable",
	"schema_not_found":         "the reviewed schema entry was not found",
	"schema_version_not_found": "the API version is not reviewed for that entry",
	"schema_cloud_not_bound":   "the schema cloud is not bound by the context",
	"route_denied":             "the request is not in the reviewed route policy",
	"capability_denied":        "the context does not authorize that operation scope",
	"upstream_error":           "the upstream operation could not complete",
}

func publicError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	var host *azure.HostError
	if errors.As(err, &host) {
		code := host.Code
		switch code {
		case "client_unavailable", "audit_unavailable":
			code = "upstream_error"
		case "response_too_large":
			code = "result_too_large"
		case "subscription_ambiguous":
			code = "subscription_mismatch"
		case "cloud_required", "binding_unavailable", "invalid_response", "protocol_error", "cloud_not_bound":
			code = "invalid_request"
		case "principal_mismatch":
			code = "authentication_required"
		}
		return &Error{Code: code, Message: host.Message, Retryable: host.Retryable}
	}
	var c *core.Error
	if errors.As(err, &c) {
		return failure(c.Code)
	}
	return failure("upstream_error")
}
func shapeDetails(value any, size, limit int) any {
	return map[string]any{"summary": shapeSummary(value, size, limit), "guidance": "Project or aggregate results in the Azure query, or use azure_export to write the full response locally."}
}
func valueType(value any) string {
	switch value.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64, json.Number:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	default:
		return "object"
	}
}
func shapeSummary(value any, size, limit int) map[string]any {
	if raw, ok := value.(json.RawMessage); ok {
		var decoded any
		if json.Unmarshal(raw, &decoded) == nil {
			value = decoded
		}
	}
	summary := map[string]any{"type": valueType(value), "encodedBytes": size, "limitBytes": limit}
	switch v := value.(type) {
	case string:
		summary["length"] = utf8.RuneCountInString(v)
	case []any:
		summary["length"] = len(v)
		counts := map[string]int{}
		for _, x := range v[:min(len(v), 32)] {
			counts[valueType(x)]++
		}
		summary["counts"] = counts
		if len(v) > 32 {
			summary["countsOmitted"] = len(v) - 32
		}
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		summary["keyCount"] = len(keys)
		counts := map[string]int{}
		for _, k := range keys[:min(len(keys), 32)] {
			counts[valueType(v[k])]++
		}
		summary["counts"] = counts
		omitted := max(len(keys)-32, 0)
		keys = keys[:min(len(keys), 32)]
		for i, k := range keys {
			if len(k) > 128 {
				k = k[:128]
				for !utf8.ValidString(k) {
					k = k[:len(k)-1]
				}
				keys[i] = k
			}
		}
		summary["keys"] = keys
		summary["keysOmitted"] = omitted
		summary["keysSampled"] = omitted > 0
		if omitted > 0 {
			summary["countsOmitted"] = omitted
		}
	}
	return summary
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
