package server

import (
	_ "embed"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"strconv"
	"unicode/utf8"

	"azmcp/internal/core"
)

//go:embed tools.json
var catalogJSON []byte

type Tool struct {
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	InputSchema  map[string]any  `json:"inputSchema"`
	OutputSchema map[string]any  `json:"outputSchema"`
	Annotations  map[string]bool `json:"annotations"`
}

var catalog = func() []Tool {
	var tools []Tool
	if err := json.Unmarshal(catalogJSON, &tools); err != nil {
		panic(err)
	}
	return tools
}()

var errArguments = errors.New("tool arguments do not match the declared v0 schema")

func parseArguments(name string, raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	value, err := uniqueJSON(raw)
	if err != nil {
		return nil, errArguments
	}
	for _, tool := range catalog {
		if tool.Name == name {
			if !accepts(tool.InputSchema, value) {
				return nil, errArguments
			}
			return raw, nil
		}
	}
	return nil, errors.New("unknown tool")
}

// accepts validates the closed, checked-in tool schema vocabulary at the MCP boundary.
func accepts(schema map[string]any, value any) bool {
	if constant, ok := schema["const"]; ok && !reflect.DeepEqual(constant, value) {
		return false
	}
	if values, ok := schema["enum"].([]any); ok {
		found := false
		for _, candidate := range values {
			if reflect.DeepEqual(candidate, value) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if choices, ok := schema["oneOf"].([]any); ok {
		matched := 0
		for _, choice := range choices {
			if accepts(choice.(map[string]any), value) {
				matched++
			}
		}
		if matched != 1 {
			return false
		}
	}
	switch schema["type"] {
	case "object":
		obj, ok := value.(map[string]any)
		if !ok {
			return false
		}
		props, _ := schema["properties"].(map[string]any)
		if required, ok := schema["required"].([]any); ok {
			for _, name := range required {
				if _, ok := obj[name.(string)]; !ok {
					return false
				}
			}
		}
		for name, v := range obj {
			property, exists := props[name]
			if !exists {
				if schema["additionalProperties"] == false {
					return false
				}
				continue
			}
			if !accepts(property.(map[string]any), v) {
				return false
			}
		}
	case "array":
		list, ok := value.([]any)
		if !ok {
			return false
		}
		if n, ok := schema["minItems"].(float64); ok && len(list) < int(n) {
			return false
		}
		if n, ok := schema["maxItems"].(float64); ok && len(list) > int(n) {
			return false
		}
		seen := map[string]bool{}
		for _, v := range list {
			if item, ok := schema["items"].(map[string]any); ok && !accepts(item, v) {
				return false
			}
			if schema["uniqueItems"] == true {
				raw, _ := json.Marshal(v)
				if seen[string(raw)] {
					return false
				}
				seen[string(raw)] = true
			}
		}
	case "string":
		str, ok := value.(string)
		if !ok {
			return false
		}
		n := utf8.RuneCountInString(str)
		if limit, ok := schema["minLength"].(float64); ok && n < int(limit) {
			return false
		}
		if limit, ok := schema["maxLength"].(float64); ok && n > int(limit) {
			return false
		}
		if pattern, ok := schema["pattern"].(string); ok && !regexp.MustCompile(pattern).MatchString(str) {
			return false
		}
	case "integer":
		number, ok := value.(json.Number)
		if !ok {
			return false
		}
		n, err := strconv.ParseUint(string(number), 10, 64)
		if err != nil {
			return false
		}
		if min, ok := schema["minimum"].(float64); ok && float64(n) < min {
			return false
		}
		if max, ok := schema["maximum"].(float64); ok && float64(n) > max {
			return false
		}
	case nil:
	default:
		panic("unsupported tool schema type")
	}
	return true
}

func uniqueJSON(raw []byte) (any, error) {
	return core.DecodeJSON(raw)
}
