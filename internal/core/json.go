package core

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

// encoding/json accepts duplicate keys and case-insensitive struct field
// names. The reviewed wire schemas require one exact spelling per field.
func readJSON(d *json.Decoder, depth int) (any, error) {
	if depth > 128 {
		return nil, Fail("invalid_request", "JSON nesting limit exceeded")
	}
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delimiter {
	case '{':
		result := map[string]any{}
		for d.More() {
			keyToken, err := d.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, fmt.Errorf("object key is not a string")
			}
			if _, exists := result[key]; exists {
				return nil, detail("invalid_request", "duplicate JSON field %s", key)
			}
			child, err := readJSON(d, depth+1)
			if err != nil {
				return nil, err
			}
			result[key] = child
		}
		if _, err := d.Token(); err != nil {
			return nil, err
		}
		return result, nil
	case '[':
		result := []any{}
		for d.More() {
			child, err := readJSON(d, depth+1)
			if err != nil {
				return nil, err
			}
			result = append(result, child)
		}
		if _, err := d.Token(); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, fmt.Errorf("unexpected closing JSON delimiter")
	}
}
func exactFields(value any, target reflect.Type) error {
	for target.Kind() == reflect.Pointer {
		target = target.Elem()
	}
	if value == nil || target == reflect.TypeFor[json.RawMessage]() {
		return nil
	}
	switch target.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return Fail("invalid_request", "expected a JSON object")
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < target.NumField(); i++ {
			field := target.Field(i)
			if !field.IsExported() {
				continue
			}
			tag := strings.Split(field.Tag.Get("json"), ",")[0]
			if tag == "-" {
				continue
			}
			if tag == "" {
				tag = field.Name
			}
			fields[tag] = field.Type
		}
		for key, child := range object {
			field, ok := fields[key]
			if !ok {
				return detail("invalid_request", "unknown JSON field %s", key)
			}
			if err := exactFields(child, field); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		values, ok := value.([]any)
		if !ok {
			return nil
		}
		for _, child := range values {
			if err := exactFields(child, target.Elem()); err != nil {
				return err
			}
		}
	case reflect.Map:
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		for _, child := range object {
			if err := exactFields(child, target.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

// DecodeJSON preserves JSON numbers and rejects ambiguous fields, excessive
// nesting, and invalid Unicode before wire values become application inputs.
func DecodeJSON(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, Fail("invalid_request", "JSON is not valid UTF-8")
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.UseNumber()
	value, err := readJSON(d, 0)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, Fail("invalid_request", "JSON contains trailing data")
	}
	if err := validJSONUnicode(raw); err != nil {
		return nil, err
	}
	return value, nil
}

func validateJSON(raw []byte, target any, closed bool) error {
	value, err := DecodeJSON(raw)
	if err != nil {
		return err
	}
	if closed {
		t := reflect.TypeOf(target)
		if t == nil || t.Kind() != reflect.Pointer {
			panic("DecodeClosed target must be a pointer")
		}
		return exactFields(value, t.Elem())
	}
	return nil
}

// Go replaces unpaired UTF-16 escapes while serde_json rejects them. A
// replacement would change source bytes before content hashing or binding.
func validJSONUnicode(raw []byte) error {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '"' {
			continue
		}
		for i++; i < len(raw) && raw[i] != '"'; i++ {
			if raw[i] != '\\' {
				continue
			}
			i++
			if raw[i] != 'u' {
				continue
			}
			value, _ := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
			i += 4
			if value >= 0xdc00 && value <= 0xdfff {
				return Fail("invalid_request", "JSON contains an unpaired Unicode surrogate")
			}
			if value < 0xd800 || value > 0xdbff {
				continue
			}
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return Fail("invalid_request", "JSON contains an unpaired Unicode surrogate")
			}
			low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return Fail("invalid_request", "JSON contains an unpaired Unicode surrogate")
			}
			i += 6
		}
	}
	return nil
}
