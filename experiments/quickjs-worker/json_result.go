package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// The Rust protocol receiver recalculates reference sizes by serializing a
// serde_json::Value. Its locked zmij formatter uses fixed notation for float64
// decimal exponents -5 through 15, unlike JavaScript's JSON.stringify.
func canonicalResultJSON(raw []byte) (json.RawMessage, error) {
	if !json.Valid(raw) {
		return nil, errors.New("result is not JSON")
	}
	var output bytes.Buffer
	output.Grow(len(raw))
	for index := 0; index < len(raw); {
		start := index
		if raw[index] == '"' {
			index++
			for index < len(raw) {
				c := raw[index]
				index++
				if c == '\\' {
					index++
				} else if c == '"' {
					break
				}
			}
			var text string
			if err := json.Unmarshal(raw[start:index], &text); err != nil {
				return nil, err
			}
			writeJSONString(&output, text)
		} else if raw[index] == '-' || raw[index] >= '0' && raw[index] <= '9' {
			for index < len(raw) && strings.ContainsRune("-+0123456789.eE", rune(raw[index])) {
				index++
			}
			number, err := canonicalNumber(string(raw[start:index]))
			if err != nil {
				return nil, err
			}
			output.WriteString(number)
		} else {
			output.WriteByte(raw[index])
			index++
		}
	}
	return json.RawMessage(output.Bytes()), nil
}

func writeJSONString(output *bytes.Buffer, text string) {
	output.WriteByte('"')
	const hex = "0123456789abcdef"
	for _, r := range text {
		switch r {
		case '"', '\\':
			output.WriteByte('\\')
			output.WriteRune(r)
		case '\b':
			output.WriteString(`\b`)
		case '\f':
			output.WriteString(`\f`)
		case '\n':
			output.WriteString(`\n`)
		case '\r':
			output.WriteString(`\r`)
		case '\t':
			output.WriteString(`\t`)
		default:
			if r < 0x20 {
				output.WriteString(`\u00`)
				output.WriteByte(hex[r>>4])
				output.WriteByte(hex[r&15])
			} else {
				output.WriteRune(r)
			}
		}
	}
	output.WriteByte('"')
}

func canonicalNumber(number string) (string, error) {
	if !strings.ContainsAny(number, ".eE") {
		if strings.HasPrefix(number, "-") {
			if _, err := strconv.ParseInt(number, 10, 64); err == nil {
				return number, nil
			}
		} else if _, err := strconv.ParseUint(number, 10, 64); err == nil {
			return number, nil
		}
	}
	value, err := strconv.ParseFloat(number, 64)
	if err != nil {
		return "", err
	}
	scientific := strconv.FormatFloat(value, 'e', -1, 64)
	position := strings.IndexByte(scientific, 'e')
	mantissa := scientific[:position]
	exponent, err := strconv.Atoi(scientific[position+1:])
	if err != nil {
		return "", err
	}
	if exponent < -5 || exponent > 15 {
		sign := "+"
		if exponent < 0 {
			sign, exponent = "-", -exponent
		}
		return mantissa + "e" + sign + strconv.Itoa(exponent), nil
	}
	sign := ""
	if mantissa[0] == '-' {
		sign, mantissa = "-", mantissa[1:]
	}
	digits := strings.ReplaceAll(mantissa, ".", "")
	point := exponent + 1
	if point <= 0 {
		return sign + "0." + strings.Repeat("0", -point) + digits, nil
	}
	if point >= len(digits) {
		return sign + digits + strings.Repeat("0", point-len(digits)) + ".0", nil
	}
	return sign + digits[:point] + "." + digits[point:], nil
}
