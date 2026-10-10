package core

import (
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

type QueryPair struct {
	Name  string
	Value string
}
type RequestTarget struct {
	Path     string
	Segments []string
	Query    []QueryPair
}

func control(value string) bool { return strings.IndexFunc(value, unicode.IsControl) >= 0 }
func hex(byte byte) bool {
	return byte >= '0' && byte <= '9' || byte >= 'a' && byte <= 'f' || byte >= 'A' && byte <= 'F'
}
func validEscapes(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] == '%' {
			if i+2 >= len(value) || !hex(value[i+1]) || !hex(value[i+2]) {
				return false
			}
			i += 2
		}
	}
	return true
}
func nestedEscape(value string) bool {
	for i := 0; i+2 < len(value); i++ {
		if value[i] == '%' && hex(value[i+1]) && hex(value[i+2]) {
			return true
		}
	}
	return false
}
func formEncode(value string, query bool) string {
	const digits = "0123456789ABCDEF"
	var encoded strings.Builder
	for _, b := range []byte(value) {
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("*-._", rune(b)) {
			encoded.WriteByte(b)
		} else if query && b == ' ' {
			encoded.WriteByte('+')
		} else {
			encoded.WriteByte('%')
			encoded.WriteByte(digits[b>>4])
			encoded.WriteByte(digits[b&15])
		}
	}
	return encoded.String()
}

// Query decoding permits malformed UTF-8, replacing each maximal malformed
// sequence as url::form_urlencoded does. ToValidUTF8 instead collapses a run
// of unrelated invalid bytes, which changes the query sent to the service.
func queryUTF8(value string) string {
	if utf8.ValidString(value) {
		return value
	}
	var result strings.Builder
	for len(value) > 0 {
		r, size := utf8.DecodeRuneInString(value)
		if r != utf8.RuneError || size != 1 {
			result.WriteString(value[:size])
			value = value[size:]
			continue
		}
		length := 1
		expected := 1
		lead := value[0]
		switch {
		case lead >= 0xc2 && lead <= 0xdf:
			expected = 2
		case lead >= 0xe0 && lead <= 0xef:
			expected = 3
		case lead >= 0xf0 && lead <= 0xf4:
			expected = 4
		}
		for length < expected && length < len(value) {
			next := value[length]
			if next < 0x80 || next > 0xbf || length == 1 && (lead == 0xe0 && next < 0xa0 || lead == 0xed && next > 0x9f || lead == 0xf0 && next < 0x90 || lead == 0xf4 && next > 0x8f) {
				break
			}
			length++
		}
		result.WriteRune(utf8.RuneError)
		value = value[length:]
	}
	return result.String()
}
func ParseTarget(value string) (RequestTarget, error) {
	var target RequestTarget
	reject := func(message string) (RequestTarget, error) { return target, Fail("invalid_request", message) }
	if len(value) > 16*1024 {
		return reject("request target exceeds size limit")
	}
	if !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") {
		return reject("request target must be an absolute path without authority")
	}
	if strings.Contains(value, "#") || strings.Contains(value, "\\") {
		return reject("request target contains fragment or backslash")
	}
	path, query, hasQuery := strings.Cut(value, "?")
	if len(path) > 1 && strings.HasSuffix(path, "/") || strings.Contains(path, "//") {
		return reject("request target contains empty path segments")
	}
	for _, segment := range strings.Split(path, "/")[1:] {
		if !validEscapes(segment) {
			return reject("request target contains invalid percent encoding")
		}
		decoded, err := url.PathUnescape(segment)
		if err != nil || !utf8.ValidString(decoded) {
			return reject("request target contains invalid UTF-8")
		}
		if decoded == "." || decoded == ".." || strings.ContainsAny(decoded, "/\\") || nestedEscape(decoded) || control(decoded) {
			return reject("request target contains unsafe path segment")
		}
		target.Segments = append(target.Segments, decoded)
	}
	if hasQuery && query != "" {
		if !validEscapes(query) {
			return reject("request query contains invalid percent encoding")
		}
		for _, pair := range strings.Split(query, "&") {
			if pair == "" {
				continue
			}
			name, value, _ := strings.Cut(pair, "=")
			name, _ = url.QueryUnescape(name)
			value, _ = url.QueryUnescape(value)
			name = queryUTF8(name)
			value = queryUTF8(value)
			if EqualFoldASCII(name, "api-version") || control(name) || control(value) {
				return reject("request query contains an API-version override or control character")
			}
			target.Query = append(target.Query, QueryPair{name, value})
			if len(target.Query) > 64 {
				return reject("request query contains too many pairs")
			}
		}
	}
	encoded := make([]string, len(target.Segments))
	for i, segment := range target.Segments {
		encoded[i] = formEncode(segment, false)
	}
	target.Path = "/" + strings.Join(encoded, "/")
	return target, nil
}
func (target RequestTarget) String() string {
	result := target.Path
	if len(target.Query) > 0 {
		pairs := make([]string, len(target.Query))
		for i, pair := range target.Query {
			pairs[i] = formEncode(pair.Name, true) + "=" + formEncode(pair.Value, true)
		}
		result += "?" + strings.Join(pairs, "&")
	}
	return result
}
