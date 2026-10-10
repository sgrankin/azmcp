package core

import (
	"bytes"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

type Route struct {
	Cloud                  Cloud    `json:"cloud"`
	Purpose                string   `json:"purpose"`
	Method                 string   `json:"method"`
	PathTemplate           string   `json:"pathTemplate"`
	APIVersions            []string `json:"apiVersions"`
	RBACAction             string   `json:"rbacAction"`
	ArmTier                string   `json:"armTier"`
	AllowedQueryParameters []string `json:"allowedQueryParameters"`
}

func (route *Route) UnmarshalJSON(raw []byte) error {
	type fields Route
	var decoded fields
	if err := DecodeClosed(raw, &decoded); err != nil {
		return err
	}
	var presence map[string]json.RawMessage
	if err := json.Unmarshal(raw, &presence); err != nil {
		return err
	}
	if value, ok := presence["allowedQueryParameters"]; ok && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return Fail("invalid_request", "route query parameters must be an array")
	}
	if decoded.AllowedQueryParameters == nil {
		decoded.AllowedQueryParameters = []string{}
	}
	*route = Route(decoded)
	return nil
}

type Policy struct {
	Version string
	Hash    string
	Routes  []Route
}
type template struct {
	parts    []string
	literals int
	tail     bool
}

var parameterName = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

func parseTemplate(value string) (template, error) {
	var parsed template
	if !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || value == "/" || strings.HasSuffix(value, "/") || strings.Contains(value, "//") || strings.ContainsAny(value, "?#\\%") {
		return parsed, Fail("invalid_request", "invalid reviewed path template")
	}
	parsed.parts = strings.Split(value, "/")[1:]
	if len(parsed.parts) > 64 {
		return parsed, Fail("invalid_request", "reviewed path template is overlarge")
	}
	for _, part := range parsed.parts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			name := part[1 : len(part)-1]
			if !parameterName.MatchString(name) {
				return parsed, Fail("invalid_request", "invalid route parameter")
			}
			if name == "resourceUri" {
				if parsed.tail {
					return parsed, Fail("invalid_request", "duplicate resourceUri parameter")
				}
				parsed.tail = true
			}
		} else {
			if strings.ContainsAny(part, "{}") || control(part) {
				return parsed, Fail("invalid_request", "invalid route literal")
			}
			parsed.literals++
		}
	}
	return parsed, nil
}
func (r Route) Validate() error {
	if _, err := ParseCloud(string(r.Cloud)); err != nil {
		return err
	}
	if !Contains([]string{"request", "resourceGraph", "logsQuery", "internal", "metricsSingle", "metricsBatch"}, r.Purpose) || !Contains([]string{"GET", "POST", "PUT", "PATCH", "DELETE"}, r.Method) || !Contains([]string{"inspect", "read", "write"}, r.ArmTier) {
		return Fail("invalid_request", "invalid reviewed route discriminator")
	}
	if _, err := parseTemplate(r.PathTemplate); err != nil {
		return err
	}
	if !bounded(r.RBACAction, 512) || len(r.APIVersions) == 0 || len(r.APIVersions) > 32 {
		return Fail("invalid_request", "invalid reviewed RBAC action or API versions")
	}
	for i, version := range r.APIVersions {
		if !bounded(version, 64) || i > 0 && r.APIVersions[i-1] >= version {
			return Fail("invalid_request", "API versions must be sorted unique bounded values")
		}
	}
	if len(r.AllowedQueryParameters) > 64 {
		return Fail("invalid_request", "too many reviewed query parameters")
	}
	for i, name := range r.AllowedQueryParameters {
		if !bounded(name, 128) || EqualFoldASCII(name, "api-version") || i > 0 && lowerASCII(r.AllowedQueryParameters[i-1]) >= lowerASCII(name) {
			return Fail("invalid_request", "query parameters must be sorted unique reviewed names")
		}
	}
	return nil
}
func matchTemplate(parts, actual []string, index, offset int, parameters map[string]string) bool {
	if index == len(parts) {
		return offset == len(actual)
	}
	if parts[index] == "{resourceUri}" {
		remaining := len(parts) - index - 1
		for count := 1; count <= len(actual)-offset-remaining; count++ {
			if matchTemplate(parts, actual, index+1, offset+count, parameters) {
				return true
			}
		}
		return false
	}
	if offset >= len(actual) {
		return false
	}
	part := parts[index]
	if strings.HasPrefix(part, "{") {
		name := part[1 : len(part)-1]
		if actual[offset] == "" {
			return false
		}
		if prior, ok := parameters[name]; ok && !EqualFoldASCII(prior, actual[offset]) {
			return false
		}
		next := make(map[string]string, len(parameters)+1)
		for key, value := range parameters {
			next[key] = value
		}
		next[name] = actual[offset]
		return matchTemplate(parts, actual, index+1, offset+1, next)
	}
	return EqualFoldASCII(part, actual[offset]) && matchTemplate(parts, actual, index+1, offset+1, parameters)
}
func (p Policy) Classify(cloud Cloud, purpose, method string, target RequestTarget, version string) (Route, error) {
	var best Route
	specificity := -1
	ambiguous := false
	for _, route := range p.Routes {
		if route.Cloud != cloud || route.Purpose != purpose || route.Method != method || !Contains(route.APIVersions, version) {
			continue
		}
		allowed := true
		for _, pair := range target.Query {
			found := false
			for _, name := range route.AllowedQueryParameters {
				if EqualFoldASCII(name, pair.Name) {
					found = true
					break
				}
			}
			if !found {
				allowed = false
				break
			}
		}
		if !allowed {
			continue
		}
		parsed, err := parseTemplate(route.PathTemplate)
		if err != nil {
			panic("invalid installed core policy")
		}
		if !matchTemplate(parsed.parts, target.Segments, 0, 0, map[string]string{}) {
			continue
		}
		if parsed.literals > specificity {
			best, specificity, ambiguous = route, parsed.literals, false
		} else if parsed.literals == specificity {
			ambiguous = true
		}
	}
	if specificity < 0 {
		return Route{}, Fail("route_denied", "request does not match a reviewed route")
	}
	if ambiguous {
		return Route{}, Fail("route_denied", "request matches equally specific reviewed routes")
	}
	return best, nil
}
func (p Policy) Validate() error {
	if p.Version == "" || len(p.Routes) == 0 {
		return Fail("invalid_request", "policy identity and routes are required")
	}
	for i, route := range p.Routes {
		if err := route.Validate(); err != nil {
			return err
		}
		for _, other := range p.Routes[:i] {
			if selectorsOverlap(route, other) {
				return Fail("invalid_request", "overlapping executable route selectors")
			}
		}
	}
	return nil
}

type matchToken struct{ literal, variable string }

func expand(t template, length int) []matchToken {
	if !t.tail && length != len(t.parts) || length < len(t.parts) {
		return nil
	}
	var result []matchToken
	for _, part := range t.parts {
		if part == "{resourceUri}" {
			for range length - len(t.parts) + 1 {
				result = append(result, matchToken{})
			}
		} else if strings.HasPrefix(part, "{") {
			result = append(result, matchToken{variable: part[1 : len(part)-1]})
		} else {
			result = append(result, matchToken{literal: part})
		}
	}
	return result
}
func templatesOverlap(left, right string) bool {
	a, err := parseTemplate(left)
	if err != nil {
		return false
	}
	b, err := parseTemplate(right)
	if err != nil || a.literals != b.literals {
		return false
	}
	maximum := max(len(a.parts), len(b.parts))
	if a.tail || b.tail {
		maximum = len(a.parts) + len(b.parts)
	}
	for length := max(len(a.parts), len(b.parts)); length <= maximum; length++ {
		aa, bb := expand(a, length), expand(b, length)
		if aa == nil || bb == nil {
			continue
		}
		parents := map[string]string{}
		constants := map[string]string{}
		var find func(string) string
		find = func(v string) string {
			if parents[v] == "" {
				parents[v] = v
			}
			if parents[v] != v {
				parents[v] = find(parents[v])
			}
			return parents[v]
		}
		bind := func(v, value string) bool {
			root := find(v)
			if prior := constants[root]; prior != "" && !EqualFoldASCII(prior, value) {
				return false
			}
			constants[root] = value
			return true
		}
		possible := true
		for i, x := range aa {
			y := bb[i]
			switch {
			case x.literal != "" && y.literal != "":
				possible = EqualFoldASCII(x.literal, y.literal)
			case x.literal != "" && y.variable != "":
				possible = bind("r:"+y.variable, x.literal)
			case x.variable != "" && y.literal != "":
				possible = bind("l:"+x.variable, y.literal)
			case x.variable != "" && y.variable != "":
				u, v := find("l:"+x.variable), find("r:"+y.variable)
				if u != v {
					if constants[u] != "" && constants[v] != "" && !EqualFoldASCII(constants[u], constants[v]) {
						possible = false
					} else {
						parents[v] = u
						if constants[u] == "" {
							constants[u] = constants[v]
						}
					}
				}
			}
			if !possible {
				break
			}
		}
		if possible {
			return true
		}
	}
	return false
}
func selectorsOverlap(a, b Route) bool {
	if a.Cloud != b.Cloud || a.Purpose != b.Purpose || a.Method != b.Method {
		return false
	}
	for _, version := range a.APIVersions {
		if Contains(b.APIVersions, version) && templatesOverlap(a.PathTemplate, b.PathTemplate) {
			return true
		}
	}
	return false
}
func routeSortKey(r Route) string {
	rank := map[string]string{"request": "0", "resourceGraph": "1", "logsQuery": "2", "internal": "3", "metricsSingle": "4", "metricsBatch": "5"}
	method := map[string]string{"GET": "Get", "POST": "Post", "PUT": "Put", "PATCH": "Patch", "DELETE": "Delete"}
	tier := map[string]string{"inspect": "Inspect", "read": "Read", "write": "Write"}
	return rank[r.Purpose] + "|" + string(r.Cloud) + "|" + r.Purpose + "|" + method[r.Method] + "|" + r.PathTemplate + "|" + strings.Join(r.APIVersions, ",") + "|" + r.RBACAction + "|" + tier[r.ArmTier]
}
func sortRoutes(routes []Route) {
	sort.SliceStable(routes, func(i, j int) bool { return routeSortKey(routes[i]) < routeSortKey(routes[j]) })
}
