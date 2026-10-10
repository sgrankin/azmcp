package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"unicode/utf8"

	reviewed "azmcp/fixtures"
)

type RbacEvidence struct {
	Kind         string `json:"kind"`
	Repository   string `json:"repository"`
	Revision     string `json:"revision"`
	Path         string `json:"path"`
	SourceSHA256 string `json:"sourceSha256"`
}
type UpstreamSource struct {
	Kind           string       `json:"kind"`
	Repository     string       `json:"repository"`
	Revision       string       `json:"revision"`
	Path           string       `json:"path"`
	SourceSHA256   string       `json:"sourceSha256"`
	CatalogSHA256  string       `json:"catalogSha256"`
	ReviewID       string       `json:"reviewId"`
	ReviewRevision string       `json:"reviewRevision"`
	ReviewSHA256   string       `json:"reviewSha256"`
	RbacEvidence   RbacEvidence `json:"rbacEvidence"`
}
type ManifestSource struct {
	Kind     string          `json:"kind"`
	Revision string          `json:"revision"`
	Upstream *UpstreamSource `json:"upstream,omitempty"`
}
type ManifestSchema struct {
	EntryID               string   `json:"entryId"`
	ResourceType          string   `json:"resourceType"`
	Operation             string   `json:"operation"`
	Purpose               string   `json:"purpose"`
	DisplayName           string   `json:"displayName"`
	Description           string   `json:"description"`
	CLIEquivalent         *string  `json:"cliEquivalent"`
	Cloud                 Cloud    `json:"cloud"`
	Method                string   `json:"method"`
	CanonicalPathTemplate string   `json:"canonicalPathTemplate"`
	RequestPathTemplate   string   `json:"requestPathTemplate"`
	APIVersions           []string `json:"apiVersions"`
	RBACAction            string   `json:"rbacAction"`
	ArmTier               string   `json:"armTier"`
	DataPlaneGrant        *string  `json:"dataPlaneGrant"`
	ArgumentSchema        any      `json:"argumentSchema"`
	RequestBodySchema     any      `json:"requestBodySchema"`
	ResponseBodySchema    any      `json:"responseBodySchema"`
}
type RouteManifest struct {
	FormatVersion uint32           `json:"formatVersion"`
	ManifestID    string           `json:"manifestId"`
	PolicyVersion string           `json:"policyVersion"`
	PolicyHash    string           `json:"policyHash"`
	Source        ManifestSource   `json:"source"`
	Routes        []Route          `json:"routes"`
	Schemas       []ManifestSchema `json:"schemas"`
}

func DecodeClosed(raw []byte, target any) error {
	if !utf8.Valid(raw) {
		return Fail("invalid_request", "JSON is not valid UTF-8")
	}
	if err := validateJSON(raw, target, true); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	d.UseNumber()
	if err := d.Decode(target); err != nil {
		return detail("invalid_request", "invalid closed JSON object: %s", err)
	}
	var trailing any
	if err := d.Decode(&trailing); err != io.EOF {
		return Fail("invalid_request", "JSON contains trailing data")
	}
	return nil
}
func bounded(value string, limit int) bool {
	return value != "" && len(value) <= limit && !control(value)
}
func validHash(value string) bool {
	if len(value) != 71 || value[:7] != "sha256:" {
		return false
	}
	for _, b := range []byte(value[7:]) {
		if !hex(b) {
			return false
		}
	}
	return true
}
func validEvidence(e RbacEvidence) bool {
	return bounded(e.Kind, 128) && bounded(e.Repository, 512) && bounded(e.Revision, 256) && bounded(e.Path, 1024) && validHash(e.SourceSHA256)
}
func validUpstream(s UpstreamSource) bool {
	return bounded(s.Kind, 128) && bounded(s.Repository, 512) && bounded(s.Revision, 256) && bounded(s.Path, 1024) && bounded(s.ReviewID, 256) && bounded(s.ReviewRevision, 256) && validHash(s.SourceSHA256) && validHash(s.CatalogSHA256) && validHash(s.ReviewSHA256) && validEvidence(s.RbacEvidence)
}
func containsRef(value any) bool {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			if key == "$ref" || key == "$dynamicRef" || key == "$recursiveRef" || containsRef(child) {
				return true
			}
		}
	case []any:
		for _, child := range v {
			if containsRef(child) {
				return true
			}
		}
	}
	return false
}
func validSchema(value any) bool {
	if _, ok := value.(map[string]any); !ok || containsRef(value) {
		return false
	}
	raw, err := encodeCanonical(value, false)
	return err == nil && len(raw) <= 64*1024
}
func closedObject(value any) bool {
	if !validSchema(value) {
		return false
	}
	object := value.(map[string]any)
	if object["type"] != "object" || object["additionalProperties"] != false {
		return false
	}
	properties, ok := object["properties"].(map[string]any)
	if !ok {
		return false
	}
	required, ok := object["required"].([]any)
	if !ok {
		return false
	}
	seen := map[string]bool{}
	for _, value := range required {
		name, ok := value.(string)
		if !ok || seen[name] {
			return false
		}
		if _, ok := properties[name]; !ok {
			return false
		}
		seen[name] = true
	}
	return true
}
func discoverable(purpose string) bool {
	return purpose == "request" || purpose == "metricsSingle" || purpose == "metricsBatch" || purpose == "logsQuery"
}
func expectedPath(route Route) string {
	if route.Purpose != "request" {
		return route.PathTemplate
	}
	if route.PathTemplate == "/subscriptions/{subscription}" {
		return "/"
	}
	const prefix = "/subscriptions/{subscription}"
	if len(route.PathTemplate) > len(prefix) && route.PathTemplate[:len(prefix)] == prefix {
		return route.PathTemplate[len(prefix):]
	}
	return ""
}
func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, value := range a {
		if value != b[i] {
			return false
		}
	}
	return true
}
func (schema ManifestSchema) Validate() error {
	for _, field := range []struct {
		value string
		limit int
	}{{schema.EntryID, 256}, {schema.ResourceType, 256}, {schema.Operation, 128}, {schema.DisplayName, 256}, {schema.Description, 2048}, {schema.CanonicalPathTemplate, 1024}, {schema.RequestPathTemplate, 1024}, {schema.RBACAction, 512}} {
		if !bounded(field.value, field.limit) {
			return Fail("invalid_request", "schema metadata is missing or unbounded")
		}
	}
	if schema.CLIEquivalent != nil && !bounded(*schema.CLIEquivalent, 512) || schema.DataPlaneGrant != nil && !bounded(*schema.DataPlaneGrant, 128) {
		return Fail("invalid_request", "optional schema metadata is invalid")
	}
	if len(schema.APIVersions) == 0 || len(schema.APIVersions) > 32 {
		return Fail("invalid_request", "invalid schema API versions")
	}
	for i, version := range schema.APIVersions {
		if !bounded(version, 64) || i > 0 && schema.APIVersions[i-1] >= version {
			return Fail("invalid_request", "schema API versions must be sorted and unique")
		}
	}
	if !closedObject(schema.ArgumentSchema) || schema.RequestBodySchema != nil && !closedObject(schema.RequestBodySchema) || schema.ResponseBodySchema != nil && !validSchema(schema.ResponseBodySchema) {
		return Fail("invalid_request", "schema must be a closed inline bounded object without references")
	}
	bodyRequired := schema.Purpose == "metricsBatch" || schema.Purpose == "logsQuery"
	if bodyRequired != (schema.RequestBodySchema != nil) {
		return Fail("invalid_request", "request body schema does not match execution surface")
	}
	if schema.Purpose == "logsQuery" {
		if schema.DataPlaneGrant == nil || *schema.DataPlaneGrant != "logs.query" {
			return Fail("invalid_request", "logs schema requires its grant")
		}
	} else if schema.DataPlaneGrant != nil {
		return Fail("invalid_request", "unexpected data plane grant")
	}
	object := schema.ArgumentSchema.(map[string]any)
	properties, _ := object["properties"].(map[string]any)
	cloud, _ := properties["cloud"].(map[string]any)
	values, _ := cloud["enum"].([]any)
	if len(values) != 1 || values[0] != string(schema.Cloud) {
		return Fail("invalid_request", "argument schema must constrain its exact cloud")
	}
	return nil
}
func (m RouteManifest) Validate(pinned bool) error {
	if m.FormatVersion != 1 || m.ManifestID != "v1-observability-1" || m.PolicyVersion != PolicyVersion {
		return Fail("invalid_request", "manifest identity is not reviewed")
	}
	if m.Source.Kind != "checked-in-reviewed-fixture" || m.Source.Revision != "reviewed-manifest-v2" || m.Source.Upstream != nil && !validUpstream(*m.Source.Upstream) {
		return Fail("invalid_request", "manifest provenance is not reviewed")
	}
	if len(m.Routes) == 0 || len(m.Routes) > 256 || len(m.Schemas) > 256 {
		return Fail("invalid_request", "manifest route or schema count is invalid")
	}
	if err := (Policy{Version: m.PolicyVersion, Hash: m.PolicyHash, Routes: m.Routes}).Validate(); err != nil {
		return err
	}
	seen := map[string]bool{}
	used := map[int]bool{}
	for _, schema := range m.Schemas {
		if err := schema.Validate(); err != nil {
			return err
		}
		if seen[schema.EntryID] {
			return Fail("invalid_request", "duplicate schema entry identifier")
		}
		seen[schema.EntryID] = true
		found := -1
		for i, route := range m.Routes {
			if discoverable(route.Purpose) && route.Cloud == schema.Cloud && route.Purpose == schema.Purpose && route.Method == schema.Method && route.PathTemplate == schema.CanonicalPathTemplate && sameStrings(route.APIVersions, schema.APIVersions) && route.RBACAction == schema.RBACAction && route.ArmTier == schema.ArmTier {
				found = i
				break
			}
		}
		if found < 0 || used[found] || expectedPath(m.Routes[found]) != schema.RequestPathTemplate {
			return Fail("invalid_request", "schema does not uniquely describe a representable reviewed route")
		}
		used[found] = true
	}
	for i, route := range m.Routes {
		if discoverable(route.Purpose) && !used[i] {
			return Fail("invalid_request", "reviewed route has no schema metadata")
		}
	}
	expected, err := ComputedPolicyHash(m)
	if err != nil {
		return err
	}
	if expected != m.PolicyHash || pinned && m.PolicyHash != PolicyHash {
		return Fail("invalid_request", "manifest policy hash does not match reviewed content")
	}
	return nil
}
func parseManifest(raw []byte, pinned bool) (RouteManifest, error) {
	var m RouteManifest
	if len(raw) > 512*1024 {
		return m, Fail("invalid_request", "route manifest is too large")
	}
	if err := DecodeClosed(raw, &m); err != nil {
		return m, err
	}
	return m, m.Validate(pinned)
}
func ParseManifest(raw []byte) (RouteManifest, error)              { return parseManifest(raw, true) }
func ParseManifestForGeneration(raw []byte) (RouteManifest, error) { return parseManifest(raw, false) }
func normalizedManifest(m RouteManifest) RouteManifest {
	m.Routes = append([]Route{}, m.Routes...)
	m.Schemas = append([]ManifestSchema{}, m.Schemas...)
	for i := range m.Routes {
		if m.Routes[i].AllowedQueryParameters == nil {
			m.Routes[i].AllowedQueryParameters = []string{}
		}
	}
	sortRoutes(m.Routes)
	sort.SliceStable(m.Schemas, func(i, j int) bool { return m.Schemas[i].EntryID < m.Schemas[j].EntryID })
	return m
}
func encodeCanonical(value any, pretty bool) ([]byte, error) {
	var buffer bytes.Buffer
	e := json.NewEncoder(&buffer)
	e.SetEscapeHTML(false)
	if pretty {
		e.SetIndent("", "  ")
	}
	if err := e.Encode(value); err != nil {
		return nil, err
	}
	raw := buffer.Bytes()
	if !pretty {
		raw = raw[:len(raw)-1]
	}
	return canonicalJSON(raw)
}
func CanonicalManifest(m RouteManifest) ([]byte, error) {
	return encodeCanonical(normalizedManifest(m), true)
}
func ComputedPolicyHash(m RouteManifest) (string, error) {
	m = normalizedManifest(m)
	m.PolicyHash = ""
	raw, err := encodeCanonical(m, false)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(raw)), nil
}
func LoadPolicy(raw []byte) (Policy, error) {
	m, err := ParseManifest(raw)
	if err != nil {
		return Policy{}, err
	}
	return Policy{Version: m.PolicyVersion, Hash: m.PolicyHash, Routes: m.Routes}, nil
}
func LoadReviewed() (Policy, SchemaIndex, error) {
	m, err := ParseManifest(reviewed.Manifest)
	if err != nil {
		return Policy{}, SchemaIndex{}, err
	}
	canonical, err := CanonicalManifest(m)
	if err != nil || !bytes.Equal(canonical, reviewed.Manifest) {
		return Policy{}, SchemaIndex{}, Fail("invalid_request", "checked-in manifest is not canonical")
	}
	policy := Policy{Version: m.PolicyVersion, Hash: m.PolicyHash, Routes: m.Routes}
	index, err := NewSchemaIndex(policy, m.Schemas)
	return policy, index, err
}
