package core

import (
	"regexp"
	"sort"
	"strings"
)

type SchemaAccess struct {
	Executable   bool    `json:"executable"`
	DenialReason *string `json:"denialReason"`
}
type SchemaSearchHit struct {
	EntryID                string       `json:"entryId"`
	ResourceType           string       `json:"resourceType"`
	Operation              string       `json:"operation"`
	ExecutionSurface       string       `json:"executionSurface"`
	DisplayName            string       `json:"displayName"`
	Description            string       `json:"description"`
	CLIEquivalent          *string      `json:"cliEquivalent"`
	Cloud                  Cloud        `json:"cloud"`
	Audience               string       `json:"audience"`
	Method                 string       `json:"method"`
	PathTemplate           string       `json:"pathTemplate"`
	CanonicalPathTemplate  string       `json:"canonicalPathTemplate"`
	APIVersions            []string     `json:"apiVersions"`
	RBACAction             string       `json:"rbacAction"`
	ArmTier                string       `json:"armTier"`
	DataPlaneGrant         *string      `json:"dataPlaneGrant"`
	DataPlane              *string      `json:"dataPlane"`
	DataScope              *string      `json:"dataScope"`
	AllowedQueryParameters []string     `json:"allowedQueryParameters"`
	Access                 SchemaAccess `json:"access"`
}
type SchemaSearchResult struct {
	PolicyVersion string            `json:"policyVersion"`
	Results       []SchemaSearchHit `json:"results"`
	Omitted       int               `json:"omitted"`
}
type SchemaDetails struct {
	SchemaSearchHit
	APIVersion         string `json:"apiVersion"`
	ArgumentSchema     any    `json:"argumentSchema"`
	RequestBodySchema  any    `json:"requestBodySchema"`
	ResponseBodySchema any    `json:"responseBodySchema"`
	SchemaAvailability string `json:"schemaAvailability"`
}
type schemaEntry struct {
	source ManifestSchema
	query  []string
}
type SchemaIndex struct {
	PolicyHash    string
	PolicyVersion string
	entries       []schemaEntry
}

func NewSchemaIndex(policy Policy, sources []ManifestSchema) (SchemaIndex, error) {
	index := SchemaIndex{PolicyHash: policy.Hash, PolicyVersion: policy.Version}
	if policy.Hash == "" {
		return index, Fail("schema_unavailable", "schema policy hash is required")
	}
	if err := policy.Validate(); err != nil {
		return index, err
	}
	seen := map[string]bool{}
	used := map[int]bool{}
	for _, source := range sources {
		if err := source.Validate(); err != nil {
			return index, err
		}
		if seen[source.EntryID] {
			return index, Fail("schema_unavailable", "duplicate schema entry")
		}
		seen[source.EntryID] = true
		matched := -1
		for i, route := range policy.Routes {
			if discoverable(route.Purpose) && route.Cloud == source.Cloud && route.Purpose == source.Purpose && route.Method == source.Method && route.PathTemplate == source.CanonicalPathTemplate && sameStrings(route.APIVersions, source.APIVersions) && route.RBACAction == source.RBACAction && route.ArmTier == source.ArmTier {
				matched = i
				break
			}
		}
		if matched < 0 || used[matched] || expectedPath(policy.Routes[matched]) != source.RequestPathTemplate {
			return index, Fail("schema_unavailable", "schema source does not match its reviewed route")
		}
		used[matched] = true
		index.entries = append(index.entries, schemaEntry{source, append([]string{}, policy.Routes[matched].AllowedQueryParameters...)})
	}
	for i, route := range policy.Routes {
		if discoverable(route.Purpose) && !used[i] {
			return index, Fail("schema_unavailable", "reviewed route has no schema metadata")
		}
	}
	sort.Slice(index.entries, func(i, j int) bool { return index.entries[i].source.EntryID < index.entries[j].source.EntryID })
	return index, nil
}
func (index SchemaIndex) ensurePolicy(options ContextOptions) error {
	if options.PolicyHash != index.PolicyHash || options.PolicyVersion != index.PolicyVersion {
		return Fail("schema_unavailable", "schema index does not match context policy identity")
	}
	return nil
}
func access(entry schemaEntry, options ContextOptions) SchemaAccess {
	deny := func(reason string) SchemaAccess { return SchemaAccess{false, &reason} }
	tier := map[string]int{"inspect": 0, "read": 1, "write": 2}
	if tier[options.ArmTier] < tier[entry.source.ArmTier] {
		return deny("arm_tier_required")
	}
	if entry.source.DataPlaneGrant != nil && !Contains(options.DataPlanes, *entry.source.DataPlaneGrant) {
		return deny("data_plane_grant_required")
	}
	if entry.source.Purpose == "logsQuery" && options.LogsScopes[entry.source.Cloud] != "allAccessible" {
		return deny("data_scope_required")
	}
	return SchemaAccess{Executable: true}
}
func surface(purpose string) string {
	switch purpose {
	case "request":
		return "azure_request"
	case "resourceGraph":
		return "azure_graph"
	case "logsQuery":
		return "azure_logs_query"
	case "metricsSingle":
		return "azure_metrics_single"
	case "metricsBatch":
		return "azure_metrics_batch"
	default:
		return "internal"
	}
}

func copySchema(value any) any {
	switch value := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(value))
		for name, child := range value {
			result[name] = copySchema(child)
		}
		return result
	case []any:
		result := make([]any, len(value))
		for i, child := range value {
			result[i] = copySchema(child)
		}
		return result
	default:
		return value
	}
}

func toolArgumentSchema(source ManifestSchema) any {
	schema := copySchema(source.ArgumentSchema).(map[string]any)
	properties := schema["properties"].(map[string]any)
	properties["contextId"] = map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{43}$"}
	schema["required"] = append([]any{"contextId"}, schema["required"].([]any)...)
	schema["title"] = surface(source.Purpose) + " arguments"
	if path, ok := properties["path"].(map[string]any); ok {
		if description, ok := path["description"].(string); ok {
			path["description"] = strings.ReplaceAll(description, "az.request", "azure_request")
		}
	}
	return schema
}
func pointer(value string) *string { return &value }
func hit(entry schemaEntry, options ContextOptions) SchemaSearchHit {
	source := entry.source
	var dataPlane, dataScope *string
	switch source.Purpose {
	case "metricsBatch":
		dataPlane = pointer("metrics")
		dataScope = pointer("boundSubscription")
	case "metricsSingle":
		dataScope = pointer("boundSubscription")
	case "logsQuery":
		dataPlane = pointer("logs.query")
		dataScope = pointer("allAccessible")
	}
	return SchemaSearchHit{source.EntryID, source.ResourceType, source.Operation, surface(source.Purpose), source.DisplayName, source.Description, source.CLIEquivalent, source.Cloud, source.Cloud.Audience(source.Purpose), source.Method, source.RequestPathTemplate, source.CanonicalPathTemplate, source.APIVersions, source.RBACAction, source.ArmTier, source.DataPlaneGrant, dataPlane, dataScope, entry.query, access(entry, options)}
}

var words = regexp.MustCompile(`[A-Za-z0-9]+`)

func queryTerms(query string) []string {
	seen := map[string]bool{}
	var terms []string
	for _, term := range words.FindAllString(lowerASCII(query), -1) {
		if !seen[term] {
			seen[term] = true
			terms = append(terms, term)
		}
	}
	sort.Strings(terms)
	return terms
}
func score(entry schemaEntry, terms []string) int {
	source := entry.source
	cli := ""
	if source.CLIEquivalent != nil {
		cli = *source.CLIEquivalent
	}
	fields := []struct {
		value  string
		weight int
	}{{source.ResourceType, 100}, {source.Operation, 90}, {surface(source.Purpose), 90}, {cli, 80}, {source.RequestPathTemplate, 60}, {source.DisplayName, 40}, {source.Description, 10}}
	result := 0
	for _, term := range terms {
		weight := 0
		for _, field := range fields {
			for _, word := range words.FindAllString(field.value, -1) {
				if EqualFoldASCII(word, term) {
					weight = max(weight, field.weight)
				}
			}
		}
		if weight == 0 {
			for _, field := range fields {
				if strings.Contains(lowerASCII(field.value), term) {
					weight = 1
					break
				}
			}
		}
		result += weight
	}
	return result
}
func (index SchemaIndex) Search(options ContextOptions, query string, cloud *Cloud, limit int) (SchemaSearchResult, error) {
	result := SchemaSearchResult{PolicyVersion: index.PolicyVersion, Results: []SchemaSearchHit{}}
	if err := index.ensurePolicy(options); err != nil {
		return result, err
	}
	if strings.TrimSpace(query) == "" || len(query) > 256 {
		return result, Fail("invalid_request", "schema search query is empty or too large")
	}
	if limit < 1 || limit > 50 {
		return result, Fail("invalid_request", "schema search limit is outside supported range")
	}
	if cloud != nil {
		if _, err := options.Binding(*cloud); err != nil {
			return result, Fail("schema_cloud_not_bound", "schema cloud is not bound by context")
		}
	}
	type scored struct {
		weight int
		entry  schemaEntry
	}
	var matches []scored
	terms := queryTerms(query)
	for _, entry := range index.entries {
		if _, err := options.Binding(entry.source.Cloud); err != nil || cloud != nil && *cloud != entry.source.Cloud {
			continue
		}
		if weight := score(entry, terms); weight > 0 {
			matches = append(matches, scored{weight, entry})
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].weight != matches[j].weight {
			return matches[i].weight > matches[j].weight
		}
		return matches[i].entry.source.EntryID < matches[j].entry.source.EntryID
	})
	result.Omitted = max(0, len(matches)-limit)
	for _, match := range matches[:min(len(matches), limit)] {
		result.Results = append(result.Results, hit(match.entry, options))
	}
	return result, nil
}
func (index SchemaIndex) Get(options ContextOptions, id, version string) (SchemaDetails, error) {
	if err := index.ensurePolicy(options); err != nil {
		return SchemaDetails{}, err
	}
	for _, entry := range index.entries {
		if entry.source.EntryID != id {
			continue
		}
		if _, err := options.Binding(entry.source.Cloud); err != nil {
			return SchemaDetails{}, Fail("schema_cloud_not_bound", "schema cloud is not bound by context")
		}
		if !Contains(entry.source.APIVersions, version) {
			return SchemaDetails{}, Fail("schema_version_not_found", "schema API version is not reviewed")
		}
		availability := "metadataOnly"
		if entry.source.ResponseBodySchema != nil {
			availability = "full"
		}
		return SchemaDetails{hit(entry, options), version, toolArgumentSchema(entry.source), copySchema(entry.source.RequestBodySchema), copySchema(entry.source.ResponseBodySchema), availability}, nil
	}
	return SchemaDetails{}, Fail("schema_not_found", "schema entry was not found")
}
