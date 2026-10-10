package core

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
)

type CatalogSource struct {
	Kind          string `json:"kind"`
	Repository    string `json:"repository"`
	Revision      string `json:"revision"`
	Path          string `json:"path"`
	SourceSHA256  string `json:"sourceSha256"`
	CatalogSHA256 string `json:"catalogSha256"`
}
type CatalogOperation struct {
	OperationID        string   `json:"operationId"`
	ProviderNamespace  string   `json:"providerNamespace"`
	ResourceType       string   `json:"resourceType"`
	Operation          string   `json:"operation"`
	Method             string   `json:"method"`
	PathTemplate       string   `json:"pathTemplate"`
	APIVersions        []string `json:"apiVersions"`
	RequestBodySchema  any      `json:"requestBodySchema"`
	ResponseBodySchema any      `json:"responseBodySchema"`
}
type Catalog struct {
	FormatVersion uint32             `json:"formatVersion"`
	Source        CatalogSource      `json:"source"`
	Operations    []CatalogOperation `json:"operations"`
}
type ReviewSource struct {
	Kind     string `json:"kind"`
	Revision string `json:"revision"`
}
type CatalogPin struct {
	Repository    string `json:"repository"`
	Revision      string `json:"revision"`
	Path          string `json:"path"`
	SourceSHA256  string `json:"sourceSha256"`
	CatalogSHA256 string `json:"catalogSha256"`
}
type ReviewOperation struct {
	OperationID            string   `json:"operationId"`
	EntryID                string   `json:"entryId"`
	DisplayName            string   `json:"displayName"`
	Description            string   `json:"description"`
	CLIEquivalent          *string  `json:"cliEquivalent"`
	Cloud                  Cloud    `json:"cloud"`
	ArmTier                string   `json:"armTier"`
	RBACAction             string   `json:"rbacAction"`
	AllowedQueryParameters []string `json:"allowedQueryParameters"`
}
type Review struct {
	FormatVersion uint32            `json:"formatVersion"`
	ReviewID      string            `json:"reviewId"`
	Source        ReviewSource      `json:"source"`
	Upstream      CatalogPin        `json:"upstream"`
	RbacEvidence  RbacEvidence      `json:"rbacEvidence"`
	ReviewSHA256  string            `json:"reviewSha256"`
	Operations    []ReviewOperation `json:"operations"`
}

func normalizedCatalog(c Catalog) Catalog {
	c.Operations = append([]CatalogOperation{}, c.Operations...)
	sort.SliceStable(c.Operations, func(i, j int) bool { return c.Operations[i].OperationID < c.Operations[j].OperationID })
	return c
}
func normalizedReview(r Review) Review {
	r.Operations = append([]ReviewOperation{}, r.Operations...)
	sort.SliceStable(r.Operations, func(i, j int) bool {
		a, b := r.Operations[i], r.Operations[j]
		if a.EntryID != b.EntryID {
			return a.EntryID < b.EntryID
		}
		if a.OperationID != b.OperationID {
			return a.OperationID < b.OperationID
		}
		return a.Cloud < b.Cloud
	})
	for i := range r.Operations {
		if r.Operations[i].AllowedQueryParameters == nil {
			r.Operations[i].AllowedQueryParameters = []string{}
		}
	}
	return r
}
func catalogHash(c Catalog) (string, error) {
	c = normalizedCatalog(c)
	c.Source.CatalogSHA256 = ""
	raw, err := encodeCanonical(c, false)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(raw)), nil
}
func reviewHash(r Review) (string, error) {
	r = normalizedReview(r)
	r.ReviewSHA256 = ""
	raw, err := encodeCanonical(r, false)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(raw)), nil
}
func CanonicalCatalog(c Catalog) ([]byte, error) { return encodeCanonical(normalizedCatalog(c), true) }
func CanonicalReview(r Review) ([]byte, error)   { return encodeCanonical(normalizedReview(r), true) }
func ParseCatalog(raw []byte) (Catalog, error) {
	var c Catalog
	if len(raw) > 256*1024 {
		return c, Fail("invalid_request", "upstream catalog is too large")
	}
	if err := DecodeClosed(raw, &c); err != nil {
		return c, err
	}
	return c, c.Validate()
}
func ParseReview(raw []byte) (Review, error) {
	var r Review
	if len(raw) > 256*1024 {
		return r, Fail("invalid_request", "review bundle is too large")
	}
	if err := DecodeClosed(raw, &r); err != nil {
		return r, err
	}
	for i := range r.Operations {
		if r.Operations[i].AllowedQueryParameters == nil {
			r.Operations[i].AllowedQueryParameters = []string{}
		}
	}
	return r, r.Validate()
}
func (c Catalog) Validate() error {
	s := c.Source
	if c.FormatVersion != 1 || !Contains([]string{"synthetic-upstream-contract", "azure-rest-openapi"}, s.Kind) || !bounded(s.Repository, 512) || !bounded(s.Revision, 256) || !bounded(s.Path, 1024) || !validHash(s.SourceSHA256) || !validHash(s.CatalogSHA256) {
		return Fail("invalid_request", "upstream catalog format or source is not pinned")
	}
	if len(c.Operations) == 0 || len(c.Operations) > 256 {
		return Fail("invalid_request", "invalid upstream operation count")
	}
	seen := map[string]bool{}
	for _, operation := range c.Operations {
		if !bounded(operation.OperationID, 256) || !bounded(operation.ProviderNamespace, 256) || !bounded(operation.ResourceType, 256) || !bounded(operation.Operation, 128) || !bounded(operation.PathTemplate, 1024) || seen[operation.OperationID] {
			return Fail("invalid_request", "invalid or duplicate upstream operation")
		}
		seen[operation.OperationID] = true
		if operation.RequestBodySchema != nil && !validSchema(operation.RequestBodySchema) || operation.ResponseBodySchema != nil && !validSchema(operation.ResponseBodySchema) {
			return Fail("invalid_request", "upstream schema is unbounded or references unpinned data")
		}
		route := Route{Commercial, "request", operation.Method, operation.PathTemplate, operation.APIVersions, "import/read", "inspect", []string{}}
		if err := route.Validate(); err != nil {
			return err
		}
	}
	expected, err := catalogHash(c)
	if err != nil {
		return err
	}
	if expected != s.CatalogSHA256 {
		return Fail("invalid_request", "catalog content hash mismatch")
	}
	return nil
}
func (r Review) Validate() error {
	if r.FormatVersion != 1 || !bounded(r.ReviewID, 256) || r.Source.Kind != "manual-route-review" || !bounded(r.Source.Revision, 256) || !bounded(r.Upstream.Repository, 512) || !bounded(r.Upstream.Revision, 256) || !bounded(r.Upstream.Path, 1024) || !validHash(r.Upstream.SourceSHA256) || !validHash(r.Upstream.CatalogSHA256) || !validEvidence(r.RbacEvidence) {
		return Fail("invalid_request", "review format, upstream source, or RBAC evidence is not pinned")
	}
	if len(r.Operations) > 256 {
		return Fail("invalid_request", "too many reviewed operations")
	}
	seenID := map[string]bool{}
	seenOperation := map[string]bool{}
	for _, operation := range r.Operations {
		if !bounded(operation.OperationID, 256) || !bounded(operation.EntryID, 256) || !bounded(operation.DisplayName, 256) || !bounded(operation.Description, 2048) || !bounded(operation.RBACAction, 512) || operation.CLIEquivalent != nil && !bounded(*operation.CLIEquivalent, 512) || len(operation.AllowedQueryParameters) > 64 {
			return Fail("invalid_request", "reviewed operation metadata is not bounded")
		}
		if _, err := ParseCloud(string(operation.Cloud)); err != nil {
			return err
		}
		if !Contains([]string{"inspect", "read", "write"}, operation.ArmTier) {
			return Fail("invalid_request", "invalid reviewed ARM tier")
		}
		for i, name := range operation.AllowedQueryParameters {
			if !bounded(name, 128) || i > 0 && operation.AllowedQueryParameters[i-1] >= name {
				return Fail("invalid_request", "review query parameters must be sorted and unique")
			}
		}
		key := operation.OperationID + "|" + string(operation.Cloud)
		if seenOperation[key] || seenID[operation.EntryID] {
			return Fail("invalid_request", "duplicate reviewed operation or schema identifier")
		}
		seenOperation[key], seenID[operation.EntryID] = true, true
	}
	expected, err := reviewHash(r)
	if err != nil {
		return err
	}
	if expected != r.ReviewSHA256 {
		return Fail("invalid_request", "review content hash mismatch")
	}
	return nil
}
func requestArgumentSchema(cloud Cloud, path string, versions []string, canonical string) map[string]any {
	version := map[string]any{}
	if len(versions) == 1 {
		version["const"] = versions[0]
	} else {
		values := make([]any, len(versions))
		for i, value := range versions {
			values[i] = value
		}
		version["enum"] = values
	}
	return map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "additionalProperties": false, "properties": map[string]any{
		"cloud": map[string]any{"enum": []any{string(cloud)}}, "method": map[string]any{"const": "GET"},
		"path":         map[string]any{"description": fmt.Sprintf("Relative az.request path matching %s; the host prepends the selected subscription for %s.", path, canonical), "maxLength": 16384, "minLength": 1, "type": "string"},
		"subscription": map[string]any{"pattern": "^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$", "type": "string"}, "apiVersion": version,
	}, "required": []any{"cloud", "method", "path", "apiVersion"}, "title": "az.request arguments for " + canonical, "type": "object"}
}
func GenerateManifest(seed RouteManifest, catalog Catalog, review Review) (RouteManifest, error) {
	if err := seed.Validate(false); err != nil {
		return RouteManifest{}, err
	}
	if err := catalog.Validate(); err != nil {
		return RouteManifest{}, err
	}
	if err := review.Validate(); err != nil {
		return RouteManifest{}, err
	}
	source := catalog.Source
	pin := review.Upstream
	if source.Repository != pin.Repository || source.Revision != pin.Revision || source.Path != pin.Path || source.SourceSHA256 != pin.SourceSHA256 || source.CatalogSHA256 != pin.CatalogSHA256 {
		return RouteManifest{}, Fail("invalid_request", "review does not pin this exact upstream catalog")
	}
	result := normalizedManifest(seed)
	byID := map[string]CatalogOperation{}
	for _, operation := range catalog.Operations {
		byID[operation.OperationID] = operation
	}
	seenSchema := map[string]bool{}
	for _, schema := range seed.Schemas {
		seenSchema[schema.EntryID] = true
	}
	for _, selected := range review.Operations {
		operation, ok := byID[selected.OperationID]
		if !ok {
			return RouteManifest{}, Fail("invalid_request", "review selected an unknown operation")
		}
		if operation.Method != "GET" || operation.RequestBodySchema != nil || selected.ArmTier != "inspect" {
			return RouteManifest{}, Fail("invalid_request", "only bodyless inspect GET operations can be imported")
		}
		const prefix = "/subscriptions/{subscription}"
		path, ok := strings.CutPrefix(operation.PathTemplate, prefix)
		if !ok || path == "" || !strings.HasPrefix(path, "/") {
			return RouteManifest{}, Fail("invalid_request", "upstream path is not representable by az.request")
		}
		route := Route{selected.Cloud, "request", "GET", operation.PathTemplate, operation.APIVersions, selected.RBACAction, "inspect", selected.AllowedQueryParameters}
		if err := route.Validate(); err != nil {
			return RouteManifest{}, err
		}
		for _, known := range result.Routes {
			if selectorsOverlap(known, route) {
				return RouteManifest{}, Fail("invalid_request", "upstream route collides with reviewed policy")
			}
		}
		if seenSchema[selected.EntryID] {
			return RouteManifest{}, Fail("invalid_request", "upstream schema identifier collides with reviewed policy")
		}
		seenSchema[selected.EntryID] = true
		result.Routes = append(result.Routes, route)
		result.Schemas = append(result.Schemas, ManifestSchema{EntryID: selected.EntryID, ResourceType: operation.ResourceType, Operation: operation.Operation, Purpose: "request", DisplayName: selected.DisplayName, Description: selected.Description, CLIEquivalent: selected.CLIEquivalent, Cloud: selected.Cloud, Method: "GET", CanonicalPathTemplate: operation.PathTemplate, RequestPathTemplate: path, APIVersions: operation.APIVersions, RBACAction: selected.RBACAction, ArmTier: "inspect", ArgumentSchema: requestArgumentSchema(selected.Cloud, path, operation.APIVersions, operation.PathTemplate)})
	}
	result.Source.Upstream = &UpstreamSource{source.Kind, source.Repository, source.Revision, source.Path, source.SourceSHA256, source.CatalogSHA256, review.ReviewID, review.Source.Revision, review.ReviewSHA256, review.RbacEvidence}
	result.Source.Revision = "reviewed-manifest-v2"
	hash, err := ComputedPolicyHash(result)
	if err != nil {
		return RouteManifest{}, err
	}
	result.PolicyHash = hash
	return result, result.Validate(false)
}
