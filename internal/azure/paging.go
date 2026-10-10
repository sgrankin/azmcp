package azure

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"time"

	"azmcp/internal/core"
)

type PagingLimits struct {
	MaxPages, MaxItems, MaxBytes int
	MaxElapsed                   time.Duration
}

func DefaultPagingLimits() PagingLimits {
	return PagingLimits{32, 50000, 16 * 1024 * 1024, 60 * time.Second}
}
func (l PagingLimits) validate() error {
	if l.MaxPages < 1 || l.MaxPages > 256 || l.MaxItems < 1 || l.MaxItems > 1000000 || l.MaxBytes < 1 || l.MaxBytes > 64*1024*1024 || l.MaxElapsed <= 0 || l.MaxElapsed > 5*time.Minute {
		return pagingError("invalid_limits")
	}
	return nil
}

type PagingError struct {
	Code       string
	RetryCount int
	Cause      error
}

func (e *PagingError) Error() string       { return "Azure paging failed: " + e.Code }
func (e *PagingError) Unwrap() error       { return e.Cause }
func pagingError(code string) *PagingError { return &PagingError{Code: code} }

type PagedPage struct {
	Status                     int     `json:"status"`
	ResponseBodyBytes          int     `json:"responseBodyBytes"`
	ItemCount                  int     `json:"itemCount"`
	DurationMS                 uint64  `json:"durationMs"`
	RetryCount                 int     `json:"retryCount"`
	RemainingSubscriptionReads *uint64 `json:"remainingSubscriptionReads,omitempty"`
}
type PagedResponse struct {
	Items             []json.RawMessage `json:"items"`
	Pages             []PagedPage       `json:"pages"`
	ResponseBodyBytes int               `json:"responseBodyBytes"`
}

func (c *Client) ExecutePaged(ctx context.Context, request Request, limits PagingLimits) (PagedResponse, error) {
	var result PagedResponse
	if err := limits.validate(); err != nil {
		return result, err
	}
	if request.Method != "GET" || len(request.Headers) != 0 || len(request.Body) != 0 {
		return result, pagingError("unsafe_operation")
	}
	target, err := core.ParseTarget(request.Target.String())
	if err != nil {
		return result, &PagingError{Code: "http", Cause: httpError("invalid_target")}
	}
	request.Target = target
	initial, err := c.Policy.Classify(request.Binding.Cloud, request.Purpose, request.Method, request.Target, request.APIVersion)
	if err != nil {
		return result, &PagingError{Code: "http", Cause: httpError("policy_denied")}
	}
	if initial.ArmTier == "write" {
		return result, pagingError("unsafe_operation")
	}
	origin, err := c.origin(request)
	if err != nil {
		return result, &PagingError{Code: "http", Cause: err}
	}
	ctx, cancel := context.WithTimeout(ctx, limits.MaxElapsed)
	defer cancel()
	seen := map[string]bool{canonicalRequestKey(origin, request.Target, request.APIVersion): true}
	result.Items = []json.RawMessage{}
	result.Pages = []PagedPage{}
	for {
		if ctx.Err() != nil {
			return PagedResponse{}, pagingError("elapsed_limit_exceeded")
		}
		remaining := limits.MaxBytes - result.ResponseBodyBytes
		if remaining <= 0 {
			return PagedResponse{}, pagingError("byte_limit_exceeded")
		}
		started := time.Now()
		bodyLimit := min(remaining, c.limits.ResponseBytes)
		response, err := c.execute(ctx, request, bodyLimit)
		if err != nil {
			if ctx.Err() != nil {
				return PagedResponse{}, pagingError("elapsed_limit_exceeded")
			}
			var failure *HTTPError
			if errors.As(err, &failure) && failure.Code == "response_body_too_large" && bodyLimit == remaining {
				return PagedResponse{}, pagingError("byte_limit_exceeded")
			}
			retries := 0
			if failure != nil {
				retries = failure.RetryCount
			}
			return PagedResponse{}, &PagingError{Code: "http", RetryCount: retries, Cause: err}
		}
		if response.Status < 200 || response.Status >= 300 {
			return PagedResponse{}, &PagingError{Code: "upstream_status", RetryCount: response.RetryCount}
		}
		result.ResponseBodyBytes += len(response.Body)
		if result.ResponseBodyBytes > limits.MaxBytes {
			return PagedResponse{}, pagingError("byte_limit_exceeded")
		}
		var page map[string]json.RawMessage
		if json.Unmarshal(response.Body, &page) != nil || page == nil {
			return PagedResponse{}, pagingError("invalid_response")
		}
		var items []json.RawMessage
		if page["value"] == nil || string(page["value"]) == "null" || json.Unmarshal(page["value"], &items) != nil {
			return PagedResponse{}, pagingError("invalid_response")
		}
		if len(result.Items)+len(items) > limits.MaxItems {
			return PagedResponse{}, pagingError("item_limit_exceeded")
		}
		result.Items = append(result.Items, items...)
		metadata := PagedPage{Status: response.Status, ResponseBodyBytes: len(response.Body), ItemCount: len(items), DurationMS: uint64(time.Since(started).Milliseconds()), RetryCount: response.RetryCount}
		if reads, err := strconv.ParseUint(response.Headers["x-ms-ratelimit-remaining-subscription-reads"], 10, 64); err == nil {
			metadata.RemainingSubscriptionReads = &reads
		}
		result.Pages = append(result.Pages, metadata)
		if ctx.Err() != nil {
			return PagedResponse{}, pagingError("elapsed_limit_exceeded")
		}
		rawNext, hasNext := page["nextLink"]
		if !hasNext || string(rawNext) == "null" {
			return result, nil
		}
		var next string
		if json.Unmarshal(rawNext, &next) != nil || next == "" {
			return PagedResponse{}, pagingError("invalid_response")
		}
		if len(result.Pages) >= limits.MaxPages {
			return PagedResponse{}, pagingError("page_limit_exceeded")
		}
		if len(next) > 16*1024 || !cleanValue(next) {
			return PagedResponse{}, pagingError("invalid_continuation")
		}
		u, err := url.Parse(next)
		if err != nil || !u.IsAbs() {
			return PagedResponse{}, pagingError("invalid_continuation")
		}
		if !sameOrigin(origin, u) || u.User != nil || u.Fragment != "" {
			return PagedResponse{}, pagingError("continuation_origin_mismatch")
		}
		values, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			return PagedResponse{}, pagingError("invalid_continuation")
		}
		var apiVersions []string
		for name, value := range values {
			if core.EqualFoldASCII(name, "api-version") {
				apiVersions = append(apiVersions, value...)
				delete(values, name)
			}
		}
		if len(apiVersions) != 1 {
			return PagedResponse{}, pagingError("invalid_continuation")
		}
		if apiVersions[0] != request.APIVersion {
			return PagedResponse{}, pagingError("continuation_version_mismatch")
		}
		targetText := u.EscapedPath()
		if encoded := values.Encode(); encoded != "" {
			targetText += "?" + encoded
		}
		target, err := core.ParseTarget(targetText)
		if err != nil {
			return PagedResponse{}, pagingError("invalid_continuation")
		}
		route, err := c.Policy.Classify(request.Binding.Cloud, request.Purpose, request.Method, target, request.APIVersion)
		if err != nil || !reflect.DeepEqual(route, initial) {
			return PagedResponse{}, pagingError("continuation_route_mismatch")
		}
		key := canonicalRequestKey(origin, target, request.APIVersion)
		if seen[key] {
			return PagedResponse{}, pagingError("continuation_cycle")
		}
		seen[key] = true
		request.Target = target
	}
}
func canonicalRequestKey(origin *url.URL, target core.RequestTarget, version string) string {
	target.Query = append([]core.QueryPair{}, target.Query...)
	sort.Slice(target.Query, func(i, j int) bool {
		if target.Query[i].Name == target.Query[j].Name {
			return target.Query[i].Value < target.Query[j].Value
		}
		return target.Query[i].Name < target.Query[j].Name
	})
	u, err := requestURL(origin, target, version, false)
	if err != nil {
		panic("validated canonical paging target cannot produce an invalid URL")
	}
	return u.String()
}
