package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"azmcp/internal/core"
)

type HostError struct {
	Code             string `json:"code"`
	Message          string `json:"message"`
	Retryable        bool   `json:"retryable"`
	IdentityMismatch bool   `json:"-"`
}

func (e *HostError) Error() string { return e.Code + ": " + e.Message }
func hostError(code, message string, retryable bool) *HostError {
	return &HostError{Code: code, Message: message, Retryable: retryable}
}
func invalidHost() *HostError { return hostError("invalid_request", "invalid host request", false) }

type CallRecord struct {
	CorrelationID              string     `json:"correlationId"`
	Operation                  string     `json:"operation"`
	Cloud                      core.Cloud `json:"cloud"`
	Subscription               *string    `json:"subscription"`
	SubscriptionSource         *string    `json:"subscriptionSource"`
	Tenant                     *string    `json:"tenant"`
	Identity                   string     `json:"identity"`
	ArmTier                    string     `json:"armTier"`
	Method                     string     `json:"method"`
	PathTemplate               string     `json:"pathTemplate"`
	APIVersion                 string     `json:"apiVersion"`
	APIVersionSource           string     `json:"apiVersionSource"`
	PolicyHash                 string     `json:"policyHash"`
	PolicyVersion              string     `json:"policyVersion"`
	RBACAction                 *string    `json:"rbacAction"`
	Decision                   string     `json:"decision"`
	Reason                     *string    `json:"reason"`
	Status                     *int       `json:"status"`
	DurationMS                 uint64     `json:"durationMs"`
	RetryCount                 int        `json:"retryCount"`
	RemainingSubscriptionReads *uint64    `json:"remainingSubscriptionReads"`
	GraphScope                 *string    `json:"graphScope"`
	DataPlane                  *string    `json:"dataPlane"`
	DataScope                  *string    `json:"dataScope"`
}
type CallRecords struct {
	Calls        []CallRecord `json:"calls"`
	CallsOmitted int          `json:"callsOmitted"`
}
type HostConfig struct {
	Context       core.ContextOptions
	Client        *Client
	IdentityPin   *IdentityPin
	CorrelationID string
	Audit         func(CallRecord) error
	PrepareAudit  func() error
}
type Host struct {
	config            HostConfig
	mu                sync.Mutex
	records           []CallRecord
	omitted           int
	lastError         *HostError
	principalMismatch bool
}

func NewHost(config HostConfig) (*Host, error) {
	if config.Client == nil {
		return nil, hostError("client_unavailable", "HTTP client unavailable", true)
	}
	if err := config.Context.Validate(); err != nil {
		return nil, err
	}
	if config.IdentityPin == nil {
		config.IdentityPin = NewIdentityPin()
	}
	if config.CorrelationID == "" || len(config.CorrelationID) > 128 || strings.IndexFunc(config.CorrelationID, unicode.IsControl) != -1 {
		return nil, invalidHost()
	}
	// Each run captures the immutable option snapshot, including its maps.
	raw, err := json.Marshal(config.Context)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(raw, &config.Context); err != nil {
		return nil, err
	}
	return &Host{config: config, records: []CallRecord{}}, nil
}
func (h *Host) Records() CallRecords {
	h.mu.Lock()
	defer h.mu.Unlock()
	return CallRecords{append([]CallRecord{}, h.records...), h.omitted}
}
func (h *Host) LastError() *HostError {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.lastError == nil {
		return nil
	}
	value := *h.lastError
	return &value
}
func (h *Host) PrincipalMismatch() bool { h.mu.Lock(); defer h.mu.Unlock(); return h.principalMismatch }
func (h *Host) Call(ctx context.Context, method string, args json.RawMessage) (json.RawMessage, error) {
	value, err := h.call(ctx, method, args)
	if err != nil {
		var failure *HostError
		if !errors.As(err, &failure) {
			failure = hostError("upstream_error", "upstream request failed", true)
		}
		h.mu.Lock()
		h.lastError = failure
		h.principalMismatch = h.principalMismatch || failure.IdentityMismatch
		h.mu.Unlock()
		return nil, failure
	}
	return value, nil
}
func (h *Host) record(method string, cloud core.Cloud) CallRecord {
	return CallRecord{CorrelationID: h.config.CorrelationID, Operation: method, Cloud: cloud, Identity: "user", ArmTier: "inspect", PathTemplate: "<unmatched>", APIVersionSource: "callerReviewed", PolicyHash: h.config.Context.PolicyHash, PolicyVersion: h.config.Context.PolicyVersion, Decision: "denied"}
}
func (h *Host) audited(ctx context.Context, record CallRecord, execute func(*CallRecord) (json.RawMessage, error)) (json.RawMessage, error) {
	started := time.Now()
	var result json.RawMessage
	var err error
	if h.config.PrepareAudit != nil && h.config.PrepareAudit() != nil {
		err = hostError("audit_unavailable", "durable request audit log is unavailable", true)
	} else {
		result, err = execute(&record)
	}
	if err != nil && record.Reason == nil {
		var failure *HostError
		if errors.As(err, &failure) {
			record.Reason = ptr(failure.Code)
		} else {
			record.Reason = ptr("upstream_error")
		}
	}
	record.DurationMS = uint64(time.Since(started).Milliseconds())
	if h.config.Audit != nil && h.config.Audit(record) != nil {
		err = hostError("audit_unavailable", "durable request audit log is unavailable", true)
	}
	h.mu.Lock()
	if len(h.records) < 128 {
		h.records = append(h.records, record)
	} else {
		h.omitted++
	}
	h.mu.Unlock()
	return result, err
}
func ptr[T any](value T) *T { return &value }
func closedDecode(raw json.RawMessage, target any, required ...string) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return invalidHost()
	}
	for _, name := range required {
		value, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return invalidHost()
		}
	}
	if err := core.DecodeClosed(raw, target); err != nil {
		return invalidHost()
	}
	return nil
}

type RequestArgs struct {
	Cloud        *core.Cloud       `json:"cloud"`
	Subscription *string           `json:"subscription"`
	Method       string            `json:"method"`
	Path         string            `json:"path"`
	APIVersion   string            `json:"apiVersion"`
	Headers      map[string]string `json:"headers"`
	Body         json.RawMessage   `json:"body"`
}
type GraphArgs struct {
	Cloud         *core.Cloud     `json:"cloud"`
	Query         string          `json:"query"`
	Subscriptions *[]string       `json:"subscriptions"`
	Scope         json.RawMessage `json:"scope"`
}
type MetricsArgs struct {
	Cloud               *core.Cloud `json:"cloud"`
	ResourceID          string      `json:"resourceId"`
	MetricNames         []string    `json:"metricNames"`
	Timespan            *string     `json:"timespan"`
	Interval            *string     `json:"interval"`
	Aggregation         *string     `json:"aggregation"`
	Top                 *uint32     `json:"top"`
	OrderBy             *string     `json:"orderBy"`
	Filter              *string     `json:"filter"`
	ResultType          *string     `json:"resultType"`
	MetricNamespace     *string     `json:"metricNamespace"`
	AutoAdjustTimegrain *bool       `json:"autoAdjustTimegrain"`
	ValidateDimensions  *bool       `json:"validateDimensions"`
	RollupBy            *string     `json:"rollupBy"`
}
type BatchArgs struct {
	Cloud           *core.Cloud `json:"cloud"`
	Region          string      `json:"region"`
	ResourceIDs     []string    `json:"resourceIds"`
	MetricNamespace string      `json:"metricNamespace"`
	MetricNames     []string    `json:"metricNames"`
	StartTime       *string     `json:"startTime"`
	EndTime         *string     `json:"endTime"`
	Interval        *string     `json:"interval"`
	Aggregation     *string     `json:"aggregation"`
	Top             *uint32     `json:"top"`
	OrderBy         *string     `json:"orderBy"`
	Filter          *string     `json:"filter"`
	RollupBy        *string     `json:"rollupBy"`
}
type LogsArgs struct {
	Cloud        *core.Cloud `json:"cloud"`
	Subscription *string     `json:"subscription"`
	WorkspaceID  string      `json:"workspaceId"`
	Query        string      `json:"query"`
	Timespan     string      `json:"timespan"`
}

func cloudRequired(cloud *core.Cloud) (core.Cloud, error) {
	if cloud == nil {
		return "", hostError("cloud_required", "cloud is required", false)
	}
	return *cloud, nil
}
func (h *Host) call(ctx context.Context, method string, raw json.RawMessage) (json.RawMessage, error) {
	switch method {
	case "az.request":
		var args RequestArgs
		if err := closedDecode(raw, &args, "method", "path", "apiVersion"); err != nil {
			return nil, err
		}
		cloud, err := cloudRequired(args.Cloud)
		if err != nil {
			return nil, err
		}
		record := h.record(method, cloud)
		record.Method = args.Method
		record.APIVersion = args.APIVersion
		return h.audited(ctx, record, func(record *CallRecord) (json.RawMessage, error) {
			if len(args.Headers) != 0 || len(args.Body) != 0 && string(args.Body) != "null" {
				return nil, invalidHost()
			}
			switch args.Method {
			case "GET", "POST", "PUT", "PATCH", "DELETE":
			default:
				return nil, invalidHost()
			}
			binding, err := h.resolve(cloud, args.Subscription, record)
			if err != nil {
				return nil, err
			}
			relative, err := core.ParseTarget(args.Path)
			if err != nil {
				return nil, invalidHost()
			}
			if len(relative.Segments) > 0 && core.EqualFoldASCII(relative.Segments[0], "subscriptions") {
				return nil, invalidHost()
			}
			targetText := "/subscriptions/" + binding.Subscription + relative.String()
			if relative.Path == "/" {
				targetText = "/subscriptions/" + binding.Subscription + strings.TrimPrefix(relative.String(), "/")
			}
			target, err := core.ParseTarget(targetText)
			if err != nil {
				return nil, invalidHost()
			}
			return h.execute(ctx, Request{Binding: binding, Purpose: "request", Method: args.Method, Target: target, APIVersion: args.APIVersion, Pin: h.config.IdentityPin}, record, false)
		})
	case "az.graph":
		var args GraphArgs
		if err := closedDecode(raw, &args, "query"); err != nil {
			return nil, err
		}
		cloud, err := cloudRequired(args.Cloud)
		if err != nil {
			return nil, err
		}
		record := h.record(method, cloud)
		record.Method = "POST"
		record.APIVersion = core.GraphAPIVersion
		record.APIVersionSource = "reviewedRoute"
		return h.audited(ctx, record, func(record *CallRecord) (json.RawMessage, error) {
			if strings.TrimSpace(args.Query) == "" || len(args.Query) > 256*1024 {
				return nil, invalidHost()
			}
			binding, err := h.resolve(cloud, nil, record)
			if err != nil {
				return nil, err
			}
			body := map[string]any{"query": args.Query}
			scope := h.config.Context.GraphScopes[cloud]
			hasScope := len(args.Scope) > 0 && string(args.Scope) != "null"
			if hasScope && args.Subscriptions != nil {
				return nil, invalidHost()
			}
			if hasScope {
				var selected string
				if json.Unmarshal(args.Scope, &selected) != nil {
					var object struct {
						Scope string `json:"scope"`
					}
					if closedDecode(args.Scope, &object, "scope") != nil {
						return nil, invalidHost()
					}
					selected = object.Scope
				}
				if selected != "allAccessible" {
					return nil, invalidHost()
				}
				if !scope.AllAccessible {
					return nil, hostError("capability_denied", "Resource Graph scope is not authorized by this context", false)
				}
				record.GraphScope = ptr("allAccessible")
			} else if args.Subscriptions != nil {
				subscriptions, err := subscriptionList(*args.Subscriptions)
				if err != nil || len(subscriptions) == 0 {
					return nil, invalidHost()
				}
				if !scope.AllAccessible {
					for _, subscription := range subscriptions {
						if !containsFold(scope.Subscriptions, subscription) {
							return nil, hostError("capability_denied", "Resource Graph scope is not authorized by this context", false)
						}
					}
				}
				body["subscriptions"] = subscriptions
				record.GraphScope = ptr("subscriptions")
			} else if scope.AllAccessible {
				record.GraphScope = ptr("allAccessible")
			} else {
				body["subscriptions"] = scope.Subscriptions
				record.GraphScope = ptr("subscriptions")
			}
			target, _ := core.ParseTarget("/providers/Microsoft.ResourceGraph/resources")
			encoded, _ := json.Marshal(body)
			return h.execute(ctx, Request{Binding: binding, Purpose: "resourceGraph", Method: "POST", Target: target, APIVersion: core.GraphAPIVersion, Body: encoded, Headers: map[string]string{"Content-Type": "application/json"}, Pin: h.config.IdentityPin}, record, false)
		})
	case "az.metrics.single":
		var args MetricsArgs
		if err := closedDecode(raw, &args, "resourceId", "metricNames"); err != nil {
			return nil, err
		}
		cloud, err := cloudRequired(args.Cloud)
		if err != nil {
			return nil, err
		}
		record := h.record(method, cloud)
		record.Method = "GET"
		record.APIVersion = core.MetricsAPIVersion
		record.APIVersionSource = "reviewedRoute"
		return h.audited(ctx, record, func(record *CallRecord) (json.RawMessage, error) {
			resource, err := metricResource(args.ResourceID)
			if err != nil {
				return nil, err
			}
			binding, err := h.resolve(cloud, &resource.subscription, record)
			if err != nil {
				return nil, err
			}
			query, err := singleQuery(args)
			if err != nil {
				return nil, err
			}
			target, err := core.ParseTarget(resource.path + "/providers/Microsoft.Insights/metrics?" + query)
			if err != nil {
				return nil, invalidHost()
			}
			return h.execute(ctx, Request{Binding: binding, Purpose: "metricsSingle", Method: "GET", Target: target, APIVersion: core.MetricsAPIVersion, Pin: h.config.IdentityPin}, record, false)
		})
	case "az.metrics.batch":
		var args BatchArgs
		if err := closedDecode(raw, &args, "region", "resourceIds", "metricNamespace", "metricNames"); err != nil {
			return nil, err
		}
		cloud, err := cloudRequired(args.Cloud)
		if err != nil {
			return nil, err
		}
		record := h.record(method, cloud)
		record.Method = "POST"
		record.APIVersion = core.MetricsAPIVersion
		record.APIVersionSource = "reviewedRoute"
		return h.audited(ctx, record, func(record *CallRecord) (json.RawMessage, error) {
			if len(args.ResourceIDs) == 0 || len(args.ResourceIDs) > 50 {
				return nil, invalidHost()
			}
			var resources []metricResourceValue
			paths := []string{}
			for _, id := range args.ResourceIDs {
				resource, err := metricResource(id)
				if err != nil {
					return nil, err
				}
				for _, known := range resources {
					if core.EqualFoldASCII(known.path, resource.path) || known.subscription != resource.subscription || !core.EqualFoldASCII(known.resourceType, resource.resourceType) {
						return nil, invalidHost()
					}
				}
				resources = append(resources, resource)
				paths = append(paths, resource.path)
			}
			binding, err := h.resolve(cloud, &resources[0].subscription, record)
			if err != nil {
				return nil, err
			}
			query, err := batchQuery(args)
			if err != nil {
				return nil, err
			}
			if _, err := normalizeRegion(args.Region); err != nil {
				return nil, invalidHost()
			}
			target, err := core.ParseTarget("/subscriptions/" + binding.Subscription + "/metrics:getBatch?" + query)
			if err != nil {
				return nil, invalidHost()
			}
			body, _ := json.Marshal(map[string]any{"resourceids": paths})
			return h.execute(ctx, Request{Binding: binding, Purpose: "metricsBatch", Method: "POST", Target: target, APIVersion: core.MetricsAPIVersion, Region: args.Region, Body: body, Headers: map[string]string{"Content-Type": "application/json"}, Pin: h.config.IdentityPin}, record, false)
		})
	case "az.logs.query":
		var args LogsArgs
		if err := closedDecode(raw, &args, "workspaceId", "query", "timespan"); err != nil {
			return nil, err
		}
		cloud, err := cloudRequired(args.Cloud)
		if err != nil {
			return nil, err
		}
		record := h.record(method, cloud)
		record.Method = "POST"
		record.APIVersion = core.LogsAPIVersion
		record.APIVersionSource = "reviewedRoute"
		record.DataPlane = ptr("logs.query")
		record.DataScope = ptr("allAccessible")
		return h.audited(ctx, record, func(record *CallRecord) (json.RawMessage, error) {
			if strings.TrimSpace(args.Query) == "" || len(args.Query) > 256*1024 || !validTimespan(args.Timespan) {
				return nil, invalidHost()
			}
			binding, err := h.resolve(cloud, args.Subscription, record)
			if err != nil {
				return nil, err
			}
			if !core.Contains(h.config.Context.DataPlanes, "logs.query") || h.config.Context.LogsScopes[cloud] != "allAccessible" {
				return nil, hostError("capability_denied", "Logs Query is not authorized by this context", false)
			}
			workspace, err := core.NormalizeID(args.WorkspaceID)
			if err != nil {
				return nil, invalidHost()
			}
			target, _ := core.ParseTarget("/v1/workspaces/" + workspace + "/query")
			body, _ := json.Marshal(map[string]any{"query": args.Query, "timespan": args.Timespan})
			return h.execute(ctx, Request{Binding: binding, Purpose: "logsQuery", Method: "POST", Target: target, APIVersion: core.LogsAPIVersion, Body: body, Headers: map[string]string{"Content-Type": "application/json"}, Pin: h.config.IdentityPin}, record, true)
		})
	default:
		return nil, hostError("protocol_error", "unknown host operation", false)
	}
}
func (h *Host) resolve(cloud core.Cloud, subscription *string, record *CallRecord) (core.ResolvedBinding, error) {
	binding, err := h.config.Context.Binding(cloud)
	if err != nil {
		return binding, hostError("cloud_not_bound", "cloud has no context binding", false)
	}
	source := h.config.Context.BindingSources[cloud]
	if subscription != nil {
		sub, err := core.NormalizeID(*subscription)
		if err != nil {
			return binding, invalidHost()
		}
		pair, err := h.config.Context.AllowsSubscription(cloud, sub)
		if err != nil {
			return binding, hostError("subscription_mismatch", "subscription is not in the context allowlist", false)
		}
		binding.Subscription, binding.Tenant, binding.AllowedSubscriptions = pair.Subscription, pair.Tenant, []core.Pair{pair}
		source = "explicit"
	}
	record.Subscription, record.Tenant, record.SubscriptionSource = ptr(binding.Subscription), ptr(binding.Tenant), ptr(source)
	return binding, nil
}
func (h *Host) execute(ctx context.Context, request Request, record *CallRecord, logs bool) (json.RawMessage, error) {
	route, err := h.config.Client.Policy.Classify(request.Binding.Cloud, request.Purpose, request.Method, request.Target, request.APIVersion)
	if err != nil {
		return nil, hostError("route_denied", "request denied by route policy", false)
	}
	record.PathTemplate, record.RBACAction, record.Decision = route.PathTemplate, ptr(route.RBACAction), "allowed"
	response, err := h.config.Client.Execute(ctx, request)
	if err != nil {
		var httpFailure *HTTPError
		if errors.As(err, &httpFailure) {
			record.RetryCount = httpFailure.RetryCount
		}
		return nil, mapHTTPError(err, request.Binding)
	}
	record.Status, record.RetryCount = ptr(response.Status), response.RetryCount
	if remaining, err := strconv.ParseUint(response.Headers["x-ms-ratelimit-remaining-subscription-reads"], 10, 64); err == nil {
		record.RemainingSubscriptionReads = &remaining
	}
	return decodeResponse(response, logs)
}
func (h *Host) ValidateBinding(ctx context.Context, binding core.ResolvedBinding) error {
	record := h.record("context.validate", binding.Cloud)
	record.Method = "GET"
	record.APIVersion = core.SubscriptionsAPIVersion
	record.APIVersionSource = "reviewedRoute"
	record.Subscription = ptr(binding.Subscription)
	record.Tenant = ptr(binding.Tenant)
	record.SubscriptionSource = ptr(h.config.Context.BindingSources[binding.Cloud])
	_, err := h.audited(ctx, record, func(record *CallRecord) (json.RawMessage, error) {
		target, _ := core.ParseTarget("/subscriptions/" + binding.Subscription)
		route, err := h.config.Client.Policy.Classify(binding.Cloud, "internal", "GET", target, core.SubscriptionsAPIVersion)
		if err != nil {
			return nil, hostError("route_denied", "request denied by route policy", false)
		}
		record.PathTemplate, record.RBACAction = route.PathTemplate, ptr(route.RBACAction)
		response, err := h.config.Client.Execute(ctx, Request{Binding: binding, Purpose: "internal", Method: "GET", Target: target, APIVersion: core.SubscriptionsAPIVersion, Pin: h.config.IdentityPin})
		if err != nil {
			record.Reason = ptr("request_failed")
			var failure *HTTPError
			if errors.As(err, &failure) {
				record.RetryCount = failure.RetryCount
			}
			return nil, mapHTTPError(err, binding)
		}
		record.Decision, record.Status, record.RetryCount = "allowed", ptr(response.Status), response.RetryCount
		if reads, err := strconv.ParseUint(response.Headers["x-ms-ratelimit-remaining-subscription-reads"], 10, 64); err == nil {
			record.RemainingSubscriptionReads = &reads
		}
		var body struct {
			SubscriptionID string `json:"subscriptionId"`
		}
		normalized := ""
		if json.Unmarshal(response.Body, &body) == nil {
			normalized, _ = core.NormalizeID(body.SubscriptionID)
		}
		if response.Status < 200 || response.Status >= 300 || normalized != strings.ToLower(binding.Subscription) {
			record.Reason = ptr("validation_failed")
			return nil, hostError("subscription_mismatch", "subscription validation did not match the requested binding", false)
		}
		return json.RawMessage(`null`), nil
	})
	if err != nil {
		var failure *HostError
		if errors.As(err, &failure) {
			h.mu.Lock()
			h.lastError = failure
			h.principalMismatch = h.principalMismatch || failure.IdentityMismatch
			h.mu.Unlock()
		}
	}
	return err
}
func mapHTTPError(err error, binding core.ResolvedBinding) *HostError {
	var credential *CredentialError
	if errors.As(err, &credential) {
		if credential.Code == "principal_mismatch" {
			e := hostError("authentication_required", "Azure CLI principal changed; close this context and re-authenticate", true)
			e.IdentityMismatch = true
			return e
		}
		switch credential.Code {
		case "authentication_required":
			return hostError("authentication_required", fmt.Sprintf("Azure CLI authentication is required; run AZURE_CLOUD_NAME=%s az login --tenant %s", binding.Cloud, binding.Tenant), true)
		case "spawn_failed":
			return hostError("authentication_required", "Azure CLI could not be started; configure AZMCP_AZ_EXECUTABLE, then retry", true)
		case "unsupported_cli":
			return hostError("authentication_required", "Azure CLI 2.89.0 or newer is required; upgrade Azure CLI or configure AZMCP_AZ_EXECUTABLE, then retry", true)
		}
		return hostError("authentication_required", "Azure authentication is unavailable", true)
	}
	var failure *HTTPError
	if errors.As(err, &failure) {
		switch failure.Code {
		case "policy_denied":
			return hostError("route_denied", "request denied by route policy", false)
		case "subscription_mismatch":
			return hostError("subscription_mismatch", "subscription is not in the context allowlist", false)
		case "response_body_too_large":
			return hostError("response_too_large", "response exceeds the transport limit", false)
		case "request_body_too_large", "invalid_target", "invalid_api_version", "invalid_header", "forbidden_header", "duplicate_header", "invalid_limits", "invalid_metrics_region", "invalid_binding":
			return invalidHost()
		case "timeout":
			return hostError("upstream_error", "upstream request timed out", true)
		}
	}
	return hostError("upstream_error", "upstream request failed", true)
}
func decodeResponse(response Response, logs bool) (json.RawMessage, error) {
	if response.Status < 200 || response.Status >= 300 {
		return nil, upstreamError(response, logs)
	}
	if len(response.Body) > 1024*1024 {
		return nil, hostError("response_too_large", "response exceeds the host JSON limit", false)
	}
	if !json.Valid(response.Body) {
		return nil, hostError("invalid_response", "upstream response was not valid JSON", false)
	}
	if logs {
		if err := validateLogsResponse(response.Body); err != nil {
			return nil, err
		}
		return response.Body, nil
	}
	result, err := json.Marshal(map[string]any{"status": response.Status, "headers": response.Headers, "body": json.RawMessage(response.Body)})
	if err != nil {
		return nil, hostError("invalid_response", "upstream response was not valid JSON", false)
	}
	return result, nil
}
func upstreamError(response Response, logs bool) *HostError {
	operation := "Azure"
	if logs {
		operation = "Logs Query"
	}
	message := fmt.Sprintf("%s returned HTTP %d", operation, response.Status)
	if len(response.Body) <= 64*1024 {
		var value map[string]any
		if json.Unmarshal(response.Body, &value) == nil {
			errorValue := any(value)
			if candidate, ok := value["error"]; ok {
				errorValue = candidate
			}
			var summaries []string
			for depth := 0; depth < 4; depth++ {
				object, ok := errorValue.(map[string]any)
				if !ok {
					break
				}
				code, _ := object["code"].(string)
				text, _ := object["message"].(string)
				code = safeErrorCode(code)
				text = safeErrorText(text, 256)
				if code != "" && text != "" {
					summaries = append(summaries, code+": "+text)
				} else if code != "" {
					summaries = append(summaries, code)
				} else if text != "" {
					summaries = append(summaries, text)
				}
				errorValue = object["innererror"]
				if errorValue == nil {
					errorValue = object["innerError"]
				}
			}
			if len(summaries) > 0 {
				message += ": " + strings.Join(summaries, "; ")
			}
		}
	}
	for _, name := range []string{"x-ms-request-id", "x-ms-correlation-request-id", "request-id"} {
		if id := safeErrorCode(response.Headers[name]); id != "" {
			message += " (request ID " + id + ")"
			break
		}
	}
	return hostError("upstream_error", safeErrorText(message, 512), response.Status == 429 || response.Status >= 500)
}
func safeErrorCode(value string) string {
	if value == "" || len(value) > 256 || strings.IndexFunc(value, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._:-", r))
	}) != -1 {
		return ""
	}
	return value
}
func safeErrorText(value string, limit int) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
	value = strings.TrimSpace(value)
	if len(value) > limit {
		for limit > 0 && !utf8Boundary(value[limit]) {
			limit--
		}
		value = value[:limit]
	}
	return value
}
func utf8Boundary(b byte) bool { return b&0xc0 != 0x80 }
func containsFold(values []string, value string) bool {
	for _, v := range values {
		if core.EqualFoldASCII(v, value) {
			return true
		}
	}
	return false
}
func subscriptionList(values []string) ([]string, error) {
	seen := map[string]bool{}
	var result []string
	for _, value := range values {
		normalized, err := core.NormalizeID(value)
		if err != nil || seen[normalized] {
			return nil, invalidHost()
		}
		seen[normalized] = true
		result = append(result, normalized)
	}
	return result, nil
}

type metricResourceValue struct{ subscription, path, resourceType string }

func metricResource(value string) (metricResourceValue, error) {
	target, err := core.ParseTarget(value)
	if err != nil || len(target.Query) != 0 || len(target.Segments) < 6 || !core.EqualFoldASCII(target.Segments[0], "subscriptions") {
		return metricResourceValue{}, invalidHost()
	}
	subscription, err := core.NormalizeID(target.Segments[1])
	if err != nil {
		return metricResourceValue{}, invalidHost()
	}
	provider := -1
	for i, segment := range target.Segments {
		if core.EqualFoldASCII(segment, "providers") {
			provider = i
			break
		}
	}
	if provider < 0 || provider+3 >= len(target.Segments) || (len(target.Segments)-provider-2)%2 != 0 {
		return metricResourceValue{}, invalidHost()
	}
	resourceType := target.Segments[provider+1]
	for i := provider + 2; i < len(target.Segments); i += 2 {
		resourceType += "/" + target.Segments[i]
	}
	return metricResourceValue{subscription, target.Path, resourceType}, nil
}
func metricNames(names []string) error {
	if len(names) == 0 || len(names) > 20 {
		return invalidHost()
	}
	for _, name := range names {
		if name == "" || len(name) > 256 || strings.Contains(name, ",") || strings.IndexFunc(name, unicode.IsControl) != -1 {
			return invalidHost()
		}
	}
	return nil
}
func pushMetric(values url.Values, name string, value *string) error {
	if value == nil {
		return nil
	}
	if *value == "" || len(*value) > 4096 || strings.IndexFunc(*value, unicode.IsControl) != -1 {
		return invalidHost()
	}
	values.Add(name, *value)
	return nil
}
func singleQuery(args MetricsArgs) (string, error) {
	if err := metricNames(args.MetricNames); err != nil {
		return "", err
	}
	q := url.Values{}
	for _, pair := range []struct {
		name  string
		value *string
	}{{"timespan", args.Timespan}, {"interval", args.Interval}, {"metricnames", ptr(strings.Join(args.MetricNames, ","))}, {"aggregation", args.Aggregation}, {"orderby", args.OrderBy}, {"$filter", args.Filter}, {"resultType", args.ResultType}, {"metricnamespace", args.MetricNamespace}, {"rollupby", args.RollupBy}} {
		if err := pushMetric(q, pair.name, pair.value); err != nil {
			return "", err
		}
	}
	if args.Top != nil {
		q.Set("top", strconv.FormatUint(uint64(*args.Top), 10))
	}
	if args.AutoAdjustTimegrain != nil {
		q.Set("AutoAdjustTimegrain", strconv.FormatBool(*args.AutoAdjustTimegrain))
	}
	if args.ValidateDimensions != nil {
		q.Set("ValidateDimensions", strconv.FormatBool(*args.ValidateDimensions))
	}
	return q.Encode(), nil
}
func batchQuery(args BatchArgs) (string, error) {
	if err := metricNames(args.MetricNames); err != nil {
		return "", err
	}
	q := url.Values{}
	for _, pair := range []struct {
		name  string
		value *string
	}{{"starttime", args.StartTime}, {"endtime", args.EndTime}, {"interval", args.Interval}, {"metricnamespace", &args.MetricNamespace}, {"metricnames", ptr(strings.Join(args.MetricNames, ","))}, {"aggregation", args.Aggregation}, {"orderby", args.OrderBy}, {"filter", args.Filter}, {"rollupby", args.RollupBy}} {
		if err := pushMetric(q, pair.name, pair.value); err != nil {
			return "", err
		}
	}
	if args.Top != nil {
		q.Set("top", strconv.FormatUint(uint64(*args.Top), 10))
	}
	return q.Encode(), nil
}
func validTimespan(value string) bool {
	if len(value) < 2 || len(value) > 128 || !cleanValue(value) || value[0] != 'P' {
		return false
	}
	var seconds, number uint64
	haveNumber, inTime, haveComponent, haveTime := false, false, false, false
	for _, c := range value[1:] {
		if c >= '0' && c <= '9' {
			digit := uint64(c - '0')
			if number > (^uint64(0)-digit)/10 {
				return false
			}
			number = number*10 + digit
			haveNumber = true
			continue
		}
		if c == 'T' {
			if inTime || haveNumber {
				return false
			}
			inTime = true
			continue
		}
		if !haveNumber {
			return false
		}
		var multiplier uint64
		switch {
		case !inTime && c == 'D':
			multiplier = 86400
		case inTime && c == 'H':
			multiplier = 3600
		case inTime && c == 'M':
			multiplier = 60
		case inTime && c == 'S':
			multiplier = 1
		default:
			return false
		}
		if number > (30*24*60*60-seconds)/multiplier {
			return false
		}
		seconds += number * multiplier
		number = 0
		haveNumber = false
		haveComponent = true
		haveTime = haveTime || inTime
	}
	return haveComponent && (!inTime || haveTime) && !haveNumber && seconds > 0 && seconds <= 30*24*60*60
}
func validateLogsResponse(raw []byte) error {
	var value map[string]json.RawMessage
	if json.Unmarshal(raw, &value) != nil {
		return hostError("invalid_response", "Logs Query response has an invalid table shape", false)
	}
	var tables []map[string]json.RawMessage
	if value["tables"] == nil || string(value["tables"]) == "null" || json.Unmarshal(value["tables"], &tables) != nil {
		return hostError("invalid_response", "Logs Query response has an invalid table shape", false)
	}
	rowsTotal := 0
	for _, table := range tables {
		var columns []map[string]json.RawMessage
		if table["columns"] == nil || string(table["columns"]) == "null" || json.Unmarshal(table["columns"], &columns) != nil {
			return hostError("invalid_response", "Logs Query response has an invalid column shape", false)
		}
		for _, column := range columns {
			var name, kind string
			if column["name"] == nil || column["type"] == nil || string(column["name"]) == "null" || string(column["type"]) == "null" || json.Unmarshal(column["name"], &name) != nil || json.Unmarshal(column["type"], &kind) != nil {
				return hostError("invalid_response", "Logs Query response has an invalid column shape", false)
			}
		}
		var rows []json.RawMessage
		if table["rows"] == nil || string(table["rows"]) == "null" || json.Unmarshal(table["rows"], &rows) != nil {
			return hostError("invalid_response", "Logs Query response has an invalid row shape", false)
		}
		rowsTotal += len(rows)
		if rowsTotal > 50000 {
			return hostError("invalid_response", "Logs Query response exceeds the row limit or has an invalid row shape", false)
		}
		for _, row := range rows {
			var cells []json.RawMessage
			if string(row) == "null" || json.Unmarshal(row, &cells) != nil || len(cells) != len(columns) {
				return hostError("invalid_response", "Logs Query response exceeds the row limit or has an invalid row shape", false)
			}
		}
	}
	return nil
}
