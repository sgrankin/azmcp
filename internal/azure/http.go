package azure

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"azmcp/internal/core"
)

type HTTPError struct {
	Code       string
	RetryCount int
	Cause      error
}

func (e *HTTPError) Error() string     { return "Azure HTTP request failed: " + e.Code }
func (e *HTTPError) Unwrap() error     { return e.Cause }
func httpError(code string) *HTTPError { return &HTTPError{Code: code} }

type Limits struct {
	RequestBytes, ResponseBytes int
	Timeout                     time.Duration
	Retry                       RetryPolicy
}
type RetryPolicy struct {
	MaxAttempts                            int
	MaxElapsed, InitialBackoff, MaxBackoff time.Duration
}

func DefaultLimits() Limits {
	return Limits{1024 * 1024, 8 * 1024 * 1024, 30 * time.Second, RetryPolicy{3, 10 * time.Second, 100 * time.Millisecond, 2 * time.Second}}
}
func (l Limits) validate() error {
	r := l.Retry
	if l.RequestBytes <= 0 || l.ResponseBytes <= 0 || l.ResponseBytes > 64*1024*1024 || l.Timeout <= 0 || r.MaxAttempts < 1 || r.MaxAttempts > 8 || r.MaxElapsed <= 0 || r.MaxElapsed > 60*time.Second || r.InitialBackoff < 0 || r.MaxBackoff < 0 || r.InitialBackoff > r.MaxBackoff || r.MaxBackoff > 30*time.Second {
		return httpError("invalid_limits")
	}
	return nil
}

type Client struct {
	Policy      *core.Policy
	credentials CredentialProvider
	http        *http.Client
	limits      Limits
	loopback    *url.URL
}

func NewClient(credentials CredentialProvider, policy *core.Policy) (*Client, error) {
	return newClient(credentials, policy, DefaultLimits(), nil)
}
func NewClientWithLimits(credentials CredentialProvider, policy *core.Policy, limits Limits) (*Client, error) {
	return newClient(credentials, policy, limits, nil)
}
func NewLoopbackClient(credentials CredentialProvider, policy *core.Policy, origin string) (*Client, error) {
	return NewLoopbackClientWithLimits(credentials, policy, origin, DefaultLimits())
}
func NewLoopbackClientWithLimits(credentials CredentialProvider, policy *core.Policy, origin string, limits Limits) (*Client, error) {
	u, err := url.Parse(origin)
	if err != nil || !loopbackOrigin(u) {
		return nil, httpError("invalid_loopback_origin")
	}
	return newClient(credentials, policy, limits, u)
}
func loopbackOrigin(u *url.URL) bool {
	if u == nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "/" && u.Path != "") || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	return core.EqualFoldASCII(host, "localhost") || ip != nil && ip.IsLoopback()
}
func newClient(credentials CredentialProvider, policy *core.Policy, limits Limits, loopback *url.URL) (*Client, error) {
	if credentials == nil {
		return nil, httpError("invalid_credential_provider")
	}
	if policy == nil {
		return nil, httpError("invalid_policy")
	}
	if err := policy.Validate(); err != nil {
		return nil, httpError("invalid_policy")
	}
	if err := limits.validate(); err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// A proxy must not turn an explicitly injected loopback simulator into an
	// outbound request, or send its synthetic bearer to another destination.
	transport.Proxy = nil
	return &Client{Policy: policy, credentials: credentials, limits: limits, loopback: loopback, http: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) Close() { c.http.CloseIdleConnections() }

type Request struct {
	Binding                             core.ResolvedBinding
	Purpose, Method, APIVersion, Region string
	Target                              core.RequestTarget
	Headers                             map[string]string
	Body                                []byte
	Pin                                 *IdentityPin
}
type Response struct {
	Status     int
	Headers    map[string]string
	Body       []byte
	RetryCount int
}

func (c *Client) origin(r Request) (*url.URL, error) {
	if _, err := core.ParseCloud(string(r.Binding.Cloud)); err != nil {
		return nil, httpError("invalid_cloud")
	}
	m := r.Binding.Cloud.Manifest()
	origin := m.ResourceManager
	if r.Purpose == "logsQuery" {
		origin = m.DataPlane.LogsQuery
	}
	if r.Purpose == "metricsBatch" {
		region, err := normalizeRegion(r.Region)
		if err != nil {
			return nil, err
		}
		origin = "https://" + region + "." + m.DataPlane.Metrics + "/"
	}
	if c.loopback != nil {
		copy := *c.loopback
		return &copy, nil
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
		return nil, httpError("invalid_manifest_origin")
	}
	return u, nil
}
func normalizeRegion(region string) (string, error) {
	if len(region) < 2 || len(region) > 63 || !cleanValue(region) {
		return "", httpError("invalid_metrics_region")
	}
	for i, c := range region {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' && i > 0 && i < len(region)-1) {
			return "", httpError("invalid_metrics_region")
		}
	}
	return strings.ToLower(region), nil
}
func (c *Client) Execute(ctx context.Context, r Request) (Response, error) {
	return c.execute(ctx, r, c.limits.ResponseBytes)
}
func (c *Client) execute(ctx context.Context, r Request, responseLimit int) (Response, error) {
	if responseLimit <= 0 || responseLimit > c.limits.ResponseBytes {
		return Response{}, httpError("invalid_limits")
	}
	if !cleanValue(r.APIVersion) || strings.ContainsAny(r.APIVersion, "?#&=") {
		return Response{}, httpError("invalid_api_version")
	}
	if len(r.Body) > c.limits.RequestBytes {
		return Response{}, httpError("request_body_too_large")
	}
	if err := validateHeaders(r.Headers); err != nil {
		return Response{}, err
	}
	// Reparse the transport's public target value; constructed structs cannot
	// bypass canonical path and query checks at the signing boundary.
	target, err := core.ParseTarget(r.Target.String())
	if err != nil {
		return Response{}, httpError("invalid_target")
	}
	r.Target = target
	route, err := c.Policy.Classify(r.Binding.Cloud, r.Purpose, r.Method, r.Target, r.APIVersion)
	if err != nil {
		return Response{}, httpError("policy_denied")
	}
	if len(r.Target.Segments) > 1 && core.EqualFoldASCII(r.Target.Segments[0], "subscriptions") && !core.EqualFoldASCII(r.Target.Segments[1], r.Binding.Subscription) {
		return Response{}, httpError("subscription_mismatch")
	}
	if !validID(r.Binding.Tenant) || !validID(r.Binding.Subscription) {
		return Response{}, httpError("invalid_binding")
	}
	origin, err := c.origin(r)
	if err != nil {
		return Response{}, err
	}
	u, err := requestURL(origin, r.Target, r.APIVersion, r.Purpose == "logsQuery")
	if err != nil {
		return Response{}, err
	}
	tokenRequest := TokenRequest{Cloud: r.Binding.Cloud, Tenant: r.Binding.Tenant, Subscription: r.Binding.Subscription, Audience: r.Binding.Cloud.Audience(r.Purpose), Scope: r.Pin.Scope()}
	if ctx.Err() != nil {
		return Response{}, httpError("timeout")
	}
	credential, err := c.credentials.Acquire(ctx, tokenRequest)
	if err != nil {
		return Response{}, &HTTPError{Code: "credential", Cause: err}
	}
	defer credential.Clear()
	if ctx.Err() != nil {
		return Response{}, httpError("timeout")
	}
	if err := r.Pin.Check(tokenRequest, credential); err != nil {
		return Response{}, &HTTPError{Code: "credential", Cause: err}
	}
	if !cleanValue(string(credential.Token)) {
		return Response{}, &HTTPError{Code: "credential", Cause: credentialError("empty_token")}
	}
	retryable := route.ArmTier != "write" && (r.Method == "GET" && (r.Purpose == "request" || r.Purpose == "internal" || r.Purpose == "metricsSingle") || r.Method == "POST" && (r.Purpose == "resourceGraph" || r.Purpose == "metricsBatch" || r.Purpose == "logsQuery"))
	budget, cancel := context.WithTimeout(ctx, c.limits.Retry.MaxElapsed)
	defer cancel()
	for attempt := 0; attempt < c.limits.Retry.MaxAttempts; attempt++ {
		attemptCtx, cancelAttempt := context.WithTimeout(budget, c.limits.Timeout)
		response, err := c.send(attemptCtx, r, u, credential.Token, responseLimit)
		cancelAttempt()
		if err != nil {
			var failure *HTTPError
			if errors.As(err, &failure) {
				failure.RetryCount = attempt
			}
			return Response{}, err
		}
		response.RetryCount = attempt
		if !retryable || (response.Status != 429 && (response.Status < 500 || response.Status > 599)) || attempt+1 >= c.limits.Retry.MaxAttempts {
			return response, nil
		}
		delay := c.limits.Retry.InitialBackoff
		for count := 0; count < attempt && delay < c.limits.Retry.MaxBackoff; count++ {
			delay = min(delay*2, c.limits.Retry.MaxBackoff)
		}
		if delay > c.limits.Retry.MaxBackoff {
			delay = c.limits.Retry.MaxBackoff
		}
		if parsed, ok := retryAfter(response.Headers["retry-after"]); ok {
			delay = min(parsed, c.limits.Retry.MaxBackoff)
		}
		deadline, _ := budget.Deadline()
		if delay >= time.Until(deadline) {
			return response, nil
		}
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-budget.Done():
			timer.Stop()
			return Response{}, httpError("timeout")
		}
	}
	panic("retry loop exhausted without returning")
}
func requestURL(origin *url.URL, target core.RequestTarget, apiVersion string, logs bool) (*url.URL, error) {
	relative, err := url.Parse(target.String())
	if err != nil {
		return nil, httpError("invalid_target")
	}
	u := origin.ResolveReference(relative)
	if !sameOrigin(origin, u) || u.User != nil || u.Fragment != "" {
		return nil, httpError("origin_mismatch")
	}
	if logs {
		if u.RawQuery != "" {
			return nil, httpError("origin_mismatch")
		}
	} else {
		query := u.Query()
		query.Add("api-version", apiVersion)
		u.RawQuery = query.Encode()
	}
	return u, nil
}
func sameOrigin(a, b *url.URL) bool {
	return core.EqualFoldASCII(a.Scheme, b.Scheme) && core.EqualFoldASCII(a.Hostname(), b.Hostname()) && effectivePort(a) == effectivePort(b)
}
func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}
func (c *Client) send(ctx context.Context, r Request, u *url.URL, token []byte, limit int) (Response, error) {
	request, err := http.NewRequestWithContext(ctx, r.Method, u.String(), bytes.NewReader(r.Body))
	if err != nil {
		return Response{}, httpError("invalid_target")
	}
	request.Header.Set("Authorization", "Bearer "+string(token))
	for key, value := range r.Headers {
		request.Header.Set(key, value)
	}
	result, err := c.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return Response{}, httpError("timeout")
		}
		return Response{}, httpError("request_send")
	}
	defer result.Body.Close()
	if result.StatusCode >= 300 && result.StatusCode < 400 {
		return Response{}, httpError("redirect_denied")
	}
	if result.ContentLength > int64(limit) {
		return Response{}, httpError("response_body_too_large")
	}
	body, err := io.ReadAll(io.LimitReader(result.Body, int64(limit)+1))
	if err != nil {
		if ctx.Err() != nil {
			return Response{}, httpError("timeout")
		}
		return Response{}, httpError("response_read")
	}
	if len(body) > limit {
		return Response{}, httpError("response_body_too_large")
	}
	return Response{Status: result.StatusCode, Headers: safeHeaders(result.Header), Body: body}, nil
}
func validateHeaders(headers map[string]string) error {
	seen := map[string]bool{}
	for name, value := range headers {
		lower := strings.ToLower(name)
		if name == "" || strings.IndexFunc(name, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", r))
		}) != -1 {
			return httpError("invalid_header")
		}
		if seen[lower] {
			return httpError("duplicate_header")
		}
		seen[lower] = true
		switch lower {
		case "authorization", "proxy-authorization", "host", "connection", "keep-alive", "proxy-authenticate", "te", "trailer", "transfer-encoding", "upgrade", "forwarded", "via", "x-forwarded-for", "x-forwarded-host", "x-forwarded-port", "x-forwarded-proto", "x-forwarded-server", "x-real-ip", "cookie", "set-cookie":
			return httpError("forbidden_header")
		}
		if strings.IndexFunc(value, unicode.IsControl) != -1 {
			return httpError("invalid_header")
		}
	}
	return nil
}
func safeHeaders(headers http.Header) map[string]string {
	result := map[string]string{}
	for _, name := range []string{"content-length", "content-type", "etag", "last-modified", "request-id", "retry-after", "x-ms-correlation-request-id", "x-ms-ratelimit-remaining-subscription-reads", "x-ms-request-id"} {
		value := headers.Get(name)
		if value == "" || len(value) > 4096 || strings.IndexFunc(value, unicode.IsControl) != -1 {
			continue
		}
		if name == "retry-after" {
			delay, ok := retryAfter(value)
			if len(value) > 128 || !ok || delay > 30*time.Second {
				continue
			}
		}
		result[name] = value
	}
	return result
}
func retryAfter(value string) (time.Duration, bool) {
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseUint(value, 10, 64); err == nil {
		if seconds > uint64((1<<63-1)/int64(time.Second)) {
			return 0, false
		}
		return time.Duration(seconds) * time.Second, true
	}
	if t, err := http.ParseTime(value); err == nil {
		return max(time.Until(t), 0), true
	}
	return 0, false
}
