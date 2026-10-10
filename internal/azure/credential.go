package azure

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"azmcp/internal/core"
)

const maxCLIOutput = 1024 * 1024

var processLock = make(chan struct{}, 1)

type CredentialError struct {
	Code    string
	Message string
}

func (e *CredentialError) Error() string { return e.Message }
func credentialError(code string) *CredentialError {
	messages := map[string]string{
		"invalid_request": "invalid credential request", "spawn_failed": "credential broker could not start",
		"output_read_failed": "credential broker output could not be read", "timeout": "credential broker timed out",
		"authentication_required": "Azure CLI authentication is required", "subscription_rejected": "Azure CLI rejected the requested subscription",
		"cli_rejected": "Azure CLI rejected the credential request", "invalid_json": "credential broker returned invalid JSON",
		"invalid_response": "credential broker returned an incomplete or invalid response", "tenant_mismatch": "credential broker returned a token for a different tenant",
		"subscription_mismatch": "credential broker returned a token for a different subscription", "principal_mismatch": "credential broker returned a different token principal or client identity",
		"empty_token": "credential broker returned an empty access token", "invalid_token_type": "credential broker returned an unsupported token type",
		"expired_token": "credential broker returned an expired or near-expiry token", "unsupported_cli": "Azure CLI does not meet the supported version and command requirements",
	}
	return &CredentialError{Code: code, Message: messages[code]}
}

type TokenRequest struct {
	Cloud                                 core.Cloud
	Tenant, Subscription, Audience, Scope string
}

type Credential struct {
	Token               []byte
	Principal, ClientID string
	ExpiresAt           time.Time
}

func (c Credential) Format(state fmt.State, verb rune) {
	io.WriteString(state, "Credential{token:<redacted>}")
}
func (c *Credential) Clear()                  { clear(c.Token); c.Token = nil }
func cloneCredential(c Credential) Credential { c.Token = bytes.Clone(c.Token); return c }

type CredentialProvider interface {
	Acquire(context.Context, TokenRequest) (Credential, error)
}

type IdentityPin struct {
	mu         sync.Mutex
	scope      string
	identities map[string]string
}

func NewIdentityPin() *IdentityPin {
	return &IdentityPin{scope: randomID(), identities: make(map[string]string)}
}
func (p *IdentityPin) Scope() string {
	if p == nil {
		return ""
	}
	return p.scope
}
func (p *IdentityPin) Check(request TokenRequest, credential Credential) error {
	if p == nil {
		return nil
	}
	if !validID(credential.Principal) || !validID(credential.ClientID) {
		return credentialError("invalid_response")
	}
	key := string(request.Cloud) + "|" + strings.ToLower(request.Tenant) + "|" + request.Audience
	identity := strings.ToLower(credential.Principal) + "|" + strings.ToLower(credential.ClientID)
	p.mu.Lock()
	defer p.mu.Unlock()
	if previous, exists := p.identities[key]; exists && previous != identity {
		return credentialError("principal_mismatch")
	}
	p.identities[key] = identity
	return nil
}

type BrokerConfig struct {
	Executable, ProfileDir, CorrelationID string
	Timeout                               time.Duration
}
type Broker struct {
	config  BrokerConfig
	mu      sync.Mutex
	closed  bool
	version string
	cache   map[TokenRequest]Credential
}

func NewBroker(config BrokerConfig) (*Broker, error) {
	if !filepath.IsAbs(config.Executable) || !filepath.IsAbs(config.ProfileDir) || config.Executable == "" || config.ProfileDir == "" {
		return nil, credentialError("invalid_request")
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.Timeout < 0 {
		return nil, credentialError("invalid_request")
	}
	if config.CorrelationID == "" {
		config.CorrelationID = "azmcp-" + randomID()
	}
	if len(config.CorrelationID) > 128 || strings.IndexFunc(config.CorrelationID, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._:-", r))
	}) != -1 {
		return nil, credentialError("invalid_request")
	}
	return &Broker{config: config, cache: make(map[TokenRequest]Credential)}, nil
}
func (b *Broker) CorrelationID() string { return b.config.CorrelationID }
func (b *Broker) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	for k, c := range b.cache {
		c.Clear()
		delete(b.cache, k)
	}
}
func (b *Broker) Probe(ctx context.Context) (string, error) {
	if err := lockProcess(ctx); err != nil {
		return "", err
	}
	defer unlockProcess()
	return b.probeLocked(ctx)
}
func lockProcess(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case processLock <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func unlockProcess() { <-processLock }
func (b *Broker) probeLocked(ctx context.Context) (string, error) {
	if ctx.Err() != nil {
		return "", credentialError("timeout")
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return "", credentialError("invalid_request")
	}
	version := b.version
	b.mu.Unlock()
	if version != "" {
		return version, nil
	}
	out, _, err := b.command(ctx, "version", "--output", "json", "--only-show-errors")
	defer clear(out)
	if err != nil {
		if c, ok := err.(*CredentialError); ok && c.Code == "cli_rejected" {
			return "", credentialError("unsupported_cli")
		}
		return "", err
	}
	var result struct {
		Version string `json:"azure-cli"`
	}
	if decodeCredentialObject(out, &result, "azure-cli") != nil {
		return "", credentialError("unsupported_cli")
	}
	parts := strings.Split(strings.TrimSpace(result.Version), ".")
	if len(parts) != 3 {
		return "", credentialError("unsupported_cli")
	}
	var numbers [3]int
	for i, s := range parts {
		n, e := strconv.Atoi(s)
		if e != nil || n < 0 {
			return "", credentialError("unsupported_cli")
		}
		numbers[i] = n
	}
	if numbers[0] < 2 || numbers[0] == 2 && numbers[1] < 89 {
		return "", credentialError("unsupported_cli")
	}
	b.mu.Lock()
	b.version = result.Version
	b.mu.Unlock()
	return result.Version, nil
}
func (b *Broker) Acquire(ctx context.Context, r TokenRequest) (Credential, error) {
	if ctx.Err() != nil {
		return Credential{}, credentialError("timeout")
	}
	b.mu.Lock()
	closed := b.closed
	b.mu.Unlock()
	if closed {
		return Credential{}, credentialError("invalid_request")
	}
	if _, err := core.ParseCloud(string(r.Cloud)); err != nil {
		return Credential{}, credentialError("invalid_request")
	}
	if !validID(r.Tenant) || !validID(r.Subscription) || !validAudience(r.Cloud, r.Audience) {
		return Credential{}, credentialError("invalid_request")
	}
	r.Tenant, r.Subscription = strings.ToLower(r.Tenant), strings.ToLower(r.Subscription)
	if token, ok := b.fresh(r); ok {
		return token, nil
	}
	if err := lockProcess(ctx); err != nil {
		return Credential{}, err
	}
	defer unlockProcess()
	if token, ok := b.fresh(r); ok {
		return token, nil
	}
	if _, err := b.probeLocked(ctx); err != nil {
		return Credential{}, err
	}
	out, stderr, err := b.commandCloud(ctx, r.Cloud, "account", "get-access-token", "--subscription", r.Subscription, "--resource", r.Audience, "--output", "json", "--only-show-errors")
	defer clear(out)
	defer clear(stderr)
	if err != nil {
		if c, ok := err.(*CredentialError); ok && c.Code == "cli_rejected" {
			text := strings.ToLower(string(stderr))
			if strings.Contains(text, "login") || strings.Contains(text, "aadsts") || strings.Contains(text, "authentication") || strings.Contains(text, "not logged in") {
				return Credential{}, credentialError("authentication_required")
			}
			if strings.Contains(text, "subscription") && (strings.Contains(text, "not found") || strings.Contains(text, "does not exist") || strings.Contains(text, "invalid")) {
				return Credential{}, credentialError("subscription_rejected")
			}
		}
		return Credential{}, err
	}
	credential, err := parseCredential(out, r)
	if err != nil {
		return Credential{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		credential.Clear()
		return Credential{}, credentialError("invalid_request")
	}
	for key, token := range b.cache {
		if time.Until(token.ExpiresAt) <= 5*time.Minute {
			token.Clear()
			delete(b.cache, key)
		}
	}
	if len(b.cache) < 64 {
		b.cache[r] = cloneCredential(credential)
	}
	return credential, nil
}
func (b *Broker) fresh(r TokenRequest) (Credential, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return Credential{}, false
	}
	token, ok := b.cache[r]
	if !ok {
		return Credential{}, false
	}
	if time.Until(token.ExpiresAt) <= 5*time.Minute {
		token.Clear()
		delete(b.cache, r)
		return Credential{}, false
	}
	return cloneCredential(token), true
}
func (b *Broker) command(ctx context.Context, args ...string) ([]byte, []byte, error) {
	return b.commandCloud(ctx, "", args...)
}
func (b *Broker) commandCloud(ctx context.Context, cloud core.Cloud, args ...string) ([]byte, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, b.config.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, b.config.Executable, args...)
	cmd.Env = []string{"AZURE_CONFIG_DIR=" + b.config.ProfileDir, "COPILOT_AGENT_SESSION_ID=" + b.config.CorrelationID}
	for _, name := range []string{"PATH", "LANG", "LC_ALL", "TMPDIR", "SystemRoot", "SSL_CERT_FILE"} {
		if value, ok := os.LookupEnv(name); ok {
			cmd.Env = append(cmd.Env, name+"="+value)
		}
	}
	// The profile is explicit even when HOME would ordinarily select ~/.azure.
	cmd.Env = append(cmd.Env, "HOME="+filepath.Dir(b.config.ProfileDir), "USERPROFILE="+filepath.Dir(b.config.ProfileDir))
	if cloud != "" {
		cmd.Env = append(cmd.Env, "AZURE_CLOUD_NAME="+string(cloud))
	}
	var out, stderr boundedOutput
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	if ctx.Err() != nil {
		out.clear()
		stderr.clear()
		return nil, nil, credentialError("timeout")
	}
	if out.exceeded || stderr.exceeded {
		out.clear()
		stderr.clear()
		return nil, nil, credentialError("output_read_failed")
	}
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return out.bytes, stderr.bytes, credentialError("cli_rejected")
		}
		out.clear()
		stderr.clear()
		return nil, nil, credentialError("spawn_failed")
	}
	return out.bytes, stderr.bytes, nil
}

type boundedOutput struct {
	bytes    []byte
	exceeded bool
}

func (o *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := maxCLIOutput - len(o.bytes)
	if n > remaining {
		o.exceeded = true
		p = p[:remaining]
	}
	o.bytes = append(o.bytes, p...)
	return n, nil
}
func (o *boundedOutput) clear() { clear(o.bytes); o.bytes = nil }

func parseCredential(out []byte, r TokenRequest) (Credential, error) {
	var value struct {
		Token        string          `json:"accessToken"`
		TokenType    string          `json:"tokenType"`
		Tenant       string          `json:"tenant"`
		Subscription string          `json:"subscription"`
		ExpiresOn    string          `json:"expiresOn"`
		ExpiresEpoch json.RawMessage `json:"expires_on"`
	}
	if decodeCredentialObject(out, &value, "accessToken", "tokenType", "tenant", "subscription", "expiresOn", "expires_on") != nil {
		return Credential{}, credentialError("invalid_json")
	}
	if !cleanValue(value.Token) {
		return Credential{}, credentialError("empty_token")
	}
	if value.TokenType != "" && !core.EqualFoldASCII(value.TokenType, "Bearer") {
		return Credential{}, credentialError("invalid_token_type")
	}
	if !core.EqualFoldASCII(value.Tenant, r.Tenant) {
		return Credential{}, credentialError("tenant_mismatch")
	}
	if !core.EqualFoldASCII(value.Subscription, r.Subscription) {
		return Credential{}, credentialError("subscription_mismatch")
	}
	expires := value.ExpiresOn
	if len(value.ExpiresEpoch) > 0 && string(value.ExpiresEpoch) != "null" {
		if json.Unmarshal(value.ExpiresEpoch, &expires) != nil {
			var seconds uint64
			if json.Unmarshal(value.ExpiresEpoch, &seconds) != nil {
				return Credential{}, credentialError("invalid_response")
			}
			expires = strconv.FormatUint(seconds, 10)
		}
	}
	expiry, err := parseExpiration(expires)
	if err != nil || time.Until(expiry) <= 5*time.Minute {
		return Credential{}, credentialError("expired_token")
	}
	parts := strings.Split(value.Token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return Credential{}, credentialError("invalid_response")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Credential{}, credentialError("invalid_response")
	}
	defer clear(payload)
	var claims struct {
		Audience  string `json:"aud"`
		Tenant    string `json:"tid"`
		Principal string `json:"oid"`
		AppID     string `json:"appid"`
		AZP       string `json:"azp"`
	}
	if decodeCredentialObject(payload, &claims, "aud", "tid", "oid", "appid", "azp") != nil || claims.Audience != r.Audience {
		return Credential{}, credentialError("invalid_response")
	}
	if !core.EqualFoldASCII(claims.Tenant, r.Tenant) {
		return Credential{}, credentialError("tenant_mismatch")
	}
	client := claims.AppID
	if !validID(client) {
		client = claims.AZP
	}
	if !validID(client) || !validID(claims.Principal) {
		return Credential{}, credentialError("invalid_response")
	}
	return Credential{Token: []byte(value.Token), Principal: strings.ToLower(claims.Principal), ClientID: strings.ToLower(client), ExpiresAt: expiry}, nil
}

// CLI responses and JWTs permit extension fields, but known identity fields
// use exact names and cannot be repeated. Ambiguous fields cannot select a
// different audience or principal through encoding/json's case folding.
func decodeCredentialObject(raw []byte, value any, names ...string) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return fmt.Errorf("invalid credential JSON object")
	}
	known := make(map[string]bool, len(names))
	for _, name := range names {
		known[name] = true
	}
	fields := make(map[string]json.RawMessage, len(names))
	defer func() {
		for _, field := range fields {
			clear(field)
		}
	}()
	for decoder.More() {
		name, err := decoder.Token()
		if err != nil {
			return err
		}
		var field json.RawMessage
		if err := decoder.Decode(&field); err != nil {
			return err
		}
		key := name.(string)
		if !known[key] {
			clear(field)
			continue
		}
		if _, exists := fields[key]; exists {
			clear(field)
			return fmt.Errorf("duplicate credential JSON field")
		}
		fields[key] = field
	}
	if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
		return fmt.Errorf("invalid credential JSON object")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing credential JSON data")
	}
	filtered, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	defer clear(filtered)
	return core.DecodeClosed(filtered, value)
}

func parseExpiration(value string) (time.Time, error) {
	if seconds, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64); err == nil {
		if seconds > 100_000_000_000 {
			seconds /= 1000
		}
		if seconds > 1<<63-1 {
			return time.Time{}, credentialError("expired_token")
		}
		return time.Unix(int64(seconds), 0), nil
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999Z07:00", "2006-01-02 15:04:05.999999999", "2006-01-02T15:04:05.999999999"} {
		if t, err := time.Parse(layout, value); err == nil {
			return t, nil
		}
	}
	return time.Time{}, credentialError("expired_token")
}
func validAudience(cloud core.Cloud, audience string) bool {
	arm, metrics, logs := audiences(cloud)
	return audience == arm || audience == metrics || audience == logs
}
func audiences(cloud core.Cloud) (arm, metrics, logs string) {
	m := cloud.Manifest()
	return m.ResourceManager, m.Authentication.Audiences[1], m.DataPlane.LogsTokenResource
}
func validID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, c := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}
func cleanValue(value string) bool {
	return value != "" && strings.TrimSpace(value) == value && strings.IndexFunc(value, unicode.IsControl) == -1
}
func randomID() string {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(data[:])
}
