package azure

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"azmcp/internal/core"
)

const testSubscription = "11111111-1111-1111-1111-111111111111"
const testTenant = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
const testPrincipal = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
const testClientID = "cccccccc-cccc-cccc-cccc-cccccccccccc"
const testWorkspace = "dddddddd-dddd-dddd-dddd-dddddddddddd"

func tokenResponse(t *testing.T, request TokenRequest, principal string) []byte {
	t.Helper()
	claims, _ := json.Marshal(map[string]any{"aud": request.Audience, "tid": request.Tenant, "oid": principal, "appid": testClientID})
	jwt := "header." + base64.RawURLEncoding.EncodeToString(claims) + ".synthetic-signature"
	response, _ := json.Marshal(map[string]any{"accessToken": jwt, "tenant": request.Tenant, "subscription": request.Subscription, "expires_on": time.Now().Add(time.Hour).Unix(), "tokenType": "Bearer"})
	return response
}
func testTokenRequest(cloud core.Cloud) TokenRequest {
	return TokenRequest{Cloud: cloud, Tenant: testTenant, Subscription: testSubscription, Audience: cloud.Audience("request"), Scope: "synthetic-test-context"}
}
func fakeBroker(t *testing.T, response []byte, extra string) (*Broker, string) {
	t.Helper()
	root := t.TempDir()
	profile := filepath.Join(root, "synthetic-profile")
	executable := filepath.Join(root, "injected-fake-cli")
	if !filepath.IsAbs(root) || filepath.Base(executable) != "injected-fake-cli" {
		t.Fatal("test has not proven its fake process boundary")
	}
	if err := os.Mkdir(profile, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profile, "response.json"), response, 0600); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
expected="$(/usr/bin/dirname "$0")/synthetic-profile"
[ "$AZURE_CONFIG_DIR" = "$expected" ] || exit 98
[ "$HOME" = "$(/usr/bin/dirname "$expected")" ] || exit 97
/usr/bin/printf '%s\n' "$*|$AZURE_CLOUD_NAME|$COPILOT_AGENT_SESSION_ID" >> "$expected/argv"
if [ "$1" = "version" ]; then
  /usr/bin/printf '%s' '{"azure-cli":"2.89.0"}'
  exit 0
fi
` + extra + `
/bin/cat "$expected/response.json"
`
	if err := os.WriteFile(executable, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	broker, err := NewBroker(BrokerConfig{Executable: executable, ProfileDir: profile, CorrelationID: "azmcp-test-synthetic", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(broker.Close)
	return broker, profile
}
func TestBrokerExplicitScopeAndSingleFlight(t *testing.T) {
	request := testTokenRequest(core.Government)
	broker, profile := fakeBroker(t, tokenResponse(t, request, testPrincipal), "")
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := broker.Acquire(context.Background(), request)
			if err == nil && token.Principal != testPrincipal {
				err = fmt.Errorf("wrong principal")
			}
			token.Clear()
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	argv, err := os.ReadFile(filepath.Join(profile, "argv"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(argv)), "\n")
	if len(lines) != 2 {
		t.Fatalf("single-flight ran %d processes: %s", len(lines), argv)
	}
	if !strings.Contains(lines[1], "--subscription "+testSubscription) || !strings.Contains(lines[1], "--resource "+request.Audience) || !strings.Contains(lines[1], "|AzureUSGovernment|azmcp-test-synthetic") {
		t.Fatalf("explicit cloud/audience/subscription lost: %s", argv)
	}
	request.Scope = "new-context"
	credential, err := broker.Acquire(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	credential.Clear()
	argv, _ = os.ReadFile(filepath.Join(profile, "argv"))
	if len(strings.Split(strings.TrimSpace(string(argv)), "\n")) != 3 {
		t.Fatal("new context scope inherited credential cache")
	}
}
func TestCredentialClaimsAndExpiry(t *testing.T) {
	request := testTokenRequest(core.Commercial)
	valid := tokenResponse(t, request, testPrincipal)
	for _, name := range []string{"wrongAudience", "wrongTenant", "wrongSubscription", "expired", "invalidIdentity", "notBearer", "malformedJWT"} {
		t.Run(name, func(t *testing.T) {
			var value map[string]any
			json.Unmarshal(valid, &value)
			switch name {
			case "wrongSubscription":
				value["subscription"] = testWorkspace
			case "expired":
				value["expires_on"] = time.Now().Add(time.Minute).Unix()
			case "notBearer":
				value["tokenType"] = "Basic"
			case "malformedJWT":
				value["accessToken"] = "opaque"
			default:
				claims := map[string]any{"aud": request.Audience, "tid": testTenant, "oid": testPrincipal, "appid": testClientID}
				if name == "wrongAudience" {
					claims["aud"] = core.Government.Audience("request")
				}
				if name == "wrongTenant" {
					claims["tid"] = testWorkspace
				}
				if name == "invalidIdentity" {
					claims["oid"] = "not-an-id"
				}
				payload, _ := json.Marshal(claims)
				value["accessToken"] = "header." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
			}
			raw, _ := json.Marshal(value)
			if credential, err := parseCredential(raw, request); err == nil {
				credential.Clear()
				t.Fatal("accepted invalid credential")
			}
		})
	}
	credential, err := parseCredential(valid, request)
	if err != nil {
		t.Fatal(err)
	}
	secret := string(credential.Token)
	if strings.Contains(fmt.Sprintf("%#v", credential), secret) {
		t.Fatal("credential formatting exposes bearer")
	}
	credential.Clear()
}
func TestIdentityPinExcludesSubscriptionAndSeparatesContext(t *testing.T) {
	pin := NewIdentityPin()
	request := testTokenRequest(core.Commercial)
	credential := Credential{Token: []byte("synthetic"), Principal: testPrincipal, ClientID: testClientID}
	if err := pin.Check(request, credential); err != nil {
		t.Fatal(err)
	}
	request.Subscription = testWorkspace
	credential.Principal = testWorkspace
	if err := pin.Check(request, credential); err == nil {
		t.Fatal("principal switched across subscriptions")
	}
	if err := NewIdentityPin().Check(request, credential); err != nil {
		t.Fatal("new context retained old principal pin")
	}
}
func TestBrokerCancellationAndSanitizedFailure(t *testing.T) {
	request := testTokenRequest(core.Commercial)
	broker, _ := fakeBroker(t, tokenResponse(t, request, testPrincipal), `/usr/bin/printf '%s' 'SECRET aadsts login required' >&2
exit 1`)
	_, err := broker.Acquire(context.Background(), request)
	var failure *CredentialError
	if !errors.As(err, &failure) || failure.Code != "authentication_required" || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("raw diagnostics escaped: %v", err)
	}
	broker, _ = fakeBroker(t, tokenResponse(t, request, testPrincipal), `exec /bin/sleep 3`)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = broker.Acquire(ctx, request)
	if err == nil || time.Since(started) > time.Second {
		t.Fatalf("CLI cancellation failed: %v", err)
	}
}
func TestBrokerRejectsUnprovedInputBeforeProcess(t *testing.T) {
	if _, err := NewBroker(BrokerConfig{Executable: "az", ProfileDir: "profile"}); err == nil {
		t.Fatal("broker accepted ambient executable/profile selection")
	}
	request := testTokenRequest(core.Commercial)
	broker, profile := fakeBroker(t, tokenResponse(t, request, testPrincipal), "")
	request.Audience = "https://attacker.invalid/"
	if _, err := broker.Acquire(context.Background(), request); err == nil {
		t.Fatal("unknown audience accepted")
	}
	if _, err := os.Stat(filepath.Join(profile, "argv")); !os.IsNotExist(err) {
		t.Fatal("invalid request reached subprocess")
	}
}

func TestCredentialJSONRejectsAmbiguousKnownFields(t *testing.T) {
	request := testTokenRequest(core.Commercial)
	valid := tokenResponse(t, request, testPrincipal)
	for _, alias := range []string{"tenant", "TENANT"} {
		t.Run("response_"+alias, func(t *testing.T) {
			raw := strings.Replace(string(valid), `"tenant":"`+testTenant+`"`, `"tenant":"`+testWorkspace+`","`+alias+`":"`+testTenant+`"`, 1)
			credential, err := parseCredential([]byte(raw), request)
			credential.Clear()
			if err == nil {
				t.Fatal("ambiguous CLI tenant reached credential acceptance")
			}
		})
	}
	for _, alias := range []string{"aud", "AUD"} {
		t.Run("claim_"+alias, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal(valid, &value); err != nil {
				t.Fatal(err)
			}
			claims := fmt.Sprintf(`{"aud":"https://outside.invalid/","%s":%q,"tid":%q,"oid":%q,"appid":%q}`, alias, request.Audience, testTenant, testPrincipal, testClientID)
			value["accessToken"] = "header." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".signature"
			raw, _ := json.Marshal(value)
			credential, err := parseCredential(raw, request)
			credential.Clear()
			if err == nil {
				t.Fatal("ambiguous JWT audience reached credential acceptance")
			}
		})
	}
}

func TestBrokerVersionDoesNotAcceptCaseAlias(t *testing.T) {
	request := testTokenRequest(core.Commercial)
	broker, _ := fakeBroker(t, tokenResponse(t, request, testPrincipal), "")
	script, err := os.ReadFile(broker.config.Executable)
	if err != nil {
		t.Fatal(err)
	}
	script = []byte(strings.Replace(string(script), `{"azure-cli":"2.89.0"}`, `{"azure-cli":"2.1.0","AZURE-CLI":"2.89.0"}`, 1))
	if err := os.WriteFile(broker.config.Executable, script, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Probe(context.Background()); err == nil {
		t.Fatal("version alias bypassed the minimum CLI version")
	}
}

func TestBrokerClosePreventsNewProcessesAndCachedCredentials(t *testing.T) {
	request := testTokenRequest(core.Commercial)
	broker, profile := fakeBroker(t, tokenResponse(t, request, testPrincipal), "")
	credential, err := broker.Acquire(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	credential.Clear()
	before, err := os.ReadFile(filepath.Join(profile, "argv"))
	if err != nil {
		t.Fatal(err)
	}
	broker.Close()
	credential, err = broker.Acquire(context.Background(), request)
	credential.Clear()
	if err == nil {
		t.Fatal("closed broker issued a credential")
	}
	if _, err := broker.Probe(context.Background()); err == nil {
		t.Fatal("closed broker reported capabilities")
	}
	after, _ := os.ReadFile(filepath.Join(profile, "argv"))
	if string(before) != string(after) {
		t.Fatal("closed broker spawned a process")
	}
}

func TestBrokerCloseDoesNotRepopulateCacheFromInFlightProcess(t *testing.T) {
	request := testTokenRequest(core.Commercial)
	broker, profile := fakeBroker(t, tokenResponse(t, request, testPrincipal), `/usr/bin/touch "$expected/token-started"
while [ ! -f "$expected/token-continue" ]; do /bin/sleep 0.01; done`)
	result := make(chan error, 1)
	go func() {
		credential, err := broker.Acquire(context.Background(), request)
		credential.Clear()
		result <- err
	}()
	started := filepath.Join(profile, "token-started")
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("injected fake CLI did not reach token barrier")
		}
		time.Sleep(time.Millisecond)
	}
	broker.Close()
	if err := os.WriteFile(filepath.Join(profile, "token-continue"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err == nil {
		t.Fatal("in-flight process issued a credential after broker close")
	}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	if len(broker.cache) != 0 {
		t.Fatal("in-flight process repopulated the closed broker cache")
	}
}

func TestCredentialResponsePreservesIgnoredExtensions(t *testing.T) {
	request := testTokenRequest(core.Commercial)
	valid := tokenResponse(t, request, testPrincipal)
	raw := append(append([]byte{}, valid[:len(valid)-1]...), []byte(`,"newCLIField":{"nested":[1,2]},"TENANT":"ignored"}`)...)
	credential, err := parseCredential(raw, request)
	defer credential.Clear()
	if err != nil || credential.Principal != testPrincipal {
		t.Fatalf("ignored extension changed credential selection: %v", err)
	}
}
