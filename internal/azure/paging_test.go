package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"azmcp/internal/core"
)

func pagingClient(t *testing.T, credentials *fakeCredentials, server *httptest.Server) *Client {
	t.Helper()
	policy := reviewedPolicy(t)
	for i := range policy.Routes {
		route := &policy.Routes[i]
		if route.Purpose == "request" && route.PathTemplate == "/subscriptions/{subscription}" {
			route.AllowedQueryParameters = []string{"$skiptoken"}
		}
	}
	client, err := NewLoopbackClientWithLimits(credentials, policy, server.URL, Limits{1024 * 1024, 8 * 1024 * 1024, time.Second, RetryPolicy{1, time.Second, 0, 0}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}
func TestPagingReauthorizesAndRetainsTransportFacts(t *testing.T) {
	credentials := &fakeCredentials{}
	var server *httptest.Server
	server = simulator(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Ms-Ratelimit-Remaining-Subscription-Reads", "123")
		if r.URL.Query().Get("$skiptoken") == "two" {
			io.WriteString(w, `{"value":[2],"nextLink":null}`)
		} else {
			json.NewEncoder(w).Encode(map[string]any{"value": []int{1}, "nextLink": server.URL + "/subscriptions/" + testSubscription + "?$skiptoken=two&api-version=" + core.SubscriptionsAPIVersion})
		}
	})
	result, err := pagingClient(t, credentials, server).ExecutePaged(context.Background(), subscriptionRequest(t, core.Commercial), DefaultPagingLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) != 2 || string(result.Items[0]) != "1" || string(result.Items[1]) != "2" || len(result.Pages) != 2 || credentials.calls() != 2 || result.Pages[0].RemainingSubscriptionReads == nil || *result.Pages[0].RemainingSubscriptionReads != 123 {
		t.Fatalf("paging result: %#v", result)
	}
	metadata, _ := json.Marshal(result.Pages)
	if strings.Contains(string(metadata), "nextLink") || strings.Contains(string(metadata), "skiptoken") {
		t.Fatal("page metadata retained continuation")
	}
}
func TestPagingContinuationDenialsBeforeSecondCredential(t *testing.T) {
	for _, test := range []struct{ name, tail, code string }{
		{"origin", "https://outside.invalid/subscriptions/" + testSubscription + "?api-version=2020-01-01", "continuation_origin_mismatch"},
		{"route", "/subscriptions/" + testSubscription + "/providers/Microsoft.Compute?api-version=2021-04-01", "continuation_version_mismatch"},
		{"cycle", "/subscriptions/" + testSubscription + "?api-version=2020-01-01", "continuation_cycle"},
		{"version", "/subscriptions/" + testSubscription + "?api-version=wrong", "continuation_version_mismatch"},
		{"duplicateVersion", "/subscriptions/" + testSubscription + "?api-version=2020-01-01&API-VERSION=2020-01-01", "invalid_continuation"},
		{"encodedTraversal", "/subscriptions/" + testSubscription + "/%252e%252e?api-version=2020-01-01", "invalid_continuation"},
	} {
		t.Run(test.name, func(t *testing.T) {
			credentials := &fakeCredentials{}
			var server *httptest.Server
			server = simulator(t, func(w http.ResponseWriter, r *http.Request) {
				next := test.tail
				if strings.HasPrefix(next, "/") {
					next = server.URL + next
				}
				json.NewEncoder(w).Encode(map[string]any{"value": []int{1}, "nextLink": next})
			})
			_, err := pagingClient(t, credentials, server).ExecutePaged(context.Background(), subscriptionRequest(t, core.Commercial), DefaultPagingLimits())
			var failure *PagingError
			if !errors.As(err, &failure) || failure.Code != test.code {
				t.Fatalf("got %v want %s", err, test.code)
			}
			if credentials.calls() != 1 {
				t.Fatal("continuation denial reached credentials")
			}
		})
	}
}
func TestPagingLimitsCoverInitialExchangeAndContinuation(t *testing.T) {
	credentials := &fakeCredentials{}
	var count atomic.Int32
	var server *httptest.Server
	server = simulator(t, func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		if r.URL.Query().Get("$skiptoken") != "" {
			io.WriteString(w, `{"value":[2,3]}`)
		} else {
			json.NewEncoder(w).Encode(map[string]any{"value": []int{1}, "nextLink": server.URL + "/subscriptions/" + testSubscription + "?$skiptoken=two&api-version=2020-01-01"})
		}
	})
	client := pagingClient(t, credentials, server)
	for _, limits := range []PagingLimits{{1, 100, 1024, time.Second}, {10, 2, 1024, time.Second}, {10, 100, 1, time.Second}} {
		_, err := client.ExecutePaged(context.Background(), subscriptionRequest(t, core.Commercial), limits)
		if err == nil {
			t.Fatalf("accepted exhausted paging cap %#v", limits)
		}
	}
	before := credentials.calls()
	_, err := client.ExecutePaged(context.Background(), subscriptionRequest(t, core.Commercial), PagingLimits{0, 1, 1, time.Second})
	if err == nil || credentials.calls() != before {
		t.Fatal("invalid limits reached credentials")
	}
	slow := simulator(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		fmt.Fprint(w, `{"value":[]}`)
	})
	_, err = pagingClient(t, &fakeCredentials{}, slow).ExecutePaged(context.Background(), subscriptionRequest(t, core.Commercial), PagingLimits{1, 1, 1024, 10 * time.Millisecond})
	var failure *PagingError
	if !errors.As(err, &failure) || failure.Code != "elapsed_limit_exceeded" {
		t.Fatalf("initial exchange escaped elapsed cap: %v", err)
	}
}

func TestPagingRejectsConstructedTargetBeforeCredentials(t *testing.T) {
	credentials := &fakeCredentials{}
	server := simulator(t, func(w http.ResponseWriter, r *http.Request) { t.Error("invalid target reached socket") })
	client := pagingClient(t, credentials, server)
	request := subscriptionRequest(t, core.Commercial)
	request.Target.Path = "//outside.invalid/subscriptions/" + testSubscription
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Errorf("invalid public target panicked: %v", recovered)
		}
	}()
	if _, err := client.ExecutePaged(context.Background(), request, DefaultPagingLimits()); err == nil {
		t.Fatal("constructed invalid target accepted")
	}
	if credentials.calls() != 0 {
		t.Fatal("invalid target reached credentials")
	}
}
