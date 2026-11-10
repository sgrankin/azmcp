package server

import (
	"context"
	"testing"

	"azmcp/internal/core"
)

func TestExplicitBindingsExcludeSignedOutCloud(t *testing.T) {
	for _, selected := range []core.Cloud{core.Commercial, core.Government} {
		for _, source := range []string{"profile", "config"} {
			t.Run(string(selected)+"/"+source, func(t *testing.T) {
				other := core.Government
				if selected == other {
					other = core.Commercial
				}
				app, _, credentials, count := newSyntheticApp(t, nil)
				credentials.signedOut = other
				rows := []any{}
				for _, cloud := range []core.Cloud{selected, other} {
					rows = append(rows, map[string]any{
						"id": testSubscription, "tenantId": testTenant, "environmentName": cloud,
						"name": "synthetic", "state": "Enabled",
						"user": map[string]string{"name": "synthetic@example.invalid", "type": "user"},
					})
				}
				profile := mustJSON(t, map[string]any{"subscriptions": rows})
				app.config.Profile = func(context.Context) ([]byte, error) { return profile, nil }
				if source == "config" {
					app.config.Config.Clouds[other] = core.Binding{Subscription: testSubscription, Tenant: testTenant}
				}
				bindings := map[core.Cloud]map[string]string{selected: {"subscription": testSubscription}}
				args := map[string]any{
					"bindings": bindings, "dataPlanes": []string{"logs.query"},
					"logsScopes": map[core.Cloud]scopeArgs{selected: {Scope: "allAccessible"}},
				}
				opened, err := callSynthetic(t, app, "azure_context_open", args)
				if err != nil {
					t.Fatalf("selected cloud required the signed-out peer: %v", err)
				}
				resolved := opened["resolvedBindings"].([]any)
				if len(resolved) != 1 || resolved[0].(map[string]any)["cloud"] != selected {
					t.Fatal("context included an unrequested cloud", resolved)
				}
				id := opened["contextId"].(string)
				_, err = callSynthetic(t, app, "azure_logs_query", map[string]any{
					"contextId": id, "cloud": selected, "workspaceId": testWorkspace,
					"query": "print Count=7", "timespan": "PT1H",
				})
				if err != nil {
					t.Fatal("selected cloud Logs query failed", err)
				}
				before := count.Load()
				request := requestArgs(id)
				request["cloud"] = other
				_, err = callSynthetic(t, app, "azure_request", request)
				assertCode(t, err, "invalid_request")
				if count.Load() != before {
					t.Fatal("unbound cloud reached HTTP")
				}
				credentials.mu.Lock()
				requests := make([]core.Cloud, 0, len(credentials.requests))
				for _, request := range credentials.requests {
					requests = append(requests, request.Cloud)
				}
				credentials.mu.Unlock()
				for _, cloud := range requests {
					if cloud != selected {
						t.Fatal("unrequested cloud acquired credentials", cloud)
					}
				}
				// An explicitly requested cloud must still pass binding validation.
				bindings[other] = map[string]string{"subscription": testSubscription, "tenant": testTenant}
				_, err = callSynthetic(t, app, "azure_context_open", args)
				assertCode(t, err, "authentication_required")
			})
		}
	}
}

func TestExplicitBindingWithTenantDoesNotReadPeerProfile(t *testing.T) {
	app, _, credentials, _ := newSyntheticApp(t, nil)
	credentials.signedOut = core.Government
	app.config.Config.Clouds[core.Government] = core.Binding{Subscription: testOtherSubscription}
	app.config.Profile = func(context.Context) ([]byte, error) {
		t.Error("explicit commercial binding read the profile for Government tenant resolution")
		return nil, failure("authentication_required")
	}
	openSynthetic(t, app, nil)
}

func TestExplicitBindingsRejectGrantsForUnselectedCloud(t *testing.T) {
	for field, grant := range map[string]any{
		"allowedSubscriptions": []core.Pair{{Subscription: testOtherSubscription, Tenant: testTenant}},
		"graphScopes":          map[string]any{"scope": "allAccessible"},
		"logsScopes":           map[string]any{"scope": "allAccessible"},
	} {
		t.Run(field, func(t *testing.T) {
			app, _, credentials, count := newSyntheticApp(t, nil)
			app.config.Config.Clouds[core.Government] = core.Binding{Subscription: testSubscription, Tenant: testTenant}
			_, err := callSynthetic(t, app, "azure_context_open", map[string]any{
				"bindings":   map[core.Cloud]bindingArgs{core.Commercial: {Subscription: testSubscription, Tenant: testTenant}},
				"dataPlanes": []string{"logs.query"},
				field:        map[core.Cloud]any{core.Government: grant},
			})
			assertCode(t, err, "invalid_request")
			if len(credentials.requests) != 0 || count.Load() != 0 {
				t.Fatal("unselected-cloud grant reached credentials or HTTP")
			}
		})
	}
}

func TestContextOpenWithoutExplicitBindingsKeepsDiscovery(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(map[bool]string{false: "omitted", true: "empty"}[empty], func(t *testing.T) {
			app, _, _, _ := newSyntheticApp(t, nil)
			for _, cloud := range []core.Cloud{core.Commercial, core.Government} {
				app.config.Config.Clouds[cloud] = core.Binding{Subscription: testSubscription, Tenant: testTenant}
			}
			app.config.Profile = func(context.Context) ([]byte, error) {
				t.Error("fully configured bindings read the profile")
				return nil, failure("authentication_required")
			}
			args := map[string]any{}
			if empty {
				args["bindings"] = map[string]any{}
			}
			opened, err := callSynthetic(t, app, "azure_context_open", args)
			if err != nil {
				t.Fatal(err)
			}
			if len(opened["resolvedBindings"].([]any)) != 2 {
				t.Fatal("default discovery lost a configured cloud", opened)
			}
		})
	}
}
