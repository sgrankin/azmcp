package azure

import (
	"net/http"
	"reflect"
	"sync"
	"testing"

	"azmcp/internal/core"
)

func grantedOptions() core.ContextOptions {
	options := core.DefaultOptions([]core.ResolvedBinding{binding(core.Commercial)})
	options.LocalCapabilities = []string{"artifacts.write"}
	options.DataPlanes = []string{"logs.query"}
	options.LogsScopes[core.Commercial] = "allAccessible"
	return options
}

func TestHostsCaptureIndependentContextOptions(t *testing.T) {
	server := simulator(t, func(http.ResponseWriter, *http.Request) { t.Error("context snapshot opened a socket") })
	client := loopbackClient(t, &fakeCredentials{}, server)
	options := grantedOptions()
	first := hostFor(t, client, options)
	second := hostFor(t, client, options)
	want := grantedOptions()
	options.LocalCapabilities[0] = "changed"
	options.DataPlanes[0] = "changed"
	options.LogsScopes[core.Commercial] = "changed"
	options.BindingSources[core.Commercial] = "changed"
	options.GraphScopes[core.Commercial].Subscriptions[0] = "changed"
	options.ResolvedBindings[0].AllowedSubscriptions[0].Subscription = "changed"
	if !reflect.DeepEqual(first.config.Context, want) || !reflect.DeepEqual(second.config.Context, want) {
		t.Fatal("caller mutation changed a captured authorization snapshot")
	}
	first.config.Context.LocalCapabilities[0] = "host changed"
	first.config.Context.GraphScopes[core.Commercial].Subscriptions[0] = "host changed"
	if !reflect.DeepEqual(second.config.Context, want) || options.LocalCapabilities[0] != "changed" {
		t.Fatal("one host changed another host or the original options")
	}
}

func TestHostsCaptureSharedContextConcurrently(t *testing.T) {
	server := simulator(t, func(http.ResponseWriter, *http.Request) { t.Error("context snapshot opened a socket") })
	credentials := &fakeCredentials{}
	client := loopbackClient(t, credentials, server)
	options := grantedOptions()
	want := string(argsJSON(options))
	var group sync.WaitGroup
	start := make(chan struct{})
	for range 8 {
		group.Go(func() {
			<-start
			for range 32 {
				host, err := NewHost(HostConfig{Context: options, Client: client, CorrelationID: "synthetic-concurrent-snapshot"})
				if err != nil {
					t.Error(err)
					return
				}
				if string(argsJSON(host.config.Context)) != want {
					t.Error("concurrent host captured different authorization options")
				}
			}
		})
	}
	close(start)
	group.Wait()
	if string(argsJSON(options)) != want || credentials.calls() != 0 {
		t.Fatal("host creation mutated shared options or acquired credentials")
	}
}
