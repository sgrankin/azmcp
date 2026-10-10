package server

import (
	"azmcp/internal/azure"
	"azmcp/internal/core"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestClosedConfiguredCredentialsCannotResolveOrStartCLI(t *testing.T) {
	credentials := &configuredCredentials{executable: "must-never-be-resolved", profileDir: canonicalTemp(t)}
	credentials.Close()
	if _, err := credentials.Acquire(context.Background(), azure.TokenRequest{Cloud: core.Commercial, Tenant: testTenant, Subscription: testSubscription, Audience: core.Commercial.Manifest().ResourceManager}); err == nil {
		t.Fatal("closed credentials reopened")
	}
	if credentials.broker != nil {
		t.Fatal("closed credentials instantiated broker")
	}
}
func TestProductionAssemblyAndToolDiscoveryAreInert(t *testing.T) {
	root := canonicalTemp(t)
	home := filepath.Join(root, "home")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	profileDir := filepath.Join(root, "synthetic-azure")
	if err := os.Mkdir(profileDir, 0700); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(profileDir, "azureProfile.json")
	if err := os.WriteFile(profile, []byte(`{"subscriptions":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "cli-was-executed")
	fakeCLI := filepath.Join(root, "fake-az")
	if err := os.WriteFile(fakeCLI, []byte("#!/bin/sh\n: > '"+marker+"'\nexit 99\n"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"HOME": home, "AZMCP_CONFIG": filepath.Join(root, "absent.toml"), "AZURE_CONFIG_DIR": profileDir, "AZMCP_AZURE_PROFILE": profile, "AZMCP_AZ_EXECUTABLE": fakeCLI, "XDG_CONFIG_HOME": filepath.Join(home, "config"), "XDG_DATA_HOME": filepath.Join(home, "data"), "XDG_STATE_HOME": filepath.Join(home, "state"), "AZMCP_AUDIT_LOG": filepath.Join(home, "state", "audit.jsonl")} {
		t.Setenv(name, value)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := Production(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	c := newWire(t, runtime.Application)
	initializeWire(t, c, "2025-06-18")
	c.send(t, request(2, "tools/list", map[string]any{}))
	if c.receive(t)["result"] == nil {
		t.Fatal("catalog discovery failed")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("inert startup/discovery invoked CLI", err)
	}
	for _, path := range []string{filepath.Join(home, "data", "azmcp", "artifacts"), filepath.Join(home, "state", "audit.jsonl")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("inert startup/discovery created runtime storage", path, err)
		}
	}
	if runtime.credentials.broker != nil {
		t.Fatal("inert assembly resolved credentials")
	}
}
