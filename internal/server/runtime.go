package server

import (
	"azmcp/internal/artifact"
	"azmcp/internal/azure"
	"azmcp/internal/core"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
)

// configuredCredentials resolves the CLI lazily so schema discovery needs no CLI installation.
type configuredCredentials struct {
	mu                     sync.Mutex
	executable, profileDir string
	broker                 *azure.Broker
	closed                 bool
}

func (c *configuredCredentials) Acquire(ctx context.Context, request azure.TokenRequest) (azure.Credential, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return azure.Credential{}, &azure.CredentialError{Code: "closed", Message: "credential broker is closed"}
	}
	if c.broker == nil {
		executable := c.executable
		if !filepath.IsAbs(executable) {
			var err error
			executable, err = exec.LookPath(executable)
			if err != nil {
				c.mu.Unlock()
				return azure.Credential{}, &azure.CredentialError{Code: "spawn_failed", Message: "Azure CLI could not be started"}
			}
			executable, err = filepath.Abs(executable)
			if err != nil {
				c.mu.Unlock()
				return azure.Credential{}, err
			}
		}
		broker, err := azure.NewBroker(azure.BrokerConfig{Executable: executable, ProfileDir: c.profileDir})
		if err != nil {
			c.mu.Unlock()
			return azure.Credential{}, err
		}
		c.broker = broker
	}
	broker := c.broker
	c.mu.Unlock()
	return broker.Acquire(ctx, request)
}
func (c *configuredCredentials) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if c.broker != nil {
		c.broker.Close()
	}
}

type Runtime struct {
	Application *Application
	audit       *FileAudit
	credentials *configuredCredentials
}

func (r *Runtime) Close() error {
	err := r.Application.Close()
	r.credentials.Close()
	return errors.Join(err, r.audit.Close())
}

func envPath(name, fallback string) (string, error) {
	value, ok := os.LookupEnv(name)
	if !ok {
		return fallback, nil
	}
	if value == "" {
		return "", errors.New(name + " must not be empty")
	}
	return value, nil
}
func envInteger(name string, fallback int64) (int64, error) {
	value, ok := os.LookupEnv(name)
	if !ok {
		return fallback, nil
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n <= 0 {
		return 0, errors.New(name + " must be a positive integer")
	}
	return n, nil
}

// Production parses only azmcp configuration at startup; Azure profiles and credentials stay lazy.
func Production() (*Runtime, error) {
	home, err := envPath("HOME", "")
	if err != nil || home == "" {
		return nil, errors.New("HOME must be set")
	}
	configRoot, err := envPath("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	if err != nil {
		return nil, err
	}
	configPath, err := envPath("AZMCP_CONFIG", filepath.Join(configRoot, "azmcp/config.toml"))
	if err != nil {
		return nil, err
	}
	config := core.Config{}
	if raw, readErr := os.ReadFile(configPath); readErr == nil {
		config, err = core.ParseConfig(string(raw))
		if err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(readErr) {
		return nil, readErr
	}
	if err = config.Validate(); err != nil {
		return nil, err
	}
	profileDir, err := envPath("AZURE_CONFIG_DIR", filepath.Join(home, ".azure"))
	if err != nil {
		return nil, err
	}
	profile, err := envPath("AZMCP_AZURE_PROFILE", filepath.Join(profileDir, "azureProfile.json"))
	if err != nil {
		return nil, err
	}
	cli, err := envPath("AZMCP_AZ_EXECUTABLE", "az")
	if err != nil {
		return nil, err
	}
	dataRoot, err := envPath("XDG_DATA_HOME", filepath.Join(home, ".local/share"))
	if err != nil {
		return nil, err
	}
	artifactRoot := config.Artifacts.Root
	if artifactRoot == "" {
		artifactRoot = filepath.Join(dataRoot, "azmcp/artifacts")
	}
	store, err := artifact.NewStore(artifactRoot, artifact.DefaultLimits())
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Runtime, error) { store.Close(); return nil, err }
	stateRoot, err := envPath("XDG_STATE_HOME", filepath.Join(home, ".local/state"))
	if err != nil {
		return fail(err)
	}
	auditPath, err := envPath("AZMCP_AUDIT_LOG", filepath.Join(stateRoot, "azmcp/requests.jsonl"))
	if err != nil {
		return fail(err)
	}
	auditBytes, err := envInteger("AZMCP_AUDIT_MAX_BYTES", 10*1024*1024)
	if err != nil {
		return fail(err)
	}
	auditRetained, err := envInteger("AZMCP_AUDIT_RETAINED_FILES", 10)
	if err != nil {
		return fail(err)
	}
	audit, err := NewFileAudit(auditPath, auditBytes, int(auditRetained))
	if err != nil {
		return fail(err)
	}
	policy, schema, err := core.LoadReviewed()
	if err != nil {
		return fail(err)
	}
	credentials := &configuredCredentials{executable: cli, profileDir: profileDir}
	client, err := azure.NewClient(credentials, &policy)
	if err != nil {
		return fail(err)
	}
	app, err := NewApplication(AppConfig{Config: config, Policy: policy, Schema: schema, Profile: FileProfile(profile), Client: client, Audit: audit, Artifacts: store})
	if err != nil {
		return fail(err)
	}
	return &Runtime{app, audit, credentials}, nil
}
