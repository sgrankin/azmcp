package core

import "strings"

type Pair struct {
	Subscription string `json:"subscription" toml:"subscription"`
	Tenant       string `json:"tenant" toml:"tenant"`
}
type Binding struct {
	Subscription         string `json:"subscription" toml:"subscription"`
	Tenant               string `json:"tenant,omitempty" toml:"tenant"`
	AllowedSubscriptions []Pair `json:"allowed_subscriptions,omitempty" toml:"allowed_subscriptions"`
}
type ResolvedBinding struct {
	Cloud                Cloud  `json:"cloud"`
	Subscription         string `json:"subscription"`
	Tenant               string `json:"tenant"`
	AllowedSubscriptions []Pair `json:"allowedSubscriptions"`
}
type GraphScope struct {
	AllAccessible bool     `json:"allAccessible"`
	Subscriptions []string `json:"subscriptions"`
}
type ContextOptions struct {
	Identity          string               `json:"identity"`
	ArmTier           string               `json:"armTier"`
	DataPlanes        []string             `json:"dataPlanes"`
	LocalCapabilities []string             `json:"localCapabilities"`
	ResolvedBindings  []ResolvedBinding    `json:"resolvedBindings"`
	BindingSources    map[Cloud]string     `json:"bindingSources"`
	GraphScopes       map[Cloud]GraphScope `json:"graphScopes"`
	LogsScopes        map[Cloud]string     `json:"logsScopes"`
	PolicyHash        string               `json:"policyHash"`
	PolicyVersion     string               `json:"policyVersion"`
}

func (b *Binding) Validate() error {
	var err error
	if b.Subscription, err = NormalizeID(b.Subscription); err != nil {
		return err
	}
	if b.Tenant != "" {
		if b.Tenant, err = NormalizeID(b.Tenant); err != nil {
			return err
		}
	}
	seen := map[string]string{b.Subscription: b.Tenant}
	for i := range b.AllowedSubscriptions {
		pair := &b.AllowedSubscriptions[i]
		if pair.Subscription, err = NormalizeID(pair.Subscription); err != nil {
			return err
		}
		if pair.Tenant, err = NormalizeID(pair.Tenant); err != nil {
			return err
		}
		if _, exists := seen[pair.Subscription]; exists {
			return Fail("invalid_request", "subscription appears more than once in allowlist")
		}
		seen[pair.Subscription] = pair.Tenant
	}
	return nil
}
func (b Binding) Resolve(cloud Cloud, candidates []Account) (ResolvedBinding, error) {
	if err := b.Validate(); err != nil {
		return ResolvedBinding{}, err
	}
	tenant := b.Tenant
	if tenant == "" {
		var matching []Account
		for _, candidate := range candidates {
			if candidate.Cloud == string(cloud) && EqualFoldASCII(candidate.Subscription, b.Subscription) {
				matching = append(matching, candidate)
			}
		}
		if len(matching) == 0 {
			return ResolvedBinding{}, Fail("account_ambiguous", "no tenant candidate for configured subscription")
		}
		if len(matching) != 1 {
			return ResolvedBinding{}, Fail("account_ambiguous", "multiple tenant candidates for configured subscription")
		}
		var err error
		tenant, err = NormalizeID(matching[0].Tenant)
		if err != nil {
			return ResolvedBinding{}, err
		}
	}
	pairs := []Pair{{b.Subscription, tenant}}
	pairs = append(pairs, b.AllowedSubscriptions...)
	return ResolvedBinding{cloud, b.Subscription, tenant, pairs}, nil
}
func DefaultOptions(bindings []ResolvedBinding) ContextOptions {
	options := ContextOptions{Identity: "user", ArmTier: "inspect", DataPlanes: []string{}, LocalCapabilities: []string{}, ResolvedBindings: bindings, BindingSources: map[Cloud]string{}, GraphScopes: map[Cloud]GraphScope{}, LogsScopes: map[Cloud]string{}, PolicyHash: PolicyHash, PolicyVersion: PolicyVersion}
	for _, binding := range bindings {
		options.BindingSources[binding.Cloud] = "contextOverride"
		options.GraphScopes[binding.Cloud] = GraphScope{Subscriptions: []string{binding.Subscription}}
	}
	return options
}
func (options ContextOptions) Validate() error {
	if options.Identity != "user" {
		return Fail("invalid_request", "context identity must be user")
	}
	if options.ArmTier != "inspect" {
		return Fail("invalid_request", "context ARM tier must be inspect")
	}
	for _, list := range []struct {
		values  []string
		allowed string
		code    string
	}{{options.DataPlanes, "logs.query", "invalid_request"}, {options.LocalCapabilities, ArtifactsWriteCapability, "invalid_request"}} {
		seen := map[string]bool{}
		for _, value := range list.values {
			if value != list.allowed || seen[value] {
				return Fail(list.code, "context grants are unsupported or duplicated")
			}
			seen[value] = true
		}
	}
	if options.PolicyHash == "" || options.PolicyVersion == "" {
		return Fail("invalid_request", "context policy identity is required")
	}
	if len(options.ResolvedBindings) == 0 {
		return Fail("invalid_request", "context requires at least one cloud binding")
	}
	clouds := map[Cloud]bool{}
	for _, binding := range options.ResolvedBindings {
		if _, err := ParseCloud(string(binding.Cloud)); err != nil {
			return err
		}
		if clouds[binding.Cloud] {
			return Fail("invalid_request", "duplicate cloud binding")
		}
		clouds[binding.Cloud] = true
		if !validID(binding.Subscription) || !validID(binding.Tenant) {
			return Fail("invalid_request", "resolved binding contains invalid UUID")
		}
		seen := map[string]bool{}
		primary := false
		for _, pair := range binding.AllowedSubscriptions {
			if !validID(pair.Subscription) || !validID(pair.Tenant) || seen[strings.ToLower(pair.Subscription)] {
				return Fail("invalid_request", "resolved allowlist is invalid or ambiguous")
			}
			seen[strings.ToLower(pair.Subscription)] = true
			if EqualFoldASCII(pair.Subscription, binding.Subscription) && EqualFoldASCII(pair.Tenant, binding.Tenant) {
				primary = true
			}
		}
		if !primary {
			return Fail("invalid_request", "resolved allowlist is missing primary binding")
		}
		source, ok := options.BindingSources[binding.Cloud]
		if !ok || (source != "config" && source != "contextOverride" && source != "auto") {
			return Fail("invalid_request", "binding provenance does not match bound clouds")
		}
		scope, ok := options.GraphScopes[binding.Cloud]
		if !ok {
			return Fail("invalid_request", "graph scopes must match bound clouds")
		}
		if scope.AllAccessible {
			if len(scope.Subscriptions) != 0 {
				return Fail("invalid_request", "graph scope cannot mix allAccessible and subscriptions")
			}
		} else {
			if len(scope.Subscriptions) == 0 {
				return Fail("invalid_request", "graph subscription scope must not be empty")
			}
			seen = map[string]bool{}
			for _, sub := range scope.Subscriptions {
				normalized, err := NormalizeID(sub)
				if err != nil {
					return err
				}
				if seen[normalized] {
					return Fail("invalid_request", "graph subscriptions must be unique")
				}
				seen[normalized] = true
				if _, err := options.AllowsSubscription(binding.Cloud, normalized); err != nil {
					return err
				}
			}
		}
	}
	if len(options.GraphScopes) != len(clouds) || len(options.BindingSources) != len(clouds) {
		return Fail("invalid_request", "scope and source keys must match bound clouds")
	}
	for cloud, scope := range options.LogsScopes {
		if !clouds[cloud] || scope != "allAccessible" || !Contains(options.DataPlanes, "logs.query") {
			return Fail("invalid_request", "logs scope requires bound cloud and logs.query grant")
		}
	}
	return nil
}
func (options ContextOptions) Binding(cloud Cloud) (ResolvedBinding, error) {
	for _, binding := range options.ResolvedBindings {
		if binding.Cloud == cloud {
			return binding, nil
		}
	}
	return ResolvedBinding{}, Fail("cloud_not_bound", "cloud is not bound by this context")
}
func (options ContextOptions) AllowsSubscription(cloud Cloud, subscription string) (Pair, error) {
	binding, err := options.Binding(cloud)
	if err != nil {
		return Pair{}, err
	}
	for _, pair := range binding.AllowedSubscriptions {
		if EqualFoldASCII(pair.Subscription, subscription) {
			return pair, nil
		}
	}
	return Pair{}, Fail("subscription_mismatch", "subscription is not in context allowlist")
}
func Contains(values []string, value string) bool {
	for _, known := range values {
		if known == value {
			return true
		}
	}
	return false
}
