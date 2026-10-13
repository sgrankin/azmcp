package server

import (
	"azmcp/internal/artifact"
	"azmcp/internal/azure"
	"azmcp/internal/core"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"time"
)

const maxConcurrentOperations = 8

type ProfileSource func(context.Context) ([]byte, error)
type AppConfig struct {
	Config               core.Config
	Policy               core.Policy
	Schema               core.SchemaIndex
	Profile              ProfileSource
	Client               *azure.Client
	Audit                Audit
	Artifacts            *artifact.Store
	MaxContexts          int
	IdleTTL, AbsoluteTTL time.Duration
}
type Application struct {
	config   AppConfig
	mu       sync.Mutex
	contexts map[string]*contextSlot
	closed   bool
}
type contextSlot struct {
	id                                   string
	options                              core.ContextOptions
	pin                                  *azure.IdentityPin
	namespace                            artifact.Namespace
	active                               int
	opened, idleExpires, absoluteExpires time.Time
	life                                 context.Context
	cancel                               context.CancelFunc
	exports                              map[*artifact.Turn]bool
}

type bindingArgs struct {
	Subscription string `json:"subscription"`
	Tenant       string `json:"tenant"`
}
type scopeArgs struct {
	Subscriptions []string `json:"subscriptions,omitempty"`
	Scope         string   `json:"scope,omitempty"`
}
type openArgs struct {
	Identity             string                     `json:"identity"`
	ArmTier              string                     `json:"armTier"`
	DataPlanes           []string                   `json:"dataPlanes"`
	LocalCapabilities    []string                   `json:"localCapabilities"`
	Bindings             map[core.Cloud]bindingArgs `json:"bindings"`
	AllowedSubscriptions map[core.Cloud][]core.Pair `json:"allowedSubscriptions"`
	GraphScopes          map[core.Cloud]scopeArgs   `json:"graphScopes"`
	LogsScopes           map[core.Cloud]scopeArgs   `json:"logsScopes"`
}
type exportArgs struct {
	ContextID   string          `json:"contextId"`
	Name        string          `json:"name"`
	Compression string          `json:"compression"`
	Operation   string          `json:"operation"`
	Arguments   json.RawMessage `json:"arguments"`
}
type contextArgs struct {
	ContextID string `json:"contextId"`
}
type searchArgs struct {
	ContextID string      `json:"contextId"`
	Query     string      `json:"query"`
	Cloud     *core.Cloud `json:"cloud"`
	Limit     *int        `json:"limit"`
}
type getArgs struct {
	ContextID  string `json:"contextId"`
	EntryID    string `json:"entryId"`
	APIVersion string `json:"apiVersion"`
}

func NewApplication(config AppConfig) (*Application, error) {
	if err := config.Config.Validate(); err != nil {
		return nil, err
	}
	if config.Profile == nil || config.Client == nil || config.Audit == nil || config.Artifacts == nil {
		return nil, failure("invalid_request")
	}
	if config.MaxContexts == 0 {
		config.MaxContexts = 32
	}
	if config.MaxContexts < 1 {
		return nil, failure("invalid_request")
	}
	if config.IdleTTL == 0 {
		config.IdleTTL = 30 * time.Minute
	}
	if config.AbsoluteTTL == 0 {
		config.AbsoluteTTL = 24 * time.Hour
	}
	if config.IdleTTL < 0 || config.AbsoluteTTL < 0 {
		return nil, failure("invalid_request")
	}
	return &Application{config: config, contexts: map[string]*contextSlot{}}, nil
}
func FileProfile(path string) ProfileSource {
	return func(ctx context.Context) ([]byte, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, failure("authentication_required")
		}
		defer file.Close()
		raw, err := io.ReadAll(io.LimitReader(file, 16*1024*1024+1))
		if err != nil || len(raw) > 16*1024*1024 {
			return nil, failure("authentication_required")
		}
		return raw, nil
	}
}
func (a *Application) index(ctx context.Context) (core.AccountIndex, error) {
	raw, err := a.config.Profile(ctx)
	if err != nil {
		return core.AccountIndex{}, failure("authentication_required")
	}
	return core.ParseAzureProfile(raw)
}
func (a *Application) Call(ctx context.Context, name string, raw json.RawMessage) (any, error) {
	switch name {
	case "azure_accounts":
		return a.accounts(ctx)
	case "azure_context_open":
		var args openArgs
		if core.DecodeClosed(raw, &args) != nil {
			return nil, failure("invalid_request")
		}
		return a.open(ctx, args)
	case "azure_context_close":
		var args contextArgs
		if core.DecodeClosed(raw, &args) != nil {
			return nil, failure("invalid_request")
		}
		return map[string]bool{"closed": true}, a.close(args.ContextID)
	case "azure_request", "azure_graph", "azure_metrics_single", "azure_metrics_batch", "azure_logs_query":
		fields, err := closedJSONObject(raw)
		if err != nil {
			return nil, failure("invalid_request")
		}
		var id string
		if json.Unmarshal(fields["contextId"], &id) != nil {
			return nil, failure("invalid_request")
		}
		delete(fields, "contextId")
		arguments, err := marshalJSON(fields)
		if err != nil {
			return nil, failure("invalid_request")
		}
		return a.operate(ctx, id, name, arguments, nil)
	case "azure_export":
		var args exportArgs
		if core.DecodeClosed(raw, &args) != nil || !azureOperation(args.Operation) || len(args.Arguments) == 0 {
			return nil, failure("invalid_request")
		}
		if args.Compression == "" {
			args.Compression = "identity"
		}
		return a.operate(ctx, args.ContextID, args.Operation, args.Arguments, &args)
	case "azure_schema_search":
		var args searchArgs
		if core.DecodeClosed(raw, &args) != nil {
			return nil, failure("invalid_request")
		}
		slot, err := a.lease(args.ContextID)
		if err != nil {
			return nil, err
		}
		defer a.release(slot)
		limit := 20
		if args.Limit != nil {
			limit = *args.Limit
		}
		result, err := a.config.Schema.Search(slot.options, args.Query, args.Cloud, limit)
		if err != nil {
			return nil, err
		}
		a.mu.Lock()
		liveErr := a.liveLocked(slot, ctx)
		a.mu.Unlock()
		if liveErr != nil {
			return nil, liveErr
		}
		return map[string]any{"policyHash": slot.options.PolicyHash, "policyVersion": a.config.Schema.PolicyVersion, "query": args.Query, "results": result.Results, "omitted": result.Omitted}, nil
	case "azure_schema_get":
		var args getArgs
		if core.DecodeClosed(raw, &args) != nil {
			return nil, failure("invalid_request")
		}
		slot, err := a.lease(args.ContextID)
		if err != nil {
			return nil, err
		}
		defer a.release(slot)
		result, err := a.config.Schema.Get(slot.options, args.EntryID, args.APIVersion)
		if err != nil {
			return nil, err
		}
		a.mu.Lock()
		liveErr := a.liveLocked(slot, ctx)
		a.mu.Unlock()
		if liveErr != nil {
			return nil, liveErr
		}
		return map[string]any{"policyHash": slot.options.PolicyHash, "policyVersion": a.config.Schema.PolicyVersion, "schema": result}, nil
	}
	return nil, failure("invalid_request")
}
func (a *Application) accounts(ctx context.Context) (any, error) {
	index, err := a.index(ctx)
	if err != nil {
		return nil, err
	}
	result := []any{}
	for _, candidate := range index.Candidates {
		cloud, err := core.ParseCloud(candidate.Cloud)
		if err != nil {
			return nil, failure("authentication_required")
		}
		if _, err = core.NormalizeID(candidate.Subscription); err != nil {
			return nil, failure("authentication_required")
		}
		if _, err = core.NormalizeID(candidate.Tenant); err != nil {
			return nil, failure("authentication_required")
		}
		result = append(result, map[string]any{"cloud": cloud, "tenantId": candidate.Tenant, "subscriptionId": candidate.Subscription, "name": candidate.Name, "user": candidate.User, "state": candidate.State, "tokenStatus": "unknown"})
	}
	return map[string]any{"accounts": result}, nil
}
func (a *Application) resolve(ctx context.Context, args openArgs) (core.ContextOptions, error) {
	clouds := []core.Cloud{core.Commercial, core.Government}
	explicit, requiresProfile, autoCloud := false, false, false
	for _, cloud := range clouds {
		if override, ok := args.Bindings[cloud]; ok {
			explicit = true
			requiresProfile = requiresProfile || override.Tenant == ""
		} else if binding, ok := a.config.Config.Clouds[cloud]; ok {
			explicit = true
			requiresProfile = requiresProfile || binding.Tenant == ""
		} else {
			autoCloud = true
		}
	}
	var index core.AccountIndex
	if requiresProfile || autoCloud {
		var err error
		index, err = a.index(ctx)
		if err != nil && (!explicit || requiresProfile) {
			return core.ContextOptions{}, err
		}
	}
	bindings := []core.ResolvedBinding{}
	sources := map[core.Cloud]string{}
	for _, cloud := range clouds {
		var binding core.Binding
		source := "auto"
		if override, ok := args.Bindings[cloud]; ok {
			binding = core.Binding{Subscription: override.Subscription, Tenant: override.Tenant}
			source = "contextOverride"
		} else if configured, ok := a.config.Config.Clouds[cloud]; ok {
			binding = configured
			source = "config"
		} else {
			candidates := index.ForCloud(cloud)
			if len(candidates) == 0 {
				continue
			}
			if len(candidates) != 1 {
				return core.ContextOptions{}, failure("account_ambiguous")
			}
			binding = core.Binding{Subscription: candidates[0].Subscription, Tenant: candidates[0].Tenant}
		}
		extra := args.AllowedSubscriptions[cloud]
		binding.AllowedSubscriptions = append(append([]core.Pair{}, binding.AllowedSubscriptions...), extra...)
		resolved, err := binding.Resolve(cloud, index.Candidates)
		if err != nil {
			return core.ContextOptions{}, err
		}
		bindings = append(bindings, resolved)
		sources[cloud] = source
	}
	if len(bindings) == 0 {
		return core.ContextOptions{}, failure("account_ambiguous")
	}
	options := core.DefaultOptions(bindings)
	options.PolicyHash = a.config.Policy.Hash
	options.PolicyVersion = a.config.Policy.Version
	options.BindingSources = sources
	options.DataPlanes = append([]string{}, args.DataPlanes...)
	options.LocalCapabilities = append([]string{}, args.LocalCapabilities...)
	if args.Identity != "" {
		options.Identity = args.Identity
	}
	if args.ArmTier != "" {
		options.ArmTier = args.ArmTier
	}
	for cloud, scope := range args.GraphScopes {
		if _, err := options.Binding(cloud); err != nil {
			return options, failure("invalid_request")
		}
		if scope.Scope == "allAccessible" {
			options.GraphScopes[cloud] = core.GraphScope{AllAccessible: true}
		} else {
			subs := []string{}
			for _, s := range scope.Subscriptions {
				normalized, err := core.NormalizeID(s)
				if err != nil {
					return options, err
				}
				subs = append(subs, normalized)
			}
			options.GraphScopes[cloud] = core.GraphScope{Subscriptions: subs}
		}
	}
	for cloud, scope := range args.LogsScopes {
		if scope.Scope != "allAccessible" {
			return options, failure("invalid_request")
		}
		options.LogsScopes[cloud] = scope.Scope
	}
	for cloud, extra := range args.AllowedSubscriptions {
		if len(extra) > 0 {
			if _, err := options.Binding(cloud); err != nil {
				return options, failure("invalid_request")
			}
		}
	}
	return options, options.Validate()
}
func (a *Application) host(options core.ContextOptions, pin *azure.IdentityPin, correlation string, responseBytes int) (*azure.Host, error) {
	return azure.NewHost(azure.HostConfig{Context: options, Client: a.config.Client, IdentityPin: pin, CorrelationID: correlation, ResponseBytes: responseBytes, PrepareAudit: a.config.Audit.Prepare, Audit: func(record azure.CallRecord) error { return a.config.Audit.Append(record) }})
}
func (a *Application) open(ctx context.Context, args openArgs) (result any, err error) {
	defer func() {
		if ctx.Err() != nil && err != nil {
			err = failure("request_cancelled")
		}
	}()
	options, err := a.resolve(ctx, args)
	if err != nil {
		return nil, err
	}
	pin := azure.NewIdentityPin()
	correlation, err := randomHex(16)
	if err != nil {
		return nil, failure("upstream_error")
	}
	host, err := a.host(options, pin, correlation, 0)
	if err != nil {
		return nil, err
	}
	for _, binding := range options.ResolvedBindings {
		for _, pair := range binding.AllowedSubscriptions {
			effective := core.ResolvedBinding{Cloud: binding.Cloud, Subscription: pair.Subscription, Tenant: pair.Tenant, AllowedSubscriptions: []core.Pair{pair}}
			if err = host.ValidateBinding(ctx, effective); err != nil {
				return nil, err
			}
		}
	}
	if ctx.Err() != nil {
		return nil, failure("request_cancelled")
	}
	var bytes [32]byte
	if _, err = rand.Read(bytes[:]); err != nil {
		return nil, failure("upstream_error")
	}
	id := base64.RawURLEncoding.EncodeToString(bytes[:])
	now := time.Now()
	life, cancel := context.WithCancel(context.Background())
	slot := &contextSlot{id: id, options: options, pin: pin, opened: now, idleExpires: now.Add(a.config.IdleTTL), absoluteExpires: now.Add(a.config.AbsoluteTTL), life: life, cancel: cancel, exports: map[*artifact.Turn]bool{}}
	if core.Contains(options.LocalCapabilities, core.ArtifactsWriteCapability) {
		slot.namespace, err = a.config.Artifacts.AllocateNamespace()
		if err != nil {
			cancel()
			return nil, mapArtifactError(err)
		}
	}
	a.mu.Lock()
	if a.closed || len(a.contexts) >= a.config.MaxContexts {
		a.mu.Unlock()
		cancel()
		return nil, failure("upstream_error")
	}
	if ctx.Err() != nil {
		a.mu.Unlock()
		cancel()
		return nil, failure("request_cancelled")
	}
	a.contexts[id] = slot
	a.mu.Unlock()
	defer func() {
		if err != nil {
			a.dispose(slot)
		}
	}()
	if ctx.Err() != nil {
		return nil, failure("request_cancelled")
	}
	go a.reap(slot)
	result = contextMetadata(slot, true)
	return result, nil
}
func validContextID(id string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(id)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == id
}
func (a *Application) lease(id string) (*contextSlot, error) {
	if !validContextID(id) {
		return nil, failure("invalid_request")
	}
	a.mu.Lock()
	slot := a.contexts[id]
	if slot == nil {
		a.mu.Unlock()
		return nil, failure("context_evicted")
	}
	if slot.active >= maxConcurrentOperations {
		a.mu.Unlock()
		return nil, failure("context_busy")
	}
	now := time.Now()
	if !now.Before(slot.idleExpires) || !now.Before(slot.absoluteExpires) {
		a.mu.Unlock()
		a.dispose(slot)
		return nil, failure("context_evicted")
	}
	slot.active++
	slot.idleExpires = now.Add(a.config.IdleTTL)
	a.mu.Unlock()
	return slot, nil
}
func (a *Application) release(slot *contextSlot) { a.mu.Lock(); slot.active--; a.mu.Unlock() }
func (a *Application) dispose(slot *contextSlot) error {
	a.mu.Lock()
	slot.cancel()
	if a.contexts[slot.id] == slot {
		delete(a.contexts, slot.id)
	}
	turns := make([]*artifact.Turn, 0, len(slot.exports))
	for turn := range slot.exports {
		turns = append(turns, turn)
	}
	a.mu.Unlock()
	var result error
	for _, turn := range turns {
		if err := turn.Rollback(); err != nil {
			result = errors.Join(result, failure("upstream_error"))
		}
	}
	return result
}
func (a *Application) close(id string) error {
	if !validContextID(id) {
		return failure("invalid_request")
	}
	a.mu.Lock()
	slot := a.contexts[id]
	a.mu.Unlock()
	if slot == nil {
		return failure("context_evicted")
	}
	return a.dispose(slot)
}
func (a *Application) Close() error {
	a.mu.Lock()
	a.closed = true
	slots := make([]*contextSlot, 0, len(a.contexts))
	for _, slot := range a.contexts {
		slots = append(slots, slot)
	}
	a.mu.Unlock()
	var result error
	for _, slot := range slots {
		if err := a.dispose(slot); err != nil {
			result = errors.Join(result, err)
		}
	}
	return errors.Join(result, a.config.Artifacts.Close())
}
func (a *Application) reap(slot *contextSlot) {
	for {
		a.mu.Lock()
		expires := slot.idleExpires
		if slot.absoluteExpires.Before(expires) {
			expires = slot.absoluteExpires
		}
		live := a.contexts[slot.id] == slot
		a.mu.Unlock()
		if !live {
			return
		}
		timer := time.NewTimer(time.Until(expires))
		select {
		case <-slot.life.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		a.mu.Lock()
		expired := !time.Now().Before(slot.idleExpires) || !time.Now().Before(slot.absoluteExpires)
		a.mu.Unlock()
		if expired {
			a.dispose(slot)
			return
		}
	}
}
func contextMetadata(slot *contextSlot, includeID bool) map[string]any {
	bindings := []any{}
	allowed := map[core.Cloud][]core.Pair{}
	graph := map[core.Cloud]scopeArgs{}
	logs := map[core.Cloud]scopeArgs{}
	for _, b := range slot.options.ResolvedBindings {
		bindings = append(bindings, map[string]any{"cloud": b.Cloud, "subscription": b.Subscription, "tenant": b.Tenant})
		allowed[b.Cloud] = b.AllowedSubscriptions
	}
	for cloud, scope := range slot.options.GraphScopes {
		if scope.AllAccessible {
			graph[cloud] = scopeArgs{Scope: "allAccessible"}
		} else {
			graph[cloud] = scopeArgs{Subscriptions: scope.Subscriptions}
		}
	}
	for cloud, scope := range slot.options.LogsScopes {
		logs[cloud] = scopeArgs{Scope: scope}
	}
	result := map[string]any{"identity": "user", "armTier": "inspect", "dataPlanes": slot.options.DataPlanes, "localCapabilities": slot.options.LocalCapabilities, "allowedSubscriptions": allowed, "graphScopes": graph, "logsScopes": logs}
	if includeID {
		result["contextId"] = slot.id
		result["maxConcurrentOperations"] = maxConcurrentOperations
		result["resolvedBindings"] = bindings
		result["expiresAt"] = slot.absoluteExpires.UTC().Format(time.RFC3339)
	} else {
		result["bindings"] = bindings
		result["policyHash"] = slot.options.PolicyHash
	}
	return result
}
func mapArtifactError(err error) *Error {
	var public *Error
	if errors.As(err, &public) {
		return public
	}
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return failure("request_cancelled")
	case errors.Is(err, artifact.ErrInvalidName):
		return failure("invalid_request")
	case errors.Is(err, artifact.ErrValueTooLarge):
		return failure("result_too_large")
	case errors.Is(err, artifact.ErrQuota):
		return failure("artifact_capacity")
	case errors.Is(err, artifact.ErrExists):
		return failure("invalid_request")
	default:
		return failure("upstream_error")
	}
}

func azureOperation(name string) bool {
	switch name {
	case "azure_request", "azure_graph", "azure_metrics_single", "azure_metrics_batch", "azure_logs_query":
		return true
	}
	return false
}
func closedJSONObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	if _, err := core.DecodeJSON(raw); err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, failure("invalid_request")
	}
	return fields, nil
}

// The caller holds the registry lock through the final output acceptance point.
func (a *Application) liveLocked(slot *contextSlot, ctx context.Context) error {
	now := time.Now()
	if a.contexts[slot.id] != slot || slot.life.Err() != nil || !now.Before(slot.idleExpires) || !now.Before(slot.absoluteExpires) {
		return failure("context_evicted")
	}
	if ctx.Err() != nil {
		return failure("request_cancelled")
	}
	return nil
}
func (a *Application) operate(ctx context.Context, id, operation string, arguments json.RawMessage, export *exportArgs) (result any, err error) {
	slot, err := a.lease(id)
	if err != nil {
		return nil, err
	}
	defer a.release(slot)
	callCtx, cancel := context.WithDeadline(ctx, slot.absoluteExpires)
	stop := context.AfterFunc(slot.life, cancel)
	defer stop()
	defer cancel()
	if export != nil && !core.Contains(slot.options.LocalCapabilities, core.ArtifactsWriteCapability) {
		return nil, failure("invalid_request")
	}
	correlation, err := randomHex(16)
	if err != nil {
		return nil, failure("upstream_error")
	}
	limit := 0
	if export != nil {
		limit = 8 * 1024 * 1024
	}
	host, err := a.host(slot.options, slot.pin, correlation, limit)
	if err != nil {
		return nil, err
	}
	var turn *artifact.Turn
	if export != nil {
		turn, err = a.config.Artifacts.BeginTurn(callCtx, slot.namespace)
		if err != nil {
			return nil, a.artifactFailure(slot, callCtx, err)
		}
		a.mu.Lock()
		err = a.liveLocked(slot, callCtx)
		if err == nil {
			slot.exports[turn] = true
		}
		a.mu.Unlock()
		defer func() {
			a.mu.Lock()
			delete(slot.exports, turn)
			a.mu.Unlock()
			if result == nil {
				if cleanup := turn.Rollback(); cleanup != nil {
					a.dispose(slot)
					err = failure("upstream_error")
				}
			}
		}()
		if err != nil {
			return nil, err
		}
	}
	value, callErr := host.Call(callCtx, operation, arguments)
	if host.PrincipalMismatch() {
		a.dispose(slot)
		return nil, callErr
	}
	a.mu.Lock()
	err = a.liveLocked(slot, callCtx)
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if callErr != nil {
		return nil, callErr
	}
	records := host.Records()
	response := map[string]any{"calls": records.Calls, "callsOmitted": records.CallsOmitted, "sensitivity": "customerData", "correlationId": correlation}
	if export == nil {
		response["value"] = value
		a.mu.Lock()
		err = a.liveLocked(slot, callCtx)
		a.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return response, nil
	}
	if a.config.Audit.Prepare() != nil {
		return nil, failure("upstream_error")
	}
	receipt, err := turn.PutJSON(export.Name, value, export.Compression)
	if err != nil {
		return nil, a.artifactFailure(slot, callCtx, err)
	}
	record := artifactAuditRecord{correlation, "azure_export", "authorized", receipt.Bytes, receipt.LogicalBytes, receipt.ContentEncoding, receipt.MediaType, "customerData"}
	if a.config.Audit.Append(record) != nil {
		return nil, failure("upstream_error")
	}
	if err = turn.Commit(); err != nil {
		return nil, a.artifactFailure(slot, callCtx, err)
	}
	a.mu.Lock()
	err = a.liveLocked(slot, callCtx)
	if err == nil {
		if finalErr := turn.Finalize(); finalErr != nil {
			err = a.liveLocked(slot, callCtx)
			if err == nil {
				err = mapArtifactError(finalErr)
			}
		}
	}
	if err == nil {
		delete(slot.exports, turn)
	}
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	response["receipt"] = receipt
	return response, nil
}

type artifactAuditRecord struct {
	CorrelationID   string `json:"correlationId"`
	Operation       string `json:"operation"`
	Decision        string `json:"decision"`
	Bytes           int64  `json:"bytes"`
	LogicalBytes    int64  `json:"logicalBytes"`
	ContentEncoding string `json:"contentEncoding,omitempty"`
	MediaType       string `json:"mediaType"`
	Sensitivity     string `json:"sensitivity"`
}

func (a *Application) artifactFailure(slot *contextSlot, ctx context.Context, cause error) *Error {
	a.mu.Lock()
	liveErr := a.liveLocked(slot, ctx)
	a.mu.Unlock()
	if liveErr != nil {
		return publicError(liveErr)
	}
	return mapArtifactError(cause)
}
