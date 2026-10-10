package server

import (
	"azmcp/internal/artifact"
	"azmcp/internal/azure"
	"azmcp/internal/core"
	"azmcp/internal/worker"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

type ProfileSource func(context.Context) ([]byte, error)
type AppConfig struct {
	Config               core.Config
	Policy               core.Policy
	Schema               core.SchemaIndex
	Profile              ProfileSource
	Client               *azure.Client
	Audit                Audit
	Artifacts            *artifact.Store
	Worker               WorkerFactory
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
	worker                               WorkerHandle
	busy                                 bool
	opened, idleExpires, absoluteExpires time.Time
	life                                 context.Context
	cancel                               context.CancelFunc
	turn                                 *artifact.Turn
	refs                                 refStore
	wake                                 chan struct{}
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
type runArgs struct {
	ContextID string  `json:"contextId"`
	Code      string  `json:"code"`
	TimeoutMS *uint64 `json:"timeoutMs"`
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
	if config.Profile == nil || config.Client == nil || config.Audit == nil || config.Artifacts == nil || config.Worker == nil {
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
		if json.Unmarshal(raw, &args) != nil {
			return nil, failure("invalid_request")
		}
		return a.open(ctx, args)
	case "azure_context_close":
		var args contextArgs
		if json.Unmarshal(raw, &args) != nil {
			return nil, failure("invalid_request")
		}
		return map[string]bool{"closed": true}, a.close(args.ContextID)
	case "azure_run":
		var args runArgs
		if json.Unmarshal(raw, &args) != nil {
			return nil, failure("invalid_request")
		}
		return a.run(ctx, args)
	case "azure_schema_search":
		var args searchArgs
		if json.Unmarshal(raw, &args) != nil {
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
		return map[string]any{"policyHash": slot.options.PolicyHash, "policyVersion": a.config.Schema.PolicyVersion, "query": args.Query, "results": result.Results, "omitted": result.Omitted}, nil
	case "azure_schema_get":
		var args getArgs
		if json.Unmarshal(raw, &args) != nil {
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
func (a *Application) host(options core.ContextOptions, pin *azure.IdentityPin, correlation string) (*azure.Host, error) {
	return azure.NewHost(azure.HostConfig{Context: options, Client: a.config.Client, IdentityPin: pin, CorrelationID: correlation, PrepareAudit: a.config.Audit.Prepare, Audit: func(record azure.CallRecord) error { return a.config.Audit.Append(record) }})
}
func (a *Application) open(ctx context.Context, args openArgs) (result any, err error) {
	options, err := a.resolve(ctx, args)
	if err != nil {
		return nil, err
	}
	pin := azure.NewIdentityPin()
	correlation, err := randomHex(16)
	if err != nil {
		return nil, failure("upstream_error")
	}
	host, err := a.host(options, pin, correlation)
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
		return nil, failure("context_evicted")
	}
	var bytes [32]byte
	if _, err = rand.Read(bytes[:]); err != nil {
		return nil, failure("upstream_error")
	}
	id := base64.RawURLEncoding.EncodeToString(bytes[:])
	now := time.Now()
	life, cancel := context.WithCancel(context.Background())
	slot := &contextSlot{id: id, wake: make(chan struct{}, 1), options: options, pin: pin, opened: now, idleExpires: now.Add(a.config.IdleTTL), absoluteExpires: now.Add(a.config.AbsoluteTTL), life: life, cancel: cancel}
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
	a.contexts[id] = slot
	a.mu.Unlock()
	defer func() {
		if err != nil {
			a.dispose(slot)
		}
	}()
	startup, stop := context.WithCancel(ctx)
	unsubscribe := context.AfterFunc(life, stop)
	handle, err := a.config.Worker(startup)
	unsubscribe()
	stop()
	if err != nil {
		return nil, failure("worker_crashed")
	}
	a.mu.Lock()
	slot.worker = handle
	live := a.contexts[id] == slot && life.Err() == nil && ctx.Err() == nil
	a.mu.Unlock()
	if !live {
		handle.Terminate()
		return nil, failure("context_evicted")
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
	if slot.busy {
		a.mu.Unlock()
		return nil, failure("context_busy")
	}
	now := time.Now()
	if !now.Before(slot.idleExpires) || !now.Before(slot.absoluteExpires) {
		a.mu.Unlock()
		a.dispose(slot)
		return nil, failure("context_evicted")
	}
	slot.busy = true
	slot.idleExpires = now.Add(a.config.IdleTTL)
	a.mu.Unlock()
	return slot, nil
}
func (a *Application) release(slot *contextSlot) { a.mu.Lock(); slot.busy = false; a.mu.Unlock() }
func (a *Application) dispose(slot *contextSlot) error {
	slot.cancel()
	a.mu.Lock()
	if a.contexts[slot.id] == slot {
		delete(a.contexts, slot.id)
	}
	handle, turn := slot.worker, slot.turn
	slot.refs = refStore{}
	a.mu.Unlock()
	var err error
	if handle != nil {
		err = handle.Terminate()
	}
	if turn != nil {
		if cleanup := turn.Rollback(); cleanup != nil {
			return failure("upstream_error")
		}
	}
	if err != nil {
		return failure("worker_crashed")
	}
	return nil
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
		a.mu.Lock()
		for _, entry := range slot.refs.entries {
			if entry.expires.Before(expires) {
				expires = entry.expires
			}
		}
		a.mu.Unlock()
		timer := time.NewTimer(time.Until(expires))
		select {
		case <-slot.life.Done():
			timer.Stop()
			return
		case <-slot.wake:
			timer.Stop()
			continue
		case <-timer.C:
		}
		a.mu.Lock()
		now := time.Now()
		expired := !now.Before(slot.idleExpires) || !now.Before(slot.absoluteExpires)
		slot.refs.sweep(now)
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
		result["resolvedBindings"] = bindings
		result["expiresAt"] = slot.absoluteExpires.UTC().Format(time.RFC3339)
	} else {
		result["bindings"] = bindings
		result["policyHash"] = slot.options.PolicyHash
	}
	return result
}
func mapArtifactError(err error) *Error {
	switch {
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

func (a *Application) run(ctx context.Context, args runArgs) (any, error) {
	timeout := uint64(60000)
	if args.TimeoutMS != nil {
		timeout = *args.TimeoutMS
	}
	if timeout < 1 || timeout > worker.MaxTimeoutMS || len(args.Code) > worker.MaxCodeBytes {
		return nil, failure("invalid_request")
	}
	slot, err := a.lease(args.ContextID)
	if err != nil {
		return nil, err
	}
	defer a.release(slot)
	runCtx, cancel := context.WithCancel(ctx)
	unsubscribe := context.AfterFunc(slot.life, cancel)
	defer unsubscribe()
	defer cancel()
	correlation, err := randomHex(16)
	if err != nil {
		return nil, failure("upstream_error")
	}
	host, err := a.host(slot.options, slot.pin, correlation)
	if err != nil {
		return nil, err
	}
	var turn *artifact.Turn
	if core.Contains(slot.options.LocalCapabilities, core.ArtifactsWriteCapability) {
		turn, err = a.config.Artifacts.BeginTurn(runCtx, slot.namespace)
		if err != nil {
			a.dispose(slot)
			return nil, mapArtifactError(err)
		}
	}
	a.mu.Lock()
	slot.turn = turn
	handle := slot.worker
	live := a.contexts[slot.id] == slot
	a.mu.Unlock()
	if !live || handle == nil {
		if turn != nil {
			turn.Rollback()
		}
		a.dispose(slot)
		return nil, failure("context_evicted")
	}
	var lastArtifact error
	var artifactMu sync.Mutex
	handler := func(callCtx context.Context, request worker.HostCallRequest) (json.RawMessage, error) {
		switch request.Method {
		case "az.ref":
			if callCtx.Err() != nil {
				return nil, failure("context_evicted")
			}
			fields, err := closedJSONObject(request.Arguments)
			if err != nil || len(fields) != 1 {
				return nil, failure("invalid_request")
			}
			var token string
			if json.Unmarshal(fields["refId"], &token) != nil {
				return nil, failure("invalid_request")
			}
			a.mu.Lock()
			if a.contexts[slot.id] != slot || slot.life.Err() != nil || callCtx.Err() != nil {
				a.mu.Unlock()
				return nil, failure("context_evicted")
			}
			value, err := slot.refs.get(token, time.Now())
			a.mu.Unlock()
			if err != nil {
				return nil, failure("invalid_request")
			}
			return value, nil
		case "az.artifacts.writeJson", "az.artifacts.writeJsonArray", "az.artifacts.writeJsonLines":
			value, err := a.artifactCall(callCtx, turn, request, correlation)
			if err != nil {
				artifactMu.Lock()
				lastArtifact = err
				artifactMu.Unlock()
			}
			return value, err
		default:
			return host.Call(callCtx, request.Method, request.Arguments)
		}
	}
	response, err := handle.Execute(runCtx, args.Code, time.Duration(timeout)*time.Millisecond, handler)
	if slot.life.Err() != nil || ctx.Err() != nil {
		err = failure("context_evicted")
		err.(*Error).Fatal = true
	}
	if host.PrincipalMismatch() {
		err = host.LastError()
		a.dispose(slot)
	}
	rollback := func() error {
		if turn == nil {
			return nil
		}
		return turn.Rollback()
	}
	if err != nil {
		cleanup := rollback()
		hostErr := host.LastError()
		artifactMu.Lock()
		artifactErr := lastArtifact
		artifactMu.Unlock()
		e := publicError(err)
		if e.Fatal || cleanup != nil {
			a.dispose(slot)
		}
		a.mu.Lock()
		if slot.turn == turn {
			slot.turn = nil
		}
		a.mu.Unlock()
		if cleanup != nil {
			return nil, failure("upstream_error")
		}
		if e.Code != "context_evicted" && hostErr != nil {
			return nil, hostErr
		}
		if e.Code != "context_evicted" && artifactErr != nil {
			return nil, artifactErr
		}
		return nil, err
	}
	value := response.Value
	if response.Type == "result_ref" {
		a.mu.Lock()
		token, refErr := slot.refs.put(value, time.Now())
		select {
		case slot.wake <- struct{}{}:
		default:
		}
		a.mu.Unlock()
		if refErr != nil {
			rollback()
			a.dispose(slot)
			return nil, failure("result_too_large")
		}
		envelope := shapeSummary(value, len(value), worker.MaxResultBytes)
		envelope["__ref"] = token
		envelope["sensitivity"] = "customerData"
		value, _ = marshalJSON(envelope)
	}
	if turn != nil {
		if err = turn.Commit(); err != nil {
			cleanup := rollback()
			a.dispose(slot)
			if cleanup != nil {
				return nil, failure("upstream_error")
			}
			return nil, mapArtifactError(err)
		}
	}
	a.mu.Lock()
	live = a.contexts[slot.id] == slot && slot.life.Err() == nil && runCtx.Err() == nil
	if live && turn != nil {
		err = turn.Finalize()
	}
	if live && err == nil {
		slot.turn = nil
	}
	a.mu.Unlock()
	if err != nil {
		cleanup := rollback()
		a.dispose(slot)
		if cleanup != nil {
			return nil, failure("upstream_error")
		}
		return nil, mapArtifactError(err)
	}
	if !live {
		rollback()
		a.dispose(slot)
		return nil, failure("context_evicted")
	}
	records := host.Records()
	return map[string]any{"value": value, "console": response.Logs, "consoleOmitted": response.LogsOmitted, "calls": records.Calls, "callsOmitted": records.CallsOmitted, "context": contextMetadata(slot, false), "sensitivity": "customerData", "correlationId": correlation}, nil
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

func (a *Application) artifactCall(ctx context.Context, turn *artifact.Turn, request worker.HostCallRequest, correlation string) (json.RawMessage, error) {
	if turn == nil {
		return nil, failure("capability_denied")
	}
	if ctx.Err() != nil {
		return nil, failure("context_evicted")
	}
	if err := a.config.Audit.Prepare(); err != nil {
		return nil, failure("upstream_error")
	}
	var receipt artifact.Receipt
	fields, err := closedJSONObject(request.Arguments)
	if err != nil {
		return nil, failure("invalid_request")
	}
	if request.Method == "az.artifacts.writeJson" {
		if len(fields) != 2 || fields["name"] == nil || fields["value"] == nil {
			return nil, failure("invalid_request")
		}
		var name string
		if json.Unmarshal(fields["name"], &name) != nil {
			return nil, failure("invalid_request")
		}
		receipt, err = turn.Put(name, fields["value"])
	} else {
		var phase string
		if json.Unmarshal(fields["phase"], &phase) != nil {
			return nil, failure("invalid_request")
		}
		format := "jsonArray"
		if strings.HasSuffix(request.Method, "JsonLines") {
			format = "jsonLines"
		}
		var id string
		switch phase {
		case "begin":
			var args struct{ Phase, Name, Compression string }
			if json.Unmarshal(request.Arguments, &args) != nil {
				return nil, failure("invalid_request")
			}
			if len(fields) != 3 || fields["name"] == nil || fields["compression"] == nil {
				return nil, failure("invalid_request")
			}
			id, err = turn.Begin(args.Name, args.Compression, format)
			if err == nil {
				return marshalJSON(map[string]any{"streamId": id})
			}
		case "append":
			var args struct {
				Phase    string
				StreamID string `json:"streamId"`
				Sequence uint16
				Values   []json.RawMessage
			}
			if json.Unmarshal(request.Arguments, &args) != nil || len(fields) != 4 || fields["streamId"] == nil || fields["sequence"] == nil || string(fields["sequence"]) == "null" || fields["values"] == nil {
				return nil, failure("invalid_request")
			}
			if turn.CheckStreamFormat(args.StreamID, format) != nil {
				return nil, failure("invalid_request")
			}
			err = turn.Append(args.StreamID, args.Sequence, args.Values)
			if err == nil {
				return marshalJSON(map[string]any{"acceptedSequence": args.Sequence})
			}
		case "finish":
			var args struct {
				Phase    string
				StreamID string `json:"streamId"`
				Chunks   uint16
				Items    uint64
			}
			if json.Unmarshal(request.Arguments, &args) != nil || len(fields) != 4 || fields["streamId"] == nil || fields["chunks"] == nil || string(fields["chunks"]) == "null" || fields["items"] == nil || string(fields["items"]) == "null" {
				return nil, failure("invalid_request")
			}
			if turn.CheckStreamFormat(args.StreamID, format) != nil {
				return nil, failure("invalid_request")
			}
			receipt, err = turn.Finish(args.StreamID, args.Chunks, args.Items)
		case "abort":
			if len(fields) != 2 || json.Unmarshal(fields["streamId"], &id) != nil {
				return nil, failure("invalid_request")
			}
			err = turn.Abort(id)
			if err == nil {
				return marshalJSON(map[string]bool{"aborted": true})
			}
		default:
			return nil, failure("invalid_request")
		}
	}
	if err != nil {
		return nil, mapArtifactError(err)
	}
	record := artifactAuditRecord{correlation, request.Method, "authorized", receipt.Bytes, receipt.LogicalBytes, receipt.ContentEncoding, receipt.MediaType, "customerData"}
	if a.config.Audit.Append(record) != nil {
		if cleanup := turn.Discard(receipt); cleanup != nil {
			return nil, &Error{Code: "upstream_error", Message: messages["upstream_error"], Fatal: true}
		}
		return nil, failure("upstream_error")
	}
	encoded, err := marshalJSON(receipt)
	if err != nil {
		if cleanup := turn.Discard(receipt); cleanup != nil {
			return nil, &Error{Code: "upstream_error", Message: messages["upstream_error"], Fatal: true}
		}
		return nil, failure("upstream_error")
	}
	return encoded, nil
}
