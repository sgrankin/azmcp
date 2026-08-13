//! Stateful application orchestration for the v0 tools.
//!
//! This module deliberately stops at dependency boundaries.  Profile bytes,
//! binding validation, and JavaScript workers are injected; no Azure CLI path,
//! credential, or network client is selected here.

use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Weak},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use azmcp_core::{
    accounts::{AccountIndex, SubscriptionCandidate, parse_azure_profile_bytes},
    cloud::AzureCloud,
    config::{
        BindingResolutionError, CloudBinding, Config, ResolvedCloudBinding, SubscriptionId,
        SubscriptionTenantPair, TenantId,
    },
    context::{
        ArmTier, BindingSource, Context, ContextOptions, ContextRegistry, ContextRegistryError,
        GraphScope, Identity, RegistryConfig,
    },
    credential::{CredentialError, CredentialIdentityPin},
    http::{HttpError, HttpRequest},
    policy::{HttpMethod, RoutePurpose},
    routes::SUBSCRIPTIONS_API_VERSION,
    target::RelativeRequestTarget,
};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::{Mutex, watch};

use crate::{
    audit::AuditSink,
    host::{CallDecision, CallRecord, CallRecords, HostAdapter, HttpClientFactory},
    tools::{
        AccountsArgs, ContextCloseArgs, ContextOpenArgs, GraphScopeArgs, GraphSubscriptionsArgs,
        RunArgs,
    },
    worker::{ExecutionResult, HostCallHandler, ResultTooLargeSummary, WorkerProcess},
};

/// A boxed, sendable future used instead of an async-trait dependency.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Dependency failures are intentionally opaque at the application boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DependencyError {
    Failed,
    AuditFailed,
    ExecutionFailed,
    ExecutionTimeout,
    ResultTooLarge {
        summary: Box<ResultTooLargeSummary>,
    },
    WorkerCrashed,
    AuthenticationRequired {
        cloud_name: String,
        tenant_id: String,
    },
    PrincipalMismatch,
}

/// Profile bytes are supplied by the embedding application.
pub trait ProfileSource: Send + Sync {
    fn load<'a>(&'a self) -> BoxFuture<'a, Result<Vec<u8>, DependencyError>>;
}

/// Validate one fully resolved binding before a context is retained.
pub trait BindingValidator: Send + Sync {
    fn validate<'a>(
        &'a self,
        binding: &'a ResolvedCloudBinding,
        identity_pin: &'a CredentialIdentityPin,
    ) -> BoxFuture<'a, Result<(), DependencyError>>;
}

/// Live subscription validation through the same reviewed HTTP boundary used
/// by JavaScript host calls. Every normalized allowlist pair is checked.
pub struct HttpBindingValidator {
    clients: Arc<dyn HttpClientFactory>,
    audit_sink: Option<Arc<dyn AuditSink>>,
    policy_hash: String,
    policy_version: String,
}

impl HttpBindingValidator {
    pub fn new(clients: Arc<dyn HttpClientFactory>) -> Self {
        Self {
            clients,
            audit_sink: None,
            policy_hash: DEFAULT_POLICY_HASH.to_owned(),
            policy_version: DEFAULT_POLICY_VERSION.to_owned(),
        }
    }

    /// Require durable records for the server-owned validation requests.
    pub fn with_audit_sink(
        mut self,
        audit_sink: Arc<dyn AuditSink>,
        policy_hash: impl Into<String>,
        policy_version: impl Into<String>,
    ) -> Self {
        self.audit_sink = Some(audit_sink);
        self.policy_hash = policy_hash.into();
        self.policy_version = policy_version.into();
        self
    }
}

impl BindingValidator for HttpBindingValidator {
    fn validate<'a>(
        &'a self,
        binding: &'a ResolvedCloudBinding,
        identity_pin: &'a CredentialIdentityPin,
    ) -> BoxFuture<'a, Result<(), DependencyError>> {
        Box::pin(async move {
            for pair in binding.allowed_subscriptions() {
                if let Some(sink) = &self.audit_sink {
                    sink.prepare().map_err(|_| DependencyError::AuditFailed)?;
                }
                let correlation_id = correlation_id().map_err(|_| DependencyError::Failed)?;
                let started = Instant::now();
                let response = async {
                    let effective =
                        CloudBinding::new(pair.subscription().clone(), Some(pair.tenant().clone()))
                            .resolve(binding.cloud(), &[])
                            .map_err(|_| DependencyError::Failed)?;
                    let client = self
                        .clients
                        .client_for(&effective)
                        .map_err(|_| DependencyError::Failed)?;
                    let target = RelativeRequestTarget::parse(&format!(
                        "/subscriptions/{}",
                        pair.subscription_id()
                    ))
                    .map_err(|_| DependencyError::Failed)?;
                    let request = HttpRequest::for_purpose(
                        RoutePurpose::Internal,
                        HttpMethod::Get,
                        target,
                        SUBSCRIPTIONS_API_VERSION,
                    )
                    .map_err(|_| DependencyError::Failed)?;
                    client
                        .execute_with_identity_pin(request, Some(identity_pin))
                        .await
                        .map_err(map_http_dependency_error)
                }
                .await;
                let mut validation = Err(DependencyError::Failed);
                let (status, remaining_reads, decision, reason) = match &response {
                    Ok(response) => {
                        let value = serde_json::from_slice::<Value>(response.body());
                        if (200..300).contains(&response.status())
                            && value.as_ref().ok().and_then(|value| {
                                value.get("subscriptionId").and_then(Value::as_str)
                            }) == Some(pair.subscription_id())
                        {
                            validation = Ok(());
                        }
                        (
                            Some(response.status()),
                            response
                                .headers()
                                .get("x-ms-ratelimit-remaining-subscription-reads")
                                .and_then(|value| value.parse().ok()),
                            CallDecision::Allowed,
                            validation
                                .as_ref()
                                .err()
                                .map(|_| "validation_failed".to_owned()),
                        )
                    }
                    Err(_) => (
                        None,
                        None,
                        CallDecision::Denied,
                        Some("request_failed".to_owned()),
                    ),
                };
                let record = CallRecord {
                    correlation_id,
                    operation: "context.validate".to_owned(),
                    cloud: binding.cloud(),
                    subscription: Some(pair.subscription_id().to_owned()),
                    subscription_source: None,
                    tenant: Some(pair.tenant_id().to_owned()),
                    identity: "user".to_owned(),
                    arm_tier: "inspect".to_owned(),
                    method: "GET".to_owned(),
                    path_template: "/subscriptions/{subscription}".to_owned(),
                    api_version: SUBSCRIPTIONS_API_VERSION.to_owned(),
                    api_version_source: "reviewedRoute".to_owned(),
                    policy_hash: self.policy_hash.clone(),
                    policy_version: self.policy_version.clone(),
                    rbac_action: Some("Microsoft.Resources/subscriptions/read".to_owned()),
                    decision,
                    reason,
                    status,
                    duration_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
                    retry_count: 0,
                    remaining_subscription_reads: remaining_reads,
                    graph_scope: None,
                };
                if let Some(sink) = &self.audit_sink {
                    sink.append(&record)
                        .map_err(|_| DependencyError::AuditFailed)?;
                }
                response?;
                validation?;
            }
            Ok(())
        })
    }
}

/// Create one isolated worker for a retained context.
pub trait WorkerFactory: Send + Sync {
    fn start<'a>(
        &'a self,
        context: &'a Context,
    ) -> BoxFuture<'a, Result<Box<dyn WorkerHandle>, DependencyError>>;
}

/// The per-context worker lifecycle used by the application.
pub trait WorkerHandle: Send {
    fn execute<'a>(
        &'a mut self,
        code: &'a str,
        timeout: Duration,
        host_handler: Option<HostCallHandler>,
    ) -> BoxFuture<'a, Result<ExecutionResult, DependencyError>>;

    fn close<'a>(&'a mut self) -> BoxFuture<'a, Result<(), DependencyError>>;

    /// Hard-terminate a worker whose current turn was cancelled.
    ///
    /// Implementations backed by a process should kill that process without
    /// waiting for a protocol acknowledgement. The default keeps custom
    /// embedding implementations source-compatible and falls back to their
    /// graceful close path.
    fn terminate<'a>(&'a mut self) -> BoxFuture<'a, Result<(), DependencyError>> {
        self.close()
    }
}

/// Stable machine-readable application failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppErrorCode {
    InvalidInput,
    InvalidConfiguration,
    ProfileUnavailable,
    ProfileInvalid,
    NoBinding,
    BindingInvalid,
    BindingMissingTenant,
    BindingAmbiguous,
    BindingValidationFailed,
    RegistryCapacity,
    ContextInvalid,
    ContextNotFound,
    ContextEvicted,
    ContextBusy,
    WorkerStartFailed,
    WorkerMissing,
    WorkerExecuteFailed,
    WorkerCloseFailed,
    CorrelationUnavailable,
    RouteDenied,
    CapabilityDenied,
    AuthenticationRequired,
    SubscriptionMismatch,
    UpstreamError,
    ResultTooLarge,
    ExecutionTimeout,
    ExecutionFailed,
}

impl AppErrorCode {
    /// The stable wire spelling for this failure category.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput | Self::InvalidConfiguration | Self::BindingInvalid => {
                "invalid_request"
            }
            Self::ProfileUnavailable | Self::ProfileInvalid => "authentication_required",
            Self::NoBinding | Self::BindingMissingTenant | Self::BindingAmbiguous => {
                "account_ambiguous"
            }
            Self::BindingValidationFailed => "subscription_mismatch",
            Self::RegistryCapacity => "upstream_error",
            Self::ContextInvalid => "invalid_request",
            Self::ContextNotFound => "context_evicted",
            Self::ContextEvicted => "context_evicted",
            Self::ContextBusy => "context_busy",
            Self::WorkerStartFailed
            | Self::WorkerMissing
            | Self::WorkerExecuteFailed
            | Self::WorkerCloseFailed => "worker_crashed",
            Self::CorrelationUnavailable => "upstream_error",
            Self::RouteDenied => "route_denied",
            Self::CapabilityDenied => "capability_denied",
            Self::AuthenticationRequired => "authentication_required",
            Self::SubscriptionMismatch => "subscription_mismatch",
            Self::UpstreamError => "upstream_error",
            Self::ResultTooLarge => "result_too_large",
            Self::ExecutionTimeout => "execution_timeout",
            Self::ExecutionFailed => "invalid_request",
        }
    }
}

/// An application error with no dependency, handle, token, or source-code payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppError {
    code: AppErrorCode,
    result_too_large: Option<Box<ResultTooLargeSummary>>,
    authentication_message: Option<String>,
}

impl AppError {
    const fn new(code: AppErrorCode) -> Self {
        Self {
            code,
            result_too_large: None,
            authentication_message: None,
        }
    }

    fn result_too_large(summary: Box<ResultTooLargeSummary>) -> Self {
        Self {
            code: AppErrorCode::ResultTooLarge,
            result_too_large: Some(summary),
            authentication_message: None,
        }
    }

    fn authentication_required(cloud_name: String, tenant_id: String) -> Self {
        Self {
            code: AppErrorCode::AuthenticationRequired,
            result_too_large: None,
            authentication_message: Some(format!(
                "Azure CLI authentication is required; run AZURE_CLOUD_NAME={cloud_name} az login --tenant {tenant_id}"
            )),
        }
    }

    fn authentication_required_message(message: String) -> Self {
        Self {
            code: AppErrorCode::AuthenticationRequired,
            result_too_large: None,
            authentication_message: Some(message),
        }
    }

    /// Return the stable machine-readable error code.
    pub const fn code(&self) -> &'static str {
        self.code.as_str()
    }

    /// Return the typed failure category.
    pub const fn kind(&self) -> AppErrorCode {
        self.code
    }

    /// Return the shape-only result summary, when the result exceeded a
    /// serialization boundary.
    pub fn result_too_large_summary(&self) -> Option<&ResultTooLargeSummary> {
        self.result_too_large.as_deref()
    }

    pub(crate) fn authentication_message(&self) -> Option<&str> {
        self.authentication_message.as_deref()
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for AppError {}

/// The account-discovery result.  `token_status` is always `unknown` here:
/// profile enumeration never acquires credentials.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountsResult {
    pub accounts: Vec<AccountResult>,
}

/// One cached subscription candidate exposed by account discovery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountResult {
    pub cloud: AzureCloud,
    pub tenant_id: String,
    pub subscription_id: String,
    pub name: String,
    pub user: String,
    pub state: String,
    pub token_status: &'static str,
}

/// The retained context returned by `context_open`.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextOpenResult {
    pub context_id: String,
    pub identity: &'static str,
    pub arm_tier: &'static str,
    pub data_planes: Vec<Value>,
    pub resolved_bindings: Vec<ResolvedBindingResult>,
    pub allowed_subscriptions: BTreeMap<AzureCloud, Vec<AllowedSubscriptionResult>>,
    pub graph_scopes: BTreeMap<AzureCloud, GraphScopeArgs>,
    pub expires_at: String,
}

impl ContextOpenResult {
    /// Return immutable context metadata without the bearer handle.
    pub fn context_summary(&self, policy_hash: &str) -> Value {
        serde_json::json!({
            "identity": self.identity,
            "armTier": self.arm_tier,
            "dataPlanes": self.data_planes,
            "bindings": self.resolved_bindings,
            "allowedSubscriptions": self.allowed_subscriptions,
            "graphScopes": self.graph_scopes,
            "policyHash": policy_hash,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedBindingResult {
    pub cloud: AzureCloud,
    pub subscription: String,
    pub tenant: String,
}

impl ResolvedBindingResult {
    pub fn subscription_id(&self) -> &str {
        &self.subscription
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowedSubscriptionResult {
    pub subscription: String,
    pub tenant: String,
}

/// The close acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ContextCloseResult {
    pub closed: bool,
}

/// The bounded result returned by one isolated JavaScript turn.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunResult {
    pub value: Value,
    pub console: Vec<String>,
    pub console_omitted: usize,
    pub calls: Vec<Value>,
    pub calls_omitted: usize,
    pub context: Value,
    pub sensitivity: &'static str,
    pub correlation_id: String,
}

/// A small in-memory profile source useful for tests and embedding callers that
/// already own a synthetic profile.  It never reads a filesystem path.
#[derive(Clone, Debug)]
pub struct MemoryProfileSource {
    bytes: Arc<Vec<u8>>,
}

impl MemoryProfileSource {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: Arc::new(bytes.into()),
        }
    }
}

impl ProfileSource for MemoryProfileSource {
    fn load<'a>(&'a self) -> BoxFuture<'a, Result<Vec<u8>, DependencyError>> {
        Box::pin(async move { Ok((*self.bytes).clone()) })
    }
}

/// Lazy, explicit filesystem profile source for the production embedding.
/// Construction does not inspect Azure CLI state.
#[derive(Clone, Debug)]
pub struct FileProfileSource {
    path: PathBuf,
}

impl FileProfileSource {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl ProfileSource for FileProfileSource {
    fn load<'a>(&'a self) -> BoxFuture<'a, Result<Vec<u8>, DependencyError>> {
        Box::pin(async move {
            tokio::fs::read(&self.path)
                .await
                .map_err(|_| DependencyError::Failed)
        })
    }
}

/// An explicit executable-path worker factory.  There is no default path and
/// constructing this value does not spawn a process.
#[derive(Clone, Debug)]
pub struct ProcessWorkerFactory {
    executable: PathBuf,
}

impl ProcessWorkerFactory {
    pub fn new(executable: impl Into<PathBuf>) -> Self {
        Self {
            executable: executable.into(),
        }
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }
}

impl WorkerFactory for ProcessWorkerFactory {
    fn start<'a>(
        &'a self,
        _context: &'a Context,
    ) -> BoxFuture<'a, Result<Box<dyn WorkerHandle>, DependencyError>> {
        Box::pin(async move {
            WorkerProcess::start(&self.executable)
                .await
                .map(|worker| Box::new(ProcessWorkerHandle { worker }) as Box<dyn WorkerHandle>)
                .map_err(|_| DependencyError::Failed)
        })
    }
}

struct ProcessWorkerHandle {
    worker: WorkerProcess,
}

impl WorkerHandle for ProcessWorkerHandle {
    fn execute<'a>(
        &'a mut self,
        code: &'a str,
        timeout: Duration,
        host_handler: Option<HostCallHandler>,
    ) -> BoxFuture<'a, Result<ExecutionResult, DependencyError>> {
        Box::pin(async move {
            let result = match host_handler {
                Some(handler) => {
                    self.worker
                        .execute_with_host_handler(code, timeout, handler)
                        .await
                }
                None => self.worker.execute(code, timeout).await,
            };
            result.map_err(|error| match error {
                crate::worker::WorkerError::Execution { .. } => DependencyError::ExecutionFailed,
                crate::worker::WorkerError::Timeout { .. } => DependencyError::ExecutionTimeout,
                crate::worker::WorkerError::ResultTooLarge { summary } => {
                    DependencyError::ResultTooLarge { summary }
                }
                _ => DependencyError::WorkerCrashed,
            })
        })
    }

    fn close<'a>(&'a mut self) -> BoxFuture<'a, Result<(), DependencyError>> {
        Box::pin(async move {
            self.worker
                .close()
                .await
                .map_err(|_| DependencyError::Failed)
        })
    }

    fn terminate<'a>(&'a mut self) -> BoxFuture<'a, Result<(), DependencyError>> {
        Box::pin(async move {
            self.worker.terminate().await;
            Ok(())
        })
    }
}

/// Defaults for the v0 policy metadata.  The policy implementation remains an
/// application concern; these non-empty values satisfy the immutable core record.
pub const DEFAULT_POLICY_HASH: &str = "v0-bootstrap-1";
pub const DEFAULT_POLICY_VERSION: &str = "v0-bootstrap-1";

struct ApplicationInner {
    config: Config,
    policy_hash: String,
    policy_version: String,
    registry: ContextRegistry,
    profile_source: Arc<dyn ProfileSource>,
    binding_validator: Arc<dyn BindingValidator>,
    worker_factory: Arc<dyn WorkerFactory>,
    host_client_factory: Option<Arc<dyn HttpClientFactory>>,
    workers: Mutex<HashMap<String, Arc<WorkerSlot>>>,
}

/// The lifecycle state for one retained context worker.
///
/// The cancellation channel is deliberately outside the worker mutex. A
/// close request can therefore invalidate authority and wake an in-flight run
/// without waiting for that run's worker turn to finish.
struct WorkerSlot {
    worker: Mutex<Box<dyn WorkerHandle>>,
    cancellation: watch::Sender<bool>,
    identity_pin: CredentialIdentityPin,
}

/// Cancellation guard for the gap between registry insertion and worker
/// retention. Dropping a cancelled context-open future closes the authority.
struct ContextOpenRollback {
    registry: ContextRegistry,
    id: String,
    armed: bool,
}

impl ContextOpenRollback {
    fn new(registry: ContextRegistry, id: String) -> Self {
        Self {
            registry,
            id,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ContextOpenRollback {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.registry.close(&self.id);
        }
    }
}

/// Evict and poison a context if its run future is dropped mid-turn.
///
/// The guard cannot await from `Drop`, so it signals cancellation immediately
/// and schedules the hard worker termination after the worker mutex becomes
/// available. The slot is retained by the guard, which closes the race with a
/// concurrent manual close removing it from the application map.
struct RunAbortGuard {
    registry: ContextRegistry,
    inner: Weak<ApplicationInner>,
    id: String,
    slot: Option<Arc<WorkerSlot>>,
    armed: bool,
}

impl RunAbortGuard {
    fn new(registry: ContextRegistry, inner: Weak<ApplicationInner>, id: String) -> Self {
        Self {
            registry,
            inner,
            id,
            slot: None,
            armed: true,
        }
    }

    fn set_slot(&mut self, slot: Arc<WorkerSlot>) {
        self.slot = Some(slot);
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RunAbortGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = self.registry.close(&self.id);
        let id = self.id.clone();
        let inner = self.inner.clone();
        let slot = self.slot.clone();
        let cleanup = async move {
            let Some(inner) = inner.upgrade() else {
                return;
            };
            let slot = if let Some(slot) = slot {
                let mut workers = inner.workers.lock().await;
                if workers
                    .get(&id)
                    .is_some_and(|current| Arc::ptr_eq(current, &slot))
                {
                    workers.remove(&id);
                }
                slot
            } else {
                let Some(slot) = inner.workers.lock().await.remove(&id) else {
                    return;
                };
                slot
            };
            slot.cancel();
            let mut handle = slot.worker.lock().await;
            let _ = handle.terminate().await;
        };
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(cleanup);
        }
    }
}

impl WorkerSlot {
    fn new(worker: Box<dyn WorkerHandle>, identity_pin: CredentialIdentityPin) -> Self {
        let (cancellation, _) = watch::channel(false);
        Self {
            worker: Mutex::new(worker),
            cancellation,
            identity_pin,
        }
    }

    fn cancel(&self) {
        self.cancellation.send_replace(true);
    }

    fn subscribe(&self) -> watch::Receiver<bool> {
        self.cancellation.subscribe()
    }
}

/// Stateful orchestration for the four v0 application tools.
#[derive(Clone)]
pub struct Application {
    inner: Arc<ApplicationInner>,
    audit_sink: Option<Arc<dyn AuditSink>>,
}

impl Application {
    /// Construct an application with the default v0 policy metadata.
    pub fn new<P, V, F>(
        config: Config,
        registry: ContextRegistry,
        profile_source: P,
        binding_validator: V,
        worker_factory: F,
    ) -> Result<Self, AppError>
    where
        P: ProfileSource + 'static,
        V: BindingValidator + 'static,
        F: WorkerFactory + 'static,
    {
        Self::with_policy(
            config,
            registry,
            profile_source,
            binding_validator,
            worker_factory,
            DEFAULT_POLICY_HASH,
            DEFAULT_POLICY_VERSION,
        )
    }

    /// Construct an application with explicit immutable policy metadata.
    pub fn with_policy<P, V, F>(
        config: Config,
        registry: ContextRegistry,
        profile_source: P,
        binding_validator: V,
        worker_factory: F,
        policy_hash: impl Into<String>,
        policy_version: impl Into<String>,
    ) -> Result<Self, AppError>
    where
        P: ProfileSource + 'static,
        V: BindingValidator + 'static,
        F: WorkerFactory + 'static,
    {
        Self::from_arcs(
            config,
            registry,
            Arc::new(profile_source),
            Arc::new(binding_validator),
            Arc::new(worker_factory),
            policy_hash.into(),
            policy_version.into(),
        )
    }

    /// Arc-based constructor for applications that already have shared dependencies.
    pub fn from_arcs(
        config: Config,
        registry: ContextRegistry,
        profile_source: Arc<dyn ProfileSource>,
        binding_validator: Arc<dyn BindingValidator>,
        worker_factory: Arc<dyn WorkerFactory>,
        policy_hash: impl Into<String>,
        policy_version: impl Into<String>,
    ) -> Result<Self, AppError> {
        Self::from_parts(
            config,
            registry,
            profile_source,
            binding_validator,
            worker_factory,
            None,
            policy_hash.into(),
            policy_version.into(),
        )
    }

    /// Construct a fully executable application with semantic Azure host calls.
    #[allow(clippy::too_many_arguments)]
    pub fn from_arcs_with_host_clients(
        config: Config,
        registry: ContextRegistry,
        profile_source: Arc<dyn ProfileSource>,
        binding_validator: Arc<dyn BindingValidator>,
        worker_factory: Arc<dyn WorkerFactory>,
        host_client_factory: Arc<dyn HttpClientFactory>,
        policy_hash: impl Into<String>,
        policy_version: impl Into<String>,
    ) -> Result<Self, AppError> {
        Self::from_parts(
            config,
            registry,
            profile_source,
            binding_validator,
            worker_factory,
            Some(host_client_factory),
            policy_hash.into(),
            policy_version.into(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        config: Config,
        registry: ContextRegistry,
        profile_source: Arc<dyn ProfileSource>,
        binding_validator: Arc<dyn BindingValidator>,
        worker_factory: Arc<dyn WorkerFactory>,
        host_client_factory: Option<Arc<dyn HttpClientFactory>>,
        policy_hash: String,
        policy_version: String,
    ) -> Result<Self, AppError> {
        config
            .validate()
            .map_err(|_| AppError::new(AppErrorCode::InvalidConfiguration))?;
        if policy_hash.is_empty() || policy_version.is_empty() {
            return Err(AppError::new(AppErrorCode::InvalidConfiguration));
        }
        Ok(Self {
            inner: Arc::new(ApplicationInner {
                config,
                policy_hash,
                policy_version,
                registry,
                profile_source,
                binding_validator,
                worker_factory,
                host_client_factory,
                workers: Mutex::new(HashMap::new()),
            }),
            audit_sink: None,
        })
    }

    /// Attach the durable, redacted request log required by the MCP server.
    pub fn with_audit_sink(mut self, audit_sink: Arc<dyn AuditSink>) -> Self {
        self.audit_sink = Some(audit_sink);
        self
    }

    /// Clone the underlying registry for diagnostics or deterministic tests.
    pub fn registry(&self) -> ContextRegistry {
        self.inner.registry.clone()
    }

    /// Whether `az.request` and `az.graph` have a real semantic host boundary.
    pub fn host_calls_ready(&self) -> bool {
        self.inner.host_client_factory.is_some()
    }

    /// Whether the application can durably record executable host calls.
    pub fn audit_ready(&self) -> bool {
        self.audit_sink.is_some()
    }

    /// Enumerate cached profile records without acquiring a token.
    pub async fn accounts(&self, _args: AccountsArgs) -> Result<AccountsResult, AppError> {
        let bytes = self
            .inner
            .profile_source
            .load()
            .await
            .map_err(|_| AppError::new(AppErrorCode::ProfileUnavailable))?;
        let index = parse_azure_profile_bytes(&bytes)
            .map_err(|_| AppError::new(AppErrorCode::ProfileInvalid))?;
        let accounts = index
            .candidates()
            .map(account_result)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(AccountsResult { accounts })
    }

    /// Open a persistent context and its one worker.
    pub async fn context_open(&self, args: ContextOpenArgs) -> Result<ContextOpenResult, AppError> {
        args.validate()
            .map_err(|_| AppError::new(AppErrorCode::InvalidInput))?;
        self.reap_expired_workers(Instant::now()).await;
        // Start the identity lifetime before any live binding validation.
        // The same handle is retained by the worker slot below.
        let identity_pin = CredentialIdentityPin::new();
        let (bindings, binding_sources) = self.resolve_bindings(&args).await?;
        let graph_scopes = resolve_graph_scopes(&args, &bindings)?;
        let options = ContextOptions::new(
            Identity::User,
            ArmTier::Inspect,
            Vec::new(),
            bindings.clone(),
            self.inner.policy_hash.clone(),
            self.inner.policy_version.clone(),
        )
        .and_then(|options| options.with_binding_sources(binding_sources))
        .and_then(|options| options.with_graph_scopes(graph_scopes))
        .map_err(|_| AppError::new(AppErrorCode::InvalidInput))?;

        let mut validation_error = None;
        for binding in &bindings {
            match self
                .inner
                .binding_validator
                .validate(binding, &identity_pin)
                .await
            {
                Ok(()) => {}
                Err(DependencyError::AuditFailed) => {
                    return Err(AppError::new(AppErrorCode::UpstreamError));
                }
                Err(DependencyError::AuthenticationRequired {
                    cloud_name,
                    tenant_id,
                }) => return Err(AppError::authentication_required(cloud_name, tenant_id)),
                Err(DependencyError::PrincipalMismatch) => {
                    return Err(AppError::authentication_required_message(format!(
                        "Azure authentication identity changed while validating context bindings; run AZURE_CLOUD_NAME={} az login --tenant {} and retry context creation",
                        binding.cloud(),
                        binding.tenant_id(),
                    )));
                }
                Err(_) if validation_error.is_none() => {
                    validation_error = Some(AppErrorCode::BindingValidationFailed);
                }
                Err(_) => {}
            }
        }
        if let Some(code) = validation_error {
            return Err(AppError::new(code));
        }

        let context = self
            .inner
            .registry
            .open(options, Instant::now())
            .map_err(map_registry_error)?;
        let id = context.id().as_str().to_owned();
        let mut rollback = ContextOpenRollback::new(self.inner.registry.clone(), id.clone());
        let worker = match self.inner.worker_factory.start(&context).await {
            Ok(worker) => worker,
            Err(_) => {
                let _ = self.inner.registry.close(&id);
                return Err(AppError::new(AppErrorCode::WorkerStartFailed));
            }
        };
        let slot = Arc::new(WorkerSlot::new(worker, identity_pin));
        self.inner
            .workers
            .lock()
            .await
            .insert(id.clone(), Arc::clone(&slot));
        self.spawn_worker_reaper(id.clone(), Arc::clone(&slot));
        rollback.disarm();

        Ok(ContextOpenResult {
            context_id: id,
            identity: "user",
            arm_tier: "inspect",
            data_planes: Vec::new(),
            resolved_bindings: resolved_binding_results(&context),
            allowed_subscriptions: allowed_subscription_results(&context),
            graph_scopes: graph_scope_results(&context),
            expires_at: format_expiry(context.expires_at()),
        })
    }

    /// Remove a context and close its worker, even if a run is in flight.
    pub async fn context_close(
        &self,
        args: ContextCloseArgs,
    ) -> Result<ContextCloseResult, AppError> {
        let id = parse_context_id(&args.context_id)?;
        let close_result = self.inner.registry.close(id.as_str());
        match close_result {
            Ok(()) => {
                self.close_worker(&id).await?;
                Ok(ContextCloseResult { closed: true })
            }
            Err(ContextRegistryError::ContextEvicted) => {
                let _ = self.close_worker(&id).await;
                Err(AppError::new(AppErrorCode::ContextEvicted))
            }
            Err(error) => Err(map_registry_error(error)),
        }
    }

    /// Execute one bounded turn while holding the registry's exclusive lease.
    pub async fn run(&self, args: RunArgs) -> Result<RunResult, AppError> {
        let timeout_ms = args
            .timeout_ms()
            .map_err(|_| AppError::new(AppErrorCode::InvalidInput))?;
        let id = parse_context_id(&args.context_id)?;
        let lease = match self.inner.registry.lease(id.as_str(), Instant::now()) {
            Ok(lease) => lease,
            Err(ContextRegistryError::ContextEvicted) => {
                let _ = self.close_worker(&id).await;
                return Err(AppError::new(AppErrorCode::ContextEvicted));
            }
            Err(error) => return Err(map_registry_error(error)),
        };
        let mut abort_guard = RunAbortGuard::new(
            self.inner.registry.clone(),
            Arc::downgrade(&self.inner),
            id.clone(),
        );
        let worker = self
            .inner
            .workers
            .lock()
            .await
            .get(id.as_str())
            .cloned()
            .ok_or_else(|| AppError::new(AppErrorCode::WorkerMissing));
        let worker = match worker {
            Ok(worker) => worker,
            Err(error) => {
                abort_guard.disarm();
                return Err(error);
            }
        };
        abort_guard.set_slot(Arc::clone(&worker));
        let mut cancellation = worker.subscribe();
        let identity_pin = worker.identity_pin.clone();
        let correlation_id = match correlation_id() {
            Ok(correlation_id) => correlation_id,
            Err(error) => {
                abort_guard.disarm();
                return Err(error);
            }
        };
        let adapter = self.inner.host_client_factory.as_ref().map(|factory| {
            let mut adapter = HostAdapter::with_identity_pin(
                lease.context(),
                Arc::clone(factory),
                correlation_id.clone(),
                identity_pin,
            );
            if let Some(audit_sink) = &self.audit_sink {
                adapter = adapter.with_audit_sink(Arc::clone(audit_sink));
            }
            Arc::new(adapter)
        });
        let host_handler = adapter.as_ref().map(|adapter| {
            let adapter = Arc::clone(adapter);
            Arc::new(move |request| {
                let adapter = Arc::clone(&adapter);
                Box::pin(async move { adapter.handle(request).await })
                    as crate::worker::HostCallFuture
            }) as HostCallHandler
        });
        let result = {
            let mut handle = worker.worker.lock().await;
            if *cancellation.borrow() {
                let _ = handle.terminate().await;
                Err(DependencyError::WorkerCrashed)
            } else {
                let mut execution = Box::pin(handle.execute(
                    &args.code,
                    Duration::from_millis(timeout_ms),
                    host_handler,
                ));
                let mut cancelled = false;
                let result = tokio::select! {
                    result = &mut execution => result,
                    _ = cancellation.changed() => {
                        cancelled = true;
                        Err(DependencyError::WorkerCrashed)
                    }
                };
                drop(execution);
                if cancelled || *cancellation.borrow() {
                    let _ = handle.terminate().await;
                    Err(DependencyError::WorkerCrashed)
                } else {
                    result
                }
            }
        };
        if adapter
            .as_ref()
            .is_some_and(|adapter| adapter.principal_mismatch())
        {
            let error = adapter
                .as_ref()
                .and_then(|adapter| adapter.take_last_error())
                .map(map_host_error)
                .unwrap_or_else(|| {
                    AppError::authentication_required_message(
                        "Azure authentication identity changed during the context lifetime; authenticate the intended Azure CLI identity and open a new context".to_owned(),
                    )
                });
            let _ = self.inner.registry.close(id.as_str());
            let _ = self.close_worker(id.as_str()).await;
            abort_guard.disarm();
            return Err(error);
        }
        let result = match result {
            Ok(result) => {
                let context = context_summary(lease.context());
                let records = match adapter {
                    Some(adapter) => adapter.take_records(),
                    None => CallRecords {
                        calls: Vec::new(),
                        calls_omitted: 0,
                    },
                };
                drop(lease);
                run_result(result, records, context, correlation_id)
            }
            Err(error) => {
                let host_error = match &adapter {
                    Some(adapter) => adapter.take_last_error(),
                    None => None,
                };
                let worker_needs_eviction = matches!(
                    error,
                    DependencyError::ExecutionTimeout | DependencyError::WorkerCrashed
                );
                let app_error = host_error
                    .map(map_host_error)
                    .unwrap_or_else(|| map_worker_dependency(error));
                if worker_needs_eviction {
                    let _ = self.inner.registry.close(id.as_str());
                    let _ = self.close_worker(id.as_str()).await;
                } else {
                    drop(lease);
                }
                Err(app_error)
            }
        };
        abort_guard.disarm();
        result
    }

    fn spawn_worker_reaper(&self, id: String, slot: Arc<WorkerSlot>) {
        let registry = self.inner.registry.clone();
        let inner = Arc::downgrade(&self.inner);
        let mut cancellation = slot.subscribe();
        tokio::spawn(async move {
            loop {
                let expiration = match registry.expiration(&id) {
                    Ok(expiration) => expiration,
                    Err(_) => {
                        // Another registry operation may have performed the
                        // logical eviction. Worker disposal remains this
                        // application's responsibility.
                        if let Some(inner) = inner.upgrade() {
                            let _ = close_worker_inner(&inner, &id).await;
                        }
                        return;
                    }
                };
                let delay = expiration.saturating_duration_since(Instant::now());
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    changed = cancellation.changed() => {
                        if changed.is_err() || *cancellation.borrow() {
                            return;
                        }
                    }
                }

                let now = Instant::now();
                let current_expiration = match registry.expiration(&id) {
                    Ok(expiration) => expiration,
                    Err(_) => {
                        if let Some(inner) = inner.upgrade() {
                            let _ = close_worker_inner(&inner, &id).await;
                        }
                        return;
                    }
                };
                if current_expiration > now {
                    continue;
                }
                if registry.close(&id).is_err() {
                    return;
                }
                if let Some(inner) = inner.upgrade() {
                    let _ = close_worker_inner(&inner, &id).await;
                }
                return;
            }
        });
    }

    async fn load_index(&self) -> Result<AccountIndex, AppError> {
        let bytes = self
            .inner
            .profile_source
            .load()
            .await
            .map_err(|_| AppError::new(AppErrorCode::ProfileUnavailable))?;
        parse_azure_profile_bytes(&bytes).map_err(|_| AppError::new(AppErrorCode::ProfileInvalid))
    }

    async fn resolve_bindings(
        &self,
        args: &ContextOpenArgs,
    ) -> Result<
        (
            Vec<ResolvedCloudBinding>,
            BTreeMap<AzureCloud, BindingSource>,
        ),
        AppError,
    > {
        // Caller overrides are per cloud.  A missing caller key falls back to
        // that cloud's immutable configuration, then to one profile candidate.
        let has_explicit_binding = [AzureCloud::AzureCloud, AzureCloud::AzureUSGovernment]
            .iter()
            .any(|cloud| {
                args.bindings
                    .iter()
                    .any(|(candidate, _)| candidate == *cloud)
                    || self.inner.config.binding(*cloud).is_some()
            });
        let requires_profile = [AzureCloud::AzureCloud, AzureCloud::AzureUSGovernment]
            .iter()
            .any(|cloud| {
                match args
                    .bindings
                    .iter()
                    .find(|(candidate, _)| candidate == cloud)
                {
                    Some((_, binding)) => binding.tenant.is_none(),
                    None => self
                        .inner
                        .config
                        .binding(*cloud)
                        .is_some_and(|binding| binding.tenant().is_none()),
                }
            });
        let has_auto_cloud = [AzureCloud::AzureCloud, AzureCloud::AzureUSGovernment]
            .iter()
            .any(|cloud| {
                !args
                    .bindings
                    .iter()
                    .any(|(candidate, _)| candidate == *cloud)
                    && self.inner.config.binding(*cloud).is_none()
            });
        let index = if requires_profile || has_auto_cloud {
            match self.load_index().await {
                Ok(index) => Some(index),
                Err(_) if has_explicit_binding && !requires_profile => None,
                Err(error) => return Err(error),
            }
        } else {
            None
        };
        let candidates = index
            .as_ref()
            .map(|index| index.candidates().cloned().collect::<Vec<_>>())
            .unwrap_or_default();

        let mut bindings = Vec::new();
        let mut binding_sources = BTreeMap::new();
        let mut ambiguous_auto = false;
        for cloud in [AzureCloud::AzureCloud, AzureCloud::AzureUSGovernment] {
            let source = if args
                .bindings
                .iter()
                .any(|(candidate, _)| candidate == cloud)
            {
                BindingSource::ContextOverride
            } else if self.inner.config.binding(cloud).is_some() {
                BindingSource::Config
            } else {
                BindingSource::Auto
            };
            let binding = if let Some(binding) = args
                .bindings
                .iter()
                .find(|(candidate, _)| *candidate == cloud)
            {
                Some(resolve_caller_binding(cloud, binding.1, &candidates)?)
            } else if let Some(binding) = self.inner.config.binding(cloud) {
                Some(
                    binding
                        .resolve(cloud, &candidates)
                        .map_err(map_binding_resolution)?,
                )
            } else if let Some(index) = &index {
                match index.candidates_for(cloud.as_str()).as_slice() {
                    [candidate] => Some(auto_binding(cloud, candidate)?),
                    [] => None,
                    _ => {
                        ambiguous_auto = true;
                        None
                    }
                }
            } else {
                None
            };
            if let Some(binding) = binding {
                binding_sources.insert(cloud, source);
                bindings.push(merge_allowed_subscriptions(
                    binding,
                    args.allowed_subscriptions.get(cloud),
                )?);
            }
        }
        if ambiguous_auto {
            return Err(AppError::new(AppErrorCode::BindingAmbiguous));
        }
        if bindings.is_empty() {
            return Err(AppError::new(AppErrorCode::NoBinding));
        }
        Ok((bindings, binding_sources))
    }

    async fn close_worker(&self, id: &str) -> Result<(), AppError> {
        close_worker_inner(&self.inner, id).await
    }

    async fn reap_expired_workers(&self, now: Instant) {
        for id in self.inner.registry.evict_expired_ids(now) {
            let _ = self.close_worker(id.as_str()).await;
        }
    }
}

async fn close_worker_inner(inner: &ApplicationInner, id: &str) -> Result<(), AppError> {
    let worker = inner.workers.lock().await.remove(id);
    let Some(worker) = worker else {
        return Ok(());
    };
    worker.cancel();
    let Ok(mut handle) = worker.worker.try_lock() else {
        // An active run owns the worker mutex and will hard-terminate it
        // after observing the cancellation signal.
        return Ok(());
    };
    handle
        .terminate()
        .await
        .map_err(|_| AppError::new(AppErrorCode::WorkerCloseFailed))
}

fn parse_context_id(value: &str) -> Result<String, AppError> {
    azmcp_core::context::ContextId::parse(value)
        .map(|id| id.as_str().to_owned())
        .map_err(|_| AppError::new(AppErrorCode::ContextInvalid))
}

fn account_result(candidate: &SubscriptionCandidate) -> Result<AccountResult, AppError> {
    let cloud = candidate
        .environment_name()
        .parse::<AzureCloud>()
        .map_err(|_| AppError::new(AppErrorCode::ProfileInvalid))?;
    SubscriptionId::new(candidate.subscription_id().to_owned())
        .map_err(|_| AppError::new(AppErrorCode::ProfileInvalid))?;
    TenantId::new(candidate.tenant_id().to_owned())
        .map_err(|_| AppError::new(AppErrorCode::ProfileInvalid))?;
    Ok(AccountResult {
        cloud,
        tenant_id: candidate.tenant_id().to_owned(),
        subscription_id: candidate.subscription_id().to_owned(),
        name: candidate.name.clone(),
        user: candidate.user_name().to_owned(),
        state: candidate.state.clone(),
        token_status: "unknown",
    })
}

fn resolve_caller_binding(
    cloud: AzureCloud,
    binding: &crate::tools::BindingArgs,
    candidates: &[SubscriptionCandidate],
) -> Result<ResolvedCloudBinding, AppError> {
    let subscription = SubscriptionId::new(binding.subscription.clone())
        .map_err(|_| AppError::new(AppErrorCode::BindingInvalid))?;
    let tenant = binding
        .tenant
        .as_ref()
        .map(|tenant| TenantId::new(tenant.clone()))
        .transpose()
        .map_err(|_| AppError::new(AppErrorCode::BindingInvalid))?;
    CloudBinding::new(subscription, tenant)
        .resolve(cloud, candidates)
        .map_err(map_binding_resolution)
}

fn auto_binding(
    cloud: AzureCloud,
    candidate: &SubscriptionCandidate,
) -> Result<ResolvedCloudBinding, AppError> {
    let subscription = SubscriptionId::new(candidate.subscription_id().to_owned())
        .map_err(|_| AppError::new(AppErrorCode::BindingInvalid))?;
    let tenant = TenantId::new(candidate.tenant_id().to_owned())
        .map_err(|_| AppError::new(AppErrorCode::BindingInvalid))?;
    CloudBinding::new(subscription, Some(tenant))
        .resolve(cloud, &[])
        .map_err(map_binding_resolution)
}

fn merge_allowed_subscriptions(
    binding: ResolvedCloudBinding,
    additions: &[crate::tools::AllowedSubscriptionArgs],
) -> Result<ResolvedCloudBinding, AppError> {
    let mut allowed = binding
        .allowed_subscriptions()
        .iter()
        .filter(|pair| pair.subscription() != binding.subscription())
        .cloned()
        .collect::<Vec<_>>();
    for addition in additions {
        let subscription = SubscriptionId::new(addition.subscription.clone())
            .map_err(|_| AppError::new(AppErrorCode::BindingInvalid))?;
        let tenant = TenantId::new(addition.tenant.clone())
            .map_err(|_| AppError::new(AppErrorCode::BindingInvalid))?;
        allowed.push(SubscriptionTenantPair::new(subscription, tenant));
    }
    CloudBinding::with_allowed_subscriptions(
        binding.subscription().clone(),
        Some(binding.tenant().clone()),
        allowed,
    )
    .map_err(|_| AppError::new(AppErrorCode::BindingInvalid))?
    .resolve(binding.cloud(), &[])
    .map_err(map_binding_resolution)
}

fn resolve_graph_scopes(
    args: &ContextOpenArgs,
    bindings: &[ResolvedCloudBinding],
) -> Result<BTreeMap<AzureCloud, GraphScope>, AppError> {
    bindings
        .iter()
        .map(|binding| {
            let scope = match args.graph_scopes.get(binding.cloud()) {
                None => GraphScope::Subscriptions(vec![binding.subscription().clone()]),
                Some(GraphScopeArgs::Subscriptions(scope)) => GraphScope::Subscriptions(
                    scope
                        .subscriptions
                        .iter()
                        .map(|subscription| {
                            SubscriptionId::new(subscription.clone())
                                .map_err(|_| AppError::new(AppErrorCode::InvalidInput))
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                ),
                Some(GraphScopeArgs::AllAccessible(_)) => GraphScope::AllAccessible,
            };
            Ok((binding.cloud(), scope))
        })
        .collect()
}

fn resolved_binding_results(context: &Context) -> Vec<ResolvedBindingResult> {
    context
        .resolved_bindings()
        .iter()
        .map(|binding| ResolvedBindingResult {
            cloud: binding.cloud(),
            subscription: binding.subscription_id().to_owned(),
            tenant: binding.tenant_id().to_owned(),
        })
        .collect()
}

fn allowed_subscription_results(
    context: &Context,
) -> BTreeMap<AzureCloud, Vec<AllowedSubscriptionResult>> {
    context
        .resolved_bindings()
        .iter()
        .map(|binding| {
            (
                binding.cloud(),
                binding
                    .allowed_subscriptions()
                    .iter()
                    .map(|pair| AllowedSubscriptionResult {
                        subscription: pair.subscription_id().to_owned(),
                        tenant: pair.tenant_id().to_owned(),
                    })
                    .collect(),
            )
        })
        .collect()
}

fn graph_scope_results(context: &Context) -> BTreeMap<AzureCloud, GraphScopeArgs> {
    context
        .graph_scopes()
        .iter()
        .map(|(cloud, scope)| {
            let result = match scope {
                GraphScope::Subscriptions(subscriptions) => {
                    GraphScopeArgs::Subscriptions(GraphSubscriptionsArgs {
                        subscriptions: subscriptions
                            .iter()
                            .map(|subscription| subscription.as_str().to_owned())
                            .collect(),
                    })
                }
                GraphScope::AllAccessible => {
                    GraphScopeArgs::AllAccessible(crate::tools::GraphAllAccessibleArgs {
                        scope: crate::tools::AllAccessibleScope::AllAccessible,
                    })
                }
            };
            (*cloud, result)
        })
        .collect()
}

fn map_binding_resolution(error: BindingResolutionError) -> AppError {
    AppError::new(match error {
        BindingResolutionError::MissingTenant { .. } => AppErrorCode::BindingMissingTenant,
        BindingResolutionError::AmbiguousTenant { .. } => AppErrorCode::BindingAmbiguous,
        BindingResolutionError::InvalidTenantCandidate { .. } => AppErrorCode::BindingInvalid,
    })
}

fn map_http_dependency_error(error: HttpError) -> DependencyError {
    match error {
        HttpError::Credential(CredentialError::AuthenticationRequired {
            cloud_name,
            tenant_id,
        }) => DependencyError::AuthenticationRequired {
            cloud_name,
            tenant_id,
        },
        HttpError::Credential(CredentialError::PrincipalMismatch) => {
            DependencyError::PrincipalMismatch
        }
        _ => DependencyError::Failed,
    }
}

fn map_registry_error(error: ContextRegistryError) -> AppError {
    AppError::new(match error {
        ContextRegistryError::Capacity => AppErrorCode::RegistryCapacity,
        ContextRegistryError::NotFound => AppErrorCode::ContextNotFound,
        ContextRegistryError::ContextEvicted => AppErrorCode::ContextEvicted,
        ContextRegistryError::ContextBusy => AppErrorCode::ContextBusy,
        ContextRegistryError::InvalidConfig(_) | ContextRegistryError::InvalidOptions(_) => {
            AppErrorCode::InvalidInput
        }
        ContextRegistryError::RandomHandle => AppErrorCode::RegistryCapacity,
    })
}

fn map_worker_dependency(error: DependencyError) -> AppError {
    match error {
        DependencyError::ExecutionFailed => AppError::new(AppErrorCode::ExecutionFailed),
        DependencyError::ExecutionTimeout => AppError::new(AppErrorCode::ExecutionTimeout),
        DependencyError::ResultTooLarge { summary } => AppError::result_too_large(summary),
        DependencyError::AuthenticationRequired {
            cloud_name,
            tenant_id,
        } => AppError::authentication_required(cloud_name, tenant_id),
        DependencyError::PrincipalMismatch
        | DependencyError::WorkerCrashed
        | DependencyError::Failed
        | DependencyError::AuditFailed => AppError::new(AppErrorCode::WorkerExecuteFailed),
    }
}

fn map_host_error(error: crate::host::HostError) -> AppError {
    use crate::host::HostErrorCode;
    let code = match error.code {
        HostErrorCode::RouteDenied => AppErrorCode::RouteDenied,
        HostErrorCode::CapabilityDenied => AppErrorCode::CapabilityDenied,
        HostErrorCode::AuthenticationRequired | HostErrorCode::PrincipalMismatch => {
            AppErrorCode::AuthenticationRequired
        }
        HostErrorCode::SubscriptionMismatch | HostErrorCode::SubscriptionAmbiguous => {
            AppErrorCode::SubscriptionMismatch
        }
        HostErrorCode::ResponseTooLarge => AppErrorCode::ResultTooLarge,
        HostErrorCode::UpstreamError
        | HostErrorCode::ClientUnavailable
        | HostErrorCode::AuditUnavailable => AppErrorCode::UpstreamError,
        HostErrorCode::InvalidRequest
        | HostErrorCode::CloudRequired
        | HostErrorCode::BindingUnavailable
        | HostErrorCode::InvalidResponse
        | HostErrorCode::ProtocolError => AppErrorCode::InvalidInput,
    };
    if matches!(
        error.code,
        HostErrorCode::AuthenticationRequired | HostErrorCode::PrincipalMismatch
    ) {
        AppError::authentication_required_message(error.message)
    } else {
        AppError::new(code)
    }
}

fn run_result(
    result: ExecutionResult,
    records: CallRecords,
    context: Value,
    correlation_id: String,
) -> Result<RunResult, AppError> {
    Ok(RunResult {
        value: result.value,
        console: result.logs,
        console_omitted: result.logs_omitted,
        calls: records
            .calls
            .into_iter()
            .map(|record| serde_json::to_value(record).expect("call record is serializable"))
            .collect(),
        calls_omitted: records.calls_omitted,
        context,
        sensitivity: "customerData",
        correlation_id,
    })
}

fn context_summary(context: &Context) -> Value {
    serde_json::json!({
        "identity": "user",
        "armTier": "inspect",
        "dataPlanes": context.data_planes(),
        "bindings": resolved_binding_results(context),
        "allowedSubscriptions": allowed_subscription_results(context),
        "graphScopes": graph_scope_results(context),
        "policyHash": context.policy_hash(),
    })
}

pub(crate) fn correlation_id() -> Result<String, AppError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| AppError::new(AppErrorCode::CorrelationUnavailable))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn format_expiry(deadline: Instant) -> String {
    let remaining = deadline.saturating_duration_since(Instant::now());
    format_system_time(
        SystemTime::now()
            .checked_add(remaining)
            .unwrap_or_else(SystemTime::now),
    )
}

fn format_system_time(time: SystemTime) -> String {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = seconds / 86_400;
    let day_seconds = seconds % 86_400;
    let (year, month, day) = civil_date(days as i64);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        day_seconds / 3_600,
        (day_seconds % 3_600) / 60,
        day_seconds % 60
    )
}

// Gregorian calendar conversion for a Unix day count, avoiding a date crate.
fn civil_date(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    (y + i64::from(m <= 2), m, d)
}

/// A convenient registry for callers that do not need custom limits.
pub fn default_registry() -> Result<ContextRegistry, AppError> {
    ContextRegistry::new(RegistryConfig::new(
        32,
        Duration::from_secs(30 * 60),
        Duration::from_secs(24 * 60 * 60),
    ))
    .map_err(|_| AppError::new(AppErrorCode::InvalidConfiguration))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{ClientFactoryError, HttpClientFactory};
    use azmcp_core::{
        credential::TokenAudience,
        http::{ArmOrigin, BearerCredential, CredentialFuture, CredentialProvider, HttpClient},
        policy::PolicyBundle,
    };
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::Notify,
    };

    const SUB: &str = "11111111-1111-1111-1111-111111111111";
    const SUB2: &str = "22222222-2222-2222-2222-222222222222";
    const TENANT: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    const TENANT2: &str = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

    fn profile(rows: &str) -> Vec<u8> {
        format!(r#"{{"subscriptions":[{rows}]}}"#).into_bytes()
    }
    fn row(sub: &str, tenant: &str, cloud: &str, user: &str) -> String {
        format!(
            r#"{{"id":"{sub}","name":"name","state":"Enabled","tenantId":"{tenant}","environmentName":"{cloud}","user":{{"name":"{user}"}}}}"#
        )
    }

    struct IdentityCredentials {
        calls: AtomicUsize,
    }

    impl CredentialProvider for IdentityCredentials {
        fn acquire<'a>(
            &'a self,
            _request: azmcp_core::credential::TokenRequest,
        ) -> CredentialFuture<'a> {
            Box::pin(async move {
                let (principal_id, client_id) = if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    (
                        "cccccccc-cccc-cccc-cccc-cccccccccccc",
                        "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
                    )
                } else {
                    (
                        "dddddddd-dddd-dddd-dddd-dddddddddddd",
                        "ffffffff-ffff-ffff-ffff-ffffffffffff",
                    )
                };
                BearerCredential::with_identity(
                    "synthetic-validation-token",
                    principal_id,
                    client_id,
                )
            })
        }
    }

    struct ValidationClientFactory {
        credentials: Arc<IdentityCredentials>,
        origin: String,
        policy: PolicyBundle,
    }

    impl HttpClientFactory for ValidationClientFactory {
        fn client_for(
            &self,
            binding: &ResolvedCloudBinding,
        ) -> Result<Arc<HttpClient>, ClientFactoryError> {
            let origin = ArmOrigin::loopback_from_str(binding.cloud(), &self.origin)
                .map_err(|_| ClientFactoryError::Unavailable)?;
            let credentials: Arc<dyn CredentialProvider> = self.credentials.clone();
            HttpClient::with_loopback_origin(
                credentials,
                binding.cloud(),
                binding.subscription().clone(),
                binding.tenant().clone(),
                TokenAudience::Arm,
                origin,
                self.policy.clone(),
            )
            .map(Arc::new)
            .map_err(|_| ClientFactoryError::Unavailable)
        }
    }

    async fn validation_server() -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("loopback");
        let address = listener.local_addr().expect("address");
        let task = tokio::spawn(async move {
            // The second binding is rejected by the context identity pin
            // before any HTTP request is signed or sent.
            for subscription in [SUB] {
                let (mut stream, _) = listener.accept().await.expect("validation request");
                let mut request = Vec::new();
                let mut buffer = [0_u8; 4096];
                loop {
                    let count = stream.read(&mut buffer).await.expect("read request");
                    if count == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..count]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let body = format!(r#"{{"subscriptionId":"{subscription}"}}"#);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write response");
            }
        });
        (format!("http://{address}/"), task)
    }

    #[derive(Default)]
    struct Validator {
        calls: AtomicUsize,
        reject: AtomicBool,
    }

    impl BindingValidator for Validator {
        fn validate<'a>(
            &'a self,
            _binding: &'a ResolvedCloudBinding,
            _identity_pin: &'a CredentialIdentityPin,
        ) -> BoxFuture<'a, Result<(), DependencyError>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                if self.reject.load(Ordering::SeqCst) {
                    Err(DependencyError::Failed)
                } else {
                    Ok(())
                }
            })
        }
    }

    struct WorkerState {
        starts: AtomicUsize,
        closes: AtomicUsize,
        terminates: AtomicUsize,
        codes: Mutex<Vec<String>>,
        gate: Option<Arc<Notify>>,
        started: Arc<Notify>,
        terminated: Arc<Notify>,
    }

    struct Factory {
        state: Arc<WorkerState>,
        fail: AtomicBool,
    }

    struct StartGateFactory {
        state: Arc<WorkerState>,
        calls: AtomicUsize,
        entered: Arc<Notify>,
        release: Arc<Notify>,
    }

    impl WorkerFactory for StartGateFactory {
        fn start<'a>(
            &'a self,
            _context: &'a Context,
        ) -> BoxFuture<'a, Result<Box<dyn WorkerHandle>, DependencyError>> {
            Box::pin(async move {
                let call = self.calls.fetch_add(1, Ordering::SeqCst);
                if call == 0 {
                    self.entered.notify_one();
                    self.release.notified().await;
                }
                Ok(Box::new(FakeWorker {
                    state: Arc::clone(&self.state),
                }) as Box<dyn WorkerHandle>)
            })
        }
    }

    impl WorkerFactory for Factory {
        fn start<'a>(
            &'a self,
            _context: &'a Context,
        ) -> BoxFuture<'a, Result<Box<dyn WorkerHandle>, DependencyError>> {
            Box::pin(async move {
                self.state.starts.fetch_add(1, Ordering::SeqCst);
                if self.fail.load(Ordering::SeqCst) {
                    return Err(DependencyError::Failed);
                }
                Ok(Box::new(FakeWorker {
                    state: Arc::clone(&self.state),
                }) as Box<dyn WorkerHandle>)
            })
        }
    }

    struct FakeWorker {
        state: Arc<WorkerState>,
    }

    impl WorkerHandle for FakeWorker {
        fn execute<'a>(
            &'a mut self,
            code: &'a str,
            _timeout: Duration,
            _host_handler: Option<HostCallHandler>,
        ) -> BoxFuture<'a, Result<ExecutionResult, DependencyError>> {
            let state = Arc::clone(&self.state);
            let code = code.to_owned();
            Box::pin(async move {
                state.codes.lock().await.push(code.clone());
                state.started.notify_waiters();
                if let Some(gate) = &state.gate {
                    gate.notified().await;
                }
                Ok(ExecutionResult {
                    value: Value::String(code),
                    logs: vec!["ok".to_owned()],
                    logs_omitted: 0,
                })
            })
        }

        fn close<'a>(&'a mut self) -> BoxFuture<'a, Result<(), DependencyError>> {
            Box::pin(async move {
                self.state.closes.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }

        fn terminate<'a>(&'a mut self) -> BoxFuture<'a, Result<(), DependencyError>> {
            Box::pin(async move {
                self.state.terminates.fetch_add(1, Ordering::SeqCst);
                self.state.terminated.notify_waiters();
                Ok(())
            })
        }
    }

    fn app(bytes: Vec<u8>, validator: Arc<Validator>, factory: Arc<Factory>) -> Application {
        app_with_registry(bytes, validator, factory, default_registry().unwrap())
    }
    fn app_with_registry(
        bytes: Vec<u8>,
        validator: Arc<Validator>,
        factory: Arc<Factory>,
        registry: ContextRegistry,
    ) -> Application {
        Application::from_arcs(
            Config::empty(),
            registry,
            Arc::new(MemoryProfileSource::new(bytes)),
            validator,
            factory,
            "hash",
            "version",
        )
        .unwrap()
    }
    fn state(gate: Option<Arc<Notify>>) -> Arc<WorkerState> {
        Arc::new(WorkerState {
            starts: AtomicUsize::new(0),
            closes: AtomicUsize::new(0),
            terminates: AtomicUsize::new(0),
            codes: Mutex::new(Vec::new()),
            gate,
            started: Arc::new(Notify::new()),
            terminated: Arc::new(Notify::new()),
        })
    }
    fn factory(state: Arc<WorkerState>) -> Arc<Factory> {
        Arc::new(Factory {
            state,
            fail: AtomicBool::new(false),
        })
    }

    #[tokio::test]
    async fn accounts_are_profile_only_and_do_not_acquire_tokens() {
        let validator = Arc::new(Validator::default());
        let state = state(None);
        let app = app(
            profile(&row(SUB, TENANT, "AzureCloud", "alice")),
            Arc::clone(&validator),
            factory(Arc::clone(&state)),
        );
        let result = app.accounts(AccountsArgs {}).await.expect("accounts");
        assert_eq!(result.accounts[0].token_status, "unknown");
        assert_eq!(validator.calls.load(Ordering::SeqCst), 0);
        assert_eq!(state.starts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn accounts_reject_profile_ids_outside_the_advertised_uuid_schema() {
        let application = app(
            profile(&row("not-a-uuid", TENANT, "AzureCloud", "alice")),
            Arc::new(Validator::default()),
            factory(state(None)),
        );
        assert_eq!(
            application
                .accounts(AccountsArgs {})
                .await
                .expect_err("invalid profile identifier")
                .kind(),
            AppErrorCode::ProfileInvalid
        );
    }

    #[tokio::test]
    async fn explicit_binding_wins_without_loading_profile() {
        let validator = Arc::new(Validator::default());
        let explicit = app(
            b"not a profile".to_vec(),
            Arc::clone(&validator),
            factory(state(None)),
        );
        let mut args = ContextOpenArgs::default();
        args.bindings.commercial = Some(crate::tools::BindingArgs {
            subscription: SUB.to_owned(),
            tenant: Some(TENANT.to_owned()),
        });
        let result = explicit.context_open(args).await.expect("open");
        assert_eq!(result.resolved_bindings.len(), 1);
        assert_eq!(validator.calls.load(Ordering::SeqCst), 1);
        let lease = explicit
            .registry()
            .lease(&result.context_id, Instant::now())
            .expect("context lease");
        assert_eq!(
            lease.context().binding_sources()[&AzureCloud::AzureCloud],
            BindingSource::ContextOverride
        );
    }

    #[tokio::test]
    async fn allowlists_and_graph_scopes_are_normalized_and_fail_closed() {
        let validator = Arc::new(Validator::default());
        let application = app(
            b"not a profile".to_vec(),
            Arc::clone(&validator),
            factory(state(None)),
        );
        let mut args = ContextOpenArgs::default();
        args.bindings.commercial = Some(crate::tools::BindingArgs {
            subscription: SUB.to_owned(),
            tenant: Some(TENANT.to_owned()),
        });
        args.allowed_subscriptions.commercial = vec![crate::tools::AllowedSubscriptionArgs {
            subscription: SUB2.to_owned(),
            tenant: TENANT2.to_owned(),
        }];
        args.graph_scopes.commercial =
            Some(GraphScopeArgs::Subscriptions(GraphSubscriptionsArgs {
                subscriptions: vec![SUB2.to_owned()],
            }));
        let opened = application.context_open(args).await.expect("open");
        assert_eq!(
            opened.allowed_subscriptions[&AzureCloud::AzureCloud].len(),
            2
        );
        assert_eq!(
            opened.graph_scopes[&AzureCloud::AzureCloud],
            GraphScopeArgs::Subscriptions(GraphSubscriptionsArgs {
                subscriptions: vec![SUB2.to_owned()],
            })
        );

        let mut denied = ContextOpenArgs::default();
        denied.bindings.commercial = Some(crate::tools::BindingArgs {
            subscription: SUB.to_owned(),
            tenant: Some(TENANT.to_owned()),
        });
        denied.graph_scopes.commercial =
            Some(GraphScopeArgs::Subscriptions(GraphSubscriptionsArgs {
                subscriptions: vec![SUB2.to_owned()],
            }));
        assert_eq!(
            application
                .context_open(denied)
                .await
                .expect_err("graph scope exceeds allowlist")
                .kind(),
            AppErrorCode::InvalidInput
        );
        assert_eq!(
            validator.calls.load(Ordering::SeqCst),
            1,
            "invalid graph scope is rejected before live validation"
        );
    }

    #[tokio::test]
    async fn automatic_binding_requires_one_candidate_and_omitted_tenant_uses_all_candidates() {
        let validator = Arc::new(Validator::default());
        let app = app(
            profile(&format!(
                "{},{}",
                row(SUB, TENANT, "AzureCloud", "alice"),
                row(SUB2, TENANT2, "AzureCloud", "bob")
            )),
            Arc::clone(&validator),
            factory(state(None)),
        );
        let mut args = ContextOpenArgs::default();
        args.bindings.commercial = Some(crate::tools::BindingArgs {
            subscription: SUB.to_owned(),
            tenant: None,
        });
        let result = app.context_open(args).await.expect("open");
        assert_eq!(result.resolved_bindings[0].tenant_id(), TENANT);
    }

    #[tokio::test]
    async fn automatic_binding_fills_an_undeclared_cloud_alongside_an_override() {
        let validator = Arc::new(Validator::default());
        let app = app(
            profile(&row(SUB2, TENANT2, "AzureUSGovernment", "bob")),
            Arc::clone(&validator),
            factory(state(None)),
        );
        let mut args = ContextOpenArgs::default();
        args.bindings.commercial = Some(crate::tools::BindingArgs {
            subscription: SUB.to_owned(),
            tenant: Some(TENANT.to_owned()),
        });

        let result = app.context_open(args).await.expect("open");
        assert_eq!(result.resolved_bindings.len(), 2);
        assert_eq!(
            result
                .resolved_bindings
                .iter()
                .find(|binding| binding.cloud == AzureCloud::AzureUSGovernment)
                .expect("government binding")
                .tenant_id(),
            TENANT2
        );
        assert_eq!(validator.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn ambiguous_automatic_candidates_fail_without_worker() {
        let state = state(None);
        let app = app(
            profile(&format!(
                "{},{}",
                row(SUB, TENANT, "AzureCloud", "alice"),
                row(SUB2, TENANT2, "AzureCloud", "bob")
            )),
            Arc::new(Validator::default()),
            factory(Arc::clone(&state)),
        );
        let error = app
            .context_open(ContextOpenArgs::default())
            .await
            .expect_err("ambiguous");
        assert_eq!(error.code(), "account_ambiguous");
        assert_eq!(state.starts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn validation_happens_before_registry_and_worker() {
        let validator = Arc::new(Validator::default());
        validator.reject.store(true, Ordering::SeqCst);
        let state = state(None);
        let error = app(
            profile(&row(SUB, TENANT, "AzureCloud", "alice")),
            validator,
            factory(Arc::clone(&state)),
        )
        .context_open(ContextOpenArgs::default())
        .await
        .expect_err("rejected");
        assert_eq!(error.code(), "subscription_mismatch");
        assert_eq!(state.starts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn identity_pin_begins_during_live_binding_validation() {
        let (origin, server) = validation_server().await;
        let credentials = Arc::new(IdentityCredentials {
            calls: AtomicUsize::new(0),
        });
        let clients = Arc::new(ValidationClientFactory {
            credentials: Arc::clone(&credentials),
            origin,
            policy: azmcp_core::routes::v0_policy().expect("policy"),
        });
        let validator = Arc::new(HttpBindingValidator::new(clients));
        let state = state(None);
        let application = Application::from_arcs(
            Config::empty(),
            default_registry().expect("registry"),
            Arc::new(MemoryProfileSource::new(Vec::new())),
            validator,
            factory(Arc::clone(&state)),
            "hash",
            "version",
        )
        .expect("application");
        let mut args = ContextOpenArgs::default();
        args.bindings.commercial = Some(crate::tools::BindingArgs {
            subscription: SUB.to_owned(),
            tenant: Some(TENANT.to_owned()),
        });
        args.allowed_subscriptions.commercial = vec![crate::tools::AllowedSubscriptionArgs {
            subscription: SUB2.to_owned(),
            tenant: TENANT.to_owned(),
        }];

        let error = application
            .context_open(args)
            .await
            .expect_err("the second validation token changes identity");
        assert_eq!(error.kind(), AppErrorCode::AuthenticationRequired);
        assert!(error.authentication_message().is_some_and(|message| {
            message.contains(
                "AZURE_CLOUD_NAME=AzureCloud az login --tenant aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            )
        }));
        assert_eq!(credentials.calls.load(Ordering::SeqCst), 2);
        assert_eq!(state.starts.load(Ordering::SeqCst), 0);
        server.await.expect("validation server");
    }

    #[tokio::test]
    async fn cancelled_context_open_rolls_back_registry_capacity() {
        let entered = Arc::new(Notify::new());
        let factory = Arc::new(StartGateFactory {
            state: state(None),
            calls: AtomicUsize::new(0),
            entered: Arc::clone(&entered),
            release: Arc::new(Notify::new()),
        });
        let registry = ContextRegistry::new(RegistryConfig::new(
            1,
            Duration::from_secs(60),
            Duration::from_secs(600),
        ))
        .expect("registry");
        let application = Application::from_arcs(
            Config::empty(),
            registry,
            Arc::new(MemoryProfileSource::new(profile(&row(
                SUB,
                TENANT,
                "AzureCloud",
                "alice",
            )))),
            Arc::new(Validator::default()),
            factory,
            "hash",
            "version",
        )
        .expect("application");
        let cancelled = application.clone();
        let task =
            tokio::spawn(async move { cancelled.context_open(ContextOpenArgs::default()).await });
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("worker start entered");
        task.abort();
        assert!(task.await.expect_err("open cancelled").is_cancelled());

        application
            .context_open(ContextOpenArgs::default())
            .await
            .expect("cancelled open released the only registry slot");
    }

    #[tokio::test]
    async fn state_persists_and_busy_is_registry_owned() {
        let gate = Arc::new(Notify::new());
        let state = state(Some(Arc::clone(&gate)));
        let app = app(
            profile(&row(SUB, TENANT, "AzureCloud", "alice")),
            Arc::new(Validator::default()),
            factory(Arc::clone(&state)),
        );
        let opened = app
            .context_open(ContextOpenArgs::default())
            .await
            .expect("open");
        let first = app.clone();
        let id = opened.context_id.clone();
        let task = tokio::spawn(async move {
            first
                .run(RunArgs {
                    context_id: id,
                    code: "one".to_owned(),
                    timeout_ms: None,
                })
                .await
        });
        tokio::task::yield_now().await;
        let busy = app
            .run(RunArgs {
                context_id: opened.context_id.clone(),
                code: "two".to_owned(),
                timeout_ms: None,
            })
            .await
            .expect_err("busy");
        assert_eq!(busy.code(), "context_busy");
        gate.notify_one();
        task.await.expect("task join").expect("first run");
        assert_eq!(state.codes.lock().await.as_slice(), ["one"]);
    }

    #[tokio::test]
    async fn close_returns_while_run_is_gated_and_hard_terminates_worker() {
        let gate = Arc::new(Notify::new());
        let state = state(Some(gate));
        let app = app(
            profile(&row(SUB, TENANT, "AzureCloud", "alice")),
            Arc::new(Validator::default()),
            factory(Arc::clone(&state)),
        );
        let opened = app
            .context_open(ContextOpenArgs::default())
            .await
            .expect("open");
        let entered = state.started.notified();
        let running = app.clone();
        let context_id = opened.context_id.clone();
        let task = tokio::spawn(async move {
            running
                .run(RunArgs {
                    context_id,
                    code: "gated".to_owned(),
                    timeout_ms: None,
                })
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), entered)
            .await
            .expect("run entered worker");

        let closed = tokio::time::timeout(
            Duration::from_millis(100),
            app.context_close(ContextCloseArgs {
                context_id: opened.context_id,
            }),
        )
        .await
        .expect("close does not wait on gated run")
        .expect("close");
        assert!(closed.closed);

        let result = task.await.expect("run task");
        assert_eq!(result.expect_err("cancelled run").code(), "worker_crashed");
        assert_eq!(state.terminates.load(Ordering::SeqCst), 1);
        assert_eq!(state.closes.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn aborted_run_evicts_context_and_terminates_worker() {
        let state = state(Some(Arc::new(Notify::new())));
        let app = app(
            profile(&row(SUB, TENANT, "AzureCloud", "alice")),
            Arc::new(Validator::default()),
            factory(Arc::clone(&state)),
        );
        let opened = app
            .context_open(ContextOpenArgs::default())
            .await
            .expect("open");
        let entered = state.started.notified();
        let terminated = state.terminated.notified();
        let running = app.clone();
        let context_id = opened.context_id.clone();
        let task = tokio::spawn(async move {
            running
                .run(RunArgs {
                    context_id,
                    code: "gated".to_owned(),
                    timeout_ms: None,
                })
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), entered)
            .await
            .expect("run entered worker");
        task.abort();
        assert!(task.await.expect_err("run abort").is_cancelled());
        tokio::time::timeout(Duration::from_secs(1), terminated)
            .await
            .expect("aborted run terminated worker");
        assert_eq!(state.terminates.load(Ordering::SeqCst), 1);
        assert_eq!(
            app.run(RunArgs {
                context_id: opened.context_id,
                code: "after abort".to_owned(),
                timeout_ms: None,
            })
            .await
            .expect_err("aborted context is evicted")
            .kind(),
            AppErrorCode::ContextNotFound
        );
    }

    #[tokio::test]
    async fn idle_context_reaper_terminates_worker_without_a_follow_up_request() {
        let state = state(None);
        let registry = ContextRegistry::new(RegistryConfig::new(
            4,
            Duration::from_millis(20),
            Duration::from_secs(1),
        ))
        .expect("registry");
        let app = app_with_registry(
            profile(&row(SUB, TENANT, "AzureCloud", "alice")),
            Arc::new(Validator::default()),
            factory(Arc::clone(&state)),
            registry,
        );
        let terminated = state.terminated.notified();
        let opened = app
            .context_open(ContextOpenArgs::default())
            .await
            .expect("open");
        tokio::time::timeout(Duration::from_secs(1), terminated)
            .await
            .expect("idle context was reaped");
        assert_eq!(state.terminates.load(Ordering::SeqCst), 1);
        assert_eq!(
            app.run(RunArgs {
                context_id: opened.context_id,
                code: "after expiry".to_owned(),
                timeout_ms: None,
            })
            .await
            .expect_err("expired context")
            .kind(),
            AppErrorCode::ContextNotFound
        );
    }

    #[tokio::test]
    async fn close_kills_worker_and_start_failure_rolls_back_registry() {
        let validator = Arc::new(Validator::default());
        let state = state(None);
        let factory = Arc::new(Factory {
            state: Arc::clone(&state),
            fail: AtomicBool::new(true),
        });
        let app = app(
            profile(&row(SUB, TENANT, "AzureCloud", "alice")),
            Arc::clone(&validator),
            Arc::clone(&factory),
        );
        assert_eq!(
            app.context_open(ContextOpenArgs::default())
                .await
                .expect_err("start failure")
                .code(),
            "worker_crashed"
        );
        factory.fail.store(false, Ordering::SeqCst);
        let opened = app
            .context_open(ContextOpenArgs::default())
            .await
            .expect("rollback permits retry");
        app.context_close(ContextCloseArgs {
            context_id: opened.context_id.clone(),
        })
        .await
        .expect("close");
        assert_eq!(state.terminates.load(Ordering::SeqCst), 1);
        assert_eq!(
            app.run(RunArgs {
                context_id: opened.context_id,
                code: "secret code".to_owned(),
                timeout_ms: None,
            })
            .await
            .expect_err("closed")
            .code(),
            "context_evicted"
        );
    }

    #[test]
    fn errors_do_not_include_bearer_or_source_code_values() {
        let error = AppError::new(AppErrorCode::WorkerExecuteFailed);
        let rendered = error.to_string();
        assert!(!rendered.contains("secret code"));
        assert!(!rendered.contains("token"));
        assert!(!rendered.contains("AAAAAAAA"));
    }

    #[test]
    fn principal_mismatch_preserves_the_identity_change_message() {
        let message =
            "Azure authentication identity changed during the context lifetime".to_owned();
        let error = map_host_error(crate::host::HostError {
            code: crate::host::HostErrorCode::PrincipalMismatch,
            message: message.clone(),
            retryable: false,
        });

        assert_eq!(error.kind(), AppErrorCode::AuthenticationRequired);
        assert_eq!(error.authentication_message(), Some(message.as_str()));
    }
}
