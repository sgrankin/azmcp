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
        ARTIFACTS_WRITE_CAPABILITY, ArmTier, BindingSource, Context, ContextOptions,
        ContextRegistry, ContextRegistryError, GraphScope, Identity, LogsScope, RegistryConfig,
    },
    credential::{CredentialError, CredentialIdentityPin},
    http::{HttpError, HttpRequest},
    policy::{HttpMethod, RoutePurpose},
    routes::SUBSCRIPTIONS_API_VERSION,
    schema::{SchemaDetails, SchemaError, SchemaIndex, SchemaSearchHit},
    target::RelativeRequestTarget,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{Mutex, watch};

use crate::{
    artifacts::{
        ArtifactCompression, ArtifactError, ArtifactNamespace, ArtifactStage, ArtifactStore,
        ArtifactStream, ArtifactStreamFormat,
    },
    audit::{ArtifactWriteAuditRecord, AuditSink},
    host::{CallDecision, CallRecord, CallRecords, HostAdapter, HttpClientFactory},
    refs::{RefId, RefStore},
    tools::{
        AccountsArgs, ContextCloseArgs, ContextOpenArgs, GraphScopeArgs, GraphSubscriptionsArgs,
        LogsScopeOverrides, RunArgs, SchemaGetArgs, SchemaSearchArgs,
    },
    worker::{
        ArtifactWriteCompression, ArtifactWriteJsonStreamAbortResult,
        ArtifactWriteJsonStreamAppendResult, ArtifactWriteJsonStreamArguments,
        ArtifactWriteJsonStreamBeginResult, ExecutionResult, HOST_METHOD_ARTIFACT_WRITE_JSON,
        HOST_METHOD_ARTIFACT_WRITE_JSON_ARRAY, HOST_METHOD_ARTIFACT_WRITE_JSON_LINES,
        HOST_METHOD_REF, HostCallHandler, HostCallRequest, HostCallResult, MAX_INPUT_BYTES,
        RefCandidate, ResultTooLargeSummary, WorkerProcess,
    },
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
                            .map_err(|_| (DependencyError::Failed, 0))?;
                    let client = self
                        .clients
                        .client_for(&effective)
                        .map_err(|_| (DependencyError::Failed, 0))?;
                    let target = RelativeRequestTarget::parse(&format!(
                        "/subscriptions/{}",
                        pair.subscription_id()
                    ))
                    .map_err(|_| (DependencyError::Failed, 0))?;
                    let request = HttpRequest::for_purpose(
                        RoutePurpose::Internal,
                        HttpMethod::Get,
                        target,
                        SUBSCRIPTIONS_API_VERSION,
                    )
                    .map_err(|_| (DependencyError::Failed, 0))?;
                    client
                        .execute_with_identity_pin(request, Some(identity_pin))
                        .await
                        .map_err(|error| {
                            let retry_count = error.retry_count();
                            (map_http_dependency_error(error), retry_count)
                        })
                }
                .await;
                let retry_count = match &response {
                    Ok(response) => response.retry_count(),
                    Err((_, retry_count)) => *retry_count,
                };
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
                    retry_count,
                    remaining_subscription_reads: remaining_reads,
                    graph_scope: None,
                    data_plane: None,
                    data_scope: None,
                };
                if let Some(sink) = &self.audit_sink {
                    sink.append(&record)
                        .map_err(|_| DependencyError::AuditFailed)?;
                }
                response.map_err(|(error, _)| error)?;
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
    ArtifactCapacity,
    ExecutionTimeout,
    ExecutionFailed,
    SchemaUnavailable,
    SchemaNotFound,
    SchemaVersionNotFound,
    SchemaCloudNotBound,
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
            Self::ArtifactCapacity => "artifact_capacity",
            Self::ExecutionTimeout => "execution_timeout",
            Self::ExecutionFailed => "invalid_request",
            Self::SchemaUnavailable => "schema_unavailable",
            Self::SchemaNotFound => "schema_not_found",
            Self::SchemaVersionNotFound => "schema_version_not_found",
            Self::SchemaCloudNotBound => "schema_cloud_not_bound",
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
    pub data_planes: Vec<String>,
    pub local_capabilities: Vec<String>,
    pub resolved_bindings: Vec<ResolvedBindingResult>,
    pub allowed_subscriptions: BTreeMap<AzureCloud, Vec<AllowedSubscriptionResult>>,
    pub graph_scopes: BTreeMap<AzureCloud, GraphScopeArgs>,
    pub logs_scopes: LogsScopeOverrides,
    pub expires_at: String,
}

impl ContextOpenResult {
    /// Return immutable context metadata without the bearer handle.
    pub fn context_summary(&self, policy_hash: &str) -> Value {
        serde_json::json!({
            "identity": self.identity,
            "armTier": self.arm_tier,
            "dataPlanes": self.data_planes,
            "localCapabilities": self.local_capabilities,
            "bindings": self.resolved_bindings,
            "allowedSubscriptions": self.allowed_subscriptions,
            "graphScopes": self.graph_scopes,
            "logsScopes": self.logs_scopes,
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
#[derive(Clone, PartialEq, Serialize)]
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

impl std::fmt::Debug for RunResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RunResult")
            .field(
                "value_bytes",
                &serde_json::to_vec(&self.value)
                    .map(|bytes| bytes.len())
                    .unwrap_or_default(),
            )
            .field("console_entries", &self.console.len())
            .field("console_omitted", &self.console_omitted)
            .field("call_count", &self.calls.len())
            .field("calls_omitted", &self.calls_omitted)
            .field("context", &self.context)
            .field("sensitivity", &self.sensitivity)
            .field("correlation_id", &self.correlation_id)
            .finish()
    }
}

/// Bounded metadata returned by context-scoped schema search.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaSearchResult {
    pub policy_hash: String,
    pub policy_version: String,
    pub query: String,
    pub results: Vec<SchemaSearchHit>,
    pub omitted: usize,
}

/// Full reviewed route metadata returned by schema get.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaGetResult {
    pub policy_hash: String,
    pub policy_version: String,
    pub schema: SchemaDetails,
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

/// Defaults for the reviewed policy metadata.  The policy implementation remains an
/// application concern; these non-empty values satisfy the immutable core record.
pub const DEFAULT_POLICY_HASH: &str = azmcp_core::routes::V0_POLICY_HASH;
pub const DEFAULT_POLICY_VERSION: &str = azmcp_core::routes::V0_POLICY_VERSION;

struct ApplicationInner {
    config: Config,
    policy_hash: String,
    policy_version: String,
    registry: ContextRegistry,
    profile_source: Arc<dyn ProfileSource>,
    binding_validator: Arc<dyn BindingValidator>,
    worker_factory: Arc<dyn WorkerFactory>,
    host_client_factory: Option<Arc<dyn HttpClientFactory>>,
    schema_index: Arc<SchemaIndex>,
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
    artifact_namespace: Option<ArtifactNamespace>,
    artifact_store: Option<Arc<dyn ArtifactStore>>,
    artifact_transaction: Mutex<ArtifactTransaction>,
    refs: Mutex<RefStore>,
    ref_changed: tokio::sync::Notify,
}

#[derive(Default)]
struct ArtifactTransaction {
    run_id: Option<String>,
    accepting: bool,
    stages: Vec<ArtifactStage>,
    streams: HashMap<String, ActiveArtifactStream>,
    streams_touched: bool,
}

struct ActiveArtifactStream {
    stream: ArtifactStream,
    format: ArtifactStreamFormat,
    compression: ArtifactCompression,
    next_sequence: u16,
    items: u64,
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
        if let Some(slot) = &slot {
            slot.signal_cancel();
        }
        let cleanup = async move {
            let slot = if let Some(slot) = slot {
                if let Some(inner) = inner.upgrade() {
                    let mut workers = inner.workers.lock().await;
                    if workers
                        .get(&id)
                        .is_some_and(|current| Arc::ptr_eq(current, &slot))
                    {
                        workers.remove(&id);
                    }
                }
                slot
            } else {
                let Some(inner) = inner.upgrade() else {
                    return;
                };
                let Some(slot) = inner.workers.lock().await.remove(&id) else {
                    return;
                };
                slot
            };
            let _ = slot.cancel().await;
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
            artifact_namespace: None,
            artifact_store: None,
            artifact_transaction: Mutex::new(ArtifactTransaction::default()),
            refs: Mutex::new(RefStore::default()),
            ref_changed: tokio::sync::Notify::new(),
        }
    }

    fn with_artifact_binding(
        mut self,
        namespace: Option<ArtifactNamespace>,
        store: Option<Arc<dyn ArtifactStore>>,
    ) -> Self {
        self.artifact_namespace = namespace;
        self.artifact_store = store;
        self
    }

    fn signal_cancel(&self) {
        self.cancellation.send_replace(true);
    }

    async fn cancel(&self) -> Result<(), ArtifactError> {
        self.signal_cancel();
        self.refs.lock().await.clear();
        self.rollback_pending_artifacts().await
    }

    async fn begin_artifact_run(&self, run_id: &str) -> Result<(), ArtifactError> {
        if self.artifact_store.is_none() {
            return Ok(());
        }
        let mut transaction = self.artifact_transaction.lock().await;
        if *self.cancellation.borrow()
            || transaction.run_id.is_some()
            || !transaction.stages.is_empty()
            || !transaction.streams.is_empty()
            || transaction.streams_touched
        {
            return Err(ArtifactError::Unavailable);
        }
        transaction.run_id = Some(run_id.to_owned());
        transaction.accepting = true;
        Ok(())
    }

    async fn commit_pending_artifacts(&self, run_id: &str) -> Result<(), ArtifactError> {
        if self.artifact_store.is_none() {
            return Ok(());
        }
        let mut transaction = self.artifact_transaction.lock().await;
        if !artifact_transaction_accepts(&transaction, run_id) {
            return Err(ArtifactError::Unavailable);
        }
        transaction.accepting = false;
        if *self.cancellation.borrow() {
            self.discard_artifact_transaction(&mut transaction).await?;
            return Err(ArtifactError::Unavailable);
        }
        let had_active_streams = !transaction.streams.is_empty();
        self.discard_artifact_streams(&mut transaction).await?;
        if had_active_streams {
            self.discard_artifact_stages(&mut transaction).await?;
            transaction.run_id = None;
            return Err(ArtifactError::Unavailable);
        }
        if transaction.stages.is_empty() {
            transaction.run_id = None;
            return Ok(());
        }
        let (Some(store), Some(namespace)) = (
            self.artifact_store.as_ref(),
            self.artifact_namespace.as_ref(),
        ) else {
            return Err(ArtifactError::Unavailable);
        };
        let stages = transaction.stages.clone();
        store
            .commit_staged(namespace.clone(), stages.clone())
            .await?;
        if *self.cancellation.borrow() {
            store.discard_staged(namespace.clone(), stages).await?;
            transaction.stages.clear();
            transaction.run_id = None;
            return Err(ArtifactError::Unavailable);
        }
        // There is deliberately no await between the final cancellation check
        // and clearing ownership. Publication wins at this boundary; the MCP
        // layer prioritizes the now-complete run over simultaneous cancellation.
        store.finalize_staged(namespace, &stages)?;
        transaction.stages.clear();
        transaction.run_id = None;
        Ok(())
    }

    async fn rollback_pending_artifacts(&self) -> Result<(), ArtifactError> {
        let mut transaction = self.artifact_transaction.lock().await;
        transaction.accepting = false;
        if transaction.run_id.is_none()
            && transaction.stages.is_empty()
            && transaction.streams.is_empty()
            && !transaction.streams_touched
        {
            return Ok(());
        }
        self.discard_artifact_transaction(&mut transaction).await
    }

    async fn discard_artifact_transaction(
        &self,
        transaction: &mut ArtifactTransaction,
    ) -> Result<(), ArtifactError> {
        let (Some(store), Some(namespace)) = (
            self.artifact_store.as_ref(),
            self.artifact_namespace.as_ref(),
        ) else {
            if transaction.stages.is_empty()
                && transaction.streams.is_empty()
                && !transaction.streams_touched
            {
                transaction.run_id = None;
                return Ok(());
            }
            return Err(ArtifactError::Unavailable);
        };
        let mut first_error = self.discard_artifact_streams(transaction).await.err();
        if !transaction.stages.is_empty() {
            match store
                .discard_staged(namespace.clone(), transaction.stages.clone())
                .await
            {
                Ok(()) => transaction.stages.clear(),
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        if first_error.is_none() {
            transaction.run_id = None;
        }
        first_error.map_or(Ok(()), Err)
    }

    async fn discard_artifact_streams(
        &self,
        transaction: &mut ArtifactTransaction,
    ) -> Result<(), ArtifactError> {
        if !transaction.streams_touched {
            return Ok(());
        }
        let (Some(store), Some(namespace)) = (
            self.artifact_store.as_ref(),
            self.artifact_namespace.as_ref(),
        ) else {
            return Err(ArtifactError::Unavailable);
        };
        store.discard_streams(namespace.clone()).await?;
        transaction.streams.clear();
        transaction.streams_touched = false;
        Ok(())
    }

    async fn discard_artifact_stages(
        &self,
        transaction: &mut ArtifactTransaction,
    ) -> Result<(), ArtifactError> {
        if transaction.stages.is_empty() {
            return Ok(());
        }
        let (Some(store), Some(namespace)) = (
            self.artifact_store.as_ref(),
            self.artifact_namespace.as_ref(),
        ) else {
            return Err(ArtifactError::Unavailable);
        };
        store
            .discard_staged(namespace.clone(), transaction.stages.clone())
            .await?;
        transaction.stages.clear();
        Ok(())
    }

    async fn discard_recorded_artifact_stage(
        &self,
        transaction: &mut ArtifactTransaction,
        stage: ArtifactStage,
    ) -> Result<(), ArtifactError> {
        let (Some(store), Some(namespace)) = (
            self.artifact_store.as_ref(),
            self.artifact_namespace.as_ref(),
        ) else {
            return Err(ArtifactError::Unavailable);
        };
        let Some(index) = transaction
            .stages
            .iter()
            .position(|candidate| candidate == &stage)
        else {
            return Err(ArtifactError::ReceiptMismatch);
        };
        store.discard_staged(namespace.clone(), vec![stage]).await?;
        transaction.stages.remove(index);
        Ok(())
    }

    async fn next_ref_expiry(&self) -> Option<Instant> {
        self.refs.lock().await.next_expiry()
    }

    async fn evict_expired_refs(&self, now: Instant) -> usize {
        self.refs.lock().await.evict_expired(now)
    }

    fn notify_ref_change(&self) {
        self.ref_changed.notify_one();
    }

    fn subscribe(&self) -> watch::Receiver<bool> {
        self.cancellation.subscribe()
    }
}

fn artifact_transaction_accepts(transaction: &ArtifactTransaction, run_id: &str) -> bool {
    transaction.accepting && transaction.run_id.as_deref() == Some(run_id)
}

/// Stateful orchestration for the v0 application tools.
#[derive(Clone)]
pub struct Application {
    inner: Arc<ApplicationInner>,
    audit_sink: Option<Arc<dyn AuditSink>>,
    artifact_store: Option<Arc<dyn ArtifactStore>>,
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
        let schema_index = default_schema_index()?;
        Self::from_parts(
            config,
            registry,
            profile_source,
            binding_validator,
            worker_factory,
            None,
            schema_index,
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
        let schema_index = default_schema_index()?;
        Self::from_parts(
            config,
            registry,
            profile_source,
            binding_validator,
            worker_factory,
            Some(host_client_factory),
            schema_index,
            policy_hash.into(),
            policy_version.into(),
        )
    }

    /// Construct a fully executable application with an explicitly aligned
    /// offline schema index.
    #[allow(clippy::too_many_arguments)]
    pub fn from_arcs_with_host_clients_and_schema(
        config: Config,
        registry: ContextRegistry,
        profile_source: Arc<dyn ProfileSource>,
        binding_validator: Arc<dyn BindingValidator>,
        worker_factory: Arc<dyn WorkerFactory>,
        host_client_factory: Arc<dyn HttpClientFactory>,
        schema_index: Arc<SchemaIndex>,
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
            schema_index,
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
        schema_index: Arc<SchemaIndex>,
        policy_hash: String,
        policy_version: String,
    ) -> Result<Self, AppError> {
        config
            .validate()
            .map_err(|_| AppError::new(AppErrorCode::InvalidConfiguration))?;
        if policy_hash.is_empty() || policy_version.is_empty() {
            return Err(AppError::new(AppErrorCode::InvalidConfiguration));
        }
        if schema_index.policy_hash() != policy_hash
            || schema_index.policy_version() != policy_version
        {
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
                schema_index,
                workers: Mutex::new(HashMap::new()),
            }),
            audit_sink: None,
            artifact_store: None,
        })
    }

    /// Attach the durable, redacted request log required by the MCP server.
    pub fn with_audit_sink(mut self, audit_sink: Arc<dyn AuditSink>) -> Self {
        self.audit_sink = Some(audit_sink);
        self
    }

    /// Attach the bounded, private JSON store used by the managed local helper.
    pub fn with_artifact_store(mut self, artifact_store: Arc<dyn ArtifactStore>) -> Self {
        self.artifact_store = Some(artifact_store);
        self
    }

    /// Clone the underlying registry for diagnostics or deterministic tests.
    pub fn registry(&self) -> ContextRegistry {
        self.inner.registry.clone()
    }

    /// Whether the reviewed JavaScript host helpers have a real semantic boundary.
    pub fn host_calls_ready(&self) -> bool {
        self.inner.host_client_factory.is_some()
    }

    /// Whether the application can durably record executable host calls.
    pub fn audit_ready(&self) -> bool {
        self.audit_sink.is_some()
    }

    /// Whether managed JSON artifact writes have a real storage boundary.
    pub fn artifact_writes_ready(&self) -> bool {
        self.artifact_store.is_some()
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

    /// Search reviewed route and helper metadata without acquiring credentials or
    /// touching the worker or HTTP client.
    pub async fn schema_search(
        &self,
        args: SchemaSearchArgs,
    ) -> Result<SchemaSearchResult, AppError> {
        let limit = args
            .limit()
            .map_err(|_| AppError::new(AppErrorCode::InvalidInput))?;
        let id = parse_context_id(&args.context_id)?;
        self.reap_expired_workers(Instant::now()).await;
        let lease = match self.inner.registry.lease(id.as_str(), Instant::now()) {
            Ok(lease) => lease,
            Err(ContextRegistryError::ContextEvicted) => {
                let _ = self.close_worker(&id).await;
                return Err(AppError::new(AppErrorCode::ContextEvicted));
            }
            Err(error) => return Err(map_registry_error(error)),
        };
        let result = self
            .inner
            .schema_index
            .search(lease.context(), &args.query, args.cloud, limit)
            .map_err(map_schema_error)?;
        Ok(SchemaSearchResult {
            policy_hash: lease.context().policy_hash().to_owned(),
            policy_version: result.policy_version,
            query: args.query,
            results: result.results,
            omitted: result.omitted,
        })
    }

    /// Get one exact reviewed route/helper entry and API version without any Azure
    /// or worker activity.
    pub async fn schema_get(&self, args: SchemaGetArgs) -> Result<SchemaGetResult, AppError> {
        args.validate()
            .map_err(|_| AppError::new(AppErrorCode::InvalidInput))?;
        let id = parse_context_id(&args.context_id)?;
        self.reap_expired_workers(Instant::now()).await;
        let lease = match self.inner.registry.lease(id.as_str(), Instant::now()) {
            Ok(lease) => lease,
            Err(ContextRegistryError::ContextEvicted) => {
                let _ = self.close_worker(&id).await;
                return Err(AppError::new(AppErrorCode::ContextEvicted));
            }
            Err(error) => return Err(map_registry_error(error)),
        };
        let schema = self
            .inner
            .schema_index
            .get(lease.context(), &args.entry_id, &args.api_version)
            .map_err(map_schema_error)?;
        Ok(SchemaGetResult {
            policy_hash: lease.context().policy_hash().to_owned(),
            policy_version: self.inner.schema_index.policy_version().to_owned(),
            schema,
        })
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
        let logs_scopes = resolve_logs_scopes(&args, &bindings)?;
        let options = ContextOptions::new(
            Identity::User,
            ArmTier::Inspect,
            args.data_planes.clone(),
            bindings.clone(),
            self.inner.policy_hash.clone(),
            self.inner.policy_version.clone(),
        )
        .and_then(|options| options.with_binding_sources(binding_sources))
        .and_then(|options| options.with_graph_scopes(graph_scopes))
        .and_then(|options| options.with_logs_scopes(logs_scopes))
        .and_then(|options| options.with_local_capabilities(args.local_capabilities.clone()))
        .map_err(|_| AppError::new(AppErrorCode::InvalidInput))?;

        let (artifact_namespace, artifact_store) = if options
            .local_capabilities()
            .iter()
            .any(|capability| capability == ARTIFACTS_WRITE_CAPABILITY)
        {
            let store = self
                .artifact_store
                .as_ref()
                .ok_or_else(|| AppError::new(AppErrorCode::CapabilityDenied))?;
            (
                Some(
                    store
                        .allocate_namespace()
                        .map_err(|_| AppError::new(AppErrorCode::UpstreamError))?,
                ),
                Some(Arc::clone(store)),
            )
        } else {
            (None, None)
        };

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
        let slot = Arc::new(
            WorkerSlot::new(worker, identity_pin)
                .with_artifact_binding(artifact_namespace, artifact_store),
        );
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
            data_planes: context.data_planes().to_vec(),
            local_capabilities: context.local_capabilities().to_vec(),
            resolved_bindings: resolved_binding_results(&context),
            allowed_subscriptions: allowed_subscription_results(&context),
            graph_scopes: graph_scope_results(&context),
            logs_scopes: logs_scope_results(&context),
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
        if worker.begin_artifact_run(&correlation_id).await.is_err() {
            let _ = self.inner.registry.close(id.as_str());
            let _ = self.close_worker(id.as_str()).await;
            abort_guard.disarm();
            return Err(AppError::new(AppErrorCode::UpstreamError));
        }
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
        let ref_worker = Arc::clone(&worker);
        let adapter_for_handler = adapter.clone();
        let artifact_audit = self.audit_sink.clone();
        let artifact_correlation_id = correlation_id.clone();
        let artifact_error = Arc::new(std::sync::Mutex::new(None));
        let artifact_error_for_handler = Arc::clone(&artifact_error);
        let host_handler = Some(Arc::new(move |request: HostCallRequest| {
            let ref_worker = Arc::clone(&ref_worker);
            let adapter = adapter_for_handler.clone();
            let artifact_audit = artifact_audit.clone();
            let artifact_correlation_id = artifact_correlation_id.clone();
            let artifact_error = Arc::clone(&artifact_error_for_handler);
            Box::pin(async move {
                if request.method == HOST_METHOD_REF {
                    handle_ref_host_call(ref_worker, request).await
                } else if request.method == HOST_METHOD_ARTIFACT_WRITE_JSON {
                    handle_artifact_host_call(
                        ref_worker,
                        artifact_audit,
                        artifact_correlation_id.clone(),
                        artifact_error,
                        request,
                    )
                    .await
                } else if request.method == HOST_METHOD_ARTIFACT_WRITE_JSON_ARRAY
                    || request.method == HOST_METHOD_ARTIFACT_WRITE_JSON_LINES
                {
                    handle_artifact_stream_host_call(
                        ref_worker,
                        artifact_audit,
                        artifact_correlation_id,
                        artifact_error,
                        request,
                    )
                    .await
                } else if let Some(adapter) = adapter {
                    adapter.handle(request).await
                } else {
                    HostCallResult::failure(&request, "host calls are unavailable")
                }
            }) as crate::worker::HostCallFuture
        }) as HostCallHandler);
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
            Ok(mut result) => {
                let context = context_summary(lease.context());
                let records = match adapter {
                    Some(adapter) => adapter.take_records(),
                    None => CallRecords {
                        calls: Vec::new(),
                        calls_omitted: 0,
                    },
                };
                let value = match result.ref_candidate.take() {
                    Some(candidate) => materialize_ref(&worker, candidate).await,
                    None => Ok(std::mem::take(&mut result.value)),
                };
                match value {
                    Ok(value) => match worker.commit_pending_artifacts(&correlation_id).await {
                        Ok(()) => {
                            drop(lease);
                            run_result(value, result, records, context, correlation_id)
                        }
                        Err(error) => {
                            let rollback_failed =
                                worker.rollback_pending_artifacts().await.is_err();
                            drop(lease);
                            let _ = self.inner.registry.close(id.as_str());
                            let _ = self.close_worker(id.as_str()).await;
                            let code = if rollback_failed {
                                AppErrorCode::UpstreamError
                            } else {
                                map_artifact_error(error)
                            };
                            Err(AppError::new(code))
                        }
                    },
                    Err(error) => {
                        let rollback_failed = worker.rollback_pending_artifacts().await.is_err();
                        drop(lease);
                        let _ = self.inner.registry.close(id.as_str());
                        let _ = self.close_worker(id.as_str()).await;
                        if rollback_failed {
                            Err(AppError::new(AppErrorCode::UpstreamError))
                        } else {
                            Err(error)
                        }
                    }
                }
            }
            Err(error) => {
                let rollback_failed = worker.rollback_pending_artifacts().await.is_err();
                let host_error = match &adapter {
                    Some(adapter) => adapter.take_last_error(),
                    None => None,
                };
                let artifact_error = artifact_error
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                let worker_needs_eviction = matches!(
                    error,
                    DependencyError::ExecutionTimeout | DependencyError::WorkerCrashed
                );
                let app_error = if rollback_failed {
                    AppError::new(AppErrorCode::UpstreamError)
                } else {
                    host_error
                        .map(map_host_error)
                        .or_else(|| artifact_error.map(AppError::new))
                        .unwrap_or_else(|| map_worker_dependency(error))
                };
                if worker_needs_eviction || rollback_failed {
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
                let next_ref_expiry = slot.next_ref_expiry().await;
                let next_expiry = next_ref_expiry
                    .filter(|ref_expiry| *ref_expiry < expiration)
                    .unwrap_or(expiration);
                let delay = next_expiry.saturating_duration_since(Instant::now());
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = slot.ref_changed.notified() => { continue; }
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
                    if slot
                        .next_ref_expiry()
                        .await
                        .is_some_and(|ref_expiry| ref_expiry <= now)
                    {
                        slot.evict_expired_refs(now).await;
                    }
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
    let cleanup = worker.cancel().await;
    let Ok(mut handle) = worker.worker.try_lock() else {
        // An active run owns the worker mutex and will hard-terminate it
        // after observing the cancellation signal.
        return cleanup.map_err(|_| AppError::new(AppErrorCode::UpstreamError));
    };
    let terminated = handle
        .terminate()
        .await
        .map_err(|_| AppError::new(AppErrorCode::WorkerCloseFailed));
    cleanup.map_err(|_| AppError::new(AppErrorCode::UpstreamError))?;
    terminated
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

fn resolve_logs_scopes(
    args: &ContextOpenArgs,
    bindings: &[ResolvedCloudBinding],
) -> Result<BTreeMap<AzureCloud, LogsScope>, AppError> {
    for cloud in [AzureCloud::AzureCloud, AzureCloud::AzureUSGovernment] {
        if args.logs_scopes.get(cloud).is_some()
            && !bindings.iter().any(|binding| binding.cloud() == cloud)
        {
            return Err(AppError::new(AppErrorCode::InvalidInput));
        }
    }
    let mut scopes = BTreeMap::new();
    for binding in bindings {
        if args.logs_scopes.get(binding.cloud()).is_some() {
            scopes.insert(binding.cloud(), LogsScope::AllAccessible);
        }
    }
    Ok(scopes)
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

fn logs_scope_results(context: &Context) -> LogsScopeOverrides {
    let mut result = LogsScopeOverrides::default();
    for cloud in context.logs_scopes().keys() {
        let scope = crate::tools::LogsAllAccessibleArgs {
            scope: crate::tools::AllAccessibleScope::AllAccessible,
        };
        match cloud {
            AzureCloud::AzureCloud => result.commercial = Some(scope),
            AzureCloud::AzureUSGovernment => result.government = Some(scope),
        }
    }
    result
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

fn default_schema_index() -> Result<Arc<SchemaIndex>, AppError> {
    let policy = azmcp_core::routes::v0_policy()
        .map_err(|_| AppError::new(AppErrorCode::InvalidConfiguration))?;
    let index =
        SchemaIndex::v0(&policy).map_err(|_| AppError::new(AppErrorCode::InvalidConfiguration))?;
    Ok(Arc::new(index))
}

fn map_schema_error(error: SchemaError) -> AppError {
    AppError::new(match error {
        SchemaError::InvalidQuery
        | SchemaError::InvalidLimit
        | SchemaError::UnrepresentablePath => AppErrorCode::InvalidInput,
        SchemaError::CloudNotBound => AppErrorCode::SchemaCloudNotBound,
        SchemaError::EntryNotFound => AppErrorCode::SchemaNotFound,
        SchemaError::ApiVersionNotFound => AppErrorCode::SchemaVersionNotFound,
        SchemaError::PolicyMismatch
        | SchemaError::DuplicateEntry
        | SchemaError::UnreviewedSource
        | SchemaError::MissingSource
        | SchemaError::InvalidSchema
        | SchemaError::Manifest(_) => AppErrorCode::SchemaUnavailable,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RefHostCallArguments {
    ref_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ArtifactWriteJsonArguments {
    name: String,
    value: Value,
}

async fn handle_artifact_host_call(
    worker: Arc<WorkerSlot>,
    audit: Option<Arc<dyn AuditSink>>,
    correlation_id: String,
    last_error: Arc<std::sync::Mutex<Option<AppErrorCode>>>,
    request: HostCallRequest,
) -> HostCallResult {
    let Some(namespace) = worker.artifact_namespace.clone() else {
        record_artifact_error(&last_error, AppErrorCode::CapabilityDenied);
        return HostCallResult::failure(&request, "artifact writing is not granted");
    };
    let Some(store) = worker.artifact_store.clone() else {
        record_artifact_error(&last_error, AppErrorCode::UpstreamError);
        return HostCallResult::failure(&request, "artifact storage is unavailable");
    };
    let Some(audit) = audit else {
        record_artifact_error(&last_error, AppErrorCode::UpstreamError);
        return HostCallResult::failure(&request, "artifact audit is unavailable");
    };
    let arguments =
        match serde_json::from_value::<ArtifactWriteJsonArguments>(request.arguments.clone()) {
            Ok(arguments) => arguments,
            Err(_) => {
                record_artifact_error(&last_error, AppErrorCode::InvalidInput);
                return HostCallResult::failure(&request, "invalid artifact arguments");
            }
        };
    let transaction_worker = Arc::clone(&worker);
    let run_id = correlation_id.clone();
    let transaction = tokio::spawn(async move {
        let prepared = store
            .prepare_json(arguments.name, arguments.value)
            .map_err(|error| (map_artifact_error(error), "artifact write was rejected"))?;
        let mut state = transaction_worker.artifact_transaction.lock().await;
        if *transaction_worker.cancellation.borrow()
            || !artifact_transaction_accepts(&state, &run_id)
        {
            return Err((
                AppErrorCode::UpstreamError,
                "artifact context is unavailable",
            ));
        }
        if audit.prepare().is_err() {
            return Err((AppErrorCode::UpstreamError, "artifact audit is unavailable"));
        }
        let audit_record = ArtifactWriteAuditRecord::authorized(
            correlation_id,
            HOST_METHOD_ARTIFACT_WRITE_JSON,
            prepared.bytes(),
            prepared.bytes(),
            None,
            "application/json",
        );
        if audit.append_artifact(&audit_record).is_err() {
            return Err((AppErrorCode::UpstreamError, "artifact audit is unavailable"));
        }
        let stage = store
            .stage_prepared(namespace.clone(), prepared)
            .await
            .map_err(|error| (map_artifact_error(error), "artifact write was rejected"))?;
        state.stages.push(stage.clone());
        if *transaction_worker.cancellation.borrow() {
            transaction_worker
                .discard_recorded_artifact_stage(&mut state, stage)
                .await
                .map_err(|_| {
                    (
                        AppErrorCode::UpstreamError,
                        "artifact cleanup is unavailable",
                    )
                })?;
            return Err((
                AppErrorCode::UpstreamError,
                "artifact context is unavailable",
            ));
        }
        let value = serde_json::to_value(stage.receipt()).map_err(|_| {
            (
                AppErrorCode::UpstreamError,
                "artifact receipt is unavailable",
            )
        });
        let value = match value {
            Ok(value) => value,
            Err(error) => {
                if transaction_worker
                    .discard_recorded_artifact_stage(&mut state, stage)
                    .await
                    .is_err()
                {
                    return Err((
                        AppErrorCode::UpstreamError,
                        "artifact cleanup is unavailable",
                    ));
                }
                return Err(error);
            }
        };
        Ok(value)
    });
    match transaction.await {
        Ok(Ok(value)) => HostCallResult::success(&request, value),
        Ok(Err((code, message))) => {
            record_artifact_error(&last_error, code);
            HostCallResult::failure(&request, message)
        }
        Err(_) => {
            record_artifact_error(&last_error, AppErrorCode::UpstreamError);
            HostCallResult::failure(&request, "artifact storage is unavailable")
        }
    }
}

async fn handle_artifact_stream_host_call(
    worker: Arc<WorkerSlot>,
    audit: Option<Arc<dyn AuditSink>>,
    run_correlation_id: String,
    last_error: Arc<std::sync::Mutex<Option<AppErrorCode>>>,
    request: HostCallRequest,
) -> HostCallResult {
    let Some(namespace) = worker.artifact_namespace.clone() else {
        record_artifact_error(&last_error, AppErrorCode::CapabilityDenied);
        return HostCallResult::failure(&request, "artifact writing is not granted");
    };
    let Some(store) = worker.artifact_store.clone() else {
        record_artifact_error(&last_error, AppErrorCode::UpstreamError);
        return HostCallResult::failure(&request, "artifact storage is unavailable");
    };
    let Some(audit) = audit else {
        record_artifact_error(&last_error, AppErrorCode::UpstreamError);
        return HostCallResult::failure(&request, "artifact audit is unavailable");
    };
    let (format, operation) = match request.method.as_str() {
        HOST_METHOD_ARTIFACT_WRITE_JSON_ARRAY => (
            ArtifactStreamFormat::JsonArray,
            HOST_METHOD_ARTIFACT_WRITE_JSON_ARRAY,
        ),
        HOST_METHOD_ARTIFACT_WRITE_JSON_LINES => (
            ArtifactStreamFormat::JsonLines,
            HOST_METHOD_ARTIFACT_WRITE_JSON_LINES,
        ),
        _ => {
            record_artifact_error(&last_error, AppErrorCode::InvalidInput);
            return HostCallResult::failure(&request, "invalid artifact stream method");
        }
    };
    let arguments =
        match serde_json::from_value::<ArtifactWriteJsonStreamArguments>(request.arguments.clone())
        {
            Ok(arguments) if arguments.validate().is_ok() => arguments,
            _ => {
                record_artifact_error(&last_error, AppErrorCode::InvalidInput);
                return HostCallResult::failure(&request, "invalid artifact stream arguments");
            }
        };

    let transaction_worker = Arc::clone(&worker);
    let run_id = run_correlation_id.clone();
    let transaction = tokio::spawn(async move {
        match arguments {
            ArtifactWriteJsonStreamArguments::Begin { name, compression } => {
                if audit.prepare().is_err() {
                    return Err((AppErrorCode::UpstreamError, "artifact audit is unavailable"));
                }
                let compression = match compression {
                    ArtifactWriteCompression::Identity => ArtifactCompression::Identity,
                    ArtifactWriteCompression::Lz4 => ArtifactCompression::Lz4Frame,
                };
                let external_id = format!(
                    "stream_{}",
                    correlation_id().map_err(|_| {
                        (
                            AppErrorCode::CorrelationUnavailable,
                            "artifact stream ID is unavailable",
                        )
                    })?
                );
                let mut state = transaction_worker.artifact_transaction.lock().await;
                if *transaction_worker.cancellation.borrow()
                    || !artifact_transaction_accepts(&state, &run_id)
                {
                    return Err((
                        AppErrorCode::UpstreamError,
                        "artifact context is unavailable",
                    ));
                }
                state.streams_touched = true;
                let stream = store
                    .begin_json_stream(namespace.clone(), name, compression, format)
                    .await
                    .map_err(|error| (map_artifact_error(error), "artifact stream was rejected"))?;
                if *transaction_worker.cancellation.borrow() {
                    store
                        .discard_stream(namespace.clone(), stream)
                        .await
                        .map_err(|_| {
                            (
                                AppErrorCode::UpstreamError,
                                "artifact cleanup is unavailable",
                            )
                        })?;
                    return Err((
                        AppErrorCode::UpstreamError,
                        "artifact context is unavailable",
                    ));
                }
                if state.streams.contains_key(&external_id) {
                    store
                        .discard_stream(namespace.clone(), stream)
                        .await
                        .map_err(|_| {
                            (
                                AppErrorCode::UpstreamError,
                                "artifact cleanup is unavailable",
                            )
                        })?;
                    return Err((
                        AppErrorCode::CorrelationUnavailable,
                        "artifact stream ID is unavailable",
                    ));
                }
                state.streams.insert(
                    external_id.clone(),
                    ActiveArtifactStream {
                        stream,
                        format,
                        compression,
                        next_sequence: 0,
                        items: 0,
                    },
                );
                serde_json::to_value(ArtifactWriteJsonStreamBeginResult {
                    stream_id: external_id,
                })
                .map_err(|_| {
                    (
                        AppErrorCode::UpstreamError,
                        "artifact receipt is unavailable",
                    )
                })
            }
            ArtifactWriteJsonStreamArguments::Append {
                stream_id,
                sequence,
                values,
            } => {
                let mut state = transaction_worker.artifact_transaction.lock().await;
                if *transaction_worker.cancellation.borrow()
                    || !artifact_transaction_accepts(&state, &run_id)
                {
                    return Err((
                        AppErrorCode::UpstreamError,
                        "artifact context is unavailable",
                    ));
                }
                let Some(mut active) = state.streams.remove(&stream_id) else {
                    return Err((AppErrorCode::InvalidInput, "artifact stream is unavailable"));
                };
                if active.format != format
                    || active.format != active.stream.format()
                    || active.compression != active.stream.compression()
                    || active.next_sequence != sequence
                {
                    state.streams.insert(stream_id, active);
                    return Err((
                        AppErrorCode::InvalidInput,
                        "artifact stream sequence is invalid",
                    ));
                }
                let added_items = u64::try_from(values.len()).map_err(|_| {
                    (
                        AppErrorCode::ResultTooLarge,
                        "artifact stream item count is too large",
                    )
                })?;
                let next_items = active.items.checked_add(added_items).ok_or((
                    AppErrorCode::ResultTooLarge,
                    "artifact stream item count is too large",
                ))?;
                active.stream = store
                    .append_json_array(namespace.clone(), active.stream, values)
                    .await
                    .map_err(|error| (map_artifact_error(error), "artifact stream was rejected"))?;
                if *transaction_worker.cancellation.borrow() {
                    store
                        .discard_stream(namespace.clone(), active.stream)
                        .await
                        .map_err(|_| {
                            (
                                AppErrorCode::UpstreamError,
                                "artifact cleanup is unavailable",
                            )
                        })?;
                    return Err((
                        AppErrorCode::UpstreamError,
                        "artifact context is unavailable",
                    ));
                }
                active.next_sequence = active.next_sequence.checked_add(1).ok_or((
                    AppErrorCode::ResultTooLarge,
                    "artifact stream chunk count is too large",
                ))?;
                active.items = next_items;
                state.streams.insert(stream_id, active);
                serde_json::to_value(ArtifactWriteJsonStreamAppendResult {
                    accepted_sequence: sequence,
                })
                .map_err(|_| {
                    (
                        AppErrorCode::UpstreamError,
                        "artifact acknowledgement is unavailable",
                    )
                })
            }
            ArtifactWriteJsonStreamArguments::Finish {
                stream_id,
                chunks,
                items,
            } => {
                let mut state = transaction_worker.artifact_transaction.lock().await;
                if *transaction_worker.cancellation.borrow()
                    || !artifact_transaction_accepts(&state, &run_id)
                {
                    return Err((
                        AppErrorCode::UpstreamError,
                        "artifact context is unavailable",
                    ));
                }
                let Some(active) = state.streams.remove(&stream_id) else {
                    return Err((AppErrorCode::InvalidInput, "artifact stream is unavailable"));
                };
                if active.format != format
                    || active.format != active.stream.format()
                    || active.compression != active.stream.compression()
                    || active.next_sequence != chunks
                    || active.items != items
                {
                    state.streams.insert(stream_id, active);
                    return Err((
                        AppErrorCode::InvalidInput,
                        "artifact stream totals are invalid",
                    ));
                }
                let stage = store
                    .finish_json_array(namespace.clone(), active.stream)
                    .await
                    .map_err(|error| (map_artifact_error(error), "artifact stream was rejected"))?;
                state.stages.push(stage.clone());
                if *transaction_worker.cancellation.borrow() {
                    transaction_worker
                        .discard_recorded_artifact_stage(&mut state, stage)
                        .await
                        .map_err(|_| {
                            (
                                AppErrorCode::UpstreamError,
                                "artifact cleanup is unavailable",
                            )
                        })?;
                    return Err((
                        AppErrorCode::UpstreamError,
                        "artifact context is unavailable",
                    ));
                }
                let receipt = stage.receipt();
                let audit_record = ArtifactWriteAuditRecord::authorized(
                    run_correlation_id,
                    operation,
                    receipt.bytes(),
                    receipt.logical_bytes(),
                    receipt.content_encoding(),
                    receipt.media_type(),
                );
                if audit.append_artifact(&audit_record).is_err() {
                    transaction_worker
                        .discard_recorded_artifact_stage(&mut state, stage)
                        .await
                        .map_err(|_| {
                            (
                                AppErrorCode::UpstreamError,
                                "artifact cleanup is unavailable",
                            )
                        })?;
                    return Err((AppErrorCode::UpstreamError, "artifact audit is unavailable"));
                }
                let value = serde_json::to_value(receipt).map_err(|_| {
                    (
                        AppErrorCode::UpstreamError,
                        "artifact receipt is unavailable",
                    )
                });
                let value = match value {
                    Ok(value) => value,
                    Err(error) => {
                        transaction_worker
                            .discard_recorded_artifact_stage(&mut state, stage)
                            .await
                            .map_err(|_| {
                                (
                                    AppErrorCode::UpstreamError,
                                    "artifact cleanup is unavailable",
                                )
                            })?;
                        return Err(error);
                    }
                };
                Ok(value)
            }
            ArtifactWriteJsonStreamArguments::Abort { stream_id } => {
                let mut state = transaction_worker.artifact_transaction.lock().await;
                if !artifact_transaction_accepts(&state, &run_id) {
                    return serde_json::to_value(ArtifactWriteJsonStreamAbortResult {
                        aborted: false,
                    })
                    .map_err(|_| {
                        (
                            AppErrorCode::UpstreamError,
                            "artifact acknowledgement is unavailable",
                        )
                    });
                }
                let Some(active) = state.streams.remove(&stream_id) else {
                    return serde_json::to_value(ArtifactWriteJsonStreamAbortResult {
                        aborted: false,
                    })
                    .map_err(|_| {
                        (
                            AppErrorCode::UpstreamError,
                            "artifact acknowledgement is unavailable",
                        )
                    });
                };
                if active.format != format || active.format != active.stream.format() {
                    state.streams.insert(stream_id, active);
                    return serde_json::to_value(ArtifactWriteJsonStreamAbortResult {
                        aborted: false,
                    })
                    .map_err(|_| {
                        (
                            AppErrorCode::UpstreamError,
                            "artifact acknowledgement is unavailable",
                        )
                    });
                }
                store
                    .discard_stream(namespace, active.stream)
                    .await
                    .map_err(|_| {
                        (
                            AppErrorCode::UpstreamError,
                            "artifact cleanup is unavailable",
                        )
                    })?;
                serde_json::to_value(ArtifactWriteJsonStreamAbortResult { aborted: true }).map_err(
                    |_| {
                        (
                            AppErrorCode::UpstreamError,
                            "artifact acknowledgement is unavailable",
                        )
                    },
                )
            }
        }
    });
    match transaction.await {
        Ok(Ok(value)) => HostCallResult::success(&request, value),
        Ok(Err((code, message))) => {
            record_artifact_error(&last_error, code);
            HostCallResult::failure(&request, message)
        }
        Err(_) => {
            record_artifact_error(&last_error, AppErrorCode::UpstreamError);
            HostCallResult::failure(&request, "artifact storage is unavailable")
        }
    }
}

fn record_artifact_error(last_error: &std::sync::Mutex<Option<AppErrorCode>>, code: AppErrorCode) {
    *last_error
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(code);
}

fn map_artifact_error(error: ArtifactError) -> AppErrorCode {
    match error {
        ArtifactError::InvalidFileName | ArtifactError::DestinationExists => {
            AppErrorCode::InvalidInput
        }
        ArtifactError::ValueTooLarge { .. } => AppErrorCode::ResultTooLarge,
        ArtifactError::ContextCapacity | ArtifactError::RootCapacity => {
            AppErrorCode::ArtifactCapacity
        }
        ArtifactError::InvalidRoot
        | ArtifactError::InvalidLimits
        | ArtifactError::UnsupportedPlatform
        | ArtifactError::RootInUse
        | ArtifactError::UnsafeRoot
        | ArtifactError::UnsafeNamespace
        | ArtifactError::UnsafeDestination
        | ArtifactError::ReceiptMismatch
        | ArtifactError::RandomId
        | ArtifactError::Serialization
        | ArtifactError::Unavailable => AppErrorCode::UpstreamError,
    }
}

async fn handle_ref_host_call(worker: Arc<WorkerSlot>, request: HostCallRequest) -> HostCallResult {
    let arguments = match serde_json::from_value::<RefHostCallArguments>(request.arguments.clone())
    {
        Ok(arguments) => arguments,
        Err(_) => return HostCallResult::failure(&request, "invalid reference arguments"),
    };
    let id = match RefId::parse(&arguments.ref_id) {
        Ok(id) => id,
        Err(_) => return HostCallResult::failure(&request, "invalid reference id"),
    };
    let value = {
        let mut refs = worker.refs.lock().await;
        match refs.read(&id, crate::worker::MAX_REF_CANDIDATE_BYTES, Instant::now()) {
            Ok(value) => value,
            Err(_) => return HostCallResult::failure(&request, "reference is unavailable"),
        }
    };
    let encoded_bytes = match serde_json::to_vec(&value) {
        Ok(bytes) => bytes.len(),
        Err(_) => return HostCallResult::failure(&request, "reference is unavailable"),
    };
    if encoded_bytes > crate::worker::MAX_REF_CANDIDATE_BYTES
        || encoded_bytes.saturating_add(1024) > MAX_INPUT_BYTES
    {
        return HostCallResult::failure(&request, "reference exceeds the read limit");
    }
    HostCallResult::success(&request, value)
}

async fn materialize_ref(
    worker: &Arc<WorkerSlot>,
    candidate: RefCandidate,
) -> Result<Value, AppError> {
    let actual_bytes = serde_json::to_vec(&candidate.value)
        .map_err(|_| AppError::new(AppErrorCode::ResultTooLarge))?
        .len();
    let summary = ResultTooLargeSummary::from_json(
        &candidate.value,
        actual_bytes,
        crate::worker::MAX_RESULT_BYTES,
    );
    if actual_bytes != candidate.encoded_bytes
        || actual_bytes <= crate::worker::MAX_RESULT_BYTES
        || actual_bytes > crate::worker::MAX_REF_CANDIDATE_BYTES
    {
        return Err(AppError::result_too_large(Box::new(summary)));
    }
    let id = worker
        .refs
        .lock()
        .await
        .put(candidate.value, Instant::now())
        .map_err(|_| AppError::result_too_large(Box::new(summary.clone())))?;
    worker.notify_ref_change();
    let mut envelope = serde_json::to_value(summary)
        .expect("reference preview is a serializable structural summary");
    if let Value::Object(fields) = &mut envelope {
        // The token is an intentional capability handoff in the result. It is
        // never used in diagnostics, errors, or call records.
        fields.insert("__ref".to_owned(), Value::String(id.as_str().to_owned()));
        fields.insert(
            "sensitivity".to_owned(),
            Value::String("customerData".to_owned()),
        );
    }
    Ok(envelope)
}

fn run_result(
    value: Value,
    result: ExecutionResult,
    records: CallRecords,
    context: Value,
    correlation_id: String,
) -> Result<RunResult, AppError> {
    Ok(RunResult {
        value,
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
        "localCapabilities": context.local_capabilities(),
        "bindings": resolved_binding_results(context),
        "allowedSubscriptions": allowed_subscription_results(context),
        "graphScopes": graph_scope_results(context),
        "logsScopes": logs_scope_results(context),
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
    use crate::artifacts::{
        ArtifactError, ArtifactFuture, ArtifactNamespace, ArtifactStore, FileArtifactStore,
    };
    use crate::host::{ClientFactoryError, HttpClientFactory};
    use crate::refs::RefStoreLimits;
    use azmcp_core::{
        credential::TokenAudience,
        http::{ArmOrigin, BearerCredential, CredentialFuture, CredentialProvider, HttpClient},
        policy::PolicyBundle,
    };
    use serde_json::json;
    use std::{
        io::Read as _,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    };
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

    #[derive(Default)]
    struct RecordingAudit {
        records: std::sync::Mutex<Vec<CallRecord>>,
        artifact_records: std::sync::Mutex<Vec<ArtifactWriteAuditRecord>>,
        reject_artifacts: AtomicBool,
    }

    impl AuditSink for RecordingAudit {
        fn prepare(&self) -> Result<(), crate::audit::AuditError> {
            Ok(())
        }

        fn append(&self, record: &CallRecord) -> Result<(), crate::audit::AuditError> {
            self.records
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(record.clone());
            Ok(())
        }

        fn append_artifact(
            &self,
            record: &crate::audit::ArtifactWriteAuditRecord,
        ) -> Result<(), crate::audit::AuditError> {
            if self.reject_artifacts.load(Ordering::SeqCst) {
                return Err(crate::audit::AuditError::Unavailable);
            }
            self.artifact_records
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(record.clone());
            Ok(())
        }
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

    async fn validation_retry_server() -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("loopback");
        let address = listener.local_addr().expect("address");
        let task = tokio::spawn(async move {
            for attempt in 0..2 {
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
                let response = if attempt == 0 {
                    "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n".to_owned()
                } else {
                    let body = format!(r#"{{"subscriptionId":"{SUB}"}}"#);
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    )
                };
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
                    ref_candidate: None,
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

    struct RefFactory;

    struct GatedArtifactStore {
        delegate: FileArtifactStore,
        entered: Notify,
        release: Notify,
        removed: Notify,
        discard_failures: AtomicUsize,
    }

    struct CommitGatedArtifactStore {
        delegate: FileArtifactStore,
        committed: Notify,
        release: Notify,
        removed: Notify,
    }

    impl ArtifactStore for GatedArtifactStore {
        fn allocate_namespace(&self) -> Result<ArtifactNamespace, ArtifactError> {
            self.delegate.allocate_namespace()
        }

        fn prepare_json(
            &self,
            file_name: String,
            value: Value,
        ) -> Result<crate::artifacts::PreparedArtifact, ArtifactError> {
            self.delegate.prepare_json(file_name, value)
        }

        fn stage_prepared<'a>(
            &'a self,
            namespace: ArtifactNamespace,
            prepared: crate::artifacts::PreparedArtifact,
        ) -> ArtifactFuture<'a, ArtifactStage> {
            Box::pin(async move {
                self.entered.notify_one();
                self.release.notified().await;
                self.delegate.stage_prepared(namespace, prepared).await
            })
        }

        fn commit_staged<'a>(
            &'a self,
            namespace: ArtifactNamespace,
            stages: Vec<ArtifactStage>,
        ) -> ArtifactFuture<'a, ()> {
            self.delegate.commit_staged(namespace, stages)
        }

        fn finalize_staged(
            &self,
            namespace: &ArtifactNamespace,
            stages: &[ArtifactStage],
        ) -> Result<(), ArtifactError> {
            self.delegate.finalize_staged(namespace, stages)
        }

        fn discard_staged<'a>(
            &'a self,
            namespace: ArtifactNamespace,
            stages: Vec<ArtifactStage>,
        ) -> ArtifactFuture<'a, ()> {
            Box::pin(async move {
                if self
                    .discard_failures
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                        remaining.checked_sub(1)
                    })
                    .is_ok()
                {
                    return Err(ArtifactError::Unavailable);
                }
                self.delegate.discard_staged(namespace, stages).await?;
                self.removed.notify_one();
                Ok(())
            })
        }
    }

    impl ArtifactStore for CommitGatedArtifactStore {
        fn allocate_namespace(&self) -> Result<ArtifactNamespace, ArtifactError> {
            self.delegate.allocate_namespace()
        }

        fn prepare_json(
            &self,
            file_name: String,
            value: Value,
        ) -> Result<crate::artifacts::PreparedArtifact, ArtifactError> {
            self.delegate.prepare_json(file_name, value)
        }

        fn stage_prepared<'a>(
            &'a self,
            namespace: ArtifactNamespace,
            prepared: crate::artifacts::PreparedArtifact,
        ) -> ArtifactFuture<'a, ArtifactStage> {
            self.delegate.stage_prepared(namespace, prepared)
        }

        fn commit_staged<'a>(
            &'a self,
            namespace: ArtifactNamespace,
            stages: Vec<ArtifactStage>,
        ) -> ArtifactFuture<'a, ()> {
            Box::pin(async move {
                self.delegate.commit_staged(namespace, stages).await?;
                self.committed.notify_one();
                self.release.notified().await;
                Ok(())
            })
        }

        fn finalize_staged(
            &self,
            namespace: &ArtifactNamespace,
            stages: &[ArtifactStage],
        ) -> Result<(), ArtifactError> {
            self.delegate.finalize_staged(namespace, stages)
        }

        fn discard_staged<'a>(
            &'a self,
            namespace: ArtifactNamespace,
            stages: Vec<ArtifactStage>,
        ) -> ArtifactFuture<'a, ()> {
            Box::pin(async move {
                self.delegate.discard_staged(namespace, stages).await?;
                self.removed.notify_one();
                Ok(())
            })
        }
    }

    impl WorkerFactory for RefFactory {
        fn start<'a>(
            &'a self,
            _context: &'a Context,
        ) -> BoxFuture<'a, Result<Box<dyn WorkerHandle>, DependencyError>> {
            Box::pin(async { Ok(Box::new(RefWorker) as Box<dyn WorkerHandle>) })
        }
    }

    struct RefWorker;

    async fn artifact_host_call(
        handler: &HostCallHandler,
        call_id: u64,
        method: &'static str,
        arguments: Value,
    ) -> Result<Value, DependencyError> {
        let response = handler(HostCallRequest {
            id: 1,
            call_id,
            method: method.to_owned(),
            arguments,
        })
        .await;
        if !response.ok {
            return Err(DependencyError::ExecutionFailed);
        }
        response.value.ok_or(DependencyError::ExecutionFailed)
    }

    impl WorkerHandle for RefWorker {
        fn execute<'a>(
            &'a mut self,
            code: &'a str,
            _timeout: Duration,
            host_handler: Option<HostCallHandler>,
        ) -> BoxFuture<'a, Result<ExecutionResult, DependencyError>> {
            let code = code.to_owned();
            Box::pin(async move {
                if matches!(
                    code.as_str(),
                    "__artifact_stream__"
                        | "__artifact_stream_unfinished__"
                        | "__artifact_stream_abort__"
                        | "__artifact_stream_bad_totals__"
                        | "__artifact_stream_then_fail__"
                ) {
                    let Some(handler) = host_handler else {
                        return Err(DependencyError::ExecutionFailed);
                    };
                    let opened = artifact_host_call(
                        &handler,
                        1,
                        HOST_METHOD_ARTIFACT_WRITE_JSON_ARRAY,
                        json!({
                            "phase": "begin",
                            "name": "series.json",
                            "compression": "identity",
                        }),
                    )
                    .await?;
                    let stream_id = opened["streamId"]
                        .as_str()
                        .ok_or(DependencyError::ExecutionFailed)?;
                    if code == "__artifact_stream_unfinished__" {
                        return Ok(ExecutionResult {
                            value: opened,
                            logs: Vec::new(),
                            logs_omitted: 0,
                            ref_candidate: None,
                        });
                    }
                    if code == "__artifact_stream_abort__" {
                        let aborted = artifact_host_call(
                            &handler,
                            2,
                            HOST_METHOD_ARTIFACT_WRITE_JSON_ARRAY,
                            json!({"phase": "abort", "streamId": stream_id}),
                        )
                        .await?;
                        return Ok(ExecutionResult {
                            value: aborted,
                            logs: Vec::new(),
                            logs_omitted: 0,
                            ref_candidate: None,
                        });
                    }
                    artifact_host_call(
                        &handler,
                        2,
                        HOST_METHOD_ARTIFACT_WRITE_JSON_ARRAY,
                        json!({
                            "phase": "append",
                            "streamId": stream_id,
                            "sequence": 0,
                            "values": [{"timestamp": "2026-08-14T00:00:00Z", "value": 1}, 2],
                        }),
                    )
                    .await?;
                    let array_receipt = artifact_host_call(
                        &handler,
                        3,
                        HOST_METHOD_ARTIFACT_WRITE_JSON_ARRAY,
                        json!({
                            "phase": "finish",
                            "streamId": stream_id,
                            "chunks": if code == "__artifact_stream_bad_totals__" { 2 } else { 1 },
                            "items": 2,
                        }),
                    )
                    .await?;
                    if code == "__artifact_stream_then_fail__" {
                        return Err(DependencyError::ExecutionFailed);
                    }

                    let opened = artifact_host_call(
                        &handler,
                        4,
                        HOST_METHOD_ARTIFACT_WRITE_JSON_LINES,
                        json!({
                            "phase": "begin",
                            "name": "rows.jsonl.lz4",
                            "compression": "lz4",
                        }),
                    )
                    .await?;
                    let stream_id = opened["streamId"]
                        .as_str()
                        .ok_or(DependencyError::ExecutionFailed)?;
                    artifact_host_call(
                        &handler,
                        5,
                        HOST_METHOD_ARTIFACT_WRITE_JSON_LINES,
                        json!({
                            "phase": "append",
                            "streamId": stream_id,
                            "sequence": 0,
                            "values": [{"row": 1}, {"row": 2}],
                        }),
                    )
                    .await?;
                    let lines_receipt = artifact_host_call(
                        &handler,
                        6,
                        HOST_METHOD_ARTIFACT_WRITE_JSON_LINES,
                        json!({
                            "phase": "finish",
                            "streamId": stream_id,
                            "chunks": 1,
                            "items": 2,
                        }),
                    )
                    .await?;
                    return Ok(ExecutionResult {
                        value: json!({"array": array_receipt, "lines": lines_receipt}),
                        logs: Vec::new(),
                        logs_omitted: 0,
                        ref_candidate: None,
                    });
                }
                if matches!(code.as_str(), "__artifact__" | "__artifact_then_fail__") {
                    let Some(handler) = host_handler else {
                        return Err(DependencyError::ExecutionFailed);
                    };
                    let request = HostCallRequest {
                        id: 1,
                        call_id: 1,
                        method: HOST_METHOD_ARTIFACT_WRITE_JSON.to_owned(),
                        arguments: json!({
                            "name": "metrics.json",
                            "value": {"series": [1, 2, 3], "private": "do-not-audit"}
                        }),
                    };
                    let response = handler(request).await;
                    if !response.ok {
                        return Err(DependencyError::ExecutionFailed);
                    }
                    if code == "__artifact_then_fail__" {
                        return Err(DependencyError::ExecutionFailed);
                    }
                    return Ok(ExecutionResult {
                        value: response.value.ok_or(DependencyError::ExecutionFailed)?,
                        logs: Vec::new(),
                        logs_omitted: 0,
                        ref_candidate: None,
                    });
                }
                if code == "__large_ref__" {
                    let value = json!({
                        "secret": "secret-value",
                        "padding": "x".repeat(70_000),
                    });
                    let encoded_bytes = serde_json::to_vec(&value).expect("candidate JSON").len();
                    return Ok(ExecutionResult {
                        value: Value::Null,
                        logs: Vec::new(),
                        logs_omitted: 0,
                        ref_candidate: Some(RefCandidate {
                            value,
                            encoded_bytes,
                        }),
                    });
                }
                if let Some(ref_id) = code.strip_prefix("__ref__") {
                    let Some(handler) = host_handler else {
                        return Err(DependencyError::ExecutionFailed);
                    };
                    let request = HostCallRequest {
                        id: 1,
                        call_id: 1,
                        method: HOST_METHOD_REF.to_owned(),
                        arguments: json!({"refId": ref_id}),
                    };
                    let response = handler(request).await;
                    if !response.ok {
                        return Err(DependencyError::ExecutionFailed);
                    }
                    let value = response.value.ok_or(DependencyError::ExecutionFailed)?;
                    return Ok(ExecutionResult {
                        value: json!({
                            "secret": value["secret"].clone(),
                            "paddingLength": value["padding"].as_str().map(str::len),
                        }),
                        logs: Vec::new(),
                        logs_omitted: 0,
                        ref_candidate: None,
                    });
                }
                Ok(ExecutionResult {
                    value: Value::String(code),
                    logs: Vec::new(),
                    logs_omitted: 0,
                    ref_candidate: None,
                })
            })
        }

        fn close<'a>(&'a mut self) -> BoxFuture<'a, Result<(), DependencyError>> {
            Box::pin(async { Ok(()) })
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
            DEFAULT_POLICY_HASH,
            DEFAULT_POLICY_VERSION,
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

    #[test]
    fn artifact_quota_errors_have_a_specific_domain_code() {
        assert_eq!(
            map_artifact_error(ArtifactError::ContextCapacity),
            AppErrorCode::ArtifactCapacity
        );
        assert_eq!(
            map_artifact_error(ArtifactError::RootCapacity),
            AppErrorCode::ArtifactCapacity
        );
        assert_eq!(
            map_artifact_error(ArtifactError::ValueTooLarge { bytes: 2, limit: 1 }),
            AppErrorCode::ResultTooLarge
        );
    }

    fn artifact_json_files(root: &Path) -> Vec<PathBuf> {
        let mut files = std::fs::read_dir(root)
            .expect("artifact root")
            .filter_map(|entry| {
                let path = entry.expect("artifact root entry").path();
                path.is_dir().then_some(path)
            })
            .flat_map(|entry| {
                std::fs::read_dir(entry)
                    .expect("namespace")
                    .map(|file| file.expect("artifact entry").path())
            })
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .collect::<Vec<_>>();
        files.sort();
        files
    }

    fn artifact_data_files(root: &Path) -> Vec<PathBuf> {
        let mut files = std::fs::read_dir(root)
            .expect("artifact root")
            .filter_map(|entry| {
                let path = entry.expect("artifact root entry").path();
                path.is_dir().then_some(path)
            })
            .flat_map(|entry| {
                std::fs::read_dir(entry)
                    .expect("namespace")
                    .map(|file| file.expect("artifact entry").path())
            })
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| !name.starts_with('.'))
            })
            .collect::<Vec<_>>();
        files.sort();
        files
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
    async fn schema_discovery_is_offline_and_context_scoped() {
        let state = state(None);
        let application = Application::from_arcs(
            Config::empty(),
            default_registry().expect("registry"),
            Arc::new(MemoryProfileSource::new(b"not a profile".to_vec())),
            Arc::new(Validator::default()),
            factory(Arc::clone(&state)),
            DEFAULT_POLICY_HASH,
            DEFAULT_POLICY_VERSION,
        )
        .expect("application");
        let mut open = ContextOpenArgs::default();
        open.bindings.commercial = Some(crate::tools::BindingArgs {
            subscription: SUB.to_owned(),
            tenant: Some(TENANT.to_owned()),
        });
        let opened = application.context_open(open).await.expect("context");
        assert_eq!(state.starts.load(Ordering::SeqCst), 1);

        let search = application
            .schema_search(SchemaSearchArgs {
                context_id: opened.context_id.clone(),
                query: "namespace".to_owned(),
                cloud: None,
                limit: None,
            })
            .await
            .expect("schema search");
        assert_eq!(search.policy_version, DEFAULT_POLICY_VERSION);
        assert_eq!(search.results.len(), 1);
        assert_eq!(search.results[0].path_template, "/providers/{namespace}");
        assert!(search.results[0].access.executable);

        let details = application
            .schema_get(SchemaGetArgs {
                context_id: opened.context_id.clone(),
                entry_id: "AzureCloud.providers.get".to_owned(),
                api_version: azmcp_core::routes::PROVIDERS_API_VERSION.to_owned(),
            })
            .await
            .expect("schema get");
        assert_eq!(details.schema.schema_availability, "metadataOnly");
        assert!(details.schema.response_body_schema.is_none());
        assert_eq!(state.starts.load(Ordering::SeqCst), 1);
        application
            .context_close(ContextCloseArgs {
                context_id: opened.context_id,
            })
            .await
            .expect("close");
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
    async fn logs_grant_and_scope_are_explicit_per_cloud() {
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
        args.data_planes = vec!["logs.query".to_owned()];
        args.logs_scopes.commercial = Some(crate::tools::LogsAllAccessibleArgs {
            scope: crate::tools::AllAccessibleScope::AllAccessible,
        });
        let opened = application.context_open(args).await.expect("open");
        assert_eq!(opened.data_planes, vec!["logs.query"]);
        assert_eq!(
            opened.logs_scopes.commercial,
            Some(crate::tools::LogsAllAccessibleArgs {
                scope: crate::tools::AllAccessibleScope::AllAccessible,
            })
        );
        assert!(opened.logs_scopes.government.is_none());

        let mut missing_grant = ContextOpenArgs::default();
        missing_grant.bindings.commercial = Some(crate::tools::BindingArgs {
            subscription: SUB.to_owned(),
            tenant: Some(TENANT.to_owned()),
        });
        missing_grant.logs_scopes.commercial = Some(crate::tools::LogsAllAccessibleArgs {
            scope: crate::tools::AllAccessibleScope::AllAccessible,
        });
        assert_eq!(
            application
                .context_open(missing_grant)
                .await
                .expect_err("scope without data-plane grant")
                .kind(),
            AppErrorCode::InvalidInput
        );

        let mut unbound_scope = ContextOpenArgs::default();
        unbound_scope.bindings.commercial = Some(crate::tools::BindingArgs {
            subscription: SUB.to_owned(),
            tenant: Some(TENANT.to_owned()),
        });
        unbound_scope.data_planes = vec!["logs.query".to_owned()];
        unbound_scope.logs_scopes.government = Some(crate::tools::LogsAllAccessibleArgs {
            scope: crate::tools::AllAccessibleScope::AllAccessible,
        });
        assert_eq!(
            application
                .context_open(unbound_scope)
                .await
                .expect_err("scope for an unbound cloud")
                .kind(),
            AppErrorCode::InvalidInput
        );
        assert_eq!(
            validator.calls.load(Ordering::SeqCst),
            1,
            "scope invariants are rejected before live validation"
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
            DEFAULT_POLICY_HASH,
            DEFAULT_POLICY_VERSION,
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
    async fn live_validation_audit_records_retry_count() {
        let (origin, server) = validation_retry_server().await;
        let credentials = Arc::new(IdentityCredentials {
            calls: AtomicUsize::new(0),
        });
        let clients = Arc::new(ValidationClientFactory {
            credentials,
            origin,
            policy: azmcp_core::routes::v0_policy().expect("policy"),
        });
        let sink = Arc::new(RecordingAudit::default());
        let audit_sink: Arc<dyn AuditSink> = sink.clone();
        let validator = HttpBindingValidator::new(clients).with_audit_sink(
            audit_sink,
            DEFAULT_POLICY_HASH,
            DEFAULT_POLICY_VERSION,
        );
        let binding = CloudBinding::new(
            SubscriptionId::new(SUB).expect("subscription"),
            Some(TenantId::new(TENANT).expect("tenant")),
        )
        .resolve(AzureCloud::AzureCloud, &[])
        .expect("binding");

        validator
            .validate(&binding, &CredentialIdentityPin::new())
            .await
            .expect("validation after retry");
        server.await.expect("validation server");

        let records = sink
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].retry_count, 1);
        assert_eq!(records[0].status, Some(200));
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
            DEFAULT_POLICY_HASH,
            DEFAULT_POLICY_VERSION,
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
    async fn cancelling_worker_slot_disposes_context_refs() {
        let state = state(None);
        let slot = WorkerSlot::new(
            Box::new(FakeWorker {
                state: Arc::clone(&state),
            }),
            CredentialIdentityPin::new(),
        );
        let now = Instant::now();
        {
            let mut refs = slot.refs.lock().await;
            refs.put(serde_json::json!({"private": true}), now)
                .expect("reference");
            assert_eq!(refs.len(), 1);
        }

        slot.cancel().await.expect("cancel worker slot");

        assert!(slot.refs.lock().await.is_empty());
    }

    #[tokio::test]
    async fn cancelled_slot_cannot_commit_after_close_already_cleared_its_stage() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let artifact_root = temporary.path().join("artifacts");
        let store = Arc::new(FileArtifactStore::new(&artifact_root).expect("artifact store"));
        let namespace = store.allocate_namespace().expect("namespace");
        let slot = WorkerSlot::new(
            Box::new(FakeWorker { state: state(None) }),
            CredentialIdentityPin::new(),
        )
        .with_artifact_binding(Some(namespace.clone()), Some(store.clone()));
        slot.begin_artifact_run("run-1")
            .await
            .expect("artifact transaction");
        let stage = store
            .stage_prepared(
                namespace,
                store
                    .prepare_json("result.json".to_owned(), serde_json::json!({"ok": true}))
                    .expect("prepared artifact"),
            )
            .await
            .expect("staged artifact");
        slot.artifact_transaction.lock().await.stages.push(stage);

        slot.cancel().await.expect("cancel artifact slot");

        assert_eq!(
            slot.commit_pending_artifacts("run-1")
                .await
                .expect_err("cancelled slot cannot report commit success"),
            ArtifactError::Unavailable
        );
        assert!(artifact_json_files(&artifact_root).is_empty());
    }

    #[tokio::test]
    async fn idle_context_reaper_evicts_expired_refs_without_a_run() {
        let state = state(None);
        let application = app(
            profile(&row(SUB, TENANT, "AzureCloud", "alice")),
            Arc::new(Validator::default()),
            factory(Arc::clone(&state)),
        );
        let opened = application
            .context_open(ContextOpenArgs::default())
            .await
            .expect("context");
        let slot = application
            .inner
            .workers
            .lock()
            .await
            .get(&opened.context_id)
            .cloned()
            .expect("worker slot");
        {
            let mut refs = slot.refs.lock().await;
            *refs = RefStore::new(RefStoreLimits::new(
                4,
                256,
                Duration::from_millis(20),
                48,
                48,
            ))
            .expect("short test TTL");
            refs.put(serde_json::json!({"private": true}), Instant::now())
                .expect("reference");
        }
        slot.notify_ref_change();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if slot.refs.lock().await.is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("idle reaper evicted expired ref");
        application
            .context_close(ContextCloseArgs {
                context_id: opened.context_id,
            })
            .await
            .expect("close");
    }

    #[tokio::test]
    async fn context_close_waits_for_ref_store_contention_before_disposal() {
        let state = state(None);
        let application = app(
            profile(&row(SUB, TENANT, "AzureCloud", "alice")),
            Arc::new(Validator::default()),
            factory(Arc::clone(&state)),
        );
        let opened = application
            .context_open(ContextOpenArgs::default())
            .await
            .expect("context");
        let slot = application
            .inner
            .workers
            .lock()
            .await
            .get(&opened.context_id)
            .cloned()
            .expect("worker slot");
        slot.refs
            .lock()
            .await
            .put(serde_json::json!({"private": true}), Instant::now())
            .expect("reference");
        let refs_guard = slot.refs.lock().await;
        let closing = {
            let application = application.clone();
            let context_id = opened.context_id.clone();
            tokio::spawn(async move {
                application
                    .context_close(ContextCloseArgs { context_id })
                    .await
            })
        };
        tokio::task::yield_now().await;
        assert!(!closing.is_finished());
        drop(refs_guard);
        closing
            .await
            .expect("close task")
            .expect("close waits and succeeds");
        assert!(slot.refs.lock().await.is_empty());
    }

    #[tokio::test]
    async fn artifact_grant_without_storage_fails_before_live_validation() {
        let validator = Arc::new(Validator::default());
        let application = Application::from_arcs(
            Config::empty(),
            default_registry().expect("registry"),
            Arc::new(MemoryProfileSource::new(profile(&row(
                SUB,
                TENANT,
                "AzureCloud",
                "alice",
            )))),
            validator.clone(),
            Arc::new(RefFactory),
            DEFAULT_POLICY_HASH,
            DEFAULT_POLICY_VERSION,
        )
        .expect("application");
        let args = ContextOpenArgs {
            local_capabilities: vec![ARTIFACTS_WRITE_CAPABILITY.to_owned()],
            ..ContextOpenArgs::default()
        };
        assert_eq!(
            application
                .context_open(args)
                .await
                .expect_err("missing artifact storage")
                .kind(),
            AppErrorCode::CapabilityDenied
        );
        assert_eq!(validator.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn managed_artifact_write_requires_grant_and_rolls_back_failed_audit() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let artifact_root = temporary.path().join("artifacts");
        let store = Arc::new(FileArtifactStore::new(&artifact_root).expect("artifact store"));
        let audit = Arc::new(RecordingAudit::default());
        let application = Application::from_arcs(
            Config::empty(),
            default_registry().expect("registry"),
            Arc::new(MemoryProfileSource::new(profile(&row(
                SUB,
                TENANT,
                "AzureCloud",
                "alice",
            )))),
            Arc::new(Validator::default()),
            Arc::new(RefFactory),
            DEFAULT_POLICY_HASH,
            DEFAULT_POLICY_VERSION,
        )
        .expect("application")
        .with_audit_sink(audit.clone())
        .with_artifact_store(store);

        let ungranted = application
            .context_open(ContextOpenArgs::default())
            .await
            .expect("ungranted context");
        assert_eq!(
            application
                .run(RunArgs {
                    context_id: ungranted.context_id.clone(),
                    code: "__artifact__".to_owned(),
                    timeout_ms: None,
                })
                .await
                .expect_err("write without grant")
                .kind(),
            AppErrorCode::CapabilityDenied
        );
        assert!(!artifact_root.exists());
        application
            .context_close(ContextCloseArgs {
                context_id: ungranted.context_id,
            })
            .await
            .expect("close ungranted context");

        let granted_args = ContextOpenArgs {
            local_capabilities: vec![ARTIFACTS_WRITE_CAPABILITY.to_owned()],
            ..ContextOpenArgs::default()
        };
        let granted = application
            .context_open(granted_args)
            .await
            .expect("granted context");
        assert_eq!(granted.local_capabilities, vec![ARTIFACTS_WRITE_CAPABILITY]);
        let result = application
            .run(RunArgs {
                context_id: granted.context_id.clone(),
                code: "__artifact__".to_owned(),
                timeout_ms: None,
            })
            .await
            .expect("artifact write");
        assert_eq!(
            result.context["localCapabilities"],
            json!([ARTIFACTS_WRITE_CAPABILITY])
        );
        assert!(result.calls.is_empty());
        let path = PathBuf::from(result.value["path"].as_str().expect("receipt path"));
        let expected_value = json!({
            "series": [1, 2, 3],
            "private": "do-not-audit"
        });
        let mut expected_bytes = serde_json::to_vec(&expected_value).expect("expected JSON");
        expected_bytes.push(b'\n');
        assert_eq!(
            std::fs::read(&path).expect("artifact bytes"),
            expected_bytes
        );
        assert_eq!(result.value["bytes"], expected_bytes.len());
        assert_eq!(result.value["mediaType"], "application/json");
        assert_eq!(result.value["sensitivity"], "customerData");
        let artifact_records = audit
            .artifact_records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(artifact_records.len(), 1);
        assert_eq!(artifact_records[0].bytes, expected_bytes.len());
        let encoded_audit = serde_json::to_string(&artifact_records).expect("audit JSON");
        assert!(!encoded_audit.contains("metrics.json"));
        assert!(!encoded_audit.contains("do-not-audit"));
        assert!(!encoded_audit.contains(path.to_string_lossy().as_ref()));

        application
            .context_close(ContextCloseArgs {
                context_id: granted.context_id,
            })
            .await
            .expect("close granted context");
        assert_eq!(
            std::fs::read(&path).expect("artifact survives close"),
            expected_bytes
        );

        let failing_args = ContextOpenArgs {
            local_capabilities: vec![ARTIFACTS_WRITE_CAPABILITY.to_owned()],
            ..ContextOpenArgs::default()
        };
        let failing = application
            .context_open(failing_args)
            .await
            .expect("failed-run context");
        assert_eq!(
            application
                .run(RunArgs {
                    context_id: failing.context_id.clone(),
                    code: "__artifact_then_fail__".to_owned(),
                    timeout_ms: None,
                })
                .await
                .expect_err("failed run rolls back artifact")
                .kind(),
            AppErrorCode::ExecutionFailed
        );
        assert_eq!(artifact_json_files(&artifact_root), vec![path.clone()]);
        application
            .context_close(ContextCloseArgs {
                context_id: failing.context_id,
            })
            .await
            .expect("close failed-run context");

        audit.reject_artifacts.store(true, Ordering::SeqCst);
        let rejected_args = ContextOpenArgs {
            local_capabilities: vec![ARTIFACTS_WRITE_CAPABILITY.to_owned()],
            ..ContextOpenArgs::default()
        };
        let rejected = application
            .context_open(rejected_args)
            .await
            .expect("audit-failure context");
        assert_eq!(
            application
                .run(RunArgs {
                    context_id: rejected.context_id.clone(),
                    code: "__artifact__".to_owned(),
                    timeout_ms: None,
                })
                .await
                .expect_err("audit failure")
                .kind(),
            AppErrorCode::UpstreamError
        );
        assert_eq!(artifact_json_files(&artifact_root), vec![path]);
        application
            .context_close(ContextCloseArgs {
                context_id: rejected.context_id,
            })
            .await
            .expect("close audit-failure context");
    }

    #[tokio::test]
    async fn streamed_arrays_and_json_lines_publish_transactionally_with_redacted_audit() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let artifact_root = temporary.path().join("artifacts");
        let store = Arc::new(FileArtifactStore::new(&artifact_root).expect("artifact store"));
        let audit = Arc::new(RecordingAudit::default());
        let application = Application::from_arcs(
            Config::empty(),
            default_registry().expect("registry"),
            Arc::new(MemoryProfileSource::new(profile(&row(
                SUB,
                TENANT,
                "AzureCloud",
                "alice",
            )))),
            Arc::new(Validator::default()),
            Arc::new(RefFactory),
            DEFAULT_POLICY_HASH,
            DEFAULT_POLICY_VERSION,
        )
        .expect("application")
        .with_audit_sink(audit.clone())
        .with_artifact_store(store);
        let granted = application
            .context_open(ContextOpenArgs {
                local_capabilities: vec![ARTIFACTS_WRITE_CAPABILITY.to_owned()],
                ..ContextOpenArgs::default()
            })
            .await
            .expect("context");

        let result = application
            .run(RunArgs {
                context_id: granted.context_id.clone(),
                code: "__artifact_stream__".to_owned(),
                timeout_ms: None,
            })
            .await
            .expect("streamed artifacts");
        let array_path = PathBuf::from(
            result.value["array"]["path"]
                .as_str()
                .expect("array receipt path"),
        );
        let lines_path = PathBuf::from(
            result.value["lines"]["path"]
                .as_str()
                .expect("lines receipt path"),
        );
        assert_eq!(
            std::fs::read(&array_path).expect("array bytes"),
            br#"[{"timestamp":"2026-08-14T00:00:00Z","value":1},2]
"#
        );
        let compressed = std::fs::read(&lines_path).expect("compressed JSON Lines");
        let mut decoded = Vec::new();
        lz4_flex::frame::FrameDecoder::new(compressed.as_slice())
            .read_to_end(&mut decoded)
            .expect("decode LZ4 frame");
        assert_eq!(decoded, b"{\"row\":1}\n{\"row\":2}\n");
        assert_eq!(result.value["array"]["mediaType"], "application/json");
        assert!(result.value["array"].get("contentEncoding").is_none());
        assert_eq!(result.value["lines"]["mediaType"], "application/x-ndjson");
        assert_eq!(result.value["lines"]["contentEncoding"], "lz4");
        assert_eq!(
            result.value["lines"]["bytes"],
            u64::try_from(compressed.len()).unwrap()
        );
        assert_eq!(
            result.value["lines"]["logicalBytes"],
            u64::try_from(decoded.len()).unwrap()
        );
        assert_eq!(artifact_data_files(&artifact_root).len(), 2);

        let records = audit
            .artifact_records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].operation, HOST_METHOD_ARTIFACT_WRITE_JSON_ARRAY);
        assert_eq!(records[0].media_type, "application/json");
        assert_eq!(records[1].operation, HOST_METHOD_ARTIFACT_WRITE_JSON_LINES);
        assert_eq!(records[1].content_encoding, Some("lz4"));
        let encoded_audit = serde_json::to_string(&records).expect("audit JSON");
        assert!(!encoded_audit.contains("series.json"));
        assert!(!encoded_audit.contains("rows.jsonl"));
        assert!(!encoded_audit.contains("timestamp"));

        let failed = application
            .context_open(ContextOpenArgs {
                local_capabilities: vec![ARTIFACTS_WRITE_CAPABILITY.to_owned()],
                ..ContextOpenArgs::default()
            })
            .await
            .expect("failed-run context");
        assert_eq!(
            application
                .run(RunArgs {
                    context_id: failed.context_id,
                    code: "__artifact_stream_then_fail__".to_owned(),
                    timeout_ms: None,
                })
                .await
                .expect_err("failed run rolls back finished stream")
                .kind(),
            AppErrorCode::ExecutionFailed
        );
        assert_eq!(artifact_data_files(&artifact_root).len(), 2);

        let unfinished = application
            .context_open(ContextOpenArgs {
                local_capabilities: vec![ARTIFACTS_WRITE_CAPABILITY.to_owned()],
                ..ContextOpenArgs::default()
            })
            .await
            .expect("unfinished-stream context");
        assert_eq!(
            application
                .run(RunArgs {
                    context_id: unfinished.context_id,
                    code: "__artifact_stream_unfinished__".to_owned(),
                    timeout_ms: None,
                })
                .await
                .expect_err("unfinished stream rejects successful run")
                .kind(),
            AppErrorCode::UpstreamError
        );
        assert_eq!(artifact_data_files(&artifact_root).len(), 2);

        let aborted = application
            .context_open(ContextOpenArgs {
                local_capabilities: vec![ARTIFACTS_WRITE_CAPABILITY.to_owned()],
                ..ContextOpenArgs::default()
            })
            .await
            .expect("aborted-stream context");
        let aborted = application
            .run(RunArgs {
                context_id: aborted.context_id,
                code: "__artifact_stream_abort__".to_owned(),
                timeout_ms: None,
            })
            .await
            .expect("explicit stream abort");
        assert_eq!(aborted.value, json!({"aborted": true}));
        assert_eq!(artifact_data_files(&artifact_root).len(), 2);

        let invalid = application
            .context_open(ContextOpenArgs {
                local_capabilities: vec![ARTIFACTS_WRITE_CAPABILITY.to_owned()],
                ..ContextOpenArgs::default()
            })
            .await
            .expect("invalid-totals context");
        assert_eq!(
            application
                .run(RunArgs {
                    context_id: invalid.context_id,
                    code: "__artifact_stream_bad_totals__".to_owned(),
                    timeout_ms: None,
                })
                .await
                .expect_err("parent rejects mismatched stream totals")
                .kind(),
            AppErrorCode::InvalidInput
        );
        assert_eq!(artifact_data_files(&artifact_root).len(), 2);

        audit.reject_artifacts.store(true, Ordering::SeqCst);
        let rejected = application
            .context_open(ContextOpenArgs {
                local_capabilities: vec![ARTIFACTS_WRITE_CAPABILITY.to_owned()],
                ..ContextOpenArgs::default()
            })
            .await
            .expect("audit-failure context");
        assert_eq!(
            application
                .run(RunArgs {
                    context_id: rejected.context_id,
                    code: "__artifact_stream__".to_owned(),
                    timeout_ms: None,
                })
                .await
                .expect_err("stream audit failure removes its stage")
                .kind(),
            AppErrorCode::UpstreamError
        );
        assert_eq!(artifact_data_files(&artifact_root).len(), 2);
        audit.reject_artifacts.store(false, Ordering::SeqCst);

        application
            .context_close(ContextCloseArgs {
                context_id: granted.context_id,
            })
            .await
            .expect("close successful context");
        assert!(array_path.is_file());
        assert!(lines_path.is_file());
    }

    #[tokio::test]
    async fn aborted_artifact_write_retries_failed_immediate_cleanup() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let artifact_root = temporary.path().join("artifacts");
        let store = Arc::new(GatedArtifactStore {
            delegate: FileArtifactStore::new(&artifact_root).expect("artifact store"),
            entered: Notify::new(),
            release: Notify::new(),
            removed: Notify::new(),
            discard_failures: AtomicUsize::new(1),
        });
        let audit = Arc::new(RecordingAudit::default());
        let application = Application::from_arcs(
            Config::empty(),
            default_registry().expect("registry"),
            Arc::new(MemoryProfileSource::new(profile(&row(
                SUB,
                TENANT,
                "AzureCloud",
                "alice",
            )))),
            Arc::new(Validator::default()),
            Arc::new(RefFactory),
            DEFAULT_POLICY_HASH,
            DEFAULT_POLICY_VERSION,
        )
        .expect("application")
        .with_audit_sink(audit.clone())
        .with_artifact_store(store.clone());
        let opened = application
            .context_open(ContextOpenArgs {
                local_capabilities: vec![ARTIFACTS_WRITE_CAPABILITY.to_owned()],
                ..ContextOpenArgs::default()
            })
            .await
            .expect("context");
        let running = application.clone();
        let context_id = opened.context_id.clone();
        let task = tokio::spawn(async move {
            running
                .run(RunArgs {
                    context_id,
                    code: "__artifact__".to_owned(),
                    timeout_ms: None,
                })
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), store.entered.notified())
            .await
            .expect("artifact transaction entered store");
        task.abort();
        assert!(task.await.expect_err("aborted run").is_cancelled());
        store.release.notify_one();
        tokio::time::timeout(Duration::from_secs(1), store.removed.notified())
            .await
            .expect("cancelled artifact removed");
        assert!(artifact_json_files(&artifact_root).is_empty());
        assert_eq!(
            application
                .run(RunArgs {
                    context_id: opened.context_id,
                    code: "after abort".to_owned(),
                    timeout_ms: None,
                })
                .await
                .expect_err("aborted context")
                .kind(),
            AppErrorCode::ContextNotFound
        );
        let artifact_records = audit
            .artifact_records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(artifact_records.len(), 1);
        assert_eq!(artifact_records[0].decision, "authorized");
    }

    #[tokio::test]
    async fn aborted_run_after_artifact_publication_removes_the_unreturned_file() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let artifact_root = temporary.path().join("artifacts");
        let store = Arc::new(CommitGatedArtifactStore {
            delegate: FileArtifactStore::new(&artifact_root).expect("artifact store"),
            committed: Notify::new(),
            release: Notify::new(),
            removed: Notify::new(),
        });
        let application = Application::from_arcs(
            Config::empty(),
            default_registry().expect("registry"),
            Arc::new(MemoryProfileSource::new(profile(&row(
                SUB,
                TENANT,
                "AzureCloud",
                "alice",
            )))),
            Arc::new(Validator::default()),
            Arc::new(RefFactory),
            DEFAULT_POLICY_HASH,
            DEFAULT_POLICY_VERSION,
        )
        .expect("application")
        .with_audit_sink(Arc::new(RecordingAudit::default()))
        .with_artifact_store(store.clone());
        let opened = application
            .context_open(ContextOpenArgs {
                local_capabilities: vec![ARTIFACTS_WRITE_CAPABILITY.to_owned()],
                ..ContextOpenArgs::default()
            })
            .await
            .expect("context");
        let running = application.clone();
        let context_id = opened.context_id.clone();
        let task = tokio::spawn(async move {
            running
                .run(RunArgs {
                    context_id,
                    code: "__artifact__".to_owned(),
                    timeout_ms: None,
                })
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), store.committed.notified())
            .await
            .expect("artifact reached publication boundary");
        assert_eq!(artifact_json_files(&artifact_root).len(), 1);

        task.abort();
        assert!(task.await.expect_err("aborted run").is_cancelled());
        tokio::time::timeout(Duration::from_secs(1), store.removed.notified())
            .await
            .expect("published artifact removed");
        assert!(artifact_json_files(&artifact_root).is_empty());
        assert_eq!(
            application
                .run(RunArgs {
                    context_id: opened.context_id,
                    code: "after abort".to_owned(),
                    timeout_ms: None,
                })
                .await
                .expect_err("aborted context")
                .kind(),
            AppErrorCode::ContextNotFound
        );
    }

    #[tokio::test]
    async fn aborted_last_application_after_publication_still_cleans_the_slot() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let artifact_root = temporary.path().join("artifacts");
        let store = Arc::new(CommitGatedArtifactStore {
            delegate: FileArtifactStore::new(&artifact_root).expect("artifact store"),
            committed: Notify::new(),
            release: Notify::new(),
            removed: Notify::new(),
        });
        let application = Application::from_arcs(
            Config::empty(),
            default_registry().expect("registry"),
            Arc::new(MemoryProfileSource::new(profile(&row(
                SUB,
                TENANT,
                "AzureCloud",
                "alice",
            )))),
            Arc::new(Validator::default()),
            Arc::new(RefFactory),
            DEFAULT_POLICY_HASH,
            DEFAULT_POLICY_VERSION,
        )
        .expect("application")
        .with_audit_sink(Arc::new(RecordingAudit::default()))
        .with_artifact_store(store.clone());
        let opened = application
            .context_open(ContextOpenArgs {
                local_capabilities: vec![ARTIFACTS_WRITE_CAPABILITY.to_owned()],
                ..ContextOpenArgs::default()
            })
            .await
            .expect("context");
        let running = application.clone();
        let task = tokio::spawn(async move {
            running
                .run(RunArgs {
                    context_id: opened.context_id,
                    code: "__artifact__".to_owned(),
                    timeout_ms: None,
                })
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), store.committed.notified())
            .await
            .expect("artifact reached publication boundary");
        assert_eq!(artifact_json_files(&artifact_root).len(), 1);

        drop(application);
        task.abort();
        assert!(task.await.expect_err("aborted run").is_cancelled());
        tokio::time::timeout(Duration::from_secs(1), store.removed.notified())
            .await
            .expect("published artifact removed without application inner");
        assert!(artifact_json_files(&artifact_root).is_empty());

        let second = FileArtifactStore::new(&artifact_root).expect("second store");
        let namespace = second.allocate_namespace().expect("second namespace");
        let prepared = second
            .prepare_json("after-abort.json".to_owned(), json!(null))
            .expect("prepare after abort");
        let stage = second
            .stage_prepared(namespace.clone(), prepared)
            .await
            .expect("abort cleanup releases root ownership");
        second
            .discard_staged(namespace, vec![stage])
            .await
            .expect("clean second stage");
    }

    #[tokio::test]
    async fn close_racing_artifact_commit_returns_no_deleted_receipt() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let artifact_root = temporary.path().join("artifacts");
        let store = Arc::new(CommitGatedArtifactStore {
            delegate: FileArtifactStore::new(&artifact_root).expect("artifact store"),
            committed: Notify::new(),
            release: Notify::new(),
            removed: Notify::new(),
        });
        let application = Application::from_arcs(
            Config::empty(),
            default_registry().expect("registry"),
            Arc::new(MemoryProfileSource::new(profile(&row(
                SUB,
                TENANT,
                "AzureCloud",
                "alice",
            )))),
            Arc::new(Validator::default()),
            Arc::new(RefFactory),
            DEFAULT_POLICY_HASH,
            DEFAULT_POLICY_VERSION,
        )
        .expect("application")
        .with_audit_sink(Arc::new(RecordingAudit::default()))
        .with_artifact_store(store.clone());
        let opened = application
            .context_open(ContextOpenArgs {
                local_capabilities: vec![ARTIFACTS_WRITE_CAPABILITY.to_owned()],
                ..ContextOpenArgs::default()
            })
            .await
            .expect("context");
        let running = application.clone();
        let context_id = opened.context_id.clone();
        let run_task = tokio::spawn(async move {
            running
                .run(RunArgs {
                    context_id,
                    code: "__artifact__".to_owned(),
                    timeout_ms: None,
                })
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), store.committed.notified())
            .await
            .expect("artifact reached publication boundary");
        let slot = application
            .inner
            .workers
            .lock()
            .await
            .get(opened.context_id.as_str())
            .cloned()
            .expect("worker slot");
        let mut cancellation = slot.subscribe();
        let closing = application.clone();
        let close_context_id = opened.context_id;
        let close_task = tokio::spawn(async move {
            closing
                .context_close(ContextCloseArgs {
                    context_id: close_context_id,
                })
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), cancellation.changed())
            .await
            .expect("close signalled cancellation")
            .expect("cancellation sender");
        store.release.notify_one();

        assert_eq!(
            run_task
                .await
                .expect("run task")
                .expect_err("cancelled commit")
                .kind(),
            AppErrorCode::UpstreamError
        );
        close_task
            .await
            .expect("close task")
            .expect("close context");
        assert!(artifact_json_files(&artifact_root).is_empty());
    }

    #[tokio::test]
    async fn application_materializes_refs_and_keeps_them_context_scoped() {
        let application = Application::from_arcs(
            Config::empty(),
            default_registry().expect("registry"),
            Arc::new(MemoryProfileSource::new(profile(&row(
                SUB,
                TENANT,
                "AzureCloud",
                "alice",
            )))),
            Arc::new(Validator::default()),
            Arc::new(RefFactory),
            DEFAULT_POLICY_HASH,
            DEFAULT_POLICY_VERSION,
        )
        .expect("application");
        let first = application
            .context_open(ContextOpenArgs::default())
            .await
            .expect("first context");
        let ref_result = application
            .run(RunArgs {
                context_id: first.context_id.clone(),
                code: "__large_ref__".to_owned(),
                timeout_ms: None,
            })
            .await
            .expect("reference result");
        let ref_id = ref_result.value["__ref"]
            .as_str()
            .expect("reference token")
            .to_owned();
        let first_slot = application
            .inner
            .workers
            .lock()
            .await
            .get(&first.context_id)
            .cloned()
            .expect("first worker slot");
        assert_eq!(first_slot.refs.lock().await.len(), 1);
        assert_eq!(ref_result.value["type"], "object");
        assert_eq!(ref_result.value["keyCount"], 2);
        assert_eq!(ref_result.value["sensitivity"], "customerData");
        let rendered = serde_json::to_string(&ref_result.value).expect("preview JSON");
        assert!(!rendered.contains("secret-value"));
        assert!(!rendered.contains(&"x".repeat(70_000)));
        let debug = format!("{ref_result:?}");
        assert!(!debug.contains("__ref"));
        assert!(!debug.contains(&ref_id));

        let restored = application
            .run(RunArgs {
                context_id: first.context_id.clone(),
                code: format!("__ref__{ref_id}"),
                timeout_ms: None,
            })
            .await
            .expect("same-context rehydration");
        assert_eq!(restored.value["secret"], "secret-value");
        assert_eq!(restored.value["paddingLength"], 70_000);
        assert_eq!(
            application
                .run(RunArgs {
                    context_id: first.context_id.clone(),
                    code: "__ref__ref_invalid".to_owned(),
                    timeout_ms: None,
                })
                .await
                .expect_err("invalid ref")
                .kind(),
            AppErrorCode::ExecutionFailed
        );
        application
            .run(RunArgs {
                context_id: first.context_id.clone(),
                code: "still alive".to_owned(),
                timeout_ms: None,
            })
            .await
            .expect("invalid ref does not evict context");

        let second = application
            .context_open(ContextOpenArgs::default())
            .await
            .expect("second context");
        let denied = application
            .run(RunArgs {
                context_id: second.context_id.clone(),
                code: format!("__ref__{ref_id}"),
                timeout_ms: None,
            })
            .await
            .expect_err("cross-context ref");
        assert_eq!(denied.kind(), AppErrorCode::ExecutionFailed);
        application
            .run(RunArgs {
                context_id: second.context_id.clone(),
                code: "still alive".to_owned(),
                timeout_ms: None,
            })
            .await
            .expect("missing ref does not evict context");

        application
            .context_close(ContextCloseArgs {
                context_id: first.context_id.clone(),
            })
            .await
            .expect("close ref context");
        assert!(first_slot.refs.lock().await.is_empty());
        assert_eq!(
            application
                .run(RunArgs {
                    context_id: first.context_id,
                    code: format!("__ref__{ref_id}"),
                    timeout_ms: None,
                })
                .await
                .expect_err("closed context cannot rehydrate")
                .kind(),
            AppErrorCode::ContextNotFound
        );
        application
            .context_close(ContextCloseArgs {
                context_id: second.context_id,
            })
            .await
            .expect("close second context");
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
