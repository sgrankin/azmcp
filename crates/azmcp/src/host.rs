//! The semantic host-call boundary for the isolated JavaScript worker.
//!
//! The worker knows only reviewed host helpers.  This module gives those names
//! meaning without giving JavaScript a URL client, token, or
//! mutable Azure selection state.  Every call carries a cloud, resolves an
//! immutable context binding, and then crosses the reviewed core HTTP policy.

use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex},
    time::Instant,
};

use azmcp_core::{
    cloud::AzureCloud,
    config::{CloudBinding, ResolvedCloudBinding, SubscriptionId},
    context::{ArmTier, BindingSource, Context, GraphScope, Identity, LogsScope},
    credential::{CredentialError, CredentialIdentityPin, TokenAudience},
    http::{
        CredentialProvider, HttpClient, HttpError, HttpRequest, HttpResponse, LogsHttpClient,
        LogsHttpRequest, MetricsOrigin, RequestOrigin,
    },
    policy::{HttpMethod, PolicyBundle, PolicyDenial, RoutePurpose},
    routes::{LOGS_QUERY_API_VERSION, RESOURCE_GRAPH_API_VERSION},
    target::RelativeRequestTarget,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

use crate::{
    audit::AuditSink,
    worker::{
        HOST_METHOD_GRAPH, HOST_METHOD_LOGS_QUERY, HOST_METHOD_METRICS_BATCH,
        HOST_METHOD_METRICS_SINGLE, HOST_METHOD_REQUEST, HostCallRequest, HostCallResult,
    },
};

const MAX_METRICS: usize = 20;
const MAX_BATCH_RESOURCES: usize = 50;
const METRICS_API_VERSION: &str = azmcp_core::routes::METRICS_API_VERSION;

/// Maximum JSON response body that this v0 adapter will decode into a value.
/// The transport has a larger byte cap so it can reject oversized responses
/// before this second, semantic cap is reached.
pub const MAX_DECODED_RESPONSE_BYTES: usize = 1024 * 1024;

/// Maximum KQL query accepted by the Resource Graph host operation.
pub const MAX_GRAPH_QUERY_BYTES: usize = 256 * 1024;

/// Maximum KQL query accepted by the direct Logs Query operation.
pub const MAX_LOGS_QUERY_BYTES: usize = 256 * 1024;
/// Maximum ISO8601 duration accepted by the direct Logs Query operation.
pub const MAX_LOGS_TIMESPAN_BYTES: usize = 128;
/// Maximum duration represented by a Logs Query timespan.
pub const MAX_LOGS_TIMESPAN_SECONDS: u64 = 30 * 24 * 60 * 60;
/// Maximum decoded bytes retained for a valid Logs Query JSON response.
pub const MAX_LOGS_RESULT_BYTES: usize = 1024 * 1024;
/// Maximum rows retained across all returned Logs Query tables.
pub const MAX_LOGS_ROWS: usize = 50_000;

/// Maximum number of call records retained for one JavaScript run.
pub const MAX_CALL_RECORDS: usize = 128;

/// Maximum bytes retained in one sanitized host failure message.
pub const MAX_HOST_ERROR_BYTES: usize = 512;

/// Build a transport client for one fully resolved cloud binding.
///
/// The factory is deliberately supplied by the embedding application.  A
/// production implementation can pair the binding with its credential broker;
/// tests can construct an `HttpClient` against an explicit loopback origin.
/// The factory must not consult ambient Azure CLI state.
pub trait HttpClientFactory: Send + Sync {
    /// Construct a client whose immutable configuration exactly matches
    /// `binding`.
    fn client_for(
        &self,
        binding: &ResolvedCloudBinding,
    ) -> Result<Arc<HttpClient>, ClientFactoryError>;

    /// Construct a dedicated client for the direct Logs Query data plane.
    /// Implementations that do not opt into that data plane remain valid and
    /// fail closed when a Logs helper is called.
    fn logs_client_for(
        &self,
        _binding: &ResolvedCloudBinding,
    ) -> Result<Arc<LogsHttpClient>, ClientFactoryError> {
        Err(ClientFactoryError::Unavailable)
    }
}

/// Production client factory using reviewed cloud origins and one credential
/// provider. Construction is inert; tokens and network are reached only by
/// an explicit validation or JavaScript host call.
pub struct ReviewedHttpClientFactory {
    credentials: Arc<dyn CredentialProvider>,
    policy: PolicyBundle,
}

impl ReviewedHttpClientFactory {
    pub fn new(credentials: Arc<dyn CredentialProvider>, policy: PolicyBundle) -> Self {
        Self {
            credentials,
            policy,
        }
    }
}

impl HttpClientFactory for ReviewedHttpClientFactory {
    fn client_for(
        &self,
        binding: &ResolvedCloudBinding,
    ) -> Result<Arc<HttpClient>, ClientFactoryError> {
        HttpClient::from_config(
            Arc::clone(&self.credentials),
            azmcp_core::http::HttpClientConfig::from_binding(
                binding,
                TokenAudience::Arm,
                self.policy.clone(),
            )
            .map_err(|_| ClientFactoryError::Unavailable)?,
        )
        .map(Arc::new)
        .map_err(|_| ClientFactoryError::Unavailable)
    }

    fn logs_client_for(
        &self,
        binding: &ResolvedCloudBinding,
    ) -> Result<Arc<LogsHttpClient>, ClientFactoryError> {
        LogsHttpClient::from_config(
            Arc::clone(&self.credentials),
            azmcp_core::http::LogsHttpClientConfig::from_binding(binding, self.policy.clone())
                .map_err(|_| ClientFactoryError::Unavailable)?,
        )
        .map(Arc::new)
        .map_err(|_| ClientFactoryError::Unavailable)
    }
}

/// A client-factory failure that intentionally carries no source or secret.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientFactoryError {
    /// No client was available for this reviewed binding.
    Unavailable,
    /// The factory returned a client whose immutable configuration did not
    /// match the binding supplied by the host adapter.
    BindingMismatch,
}

impl fmt::Display for ClientFactoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "HTTP client unavailable",
            Self::BindingMismatch => "HTTP client binding mismatch",
        })
    }
}

impl std::error::Error for ClientFactoryError {}

/// The two possible subscription-resolution sources in one host call.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SubscriptionSource {
    /// The context's primary binding came from server configuration.
    Config,
    /// The context-open request supplied the primary binding.
    ContextOverride,
    /// The server selected one unambiguous cached account candidate.
    Auto,
    /// An explicit subscription selected from that binding's allowlist.
    Explicit,
}

/// Whether a host operation crossed the local policy gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CallDecision {
    Allowed,
    Denied,
}

/// A bounded, secret-free description of one semantic host operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallRecord {
    pub correlation_id: String,
    pub operation: String,
    pub cloud: AzureCloud,
    pub subscription: Option<String>,
    pub subscription_source: Option<SubscriptionSource>,
    pub tenant: Option<String>,
    pub identity: String,
    pub arm_tier: String,
    pub method: String,
    pub path_template: String,
    pub api_version: String,
    pub api_version_source: String,
    pub policy_hash: String,
    pub policy_version: String,
    pub rbac_action: Option<String>,
    pub decision: CallDecision,
    pub reason: Option<String>,
    pub status: Option<u16>,
    pub duration_ms: u64,
    pub retry_count: u32,
    pub remaining_subscription_reads: Option<u64>,
    pub graph_scope: Option<String>,
    pub data_plane: Option<String>,
    pub data_scope: Option<String>,
}

/// A bounded record collection returned to the application after one run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallRecords {
    pub calls: Vec<CallRecord>,
    pub calls_omitted: usize,
}

/// Stable semantic failures returned by the JavaScript host helpers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostErrorCode {
    InvalidRequest,
    CloudRequired,
    BindingUnavailable,
    SubscriptionMismatch,
    SubscriptionAmbiguous,
    RouteDenied,
    CapabilityDenied,
    AuthenticationRequired,
    PrincipalMismatch,
    UpstreamError,
    ResponseTooLarge,
    InvalidResponse,
    ClientUnavailable,
    AuditUnavailable,
    ProtocolError,
}

impl HostErrorCode {
    /// Stable wire spelling used by an embedding application.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::CloudRequired => "cloud_required",
            Self::BindingUnavailable => "binding_unavailable",
            Self::SubscriptionMismatch => "subscription_mismatch",
            Self::SubscriptionAmbiguous => "subscription_ambiguous",
            Self::RouteDenied => "route_denied",
            Self::CapabilityDenied => "capability_denied",
            Self::AuthenticationRequired => "authentication_required",
            Self::PrincipalMismatch => "authentication_required",
            Self::UpstreamError => "upstream_error",
            Self::ResponseTooLarge => "response_too_large",
            Self::InvalidResponse => "invalid_response",
            Self::ClientUnavailable => "client_unavailable",
            Self::AuditUnavailable => "audit_unavailable",
            Self::ProtocolError => "protocol_error",
        }
    }
}

/// A typed and sanitized host failure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostError {
    pub code: HostErrorCode,
    pub message: String,
    pub retryable: bool,
}

impl HostError {
    fn new(code: HostErrorCode, message: &'static str, retryable: bool) -> Self {
        Self::with_message(code, message.to_owned(), retryable)
    }

    fn with_message(code: HostErrorCode, message: impl Into<String>, retryable: bool) -> Self {
        Self {
            code,
            message: message.into(),
            retryable,
        }
    }

    fn invalid() -> Self {
        Self::new(HostErrorCode::InvalidRequest, "invalid host request", false)
    }

    fn route_denied() -> Self {
        Self::new(
            HostErrorCode::RouteDenied,
            "request denied by route policy",
            false,
        )
    }

    fn capability_denied() -> Self {
        Self::new(
            HostErrorCode::CapabilityDenied,
            "Resource Graph scope is not authorized by this context",
            false,
        )
    }

    fn logs_capability_denied() -> Self {
        Self::new(
            HostErrorCode::CapabilityDenied,
            "Logs Query is not authorized by this context",
            false,
        )
    }

    fn audit_unavailable() -> Self {
        Self::new(
            HostErrorCode::AuditUnavailable,
            "durable request audit log is unavailable",
            true,
        )
    }
}

impl fmt::Display for HostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for HostError {}

/// Closed arguments for the `az.request` host operation.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RequestArgs {
    /// Cloud is optional in the wire shape only to provide a typed
    /// `cloud_required` error; omission never selects a commercial default.
    #[serde(default)]
    pub cloud: Option<AzureCloud>,
    #[serde(default)]
    pub subscription: Option<String>,
    pub method: HttpMethod,
    pub path: String,
    pub api_version: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<Value>,
}

/// The only graph scope widening accepted by v0.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum GraphScopeName {
    #[serde(rename = "allAccessible")]
    AllAccessible,
}

/// Object spelling accepted for callers that retain the context-open shape.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GraphScopeObject {
    pub scope: GraphScopeName,
}

/// Closed graph scope selector.  A string and an object are equivalent.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum GraphScopeArg {
    Name(GraphScopeName),
    Object(GraphScopeObject),
}

impl GraphScopeArg {
    fn is_all_accessible(self) -> bool {
        matches!(self, Self::Name(_) | Self::Object(_))
    }
}

/// Closed arguments for the `az.graph` host operation.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GraphArgs {
    #[serde(default)]
    pub cloud: Option<AzureCloud>,
    pub query: String,
    #[serde(default)]
    pub subscriptions: Option<Vec<String>>,
    #[serde(default)]
    pub scope: Option<GraphScopeArg>,
}

/// Closed arguments for a single-resource Azure Monitor Metrics call.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MetricsSingleArgs {
    #[serde(default)]
    pub cloud: Option<AzureCloud>,
    pub resource_id: String,
    pub metric_names: Vec<String>,
    #[serde(default)]
    pub timespan: Option<String>,
    #[serde(default)]
    pub interval: Option<String>,
    #[serde(default)]
    pub aggregation: Option<String>,
    #[serde(default)]
    pub top: Option<u32>,
    #[serde(default)]
    pub order_by: Option<String>,
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default)]
    pub result_type: Option<String>,
    #[serde(default)]
    pub metric_namespace: Option<String>,
    #[serde(default)]
    pub auto_adjust_timegrain: Option<bool>,
    #[serde(default)]
    pub validate_dimensions: Option<bool>,
    #[serde(default)]
    pub rollup_by: Option<String>,
}

/// Closed arguments for the subscription-level Metrics batch call.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MetricsBatchArgs {
    #[serde(default)]
    pub cloud: Option<AzureCloud>,
    pub region: String,
    pub resource_ids: Vec<String>,
    pub metric_namespace: String,
    pub metric_names: Vec<String>,
    #[serde(default)]
    pub start_time: Option<String>,
    #[serde(default)]
    pub end_time: Option<String>,
    #[serde(default)]
    pub interval: Option<String>,
    #[serde(default)]
    pub aggregation: Option<String>,
    #[serde(default)]
    pub top: Option<u32>,
    #[serde(default)]
    pub order_by: Option<String>,
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default)]
    pub rollup_by: Option<String>,
}

/// Closed arguments for the `az.logs.query` host operation.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LogsQueryArgs {
    #[serde(default)]
    pub cloud: Option<AzureCloud>,
    #[serde(default)]
    pub subscription: Option<String>,
    pub workspace_id: String,
    pub query: String,
    pub timespan: String,
}
#[derive(Clone, Debug)]
struct RecordBuilder {
    correlation_id: String,
    operation: String,
    cloud: AzureCloud,
    subscription: Option<String>,
    subscription_source: Option<SubscriptionSource>,
    tenant: Option<String>,
    method: String,
    path_template: String,
    api_version: String,
    api_version_source: String,
    policy_hash: String,
    policy_version: String,
    rbac_action: Option<String>,
    decision: CallDecision,
    reason: Option<String>,
    status: Option<u16>,
    remaining_subscription_reads: Option<u64>,
    graph_scope: Option<String>,
    data_plane: Option<String>,
    data_scope: Option<String>,
    started: Instant,
}

impl RecordBuilder {
    fn new(operation: &str, cloud: AzureCloud, context: &Context, correlation_id: &str) -> Self {
        Self {
            correlation_id: correlation_id.to_owned(),
            operation: operation.to_owned(),
            cloud,
            subscription: None,
            subscription_source: None,
            tenant: None,
            method: String::new(),
            path_template: "<unmatched>".to_owned(),
            api_version: String::new(),
            api_version_source: "callerReviewed".to_owned(),
            policy_hash: context.policy_hash().to_owned(),
            policy_version: context.policy_version().to_owned(),
            rbac_action: None,
            decision: CallDecision::Denied,
            reason: None,
            status: None,
            remaining_subscription_reads: None,
            graph_scope: None,
            data_plane: None,
            data_scope: None,
            started: Instant::now(),
        }
    }

    fn finish(mut self, result: &Result<Value, HostError>) -> CallRecord {
        if let Err(error) = result {
            self.reason = Some(error.code.as_str().to_owned());
        }
        CallRecord {
            correlation_id: self.correlation_id,
            operation: self.operation,
            cloud: self.cloud,
            subscription: self.subscription,
            subscription_source: self.subscription_source,
            tenant: self.tenant,
            identity: identity_name(Identity::User).to_owned(),
            arm_tier: arm_tier_name(ArmTier::Inspect).to_owned(),
            method: self.method,
            path_template: self.path_template,
            api_version: self.api_version,
            api_version_source: self.api_version_source,
            policy_hash: self.policy_hash,
            policy_version: self.policy_version,
            rbac_action: self.rbac_action,
            decision: self.decision,
            reason: self.reason,
            status: self.status,
            duration_ms: self.started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            retry_count: 0,
            remaining_subscription_reads: self.remaining_subscription_reads,
            graph_scope: self.graph_scope,
            data_plane: self.data_plane,
            data_scope: self.data_scope,
        }
    }
}

/// Stateful semantic host adapter for one immutable execution context.
pub struct HostAdapter {
    context: Context,
    correlation_id: String,
    client_factory: Arc<dyn HttpClientFactory>,
    audit_sink: Option<Arc<dyn AuditSink>>,
    identity_pin: CredentialIdentityPin,
    state: Arc<Mutex<HostAdapterState>>,
}

#[derive(Default)]
struct HostAdapterState {
    records: Vec<CallRecord>,
    calls_omitted: usize,
    last_error: Option<HostError>,
    principal_mismatch: bool,
}

impl HostAdapter {
    /// Construct an adapter from the immutable context snapshot held by a
    /// registry lease.
    pub fn new(context: &Context, client_factory: Arc<dyn HttpClientFactory>) -> Self {
        Self::with_correlation_id(context, client_factory, "unattributed")
    }

    /// Construct an adapter whose returned and durable call records share the
    /// enclosing tool result's correlation identifier.
    pub fn with_correlation_id(
        context: &Context,
        client_factory: Arc<dyn HttpClientFactory>,
        correlation_id: impl Into<String>,
    ) -> Self {
        Self::with_identity_pin(
            context,
            client_factory,
            correlation_id,
            CredentialIdentityPin::new(),
        )
    }

    /// Construct an adapter with identity state retained by the enclosing
    /// context across separate worker turns.
    pub fn with_identity_pin(
        context: &Context,
        client_factory: Arc<dyn HttpClientFactory>,
        correlation_id: impl Into<String>,
        identity_pin: CredentialIdentityPin,
    ) -> Self {
        Self {
            context: context.clone(),
            correlation_id: correlation_id.into(),
            client_factory,
            audit_sink: None,
            identity_pin,
            state: Arc::new(Mutex::new(HostAdapterState::default())),
        }
    }

    /// Attach the durable sink used for every allowed and denied host call.
    pub fn with_audit_sink(mut self, audit_sink: Arc<dyn AuditSink>) -> Self {
        self.audit_sink = Some(audit_sink);
        self
    }

    /// The immutable context copied into this adapter.
    pub fn context(&self) -> &Context {
        &self.context
    }

    /// Return a non-consuming view of retained records.
    pub fn records(&self) -> Vec<CallRecord> {
        self.lock_state().records.clone()
    }

    /// Drain the bounded record collection for the completed run.
    pub fn take_records(&self) -> CallRecords {
        let mut state = self.lock_state();
        CallRecords {
            calls: std::mem::take(&mut state.records),
            calls_omitted: std::mem::take(&mut state.calls_omitted),
        }
    }

    /// Drain the most recent semantic host failure for application error mapping.
    pub fn take_last_error(&self) -> Option<HostError> {
        self.lock_state().last_error.take()
    }

    /// Whether a token refresh proved that the Azure CLI principal changed.
    pub fn principal_mismatch(&self) -> bool {
        self.lock_state().principal_mismatch
    }

    /// Dispatch exactly one worker host call and return a worker-compatible
    /// response.  The request and call IDs are copied unchanged.
    pub async fn handle(&self, request: HostCallRequest) -> HostCallResult {
        let result = self
            .dispatch(&request.method, request.arguments.clone())
            .await;
        if let Err(error) = &result {
            let mut state = self.lock_state();
            if error.code == HostErrorCode::PrincipalMismatch {
                state.principal_mismatch = true;
            }
            state.last_error = Some(error.clone());
        }
        match result {
            Ok(value) => HostCallResult::success(&request, value),
            Err(error) => HostCallResult::failure(&request, error.to_string()),
        }
    }

    /// Dispatch a semantic host operation without coupling the caller to the
    /// worker protocol.
    pub async fn dispatch(&self, method: &str, arguments: Value) -> Result<Value, HostError> {
        match method {
            HOST_METHOD_REQUEST => self.dispatch_request(arguments).await,
            HOST_METHOD_GRAPH => self.dispatch_graph(arguments).await,
            HOST_METHOD_METRICS_SINGLE => self.dispatch_metrics_single(arguments).await,
            HOST_METHOD_METRICS_BATCH => self.dispatch_metrics_batch(arguments).await,
            HOST_METHOD_LOGS_QUERY => self.dispatch_logs_query(arguments).await,
            _ => Err(HostError::new(
                HostErrorCode::ProtocolError,
                "unknown host operation",
                false,
            )),
        }
    }

    async fn dispatch_request(&self, arguments: Value) -> Result<Value, HostError> {
        let args: RequestArgs = decode_arguments(arguments)?;
        let cloud = args.cloud.ok_or_else(|| {
            HostError::new(HostErrorCode::CloudRequired, "cloud is required", false)
        })?;
        let mut record = RecordBuilder::new(
            HOST_METHOD_REQUEST,
            cloud,
            &self.context,
            &self.correlation_id,
        );
        record.method = method_name(args.method).to_owned();
        record.api_version = args.api_version.clone();

        let result = match self.prepare_audit() {
            Ok(()) => self.execute_request(args, &mut record).await,
            Err(error) => Err(error),
        };
        let audit = self.push_record(record.finish(&result));
        if audit.is_err() {
            return Err(HostError::audit_unavailable());
        }
        result
    }

    async fn execute_request(
        &self,
        args: RequestArgs,
        record: &mut RecordBuilder,
    ) -> Result<Value, HostError> {
        // The v0 request bundle contains inspect-only GET routes.  Do not
        // forward caller-controlled headers or bodies alongside the server's
        // bearer credential until a reviewed route explicitly defines their
        // schema and allowlist.
        if !args.headers.is_empty() || args.body.is_some() {
            return Err(HostError::invalid());
        }
        let (binding, source) = self.resolve_binding(args.cloud_required(), args.subscription)?;
        record.subscription = Some(binding.subscription_id().to_owned());
        record.subscription_source = Some(source);
        record.tenant = Some(binding.tenant_id().to_owned());

        let relative =
            RelativeRequestTarget::parse(&args.path).map_err(|_| HostError::invalid())?;
        if relative
            .segments()
            .first()
            .is_some_and(|segment| segment.eq_ignore_ascii_case("subscriptions"))
        {
            return Err(HostError::invalid());
        }
        // `az.request` joins ordinary paths below the selected subscription.
        // The root path is the one exception: preserve its query, if any,
        // without introducing a trailing slash that ARM treats as a different
        // target.
        let relative_text = relative.to_string();
        let target_text = if relative.path() == "/" {
            format!(
                "/subscriptions/{}{}",
                binding.subscription_id(),
                relative_text.strip_prefix('/').unwrap_or_default()
            )
        } else {
            format!(
                "/subscriptions/{}{}",
                binding.subscription_id(),
                relative_text
            )
        };
        let target =
            RelativeRequestTarget::parse(&target_text).map_err(|_| HostError::invalid())?;
        let client = self.client_for(&binding)?;
        let route = client
            .config()
            .policy()
            .classify(
                binding.cloud(),
                RoutePurpose::Request,
                args.method,
                &target,
                &args.api_version,
            )
            .map_err(|_| HostError::route_denied())?;
        record.path_template = route.path_template().to_owned();
        record.rbac_action = Some(route.rbac_action().to_owned());
        record.decision = CallDecision::Allowed;

        let request =
            HttpRequest::for_purpose(RoutePurpose::Request, args.method, target, args.api_version)
                .map_err(|_| HostError::invalid())?;
        let response = client
            .execute_with_identity_pin(request, Some(&self.identity_pin))
            .await
            .map_err(|error| map_http_error(error, &binding))?;
        record.status = Some(response.status());
        record.remaining_subscription_reads = remaining_subscription_reads(&response);
        decode_http_response(response)
    }

    async fn dispatch_graph(&self, arguments: Value) -> Result<Value, HostError> {
        let args: GraphArgs = decode_arguments(arguments)?;
        let cloud = args.cloud.ok_or_else(|| {
            HostError::new(HostErrorCode::CloudRequired, "cloud is required", false)
        })?;
        let mut record = RecordBuilder::new(
            HOST_METHOD_GRAPH,
            cloud,
            &self.context,
            &self.correlation_id,
        );
        record.method = "POST".to_owned();
        record.api_version = RESOURCE_GRAPH_API_VERSION.to_owned();
        record.api_version_source = "reviewedRoute".to_owned();

        let result = match self.prepare_audit() {
            Ok(()) => self.execute_graph(args, &mut record).await,
            Err(error) => Err(error),
        };
        let audit = self.push_record(record.finish(&result));
        if audit.is_err() {
            return Err(HostError::audit_unavailable());
        }
        result
    }

    async fn execute_graph(
        &self,
        args: GraphArgs,
        record: &mut RecordBuilder,
    ) -> Result<Value, HostError> {
        if args.query.trim().is_empty() || args.query.len() > MAX_GRAPH_QUERY_BYTES {
            return Err(HostError::invalid());
        }
        let binding = self
            .context
            .resolved_bindings()
            .iter()
            .find(|binding| binding.cloud() == args.cloud_required())
            .cloned()
            .ok_or_else(|| {
                HostError::new(
                    HostErrorCode::BindingUnavailable,
                    "cloud has no context binding",
                    false,
                )
            })?;
        record.subscription = Some(binding.subscription_id().to_owned());
        record.subscription_source = Some(self.primary_subscription_source(binding.cloud())?);
        record.tenant = Some(binding.tenant_id().to_owned());
        let selection = self.resolve_graph_scope(&binding, &args)?;
        let mut body = serde_json::Map::new();
        body.insert("query".to_owned(), Value::String(args.query));
        match &selection {
            GraphSelection::Subscriptions(subscriptions) => {
                record.graph_scope = Some("subscriptions".to_owned());
                body.insert(
                    "subscriptions".to_owned(),
                    Value::Array(
                        subscriptions
                            .iter()
                            .map(|subscription| Value::String(subscription.as_str().to_owned()))
                            .collect(),
                    ),
                );
            }
            GraphSelection::AllAccessible => {
                record.graph_scope = Some("allAccessible".to_owned());
            }
        }

        let client = self.client_for(&binding)?;
        let target = RelativeRequestTarget::parse("/providers/Microsoft.ResourceGraph/resources")
            .map_err(|_| HostError::invalid())?;
        let route = client
            .config()
            .policy()
            .classify(
                binding.cloud(),
                RoutePurpose::ResourceGraph,
                HttpMethod::Post,
                &target,
                RESOURCE_GRAPH_API_VERSION,
            )
            .map_err(|_| HostError::route_denied())?;
        record.path_template = route.path_template().to_owned();
        record.rbac_action = Some(route.rbac_action().to_owned());
        record.decision = CallDecision::Allowed;
        let body = serde_json::to_vec(&Value::Object(body)).map_err(|_| HostError::invalid())?;
        let request = HttpRequest::for_purpose(
            RoutePurpose::ResourceGraph,
            HttpMethod::Post,
            target,
            RESOURCE_GRAPH_API_VERSION,
        )
        .map_err(|_| HostError::invalid())?
        .with_header("Content-Type", "application/json")
        .with_body(body);
        let response = client
            .execute_with_identity_pin(request, Some(&self.identity_pin))
            .await
            .map_err(|error| map_http_error(error, &binding))?;
        record.status = Some(response.status());
        record.remaining_subscription_reads = remaining_subscription_reads(&response);
        decode_http_response(response)
    }

    async fn dispatch_metrics_single(&self, arguments: Value) -> Result<Value, HostError> {
        let args: MetricsSingleArgs = decode_arguments(arguments)?;
        let cloud = args.cloud.ok_or_else(|| {
            HostError::new(HostErrorCode::CloudRequired, "cloud is required", false)
        })?;
        let mut record = RecordBuilder::new(
            HOST_METHOD_METRICS_SINGLE,
            cloud,
            &self.context,
            &self.correlation_id,
        );
        record.method = "GET".to_owned();
        record.api_version = METRICS_API_VERSION.to_owned();
        record.api_version_source = "reviewedRoute".to_owned();

        let result = match self.prepare_audit() {
            Ok(()) => self.execute_metrics_single(args, &mut record).await,
            Err(error) => Err(error),
        };
        let audit = self.push_record(record.finish(&result));
        if audit.is_err() {
            return Err(HostError::audit_unavailable());
        }
        result
    }

    async fn execute_metrics_single(
        &self,
        args: MetricsSingleArgs,
        record: &mut RecordBuilder,
    ) -> Result<Value, HostError> {
        let resource = validate_metric_resource_id(&args.resource_id)?;
        let (binding, source) = self.resolve_binding(
            args.cloud_required(),
            Some(resource.subscription.as_str().to_owned()),
        )?;
        record.subscription = Some(binding.subscription_id().to_owned());
        record.subscription_source = Some(source);
        record.tenant = Some(binding.tenant_id().to_owned());
        let query = build_single_metrics_query(&args)?;
        let target_text = format!(
            "{}/providers/Microsoft.Insights/metrics{}",
            resource.path, query
        );
        let target =
            RelativeRequestTarget::parse(&target_text).map_err(|_| HostError::invalid())?;
        let client = self.client_for(&binding)?;
        let route = client
            .config()
            .policy()
            .classify(
                binding.cloud(),
                RoutePurpose::MetricsSingle,
                HttpMethod::Get,
                &target,
                METRICS_API_VERSION,
            )
            .map_err(|_| HostError::route_denied())?;
        record.path_template = route.path_template().to_owned();
        record.rbac_action = Some(route.rbac_action().to_owned());
        record.decision = CallDecision::Allowed;
        let request = HttpRequest::for_purpose(
            RoutePurpose::MetricsSingle,
            HttpMethod::Get,
            target,
            METRICS_API_VERSION,
        )
        .map_err(|_| HostError::invalid())?;
        let response = client
            .execute_with_identity_pin(request, Some(&self.identity_pin))
            .await
            .map_err(|error| map_http_error(error, &binding))?;
        record.status = Some(response.status());
        record.remaining_subscription_reads = remaining_subscription_reads(&response);
        decode_http_response(response)
    }

    async fn dispatch_metrics_batch(&self, arguments: Value) -> Result<Value, HostError> {
        let args: MetricsBatchArgs = decode_arguments(arguments)?;
        let cloud = args.cloud.ok_or_else(|| {
            HostError::new(HostErrorCode::CloudRequired, "cloud is required", false)
        })?;
        let mut record = RecordBuilder::new(
            HOST_METHOD_METRICS_BATCH,
            cloud,
            &self.context,
            &self.correlation_id,
        );
        record.method = "POST".to_owned();
        record.api_version = METRICS_API_VERSION.to_owned();
        record.api_version_source = "reviewedRoute".to_owned();

        let result = match self.prepare_audit() {
            Ok(()) => self.execute_metrics_batch(args, &mut record).await,
            Err(error) => Err(error),
        };
        let audit = self.push_record(record.finish(&result));
        if audit.is_err() {
            return Err(HostError::audit_unavailable());
        }
        result
    }

    async fn execute_metrics_batch(
        &self,
        args: MetricsBatchArgs,
        record: &mut RecordBuilder,
    ) -> Result<Value, HostError> {
        let resources = validate_batch_resource_ids(&args.resource_ids)?;
        let (binding, source) = self.resolve_binding(
            args.cloud_required(),
            Some(resources[0].subscription.as_str().to_owned()),
        )?;
        record.subscription = Some(binding.subscription_id().to_owned());
        record.subscription_source = Some(source);
        record.tenant = Some(binding.tenant_id().to_owned());
        let query = build_batch_metrics_query(&args)?;
        let target_text = format!(
            "/subscriptions/{}/metrics:getBatch{}",
            binding.subscription_id(),
            query
        );
        let target =
            RelativeRequestTarget::parse(&target_text).map_err(|_| HostError::invalid())?;
        let client = self.metrics_client_for(&binding, &args.region)?;
        let route = client
            .config()
            .policy()
            .classify(
                binding.cloud(),
                RoutePurpose::MetricsBatch,
                HttpMethod::Post,
                &target,
                METRICS_API_VERSION,
            )
            .map_err(|_| HostError::route_denied())?;
        record.path_template = route.path_template().to_owned();
        record.rbac_action = Some(route.rbac_action().to_owned());
        record.decision = CallDecision::Allowed;
        let body = serde_json::to_vec(&json!({
            "resourceids": resources.iter().map(|resource| resource.path.as_str()).collect::<Vec<_>>(),
        }))
        .map_err(|_| HostError::invalid())?;
        let request = HttpRequest::for_purpose(
            RoutePurpose::MetricsBatch,
            HttpMethod::Post,
            target,
            METRICS_API_VERSION,
        )
        .map_err(|_| HostError::invalid())?
        .with_header("Content-Type", "application/json")
        .with_body(body);
        let response = client
            .execute_with_identity_pin(request, Some(&self.identity_pin))
            .await
            .map_err(|error| map_http_error(error, &binding))?;
        record.status = Some(response.status());
        record.remaining_subscription_reads = remaining_subscription_reads(&response);
        decode_http_response(response)
    }

    async fn dispatch_logs_query(&self, arguments: Value) -> Result<Value, HostError> {
        let args: LogsQueryArgs = decode_arguments(arguments)?;
        let cloud = args.cloud.ok_or_else(|| {
            HostError::new(HostErrorCode::CloudRequired, "cloud is required", false)
        })?;
        let mut record = RecordBuilder::new(
            HOST_METHOD_LOGS_QUERY,
            cloud,
            &self.context,
            &self.correlation_id,
        );
        record.method = "POST".to_owned();
        record.api_version = LOGS_QUERY_API_VERSION.to_owned();
        record.api_version_source = "reviewedRoute".to_owned();
        record.data_plane = Some("logs.query".to_owned());
        record.data_scope = Some("allAccessible".to_owned());

        let result = match self.prepare_audit() {
            Ok(()) => self.execute_logs_query(args, &mut record).await,
            Err(error) => Err(error),
        };
        let audit = self.push_record(record.finish(&result));
        if audit.is_err() {
            return Err(HostError::audit_unavailable());
        }
        result
    }

    async fn execute_logs_query(
        &self,
        args: LogsQueryArgs,
        record: &mut RecordBuilder,
    ) -> Result<Value, HostError> {
        if args.query.trim().is_empty() || args.query.len() > MAX_LOGS_QUERY_BYTES {
            return Err(HostError::invalid());
        }
        if !valid_logs_timespan(&args.timespan) {
            return Err(HostError::invalid());
        }
        let (binding, source) = self.resolve_binding(args.cloud_required(), args.subscription)?;
        record.subscription = Some(binding.subscription_id().to_owned());
        record.subscription_source = Some(source);
        record.tenant = Some(binding.tenant_id().to_owned());
        if !self
            .context
            .data_planes()
            .iter()
            .any(|data_plane| data_plane == "logs.query")
            || !matches!(
                self.context.logs_scopes().get(&binding.cloud()),
                Some(LogsScope::AllAccessible)
            )
        {
            return Err(HostError::logs_capability_denied());
        }

        let workspace_id =
            SubscriptionId::new(args.workspace_id).map_err(|_| HostError::invalid())?;
        let target = RelativeRequestTarget::parse(&format!(
            "/v1/workspaces/{}/query",
            workspace_id.as_str()
        ))
        .map_err(|_| HostError::invalid())?;
        let client = self.logs_client_for(&binding)?;
        let route = client
            .config()
            .policy()
            .classify(
                binding.cloud(),
                RoutePurpose::LogsQuery,
                HttpMethod::Post,
                &target,
                LOGS_QUERY_API_VERSION,
            )
            .map_err(|_| HostError::route_denied())?;
        record.path_template = route.path_template().to_owned();
        record.rbac_action = Some(route.rbac_action().to_owned());
        record.decision = CallDecision::Allowed;
        let body = serde_json::to_vec(&json!({
            "query": args.query,
            "timespan": args.timespan,
        }))
        .map_err(|_| HostError::invalid())?;
        let request = LogsHttpRequest::new(target, body).map_err(|_| HostError::invalid())?;
        let response = client
            .execute_with_identity_pin(request, Some(&self.identity_pin))
            .await
            .map_err(|error| map_http_error(error, &binding))?;
        record.status = Some(response.status());
        decode_logs_query_response(response)
    }
    fn resolve_binding(
        &self,
        cloud: AzureCloud,
        requested_subscription: Option<String>,
    ) -> Result<(ResolvedCloudBinding, SubscriptionSource), HostError> {
        let binding = self
            .context
            .resolved_bindings()
            .iter()
            .find(|binding| binding.cloud() == cloud)
            .ok_or_else(|| {
                HostError::new(
                    HostErrorCode::BindingUnavailable,
                    "cloud has no context binding",
                    false,
                )
            })?;
        let Some(requested_subscription) = requested_subscription else {
            let source = self.primary_subscription_source(cloud)?;
            return Ok((binding.clone(), source));
        };
        let subscription =
            SubscriptionId::new(requested_subscription).map_err(|_| HostError::invalid())?;
        let matches = binding
            .allowed_subscriptions()
            .iter()
            .filter(|pair| pair.subscription() == &subscription)
            .collect::<Vec<_>>();
        let pair = match matches.as_slice() {
            [] => {
                return Err(HostError::new(
                    HostErrorCode::SubscriptionMismatch,
                    "subscription is not in the context allowlist",
                    false,
                ));
            }
            [pair] => *pair,
            _ => {
                return Err(HostError::new(
                    HostErrorCode::SubscriptionAmbiguous,
                    "subscription has multiple context tenants",
                    false,
                ));
            }
        };
        let effective = CloudBinding::new(pair.subscription().clone(), Some(pair.tenant().clone()))
            .resolve(cloud, &[])
            .map_err(|_| {
                HostError::new(
                    HostErrorCode::SubscriptionAmbiguous,
                    "subscription tenant is ambiguous",
                    false,
                )
            })?;
        Ok((effective, SubscriptionSource::Explicit))
    }

    fn primary_subscription_source(
        &self,
        cloud: AzureCloud,
    ) -> Result<SubscriptionSource, HostError> {
        match self.context.binding_sources().get(&cloud) {
            Some(BindingSource::Config) => Ok(SubscriptionSource::Config),
            Some(BindingSource::ContextOverride) => Ok(SubscriptionSource::ContextOverride),
            Some(BindingSource::Auto) => Ok(SubscriptionSource::Auto),
            None => Err(HostError::new(
                HostErrorCode::BindingUnavailable,
                "cloud binding provenance is unavailable",
                false,
            )),
        }
    }

    fn resolve_graph_scope(
        &self,
        binding: &ResolvedCloudBinding,
        args: &GraphArgs,
    ) -> Result<GraphSelection, HostError> {
        if args.subscriptions.is_some() && args.scope.is_some() {
            return Err(HostError::invalid());
        }
        let immutable = self
            .context
            .graph_scopes()
            .get(&binding.cloud())
            .ok_or_else(HostError::capability_denied)?;
        if let Some(scope) = args.scope {
            if !scope.is_all_accessible() || !matches!(immutable, GraphScope::AllAccessible) {
                return Err(HostError::capability_denied());
            }
            return Ok(GraphSelection::AllAccessible);
        }
        if let Some(subscriptions) = &args.subscriptions {
            let subscriptions = parse_subscription_list(subscriptions)?;
            if subscriptions.is_empty() {
                return Err(HostError::invalid());
            }
            if let GraphScope::Subscriptions(allowed) = immutable
                && subscriptions
                    .iter()
                    .any(|subscription| !allowed.iter().any(|allowed| allowed == subscription))
            {
                return Err(HostError::capability_denied());
            }
            return Ok(GraphSelection::Subscriptions(subscriptions));
        }
        match immutable {
            GraphScope::Subscriptions(subscriptions) => {
                Ok(GraphSelection::Subscriptions(subscriptions.clone()))
            }
            GraphScope::AllAccessible => Ok(GraphSelection::AllAccessible),
        }
    }

    fn client_for(&self, binding: &ResolvedCloudBinding) -> Result<Arc<HttpClient>, HostError> {
        let client = self.client_factory.client_for(binding).map_err(|_| {
            HostError::new(
                HostErrorCode::ClientUnavailable,
                "HTTP client unavailable",
                true,
            )
        })?;
        let config = client.config();
        if config.origin().cloud() != binding.cloud()
            || config.subscription() != binding.subscription()
            || config.tenant() != binding.tenant()
            || config.audience() != TokenAudience::Arm
        {
            return Err(HostError::new(
                HostErrorCode::ClientUnavailable,
                "HTTP client binding mismatch",
                false,
            ));
        }
        Ok(client)
    }

    fn metrics_client_for(
        &self,
        binding: &ResolvedCloudBinding,
        region: &str,
    ) -> Result<Arc<HttpClient>, HostError> {
        // Validate the region against the reviewed cloud suffix before the
        // client is constructed. This remains inert and cannot contact Azure.
        MetricsOrigin::for_cloud(binding.cloud(), region).map_err(|_| HostError::invalid())?;
        let arm_client = self.client_for(binding)?;
        let client = arm_client.metrics_for_region(region).map_err(|_| {
            HostError::new(
                HostErrorCode::ClientUnavailable,
                "HTTP client unavailable",
                true,
            )
        })?;
        let config = client.config();
        if config.origin().cloud() != binding.cloud()
            || config.subscription() != binding.subscription()
            || config.tenant() != binding.tenant()
            || config.audience() != TokenAudience::Metrics
            || !matches!(config.origin(), RequestOrigin::Metrics(_))
        {
            return Err(HostError::new(
                HostErrorCode::ClientUnavailable,
                "HTTP client binding mismatch",
                false,
            ));
        }
        Ok(Arc::new(client))
    }

    fn logs_client_for(
        &self,
        binding: &ResolvedCloudBinding,
    ) -> Result<Arc<LogsHttpClient>, HostError> {
        let client = self.client_factory.logs_client_for(binding).map_err(|_| {
            HostError::new(
                HostErrorCode::ClientUnavailable,
                "Logs Query client unavailable",
                true,
            )
        })?;
        let config = client.config();
        if config.origin().cloud() != binding.cloud()
            || config.subscription() != binding.subscription()
            || config.tenant() != binding.tenant()
            || config.audience() != TokenAudience::LogAnalytics
        {
            return Err(HostError::new(
                HostErrorCode::ClientUnavailable,
                "Logs Query client binding mismatch",
                false,
            ));
        }
        Ok(client)
    }
    fn prepare_audit(&self) -> Result<(), HostError> {
        match &self.audit_sink {
            Some(sink) => sink.prepare().map_err(|_| HostError::audit_unavailable()),
            None => Ok(()),
        }
    }

    fn push_record(&self, record: CallRecord) -> Result<(), HostError> {
        let audit_result = self
            .audit_sink
            .as_ref()
            .map_or(Ok(()), |sink| sink.append(&record))
            .map_err(|_| HostError::audit_unavailable());
        let mut state = self.lock_state();
        if state.records.len() < MAX_CALL_RECORDS {
            state.records.push(record);
        } else {
            state.calls_omitted = state.calls_omitted.saturating_add(1);
        }
        audit_result
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, HostAdapterState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl RequestArgs {
    fn cloud_required(&self) -> AzureCloud {
        self.cloud.expect("cloud checked before request execution")
    }
}

impl GraphArgs {
    fn cloud_required(&self) -> AzureCloud {
        self.cloud.expect("cloud checked before graph execution")
    }
}

impl MetricsSingleArgs {
    fn cloud_required(&self) -> AzureCloud {
        self.cloud
            .expect("cloud checked before metrics single execution")
    }
}

impl MetricsBatchArgs {
    fn cloud_required(&self) -> AzureCloud {
        self.cloud
            .expect("cloud checked before metrics batch execution")
    }
}

impl LogsQueryArgs {
    fn cloud_required(&self) -> AzureCloud {
        self.cloud
            .expect("cloud checked before Logs Query execution")
    }
}
#[derive(Clone, Debug)]
enum GraphSelection {
    Subscriptions(Vec<SubscriptionId>),
    AllAccessible,
}

fn decode_arguments<T: DeserializeOwned>(arguments: Value) -> Result<T, HostError> {
    serde_json::from_value(arguments).map_err(|_| HostError::invalid())
}

fn parse_subscription_list(values: &[String]) -> Result<Vec<SubscriptionId>, HostError> {
    let mut subscriptions = Vec::with_capacity(values.len());
    for value in values {
        let subscription = SubscriptionId::new(value.clone()).map_err(|_| HostError::invalid())?;
        if subscriptions.iter().any(|known| known == &subscription) {
            return Err(HostError::invalid());
        }
        subscriptions.push(subscription);
    }
    Ok(subscriptions)
}

#[derive(Clone, Debug)]
struct ValidatedMetricResource {
    subscription: SubscriptionId,
    path: String,
    resource_type: String,
}

fn validate_metric_resource_id(value: &str) -> Result<ValidatedMetricResource, HostError> {
    let target = RelativeRequestTarget::parse(value).map_err(|_| HostError::invalid())?;
    if !target.query().is_empty() {
        return Err(HostError::invalid());
    }
    let segments = target.segments();
    if segments.len() < 6 || !segments[0].eq_ignore_ascii_case("subscriptions") {
        return Err(HostError::invalid());
    }
    let subscription =
        SubscriptionId::new(segments[1].clone()).map_err(|_| HostError::invalid())?;
    let provider_index = segments
        .iter()
        .position(|segment| segment.eq_ignore_ascii_case("providers"))
        .ok_or_else(HostError::invalid)?;
    let provider_namespace = segments
        .get(provider_index + 1)
        .filter(|segment| !segment.is_empty())
        .ok_or_else(HostError::invalid)?;
    let resource_segments = segments
        .get(provider_index + 2..)
        .filter(|segments| !segments.is_empty() && segments.len() % 2 == 0)
        .ok_or_else(HostError::invalid)?;
    if resource_segments.iter().any(|segment| segment.is_empty()) {
        return Err(HostError::invalid());
    }
    let mut resource_type = provider_namespace.to_ascii_lowercase();
    for type_name in resource_segments.iter().step_by(2) {
        resource_type.push('/');
        resource_type.push_str(&type_name.to_ascii_lowercase());
    }
    Ok(ValidatedMetricResource {
        subscription,
        path: target.path().to_owned(),
        resource_type,
    })
}

fn validate_batch_resource_ids(
    values: &[String],
) -> Result<Vec<ValidatedMetricResource>, HostError> {
    if values.is_empty() || values.len() > MAX_BATCH_RESOURCES {
        return Err(HostError::invalid());
    }
    let mut resources = Vec::with_capacity(values.len());
    for value in values {
        let resource = validate_metric_resource_id(value)?;
        if resources.iter().any(|known: &ValidatedMetricResource| {
            known.path.eq_ignore_ascii_case(&resource.path)
                || known.subscription != resource.subscription
                || known.resource_type != resource.resource_type
        }) {
            return Err(HostError::invalid());
        }
        resources.push(resource);
    }
    Ok(resources)
}

fn validate_metric_names(names: &[String]) -> Result<(), HostError> {
    if names.is_empty() || names.len() > MAX_METRICS {
        return Err(HostError::invalid());
    }
    if names.iter().any(|name| {
        name.is_empty()
            || name.len() > 256
            || name.chars().any(char::is_control)
            || name.contains(',')
    }) {
        return Err(HostError::invalid());
    }
    Ok(())
}

fn validate_metric_value(value: &str) -> Result<(), HostError> {
    if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(HostError::invalid());
    }
    Ok(())
}

fn push_metric_query(
    serializer: &mut url::form_urlencoded::Serializer<'_, String>,
    name: &str,
    value: Option<&str>,
) -> Result<(), HostError> {
    if let Some(value) = value {
        validate_metric_value(value)?;
        serializer.append_pair(name, value);
    }
    Ok(())
}

fn build_single_metrics_query(args: &MetricsSingleArgs) -> Result<String, HostError> {
    validate_metric_names(&args.metric_names)?;
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    push_metric_query(&mut serializer, "timespan", args.timespan.as_deref())?;
    push_metric_query(&mut serializer, "interval", args.interval.as_deref())?;
    let metric_names = args.metric_names.join(",");
    push_metric_query(&mut serializer, "metricnames", Some(&metric_names))?;
    push_metric_query(&mut serializer, "aggregation", args.aggregation.as_deref())?;
    if let Some(top) = args.top {
        serializer.append_pair("top", &top.to_string());
    }
    push_metric_query(&mut serializer, "orderby", args.order_by.as_deref())?;
    push_metric_query(&mut serializer, "$filter", args.filter.as_deref())?;
    push_metric_query(&mut serializer, "resultType", args.result_type.as_deref())?;
    push_metric_query(
        &mut serializer,
        "metricnamespace",
        args.metric_namespace.as_deref(),
    )?;
    if let Some(value) = args.auto_adjust_timegrain {
        serializer.append_pair("AutoAdjustTimegrain", if value { "true" } else { "false" });
    }
    if let Some(value) = args.validate_dimensions {
        serializer.append_pair("ValidateDimensions", if value { "true" } else { "false" });
    }
    push_metric_query(&mut serializer, "rollupby", args.rollup_by.as_deref())?;
    Ok(format!("?{}", serializer.finish()))
}

fn build_batch_metrics_query(args: &MetricsBatchArgs) -> Result<String, HostError> {
    validate_metric_names(&args.metric_names)?;
    validate_metric_value(&args.metric_namespace)?;
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    push_metric_query(&mut serializer, "starttime", args.start_time.as_deref())?;
    push_metric_query(&mut serializer, "endtime", args.end_time.as_deref())?;
    push_metric_query(&mut serializer, "interval", args.interval.as_deref())?;
    push_metric_query(
        &mut serializer,
        "metricnamespace",
        Some(&args.metric_namespace),
    )?;
    let metric_names = args.metric_names.join(",");
    push_metric_query(&mut serializer, "metricnames", Some(&metric_names))?;
    push_metric_query(&mut serializer, "aggregation", args.aggregation.as_deref())?;
    if let Some(top) = args.top {
        serializer.append_pair("top", &top.to_string());
    }
    push_metric_query(&mut serializer, "orderby", args.order_by.as_deref())?;
    push_metric_query(&mut serializer, "filter", args.filter.as_deref())?;
    push_metric_query(&mut serializer, "rollupby", args.rollup_by.as_deref())?;
    Ok(format!("?{}", serializer.finish()))
}

fn method_name(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Get => "GET",
        HttpMethod::Post => "POST",
        HttpMethod::Put => "PUT",
        HttpMethod::Patch => "PATCH",
        HttpMethod::Delete => "DELETE",
    }
}

fn identity_name(identity: Identity) -> &'static str {
    match identity {
        Identity::User => "user",
    }
}

fn arm_tier_name(tier: ArmTier) -> &'static str {
    match tier {
        ArmTier::Inspect => "inspect",
        ArmTier::Read => "read",
        ArmTier::Write => "write",
    }
}

fn remaining_subscription_reads(response: &HttpResponse) -> Option<u64> {
    response
        .headers()
        .get("x-ms-ratelimit-remaining-subscription-reads")
        .and_then(|value| value.parse().ok())
}

fn decode_http_response(response: HttpResponse) -> Result<Value, HostError> {
    if !(200..300).contains(&response.status()) {
        return Err(HostError::new(
            HostErrorCode::UpstreamError,
            "upstream returned an error status",
            response.status() == 429 || response.status() >= 500,
        ));
    }
    if response.body().len() > MAX_DECODED_RESPONSE_BYTES {
        return Err(HostError::new(
            HostErrorCode::ResponseTooLarge,
            "response exceeds the host JSON limit",
            false,
        ));
    }
    let body = serde_json::from_slice::<Value>(response.body()).map_err(|_| {
        HostError::new(
            HostErrorCode::InvalidResponse,
            "upstream response was not valid JSON",
            false,
        )
    })?;
    Ok(json!({
        "status": response.status(),
        "headers": response.headers(),
        "body": body,
    }))
}

fn valid_logs_timespan(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_LOGS_TIMESPAN_BYTES
        || value != value.trim()
        || value.chars().any(char::is_control)
        || !value.starts_with('P')
    {
        return false;
    }
    let mut seconds = 0_u64;
    let mut number = 0_u64;
    let mut have_number = false;
    let mut in_time = false;
    let mut have_component = false;
    let mut have_time_component = false;
    for character in value[1..].chars() {
        if let Some(digit) = character.to_digit(10) {
            number = match number
                .checked_mul(10)
                .and_then(|value| value.checked_add(u64::from(digit)))
            {
                Some(number) => number,
                None => return false,
            };
            have_number = true;
            continue;
        }
        if character == 'T' {
            if in_time || have_number {
                return false;
            }
            in_time = true;
            continue;
        }
        if !have_number {
            return false;
        }
        let multiplier = match (in_time, character) {
            (false, 'D') => 86_400,
            (true, 'H') => 3_600,
            (true, 'M') => 60,
            (true, 'S') => 1,
            _ => return false,
        };
        seconds = match number
            .checked_mul(multiplier)
            .and_then(|component| seconds.checked_add(component))
        {
            Some(seconds) => seconds,
            None => return false,
        };
        number = 0;
        have_number = false;
        have_component = true;
        have_time_component |= in_time;
    }
    have_component
        && (!in_time || have_time_component)
        && !have_number
        && seconds > 0
        && seconds <= MAX_LOGS_TIMESPAN_SECONDS
}

fn decode_logs_query_response(response: HttpResponse) -> Result<Value, HostError> {
    if !(200..300).contains(&response.status()) {
        return Err(HostError::new(
            HostErrorCode::UpstreamError,
            "upstream returned an error status",
            response.status() == 429 || response.status() >= 500,
        ));
    }
    if response.body().len() > MAX_LOGS_RESULT_BYTES {
        return Err(HostError::new(
            HostErrorCode::ResponseTooLarge,
            "Logs Query response exceeds the host JSON limit",
            false,
        ));
    }
    let body = serde_json::from_slice::<Value>(response.body()).map_err(|_| {
        HostError::new(
            HostErrorCode::InvalidResponse,
            "Logs Query response was not valid JSON",
            false,
        )
    })?;
    let tables = body
        .get("tables")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            HostError::new(
                HostErrorCode::InvalidResponse,
                "Logs Query response has an invalid table shape",
                false,
            )
        })?;
    let mut row_count = 0_usize;
    for table in tables {
        let table = table.as_object().ok_or_else(|| {
            HostError::new(
                HostErrorCode::InvalidResponse,
                "Logs Query response has an invalid table shape",
                false,
            )
        })?;
        let columns = table
            .get("columns")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                HostError::new(
                    HostErrorCode::InvalidResponse,
                    "Logs Query response has an invalid column shape",
                    false,
                )
            })?;
        if columns.iter().any(|column| {
            let Some(column) = column.as_object() else {
                return true;
            };
            !column.get("name").is_some_and(Value::is_string)
                || !column.get("type").is_some_and(Value::is_string)
        }) {
            return Err(HostError::new(
                HostErrorCode::InvalidResponse,
                "Logs Query response has an invalid column shape",
                false,
            ));
        }
        let rows = table.get("rows").and_then(Value::as_array).ok_or_else(|| {
            HostError::new(
                HostErrorCode::InvalidResponse,
                "Logs Query response has an invalid row shape",
                false,
            )
        })?;
        row_count = row_count.saturating_add(rows.len());
        if row_count > MAX_LOGS_ROWS
            || rows
                .iter()
                .any(|row| row.as_array().is_none_or(|row| row.len() != columns.len()))
        {
            return Err(HostError::new(
                HostErrorCode::InvalidResponse,
                "Logs Query response exceeds the row limit or has an invalid row shape",
                false,
            ));
        }
    }
    Ok(body)
}

fn map_http_error(error: HttpError, binding: &ResolvedCloudBinding) -> HostError {
    match error {
        HttpError::PolicyDenied(PolicyDenial::UnknownRoute)
        | HttpError::PolicyDenied(PolicyDenial::AmbiguousRoute) => HostError::route_denied(),
        HttpError::SubscriptionMismatch => HostError::new(
            HostErrorCode::SubscriptionMismatch,
            "request subscription does not match the selected binding",
            false,
        ),
        HttpError::Credential(CredentialError::PrincipalMismatch) => HostError::with_message(
            HostErrorCode::PrincipalMismatch,
            format!(
                "Azure authentication identity changed during the context lifetime; run AZURE_CLOUD_NAME={} az login --tenant {} and open a new context",
                binding.cloud(),
                binding.tenant_id(),
            ),
            false,
        ),
        HttpError::Credential(CredentialError::AuthenticationRequired {
            cloud_name,
            tenant_id,
        }) => HostError::with_message(
            HostErrorCode::AuthenticationRequired,
            format!(
                "Azure CLI authentication is required; run AZURE_CLOUD_NAME={cloud_name} az login --tenant {tenant_id}"
            ),
            true,
        ),
        HttpError::Credential(_) => HostError::new(
            HostErrorCode::AuthenticationRequired,
            "Azure authentication is unavailable",
            true,
        ),
        HttpError::ResponseBodyTooLarge { .. } => HostError::new(
            HostErrorCode::ResponseTooLarge,
            "response exceeds the transport limit",
            false,
        ),
        HttpError::RequestBodyTooLarge { .. }
        | HttpError::InvalidTarget(_)
        | HttpError::InvalidApiVersion
        | HttpError::ForbiddenHeader { .. }
        | HttpError::InvalidHeader { .. }
        | HttpError::InvalidHeaderValue { .. }
        | HttpError::DuplicateHeader { .. }
        | HttpError::InvalidLimits { .. }
        | HttpError::InvalidMetricsRegion => HostError::invalid(),
        HttpError::Timeout => HostError::new(
            HostErrorCode::UpstreamError,
            "upstream request timed out",
            true,
        ),
        HttpError::RedirectDenied
        | HttpError::RequestSend
        | HttpError::ResponseRead
        | HttpError::ClientBuild
        | HttpError::InvalidManifestOrigin
        | HttpError::InvalidLoopbackOrigin
        | HttpError::OriginCloudMismatch
        | HttpError::OriginMismatch
        | HttpError::InvalidRequestUrl
        | HttpError::InvalidAudience => HostError::new(
            HostErrorCode::UpstreamError,
            "upstream request failed",
            true,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::audit::{AuditError, AuditSink};
    use azmcp_core::{
        config::{SubscriptionTenantPair, TenantId},
        context::{ArmTier, ContextOptions, ContextRegistry, Identity, RegistryConfig},
        http::{ArmOrigin, BearerCredential, CredentialFuture, CredentialProvider, LogsOrigin},
        policy::PolicyBundle,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::Mutex,
    };

    const SUBSCRIPTION: &str = "11111111-1111-1111-1111-111111111111";
    const EXTRA_SUBSCRIPTION: &str = "22222222-2222-2222-2222-222222222222";
    const ESCAPE_SUBSCRIPTION: &str = "33333333-3333-3333-3333-333333333333";
    const WORKSPACE: &str = "44444444-4444-4444-4444-444444444444";
    const TENANT: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    const EXTRA_TENANT: &str = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

    #[derive(Default)]
    struct FakeCredentials {
        calls: AtomicUsize,
        requests: Mutex<Vec<azmcp_core::credential::TokenRequest>>,
    }

    impl CredentialProvider for FakeCredentials {
        fn acquire<'a>(
            &'a self,
            request: azmcp_core::credential::TokenRequest,
        ) -> CredentialFuture<'a> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.requests.lock().await.push(request);
                BearerCredential::new("synthetic-host-token")
            })
        }
    }

    #[derive(Default)]
    struct RecordingAudit {
        records: std::sync::Mutex<Vec<CallRecord>>,
        fail_prepare: std::sync::atomic::AtomicBool,
    }

    impl AuditSink for RecordingAudit {
        fn prepare(&self) -> Result<(), AuditError> {
            if self.fail_prepare.load(Ordering::SeqCst) {
                Err(AuditError::Unavailable)
            } else {
                Ok(())
            }
        }

        fn append(&self, record: &CallRecord) -> Result<(), AuditError> {
            self.records
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(record.clone());
            Ok(())
        }
    }

    struct TestFactory {
        credentials: Arc<dyn CredentialProvider>,
        origins: BTreeMap<AzureCloud, String>,
        policy: PolicyBundle,
    }

    struct MismatchCredentials;

    impl CredentialProvider for MismatchCredentials {
        fn acquire<'a>(
            &'a self,
            _request: azmcp_core::credential::TokenRequest,
        ) -> CredentialFuture<'a> {
            Box::pin(async { Err(CredentialError::PrincipalMismatch) })
        }
    }

    impl HttpClientFactory for TestFactory {
        fn client_for(
            &self,
            binding: &ResolvedCloudBinding,
        ) -> Result<Arc<HttpClient>, ClientFactoryError> {
            let origin = self
                .origins
                .get(&binding.cloud())
                .ok_or(ClientFactoryError::Unavailable)?;
            let origin = ArmOrigin::loopback_from_str(binding.cloud(), origin)
                .map_err(|_| ClientFactoryError::Unavailable)?;
            let client = HttpClient::with_loopback_origin(
                self.credentials.clone(),
                binding.cloud(),
                binding.subscription().clone(),
                binding.tenant().clone(),
                TokenAudience::Arm,
                origin,
                self.policy.clone(),
            )
            .map_err(|_| ClientFactoryError::Unavailable)?;
            Ok(Arc::new(client))
        }

        fn logs_client_for(
            &self,
            binding: &ResolvedCloudBinding,
        ) -> Result<Arc<LogsHttpClient>, ClientFactoryError> {
            let origin = self
                .origins
                .get(&binding.cloud())
                .ok_or(ClientFactoryError::Unavailable)?;
            let origin = LogsOrigin::loopback_from_str(binding.cloud(), origin)
                .map_err(|_| ClientFactoryError::Unavailable)?;
            let client = LogsHttpClient::with_loopback_origin(
                self.credentials.clone(),
                binding.cloud(),
                binding.subscription().clone(),
                binding.tenant().clone(),
                origin,
                self.policy.clone(),
            )
            .map_err(|_| ClientFactoryError::Unavailable)?;
            Ok(Arc::new(client))
        }
    }

    async fn server(response: &'static str) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("loopback");
        let address = listener.local_addr().expect("address");
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("request");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let count = stream.read(&mut buffer).await.expect("read");
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..count]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let header_end = request
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                        .map(|position| position + 4)
                        .expect("header terminator");
                    let content_length = String::from_utf8_lossy(&request[..header_end])
                        .lines()
                        .find_map(|line| {
                            line.strip_prefix("Content-Length:")
                                .or_else(|| line.strip_prefix("content-length:"))
                                .and_then(|value| value.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if request.len() >= header_end.saturating_add(content_length) {
                        break;
                    }
                }
            }
            stream.write_all(response.as_bytes()).await.expect("write");
            request
        });
        (format!("http://{address}/"), task)
    }

    fn binding(cloud: AzureCloud, extra: bool) -> ResolvedCloudBinding {
        let subscription = SubscriptionId::new(SUBSCRIPTION).expect("subscription");
        let tenant = TenantId::new(TENANT).expect("tenant");
        let additions = if extra {
            vec![SubscriptionTenantPair::new(
                SubscriptionId::new(EXTRA_SUBSCRIPTION).expect("extra subscription"),
                TenantId::new(EXTRA_TENANT).expect("extra tenant"),
            )]
        } else {
            Vec::new()
        };
        CloudBinding::with_allowed_subscriptions(subscription, Some(tenant), additions)
            .expect("binding")
            .resolve(cloud, &[])
            .expect("resolved binding")
    }

    fn context_for_cloud(cloud: AzureCloud, graph_scope: GraphScope, extra: bool) -> Context {
        let registry = ContextRegistry::new(RegistryConfig::new(
            2,
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(600),
        ))
        .expect("registry");
        let binding = binding(cloud, extra);
        let mut scopes = BTreeMap::new();
        scopes.insert(cloud, graph_scope);
        let options = ContextOptions::new(
            Identity::User,
            ArmTier::Inspect,
            Vec::new(),
            vec![binding],
            "test-policy-hash",
            "test-policy-v1",
        )
        .expect("options")
        .with_graph_scopes(scopes)
        .expect("scopes");
        registry
            .open(options, std::time::Instant::now())
            .expect("context")
    }

    fn context(graph_scope: GraphScope, extra: bool) -> Context {
        context_for_cloud(AzureCloud::AzureCloud, graph_scope, extra)
    }

    fn logs_context(clouds: &[AzureCloud]) -> Context {
        let registry = ContextRegistry::new(RegistryConfig::new(
            2,
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(600),
        ))
        .expect("registry");
        let bindings = clouds
            .iter()
            .copied()
            .map(|cloud| binding(cloud, false))
            .collect::<Vec<_>>();
        let logs_scopes = clouds
            .iter()
            .copied()
            .map(|cloud| (cloud, LogsScope::AllAccessible))
            .collect();
        let options = ContextOptions::new(
            Identity::User,
            ArmTier::Inspect,
            vec!["logs.query".to_owned()],
            bindings,
            "test-policy-hash",
            "test-policy-v1",
        )
        .expect("options")
        .with_logs_scopes(logs_scopes)
        .expect("logs scopes");
        registry
            .open(options, std::time::Instant::now())
            .expect("context")
    }
    fn policy() -> PolicyBundle {
        azmcp_core::routes::v0_policy().expect("v0 policy")
    }

    #[tokio::test]
    async fn cloud_is_required_and_unknown_fields_are_rejected() {
        let context = context(
            GraphScope::Subscriptions(vec![SubscriptionId::new(SUBSCRIPTION).unwrap()]),
            false,
        );
        let factory = Arc::new(TestFactory {
            credentials: Arc::new(FakeCredentials::default()),
            origins: BTreeMap::new(),
            policy: policy(),
        });
        let adapter = HostAdapter::new(&context, factory);
        let error = adapter
            .dispatch(
                HOST_METHOD_REQUEST,
                json!({"method": "GET", "path": "/providers/Microsoft.Resources", "apiVersion": "2020-01-01"}),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, HostErrorCode::CloudRequired);
        let error = adapter
            .dispatch(
                HOST_METHOD_REQUEST,
                json!({"cloud": "AzureCloud", "method": "GET", "path": "/providers/Microsoft.Resources", "apiVersion": "2020-01-01", "future": true}),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, HostErrorCode::InvalidRequest);
    }

    #[tokio::test]
    async fn request_stays_inside_the_subscription_allowlist_and_rejects_smuggling() {
        let (origin, server_task) = server(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}",
        )
        .await;
        let credentials = Arc::new(FakeCredentials::default());
        let factory = Arc::new(TestFactory {
            credentials: credentials.clone(),
            origins: [(AzureCloud::AzureCloud, origin)].into_iter().collect(),
            policy: policy(),
        });
        let context = context(
            GraphScope::Subscriptions(vec![SubscriptionId::new(SUBSCRIPTION).unwrap()]),
            true,
        );
        let adapter = HostAdapter::new(&context, factory);
        let value = adapter
            .dispatch(
                HOST_METHOD_REQUEST,
                json!({"cloud": "AzureCloud", "method": "GET", "path": "/resourceGroups/prod", "apiVersion": "2021-04-01"}),
            )
            .await
            .unwrap_err();
        assert_eq!(value.code, HostErrorCode::RouteDenied);
        let denied = adapter
            .dispatch(
                HOST_METHOD_REQUEST,
                json!({"cloud": "AzureCloud", "subscription": ESCAPE_SUBSCRIPTION, "method": "GET", "path": "/providers/Microsoft.Resources", "apiVersion": "2021-04-01"}),
            )
            .await
            .unwrap_err();
        assert_eq!(denied.code, HostErrorCode::SubscriptionMismatch);
        let smuggled = adapter
            .dispatch(
                HOST_METHOD_REQUEST,
                json!({"cloud": "AzureCloud", "method": "GET", "path": format!("/subscriptions/{SUBSCRIPTION}"), "apiVersion": "2020-01-01"}),
            )
            .await;
        assert_eq!(smuggled.unwrap_err().code, HostErrorCode::InvalidRequest);
        assert_eq!(credentials.calls.load(Ordering::SeqCst), 0);
        server_task.abort();
    }

    #[tokio::test]
    async fn subscription_root_request_does_not_add_a_trailing_slash() {
        let (origin, server_task) = server(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}",
        )
        .await;
        let factory = Arc::new(TestFactory {
            credentials: Arc::new(FakeCredentials::default()),
            origins: [(AzureCloud::AzureCloud, origin)].into_iter().collect(),
            policy: policy(),
        });
        let context = context(
            GraphScope::Subscriptions(vec![SubscriptionId::new(SUBSCRIPTION).unwrap()]),
            false,
        );
        let adapter = HostAdapter::new(&context, factory);
        let value = adapter
            .dispatch(
                HOST_METHOD_REQUEST,
                json!({
                    "cloud": "AzureCloud",
                    "method": "GET",
                    "path": "/",
                    "apiVersion": azmcp_core::routes::SUBSCRIPTIONS_API_VERSION
                }),
            )
            .await
            .expect("subscription root");
        assert_eq!(value["body"], json!({"ok": true}));
        let request = String::from_utf8(server_task.await.expect("server")).expect("request");
        assert!(
            request.starts_with(&format!("GET /subscriptions/{SUBSCRIPTION}?api-version=")),
            "{request}"
        );
    }

    #[tokio::test]
    async fn request_rejects_headers_and_bodies_before_credentials() {
        let credentials = Arc::new(FakeCredentials::default());
        let factory = Arc::new(TestFactory {
            credentials: credentials.clone(),
            origins: BTreeMap::new(),
            policy: policy(),
        });
        let context = context(
            GraphScope::Subscriptions(vec![SubscriptionId::new(SUBSCRIPTION).unwrap()]),
            false,
        );
        let adapter = HostAdapter::new(&context, factory);

        for arguments in [
            json!({
                "cloud": "AzureCloud",
                "method": "GET",
                "path": "/providers/Microsoft.Resources",
                "apiVersion": "2021-04-01",
                "headers": {"x-ms-authorization-auxiliary": "synthetic-secret"}
            }),
            json!({
                "cloud": "AzureCloud",
                "method": "GET",
                "path": "/providers/Microsoft.Resources",
                "apiVersion": "2021-04-01",
                "body": {"unexpected": true}
            }),
        ] {
            let error = adapter
                .dispatch(HOST_METHOD_REQUEST, arguments)
                .await
                .expect_err("v0 request metadata is closed");
            assert_eq!(error.code, HostErrorCode::InvalidRequest);
        }
        assert_eq!(credentials.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn graph_scope_is_separate_from_request_and_uses_exact_arg_route() {
        let (origin, server_task) = server(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"data\":[]}",
        )
        .await;
        let factory = Arc::new(TestFactory {
            credentials: Arc::new(FakeCredentials::default()),
            origins: [(AzureCloud::AzureCloud, origin)].into_iter().collect(),
            policy: policy(),
        });
        let context = context(GraphScope::AllAccessible, false);
        let audit = Arc::new(RecordingAudit::default());
        let adapter = HostAdapter::with_correlation_id(&context, factory, "graph-correlation")
            .with_audit_sink(audit.clone());
        let request = adapter
            .dispatch(
                HOST_METHOD_REQUEST,
                json!({"cloud": "AzureCloud", "method": "GET", "path": "/providers/Microsoft.ResourceGraph/resources", "apiVersion": "2022-10-01"}),
            )
            .await
            .unwrap_err();
        assert_eq!(request.code, HostErrorCode::RouteDenied);
        let graph = adapter
            .dispatch(
                HOST_METHOD_GRAPH,
                json!({"cloud": "AzureCloud", "query": "Resources", "scope": "allAccessible"}),
            )
            .await
            .expect("graph response");
        assert_eq!(graph["status"], 200);
        let records = adapter.records();
        let record = records.last().expect("record");
        assert_eq!(
            record.path_template,
            "/providers/Microsoft.ResourceGraph/resources"
        );
        assert_eq!(record.graph_scope.as_deref(), Some("allAccessible"));
        assert_eq!(record.api_version, RESOURCE_GRAPH_API_VERSION);
        let durable = audit
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(
            durable.last().expect("durable graph").correlation_id,
            "graph-correlation"
        );
        assert_eq!(
            durable.last().expect("durable graph").path_template,
            "/providers/Microsoft.ResourceGraph/resources"
        );
        server_task.await.expect("server");
    }

    #[tokio::test]
    async fn logs_query_uses_dedicated_cross_cloud_route_and_audience() {
        let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 93\r\n\r\n{\"tables\":[{\"name\":\"PrimaryResult\",\"columns\":[{\"name\":\"value\",\"type\":\"long\"}],\"rows\":[[1]]}]}";
        let (commercial_origin, commercial_server) = server(response).await;
        let (government_origin, government_server) = server(response).await;
        let credentials = Arc::new(FakeCredentials::default());
        let factory = Arc::new(TestFactory {
            credentials: credentials.clone(),
            origins: [
                (AzureCloud::AzureCloud, commercial_origin),
                (AzureCloud::AzureUSGovernment, government_origin),
            ]
            .into_iter()
            .collect(),
            policy: policy(),
        });
        let context = logs_context(&[AzureCloud::AzureCloud, AzureCloud::AzureUSGovernment]);
        let audit = Arc::new(RecordingAudit::default());
        let adapter = HostAdapter::with_correlation_id(&context, factory, "logs-correlation")
            .with_audit_sink(audit.clone());
        for cloud in ["AzureCloud", "AzureUSGovernment"] {
            let value = adapter
                .dispatch(
                    HOST_METHOD_LOGS_QUERY,
                    json!({
                        "cloud": cloud,
                        "workspaceId": WORKSPACE,
                        "query": "AppRequests | take 1",
                        "timespan": "PT1H"
                    }),
                )
                .await
                .expect("logs response");
            assert_eq!(value["tables"][0]["rows"][0][0], 1);
        }
        let requests = credentials.requests.lock().await;
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].audience, TokenAudience::LogAnalytics);
        assert_eq!(requests[0].resource(), "https://api.loganalytics.io");
        assert_eq!(requests[1].audience, TokenAudience::LogAnalytics);
        assert_eq!(requests[1].resource(), "https://api.loganalytics.us");
        drop(requests);
        let commercial_request = commercial_server.await.expect("commercial server");
        let government_request = government_server.await.expect("government server");
        for request in [commercial_request, government_request] {
            let request = String::from_utf8_lossy(&request);
            assert!(
                request.starts_with(&format!("POST /v1/workspaces/{WORKSPACE}/query HTTP/1.1"))
            );
            assert!(!request.contains("api-version"));
            assert!(request.contains("content-type: application/json"));
            assert!(
                request
                    .contains("\r\n\r\n{\"query\":\"AppRequests | take 1\",\"timespan\":\"PT1H\"}")
            );
        }
        let durable = audit
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(durable.len(), 2);
        let encoded = serde_json::to_string(&durable[0]).expect("audit record");
        assert!(!encoded.contains("AppRequests"));
        assert!(!encoded.contains(WORKSPACE));
        assert_eq!(durable[0].data_plane.as_deref(), Some("logs.query"));
        assert_eq!(durable[0].data_scope.as_deref(), Some("allAccessible"));
    }

    #[tokio::test]
    async fn logs_query_scope_and_input_limits_fail_before_network() {
        let credentials = Arc::new(FakeCredentials::default());
        let factory = Arc::new(TestFactory {
            credentials: credentials.clone(),
            origins: BTreeMap::new(),
            policy: policy(),
        });
        let denied = HostAdapter::new(
            &context(
                GraphScope::Subscriptions(vec![SubscriptionId::new(SUBSCRIPTION).unwrap()]),
                false,
            ),
            factory.clone(),
        );
        let error = denied
            .dispatch(
                HOST_METHOD_LOGS_QUERY,
                json!({
                    "cloud": "AzureCloud",
                    "workspaceId": SUBSCRIPTION,
                    "query": "AppRequests",
                    "timespan": "PT1H"
                }),
            )
            .await
            .expect_err("omitted logs scope denies the cloud");
        assert_eq!(error.code, HostErrorCode::CapabilityDenied);
        assert_eq!(credentials.calls.load(Ordering::SeqCst), 0);

        let allowed = HostAdapter::new(&logs_context(&[AzureCloud::AzureCloud]), factory);
        for arguments in [
            json!({
                "cloud": "AzureCloud",
                "workspaceId": SUBSCRIPTION,
                "query": "AppRequests",
                "timespan": "P31D"
            }),
            json!({
                "cloud": "AzureCloud",
                "workspaceId": "not-a-guid",
                "query": "AppRequests",
                "timespan": "PT1H"
            }),
            json!({
                "cloud": "AzureCloud",
                "workspaceId": SUBSCRIPTION,
                "query": "AppRequests",
                "timespan": "PT1H",
                "prefer": "wait=600"
            }),
        ] {
            let error = allowed
                .dispatch(HOST_METHOD_LOGS_QUERY, arguments)
                .await
                .expect_err("closed Logs Query arguments reject locally");
            assert_eq!(error.code, HostErrorCode::InvalidRequest);
        }
        let error = allowed
            .dispatch(
                HOST_METHOD_LOGS_QUERY,
                json!({
                    "cloud": "AzureCloud",
                    "workspaceId": SUBSCRIPTION,
                    "query": "x".repeat(MAX_LOGS_QUERY_BYTES + 1),
                    "timespan": "PT1H"
                }),
            )
            .await
            .expect_err("oversized KQL is rejected before credentials");
        assert_eq!(error.code, HostErrorCode::InvalidRequest);
        assert_eq!(credentials.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn logs_response_shape_and_byte_limits_are_fail_closed() {
        assert!(valid_logs_timespan("PT1H"));
        assert!(valid_logs_timespan("P1DT2H"));
        assert!(!valid_logs_timespan("PT0S"));
        assert!(!valid_logs_timespan("P31D"));
        assert!(!valid_logs_timespan("P1M"));

        let malformed = HttpResponse::from_parts(
            200,
            BTreeMap::new(),
            br#"{"tables":[{"columns":[],"rows":[[1]]}]}"#.to_vec(),
        );
        assert_eq!(
            decode_logs_query_response(malformed).unwrap_err().code,
            HostErrorCode::InvalidResponse
        );
        let oversized =
            HttpResponse::from_parts(200, BTreeMap::new(), vec![b' '; MAX_LOGS_RESULT_BYTES + 1]);
        assert_eq!(
            decode_logs_query_response(oversized).unwrap_err().code,
            HostErrorCode::ResponseTooLarge
        );
    }

    #[tokio::test]
    async fn unavailable_audit_fails_before_credentials_or_network() {
        let credentials = Arc::new(FakeCredentials::default());
        let factory = Arc::new(TestFactory {
            credentials: credentials.clone(),
            origins: BTreeMap::new(),
            policy: policy(),
        });
        let context = context(
            GraphScope::Subscriptions(vec![SubscriptionId::new(SUBSCRIPTION).unwrap()]),
            false,
        );
        let audit = Arc::new(RecordingAudit::default());
        audit.fail_prepare.store(true, Ordering::SeqCst);
        let adapter = HostAdapter::new(&context, factory).with_audit_sink(audit);
        let error = adapter
            .dispatch(
                HOST_METHOD_REQUEST,
                json!({"cloud": "AzureCloud", "method": "GET", "path": "/providers/Microsoft.Resources", "apiVersion": "2021-04-01"}),
            )
            .await
            .expect_err("audit unavailable");
        assert_eq!(error.code, HostErrorCode::AuditUnavailable);
        assert_eq!(credentials.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn principal_change_is_a_fatal_context_signal_before_network() {
        let (origin, server_task) =
            server("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n").await;
        let factory = Arc::new(TestFactory {
            credentials: Arc::new(MismatchCredentials),
            origins: [(AzureCloud::AzureCloud, origin)].into_iter().collect(),
            policy: policy(),
        });
        let context = context(
            GraphScope::Subscriptions(vec![SubscriptionId::new(SUBSCRIPTION).unwrap()]),
            false,
        );
        let audit = Arc::new(RecordingAudit::default());
        let adapter = HostAdapter::new(&context, factory).with_audit_sink(audit.clone());
        let result = adapter
            .handle(HostCallRequest {
                id: 1,
                call_id: 1,
                method: HOST_METHOD_REQUEST.to_owned(),
                arguments: json!({"cloud": "AzureCloud", "method": "GET", "path": "/providers/Microsoft.Resources", "apiVersion": "2021-04-01"}),
            })
            .await;
        assert!(!result.ok);
        assert!(
            result
                .error
                .as_deref()
                .is_some_and(|error| error.starts_with("authentication_required:"))
        );
        assert!(result.error.as_deref().is_some_and(|error| error.contains(
            "AZURE_CLOUD_NAME=AzureCloud az login --tenant aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        )));
        assert!(adapter.principal_mismatch());
        server_task.abort();
    }

    #[tokio::test]
    async fn both_reviewed_clouds_use_their_own_loopback_origin() {
        let (commercial_origin, commercial_server) = server(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}",
        )
        .await;
        let (government_origin, government_server) = server(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}",
        )
        .await;
        let commercial = binding(AzureCloud::AzureCloud, false);
        let government = binding(AzureCloud::AzureUSGovernment, false);
        let registry = ContextRegistry::new(RegistryConfig::new(
            2,
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(600),
        ))
        .expect("registry");
        let options = ContextOptions::new(
            Identity::User,
            ArmTier::Inspect,
            Vec::new(),
            vec![commercial, government],
            "test-policy-hash",
            "test-policy-v1",
        )
        .expect("options");
        let context = registry
            .open(options, std::time::Instant::now())
            .expect("context");
        let factory = Arc::new(TestFactory {
            credentials: Arc::new(FakeCredentials::default()),
            origins: [
                (AzureCloud::AzureCloud, commercial_origin),
                (AzureCloud::AzureUSGovernment, government_origin),
            ]
            .into_iter()
            .collect(),
            policy: policy(),
        });
        let adapter = HostAdapter::new(&context, factory);
        for cloud in ["AzureCloud", "AzureUSGovernment"] {
            adapter
                .dispatch(
                    HOST_METHOD_REQUEST,
                    json!({"cloud": cloud, "method": "GET", "path": "/providers/Microsoft.Resources", "apiVersion": "2021-04-01"}),
                )
                .await
                .expect("request");
        }
        commercial_server.await.expect("commercial server");
        government_server.await.expect("government server");
        assert_eq!(adapter.records().len(), 2);
    }

    #[tokio::test]
    async fn metrics_single_uses_arm_origin_and_keeps_resource_in_binding() {
        let (origin, server_task) = server(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}",
        )
        .await;
        let credentials = Arc::new(FakeCredentials::default());
        let factory = Arc::new(TestFactory {
            credentials: credentials.clone(),
            origins: [(AzureCloud::AzureCloud, origin)].into_iter().collect(),
            policy: policy(),
        });
        let context = context(
            GraphScope::Subscriptions(vec![SubscriptionId::new(SUBSCRIPTION).unwrap()]),
            true,
        );
        let audit = Arc::new(RecordingAudit::default());
        let adapter = HostAdapter::new(&context, factory).with_audit_sink(audit.clone());
        let result = adapter
            .dispatch(
                HOST_METHOD_METRICS_SINGLE,
                json!({
                    "cloud": "AzureCloud",
                    "resourceId": format!("/subscriptions/{EXTRA_SUBSCRIPTION}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"),
                    "metricNames": ["Percentage CPU"],
                    "timespan": "PT1H",
                    "filter": "Location eq 'eastus'"
                }),
            )
            .await
            .expect("metrics response");
        assert_eq!(result["status"], 200);
        let raw_request_bytes = server_task.await.expect("server");
        let raw_request = String::from_utf8_lossy(&raw_request_bytes);
        assert!(raw_request.contains("GET /subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm/providers/Microsoft.Insights/metrics"));
        assert!(raw_request.contains("metricnames=Percentage+CPU"));
        let requests = credentials.requests.lock().await;
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].cloud, AzureCloud::AzureCloud);
        assert_eq!(requests[0].audience, TokenAudience::Arm);
        assert_eq!(requests[0].subscription_id.as_str(), EXTRA_SUBSCRIPTION);
        assert_eq!(requests[0].tenant_id.as_str(), EXTRA_TENANT);
        let records = adapter.records();
        let record = records.last().expect("audit record");
        assert_eq!(record.operation, HOST_METHOD_METRICS_SINGLE);
        assert_eq!(
            record.rbac_action.as_deref(),
            Some("Microsoft.Insights/Metrics/Read")
        );
        let durable = audit
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let encoded = serde_json::to_string(durable.last().expect("durable record")).expect("JSON");
        assert!(!encoded.contains("Percentage CPU"));
        assert!(!encoded.contains("eastus"));
        assert!(!encoded.contains("resourceGroups"));
    }

    #[tokio::test]
    async fn metrics_batch_uses_government_data_plane_and_lowercase_body() {
        let (origin, server_task) = server(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}",
        )
        .await;
        let credentials = Arc::new(FakeCredentials::default());
        let factory = Arc::new(TestFactory {
            credentials: credentials.clone(),
            origins: [(AzureCloud::AzureUSGovernment, origin)]
                .into_iter()
                .collect(),
            policy: policy(),
        });
        let context = context_for_cloud(
            AzureCloud::AzureUSGovernment,
            GraphScope::Subscriptions(vec![SubscriptionId::new(SUBSCRIPTION).unwrap()]),
            false,
        );
        let adapter = HostAdapter::new(&context, factory);
        let result = adapter
            .dispatch(
                HOST_METHOD_METRICS_BATCH,
                json!({
                    "cloud": "AzureUSGovernment",
                    "region": "usgov-virginia",
                    "resourceIds": [
                        format!("/subscriptions/{SUBSCRIPTION}/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1"),
                        format!("/subscriptions/{SUBSCRIPTION}/resourceGroups/rg2/providers/Microsoft.Compute/virtualMachines/vm2")
                    ],
                    "metricNamespace": "Microsoft.Compute",
                    "metricNames": ["Percentage CPU"],
                    "startTime": "2024-01-01T00:00:00Z",
                    "endTime": "2024-01-01T01:00:00Z"
                }),
            )
            .await
            .expect("batch response");
        assert_eq!(result["status"], 200);
        let raw_request_bytes = server_task.await.expect("server");
        let raw_request = String::from_utf8_lossy(&raw_request_bytes);
        assert!(raw_request.contains(
            "POST /subscriptions/11111111-1111-1111-1111-111111111111/metrics%3AgetBatch"
        ));
        assert!(raw_request.contains("metricnamespace=Microsoft.Compute"));
        assert!(raw_request.contains("\"resourceids\":[\"/subscriptions/"));
        assert!(!raw_request.contains("resourceIds"));
        let requests = credentials.requests.lock().await;
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].cloud, AzureCloud::AzureUSGovernment);
        assert_eq!(requests[0].audience, TokenAudience::Metrics);
        let records = adapter.records();
        let record = records.last().expect("audit record");
        assert_eq!(record.operation, HOST_METHOD_METRICS_BATCH);
        assert_eq!(
            record.rbac_action.as_deref(),
            Some("Microsoft.Insights/Metrics/Read")
        );
    }

    #[tokio::test]
    async fn metrics_reject_cross_subscription_and_mixed_resource_types_before_credentials() {
        let credentials = Arc::new(FakeCredentials::default());
        let factory = Arc::new(TestFactory {
            credentials: credentials.clone(),
            origins: BTreeMap::new(),
            policy: policy(),
        });
        let context = context(
            GraphScope::Subscriptions(vec![SubscriptionId::new(SUBSCRIPTION).unwrap()]),
            false,
        );
        let adapter = HostAdapter::new(&context, factory);
        let wrong_subscription = adapter
            .dispatch(
                HOST_METHOD_METRICS_SINGLE,
                json!({
                    "cloud": "AzureCloud",
                    "resourceId": format!("/subscriptions/{EXTRA_SUBSCRIPTION}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"),
                    "metricNames": ["Percentage CPU"]
                }),
            )
            .await
            .expect_err("subscription is immutable");
        assert_eq!(wrong_subscription.code, HostErrorCode::SubscriptionMismatch);
        let mixed_types = adapter
            .dispatch(
                HOST_METHOD_METRICS_BATCH,
                json!({
                    "cloud": "AzureCloud",
                    "region": "eastus",
                    "resourceIds": [
                        format!("/subscriptions/{SUBSCRIPTION}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"),
                        format!("/subscriptions/{SUBSCRIPTION}/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet")
                    ],
                    "metricNamespace": "Microsoft.Compute",
                    "metricNames": ["Percentage CPU"]
                }),
            )
            .await
            .expect_err("batch resource type is fixed");
        assert_eq!(mixed_types.code, HostErrorCode::InvalidRequest);

        let invalid_region = adapter
            .dispatch(
                HOST_METHOD_METRICS_BATCH,
                json!({
                    "cloud": "AzureCloud",
                    "region": "east_us",
                    "resourceIds": [format!("/subscriptions/{SUBSCRIPTION}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm")],
                    "metricNamespace": "Microsoft.Compute",
                    "metricNames": ["Percentage CPU"]
                }),
            )
            .await
            .expect_err("region host label is closed");
        assert_eq!(invalid_region.code, HostErrorCode::InvalidRequest);

        let oversized = adapter
            .dispatch(
                HOST_METHOD_METRICS_SINGLE,
                json!({
                    "cloud": "AzureCloud",
                    "resourceId": format!("/subscriptions/{SUBSCRIPTION}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"),
                    "metricNames": vec!["metric"; MAX_METRICS + 1]
                }),
            )
            .await
            .expect_err("metric name cap");
        assert_eq!(oversized.code, HostErrorCode::InvalidRequest);

        let unknown = adapter
            .dispatch(
                HOST_METHOD_METRICS_SINGLE,
                json!({
                    "cloud": "AzureCloud",
                    "resourceId": format!("/subscriptions/{SUBSCRIPTION}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"),
                    "metricNames": ["Percentage CPU"],
                    "headers": {}
                }),
            )
            .await
            .expect_err("unknown metrics field");
        assert_eq!(unknown.code, HostErrorCode::InvalidRequest);
        assert_eq!(credentials.calls.load(Ordering::SeqCst), 0);
    }
}
