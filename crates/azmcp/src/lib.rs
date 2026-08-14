//! The modern-only MCP front end for `azmcp`.
//!
//! MCP requests are stateless; explicit application context handles retain the
//! isolated JavaScript workers and immutable Azure authority records.

pub mod app;
pub mod artifacts;
pub mod audit;
pub mod host;
pub mod refs;
pub mod runtime;
pub mod tools;
pub mod worker;

use std::{borrow::Cow, future::Future};

use rmcp::{
    ServerHandler, Service,
    model::{
        CacheScope, CallToolRequestParams, CallToolResponse, CallToolResult, ClientRequest,
        DiscoverResult, ErrorCode, ErrorData, Implementation, JsonObject, ListToolsResult,
        MetaObject, PaginatedRequestParams, ProtocolVersion, RequestMetaObject, ServerCapabilities,
        ServerInfo, ServerResult, Tool,
    },
    service::{NotificationContext, RequestContext, RoleServer},
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

use crate::{
    app::{AppError, Application},
    tools::{
        ACCOUNTS_TOOL, AccountsArgs, CONTEXT_CLOSE_TOOL, CONTEXT_OPEN_TOOL, ContextCloseArgs,
        ContextOpenArgs, RUN_TOOL, RunArgs, SCHEMA_GET_TOOL, SCHEMA_SEARCH_TOOL, SchemaGetArgs,
        SchemaSearchArgs,
    },
    worker::ResultTooLargeSummary,
};

/// The only protocol revision implemented by this server.
pub const PROTOCOL_VERSION: &str = "2026-07-28";

/// Stable server identity advertised in discovery and every result envelope.
pub const SERVER_NAME: &str = "azmcp";

/// Build version used as the server identity version.
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Cache lifetime for discovery and the deterministic tool catalog.
pub const CACHE_TTL_MS: u64 = 60_000;

const SERVER_INFO_META_KEY: &str = "io.modelcontextprotocol/serverInfo";
const MAX_TOOL_RESULT_BYTES: usize = 1024 * 1024;

/// The modern protocol front end over the stateful application.
#[derive(Clone)]
pub struct AzmcpServer {
    application: Application,
}

impl AzmcpServer {
    /// Construct a server only when every advertised host operation is real.
    pub fn new(application: Application) -> Result<Self, ServerConfigurationError> {
        if !application.host_calls_ready()
            || !application.audit_ready()
            || !application.artifact_writes_ready()
        {
            return Err(ServerConfigurationError);
        }
        Ok(Self { application })
    }

    /// Return the deterministic server identity.
    pub fn implementation() -> Implementation {
        Implementation::new(SERVER_NAME, SERVER_VERSION)
    }

    /// Return the server information used by discovery and diagnostics.
    pub fn server_info() -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::V_2026_07_28)
            .with_server_info(Self::implementation())
    }

    /// Return the deterministic catalog of tools implemented in this release.
    pub fn tools() -> Vec<Tool> {
        tools::catalog()
    }

    /// Wrap the handler with the modern per-request lifecycle boundary.
    pub fn modern_service(self) -> ModernService {
        ModernService { server: self }
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error(
    "the v0 server requires semantic Azure host calls, a durable audit sink, and managed artifact storage"
)]
pub struct ServerConfigurationError;

impl ServerHandler for AzmcpServer {
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(&[ProtocolVersion::V_2026_07_28])
    }

    fn initialize(
        &self,
        _request: rmcp::model::InitializeRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ServerInfo, ErrorData>> + rmcp::service::MaybeSendFuture + '_
    {
        std::future::ready(Err(legacy_initialize_error()))
    }

    fn discover(
        &self,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<DiscoverResult, ErrorData>> + rmcp::service::MaybeSendFuture + '_
    {
        let result = DiscoverResult::from_server_info(
            vec![ProtocolVersion::V_2026_07_28],
            Self::server_info(),
        )
        .with_ttl_ms(CACHE_TTL_MS)
        .with_cache_scope(CacheScope::Public);
        std::future::ready(Ok(result))
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, ErrorData>> + rmcp::service::MaybeSendFuture + '_
    {
        let mut result = ListToolsResult::with_all_items(Self::tools())
            .with_ttl_ms(CACHE_TTL_MS)
            .with_cache_scope(CacheScope::Public);
        result.meta = Some(server_info_meta());
        std::future::ready(Ok(result))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        match request.name.as_ref() {
            ACCOUNTS_TOOL => {
                let args = parse_tool_args::<AccountsArgs>(request.arguments)?;
                tool_result(self.application.accounts(args).await)
            }
            CONTEXT_OPEN_TOOL => {
                let args = parse_tool_args::<ContextOpenArgs>(request.arguments)?;
                let result = tokio::select! {
                    biased;
                    _ = context.ct.cancelled() => None,
                    result = self.application.context_open(args) => Some(result),
                };
                match result {
                    Some(result) => tool_result(result),
                    None => domain_error_result(
                        "context_evicted",
                        "request cancelled; context creation was rolled back",
                        false,
                        None,
                    ),
                }
            }
            CONTEXT_CLOSE_TOOL => {
                let args = parse_tool_args::<ContextCloseArgs>(request.arguments)?;
                tool_result(self.application.context_close(args).await)
            }
            RUN_TOOL => {
                let args = parse_tool_args::<RunArgs>(request.arguments)?;
                let context_id = args.context_id.clone();
                let result = tokio::select! {
                    result = self.application.run(args) => Some(result),
                    _ = context.ct.cancelled() => None,
                };
                match result {
                    Some(result) => tool_result(result),
                    None => {
                        // Cancellation makes the retained isolate unsafe to
                        // reuse: the worker protocol may still have an
                        // outstanding Execute response. Dispose the explicit
                        // application context as well as stopping this request.
                        let _ = self
                            .application
                            .context_close(ContextCloseArgs { context_id })
                            .await;
                        domain_error_result(
                            "context_evicted",
                            "request cancelled; execution context was disposed",
                            false,
                            None,
                        )
                    }
                }
            }
            SCHEMA_SEARCH_TOOL => {
                let args = parse_tool_args::<SchemaSearchArgs>(request.arguments)?;
                tool_result(self.application.schema_search(args).await)
            }
            SCHEMA_GET_TOOL => {
                let args = parse_tool_args::<SchemaGetArgs>(request.arguments)?;
                tool_result(self.application.schema_get(args).await)
            }
            _ => Err(ErrorData::new(
                ErrorCode::METHOD_NOT_FOUND,
                format!("unknown tool: {}", request.name),
                None,
            )),
        }
    }

    fn get_info(&self) -> ServerInfo {
        Self::server_info()
    }
}

/// Service wrapper that makes rmcp's direct transport explicitly modern-only.
///
/// `rmcp::serve_server` has a useful compatibility path that detects the first
/// request and then switches into stateless mode.  The executable server uses
/// `serve_directly` instead, so there is no implicit initialize lifecycle and
/// every request is checked here before rmcp dispatches it.
#[derive(Clone)]
pub struct ModernService {
    server: AzmcpServer,
}

impl ModernService {
    /// Construct a modern-only service around an `AzmcpServer`.
    pub fn new(server: AzmcpServer) -> Self {
        Self { server }
    }
}

impl Service<RoleServer> for ModernService {
    async fn handle_request(
        &self,
        request: ClientRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<ServerResult, ErrorData> {
        if matches!(request, ClientRequest::InitializeRequest(_)) {
            return Err(legacy_initialize_error());
        }

        validate_modern_metadata(&context.meta)?;
        <AzmcpServer as Service<RoleServer>>::handle_request(&self.server, request, context).await
    }

    async fn handle_notification(
        &self,
        notification: rmcp::model::ClientNotification,
        context: NotificationContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        <AzmcpServer as Service<RoleServer>>::handle_notification(
            &self.server,
            notification,
            context,
        )
        .await
    }

    fn get_info(&self) -> ServerInfo {
        <AzmcpServer as ServerHandler>::get_info(&self.server)
    }
}

/// Run the modern-only server over stdio.
pub async fn run_stdio() -> anyhow::Result<()> {
    let application = runtime::production_application().await?;
    let service = rmcp::service::serve_directly(
        AzmcpServer::new(application)?.modern_service(),
        rmcp::transport::stdio(),
        None::<rmcp::model::ClientInfo>,
    );
    service.waiting().await?;
    Ok(())
}

fn parse_tool_args<T: DeserializeOwned>(arguments: Option<JsonObject>) -> Result<T, ErrorData> {
    serde_json::from_value(Value::Object(arguments.unwrap_or_default())).map_err(|_| {
        ErrorData::invalid_params("tool arguments do not match the declared v0 schema", None)
    })
}

fn tool_result<T: Serialize>(result: Result<T, AppError>) -> Result<CallToolResponse, ErrorData> {
    match result {
        Ok(result) => {
            let value = serde_json::to_value(result)
                .map_err(|_| ErrorData::internal_error("tool result serialization failed", None))?;
            let encoded_bytes = serde_json::to_vec(&value)
                .map_err(|_| ErrorData::internal_error("tool result sizing failed", None))?
                .len();
            if encoded_bytes > MAX_TOOL_RESULT_BYTES {
                return domain_error_result(
                    "result_too_large",
                    "tool result exceeds the 1 MiB transport limit",
                    false,
                    Some(result_too_large_details(&ResultTooLargeSummary::from_json(
                        &value,
                        encoded_bytes,
                        MAX_TOOL_RESULT_BYTES,
                    ))),
                );
            }
            bounded_call_tool_result(value, false)
        }
        Err(error) => {
            let details = error
                .result_too_large_summary()
                .map(result_too_large_details);
            domain_error_result(
                error.code(),
                app_error_message(&error).as_ref(),
                matches!(error.code(), "upstream_error" | "worker_crashed"),
                details,
            )
        }
    }
}

fn domain_error_result(
    code: &str,
    message: &str,
    retryable: bool,
    details: Option<Value>,
) -> Result<CallToolResponse, ErrorData> {
    let correlation_id = app::correlation_id()
        .map_err(|_| ErrorData::internal_error("correlation ID generation failed", None))?;
    let mut value = json!({
        "code": code,
        "message": message,
        "retryable": retryable,
        "correlationId": correlation_id,
    });
    if let Some(details) = details {
        value["details"] = details;
    }
    bounded_call_tool_result(value, true)
}

fn bounded_call_tool_result(value: Value, is_error: bool) -> Result<CallToolResponse, ErrorData> {
    let value_bytes = serde_json::to_vec(&value)
        .map_err(|_| ErrorData::internal_error("tool result sizing failed", None))?
        .len();
    if value_bytes > MAX_TOOL_RESULT_BYTES {
        return oversized_call_tool_result(&value, value_bytes);
    }

    let result = if is_error {
        CallToolResult::structured_error(value)
    } else {
        CallToolResult::structured(value)
    };
    let result = result.with_meta(Some(server_info_meta()));
    let wire_bytes = serde_json::to_vec(&result)
        .map_err(|_| ErrorData::internal_error("tool result sizing failed", None))?
        .len();
    if wire_bytes > MAX_TOOL_RESULT_BYTES {
        let value = result.structured_content.as_ref().ok_or_else(|| {
            ErrorData::internal_error("tool result structured content missing", None)
        })?;
        return oversized_call_tool_result(value, wire_bytes);
    }
    Ok(result.into())
}

fn oversized_call_tool_result(
    value: &Value,
    encoded_bytes: usize,
) -> Result<CallToolResponse, ErrorData> {
    let correlation_id = app::correlation_id()
        .map_err(|_| ErrorData::internal_error("correlation ID generation failed", None))?;
    let summary = ResultTooLargeSummary::from_json(value, encoded_bytes, MAX_TOOL_RESULT_BYTES);
    let fallback = json!({
        "code": "result_too_large",
        "message": "structured tool result exceeded the 1 MiB transport limit",
        "retryable": false,
        "correlationId": correlation_id.clone(),
        "details": result_too_large_details(&summary),
    });
    let fallback = CallToolResult::structured_error(fallback).with_meta(Some(server_info_meta()));
    let fallback = match serde_json::to_vec(&fallback) {
        Ok(encoded) if encoded.len() <= MAX_TOOL_RESULT_BYTES => fallback,
        _ => CallToolResult::structured_error(json!({
            "code": "result_too_large",
            "message": "structured tool result exceeded the 1 MiB transport limit",
            "retryable": false,
            "correlationId": correlation_id,
        }))
        .with_meta(Some(server_info_meta())),
    };
    let fallback_bytes = serde_json::to_vec(&fallback)
        .map_err(|_| ErrorData::internal_error("bounded fallback sizing failed", None))?
        .len();
    if fallback_bytes > MAX_TOOL_RESULT_BYTES {
        return Err(ErrorData::internal_error(
            "bounded fallback exceeds the transport limit",
            None,
        ));
    }
    Ok(fallback.into())
}

fn result_too_large_details(summary: &ResultTooLargeSummary) -> Value {
    json!({
        "summary": summary,
        "guidance": "Reduce the value in JavaScript before returning it: project needed fields, filter rows, or aggregate counts.",
    })
}

fn app_error_message(error: &AppError) -> Cow<'static, str> {
    if let Some(message) = error.authentication_message() {
        return Cow::Owned(message.to_owned());
    }
    Cow::Borrowed(match error.code() {
        "invalid_request" => "request is outside the implemented v0 contract",
        "account_ambiguous" => "Azure account binding is missing or ambiguous",
        "authentication_required" => "Azure CLI account discovery is unavailable",
        "subscription_mismatch" => "subscription binding validation failed",
        "context_busy" => "another run is already active in this context",
        "context_evicted" => "the execution context no longer exists",
        "worker_crashed" => "the isolated JavaScript worker is unavailable",
        "execution_timeout" => "JavaScript execution exceeded its deadline",
        "result_too_large" => "the JavaScript result exceeds the v0 size limit",
        "artifact_capacity" => "managed artifact storage capacity is exhausted",
        "schema_unavailable" => "the offline schema index is unavailable",
        "schema_not_found" => "the reviewed schema entry was not found",
        "schema_version_not_found" => "the API version is not reviewed for that entry",
        "schema_cloud_not_bound" => "the schema cloud is not bound by the context",
        "route_denied" => "the request is not in the reviewed route policy",
        "capability_denied" => "the context does not authorize that operation scope",
        "upstream_error" => "the upstream operation could not complete",
        _ => "the tool could not complete",
    })
}

fn server_info_meta() -> MetaObject {
    let mut meta = MetaObject::new();
    meta.insert(
        SERVER_INFO_META_KEY.to_owned(),
        serde_json::to_value(AzmcpServer::implementation())
            .expect("server implementation is always serializable"),
    );
    meta
}

fn legacy_initialize_error() -> ErrorData {
    ErrorData::invalid_request(
        "legacy initialize is unsupported; use server/discover with protocol version 2026-07-28",
        Some(json!({
            "supportedVersions": [PROTOCOL_VERSION],
            "next": "server/discover"
        })),
    )
}

fn validate_modern_metadata(meta: &RequestMetaObject) -> Result<(), ErrorData> {
    if let Some(requested) = meta.protocol_version()
        && requested != ProtocolVersion::V_2026_07_28
    {
        return Err(ErrorData::unsupported_protocol_version(
            requested,
            &[ProtocolVersion::V_2026_07_28],
        ));
    }

    let missing = meta.missing_required_keys(&ProtocolVersion::V_2026_07_28);
    if missing.is_empty() {
        return Ok(());
    }

    Err(ErrorData::invalid_params(
        format!(
            "request _meta is missing or malformed: {}",
            missing.join(", ")
        ),
        Some(json!({"missing": missing})),
    ))
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use azmcp_core::{
        config::{Config, ResolvedCloudBinding},
        context::Context,
    };
    use rmcp::{
        model::{
            CallToolRequest, CallToolRequestParams, ClientCapabilities, ClientJsonRpcMessage,
            ClientRequest, DiscoverRequest, DiscoverRequestParams, ErrorCode, Implementation,
            ListToolsRequest, RequestId, ResultType, ServerJsonRpcMessage, ServerResult,
        },
        transport::{IntoTransport, Transport},
    };
    use tokio::sync::Notify;

    use super::*;
    use crate::{
        app::{
            BindingValidator, BoxFuture, DependencyError, MemoryProfileSource, WorkerFactory,
            WorkerHandle, default_registry,
        },
        audit::{AuditError, AuditSink},
        host::CallRecord,
        host::{ClientFactoryError, HttpClientFactory},
        worker::{ExecutionResult, HostCallHandler, ResultTooLargeSummary},
    };

    struct AllowValidator;

    impl BindingValidator for AllowValidator {
        fn validate<'a>(
            &'a self,
            _binding: &'a ResolvedCloudBinding,
            _identity_pin: &'a azmcp_core::credential::CredentialIdentityPin,
        ) -> BoxFuture<'a, Result<(), DependencyError>> {
            Box::pin(async { Ok(()) })
        }
    }

    struct TestWorkerFactory;

    impl WorkerFactory for TestWorkerFactory {
        fn start<'a>(
            &'a self,
            _context: &'a Context,
        ) -> BoxFuture<'a, Result<Box<dyn WorkerHandle>, DependencyError>> {
            Box::pin(async { Ok(Box::new(TestWorker) as Box<dyn WorkerHandle>) })
        }
    }

    struct CancelOpenWorkerFactory {
        calls: AtomicUsize,
        entered: Arc<Notify>,
    }

    impl WorkerFactory for CancelOpenWorkerFactory {
        fn start<'a>(
            &'a self,
            _context: &'a Context,
        ) -> BoxFuture<'a, Result<Box<dyn WorkerHandle>, DependencyError>> {
            Box::pin(async move {
                if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    self.entered.notify_one();
                    std::future::pending::<()>().await;
                }
                Ok(Box::new(TestWorker) as Box<dyn WorkerHandle>)
            })
        }
    }

    struct TestWorker;

    impl WorkerHandle for TestWorker {
        fn execute<'a>(
            &'a mut self,
            code: &'a str,
            _timeout: Duration,
            _host_handler: Option<HostCallHandler>,
        ) -> BoxFuture<'a, Result<ExecutionResult, DependencyError>> {
            Box::pin(async move {
                if code == "__wait_for_cancellation__" {
                    std::future::pending::<()>().await;
                }
                if code == "__too_large__" {
                    let shape = json!({"records": ["never-return-this-value"]});
                    return Err(DependencyError::ResultTooLarge {
                        summary: Box::new(ResultTooLargeSummary::from_json(&shape, 70_000, 65_536)),
                    });
                }
                Ok(ExecutionResult {
                    value: Value::String(code.to_owned()),
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

    struct NoClientFactory;

    struct TestAudit;

    impl AuditSink for TestAudit {
        fn prepare(&self) -> Result<(), AuditError> {
            Ok(())
        }

        fn append(&self, _record: &CallRecord) -> Result<(), AuditError> {
            Ok(())
        }

        fn append_artifact(
            &self,
            _record: &crate::audit::ArtifactWriteAuditRecord,
        ) -> Result<(), AuditError> {
            Ok(())
        }
    }

    impl HttpClientFactory for NoClientFactory {
        fn client_for(
            &self,
            _binding: &ResolvedCloudBinding,
        ) -> Result<Arc<azmcp_core::http::HttpClient>, ClientFactoryError> {
            Err(ClientFactoryError::Unavailable)
        }
    }

    fn test_server_with(
        registry: azmcp_core::context::ContextRegistry,
        worker_factory: Arc<dyn WorkerFactory>,
    ) -> AzmcpServer {
        let application = Application::from_arcs_with_host_clients(
            Config::empty(),
            registry,
            Arc::new(MemoryProfileSource::new(
                br#"{"subscriptions":[{"id":"11111111-1111-1111-1111-111111111111","name":"synthetic","state":"Enabled","tenantId":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","environmentName":"AzureCloud","user":{"name":"test@example.invalid"}}]}"#.to_vec(),
            )),
            Arc::new(AllowValidator),
            worker_factory,
            Arc::new(NoClientFactory),
            crate::app::DEFAULT_POLICY_HASH,
            azmcp_core::routes::V0_POLICY_VERSION,
        )
        .unwrap()
        .with_audit_sink(Arc::new(TestAudit))
        .with_artifact_store(Arc::new(
            crate::artifacts::FileArtifactStore::new(
                std::env::temp_dir().join("azmcp-lib-test-artifacts"),
            )
            .expect("artifact store"),
        ));
        AzmcpServer::new(application).unwrap()
    }

    fn test_server() -> AzmcpServer {
        test_server_with(default_registry().unwrap(), Arc::new(TestWorkerFactory))
    }

    fn modern_meta() -> RequestMetaObject {
        RequestMetaObject::with_client_context(
            ProtocolVersion::V_2026_07_28,
            Implementation::new("test-client", "0.1.0"),
            ClientCapabilities::default(),
        )
    }

    #[test]
    fn server_identity_and_capabilities_are_deterministic() {
        let first = AzmcpServer::server_info();
        let second = AzmcpServer::server_info();
        assert_eq!(first, second);
        assert_eq!(first.protocol_version, ProtocolVersion::V_2026_07_28);
        assert_eq!(first.server_info, AzmcpServer::implementation());
        assert_eq!(first.capabilities.tools.unwrap().list_changed, None);
        assert!(first.capabilities.prompts.is_none());
        assert!(first.capabilities.resources.is_none());
        assert!(first.capabilities.logging.is_none());
    }

    #[test]
    fn server_rejects_an_unavailable_managed_artifact_writer() {
        let application = Application::from_arcs_with_host_clients(
            Config::empty(),
            default_registry().expect("registry"),
            Arc::new(MemoryProfileSource::new(
                br#"{"subscriptions":[{"id":"11111111-1111-1111-1111-111111111111","name":"synthetic","state":"Enabled","tenantId":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","environmentName":"AzureCloud","user":{"name":"test@example.invalid"}}]}"#.to_vec(),
            )),
            Arc::new(AllowValidator),
            Arc::new(TestWorkerFactory),
            Arc::new(NoClientFactory),
            crate::app::DEFAULT_POLICY_HASH,
            azmcp_core::routes::V0_POLICY_VERSION,
        )
        .expect("application")
        .with_audit_sink(Arc::new(TestAudit));
        assert!(AzmcpServer::new(application).is_err());
    }

    #[test]
    fn tool_catalog_and_schemas_are_deterministic_and_bounded() {
        let first = serde_json::to_value(AzmcpServer::tools()).unwrap();
        let second = serde_json::to_value(AzmcpServer::tools()).unwrap();
        assert_eq!(first, second);
        assert_eq!(AzmcpServer::tools().len(), 6);
        assert_eq!(AzmcpServer::tools()[0].name, ACCOUNTS_TOOL);
        for tool in AzmcpServer::tools() {
            assert_eq!(
                tool.input_schema["$schema"],
                "https://json-schema.org/draft/2020-12/schema"
            );
            assert_eq!(
                tool.output_schema.as_ref().unwrap()["$schema"],
                "https://json-schema.org/draft/2020-12/schema"
            );
            assert!(!serde_json::to_string(&tool).unwrap().contains("$ref"));
        }
    }

    async fn receive(client: &mut impl Transport<rmcp::RoleClient>) -> ServerJsonRpcMessage {
        client.receive().await.expect("server response")
    }

    async fn run_server(
        server: AzmcpServer,
        transport: tokio::io::DuplexStream,
    ) -> Result<rmcp::service::QuitReason, tokio::task::JoinError> {
        rmcp::service::serve_directly(
            server.modern_service(),
            transport,
            None::<rmcp::model::ClientInfo>,
        )
        .waiting()
        .await
    }

    async fn modern_client() -> (
        impl Transport<rmcp::RoleClient>,
        tokio::task::JoinHandle<Result<rmcp::service::QuitReason, tokio::task::JoinError>>,
    ) {
        modern_client_with(test_server()).await
    }

    async fn modern_client_with(
        server: AzmcpServer,
    ) -> (
        impl Transport<rmcp::RoleClient>,
        tokio::task::JoinHandle<Result<rmcp::service::QuitReason, tokio::task::JoinError>>,
    ) {
        let (server_transport, client_transport) = tokio::io::duplex(16_384);
        let server_task = tokio::spawn(run_server(server, server_transport));
        let client = IntoTransport::<rmcp::RoleClient, _, _>::into_transport(client_transport);
        (client, server_task)
    }

    fn list_tools_request(id: i64, meta: Option<RequestMetaObject>) -> ClientJsonRpcMessage {
        let mut request = ListToolsRequest {
            method: Default::default(),
            params: None,
            extensions: Default::default(),
        };
        if let Some(meta) = meta {
            request.extensions.insert(meta);
        }
        ClientJsonRpcMessage::request(
            ClientRequest::ListToolsRequest(request),
            RequestId::Number(id),
        )
    }

    fn call_tool_request(id: i64, name: &'static str, arguments: Value) -> ClientJsonRpcMessage {
        let arguments = arguments.as_object().cloned().expect("object arguments");
        let mut request =
            CallToolRequest::new(CallToolRequestParams::new(name).with_arguments(arguments));
        request.extensions.insert(modern_meta());
        ClientJsonRpcMessage::request(
            ClientRequest::CallToolRequest(request),
            RequestId::Number(id),
        )
    }

    async fn receive_tool_result(client: &mut impl Transport<rmcp::RoleClient>) -> CallToolResult {
        let ServerJsonRpcMessage::Response(response) = receive(client).await else {
            panic!("expected tool response")
        };
        let ServerResult::CallToolResult(result) = response.result else {
            panic!("expected complete tool result")
        };
        result
    }

    #[tokio::test]
    async fn discover_list_and_accounts_are_modern_structured_results() {
        let (mut client, server_task) = modern_client().await;

        let mut discover = DiscoverRequest::new(DiscoverRequestParams {});
        discover.extensions.insert(modern_meta());
        client
            .send(ClientJsonRpcMessage::request(
                ClientRequest::DiscoverRequest(discover),
                RequestId::Number(1),
            ))
            .await
            .unwrap();
        let ServerJsonRpcMessage::Response(response) = receive(&mut client).await else {
            panic!("expected discovery response")
        };
        let ServerResult::DiscoverResult(discovered) = response.result else {
            panic!("expected typed discovery result")
        };
        assert_eq!(
            discovered.supported_versions,
            vec![ProtocolVersion::V_2026_07_28]
        );
        assert_eq!(discovered.ttl_ms, CACHE_TTL_MS);
        assert_eq!(discovered.cache_scope, CacheScope::Public);
        assert_eq!(
            discovered.server_info(),
            Some(AzmcpServer::implementation())
        );

        client
            .send(list_tools_request(2, Some(modern_meta())))
            .await
            .unwrap();
        let ServerJsonRpcMessage::Response(response) = receive(&mut client).await else {
            panic!("expected tools response")
        };
        let ServerResult::ListToolsResult(listed) = response.result else {
            panic!("expected typed tools result")
        };
        assert_eq!(listed.result_type, Some(ResultType::COMPLETE));
        assert_eq!(listed.ttl_ms, Some(CACHE_TTL_MS));
        assert_eq!(listed.cache_scope, Some(CacheScope::Public));
        assert_eq!(listed.tools, AzmcpServer::tools());
        assert_eq!(
            listed.meta.unwrap()[SERVER_INFO_META_KEY],
            json!({
                "name": SERVER_NAME,
                "version": SERVER_VERSION
            })
        );

        let mut call = CallToolRequest::new(CallToolRequestParams::new(ACCOUNTS_TOOL));
        call.extensions.insert(modern_meta());
        client
            .send(ClientJsonRpcMessage::request(
                ClientRequest::CallToolRequest(call),
                RequestId::Number(3),
            ))
            .await
            .unwrap();
        let ServerJsonRpcMessage::Response(response) = receive(&mut client).await else {
            panic!("expected tool call response")
        };
        let ServerResult::CallToolResult(result) = response.result else {
            panic!("expected typed call result")
        };
        assert_eq!(result.result_type, Some(ResultType::COMPLETE));
        assert_eq!(result.is_error, Some(false));
        let structured = result.structured_content.expect("structured content");
        assert_eq!(structured["accounts"].as_array().unwrap().len(), 1);
        let text = result.content[0].as_text().expect("text content");
        assert_eq!(
            serde_json::from_str::<Value>(&text.text).unwrap(),
            structured
        );
        assert_eq!(
            result.meta.unwrap()[SERVER_INFO_META_KEY],
            json!({
                "name": SERVER_NAME,
                "version": SERVER_VERSION
            })
        );

        drop(client);
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn modern_service_rejects_legacy_and_bad_request_metadata() {
        let (mut client, server_task) = modern_client().await;

        let initialize: ClientJsonRpcMessage = serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "legacy", "version": "1.0.0"}
            }
        }))
        .unwrap();
        client.send(initialize).await.unwrap();
        let ServerJsonRpcMessage::Error(error) = receive(&mut client).await else {
            panic!("expected initialize error")
        };
        assert_eq!(error.error.code, ErrorCode::INVALID_REQUEST);
        assert!(error.error.message.contains(PROTOCOL_VERSION));

        client.send(list_tools_request(2, None)).await.unwrap();
        let ServerJsonRpcMessage::Error(error) = receive(&mut client).await else {
            panic!("expected missing metadata error")
        };
        assert_eq!(error.error.code, ErrorCode::INVALID_PARAMS);

        let mut unsupported = RequestMetaObject::new();
        unsupported.insert(
            "io.modelcontextprotocol/protocolVersion".to_owned(),
            json!("2099-01-01"),
        );
        unsupported.set_client_capabilities(ClientCapabilities::default());
        client
            .send(list_tools_request(3, Some(unsupported)))
            .await
            .unwrap();
        let ServerJsonRpcMessage::Error(error) = receive(&mut client).await else {
            panic!("expected unsupported metadata error")
        };
        assert_eq!(error.error.code, ErrorCode::UNSUPPORTED_PROTOCOL_VERSION);

        drop(client);
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn tool_lifecycle_is_explicit_and_structured() {
        let (mut client, server_task) = modern_client().await;
        client
            .send(call_tool_request(1, CONTEXT_OPEN_TOOL, json!({})))
            .await
            .unwrap();
        let opened = receive_tool_result(&mut client).await;
        assert_eq!(opened.is_error, Some(false));
        let context_id = opened.structured_content.unwrap()["contextId"]
            .as_str()
            .unwrap()
            .to_owned();

        client
            .send(call_tool_request(
                2,
                RUN_TOOL,
                json!({"contextId": context_id, "code": "meaningful-value"}),
            ))
            .await
            .unwrap();
        let ran = receive_tool_result(&mut client).await;
        assert_eq!(ran.is_error, Some(false));
        let ran = ran.structured_content.unwrap();
        assert_eq!(ran["value"], "meaningful-value");
        assert_eq!(ran["context"]["identity"], "user");

        client
            .send(call_tool_request(
                3,
                CONTEXT_CLOSE_TOOL,
                json!({"contextId": context_id}),
            ))
            .await
            .unwrap();
        let closed = receive_tool_result(&mut client).await;
        assert_eq!(closed.structured_content.unwrap(), json!({"closed": true}));

        client
            .send(call_tool_request(
                4,
                RUN_TOOL,
                json!({"contextId": context_id, "code": "cannot-run"}),
            ))
            .await
            .unwrap();
        let evicted = receive_tool_result(&mut client).await;
        assert_eq!(evicted.is_error, Some(true));
        assert_eq!(
            evicted.structured_content.unwrap()["code"],
            "context_evicted"
        );

        drop(client);
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn schema_tools_return_modern_structured_results_and_domain_errors() {
        let (mut client, server_task) = modern_client().await;
        client
            .send(call_tool_request(1, CONTEXT_OPEN_TOOL, json!({})))
            .await
            .unwrap();
        let opened = receive_tool_result(&mut client).await;
        let context_id = opened.structured_content.unwrap()["contextId"]
            .as_str()
            .unwrap()
            .to_owned();

        client
            .send(call_tool_request(
                2,
                SCHEMA_SEARCH_TOOL,
                json!({"contextId": context_id, "query": "namespace"}),
            ))
            .await
            .unwrap();
        let searched =
            tokio::time::timeout(Duration::from_secs(1), receive_tool_result(&mut client))
                .await
                .expect("schema search response");
        assert_eq!(searched.is_error, Some(false));
        let searched = searched.structured_content.unwrap();
        assert_eq!(
            searched["results"][0]["entryId"],
            "AzureCloud.providers.get"
        );
        assert_eq!(
            searched["results"][0]["pathTemplate"],
            "/providers/{namespace}"
        );
        assert_eq!(searched["results"][0]["executionSurface"], "az.request");
        assert_eq!(
            searched["results"][0]["audience"],
            "https://management.azure.com/"
        );
        assert_eq!(searched["results"][0]["dataPlane"], Value::Null);

        client
            .send(call_tool_request(
                3,
                SCHEMA_GET_TOOL,
                json!({
                    "contextId": context_id,
                    "entryId": "AzureCloud.providers.get",
                    "apiVersion": azmcp_core::routes::PROVIDERS_API_VERSION
                }),
            ))
            .await
            .unwrap();
        let found = tokio::time::timeout(Duration::from_secs(1), receive_tool_result(&mut client))
            .await
            .expect("schema get response");
        assert_eq!(found.is_error, Some(false));
        let found = found.structured_content.unwrap();
        assert_eq!(found["schema"]["schemaAvailability"], "metadataOnly");
        assert_eq!(found["schema"]["executionSurface"], "az.request");
        assert_eq!(found["schema"]["audience"], "https://management.azure.com/");
        assert_eq!(found["schema"]["dataPlane"], Value::Null);
        assert_eq!(found["schema"]["dataScope"], Value::Null);
        assert_eq!(
            found["schema"]["argumentSchema"]["additionalProperties"],
            false
        );
        assert_eq!(
            found["schema"]["argumentSchema"]["properties"]["method"]["const"],
            "GET"
        );
        assert!(
            found["schema"]["argumentSchema"]["properties"]
                .get("headers")
                .is_none()
        );

        client
            .send(call_tool_request(
                4,
                SCHEMA_GET_TOOL,
                json!({
                    "contextId": context_id,
                    "entryId": "AzureCloud.metrics.single",
                    "apiVersion": azmcp_core::routes::METRICS_API_VERSION
                }),
            ))
            .await
            .unwrap();
        let helper = tokio::time::timeout(Duration::from_secs(1), receive_tool_result(&mut client))
            .await
            .expect("helper schema get response");
        assert_eq!(helper.is_error, Some(false));
        let helper = helper.structured_content.unwrap()["schema"].clone();
        assert_eq!(helper["executionSurface"], "az.metrics.single");
        assert_eq!(helper["audience"], "https://management.azure.com/");
        assert_eq!(helper["dataPlane"], Value::Null);
        assert_eq!(helper["dataScope"], "boundSubscription");
        assert_eq!(helper["requestBodySchema"], Value::Null);
        assert_eq!(helper["argumentSchema"]["additionalProperties"], false);
        assert_eq!(
            helper["argumentSchema"]["required"],
            json!(["cloud", "resourceId", "metricNames"])
        );

        client
            .send(call_tool_request(
                5,
                SCHEMA_GET_TOOL,
                json!({
                    "contextId": context_id,
                    "entryId": "AzureCloud.not-reviewed.get",
                    "apiVersion": azmcp_core::routes::PROVIDERS_API_VERSION
                }),
            ))
            .await
            .unwrap();
        let missing =
            tokio::time::timeout(Duration::from_secs(1), receive_tool_result(&mut client))
                .await
                .expect("schema missing response");
        assert_eq!(missing.is_error, Some(true));
        assert_eq!(
            missing.structured_content.unwrap()["code"],
            "schema_not_found"
        );

        client
            .send(call_tool_request(
                6,
                CONTEXT_CLOSE_TOOL,
                json!({"contextId": context_id}),
            ))
            .await
            .unwrap();
        let closed = tokio::time::timeout(Duration::from_secs(1), receive_tool_result(&mut client))
            .await
            .expect("context close response");
        assert_eq!(closed.is_error, Some(false));

        drop(client);
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn result_too_large_is_a_shape_only_domain_error_with_reduction_guidance() {
        let (mut client, server_task) = modern_client().await;
        client
            .send(call_tool_request(1, CONTEXT_OPEN_TOOL, json!({})))
            .await
            .unwrap();
        let opened = receive_tool_result(&mut client).await;
        let context_id = opened.structured_content.unwrap()["contextId"]
            .as_str()
            .unwrap()
            .to_owned();

        client
            .send(call_tool_request(
                2,
                RUN_TOOL,
                json!({"contextId": context_id, "code": "__too_large__"}),
            ))
            .await
            .unwrap();
        let result = receive_tool_result(&mut client).await;
        assert_eq!(result.is_error, Some(true));
        let structured = result.structured_content.unwrap();
        assert_eq!(structured["code"], "result_too_large");
        assert_eq!(structured["details"]["summary"]["type"], "object");
        assert_eq!(structured["details"]["summary"]["encodedBytes"], 70_000);
        assert_eq!(structured["details"]["summary"]["limitBytes"], 65_536);
        assert_eq!(structured["details"]["summary"]["keyCount"], 1);
        assert!(
            structured["details"]["guidance"]
                .as_str()
                .unwrap()
                .contains("project")
        );
        let serialized = serde_json::to_string(&structured).unwrap();
        assert!(!serialized.contains("never-return-this-value"));

        client
            .send(call_tool_request(
                3,
                CONTEXT_CLOSE_TOOL,
                json!({"contextId": context_id}),
            ))
            .await
            .unwrap();
        let closed = receive_tool_result(&mut client).await;
        assert_eq!(closed.structured_content.unwrap(), json!({"closed": true}));

        drop(client);
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn modern_cancellation_disposes_the_execution_context() {
        let (mut client, server_task) = modern_client().await;
        client
            .send(call_tool_request(1, CONTEXT_OPEN_TOOL, json!({})))
            .await
            .unwrap();
        let opened = receive_tool_result(&mut client).await;
        let context_id = opened.structured_content.unwrap()["contextId"]
            .as_str()
            .unwrap()
            .to_owned();

        client
            .send(call_tool_request(
                2,
                RUN_TOOL,
                json!({
                    "contextId": context_id,
                    "code": "__wait_for_cancellation__",
                    "timeoutMs": 60_000
                }),
            ))
            .await
            .unwrap();
        tokio::task::yield_now().await;
        let cancelled: ClientJsonRpcMessage = serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": 2, "reason": "synthetic test cancellation"}
        }))
        .unwrap();
        client.send(cancelled).await.unwrap();

        client
            .send(call_tool_request(
                3,
                RUN_TOOL,
                json!({"contextId": context_id, "code": "must-not-run"}),
            ))
            .await
            .unwrap();
        let response = receive_tool_result(&mut client).await;
        assert_eq!(response.is_error, Some(true));
        assert_eq!(
            response.structured_content.unwrap()["code"],
            "context_evicted"
        );

        drop(client);
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn modern_cancellation_rolls_back_context_open() {
        let entered = Arc::new(Notify::new());
        let registry =
            azmcp_core::context::ContextRegistry::new(azmcp_core::context::RegistryConfig::new(
                1,
                Duration::from_secs(60),
                Duration::from_secs(600),
            ))
            .unwrap();
        let server = test_server_with(
            registry,
            Arc::new(CancelOpenWorkerFactory {
                calls: AtomicUsize::new(0),
                entered: Arc::clone(&entered),
            }),
        );
        let (mut client, server_task) = modern_client_with(server).await;

        client
            .send(call_tool_request(1, CONTEXT_OPEN_TOOL, json!({})))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("context open entered worker startup");
        let cancelled: ClientJsonRpcMessage = serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": 1, "reason": "synthetic open cancellation"}
        }))
        .unwrap();
        client.send(cancelled).await.unwrap();

        client
            .send(call_tool_request(2, CONTEXT_OPEN_TOOL, json!({})))
            .await
            .unwrap();
        let opened = tokio::time::timeout(Duration::from_secs(1), receive_tool_result(&mut client))
            .await
            .expect("cancelled open released registry capacity");
        assert_eq!(opened.is_error, Some(false));
        let context_id = opened.structured_content.unwrap()["contextId"]
            .as_str()
            .unwrap()
            .to_owned();

        client
            .send(call_tool_request(
                3,
                CONTEXT_CLOSE_TOOL,
                json!({"contextId": context_id}),
            ))
            .await
            .unwrap();
        let closed = receive_tool_result(&mut client).await;
        assert_eq!(closed.structured_content.unwrap(), json!({"closed": true}));

        drop(client);
        server_task.await.unwrap().unwrap();
    }

    #[test]
    fn oversized_constructed_domain_error_is_bounded_at_mcp_boundary() {
        let secret = format!(
            "DO-NOT-RETURN-{}",
            "x".repeat(MAX_TOOL_RESULT_BYTES + 4_096)
        );
        let response = domain_error_result(
            "upstream_error",
            "safe error message",
            true,
            Some(json!({"secret": secret})),
        )
        .expect("bounded domain error");
        let rmcp::model::CallToolResponse::Complete(response) = response else {
            panic!("expected complete tool response");
        };
        let encoded = serde_json::to_vec(&response).expect("complete MCP result JSON");
        let structured = response.structured_content.expect("structured content");
        assert!(encoded.len() <= MAX_TOOL_RESULT_BYTES);
        assert_eq!(structured["code"], "result_too_large");
        assert!(
            !String::from_utf8(encoded)
                .unwrap()
                .contains("DO-NOT-RETURN")
        );
    }

    #[test]
    fn near_limit_success_is_bounded_as_a_complete_mcp_result() {
        let value = json!({
            "value": "x".repeat(MAX_TOOL_RESULT_BYTES / 2 - 2_048),
        });
        let response = bounded_call_tool_result(value, false).expect("bounded success");
        let rmcp::model::CallToolResponse::Complete(response) = response else {
            panic!("expected complete tool response");
        };
        let encoded = serde_json::to_vec(&response).expect("complete MCP result JSON");
        assert!(encoded.len() <= MAX_TOOL_RESULT_BYTES);
        assert_eq!(response.is_error, Some(false));
    }

    #[test]
    fn request_message_round_trip_uses_rmcp_modern_types() {
        let mut request = rmcp::model::ListToolsRequest {
            method: Default::default(),
            params: None,
            extensions: Default::default(),
        };
        request.extensions.insert(modern_meta());
        let message = ClientJsonRpcMessage::request(
            ClientRequest::ListToolsRequest(request),
            RequestId::Number(1),
        );
        let json = serde_json::to_value(&message).unwrap();
        assert_eq!(json["method"], "tools/list");
        assert_eq!(
            json["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
            PROTOCOL_VERSION
        );
        let _: ClientJsonRpcMessage = serde_json::from_value(json).unwrap();
    }
}
