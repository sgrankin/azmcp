//! The modern-only MCP front end for `azmcp`.
//!
//! The first executable slice deliberately stops at the protocol boundary.  It
//! has no Azure credential, account, or network behavior, so the only tool it
//! advertises is a local protocol-status probe.  The v0 Azure tools are added
//! only when their stateful implementations exist.

use std::{borrow::Cow, future::Future, sync::Arc};

use rmcp::{
    ServerHandler, Service,
    model::{
        CacheScope, CallToolRequestParams, CallToolResponse, CallToolResult, ClientRequest,
        DiscoverResult, ErrorCode, ErrorData, Implementation, JsonObject, ListToolsResult,
        MetaObject, PaginatedRequestParams, ProtocolVersion, RequestMetaObject, ServerCapabilities,
        ServerInfo, ServerResult, Tool, ToolAnnotations,
    },
    service::{NotificationContext, RequestContext, RoleServer},
};
use serde_json::{Value, json};

/// The only protocol revision implemented by this server.
pub const PROTOCOL_VERSION: &str = "2026-07-28";

/// Stable server identity advertised in discovery and every result envelope.
pub const SERVER_NAME: &str = "azmcp";

/// Build version used as the server identity version.
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Cache lifetime for discovery and the deterministic tool catalog.
pub const CACHE_TTL_MS: u64 = 60_000;

/// A local, dependency-free probe that proves the modern result envelope.
pub const STATUS_TOOL_NAME: &str = "azmcp_status";

const SERVER_INFO_META_KEY: &str = "io.modelcontextprotocol/serverInfo";

/// The protocol-only server implementation.
#[derive(Clone, Copy, Debug, Default)]
pub struct AzmcpServer;

impl AzmcpServer {
    /// Construct the protocol-only server.
    pub const fn new() -> Self {
        Self
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
        vec![status_tool()]
    }

    /// Wrap the handler with the modern per-request lifecycle boundary.
    pub fn modern_service(self) -> ModernService {
        ModernService { server: self }
    }
}

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

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CallToolResponse, ErrorData>> + rmcp::service::MaybeSendFuture + '_
    {
        let result = if request.name != STATUS_TOOL_NAME {
            Err(ErrorData::new(
                ErrorCode::METHOD_NOT_FOUND,
                format!("unknown tool: {}", request.name),
                None,
            ))
        } else if request
            .arguments
            .as_ref()
            .is_some_and(|arguments| !arguments.is_empty())
        {
            Err(ErrorData::invalid_params(
                "azmcp_status does not accept arguments",
                None,
            ))
        } else {
            Ok(CallToolResult::structured(status_value())
                .with_meta(Some(server_info_meta()))
                .into())
        };
        std::future::ready(result)
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
#[derive(Clone, Copy, Debug)]
pub struct ModernService {
    server: AzmcpServer,
}

impl ModernService {
    /// Construct a modern-only service around an `AzmcpServer`.
    pub const fn new(server: AzmcpServer) -> Self {
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
    let service = rmcp::service::serve_directly(
        AzmcpServer::new().modern_service(),
        rmcp::transport::stdio(),
        None::<rmcp::model::ClientInfo>,
    );
    service.waiting().await?;
    Ok(())
}

fn status_tool() -> Tool {
    Tool::new(
        STATUS_TOOL_NAME,
        "Report azmcp's local MCP protocol status; this tool never contacts Azure.",
        schema_object(json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {},
            "additionalProperties": false
        })),
    )
    .with_raw_output_schema(schema_object(status_output_schema()))
    .with_annotations(
        ToolAnnotations::new()
            .read_only(true)
            .destructive(false)
            .idempotent(true)
            .open_world(false),
    )
}

fn status_value() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "server": {
            "name": SERVER_NAME,
            "version": SERVER_VERSION
        },
        "modernOnly": true,
        "azureAccess": false
    })
}

fn status_output_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "protocolVersion": {
                "type": "string",
                "const": PROTOCOL_VERSION
            },
            "server": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "const": SERVER_NAME},
                    "version": {"type": "string", "const": SERVER_VERSION}
                },
                "required": ["name", "version"],
                "additionalProperties": false
            },
            "modernOnly": {"type": "boolean", "const": true},
            "azureAccess": {"type": "boolean", "const": false}
        },
        "required": ["protocolVersion", "server", "modernOnly", "azureAccess"],
        "additionalProperties": false
    })
}

fn schema_object(value: Value) -> Arc<JsonObject> {
    let Value::Object(object) = value else {
        unreachable!("static schemas are JSON objects")
    };
    Arc::new(object)
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
    use rmcp::{
        model::{
            CallToolRequest, CallToolRequestParams, ClientCapabilities, ClientJsonRpcMessage,
            ClientRequest, DiscoverRequest, DiscoverRequestParams, ErrorCode, Implementation,
            ListToolsRequest, RequestId, ResultType, ServerJsonRpcMessage, ServerResult,
        },
        transport::{IntoTransport, Transport},
    };

    use super::*;

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
    fn tool_catalog_and_schemas_are_deterministic_and_bounded() {
        let first = serde_json::to_value(AzmcpServer::tools()).unwrap();
        let second = serde_json::to_value(AzmcpServer::tools()).unwrap();
        assert_eq!(first, second);
        let tool = &AzmcpServer::tools()[0];
        assert_eq!(tool.name, STATUS_TOOL_NAME);
        assert_eq!(
            tool.input_schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(
            tool.output_schema.as_ref().unwrap()["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        let serialized = serde_json::to_string(tool).unwrap();
        assert!(!serialized.contains("$ref"));
    }

    async fn receive(client: &mut impl Transport<rmcp::RoleClient>) -> ServerJsonRpcMessage {
        client.receive().await.expect("server response")
    }

    async fn run_server(
        transport: tokio::io::DuplexStream,
    ) -> Result<rmcp::service::QuitReason, tokio::task::JoinError> {
        rmcp::service::serve_directly(
            AzmcpServer::new().modern_service(),
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
        let (server_transport, client_transport) = tokio::io::duplex(16_384);
        let server_task = tokio::spawn(run_server(server_transport));
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

    #[tokio::test]
    async fn discover_list_and_status_are_modern_structured_results() {
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

        let mut call = CallToolRequest::new(CallToolRequestParams::new(STATUS_TOOL_NAME));
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
