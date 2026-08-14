use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use azmcp::{
    AzmcpServer,
    app::{
        Application, HttpBindingValidator, MemoryProfileSource, ProcessWorkerFactory,
        default_registry,
    },
    audit::{AuditError, AuditSink},
    host::{CallDecision, CallRecord, ClientFactoryError, HttpClientFactory},
    tools::{CONTEXT_CLOSE_TOOL, CONTEXT_OPEN_TOOL, RUN_TOOL},
};
use azmcp_core::{
    accounts::parse_azure_profile_bytes,
    cloud::AzureCloud,
    config::{Config, ResolvedCloudBinding},
    credential::{TokenAudience, TokenRequest},
    http::{
        ArmOrigin, BearerCredential, CredentialFuture, CredentialProvider, HttpClient,
        LogsHttpClient, LogsOrigin,
    },
    policy::PolicyBundle,
    routes,
    schema::SchemaIndex,
};
use rmcp::{
    model::{
        CallToolRequest, CallToolRequestParams, CallToolResult, ClientCapabilities,
        ClientJsonRpcMessage, ClientRequest, Implementation, ProtocolVersion, RequestId,
        RequestMetaObject, ServerJsonRpcMessage, ServerResult,
    },
    transport::{IntoTransport, Transport},
};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const SUBSCRIPTION: &str = "11111111-1111-1111-1111-111111111111";
const TENANT: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const WORKSPACE: &str = "44444444-4444-4444-4444-444444444444";
const PRINCIPAL: &str = "cccccccc-cccc-cccc-cccc-cccccccccccc";
const CLIENT: &str = "dddddddd-dddd-dddd-dddd-dddddddddddd";
const TOKEN: &str = "synthetic-e2e-token";
const METRIC: &str = "E2E Secret Metric";
const KQL: &str = "E2E_SECRET_KQL | take 1";

#[derive(Default)]
struct FakeCredentials {
    requests: Mutex<Vec<TokenRequest>>,
}

impl CredentialProvider for FakeCredentials {
    fn acquire<'a>(&'a self, request: TokenRequest) -> CredentialFuture<'a> {
        Box::pin(async move {
            self.requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(request);
            BearerCredential::with_identity(TOKEN, PRINCIPAL, CLIENT)
        })
    }
}

#[derive(Default)]
struct MemoryAudit {
    prepares: AtomicUsize,
    records: Mutex<Vec<CallRecord>>,
}

impl AuditSink for MemoryAudit {
    fn prepare(&self) -> Result<(), AuditError> {
        self.prepares.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn append(&self, record: &CallRecord) -> Result<(), AuditError> {
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(record.clone());
        Ok(())
    }
}

struct LoopbackClientFactory {
    credentials: Arc<dyn CredentialProvider>,
    origin: String,
    policy: PolicyBundle,
}

impl HttpClientFactory for LoopbackClientFactory {
    fn client_for(
        &self,
        binding: &ResolvedCloudBinding,
    ) -> Result<Arc<HttpClient>, ClientFactoryError> {
        let origin = ArmOrigin::loopback_from_str(binding.cloud(), &self.origin)
            .map_err(|_| ClientFactoryError::Unavailable)?;
        HttpClient::with_loopback_origin(
            Arc::clone(&self.credentials),
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

    fn logs_client_for(
        &self,
        binding: &ResolvedCloudBinding,
    ) -> Result<Arc<LogsHttpClient>, ClientFactoryError> {
        let origin = LogsOrigin::loopback_from_str(binding.cloud(), &self.origin)
            .map_err(|_| ClientFactoryError::Unavailable)?;
        LogsHttpClient::with_loopback_origin(
            Arc::clone(&self.credentials),
            binding.cloud(),
            binding.subscription().clone(),
            binding.tenant().clone(),
            origin,
            self.policy.clone(),
        )
        .map(Arc::new)
        .map_err(|_| ClientFactoryError::Unavailable)
    }
}

#[tokio::test]
async fn modern_service_executes_synthetic_observability_end_to_end() {
    // Establish and validate every ambient-state replacement before opening a
    // socket or spawning the worker. The loopback address is injected only
    // after these synthetic dependencies exist.
    let profile = synthetic_profile();
    let accounts = parse_azure_profile_bytes(&profile).expect("synthetic profile");
    assert_eq!(accounts.candidates().count(), 1);
    let credentials = Arc::new(FakeCredentials::default());
    let audit = Arc::new(MemoryAudit::default());
    let policy = routes::v0_policy().expect("reviewed policy");
    let schema = Arc::new(SchemaIndex::v0(&policy).expect("aligned schema"));

    let (origin, upstream) = synthetic_upstream().await;
    let credential_provider: Arc<dyn CredentialProvider> = credentials.clone();
    let clients: Arc<dyn HttpClientFactory> = Arc::new(LoopbackClientFactory {
        credentials: credential_provider,
        origin,
        policy: policy.clone(),
    });
    let audit_sink: Arc<dyn AuditSink> = audit.clone();
    let validator = Arc::new(
        HttpBindingValidator::new(Arc::clone(&clients)).with_audit_sink(
            Arc::clone(&audit_sink),
            routes::V0_POLICY_HASH,
            policy.version(),
        ),
    );
    let application = Application::from_arcs_with_host_clients_and_schema(
        Config::empty(),
        default_registry().expect("registry"),
        Arc::new(MemoryProfileSource::new(profile)),
        validator,
        Arc::new(ProcessWorkerFactory::new(env!("CARGO_BIN_EXE_azmcp"))),
        clients,
        schema,
        routes::V0_POLICY_HASH,
        policy.version(),
    )
    .expect("synthetic application")
    .with_audit_sink(audit_sink);
    let server = AzmcpServer::new(application).expect("executable server");
    let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(async move {
        rmcp::service::serve_directly(
            server.modern_service(),
            server_transport,
            None::<rmcp::model::ClientInfo>,
        )
        .waiting()
        .await
    });
    let mut client = IntoTransport::<rmcp::RoleClient, _, _>::into_transport(client_transport);

    client
        .send(tool_request(
            1,
            CONTEXT_OPEN_TOOL,
            json!({
                "dataPlanes": ["logs.query"],
                "logsScopes": {"AzureCloud": {"scope": "allAccessible"}}
            }),
        ))
        .await
        .expect("send context open");
    let opened = receive_tool_result(&mut client).await;
    assert_eq!(opened.is_error, Some(false));
    let opened = opened.structured_content.expect("context result");
    let context_id = opened["contextId"].as_str().expect("context id").to_owned();
    assert_eq!(opened["dataPlanes"], json!(["logs.query"]));
    assert_eq!(
        opened["logsScopes"],
        json!({"AzureCloud": {"scope": "allAccessible"}})
    );
    assert_eq!(opened["resolvedBindings"][0]["subscription"], SUBSCRIPTION);

    let code = format!(
        r#"
(async () => {{
  globalThis.e2eCounter = 41;
  const [metrics, logs] = await Promise.all([
    az.metrics.single({{
      cloud: "AzureCloud",
      resourceId: "/subscriptions/{SUBSCRIPTION}/resourceGroups/e2e-rg/providers/Microsoft.Compute/virtualMachines/e2e-vm",
      metricNames: ["{METRIC}"],
      timespan: "PT1H"
    }}),
    az.logs.query({{
      cloud: "AzureCloud",
      workspaceId: "{WORKSPACE}",
      query: "{KQL}",
      timespan: "PT1H"
    }})
  ]);
  return {{metrics, logs}};
}})()
"#
    );
    client
        .send(tool_request(
            2,
            RUN_TOOL,
            json!({"contextId": context_id, "code": code, "timeoutMs": 5_000}),
        ))
        .await
        .expect("send observability run");
    let ran = receive_tool_result(&mut client).await;
    assert_eq!(ran.is_error, Some(false));
    let ran = ran.structured_content.expect("run result");
    assert_eq!(ran["value"]["metrics"]["body"]["kind"], "synthetic-metrics");
    assert_eq!(ran["value"]["metrics"]["body"]["value"][0]["average"], 12.5);
    assert_eq!(ran["value"]["logs"]["tables"][0]["rows"][0], json!([17]));
    assert_eq!(ran["callsOmitted"], 0);
    assert_eq!(ran["calls"].as_array().map(Vec::len), Some(2));
    let metrics_call = call(&ran, "az.metrics.single");
    assert_eq!(metrics_call["method"], "GET");
    assert_eq!(metrics_call["status"], 200);
    assert_eq!(metrics_call["subscriptionSource"], "explicit");
    assert_eq!(
        metrics_call["pathTemplate"],
        "/{resourceUri}/providers/Microsoft.Insights/metrics"
    );
    assert_eq!(
        metrics_call["rbacAction"],
        "Microsoft.Insights/Metrics/Read"
    );
    let logs_call = call(&ran, "az.logs.query");
    assert_eq!(logs_call["method"], "POST");
    assert_eq!(logs_call["status"], 200);
    assert_eq!(logs_call["subscriptionSource"], "auto");
    assert_eq!(logs_call["dataPlane"], "logs.query");
    assert_eq!(logs_call["dataScope"], "allAccessible");
    assert_eq!(
        logs_call["pathTemplate"],
        "/v1/workspaces/{workspaceId}/query"
    );
    assert_eq!(metrics_call["correlationId"], ran["correlationId"]);
    assert_eq!(logs_call["correlationId"], ran["correlationId"]);

    client
        .send(tool_request(
            3,
            RUN_TOOL,
            json!({"contextId": context_id, "code": "e2eCounter + 1"}),
        ))
        .await
        .expect("send persistence run");
    let persisted = receive_tool_result(&mut client).await;
    assert_eq!(persisted.is_error, Some(false));
    let persisted = persisted.structured_content.expect("persistence result");
    assert_eq!(persisted["value"], 42);
    assert_eq!(persisted["calls"], json!([]));

    client
        .send(tool_request(
            4,
            CONTEXT_CLOSE_TOOL,
            json!({"contextId": context_id}),
        ))
        .await
        .expect("send close");
    let closed = receive_tool_result(&mut client).await;
    assert_eq!(closed.is_error, Some(false));
    assert_eq!(closed.structured_content, Some(json!({"closed": true})));

    client
        .send(tool_request(
            5,
            RUN_TOOL,
            json!({"contextId": context_id, "code": "e2eCounter"}),
        ))
        .await
        .expect("send post-close run");
    let evicted = receive_tool_result(&mut client).await;
    assert_eq!(evicted.is_error, Some(true));
    assert_eq!(
        evicted.structured_content.expect("domain error")["code"],
        "context_evicted"
    );

    let token_requests = credentials
        .requests
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(token_requests.len(), 3);
    assert_eq!(
        token_requests
            .iter()
            .filter(|request| request.audience == TokenAudience::Arm)
            .count(),
        2
    );
    assert_eq!(
        token_requests
            .iter()
            .filter(|request| request.audience == TokenAudience::LogAnalytics)
            .count(),
        1
    );
    for request in token_requests.iter() {
        assert_eq!(request.cloud, AzureCloud::AzureCloud);
        assert_eq!(request.subscription_id.as_str(), SUBSCRIPTION);
        assert_eq!(request.tenant_id.as_str(), TENANT);
    }
    assert!(token_requests.iter().any(|request| {
        request.audience == TokenAudience::Arm
            && request.resource() == "https://management.azure.com/"
    }));
    assert!(token_requests.iter().any(|request| {
        request.audience == TokenAudience::LogAnalytics
            && request.resource() == "https://api.loganalytics.io"
    }));
    assert_eq!(audit.prepares.load(Ordering::SeqCst), 3);
    let records = audit
        .records
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(records.len(), 3);
    assert!(
        records
            .iter()
            .all(|record| record.decision == CallDecision::Allowed)
    );
    assert!(
        records
            .iter()
            .any(|record| record.operation == "context.validate")
    );
    assert!(
        records
            .iter()
            .any(|record| record.operation == "az.metrics.single")
    );
    assert!(
        records
            .iter()
            .any(|record| record.operation == "az.logs.query")
    );
    let encoded_audit = serde_json::to_string(&records).expect("audit JSON");
    for secret in [TOKEN, METRIC, KQL, WORKSPACE, "e2e-rg", "e2e-vm"] {
        assert!(!encoded_audit.contains(secret), "audit disclosed {secret}");
    }

    let requests = tokio::time::timeout(Duration::from_secs(5), upstream)
        .await
        .expect("all loopback calls reached the simulator")
        .expect("loopback task");
    assert_eq!(requests.len(), 3);
    assert!(requests.iter().all(|request| {
        request
            .to_ascii_lowercase()
            .contains("authorization: bearer synthetic-e2e-token")
    }));
    assert!(requests.iter().any(|request| {
        request.starts_with(&format!(
            "GET /subscriptions/{SUBSCRIPTION}?api-version={} HTTP/1.1",
            routes::SUBSCRIPTIONS_API_VERSION
        ))
    }));
    assert!(requests.iter().any(|request| {
        request.starts_with(&format!(
            "GET /subscriptions/{SUBSCRIPTION}/resourceGroups/e2e-rg/providers/Microsoft.Compute/virtualMachines/e2e-vm/providers/Microsoft.Insights/metrics?"
        )) && request.contains("metricnames=E2E+Secret+Metric")
    }));
    assert!(requests.iter().any(|request| {
        request.starts_with(&format!("POST /v1/workspaces/{WORKSPACE}/query HTTP/1.1"))
            && request.contains(KQL)
    }));

    drop(client);
    server_task
        .await
        .expect("MCP service task")
        .expect("clean MCP shutdown");
}

fn synthetic_profile() -> Vec<u8> {
    format!(
        r#"{{"subscriptions":[{{"id":"{SUBSCRIPTION}","name":"synthetic","state":"Enabled","tenantId":"{TENANT}","environmentName":"AzureCloud","user":{{"name":"test@example.invalid"}}}}]}}"#
    )
    .into_bytes()
}

fn modern_meta() -> RequestMetaObject {
    RequestMetaObject::with_client_context(
        ProtocolVersion::V_2026_07_28,
        Implementation::new("observability-e2e", "0.1.0"),
        ClientCapabilities::default(),
    )
}

fn tool_request(id: i64, name: &'static str, arguments: Value) -> ClientJsonRpcMessage {
    let arguments = arguments.as_object().cloned().expect("tool arguments");
    let mut request =
        CallToolRequest::new(CallToolRequestParams::new(name).with_arguments(arguments));
    request.extensions.insert(modern_meta());
    ClientJsonRpcMessage::request(
        ClientRequest::CallToolRequest(request),
        RequestId::Number(id),
    )
}

async fn receive_tool_result(client: &mut impl Transport<rmcp::RoleClient>) -> CallToolResult {
    let message = tokio::time::timeout(Duration::from_secs(10), client.receive())
        .await
        .expect("MCP response timeout")
        .expect("MCP response");
    let ServerJsonRpcMessage::Response(response) = message else {
        panic!("expected MCP response")
    };
    let ServerResult::CallToolResult(result) = response.result else {
        panic!("expected tool result")
    };
    result
}

fn call<'a>(run: &'a Value, operation: &str) -> &'a Value {
    run["calls"]
        .as_array()
        .expect("call records")
        .iter()
        .find(|record| record["operation"] == operation)
        .unwrap_or_else(|| panic!("missing {operation} call record"))
}

async fn synthetic_upstream() -> (String, tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("loopback listener");
    let address = listener.local_addr().expect("loopback address");
    let task = tokio::spawn(async move {
        let mut handlers = Vec::new();
        for _ in 0..3 {
            let (stream, peer) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .expect("expected loopback request")
                .expect("accept loopback request");
            assert!(peer.ip().is_loopback());
            handlers.push(tokio::spawn(handle_upstream_request(stream)));
        }
        let mut requests = Vec::new();
        for handler in handlers {
            requests.push(handler.await.expect("upstream handler"));
        }
        requests
    });
    (format!("http://{address}/"), task)
}

async fn handle_upstream_request(mut stream: TcpStream) -> String {
    let request = read_http_request(&mut stream).await;
    let body = if request.starts_with(&format!("GET /subscriptions/{SUBSCRIPTION}?")) {
        json!({"subscriptionId": SUBSCRIPTION})
    } else if request.contains("/providers/Microsoft.Insights/metrics?") {
        json!({"kind": "synthetic-metrics", "value": [{"average": 12.5}]})
    } else if request.starts_with(&format!("POST /v1/workspaces/{WORKSPACE}/query ")) {
        json!({
            "tables": [{
                "name": "PrimaryResult",
                "columns": [{"name": "value", "type": "long"}],
                "rows": [[17]]
            }]
        })
    } else {
        panic!("unexpected synthetic request: {request}");
    };
    let body = serde_json::to_vec(&body).expect("response JSON");
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nX-Ms-Ratelimit-Remaining-Subscription-Reads: 99\r\n\r\n",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .expect("write response headers");
    stream.write_all(&body).await.expect("write response body");
    request
}

async fn read_http_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let count = stream.read(&mut buffer).await.expect("read request");
        assert!(count > 0, "request ended before headers");
        request.extend_from_slice(&buffer[..count]);
        let Some(header_end) = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
        else {
            continue;
        };
        let content_length = String::from_utf8_lossy(&request[..header_end])
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        if request.len() >= header_end.saturating_add(content_length) {
            break;
        }
    }
    String::from_utf8(request).expect("ASCII HTTP request")
}
