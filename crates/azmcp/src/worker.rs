//! Process-isolated JavaScript worker and its tagged NDJSON protocol.

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    future::Future,
    io,
    path::Path,
    pin::Pin,
    process::ExitStatus,
    rc::Rc,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use deno_core::{Extension, JsRuntime, OpState, RuntimeOptions, error::JsError, op2, serde_v8, v8};
use futures_util::{StreamExt, stream::FuturesUnordered};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::{Mutex as AsyncMutex, Notify, mpsc},
    task::JoinHandle,
    time,
};

pub const WORKER_PROTOCOL_VERSION: u16 = 1;
pub const MAX_HEAP_BYTES: usize = 64 * 1024 * 1024;
pub const WORKER_LIFECYCLE_TIMEOUT_MS: u64 = 5_000;
pub const MAX_CODE_BYTES: usize = 256 * 1024;
pub const MAX_INPUT_BYTES: usize = 512 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
pub const MAX_RESULT_BYTES: usize = 64 * 1024;
/// A result may cross the worker boundary as a reference candidate only when
/// it remains small enough for both the parent-to-worker rehydration message
/// and the bounded context store. The final protocol envelope is checked
/// separately before it is written.
pub const MAX_REF_CANDIDATE_BYTES: usize = 480 * 1024;
pub const MAX_LOG_BYTES: usize = 64 * 1024;
pub const MAX_LOG_ENTRIES: usize = 256;
pub const MAX_ERROR_BYTES: usize = 8 * 1024;
pub const MAX_TIMEOUT_MS: u64 = 60 * 60 * 1000;
pub const MAX_HOST_METHOD_BYTES: usize = 64;
pub const MAX_HOST_CALLS_PER_EXECUTION: usize = 256;
pub const MAX_PENDING_HOST_CALLS: usize = 8;
/// Maximum resident set size for one isolated worker process.
///
/// The V8 heap ceiling is intentionally lower than this process ceiling. The
/// additional space covers the V8 executable/snapshot, Rust runtime, and
/// allocator overhead observed on the supported macOS and Linux targets.
pub const WORKER_RSS_LIMIT_BYTES: u64 = 256 * 1024 * 1024;
pub const WORKER_RSS_POLL_INTERVAL: Duration = Duration::from_millis(50);

pub const HOST_METHOD_REQUEST: &str = "az.request";
pub const HOST_METHOD_GRAPH: &str = "az.graph";
pub const HOST_METHOD_METRICS_SINGLE: &str = "az.metrics.single";
pub const HOST_METHOD_METRICS_BATCH: &str = "az.metrics.batch";
pub const HOST_METHOD_LOGS_QUERY: &str = "az.logs.query";
/// Internal worker-to-parent capability used by the JavaScript `az.ref`
/// global. It is intentionally not an MCP tool.
pub const HOST_METHOD_REF: &str = "az.ref";

/// Keep shape diagnostics useful without allowing a pathological object key
/// set to become a second oversized result.
pub const MAX_RESULT_SUMMARY_KEYS: usize = 32;
pub const MAX_RESULT_SUMMARY_KEY_BYTES: usize = 128;

/// A structural description of a result that could not cross the worker
/// boundary. It deliberately contains no samples or values.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ResultTooLargeSummary {
    #[serde(rename = "type")]
    pub value_type: String,
    pub encoded_bytes: usize,
    pub limit_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keys_omitted: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counts: Option<BTreeMap<String, usize>>,
}

impl ResultTooLargeSummary {
    /// Build a bounded shape-only summary from an already JSON-compatible
    /// value. Object keys are retained because they describe the shape, while
    /// all object and array values are intentionally omitted.
    pub fn from_json(value: &Value, encoded_bytes: usize, limit_bytes: usize) -> Self {
        let (value_type, length, key_count, keys, keys_omitted, counts) = match value {
            Value::Null => ("null", None, None, None, None, None),
            Value::Bool(_) => ("boolean", None, None, None, None, None),
            Value::Number(_) => ("number", None, None, None, None, None),
            Value::String(value) => (
                "string",
                Some(value.chars().count()),
                None,
                None,
                None,
                None,
            ),
            Value::Array(values) => (
                "array",
                Some(values.len()),
                None,
                None,
                None,
                Some(type_counts(values.iter())),
            ),
            Value::Object(values) => {
                let key_count = values.len();
                let mut keys = values
                    .keys()
                    .map(|key| truncate_utf8(key, MAX_RESULT_SUMMARY_KEY_BYTES))
                    .collect::<Vec<_>>();
                keys.sort_unstable();
                keys.truncate(MAX_RESULT_SUMMARY_KEYS);
                let keys_omitted = key_count.saturating_sub(keys.len());
                (
                    "object",
                    None,
                    Some(key_count),
                    Some(keys),
                    (keys_omitted > 0).then_some(keys_omitted),
                    Some(type_counts(values.values())),
                )
            }
        };

        Self {
            value_type: value_type.to_owned(),
            encoded_bytes,
            limit_bytes,
            length,
            key_count,
            keys,
            keys_omitted,
            counts,
        }
    }
}

fn type_counts<'a>(values: impl IntoIterator<Item = &'a Value>) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for value in values {
        let value_type = match value {
            Value::Null => "null",
            Value::Bool(_) => "boolean",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        };
        *counts.entry(value_type.to_owned()).or_default() += 1;
    }
    counts
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerRequest {
    Execute {
        id: u64,
        code: String,
        timeout_ms: u64,
    },
    Close {
        id: u64,
    },
    HostCallResult {
        id: u64,
        call_id: u64,
        ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerResponse {
    Ready {
        protocol: u16,
    },
    Result {
        id: u64,
        value: Value,
        logs: Vec<String>,
        logs_omitted: usize,
    },
    /// A serializable result larger than the ordinary MCP result cap. The
    /// application owns materialization into its context-scoped RefStore.
    ResultRef {
        id: u64,
        value: Value,
        encoded_bytes: usize,
        logs: Vec<String>,
        logs_omitted: usize,
    },
    Error {
        id: u64,
        code: String,
        message: String,
        logs: Vec<String>,
        logs_omitted: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        details: Option<ResultTooLargeSummary>,
    },
    Closed {
        id: u64,
    },
    HostCall {
        id: u64,
        call_id: u64,
        method: String,
        arguments: Value,
    },
}

/// A request from the isolated JavaScript runtime to its parent process.
#[derive(Clone, Deserialize, Serialize, PartialEq)]
pub struct HostCallRequest {
    pub id: u64,
    pub call_id: u64,
    pub method: String,
    pub arguments: Value,
}

impl fmt::Debug for HostCallRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostCallRequest")
            .field("id", &self.id)
            .field("call_id", &self.call_id)
            .field("method", &self.method)
            .field(
                "arguments_bytes",
                &serde_json::to_vec(&self.arguments)
                    .map(|bytes| bytes.len())
                    .unwrap_or_default(),
            )
            .finish()
    }
}

/// A parent response to a [`HostCallRequest`].
#[derive(Clone, Deserialize, Serialize, PartialEq)]
pub struct HostCallResult {
    pub id: u64,
    pub call_id: u64,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl fmt::Debug for HostCallResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostCallResult")
            .field("id", &self.id)
            .field("call_id", &self.call_id)
            .field("ok", &self.ok)
            .field(
                "value_bytes",
                &self.value.as_ref().map(|value| {
                    serde_json::to_vec(value)
                        .map(|bytes| bytes.len())
                        .unwrap_or_default()
                }),
            )
            .field("error_present", &self.error.is_some())
            .finish()
    }
}

impl HostCallResult {
    pub fn success(request: &HostCallRequest, value: Value) -> Self {
        Self {
            id: request.id,
            call_id: request.call_id,
            ok: true,
            value: Some(value),
            error: None,
        }
    }

    pub fn failure(request: &HostCallRequest, error: impl Into<String>) -> Self {
        Self {
            id: request.id,
            call_id: request.call_id,
            ok: false,
            value: None,
            error: Some(sanitize_text(&error.into(), MAX_ERROR_BYTES)),
        }
    }
}

/// Errors returned by a parent-side host-call implementation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostCallError {
    /// The worker was started without a host bridge.
    Unavailable,
    /// The worker and parent disagreed about the host-call protocol.
    Protocol(String),
    /// The parent rejected a valid host call.
    Rejected(String),
}

impl fmt::Display for HostCallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("host calls are unavailable"),
            Self::Protocol(message) => write!(f, "host-call protocol error: {message}"),
            Self::Rejected(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for HostCallError {}

pub type HostCallFuture = Pin<Box<dyn Future<Output = HostCallResult> + Send>>;
pub type HostCallHandler = Arc<dyn Fn(HostCallRequest) -> HostCallFuture + Send + Sync>;

#[derive(Clone, Debug, PartialEq)]
pub struct ExecutionResult {
    pub value: Value,
    pub logs: Vec<String>,
    pub logs_omitted: usize,
    /// Present only for a serializable value that exceeded the ordinary
    /// result cap but stayed below the bounded reference-candidate cap.
    pub ref_candidate: Option<RefCandidate>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RefCandidate {
    pub value: Value,
    pub encoded_bytes: usize,
}

#[derive(Debug)]
pub enum WorkerError {
    Closed,
    Limit(&'static str),
    Timeout {
        timeout_ms: u64,
    },
    Protocol(String),
    Spawn(io::Error),
    Io(io::Error),
    Runtime(String),
    Serialization(String),
    ResultTooLarge {
        summary: Box<ResultTooLargeSummary>,
    },
    HeapLimit,
    RssLimit {
        rss_bytes: u64,
        limit_bytes: u64,
    },
    Execution {
        message: String,
        logs: Vec<String>,
        logs_omitted: usize,
    },
}

impl fmt::Display for WorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => f.write_str("worker is closed"),
            Self::Limit(kind) => write!(f, "worker {kind} limit exceeded"),
            Self::Timeout { timeout_ms } => {
                write!(f, "worker execution timed out after {timeout_ms} ms")
            }
            Self::Protocol(message) => write!(f, "worker protocol error: {message}"),
            Self::Spawn(error) => write!(f, "failed to spawn worker: {error}"),
            Self::Io(error) => write!(f, "worker I/O error: {error}"),
            Self::Runtime(message) => write!(f, "worker runtime error: {message}"),
            Self::Serialization(message) => write!(f, "worker serialization error: {message}"),
            Self::ResultTooLarge { .. } => f.write_str("worker result exceeds the 64 KiB limit"),
            Self::HeapLimit => f.write_str("worker heap limit exceeded"),
            Self::RssLimit {
                rss_bytes,
                limit_bytes,
            } => write!(
                f,
                "worker resident memory limit exceeded ({rss_bytes} > {limit_bytes} bytes)"
            ),
            Self::Execution { message, .. } => write!(f, "JavaScript execution failed: {message}"),
        }
    }
}

impl std::error::Error for WorkerError {}

impl From<io::Error> for WorkerError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug)]
struct RssWatchdogState {
    exceeded: AtomicBool,
    observed_bytes: AtomicU64,
    notify: Notify,
}

impl RssWatchdogState {
    fn new() -> Self {
        Self {
            exceeded: AtomicBool::new(false),
            observed_bytes: AtomicU64::new(0),
            notify: Notify::new(),
        }
    }

    fn error(&self, limit_bytes: u64) -> WorkerError {
        WorkerError::RssLimit {
            rss_bytes: self.observed_bytes.load(Ordering::Acquire),
            limit_bytes,
        }
    }

    async fn wait_for_exceeded(self: Arc<Self>, limit_bytes: u64) -> WorkerError {
        loop {
            if self.exceeded.load(Ordering::Acquire) {
                return self.error(limit_bytes);
            }
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.exceeded.load(Ordering::Acquire) {
                return self.error(limit_bytes);
            }
            notified.await;
        }
    }
}

#[derive(Debug)]
struct RssWatchdog {
    state: Arc<RssWatchdogState>,
    limit_bytes: u64,
    stop: Arc<AtomicBool>,
    stop_notify: Arc<Notify>,
    task: Option<JoinHandle<()>>,
}

impl RssWatchdog {
    fn spawn(child: Arc<AsyncMutex<Option<Child>>>, pid: u32, limit_bytes: u64) -> Self {
        Self::spawn_with_probe(child, pid, limit_bytes, Box::new(SystemRssProbe::new()))
    }

    fn spawn_with_probe(
        child: Arc<AsyncMutex<Option<Child>>>,
        pid: u32,
        limit_bytes: u64,
        mut probe: Box<dyn RssProbe>,
    ) -> Self {
        let state = Arc::new(RssWatchdogState::new());
        let stop = Arc::new(AtomicBool::new(false));
        let stop_notify = Arc::new(Notify::new());
        let task_state = Arc::clone(&state);
        let task_stop = Arc::clone(&stop);
        let task_stop_notify = Arc::clone(&stop_notify);
        let task = tokio::spawn(async move {
            loop {
                if task_stop.load(Ordering::Acquire) {
                    return;
                }
                if let Some(rss_bytes) = probe.rss_bytes(pid)
                    && rss_limit_exceeded(rss_bytes, limit_bytes)
                {
                    task_state
                        .observed_bytes
                        .store(rss_bytes, Ordering::Release);
                    task_state.exceeded.store(true, Ordering::Release);
                    task_state.notify.notify_waiters();
                    kill_shared_child(&child).await;
                    return;
                }
                tokio::select! {
                    _ = time::sleep(WORKER_RSS_POLL_INTERVAL) => {}
                    _ = task_stop_notify.notified() => return,
                }
            }
        });
        Self {
            state,
            limit_bytes,
            stop,
            stop_notify,
            task: Some(task),
        }
    }

    fn error(&self) -> Option<WorkerError> {
        self.state
            .exceeded
            .load(Ordering::Acquire)
            .then(|| self.state.error(self.limit_bytes))
    }

    async fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        self.stop_notify.notify_waiters();
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

trait RssProbe: Send + 'static {
    fn rss_bytes(&mut self, pid: u32) -> Option<u64>;
}

struct SystemRssProbe {
    system: System,
}

impl SystemRssProbe {
    fn new() -> Self {
        Self {
            system: System::new(),
        }
    }
}

impl RssProbe for SystemRssProbe {
    fn rss_bytes(&mut self, pid: u32) -> Option<u64> {
        let pid = Pid::from_u32(pid);
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid]),
            true,
            ProcessRefreshKind::nothing().with_memory(),
        );
        self.system.process(pid).map(|process| process.memory())
    }
}

fn rss_limit_exceeded(rss_bytes: u64, limit_bytes: u64) -> bool {
    rss_bytes > limit_bytes
}

async fn kill_shared_child(child: &AsyncMutex<Option<Child>>) {
    let mut child = child.lock().await;
    if let Some(child) = child.as_mut() {
        let _ = child.start_kill();
    }
}

async fn wait_for_shared_child(
    child: &AsyncMutex<Option<Child>>,
    timeout_ms: u64,
) -> Result<(), WorkerError> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        let status: Option<ExitStatus> = {
            let mut child_guard = child.lock().await;
            let Some(child) = child_guard.as_mut() else {
                return Ok(());
            };
            match child.try_wait() {
                Ok(Some(_)) => {
                    child_guard.take();
                    return Ok(());
                }
                Ok(None) => None,
                Err(error) => return Err(WorkerError::Io(error)),
            }
        };
        debug_assert!(status.is_none());
        if tokio::time::Instant::now() >= deadline {
            kill_shared_child(child).await;
            return Err(WorkerError::Timeout { timeout_ms });
        }
        time::sleep(Duration::from_millis(10)).await;
    }
}

/// Persistent process client; `&mut self` serializes JavaScript turns.
pub struct WorkerProcess {
    child: Arc<AsyncMutex<Option<Child>>>,
    stdin: Option<ChildStdin>,
    stdout: Option<BufReader<ChildStdout>>,
    read_buffer: Vec<u8>,
    next_id: u64,
    usable: bool,
    rss_watchdog: Option<RssWatchdog>,
}

impl WorkerProcess {
    pub async fn start(executable: impl AsRef<Path>) -> Result<Self, WorkerError> {
        Self::start_with_rss_limit(executable, WORKER_RSS_LIMIT_BYTES).await
    }

    /// Start a worker with an explicit process RSS ceiling.
    ///
    /// The production entry point uses [`WORKER_RSS_LIMIT_BYTES`]. This
    /// variant is also useful to embedding callers that have a tighter
    /// process budget and to deterministic tests of the watchdog boundary.
    pub async fn start_with_rss_limit(
        executable: impl AsRef<Path>,
        rss_limit_bytes: u64,
    ) -> Result<Self, WorkerError> {
        let executable = executable.as_ref().to_owned();
        let mut command = Command::new(&executable);
        command
            .arg("--worker")
            .env_clear()
            .envs(std::env::vars_os().filter(|(name, _)| name == "PATH" || name == "LANG"))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(WorkerError::Spawn)?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| WorkerError::Protocol("worker stdin was not piped".to_owned()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| WorkerError::Protocol("worker stdout was not piped".to_owned()))?;
        let child = Arc::new(AsyncMutex::new(Some(child)));
        let pid = {
            let child_guard = child.lock().await;
            child_guard.as_ref().and_then(Child::id)
        }
        .ok_or_else(|| WorkerError::Protocol("worker process ID was unavailable".to_owned()))?;
        let mut worker = Self {
            child: Arc::clone(&child),
            stdin: Some(stdin),
            stdout: Some(BufReader::new(stdout)),
            read_buffer: Vec::new(),
            next_id: 1,
            usable: true,
            rss_watchdog: Some(RssWatchdog::spawn(child, pid, rss_limit_bytes)),
        };
        let ready = match time::timeout(
            Duration::from_millis(WORKER_LIFECYCLE_TIMEOUT_MS),
            worker.read_message(),
        )
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                if let Some(rss_error) = worker.rss_limit_error() {
                    worker.poison().await;
                    return Err(rss_error);
                }
                worker.poison().await;
                return Err(error);
            }
            Err(_) => {
                if let Some(rss_error) = worker.rss_limit_error() {
                    worker.poison().await;
                    return Err(rss_error);
                }
                worker.poison().await;
                return Err(WorkerError::Timeout {
                    timeout_ms: WORKER_LIFECYCLE_TIMEOUT_MS,
                });
            }
        };
        if let Some(rss_error) = worker.rss_limit_error() {
            worker.poison().await;
            return Err(rss_error);
        }
        if !matches!(ready, WorkerResponse::Ready { protocol } if protocol == WORKER_PROTOCOL_VERSION)
        {
            worker.poison().await;
            return Err(WorkerError::Protocol(
                "worker did not send a valid ready message".to_owned(),
            ));
        }
        Ok(worker)
    }

    pub async fn execute(
        &mut self,
        code: impl AsRef<str>,
        timeout: Duration,
    ) -> Result<ExecutionResult, WorkerError> {
        self.execute_with_handler(code, timeout, |request| async move {
            HostCallResult::failure(&request, "host calls are unavailable")
        })
        .await
    }

    /// Execute one JavaScript turn and service host calls with a parent handler.
    ///
    /// `&mut self` intentionally permits only one in-flight turn. The worker can
    /// emit a host call while that turn is pending; the handler's result is sent
    /// back over the same tagged protocol before the final result is returned.
    pub async fn execute_with_handler<F, Fut>(
        &mut self,
        code: impl AsRef<str>,
        timeout: Duration,
        mut handler: F,
    ) -> Result<ExecutionResult, WorkerError>
    where
        F: FnMut(HostCallRequest) -> Fut,
        Fut: Future<Output = HostCallResult>,
    {
        self.ensure_usable()?;
        validate_code(code.as_ref())?;
        let timeout_ms = validate_timeout(timeout)?;
        let id = self.next_request_id()?;
        let request = WorkerRequest::Execute {
            id,
            code: code.as_ref().to_owned(),
            timeout_ms,
        };
        if let Err(error) = self.write_message(&request).await {
            self.poison().await;
            return Err(error);
        }

        let rss_state = self
            .rss_watchdog
            .as_ref()
            .map(|watchdog| (Arc::clone(&watchdog.state), watchdog.limit_bytes));
        let response = match time::timeout(timeout, async {
            match rss_state {
                Some((state, limit_bytes)) => {
                    tokio::select! {
                        response = self.read_until_result(id, &mut handler) => response,
                        error = state.wait_for_exceeded(limit_bytes) => Err(error),
                    }
                }
                None => self.read_until_result(id, &mut handler).await,
            }
        })
        .await
        {
            Ok(Ok(response)) => {
                if let Some(rss_error) = self.rss_limit_error() {
                    self.poison().await;
                    return Err(rss_error);
                }
                response
            }
            Ok(Err(error)) => {
                if let Some(rss_error) = self.rss_limit_error() {
                    self.poison().await;
                    return Err(rss_error);
                }
                self.poison().await;
                return Err(error);
            }
            Err(_) => {
                if let Some(rss_error) = self.rss_limit_error() {
                    self.poison().await;
                    return Err(rss_error);
                }
                self.poison().await;
                return Err(WorkerError::Timeout { timeout_ms });
            }
        };
        match response {
            WorkerResponse::Result {
                value,
                logs,
                logs_omitted,
                ..
            } => Ok(ExecutionResult {
                value,
                logs,
                logs_omitted,
                ref_candidate: None,
            }),
            WorkerResponse::ResultRef {
                value,
                encoded_bytes,
                logs,
                logs_omitted,
                ..
            } => {
                let actual_bytes = serde_json::to_vec(&value)
                    .map_err(|error| WorkerError::Serialization(error.to_string()))?
                    .len();
                if encoded_bytes != actual_bytes {
                    self.poison().await;
                    return Err(WorkerError::Protocol(
                        "reference candidate size mismatch".to_owned(),
                    ));
                }
                if encoded_bytes <= MAX_RESULT_BYTES || encoded_bytes > MAX_REF_CANDIDATE_BYTES {
                    self.poison().await;
                    return Err(WorkerError::Protocol(
                        "reference candidate is outside its bounded size range".to_owned(),
                    ));
                }
                Ok(ExecutionResult {
                    value: Value::Null,
                    logs,
                    logs_omitted,
                    ref_candidate: Some(RefCandidate {
                        value,
                        encoded_bytes,
                    }),
                })
            }
            WorkerResponse::Error { code, .. } if code == "execution_timeout" => {
                self.poison().await;
                Err(WorkerError::Timeout { timeout_ms })
            }
            WorkerResponse::Error { code, details, .. } if code == "result_too_large" => {
                let summary = details.ok_or_else(|| {
                    WorkerError::Protocol(
                        "result_too_large response omitted its shape summary".to_owned(),
                    )
                })?;
                Err(WorkerError::ResultTooLarge {
                    summary: Box::new(summary),
                })
            }
            WorkerResponse::Error { code, message, .. } if code == "protocol_error" => {
                self.poison().await;
                Err(WorkerError::Protocol(message))
            }
            WorkerResponse::Error { code, .. } if code == "heap_limit" => {
                self.poison().await;
                Err(WorkerError::HeapLimit)
            }
            WorkerResponse::Error {
                message,
                logs,
                logs_omitted,
                ..
            } => Err(WorkerError::Execution {
                message,
                logs,
                logs_omitted,
            }),
            _ => {
                self.poison().await;
                Err(WorkerError::Protocol(
                    "unexpected worker message".to_owned(),
                ))
            }
        }
    }

    /// Execute with a cloneable, boxed handler suitable for storing in an
    /// application context.
    pub async fn execute_with_host_handler(
        &mut self,
        code: impl AsRef<str>,
        timeout: Duration,
        handler: HostCallHandler,
    ) -> Result<ExecutionResult, WorkerError> {
        self.execute_with_handler(code, timeout, move |request| (handler)(request))
            .await
    }

    pub async fn close(&mut self) -> Result<(), WorkerError> {
        if !self.usable {
            return Ok(());
        }
        if let Some(rss_error) = self.rss_limit_error() {
            self.poison().await;
            return Err(rss_error);
        }
        let id = self.next_request_id()?;
        let response =
            match time::timeout(Duration::from_millis(WORKER_LIFECYCLE_TIMEOUT_MS), async {
                self.write_message(&WorkerRequest::Close { id }).await?;
                self.read_message().await
            })
            .await
            {
                Ok(Ok(response)) => response,
                Ok(Err(error)) => {
                    if let Some(rss_error) = self.rss_limit_error() {
                        self.poison().await;
                        return Err(rss_error);
                    }
                    self.poison().await;
                    return Err(error);
                }
                Err(_) => {
                    if let Some(rss_error) = self.rss_limit_error() {
                        self.poison().await;
                        return Err(rss_error);
                    }
                    self.poison().await;
                    return Err(WorkerError::Timeout {
                        timeout_ms: WORKER_LIFECYCLE_TIMEOUT_MS,
                    });
                }
            };
        if !matches!(response, WorkerResponse::Closed { id: response_id } if response_id == id) {
            self.poison().await;
            return Err(WorkerError::Protocol(
                "worker close acknowledgement mismatch".to_owned(),
            ));
        }
        self.usable = false;
        self.stdin.take();
        self.stdout.take();
        self.stop_watchdog().await;
        wait_for_shared_child(&self.child, WORKER_LIFECYCLE_TIMEOUT_MS).await?;
        Ok(())
    }

    /// Hard-terminate this worker without waiting for a protocol response.
    ///
    /// This is intentionally separate from [`Self::close`]: callers use it
    /// when an in-flight turn has been cancelled and the isolated process can
    /// no longer be trusted to make progress through the normal protocol.
    pub async fn terminate(&mut self) {
        self.poison().await;
    }

    /// Return a best-effort current RSS sample for diagnostics and deployment
    /// measurement. Enforcement remains in the watchdog and does not depend
    /// on a caller polling this method.
    pub fn current_rss_bytes(&self) -> Option<u64> {
        let child = self.child.try_lock().ok()?;
        let pid = child.as_ref()?.id()?;
        drop(child);
        SystemRssProbe::new().rss_bytes(pid)
    }

    fn ensure_usable(&self) -> Result<(), WorkerError> {
        if let Some(rss_error) = self.rss_limit_error() {
            return Err(rss_error);
        }
        if self.usable {
            Ok(())
        } else {
            Err(WorkerError::Closed)
        }
    }

    fn rss_limit_error(&self) -> Option<WorkerError> {
        self.rss_watchdog.as_ref().and_then(RssWatchdog::error)
    }

    async fn stop_watchdog(&mut self) {
        if let Some(watchdog) = self.rss_watchdog.take() {
            watchdog.stop().await;
        }
    }

    fn next_request_id(&mut self) -> Result<u64, WorkerError> {
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(WorkerError::Protocol("request ID exhausted".to_owned()))?;
        Ok(id)
    }

    async fn write_message(&mut self, request: &WorkerRequest) -> Result<(), WorkerError> {
        let bytes = serde_json::to_vec(request)
            .map_err(|error| WorkerError::Serialization(error.to_string()))?;
        if bytes.len() + 1 > MAX_INPUT_BYTES {
            return Err(WorkerError::Limit("input"));
        }
        let stdin = self.stdin.as_mut().ok_or(WorkerError::Closed)?;
        stdin.write_all(&bytes).await.map_err(WorkerError::Io)?;
        stdin.write_all(b"\n").await.map_err(WorkerError::Io)?;
        stdin.flush().await.map_err(WorkerError::Io)
    }

    async fn read_message(&mut self) -> Result<WorkerResponse, WorkerError> {
        let stdout = self.stdout.as_mut().ok_or(WorkerError::Closed)?;
        let line =
            read_line_limited_buffered(stdout, &mut self.read_buffer, MAX_OUTPUT_BYTES).await?;
        serde_json::from_slice(&line).map_err(|error| {
            WorkerError::Protocol(format!(
                "malformed worker response ({} bytes): {error}",
                line.len()
            ))
        })
    }

    async fn read_until_result<F, Fut>(
        &mut self,
        id: u64,
        handler: &mut F,
    ) -> Result<WorkerResponse, WorkerError>
    where
        F: FnMut(HostCallRequest) -> Fut,
        Fut: Future<Output = HostCallResult>,
    {
        let mut seen_call_ids = HashSet::new();
        let mut pending = FuturesUnordered::new();
        loop {
            tokio::select! {
                response = self.read_message(), if pending.len() < MAX_PENDING_HOST_CALLS => match response? {
                    response @ (WorkerResponse::Result { id: response_id, .. }
                    | WorkerResponse::ResultRef { id: response_id, .. }
                    | WorkerResponse::Error { id: response_id, .. }) if response_id == id => {
                        if !pending.is_empty() {
                            return Err(WorkerError::Protocol(
                                "worker completed with pending host calls".to_owned(),
                            ));
                        }
                        return Ok(response);
                    }
                    WorkerResponse::HostCall {
                    id: call_request_id,
                    call_id,
                    method,
                    arguments,
                    } => {
                    if call_request_id != id {
                        return Err(WorkerError::Protocol(
                            "host call request ID mismatch".to_owned(),
                        ));
                    }
                    if call_id == 0 || !seen_call_ids.insert(call_id) {
                        return Err(WorkerError::Protocol(
                            "duplicate or invalid host call ID".to_owned(),
                        ));
                    }
                    let call = HostCallRequest {
                        id: call_request_id,
                        call_id,
                        method,
                        arguments,
                    };
                    validate_host_call_request(&call).map_err(WorkerError::Protocol)?;
                    let future = handler(call.clone());
                    pending.push(async move { (call, future.await) });
                    }
                    WorkerResponse::Result { .. }
                    | WorkerResponse::ResultRef { .. }
                    | WorkerResponse::Error { .. } => {
                        return Err(WorkerError::Protocol("response ID mismatch".to_owned()));
                    }
                    WorkerResponse::Ready { .. } | WorkerResponse::Closed { .. } => {
                        return Err(WorkerError::Protocol(
                            "unexpected worker message".to_owned(),
                        ));
                    }
                },
                completed = pending.next(), if !pending.is_empty() => {
                    let (call, result) = completed.expect("pending host future exists");
                    validate_host_call_result(&call, &result).map_err(WorkerError::Protocol)?;
                    self.write_message(&WorkerRequest::HostCallResult {
                        id: result.id,
                        call_id: result.call_id,
                        ok: result.ok,
                        value: result.value,
                        error: result.error,
                    })
                    .await?;
                }
            }
        }
    }

    async fn poison(&mut self) {
        self.usable = false;
        self.stdin.take();
        self.stdout.take();
        self.stop_watchdog().await;
        kill_shared_child(&self.child).await;
        let _ = wait_for_shared_child(&self.child, WORKER_LIFECYCLE_TIMEOUT_MS).await;
    }
}

impl Drop for WorkerProcess {
    fn drop(&mut self) {
        if let Ok(mut child) = self.child.try_lock()
            && let Some(child) = child.as_mut()
        {
            let _ = child.start_kill();
            let _ = child.try_wait();
        }
        if let Some(watchdog) = self.rss_watchdog.take() {
            watchdog.stop.store(true, Ordering::Release);
            watchdog.stop_notify.notify_waiters();
            if let Some(task) = watchdog.task {
                task.abort();
            }
        }
    }
}

#[derive(Clone)]
struct HostBridge {
    outbound: mpsc::Sender<WorkerResponse>,
    inbound: Rc<tokio::sync::Mutex<HostInbox>>,
    active_request_id: Rc<std::cell::Cell<Option<u64>>>,
    next_call_id: Rc<std::cell::Cell<u64>>,
    call_count: Rc<std::cell::Cell<usize>>,
    poisoned: Rc<RefCell<Option<String>>>,
}

struct HostInbox {
    receiver: mpsc::Receiver<WorkerRequest>,
    pending: HashMap<(u64, u64), WorkerRequest>,
}

impl HostBridge {
    fn new(outbound: mpsc::Sender<WorkerResponse>, inbound: mpsc::Receiver<WorkerRequest>) -> Self {
        Self {
            outbound,
            inbound: Rc::new(tokio::sync::Mutex::new(HostInbox {
                receiver: inbound,
                pending: HashMap::new(),
            })),
            active_request_id: Rc::new(std::cell::Cell::new(None)),
            next_call_id: Rc::new(std::cell::Cell::new(1)),
            call_count: Rc::new(std::cell::Cell::new(0)),
            poisoned: Rc::new(RefCell::new(None)),
        }
    }

    fn begin_execution(&self, id: u64) {
        self.active_request_id.set(Some(id));
        self.call_count.set(0);
    }

    fn end_execution(&self) {
        self.active_request_id.set(None);
    }

    fn take_protocol_error(&self) -> Option<String> {
        self.poisoned.borrow_mut().take()
    }

    fn protocol_error(&self, message: impl Into<String>) -> HostCallError {
        let message = sanitize_text(&message.into(), MAX_ERROR_BYTES);
        *self.poisoned.borrow_mut() = Some(message.clone());
        HostCallError::Protocol(message)
    }

    async fn next_request(&self) -> Option<WorkerRequest> {
        let mut inbox = self.inbound.lock().await;
        inbox.receiver.recv().await
    }

    async fn next_host_result(
        &self,
        id: u64,
        call_id: u64,
    ) -> Result<WorkerRequest, HostCallError> {
        let mut inbox = self.inbound.lock().await;
        if let Some(response) = inbox.pending.remove(&(id, call_id)) {
            return Ok(response);
        }
        loop {
            let Some(response) = inbox.receiver.recv().await else {
                return Err(self.protocol_error("host-call input channel closed"));
            };
            let WorkerRequest::HostCallResult {
                id: response_id,
                call_id: response_call_id,
                ..
            } = &response
            else {
                return Err(
                    self.protocol_error("unexpected worker request while a host call was pending")
                );
            };
            if *response_id != id {
                return Err(self.protocol_error("host-call request ID mismatch"));
            }
            if *response_id == id && *response_call_id == call_id {
                return Ok(response);
            }
            if inbox.pending.len() >= MAX_HOST_CALLS_PER_EXECUTION {
                return Err(self.protocol_error("pending host-call response limit exceeded"));
            }
            if inbox
                .pending
                .insert((*response_id, *response_call_id), response)
                .is_some()
            {
                return Err(self.protocol_error("duplicate host-call response"));
            }
        }
    }

    async fn call(&self, method: String, arguments: Value) -> Result<Value, HostCallError> {
        let id = self
            .active_request_id
            .get()
            .ok_or_else(|| self.protocol_error("host call outside an active execution"))?;
        let call_count = self.call_count.get();
        if call_count >= MAX_HOST_CALLS_PER_EXECUTION {
            return Err(self.protocol_error("host-call count limit exceeded"));
        }
        self.call_count.set(call_count + 1);

        let call = HostCallRequest {
            id,
            call_id: self.next_call_id.get(),
            method,
            arguments,
        };
        self.next_call_id.set(
            call.call_id
                .checked_add(1)
                .ok_or_else(|| self.protocol_error("host-call ID exhausted"))?,
        );
        validate_host_call_request(&call).map_err(|message| self.protocol_error(message))?;
        let encoded = serde_json::to_vec(&call.arguments)
            .map_err(|error| self.protocol_error(format!("host-call arguments: {error}")))?;
        if encoded.len() > MAX_INPUT_BYTES {
            return Err(self.protocol_error("host-call arguments exceed the input limit"));
        }

        self.outbound
            .send(WorkerResponse::HostCall {
                id: call.id,
                call_id: call.call_id,
                method: call.method.clone(),
                arguments: call.arguments.clone(),
            })
            .await
            .map_err(|_| self.protocol_error("host-call response channel closed"))?;

        let response = self.next_host_result(call.id, call.call_id).await?;
        let WorkerRequest::HostCallResult {
            id: response_id,
            call_id: response_call_id,
            ok,
            value,
            error,
        } = response
        else {
            return Err(
                self.protocol_error("unexpected worker request while a host call was pending")
            );
        };
        if response_id != call.id || response_call_id != call.call_id {
            return Err(self.protocol_error("host-call response ID mismatch"));
        }
        if ok {
            if error.is_some() {
                return Err(self.protocol_error("successful host call included an error"));
            }
            return value.ok_or_else(|| self.protocol_error("successful host call omitted value"));
        }
        if value.is_some() {
            return Err(self.protocol_error("rejected host call included a value"));
        }
        let error = error.ok_or_else(|| self.protocol_error("rejected host call omitted error"))?;
        if error.is_empty() || error.len() > MAX_ERROR_BYTES {
            return Err(self.protocol_error("host-call error is empty or too large"));
        }
        Err(HostCallError::Rejected(sanitize_text(
            &error,
            MAX_ERROR_BYTES,
        )))
    }
}

pub struct WorkerRuntime {
    runtime: JsRuntime,
    console: ConsoleSink,
    host_bridge: Option<HostBridge>,
    heap_limit_reached: Arc<std::sync::atomic::AtomicBool>,
}

impl WorkerRuntime {
    pub fn new() -> Result<Self, WorkerError> {
        Self::new_with_bridge(None)
    }

    fn new_with_host_bridge(bridge: HostBridge) -> Result<Self, WorkerError> {
        Self::new_with_bridge(Some(bridge))
    }

    fn new_with_bridge(host_bridge: Option<HostBridge>) -> Result<Self, WorkerError> {
        let console = ConsoleSink::default();
        let extension = worker_extension();
        let mut runtime = JsRuntime::new(RuntimeOptions {
            extensions: vec![extension],
            module_loader: None,
            create_params: Some(v8::Isolate::create_params().heap_limits(0, MAX_HEAP_BYTES)),
            ..Default::default()
        });
        runtime.op_state().borrow_mut().put(console.clone());
        if let Some(bridge) = host_bridge.clone() {
            runtime.op_state().borrow_mut().put(bridge);
        }
        let heap_limit_reached = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let heap_handle = runtime.v8_isolate().thread_safe_handle();
        let heap_limit_flag = Arc::clone(&heap_limit_reached);
        runtime.add_near_heap_limit_callback(move |current_limit, _initial_limit| {
            heap_limit_flag.store(true, std::sync::atomic::Ordering::Release);
            heap_handle.terminate_execution();
            current_limit
        });
        runtime
            .execute_script("<worker-bootstrap>", WORKER_BOOTSTRAP)
            .map_err(|error| WorkerError::Runtime(sanitize_js_error(&error)))?;
        Ok(Self {
            runtime,
            console,
            host_bridge,
            heap_limit_reached,
        })
    }

    pub async fn execute(
        &mut self,
        code: impl AsRef<str>,
        timeout: Duration,
    ) -> Result<ExecutionResult, WorkerError> {
        validate_code(code.as_ref())?;
        let timeout_ms = validate_timeout(timeout)?;
        self.console.clear();
        self.heap_limit_reached
            .store(false, std::sync::atomic::Ordering::Release);

        let timed_out = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let isolate_handle = self.runtime.v8_isolate().thread_safe_handle();
        let watchdog_timed_out = timed_out.clone();
        let watchdog = tokio::spawn(async move {
            time::sleep(timeout).await;
            watchdog_timed_out.store(true, std::sync::atomic::Ordering::Release);
            let _ = isolate_handle.terminate_execution();
        });

        let global = match self.execute_source(code.as_ref()) {
            Ok(global) => global,
            Err(error) => {
                watchdog.abort();
                let logs = self.console.take();
                if self
                    .heap_limit_reached
                    .load(std::sync::atomic::Ordering::Acquire)
                {
                    return Err(WorkerError::HeapLimit);
                }
                if timed_out.load(std::sync::atomic::Ordering::Acquire) {
                    return Err(WorkerError::Timeout { timeout_ms });
                }
                return Err(WorkerError::Execution {
                    message: sanitize_js_error(&error),
                    logs: logs.entries,
                    logs_omitted: logs.omitted,
                });
            }
        };
        let resolve = self.runtime.resolve(global);
        let resolved = time::timeout(
            timeout,
            self.runtime
                .with_event_loop_promise(resolve, Default::default()),
        )
        .await;
        watchdog.abort();

        let resolved = match resolved {
            Ok(Ok(value)) if !timed_out.load(std::sync::atomic::Ordering::Acquire) => value,
            Ok(Ok(_)) => {
                self.console.take();
                return Err(WorkerError::Timeout { timeout_ms });
            }
            Ok(Err(error)) => {
                let logs = self.console.take();
                if self
                    .heap_limit_reached
                    .load(std::sync::atomic::Ordering::Acquire)
                {
                    return Err(WorkerError::HeapLimit);
                }
                if let Some(message) = self
                    .host_bridge
                    .as_ref()
                    .and_then(HostBridge::take_protocol_error)
                {
                    return Err(WorkerError::Protocol(message));
                }
                if timed_out.load(std::sync::atomic::Ordering::Acquire) {
                    return Err(WorkerError::Timeout { timeout_ms });
                }
                return Err(WorkerError::Execution {
                    message: sanitize_text(&error.to_string(), MAX_ERROR_BYTES),
                    logs: logs.entries,
                    logs_omitted: logs.omitted,
                });
            }
            Err(_) if timed_out.load(std::sync::atomic::Ordering::Acquire) => {
                self.console.take();
                return Err(WorkerError::Timeout { timeout_ms });
            }
            Err(_) => {
                self.console.take();
                return Err(WorkerError::Timeout { timeout_ms });
            }
        };

        let value = value_to_json(&mut self.runtime, resolved)?;
        let encoded = serde_json::to_vec(&value)
            .map_err(|error| WorkerError::Serialization(error.to_string()))?;
        if encoded.len() > MAX_RESULT_BYTES {
            if encoded.len() <= MAX_REF_CANDIDATE_BYTES {
                let logs = self.console.take();
                return Ok(ExecutionResult {
                    value: Value::Null,
                    logs: logs.entries,
                    logs_omitted: logs.omitted,
                    ref_candidate: Some(RefCandidate {
                        value,
                        encoded_bytes: encoded.len(),
                    }),
                });
            }
            return Err(WorkerError::ResultTooLarge {
                summary: Box::new(ResultTooLargeSummary::from_json(
                    &value,
                    encoded.len(),
                    MAX_RESULT_BYTES,
                )),
            });
        }
        let logs = self.console.take();
        Ok(ExecutionResult {
            value,
            logs: logs.entries,
            logs_omitted: logs.omitted,
            ref_candidate: None,
        })
    }

    fn execute_source(&mut self, code: &str) -> Result<v8::Global<v8::Value>, Box<JsError>> {
        match self
            .runtime
            .execute_script("<worker-code>", code.to_owned())
        {
            Ok(global) => Ok(global),
            Err(error) if error.name.as_deref() == Some("SyntaxError") => {
                let expression = format!("(async function() {{ return await ({code}\n); }})()");
                match self
                    .runtime
                    .execute_script("<worker-async-expression>", expression)
                {
                    Ok(global) => Ok(global),
                    Err(expression_error)
                        if expression_error.name.as_deref() == Some("SyntaxError") =>
                    {
                        let body = format!("(async function() {{\n{code}\n}})()");
                        self.runtime.execute_script("<worker-async-body>", body)
                    }
                    Err(expression_error) => Err(expression_error),
                }
            }
            Err(error) => Err(error),
        }
    }
}

pub async fn run_stdio() -> anyhow::Result<()> {
    let (request_tx, request_rx) = mpsc::channel(MAX_HOST_CALLS_PER_EXECUTION + 2);
    let input_task = tokio::spawn(async move {
        let mut stdin = BufReader::new(tokio::io::stdin());
        loop {
            let Ok(line) = read_line_limited(&mut stdin, MAX_INPUT_BYTES).await else {
                return;
            };
            if line.is_empty() {
                return;
            }
            let Ok(request) = serde_json::from_slice::<WorkerRequest>(&line) else {
                return;
            };
            if request_tx.send(request).await.is_err() {
                return;
            }
        }
    });
    let (response_tx, mut response_rx) = mpsc::channel(MAX_HOST_CALLS_PER_EXECUTION + 2);
    let output_task = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(response) = response_rx.recv().await {
            write_response(&mut stdout, &response).await?;
        }
        Ok::<(), WorkerError>(())
    });
    let bridge = HostBridge::new(response_tx.clone(), request_rx);
    let mut runtime = match WorkerRuntime::new_with_host_bridge(bridge.clone()) {
        Ok(runtime) => runtime,
        Err(error) => {
            input_task.abort();
            drop(response_tx);
            let _ = output_task.await;
            return Err(anyhow::anyhow!(error.to_string()));
        }
    };
    response_tx
        .send(WorkerResponse::Ready {
            protocol: WORKER_PROTOCOL_VERSION,
        })
        .await
        .map_err(|_| anyhow::anyhow!("worker output channel closed"))?;

    let mut last_request_id = 0;
    let result = loop {
        let request = bridge.next_request().await;
        let Some(request) = request else {
            break Ok(());
        };
        match request {
            WorkerRequest::Execute {
                id,
                code,
                timeout_ms,
            } => {
                if id == 0 || id <= last_request_id {
                    break Err(anyhow::anyhow!(
                        "worker request ID is not strictly increasing"
                    ));
                }
                last_request_id = id;
                bridge.begin_execution(id);
                let (response, stop_after_response) = match runtime
                    .execute(&code, Duration::from_millis(timeout_ms))
                    .await
                {
                    Ok(result) => match result.ref_candidate {
                        Some(candidate) => {
                            let response = WorkerResponse::ResultRef {
                                id,
                                value: candidate.value,
                                encoded_bytes: candidate.encoded_bytes,
                                logs: result.logs,
                                logs_omitted: result.logs_omitted,
                            };
                            let fits_output = serde_json::to_vec(&response)
                                .is_ok_and(|bytes| bytes.len() < MAX_OUTPUT_BYTES);
                            if fits_output {
                                (response, false)
                            } else {
                                let summary = match &response {
                                    WorkerResponse::ResultRef {
                                        value,
                                        encoded_bytes,
                                        ..
                                    } => ResultTooLargeSummary::from_json(
                                        value,
                                        *encoded_bytes,
                                        MAX_RESULT_BYTES,
                                    ),
                                    _ => unreachable!("reference response variant is fixed"),
                                };
                                (
                                    WorkerResponse::Error {
                                        id,
                                        code: "result_too_large".to_owned(),
                                        message: "result exceeds the 64 KiB limit".to_owned(),
                                        logs: Vec::new(),
                                        logs_omitted: 0,
                                        details: Some(summary),
                                    },
                                    false,
                                )
                            }
                        }
                        None => (
                            WorkerResponse::Result {
                                id,
                                value: result.value,
                                logs: result.logs,
                                logs_omitted: result.logs_omitted,
                            },
                            false,
                        ),
                    },
                    Err(WorkerError::Execution {
                        message,
                        logs,
                        logs_omitted,
                    }) => (
                        WorkerResponse::Error {
                            id,
                            code: "execution_error".to_owned(),
                            message,
                            logs,
                            logs_omitted,
                            details: None,
                        },
                        false,
                    ),
                    Err(WorkerError::Timeout { timeout_ms }) => (
                        WorkerResponse::Error {
                            id,
                            code: "execution_timeout".to_owned(),
                            message: format!("execution timed out after {timeout_ms} ms"),
                            logs: Vec::new(),
                            logs_omitted: 0,
                            details: None,
                        },
                        true,
                    ),
                    Err(WorkerError::Protocol(message)) => (
                        WorkerResponse::Error {
                            id,
                            code: "protocol_error".to_owned(),
                            message,
                            logs: Vec::new(),
                            logs_omitted: 0,
                            details: None,
                        },
                        true,
                    ),
                    Err(WorkerError::ResultTooLarge { summary }) => (
                        WorkerResponse::Error {
                            id,
                            code: "result_too_large".to_owned(),
                            message: "result exceeds the 64 KiB limit".to_owned(),
                            logs: Vec::new(),
                            logs_omitted: 0,
                            details: Some(*summary),
                        },
                        false,
                    ),
                    Err(WorkerError::HeapLimit) => (
                        WorkerResponse::Error {
                            id,
                            code: "heap_limit".to_owned(),
                            message: "worker heap limit exceeded".to_owned(),
                            logs: Vec::new(),
                            logs_omitted: 0,
                            details: None,
                        },
                        true,
                    ),
                    Err(error) => (
                        WorkerResponse::Error {
                            id,
                            code: "worker_error".to_owned(),
                            message: sanitize_text(&error.to_string(), MAX_ERROR_BYTES),
                            logs: Vec::new(),
                            logs_omitted: 0,
                            details: None,
                        },
                        false,
                    ),
                };
                bridge.end_execution();
                response_tx
                    .send(response)
                    .await
                    .map_err(|_| anyhow::anyhow!("worker output channel closed"))?;
                if stop_after_response {
                    break Err(anyhow::anyhow!("worker execution stopped"));
                }
            }
            WorkerRequest::Close { id } => {
                if id == 0 || id <= last_request_id {
                    break Err(anyhow::anyhow!(
                        "worker request ID is not strictly increasing"
                    ));
                }
                response_tx
                    .send(WorkerResponse::Closed { id })
                    .await
                    .map_err(|_| anyhow::anyhow!("worker output channel closed"))?;
                break Ok(());
            }
            WorkerRequest::HostCallResult { .. } => {
                break Err(anyhow::anyhow!("unexpected host-call result"));
            }
        }
    };
    input_task.abort();
    drop(runtime);
    drop(bridge);
    drop(response_tx);
    match time::timeout(
        Duration::from_millis(WORKER_LIFECYCLE_TIMEOUT_MS),
        output_task,
    )
    .await
    {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => return Err(anyhow::anyhow!(error.to_string())),
        Ok(Err(error)) => return Err(anyhow::anyhow!(error.to_string())),
        Err(_) => return Err(anyhow::anyhow!("worker output shutdown timed out")),
    }
    result
}

const WORKER_BOOTSTRAP: &str = r#"
(() => {
  const op = Deno.core.ops.op_worker_console;
  const hostCall = Deno.core.ops.op_worker_host_call;
  const text = (args) => args.map((value) => {
    try {
      if (typeof value === "string") return value;
      const encoded = JSON.stringify(value);
      return encoded === undefined ? String(value) : encoded;
    } catch (_) {
      try { return String(value); } catch (_) { return "[unprintable]"; }
    }
  }).join(" ");
  const write = (...args) => op(text(args));
  const PEEK_LIMIT = 32;
  const shapeType = (value) => {
    if (value === null) return "null";
    if (Array.isArray(value)) return "array";
    return typeof value;
  };
  const boundedShape = (value) => {
    try {
      const type = shapeType(value);
      if (type === "string") return { type, length: value.length };
      if (type === "array") {
        const count = Math.min(value.length, PEEK_LIMIT);
        const counts = Object.create(null);
        for (let index = 0; index < count; index += 1) {
          const childType = shapeType(value[index]);
          counts[childType] = (counts[childType] || 0) + 1;
        }
        const result = { type, length: value.length, counts };
        if (value.length > count) result.itemsOmitted = value.length - count;
        return result;
      }
      if (type === "object") {
        const allKeys = Object.keys(value).sort();
        const keys = allKeys.slice(0, PEEK_LIMIT).map((key) =>
          key.length > 128 ? key.slice(0, 128) : key);
        const counts = Object.create(null);
        for (const key of allKeys.slice(0, PEEK_LIMIT)) {
          let childType = "unavailable";
          try { childType = shapeType(value[key]); } catch (_) {}
          counts[childType] = (counts[childType] || 0) + 1;
        }
        const result = { type, keyCount: allKeys.length, keys, counts };
        if (allKeys.length > keys.length) result.keysOmitted = allKeys.length - keys.length;
        return result;
      }
      return { type };
    } catch (_) {
      return { type: "unavailable" };
    }
  };
  Object.defineProperty(globalThis, "console", {
    value: Object.freeze({ log: write, debug: write, info: write, warn: write, error: write }),
    writable: false,
    configurable: false,
    enumerable: true,
  });
  Object.defineProperty(globalThis, "az", {
    value: Object.freeze(Object.assign(Object.create(null), {
      request: (arguments) => hostCall("az.request", arguments),
      graph: (arguments) => hostCall("az.graph", arguments),
      ref: (refId) => hostCall("az.ref", { refId }),
      peek: (value) => boundedShape(value),
      metrics: Object.freeze(Object.assign(Object.create(null), {
        single: (arguments) => hostCall("az.metrics.single", arguments),
        batch: (arguments) => hostCall("az.metrics.batch", arguments),
      })),
      logs: Object.freeze(Object.assign(Object.create(null), {
        query: (arguments) => hostCall("az.logs.query", arguments),
      })),
    })),
    writable: false,
    configurable: false,
    enumerable: true,
  });
  try { delete globalThis.Deno; } catch (_) { globalThis.Deno = undefined; }
  try { delete globalThis.__bootstrap; } catch (_) { globalThis.__bootstrap = undefined; }
})();
"#;

#[derive(Clone, Default)]
struct ConsoleSink(Arc<Mutex<ConsoleBuffer>>);

#[derive(Default)]
struct ConsoleBuffer {
    entries: Vec<String>,
    bytes: usize,
    omitted: usize,
}

struct TakenLogs {
    entries: Vec<String>,
    omitted: usize,
}

impl ConsoleSink {
    fn clear(&self) {
        if let Ok(mut buffer) = self.0.lock() {
            *buffer = ConsoleBuffer::default();
        }
    }

    fn push(&self, message: String) {
        let Ok(mut buffer) = self.0.lock() else {
            return;
        };
        if buffer.entries.len() >= MAX_LOG_ENTRIES || buffer.bytes >= MAX_LOG_BYTES {
            buffer.omitted = buffer.omitted.saturating_add(1);
            return;
        }
        let remaining = MAX_LOG_BYTES - buffer.bytes;
        let message = message
            .chars()
            .filter(|character| !character.is_control() || matches!(character, '\n' | '\t'))
            .collect::<String>();
        let message = truncate_utf8(&message, remaining);
        buffer.bytes = buffer.bytes.saturating_add(message.len());
        buffer.entries.push(message);
    }

    fn take(&self) -> TakenLogs {
        let Ok(mut buffer) = self.0.lock() else {
            return TakenLogs {
                entries: Vec::new(),
                omitted: 0,
            };
        };
        let current = std::mem::take(&mut *buffer);
        TakenLogs {
            entries: current.entries,
            omitted: current.omitted,
        }
    }
}

#[op2(fast)]
fn op_worker_console(op_state: Rc<RefCell<OpState>>, #[string] message: String) {
    let sink = op_state.borrow().borrow::<ConsoleSink>().clone();
    sink.push(message);
}

#[op2]
#[serde]
async fn op_worker_host_call(
    op_state: Rc<RefCell<OpState>>,
    #[string] method: String,
    #[serde] arguments: HostCallValue,
) -> Result<HostCallValue, io::Error> {
    let bridge = op_state
        .borrow()
        .try_borrow::<HostBridge>()
        .cloned()
        .ok_or_else(|| io::Error::other("host calls are unavailable"))?;
    match bridge.call(method, arguments.0).await {
        Ok(value) => Ok(HostCallValue(value)),
        Err(HostCallError::Unavailable) => Err(io::Error::other("host calls are unavailable")),
        Err(HostCallError::Rejected(message)) => Err(io::Error::other(message)),
        Err(HostCallError::Protocol(message)) => Err(io::Error::other(format!(
            "host bridge protocol error: {message}"
        ))),
    }
}

#[derive(Deserialize, Serialize)]
#[serde(transparent)]
struct HostCallValue(Value);

deno_core::extension!(
    worker_extension,
    ops = [op_worker_console, op_worker_host_call]
);

fn worker_extension() -> Extension {
    worker_extension::init()
}

fn validate_code(code: &str) -> Result<(), WorkerError> {
    if code.len() > MAX_CODE_BYTES {
        Err(WorkerError::Limit("code"))
    } else {
        Ok(())
    }
}

fn validate_timeout(timeout: Duration) -> Result<u64, WorkerError> {
    let millis = timeout.as_millis();
    let millis = u64::try_from(millis).map_err(|_| WorkerError::Limit("timeout"))?;
    if millis == 0 || millis > MAX_TIMEOUT_MS {
        return Err(WorkerError::Limit("timeout"));
    }
    Ok(millis)
}

fn sanitize_js_error(error: &JsError) -> String {
    sanitize_text(&error.exception_message, MAX_ERROR_BYTES)
}

fn sanitize_text(text: &str, max_bytes: usize) -> String {
    let mut sanitized = text
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\t'))
        .collect::<String>();
    if sanitized.len() > max_bytes {
        sanitized = truncate_utf8(&sanitized, max_bytes.saturating_sub(3));
        sanitized.push('…');
    }
    sanitized
}

fn truncate_utf8(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

fn validate_host_call_request(request: &HostCallRequest) -> Result<(), String> {
    if request.method != HOST_METHOD_REQUEST
        && request.method != HOST_METHOD_GRAPH
        && request.method != HOST_METHOD_METRICS_SINGLE
        && request.method != HOST_METHOD_METRICS_BATCH
        && request.method != HOST_METHOD_LOGS_QUERY
        && request.method != HOST_METHOD_REF
    {
        return Err("unknown host-call method".to_owned());
    }
    if request.method.len() > MAX_HOST_METHOD_BYTES
        || request
            .method
            .chars()
            .any(|character| character.is_control())
    {
        return Err("invalid host-call method".to_owned());
    }
    let encoded = serde_json::to_vec(&request.arguments)
        .map_err(|_| "host-call arguments are not JSON serializable".to_owned())?;
    if encoded.len() > MAX_INPUT_BYTES {
        return Err("host-call arguments exceed the input limit".to_owned());
    }
    Ok(())
}

fn validate_host_call_result(
    request: &HostCallRequest,
    result: &HostCallResult,
) -> Result<(), String> {
    if result.id != request.id || result.call_id != request.call_id {
        return Err("host-call result ID mismatch".to_owned());
    }
    match (result.ok, result.value.as_ref(), result.error.as_deref()) {
        (true, Some(_), None) => {}
        (true, _, _) => return Err("invalid successful host-call result".to_owned()),
        (false, None, Some(error)) if !error.is_empty() && error.len() <= MAX_ERROR_BYTES => {}
        (false, _, _) => return Err("invalid rejected host-call result".to_owned()),
    }
    Ok(())
}

fn value_to_json(
    runtime: &mut JsRuntime,
    value: v8::Global<v8::Value>,
) -> Result<Value, WorkerError> {
    deno_core::scope!(scope, runtime);
    let value = v8::Local::new(scope, value);
    if value.is_undefined() || value.is_null() {
        return Ok(Value::Null);
    }
    serde_v8::from_v8::<Value>(scope, value).map_err(|error| {
        WorkerError::Serialization(sanitize_text(&format!("{error:?}"), MAX_ERROR_BYTES))
    })
}

async fn read_line_limited<R>(reader: &mut R, max_bytes: usize) -> Result<Vec<u8>, WorkerError>
where
    R: AsyncBufRead + Unpin + ?Sized,
{
    let mut line = Vec::new();
    loop {
        let chunk = reader.fill_buf().await.map_err(WorkerError::Io)?;
        if chunk.is_empty() {
            if line.is_empty() {
                return Ok(line);
            }
            return Err(WorkerError::Protocol("unterminated worker line".to_owned()));
        }
        if let Some(index) = chunk.iter().position(|byte| *byte == b'\n') {
            let count = index + 1;
            if line.len().saturating_add(count) > max_bytes {
                return Err(WorkerError::Limit("input"));
            }
            line.extend_from_slice(&chunk[..count]);
            reader.consume(count);
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(line);
        }
        if line.len().saturating_add(chunk.len()) > max_bytes {
            return Err(WorkerError::Limit("input"));
        }
        let count = chunk.len();
        line.extend_from_slice(chunk);
        reader.consume(count);
    }
}

/// Cancellation-safe line reader for the parent-side multiplexing loop.
/// Partial bytes live on `WorkerProcess`, so `tokio::select!` cannot discard
/// the prefix of a worker response when a host handler finishes first.
async fn read_line_limited_buffered<R>(
    reader: &mut R,
    line: &mut Vec<u8>,
    max_bytes: usize,
) -> Result<Vec<u8>, WorkerError>
where
    R: AsyncBufRead + Unpin + ?Sized,
{
    loop {
        let chunk = reader.fill_buf().await.map_err(WorkerError::Io)?;
        if chunk.is_empty() {
            if line.is_empty() {
                return Ok(Vec::new());
            }
            return Err(WorkerError::Protocol("unterminated worker line".to_owned()));
        }
        let count = chunk
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(chunk.len(), |index| index + 1);
        if line.len().saturating_add(count) > max_bytes {
            return Err(WorkerError::Limit("output"));
        }
        line.extend_from_slice(&chunk[..count]);
        reader.consume(count);
        if line.last() == Some(&b'\n') {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(std::mem::take(line));
        }
    }
}

async fn write_response<W>(writer: &mut W, response: &WorkerResponse) -> Result<(), WorkerError>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    let bytes = serde_json::to_vec(response)
        .map_err(|error| WorkerError::Serialization(error.to_string()))?;
    if bytes.len() + 1 > MAX_OUTPUT_BYTES {
        return Err(WorkerError::Limit("output"));
    }
    writer.write_all(&bytes).await.map_err(WorkerError::Io)?;
    writer.write_all(b"\n").await.map_err(WorkerError::Io)?;
    writer.flush().await.map_err(WorkerError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct FixedRssProbe(Option<u64>);

    impl RssProbe for FixedRssProbe {
        fn rss_bytes(&mut self, _pid: u32) -> Option<u64> {
            self.0
        }
    }

    #[test]
    fn protocol_and_limits() {
        let request = WorkerRequest::Execute {
            id: 7,
            code: "1 + 1".to_owned(),
            timeout_ms: 1000,
        };
        let encoded = serde_json::to_string(&request).unwrap();
        assert_eq!(
            serde_json::from_str::<WorkerRequest>(&encoded).unwrap(),
            request
        );
        assert_eq!(
            serde_json::from_str::<Value>(&encoded).unwrap()["type"],
            "execute"
        );
        let host_call = WorkerResponse::HostCall {
            id: 7,
            call_id: 9,
            method: HOST_METHOD_REQUEST.to_owned(),
            arguments: json!({"ok": true}),
        };
        assert_eq!(
            serde_json::from_str::<WorkerResponse>(&serde_json::to_string(&host_call).unwrap())
                .unwrap(),
            host_call
        );
        let result_ref = WorkerResponse::ResultRef {
            id: 7,
            value: json!({"rows": [1, 2, 3]}),
            encoded_bytes: serde_json::to_vec(&json!({"rows": [1, 2, 3]}))
                .unwrap()
                .len(),
            logs: Vec::new(),
            logs_omitted: 0,
        };
        assert_eq!(
            serde_json::from_str::<WorkerResponse>(&serde_json::to_string(&result_ref).unwrap())
                .unwrap(),
            result_ref
        );
        assert!(matches!(
            validate_code(&"x".repeat(MAX_CODE_BYTES + 1)),
            Err(WorkerError::Limit("code"))
        ));
        assert!(matches!(
            validate_timeout(Duration::ZERO),
            Err(WorkerError::Limit("timeout"))
        ));
        assert!(matches!(
            validate_timeout(Duration::from_millis(MAX_TIMEOUT_MS + 1)),
            Err(WorkerError::Limit("timeout"))
        ));
        assert_eq!(truncate_utf8("éé", 3), "é");
        let request = HostCallRequest {
            id: 7,
            call_id: 9,
            method: HOST_METHOD_GRAPH.to_owned(),
            arguments: json!({"query": "Resources"}),
        };
        assert_eq!(
            HostCallResult::success(&request, json!({"count": 1})),
            HostCallResult {
                id: 7,
                call_id: 9,
                ok: true,
                value: Some(json!({"count": 1})),
                error: None,
            }
        );
        assert!(validate_host_call_request(&request).is_ok());
        let ref_request = HostCallRequest {
            method: HOST_METHOD_REF.to_owned(),
            arguments: json!({"refId": "ref_"}),
            ..request.clone()
        };
        assert!(validate_host_call_request(&ref_request).is_ok());
        let sensitive_request = HostCallRequest {
            arguments: json!({
                "refId": "ref_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "query": "KQL-SENTINEL-DO-NOT-LOG",
            }),
            ..ref_request.clone()
        };
        let rendered = format!("{sensitive_request:?}");
        assert!(!rendered.contains("ref_0123456789abcdef"));
        assert!(!rendered.contains("KQL-SENTINEL-DO-NOT-LOG"));
        let result_rendered = format!(
            "{:?}",
            HostCallResult::success(&sensitive_request, json!({"secret": "DO-NOT-LOG"}))
        );
        assert!(!result_rendered.contains("DO-NOT-LOG"));
        assert!(
            validate_host_call_request(&HostCallRequest {
                method: "az.unknown".to_owned(),
                ..request
            })
            .is_err()
        );
        assert!(!rss_limit_exceeded(256, 256));
        assert!(rss_limit_exceeded(257, 256));
    }

    #[test]
    fn result_too_large_summary_is_bounded_deterministic_and_shape_only() {
        let value = json!({
            "z": {"secret": "do-not-return"},
            "a": [1, true, null, {"value": "also-do-not-return"}],
            "message": "sensitive text",
        });
        let encoded_bytes = serde_json::to_vec(&value).unwrap().len();
        let summary = ResultTooLargeSummary::from_json(&value, encoded_bytes, MAX_RESULT_BYTES);

        assert_eq!(summary.value_type, "object");
        assert_eq!(summary.encoded_bytes, encoded_bytes);
        assert_eq!(summary.limit_bytes, MAX_RESULT_BYTES);
        assert_eq!(summary.key_count, Some(3));
        assert_eq!(
            summary.keys,
            Some(vec!["a".to_owned(), "message".to_owned(), "z".to_owned(),])
        );
        assert_eq!(
            summary.counts,
            Some(BTreeMap::from([
                ("array".to_owned(), 1),
                ("object".to_owned(), 1),
                ("string".to_owned(), 1),
            ]))
        );

        let encoded_summary = serde_json::to_string(&summary).unwrap();
        assert!(!encoded_summary.contains("do-not-return"));
        assert!(!encoded_summary.contains("sensitive text"));

        let response = WorkerResponse::Error {
            id: 1,
            code: "result_too_large".to_owned(),
            message: "result exceeds the 64 KiB limit".to_owned(),
            logs: Vec::new(),
            logs_omitted: 0,
            details: Some(summary.clone()),
        };
        assert_eq!(
            serde_json::from_str::<WorkerResponse>(&serde_json::to_string(&response).unwrap())
                .unwrap(),
            response
        );
    }

    #[tokio::test]
    async fn rss_watchdog_records_and_notifies_on_breach() {
        let child = Arc::new(AsyncMutex::new(None));
        let watchdog =
            RssWatchdog::spawn_with_probe(child, 123, 256, Box::new(FixedRssProbe(Some(512))));
        let error = tokio::time::timeout(
            Duration::from_secs(1),
            Arc::clone(&watchdog.state).wait_for_exceeded(watchdog.limit_bytes),
        )
        .await
        .expect("watchdog did not notify");
        assert!(matches!(
            error,
            WorkerError::RssLimit {
                rss_bytes: 512,
                limit_bytes: 256
            }
        ));
        watchdog.stop().await;
    }

    #[tokio::test]
    async fn runtime_persists_state_and_awaits() {
        let mut runtime = WorkerRuntime::new().unwrap();
        let first = runtime
            .execute(
                "globalThis.answer = 41; console.log('hello'); answer + 1",
                Duration::from_secs(1),
            )
            .await
            .unwrap();
        assert_eq!(first.value, json!(42));
        assert_eq!(first.logs, vec!["hello"]);

        let second = runtime
            .execute("answer + 1", Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(second.value, json!(42));
        let result = runtime
            .execute("await Promise.resolve({value: 3})", Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(result.value, json!({"value": 3}));

        let candidate = runtime
            .execute(
                format!("'x'.repeat({})", MAX_RESULT_BYTES + 1),
                Duration::from_secs(1),
            )
            .await
            .expect("bounded oversized result becomes a candidate");
        assert_eq!(candidate.value, Value::Null);
        assert_eq!(
            candidate
                .ref_candidate
                .as_ref()
                .map(|candidate| candidate.encoded_bytes),
            Some(MAX_RESULT_BYTES + 3)
        );
        assert!(matches!(
            runtime
                .execute(
                    format!("'x'.repeat({})", MAX_REF_CANDIDATE_BYTES + 1),
                    Duration::from_secs(1),
                )
                .await,
            Err(WorkerError::ResultTooLarge { .. })
        ));
    }

    #[tokio::test]
    async fn runtime_peek_is_bounded_and_ref_is_a_host_capability() {
        let mut runtime = WorkerRuntime::new().unwrap();
        let result = runtime
            .execute(
                "({peek: az.peek({secret: 'do-not-return', count: 2}), refType: typeof az.ref})",
                Duration::from_secs(1),
            )
            .await
            .expect("peek helper");
        assert_eq!(result.value["refType"], "function");
        assert_eq!(result.value["peek"]["type"], "object");
        assert_eq!(result.value["peek"]["keyCount"], 2);
        let encoded = serde_json::to_string(&result.value).expect("peek JSON");
        assert!(!encoded.contains("do-not-return"));
    }

    #[tokio::test]
    async fn runtime_host_calls_await_and_demultiplex_concurrent_promises() {
        let (response_tx, mut response_rx) = mpsc::channel(8);
        let (request_tx, request_rx) = mpsc::channel(8);
        let bridge = HostBridge::new(response_tx, request_rx);
        bridge.begin_execution(11);
        let mut runtime = WorkerRuntime::new_with_host_bridge(bridge.clone()).unwrap();
        let mut execution = Box::pin(runtime.execute(
            "Promise.all([az.request({n: 1}), az.graph({n: 2}), az.logs.query({n: 3})])",
            Duration::from_secs(1),
        ));
        let result = loop {
            tokio::select! {
                result = &mut execution => break result,
                response = response_rx.recv() => {
                    let Some(WorkerResponse::HostCall { id, call_id, method, arguments }) = response else {
                        panic!("host call channel closed before execution completed");
                    };
                    let request = HostCallRequest { id, call_id, method, arguments };
                    assert_eq!(request.id, 11);
                    assert!(request.method == HOST_METHOD_REQUEST
                        || request.method == HOST_METHOD_GRAPH
                        || request.method == HOST_METHOD_LOGS_QUERY);
                    request_tx.send(WorkerRequest::HostCallResult {
                        id: request.id,
                        call_id: request.call_id,
                        ok: true,
                        value: Some(json!({"method": request.method, "n": request.arguments["n"]})),
                        error: None,
                    }).await.unwrap();
                }
            }
        };
        bridge.end_execution();
        let result = result.unwrap();
        assert_eq!(
            result.value,
            json!([
                {"method": HOST_METHOD_REQUEST, "n": 1},
                {"method": HOST_METHOD_GRAPH, "n": 2},
                {"method": HOST_METHOD_LOGS_QUERY, "n": 3}
            ])
        );
    }

    #[tokio::test]
    async fn runtime_exposes_explicit_metrics_helpers() {
        let (response_tx, mut response_rx) = mpsc::channel(8);
        let (request_tx, request_rx) = mpsc::channel(8);
        let bridge = HostBridge::new(response_tx, request_rx);
        bridge.begin_execution(12);
        let mut runtime = WorkerRuntime::new_with_host_bridge(bridge.clone()).unwrap();
        let mut execution = Box::pin(runtime.execute(
            "Promise.all([az.metrics.single({cloud: 'AzureCloud', metricNames: ['m']}), az.metrics.batch({cloud: 'AzureUSGovernment', region: 'usgov-virginia', resourceIds: [], metricNamespace: 'n', metricNames: ['m']})])",
            Duration::from_secs(1),
        ));
        let mut methods = Vec::new();
        let result = loop {
            tokio::select! {
                result = &mut execution => break result,
                response = response_rx.recv() => {
                    let Some(WorkerResponse::HostCall { id, call_id, method, arguments }) = response else {
                        panic!("metrics host call channel closed before execution completed");
                    };
                    methods.push(method.clone());
                    request_tx.send(WorkerRequest::HostCallResult {
                        id,
                        call_id,
                        ok: true,
                        value: Some(json!({"method": method, "arguments": arguments})),
                        error: None,
                    }).await.unwrap();
                }
            }
        };
        bridge.end_execution();
        result.expect("metrics execution");
        methods.sort_unstable();
        assert_eq!(
            methods,
            vec![
                HOST_METHOD_METRICS_BATCH.to_owned(),
                HOST_METHOD_METRICS_SINGLE.to_owned()
            ]
        );
    }

    #[tokio::test]
    async fn runtime_host_call_protocol_mismatch_is_fatal() {
        let (response_tx, mut response_rx) = mpsc::channel(2);
        let (request_tx, request_rx) = mpsc::channel(2);
        let bridge = HostBridge::new(response_tx, request_rx);
        bridge.begin_execution(21);
        let mut runtime = WorkerRuntime::new_with_host_bridge(bridge.clone()).unwrap();
        let mut execution = Box::pin(runtime.execute("az.request({n: 1})", Duration::from_secs(1)));
        let response = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::select! {
                response = response_rx.recv() => response,
                result = &mut execution => panic!("execution finished before host call: {result:?}"),
            }
        })
        .await
        .expect("host call was not emitted before the test timeout");
        let Some(WorkerResponse::HostCall { id, call_id, .. }) = response else {
            panic!("host call was not emitted");
        };
        request_tx
            .send(WorkerRequest::HostCallResult {
                id: id + 1,
                call_id,
                ok: true,
                value: Some(json!(null)),
                error: None,
            })
            .await
            .unwrap();
        let result = execution.await;
        assert!(
            matches!(
                &result,
                Err(WorkerError::Protocol(message))
                    if message.contains("host-call request ID mismatch")
            ),
            "unexpected execution result: {result:?}"
        );
    }
}
