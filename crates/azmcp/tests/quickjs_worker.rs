use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use azmcp::refs::{RefId, RefStore};
use azmcp::worker::{
    ArtifactWriteCompression, ArtifactWriteJsonStreamArguments,
    HOST_METHOD_ARTIFACT_WRITE_JSON_ARRAY, HOST_METHOD_ARTIFACT_WRITE_JSON_LINES, HOST_METHOD_REF,
    HostCallHandler, HostCallResult, MAX_ARTIFACT_STREAM_CHUNKS, MAX_HOST_CALL_FRAME_BYTES,
    MAX_LOG_BYTES, MAX_LOG_ENTRIES, MAX_PENDING_HOST_CALLS, MAX_REF_CANDIDATE_BYTES,
    MAX_RESULT_BYTES, WorkerError, WorkerProcess,
};
use serde_json::{Value, json};
use tokio::sync::{Barrier, Mutex, Notify};

// The experimental binary is always injected explicitly. These tests service
// host calls in memory and never construct Azure credentials or HTTP clients.
fn worker_executable() -> PathBuf {
    let path = PathBuf::from(
        std::env::var_os("AZMCP_QUICKJS_WORKER")
            .expect("set AZMCP_QUICKJS_WORKER to the experimental worker's absolute path"),
    );
    assert!(path.is_absolute(), "worker path must be absolute");
    let path = path.canonicalize().expect("worker executable must exist");
    let metadata = path.metadata().expect("read worker executable metadata");
    assert!(metadata.is_file(), "worker path must name a regular file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_ne!(
            metadata.permissions().mode() & 0o111,
            0,
            "worker file must be executable"
        );
    }
    path
}

async fn start_worker() -> WorkerProcess {
    WorkerProcess::start(worker_executable())
        .await
        .expect("start explicitly injected isolated worker")
}

fn ref_handler(store: Arc<Mutex<RefStore>>) -> HostCallHandler {
    Arc::new(move |request| {
        let store = Arc::clone(&store);
        Box::pin(async move {
            assert_eq!(request.method, HOST_METHOD_REF);
            let ref_id = RefId::parse(
                request.arguments["refId"]
                    .as_str()
                    .expect("ref call carries its ID"),
            )
            .expect("valid ref ID");
            match store.lock().await.get(&ref_id, Instant::now()) {
                Ok(value) => HostCallResult::success(&request, value),
                Err(_) => HostCallResult::failure(&request, "reference is unavailable"),
            }
        })
    })
}

#[tokio::test]
#[ignore = "requires experimental Go worker"]
async fn quickjs_persists_global_and_lexical_bindings_and_supports_await_fallback() {
    let mut worker = start_worker().await;
    let first = worker
        .execute(
            "globalThis.saved = 40; let lexical = 2; const fixed = 3; saved + lexical + fixed",
            Duration::from_secs(2),
        )
        .await
        .expect("first turn");
    assert_eq!(first.value, 45);
    assert_eq!(
        worker
            .execute("saved += lexical; saved + fixed", Duration::from_secs(2))
            .await
            .expect("persistent bindings")
            .value,
        45
    );
    assert_eq!(
        worker
            .execute(
                "await Promise.resolve({value: fixed})",
                Duration::from_secs(2)
            )
            .await
            .expect("top-level await expression")
            .value,
        json!({"value": 3})
    );
    assert_eq!(
        worker
            .execute(
                "const temporary = await Promise.resolve(4); return temporary + saved;",
                Duration::from_secs(2),
            )
            .await
            .expect("top-level await body")
            .value,
        46
    );
    worker.close().await.expect("clean close");
    assert!(matches!(
        worker.execute("1", Duration::from_secs(1)).await,
        Err(WorkerError::Closed)
    ));
}

#[tokio::test]
#[ignore = "requires experimental Go worker"]
async fn quickjs_denies_ambient_globals_and_bounds_logs() {
    let mut worker = start_worker().await;
    let result = worker
        .execute(
            r#"console.log("hello", {n: 1});
            ({Deno: typeof Deno, process: typeof process, require: typeof require,
              fetch: typeof fetch, setTimeout: typeof setTimeout,
              std: typeof std, os: typeof os,
              hostCall: typeof __azmcpHostCall, consoleOp: typeof __azmcpConsole,
              send: typeof __azmcpSend, complete: typeof __azmcpComplete,
              syncTransport: typeof __azmcpSyncTransport,
              frozen: Object.isFrozen(az) && Object.isFrozen(az.artifacts)})"#,
            Duration::from_secs(2),
        )
        .await
        .expect("restricted globals");
    assert_eq!(
        result.value,
        json!({"Deno": "undefined", "process": "undefined", "require": "undefined",
               "fetch": "undefined", "setTimeout": "undefined", "std": "undefined", "os": "undefined",
               "hostCall": "undefined", "consoleOp": "undefined", "send": "undefined",
               "complete": "undefined", "syncTransport": "undefined", "frozen": true})
    );
    assert_eq!(result.logs, ["hello {\"n\":1}"]);
    assert_eq!(result.logs_omitted, 0);
    let result = worker
        .execute(
            "for (let n = 0; n < 300; n++) console.log(n); 'done'",
            Duration::from_secs(2),
        )
        .await
        .expect("bounded console output");
    assert_eq!(result.value, "done");
    assert_eq!(result.logs.len(), MAX_LOG_ENTRIES);
    assert_eq!(result.logs.first().map(String::as_str), Some("0"));
    assert_eq!(result.logs.last().map(String::as_str), Some("255"));
    assert_eq!(result.logs_omitted, 44);
    let result = worker
        .execute(
            "console.log('😀'.repeat(20000)); console.log('omitted'); 8",
            Duration::from_secs(2),
        )
        .await
        .expect("bounded UTF-8 console bytes");
    assert_eq!(result.logs.len(), 1);
    assert_eq!(result.logs[0].len(), MAX_LOG_BYTES);
    assert!(result.logs[0].chars().all(|character| character == '😀'));
    assert_eq!(result.logs_omitted, 1);
    let next = worker
        .execute("7", Duration::from_secs(2))
        .await
        .expect("next turn");
    assert!(next.logs.is_empty());
    assert_eq!(next.logs_omitted, 0);
    worker.close().await.expect("clean close");
}

#[tokio::test]
#[ignore = "requires experimental Go worker"]
async fn quickjs_execution_errors_preserve_context_and_error_logs() {
    let mut worker = start_worker().await;
    let error = worker
        .execute(
            "globalThis.survived = 41; console.warn('before failure'); throw new Error('synthetic failure');",
            Duration::from_secs(2),
        )
        .await
        .expect_err("throw fails this turn");
    match error {
        WorkerError::Execution {
            message,
            logs,
            logs_omitted,
        } => {
            assert!(message.contains("synthetic failure"), "{message}");
            assert_eq!(logs, ["before failure"]);
            assert_eq!(logs_omitted, 0);
        }
        other => panic!("unexpected error: {other:?}"),
    }
    for code in ["const = ;", "await az.request({n: 1})"] {
        assert!(matches!(
            worker.execute(code, Duration::from_secs(2)).await,
            Err(WorkerError::Execution { .. })
        ));
    }
    assert_eq!(
        worker
            .execute("survived + 1", Duration::from_secs(2))
            .await
            .expect("errors do not poison context")
            .value,
        42
    );
    worker.close().await.expect("clean close");
}

#[tokio::test]
#[ignore = "requires experimental Go worker"]
async fn quickjs_promise_all_demultiplexes_and_bounds_parent_concurrency() {
    let mut worker = start_worker().await;
    let active = Arc::new(AtomicUsize::new(0));
    let maximum = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(MAX_PENDING_HOST_CALLS));
    let observed_maximum = Arc::clone(&maximum);
    let handler: HostCallHandler = Arc::new(move |request| {
        let active = Arc::clone(&active);
        let maximum = Arc::clone(&maximum);
        let barrier = Arc::clone(&barrier);
        Box::pin(async move {
            assert!(request.method == "az.request" || request.method == "az.graph");
            let current = active.fetch_add(1, Ordering::SeqCst) + 1;
            maximum.fetch_max(current, Ordering::SeqCst);
            barrier.wait().await;
            active.fetch_sub(1, Ordering::SeqCst);
            HostCallResult::success(&request, request.arguments.clone())
        })
    });
    let result = worker
        .execute_with_host_handler(
            "Promise.all(Array.from({length: 32}, (_, n) => n % 2 ? az.graph({n}) : az.request({n})))",
            Duration::from_secs(5),
            handler,
        )
        .await
        .expect("concurrent promises");
    assert_eq!(
        result.value,
        Value::Array((0..32).map(|n| json!({"n": n})).collect())
    );
    assert_eq!(observed_maximum.load(Ordering::SeqCst), 8);
    worker.close().await.expect("clean close");
}

#[tokio::test]
#[ignore = "requires experimental Go worker"]
async fn quickjs_async_generator_streams_normalized_json_lines() {
    let mut worker = start_worker().await;
    let messages = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&messages);
    let result = worker
        .execute_with_handler(
            r#"az.artifacts.writeJsonLines({
                name: "rows.jsonl.lz4", compression: "lz4",
                values: (async function* () {
                    yield {ignored: true, toJSON() { return {index: 0}; }};
                    yield ["nested", true]; yield "text"; yield null;
                })(),
            })"#,
            Duration::from_secs(5),
            move |request| {
                let messages = Arc::clone(&messages);
                async move {
                    assert_eq!(request.method, HOST_METHOD_ARTIFACT_WRITE_JSON_LINES);
                    assert!(request.encoded_frame_bytes().unwrap() <= MAX_HOST_CALL_FRAME_BYTES);
                    messages.lock().await.push(request.arguments.clone());
                    let response = match request.arguments["phase"].as_str().unwrap() {
                        "begin" => json!({"streamId": "stream_lines"}),
                        "append" => json!({"acceptedSequence": 0}),
                        "finish" => json!({"path": "/synthetic/rows.jsonl.lz4", "mediaType": "application/x-ndjson"}),
                        phase => panic!("unexpected stream phase: {phase}"),
                    };
                    HostCallResult::success(&request, response)
                }
            },
        )
        .await
        .expect("stream normalized JSON lines");
    assert_eq!(
        *observed.lock().await,
        [
            json!({"phase": "begin", "name": "rows.jsonl.lz4", "compression": "lz4"}),
            json!({"phase": "append", "streamId": "stream_lines", "sequence": 0,
                   "values": [{"index": 0}, ["nested", true], "text", null]}),
            json!({"phase": "finish", "streamId": "stream_lines", "chunks": 1, "items": 4}),
        ]
    );
    assert_eq!(
        result.value,
        json!({"path": "/synthetic/rows.jsonl.lz4", "mediaType": "application/x-ndjson"})
    );
    worker.close().await.expect("clean close");
}

#[derive(Default)]
struct StreamStats {
    chunks: u16,
    items: u64,
    json_bytes: usize,
    maximum_frame_bytes: usize,
}

#[tokio::test]
#[ignore = "requires experimental Go worker"]
async fn quickjs_streams_over_32_mib_without_unbounded_frames() {
    let mut worker = start_worker().await;
    let stats = Arc::new(Mutex::new(StreamStats {
        json_bytes: 2,
        ..StreamStats::default()
    }));
    let observed = Arc::clone(&stats);
    let result = worker
        .execute_with_handler(
            r#"az.artifacts.writeJsonArray({
                name: "large.json", values: (async function* () {
                    for (let index = 0; index < 96; index++) {
                        yield {index, payload: "x".repeat(360 * 1024)};
                    }
                })(),
            })"#,
            Duration::from_secs(60),
            move |request| {
                let stats = Arc::clone(&stats);
                async move {
                    assert_eq!(request.method, HOST_METHOD_ARTIFACT_WRITE_JSON_ARRAY);
                    let frame_bytes = request.encoded_frame_bytes().unwrap();
                    assert!(frame_bytes <= MAX_HOST_CALL_FRAME_BYTES);
                    let phase: ArtifactWriteJsonStreamArguments =
                        serde_json::from_value(request.arguments.clone()).unwrap();
                    phase.validate().expect("bounded stream message");
                    let mut stats = stats.lock().await;
                    stats.maximum_frame_bytes = stats.maximum_frame_bytes.max(frame_bytes);
                    let value = match phase {
                        ArtifactWriteJsonStreamArguments::Begin { name, compression } => {
                            assert_eq!(name, "large.json");
                            assert_eq!(compression, ArtifactWriteCompression::Identity);
                            json!({"streamId": "stream_large"})
                        }
                        ArtifactWriteJsonStreamArguments::Append {
                            stream_id,
                            sequence,
                            values,
                        } => {
                            assert_eq!(stream_id, "stream_large");
                            assert_eq!(sequence, stats.chunks);
                            assert_eq!(values.len(), 1);
                            for value in values {
                                assert_eq!(value["index"], stats.items);
                                assert_eq!(value["payload"].as_str().unwrap().len(), 360 * 1024);
                                stats.json_bytes += usize::from(stats.items != 0)
                                    + serde_json::to_vec(&value).unwrap().len();
                                stats.items += 1;
                            }
                            stats.chunks += 1;
                            json!({"acceptedSequence": sequence})
                        }
                        ArtifactWriteJsonStreamArguments::Finish {
                            stream_id,
                            chunks,
                            items,
                        } => {
                            assert_eq!(stream_id, "stream_large");
                            assert_eq!(chunks, 96);
                            assert_eq!(items, 96);
                            json!({"path": "/synthetic/large.json", "bytes": stats.json_bytes})
                        }
                        ArtifactWriteJsonStreamArguments::Abort { .. } => {
                            panic!("successful stream must not abort")
                        }
                    };
                    HostCallResult::success(&request, value)
                }
            },
        )
        .await
        .expect("stream large JSON array");
    let stats = observed.lock().await;
    assert!(stats.json_bytes > 32 * 1024 * 1024);
    assert!(stats.chunks <= MAX_ARTIFACT_STREAM_CHUNKS);
    assert_eq!(stats.items, 96);
    assert!(stats.maximum_frame_bytes <= MAX_HOST_CALL_FRAME_BYTES);
    assert_eq!(result.value["bytes"], stats.json_bytes);
    drop(stats);
    worker.close().await.expect("clean close");
}

#[tokio::test]
#[ignore = "requires experimental Go worker"]
async fn quickjs_aborts_artifact_stream_after_oversized_item() {
    let mut worker = start_worker().await;
    let phases = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&phases);
    let error = worker
        .execute_with_handler(
            "az.artifacts.writeJsonArray({name: 'oversized.json', values: ['x'.repeat(400 * 1024)]})",
            Duration::from_secs(5),
            move |request| {
                let phases = Arc::clone(&phases);
                async move {
                    assert_eq!(request.method, HOST_METHOD_ARTIFACT_WRITE_JSON_ARRAY);
                    phases.lock().await.push(request.arguments.clone());
                    let value = match request.arguments["phase"].as_str().unwrap() {
                        "begin" => json!({"streamId": "stream_oversized"}),
                        "abort" => json!({"aborted": true}),
                        phase => panic!("oversized item must not emit {phase}"),
                    };
                    HostCallResult::success(&request, value)
                }
            },
        )
        .await
        .expect_err("reject oversized stream item");
    assert!(matches!(error, WorkerError::Execution { .. }), "{error:?}");
    assert_eq!(
        *observed.lock().await,
        [
            json!({"phase": "begin", "name": "oversized.json", "compression": "identity"}),
            json!({"phase": "abort", "streamId": "stream_oversized"}),
        ]
    );
    assert_eq!(
        worker
            .execute("2", Duration::from_secs(2))
            .await
            .unwrap()
            .value,
        2
    );
    worker.close().await.expect("clean close");
}

#[tokio::test]
#[ignore = "requires experimental Go worker"]
async fn quickjs_result_refs_rehydrate_immutably_and_are_context_scoped() {
    let mut worker = start_worker().await;
    let candidate = worker
        .execute(
            "({secret: 'original', padding: 'x'.repeat(70000)})",
            Duration::from_secs(2),
        )
        .await
        .expect("oversized bounded value");
    assert_eq!(candidate.value, Value::Null);
    let candidate = candidate.ref_candidate.expect("automatic result_ref");
    assert!(candidate.encoded_bytes > MAX_RESULT_BYTES);
    assert!(candidate.encoded_bytes <= MAX_REF_CANDIDATE_BYTES);
    assert_eq!(candidate.value["secret"], "original");
    assert_eq!(candidate.value["padding"].as_str().unwrap().len(), 70000);
    let store = Arc::new(Mutex::new(RefStore::with_defaults()));
    let ref_id = store
        .lock()
        .await
        .put(candidate.value, Instant::now())
        .unwrap();
    let ref_id = ref_id.as_str();
    let handler = ref_handler(Arc::clone(&store));
    let mutated = worker
        .execute_with_host_handler(
            format!("(async () => {{ const value = await az.ref({ref_id:?}); value.secret = 'changed'; return value.secret; }})()"),
            Duration::from_secs(2),
            Arc::clone(&handler),
        )
        .await
        .expect("mutate hydrated copy");
    assert_eq!(mutated.value, "changed");
    let original = worker
        .execute_with_host_handler(
            format!("(async () => {{ const value = await az.ref({ref_id:?}); return {{secret: value.secret, length: value.padding.length}}; }})()"),
            Duration::from_secs(2),
            handler,
        )
        .await
        .expect("rehydrate original");
    assert_eq!(
        original.value,
        json!({"secret": "original", "length": 70000})
    );
    let mut other = start_worker().await;
    assert!(matches!(
        other
            .execute_with_host_handler(
                format!("await az.ref({ref_id:?})"),
                Duration::from_secs(2),
                ref_handler(Arc::new(Mutex::new(RefStore::with_defaults()))),
            )
            .await,
        Err(WorkerError::Execution { .. })
    ));
    assert_eq!(
        other
            .execute("2", Duration::from_secs(2))
            .await
            .unwrap()
            .value,
        2
    );
    worker.close().await.expect("close first worker");
    other.close().await.expect("close second worker");
}

#[tokio::test]
#[ignore = "requires experimental Go worker"]
async fn quickjs_result_ref_sizes_match_parent_json_encoding() {
    let mut worker = start_worker().await;
    for code in [
        "'<>&\\u2028\\u2029😀'.repeat(7000)",
        "Array(16000).fill(1e21)",
        "Array(16000).fill(1e-7)",
        "Array(16000).fill(0.000001)",
        "'\\ud800'.repeat(40000)",
        r#"(() => {
            const numbers = [
                5e-324, 2.2250738585072014e-308, Number.MAX_VALUE, Number.EPSILON,
                Math.PI, 2 ** 64, -(2 ** 64), -0, 1e-5, 1e-6, 1e15, 1e16,
                1e-7, 1e21, 1.2345678901234567, 0.10000000000000002,
            ];
            for (let exponent = -300; exponent <= 300; exponent += 25) {
                numbers.push(1.2345678901234567 * 10 ** exponent);
            }
            return Array(400).fill(numbers);
        })()"#,
    ] {
        let result = worker
            .execute(code, Duration::from_secs(5))
            .await
            .unwrap_or_else(|error| {
                panic!("candidate size validation failed for {code}: {error:?}")
            });
        let candidate = result
            .ref_candidate
            .expect("oversized result is a candidate");
        assert_eq!(
            candidate.encoded_bytes,
            serde_json::to_vec(&candidate.value).unwrap().len()
        );
    }
    worker.close().await.expect("clean close");
}

#[tokio::test]
#[ignore = "requires experimental Go worker"]
async fn quickjs_unicode_results_and_host_arguments_match_parent_conversion() {
    let mut worker = start_worker().await;
    let result = worker
        .execute(
            r#"["\ud800", "\udc00", "\ud83d\ude00", "\u0000", "\u2028\u2029", "\\ud800"]"#,
            Duration::from_secs(2),
        )
        .await
        .expect("UTF-16 strings cross the UTF-8 JSON boundary");
    assert_eq!(
        result.value,
        json!(["�", "�", "😀", "\0", "\u{2028}\u{2029}", "\\ud800"])
    );
    let result = worker
        .execute_with_handler(
            r#"az.request({text: "\ud800", pair: "\ud83d\ude00", literal: "\\ud800"})"#,
            Duration::from_secs(2),
            |request| async move {
                assert_eq!(request.method, "az.request");
                assert_eq!(
                    request.arguments,
                    json!({"text": "�", "pair": "😀", "literal": "\\ud800"})
                );
                HostCallResult::success(&request, request.arguments.clone())
            },
        )
        .await
        .expect("host arguments use the same string conversion");
    assert_eq!(
        result.value,
        json!({"text": "�", "pair": "😀", "literal": "\\ud800"})
    );
    worker.close().await.expect("clean close");
}

#[tokio::test]
#[ignore = "requires experimental Go worker"]
async fn quickjs_oversized_diagnostic_contains_only_shape_and_preserves_context() {
    let mut worker = start_worker().await;
    let error = worker
        .execute(
            "({secret: 'do-not-leak', padding: 'x'.repeat(600000)})",
            Duration::from_secs(5),
        )
        .await
        .expect_err("value exceeds reference-candidate cap");
    let WorkerError::ResultTooLarge { summary } = error else {
        panic!("unexpected oversized-result error: {error:?}");
    };
    assert_eq!(summary.value_type, "object");
    assert_eq!(summary.limit_bytes, 65536);
    assert_eq!(summary.key_count, Some(2));
    assert_eq!(
        summary.keys,
        Some(vec!["padding".to_owned(), "secret".to_owned()])
    );
    assert_eq!(summary.counts.as_ref().unwrap().get("string"), Some(&2));
    assert!(summary.encoded_bytes > MAX_REF_CANDIDATE_BYTES);
    assert!(
        !serde_json::to_string(&summary)
            .unwrap()
            .contains("do-not-leak")
    );
    assert_eq!(
        worker
            .execute("3", Duration::from_secs(2))
            .await
            .unwrap()
            .value,
        3
    );
    worker.close().await.expect("clean close");
}

async fn assert_timeout_poisoning(code: &str) {
    let mut worker = start_worker().await;
    let started = Instant::now();
    let result = worker.execute(code, Duration::from_millis(100)).await;
    assert!(
        matches!(result, Err(WorkerError::Timeout { .. })),
        "{result:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(matches!(
        worker.execute("1 + 1", Duration::from_secs(1)).await,
        Err(WorkerError::Closed)
    ));
}

#[tokio::test]
#[ignore = "requires experimental Go worker"]
async fn quickjs_cpu_timeout_poisoning() {
    assert_timeout_poisoning("while (true) {}").await;
}

#[tokio::test]
#[ignore = "requires experimental Go worker"]
async fn quickjs_unresolved_promise_timeout_poisoning() {
    // QuickJS retains an unresolved turn until its explicit deadline. V8
    // instead returns a recoverable execution error when its event loop idles.
    assert_timeout_poisoning("new Promise(() => {})").await;
}

#[tokio::test]
#[ignore = "requires experimental Go worker"]
async fn quickjs_self_replenishing_microtask_timeout_poisoning() {
    // The V8 control exits under this load without a structured error; the
    // experiment additionally promises an explicit timeout classification.
    assert_timeout_poisoning(
        "(() => { const spin = () => Promise.resolve().then(spin); spin(); return new Promise(() => {}); })()",
    ).await;
}

#[tokio::test]
#[ignore = "requires experimental Go worker"]
async fn quickjs_allocation_pressure_is_fatal() {
    let mut worker = start_worker().await;
    let result = worker
        .execute(
            "const held=[]; while (true) held.push('x'.repeat(1024*1024));",
            Duration::from_secs(10),
        )
        .await;
    assert!(result.is_err(), "allocation pressure must fail: {result:?}");
    assert!(
        !matches!(result, Err(WorkerError::Timeout { .. })),
        "allocation pressure must reach a memory boundary before the deadline: {result:?}"
    );
    assert!(matches!(
        worker.execute("1 + 1", Duration::from_secs(1)).await,
        Err(WorkerError::Closed)
    ));
}

#[tokio::test]
#[ignore = "requires experimental Go worker"]
async fn quickjs_cancelled_execution_can_be_hard_terminated() {
    let mut worker = start_worker().await;
    let entered = Arc::new(Notify::new());
    let observed = Arc::clone(&entered);
    let mut execution = Box::pin(worker.execute_with_handler(
        "await az.request({pending: true})",
        Duration::from_secs(30),
        move |request| {
            let entered = Arc::clone(&entered);
            async move {
                assert_eq!(request.arguments, json!({"pending": true}));
                entered.notify_one();
                std::future::pending::<HostCallResult>().await
            }
        },
    ));
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(3)) => panic!("worker did not start host call"),
        _ = observed.notified() => {},
        result = &mut execution => panic!("pending execution completed unexpectedly: {result:?}"),
    }
    drop(execution);
    tokio::time::timeout(Duration::from_secs(3), worker.terminate())
        .await
        .expect("cancellation must terminate child promptly");
    assert!(matches!(
        worker.execute("1", Duration::from_secs(1)).await,
        Err(WorkerError::Closed)
    ));
}
