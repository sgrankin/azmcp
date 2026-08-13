use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use azmcp::worker::{
    HostCallHandler, HostCallResult, MAX_PENDING_HOST_CALLS, WorkerError, WorkerProcess,
};
use serde_json::json;
use tokio::sync::{Barrier, Notify};

#[tokio::test]
async fn subprocess_worker_persists_and_closes() {
    let mut worker = WorkerProcess::start(env!("CARGO_BIN_EXE_azmcp"))
        .await
        .expect("start isolated worker");
    let first = worker
        .execute("globalThis.saved = 40; saved + 2", Duration::from_secs(2))
        .await
        .expect("first turn");
    assert_eq!(first.value, json!(42));
    let second = worker
        .execute("saved + 3", Duration::from_secs(2))
        .await
        .expect("persistent turn");
    assert_eq!(second.value, json!(43));
    worker.close().await.expect("clean close");
}

#[tokio::test]
async fn subprocess_timeout_kills_and_poison_worker() {
    let mut worker = WorkerProcess::start(env!("CARGO_BIN_EXE_azmcp"))
        .await
        .expect("start isolated worker");
    assert!(matches!(
        worker
            .execute("while (true) {}", Duration::from_millis(50))
            .await,
        Err(WorkerError::Timeout { .. })
    ));
    assert!(matches!(
        worker.execute("1 + 1", Duration::from_secs(1)).await,
        Err(WorkerError::Closed)
    ));
}

#[tokio::test]
async fn subprocess_host_calls_can_complete_concurrently() {
    let mut worker = WorkerProcess::start(env!("CARGO_BIN_EXE_azmcp"))
        .await
        .expect("start isolated worker");
    let entered = Arc::new(AtomicUsize::new(0));
    let notify = Arc::new(Notify::new());
    let handler: HostCallHandler = Arc::new(move |request| {
        let entered = Arc::clone(&entered);
        let notify = Arc::clone(&notify);
        Box::pin(async move {
            entered.fetch_add(1, Ordering::SeqCst);
            notify.notify_waiters();
            while entered.load(Ordering::SeqCst) < 2 {
                notify.notified().await;
            }
            HostCallResult::success(&request, request.arguments.clone())
        })
    });
    let result = worker
        .execute_with_host_handler(
            "Promise.all([az.request({n: 1}), az.graph({n: 2})])",
            Duration::from_secs(2),
            handler,
        )
        .await
        .expect("parallel host calls");
    assert_eq!(result.value, json!([{"n": 1}, {"n": 2}]));
    worker.close().await.expect("clean close");
}

#[tokio::test]
async fn subprocess_host_calls_bound_parent_handler_concurrency() {
    let mut worker = WorkerProcess::start(env!("CARGO_BIN_EXE_azmcp"))
        .await
        .expect("start isolated worker");
    let active = Arc::new(AtomicUsize::new(0));
    let maximum = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(MAX_PENDING_HOST_CALLS));
    let observed_maximum = Arc::clone(&maximum);
    let handler: HostCallHandler = Arc::new(move |request| {
        let active = Arc::clone(&active);
        let maximum = Arc::clone(&maximum);
        let barrier = Arc::clone(&barrier);
        Box::pin(async move {
            let current = active.fetch_add(1, Ordering::SeqCst) + 1;
            maximum.fetch_max(current, Ordering::SeqCst);
            // Hold each cohort until the parent has admitted the full cap.
            // A sleep made this assertion depend on scheduler speed and could
            // observe fewer calls without indicating a concurrency defect.
            barrier.wait().await;
            active.fetch_sub(1, Ordering::SeqCst);
            HostCallResult::success(&request, request.arguments.clone())
        })
    });
    let call_count = 32;
    let code =
        format!("Promise.all(Array.from({{length: {call_count}}}, (_, n) => az.request({{n}})))");
    let result = worker
        .execute_with_host_handler(&code, Duration::from_secs(2), handler)
        .await
        .expect("bounded host calls");
    assert_eq!(result.value.as_array().map(Vec::len), Some(call_count));
    assert!(observed_maximum.load(Ordering::SeqCst) <= MAX_PENDING_HOST_CALLS);
    assert_eq!(
        observed_maximum.load(Ordering::SeqCst),
        MAX_PENDING_HOST_CALLS
    );
    worker.close().await.expect("clean close");
}

#[tokio::test]
async fn subprocess_heap_pressure_terminates_worker() {
    let mut worker = WorkerProcess::start(env!("CARGO_BIN_EXE_azmcp"))
        .await
        .expect("start isolated worker");
    let result = worker
        .execute(
            "const held=[]; while (true) held.push('x'.repeat(1024*1024));",
            Duration::from_secs(5),
        )
        .await;
    assert!(result.is_err());
    let second = worker.execute("1 + 1", Duration::from_secs(1)).await;
    assert!(matches!(second, Err(WorkerError::Closed)), "{second:?}");
}

#[tokio::test]
async fn subprocess_rss_watchdog_kills_at_explicit_test_limit() {
    let result = WorkerProcess::start_with_rss_limit(env!("CARGO_BIN_EXE_azmcp"), 1).await;
    match result {
        Err(WorkerError::RssLimit {
            rss_bytes,
            limit_bytes,
        }) => {
            assert_eq!(limit_bytes, 1);
            assert!(rss_bytes > limit_bytes);
            eprintln!("synthetic worker startup RSS: {rss_bytes} bytes");
        }
        Ok(mut worker) => {
            let error = worker
                .execute("1 + 1", Duration::from_secs(2))
                .await
                .expect_err("the one-byte RSS ceiling must terminate the worker");
            assert!(matches!(error, WorkerError::RssLimit { .. }), "{error:?}");
        }
        Err(error) => panic!("unexpected worker startup error: {error:?}"),
    }
}

#[tokio::test]
async fn subprocess_rss_watchdog_reports_real_worker_rss() {
    let limit = 64 * 1024 * 1024;
    let result =
        WorkerProcess::start_with_rss_limit(env!("CARGO_BIN_EXE_azmcp"), 256 * 1024 * 1024).await;
    let mut worker = match result {
        Ok(worker) => worker,
        Err(error @ WorkerError::RssLimit { .. }) => {
            eprintln!("synthetic worker startup RSS exceeded {limit} bytes: {error}");
            return;
        }
        Err(error) => panic!("unexpected worker startup error: {error:?}"),
    };
    let startup_rss = worker.current_rss_bytes().expect("worker RSS sample");
    eprintln!("synthetic worker startup RSS after ready: {startup_rss} bytes");
    assert!(startup_rss > 0);
    worker.terminate().await;

    let result = WorkerProcess::start_with_rss_limit(env!("CARGO_BIN_EXE_azmcp"), limit).await;
    let mut worker = match result {
        Ok(worker) => worker,
        Err(error @ WorkerError::RssLimit { .. }) => {
            eprintln!("synthetic worker startup exceeded the 64 MiB test ceiling: {error}");
            return;
        }
        Err(error) => panic!("unexpected worker startup error: {error:?}"),
    };
    let result = worker
        .execute(
            "const held=[]; while (true) held.push('x'.repeat(1024*1024));",
            Duration::from_secs(5),
        )
        .await;
    eprintln!("synthetic worker 64 MiB test result: {result:?}");
    assert!(matches!(
        result,
        Err(WorkerError::RssLimit { .. } | WorkerError::HeapLimit)
    ));
}
