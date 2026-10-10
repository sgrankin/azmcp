# Worker measurements

`measure.py` compares explicit worker binaries using the same tagged NDJSON protocol.
It invokes only `--worker`, with a fresh empty home and synthetic Azure profile.
The child inherits no host environment, and its `PATH` is `/nonexistent`.
All host results are synthetic pipe replies.
No network, Azure CLI, or ambient credentials are used.

Build each executable first, and freeze a copy if builds will continue concurrently.
The script fails if a worker executable changes during its measurement.
For an asynchronous comparison:

```sh
python3 experiments/quickjs-worker/measurements/measure.py \
  --worker v8=target/release/azmcp \
  --worker quickjs=target/quickjs-worker/azmcp-quickjs-worker \
  --dependency 'v8=deno_core 0.410.0; v8 150.4.0' \
  --dependency 'quickjs=modernc.org/quickjs v0.25.0; modernc.org/libquickjs v0.13.1' \
  --build-mode 'Rust cargo build --release; Go CGO_ENABLED=0 go build with defaults' \
  --output "$HOME/Code/fulcrum-planning/azmcp-quickjs-worker-results.json"
```

If a worker implements `--sync`, add another label for its executable and
`--sync-worker LABEL`.
The serial host workload then uses direct calls.
The script omits `Promise.all` for that mode because synchronous calls cannot overlap.

The default run uses 20 startup processes and 20 measured turns per workload,
after three warmup turns in one persistent worker.
Startup timing includes process spawn through the ready frame.
The JSON workload parses 20,000 synthetic metric rows, filters by region and value,
groups by resource ID, and returns a small verified aggregate.
Setup generates a 5,035,259-byte ASCII JSON string outside the measured query.
The host workloads each make 32 calls.
Serial calls get an immediate reply.
`Promise.all` replies are reversed in batches of eight to exercise call demultiplexing.
Each aggregate and host result is checked independently by Python.

Timing includes pipe IPC and Python frame handling.
It measures the worker and embedding together, without a production parent or HTTP requests.
Synthetic host replies have no deliberate network delay, so these timings measure local
bridge overhead and do not estimate the benefit of overlapping remote Azure requests.

RSS observations use `ps -o rss= -p PID`, converting KiB to bytes.
The requested sampling interval is 10 ms, plus `ps` execution time.
The startup observations include an RSS snapshot immediately after ready.
Sampled peaks are lower bounds, and each workload reports its actual observation count.
Persistent worker RSS includes retained runtime allocations and earlier phases.
The background sampler adds overhead to both workers.
On restricted macOS sandboxes, process observation requires the normal escalated execution
flow; do not replace the measurement with guessed RSS values.

The JSON report includes raw turn timings, median and nearest-rank p95, observed RSS,
binary size and SHA-256, binary modification time, platform and toolchains,
dependency revisions supplied on the command line, and the exact JavaScript payloads.
Use a project planning directory for the durable result report rather than checking in
machine-specific benchmark output.
