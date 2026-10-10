# Go QuickJS worker experiment

This standalone worker speaks protocol v1 to the existing Rust `WorkerProcess`.
It embeds `modernc.org/quickjs v0.25.0` and builds with `CGO_ENABLED=0`.
The module requires Go 1.26 or later.
The Rust parent continues to own capabilities, credentials, HTTP policy, references,
artifact transactions, cancellation, and the worker RSS watchdog.

Two script surfaces are implemented:

- `--worker` preserves persistent bindings, awaited host calls, concurrent promises,
  automatic final promise resolution, and async iterable artifact writers.
- `--worker --sync` returns ordinary values from blocking host calls.
  It evaluates a plain script and supports artifact writers over ordinary iterables.
  It rejects a final promise and provides no top-level await fallback or job pumping.

Async JavaScript syntax and Promise builtins still exist in the synchronous VM.
Promise reactions remain queued even when the script returns an ordinary value;
scripts using that mode must keep their control flow synchronous.

For example, the synchronous surface permits this script fragment:

```js
const result = az.logs.query(queryArgs);
result.tables[0].rows.length
```

The wait happens inside the host call.
JavaScript receives actual objects, arrays, numbers, and null values, so operators and
type checks retain their normal behavior.
Calls are sequential in this mode.
A future synchronous API would need an explicit batch operation where overlapping
independent requests matters.
Lazy proxy unwrapping would change identity and type-check behavior;
general async transparency would require a source transform or a language interpreter.

## Build and verify

Run from the repository root:

```sh
python3 experiments/quickjs-worker/sync-bootstrap.py --check
CGO_ENABLED=0 go -C experiments/quickjs-worker test ./...
go -C experiments/quickjs-worker vet ./...
CGO_ENABLED=0 go -C experiments/quickjs-worker build \
  -o ../../target/quickjs-worker/azmcp-quickjs-worker .
AZMCP_QUICKJS_WORKER="$PWD/target/quickjs-worker/azmcp-quickjs-worker" \
  cargo test -p azmcp --test quickjs_worker -- --ignored
```

The explicitly invoked Rust tests exercise the Go executable through the real parent
using in-memory host replies.
Their ignore annotations require an explicitly built experimental executable;
missing configuration fails immediately when they are selected.
Go tests also exercise the synchronous surface and its host-wait and serialization deadlines.
All test traffic is synthetic.

`sync-bootstrap.py` copies the reviewed Rust JavaScript helpers with host-hook substitutions.
It also generates the synchronous helper snapshot by replacing asynchronous iteration and calls.
Run it without `--check` after intentionally updating the reviewed helpers.
The Go runtime embeds the resulting files and never loads a filesystem module or standard-library
OS helpers into the caller's JavaScript environment.

## Compatibility limits

The verified result boundary covers JSON-native data.
The experiment uses `JSON.stringify` to cross the host and result boundaries.
The existing `serde_v8` conversion differs for custom `toJSON`, Date, Map, typed arrays,
and function values.
For example, `new Date(0)` returns an ISO string here and an empty object in V8.
Choosing the public conversion contract is required before replacing the runtime.

The parent recomputes reference-candidate sizes using its locked Rust JSON formatter.
The worker normalizes number spellings and Unicode to that wire representation.
Rust regression tests cover decimal notation thresholds, finite-number extremes,
surrogate replacement, and large candidates.
Changing the parent's JSON dependencies requires rechecking this formatter coupling.

QuickJS denies allocations above its configured 64 MiB budget, but an allocation exception
can be caught by caller JavaScript.
The library exposes no sticky indication that the budget was crossed.
Uncaught resource errors terminate this worker, including failures during serialization;
the native exception name and message can also be imitated by caller code.
Strict termination after every attempted heap-limit violation needs additional engine support.
The Rust parent's process RSS limit and hard cancellation remain authoritative.

## Measurements

See [the measurement harness](measurements/README.md) for reproducible commands and limits.
The comparison uses synthetic metric rows and pipe replies, with no Azure traffic.
Startup, RSS, executable size, and JavaScript processing time measure different costs;
the slower interpreter should be evaluated against the actual volume of script-side data processing.
