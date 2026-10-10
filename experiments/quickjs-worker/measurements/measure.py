#!/usr/bin/env python3
"""Measure explicit worker executables with synthetic NDJSON traffic only.

The script uses no network, Azure CLI, credentials, or default profile directories.
Every executable is invoked with --worker and a new empty synthetic environment.
RSS is sampled with the platform ps executable; sampled peaks are lower bounds.
"""

import argparse
import collections
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import selectors
import shutil
import statistics
import subprocess
import tempfile
import threading
import time


ROW_COUNT = 20_000
HOST_CALL_COUNT = 32
HOST_REPLY_BATCH = 8
ROW_SETUP = """(() => {
  const regions = ['eastus', 'westus', 'centralus', 'eastus2'];
  globalThis.metricRowsJSON = JSON.stringify(Array.from({length: 20000}, (_, index) => ({
    resourceId: '/subscriptions/synthetic/resourceGroups/metrics/providers/Microsoft.Compute/virtualMachines/vm-' + (index % 128),
    region: regions[index % regions.length],
    timestamp: '2026-10-09T12:' + String(index % 60).padStart(2, '0') + ':00Z',
    metricName: 'Percentage CPU',
    count: 60,
    total: ((index * 37) % 1000) * 60,
    average: (index * 37) % 1000,
    maximum: ((index * 37) % 1000) + 10
  })));
  return {rows: 20000, jsonBytes: metricRowsJSON.length};
})()"""
ROW_QUERY = """(() => {
  const rows = JSON.parse(metricRowsJSON);
  const selected = rows.filter(row => row.region === 'eastus' && row.average >= 250);
  const groups = {};
  for (const row of selected) {
    const group = groups[row.resourceId] || {samples: 0, total: 0, maximum: 0};
    group.samples += row.count;
    group.total += row.total;
    group.maximum = Math.max(group.maximum, row.maximum);
    groups[row.resourceId] = group;
  }
  let samples = 0;
  let total = 0;
  let maximum = 0;
  for (const group of Object.values(groups)) {
    samples += group.samples;
    total += group.total;
    maximum = Math.max(maximum, group.maximum);
  }
  return {rows: rows.length, selectedRows: selected.length,
    groups: Object.keys(groups).length, samples, total, maximum};
})()"""
HOST_QUERY = """Promise.all(Array.from({length: 32}, (_, index) =>
  az.request({index, resourceId: 'synthetic-' + index})))"""
SERIAL_HOST_QUERY = """(async () => {
  const values = [];
  for (let index = 0; index < 32; index++) {
    values.push(await az.request({index, resourceId: 'synthetic-' + index}));
  }
  return values;
})()"""
SYNC_HOST_QUERY = """(() => {
  const values = [];
  for (let index = 0; index < 32; index++) {
    values.push(az.request({index, resourceId: 'synthetic-' + index}));
  }
  return values;
})()"""


def expected_row_result():
    selected = [index for index in range(ROW_COUNT)
                if index % 4 == 0 and (index * 37) % 1000 >= 250]
    return {
        "rows": ROW_COUNT,
        "selectedRows": len(selected),
        "groups": len({index % 128 for index in selected}),
        "samples": len(selected) * 60,
        "total": sum(((index * 37) % 1000) * 60 for index in selected),
        "maximum": max(((index * 37) % 1000) + 10 for index in selected),
    }


def stats(values):
    ordered = sorted(values)
    return {
        "samples": len(ordered),
        "median": statistics.median(ordered),
        "p95": ordered[max(0, math.ceil(len(ordered) * 0.95) - 1)],
        "minimum": ordered[0],
        "maximum": ordered[-1],
    }


class RSSSampler:
    def __init__(self, pid, interval):
        self.pid = pid
        self.interval = interval
        self.phase = "startup"
        self.observations = collections.defaultdict(list)
        self.errors = []
        self.done = threading.Event()
        self.lock = threading.Lock()
        self.ps = Path("/bin/ps") if Path("/bin/ps").exists() else Path("/usr/bin/ps")
        if not self.ps.is_file():
            raise RuntimeError("RSS measurement requires /bin/ps or /usr/bin/ps")
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def set_phase(self, phase):
        with self.lock:
            self.phase = phase

    def sample(self):
        with self.lock:
            phase = self.phase
        result = subprocess.run(
            [str(self.ps), "-o", "rss=", "-p", str(self.pid)],
            capture_output=True, text=True, timeout=2, env={"PATH": "/nonexistent"},
        )
        if result.returncode == 0 and result.stdout.strip():
            rss_bytes = int(result.stdout.strip()) * 1024
            with self.lock:
                self.observations[phase].append(rss_bytes)
            return rss_bytes
        if result.returncode not in (0, 1):
            self.errors.append(result.stderr.strip() or f"ps exited {result.returncode}")
        return None

    def run(self):
        while not self.done.is_set():
            try:
                self.sample()
            except (OSError, ValueError, subprocess.TimeoutExpired) as error:
                self.errors.append(str(error))
            self.done.wait(self.interval)

    def stop(self):
        self.done.set()
        self.thread.join(timeout=3)
        if self.errors:
            raise RuntimeError(f"RSS sampling failed: {self.errors}")

    def snapshot(self):
        with self.lock:
            return {phase: {"sampleCount": len(values), "peakBytes": max(values)}
                    for phase, values in self.observations.items() if values}


class Worker:
    def __init__(self, executable, sample_interval, timeout, sync=False):
        self.timeout = timeout
        self.disposed = False
        self.id = 0
        self.buffer = bytearray()
        self.temp = tempfile.TemporaryDirectory(prefix="azmcp-worker-measurement-")
        self.root = Path(self.temp.name)
        home = self.root / "home"
        profile = self.root / "synthetic-azure-profile"
        home.mkdir()
        profile.mkdir()
        # Do not inherit credentials or CLI configuration from the host environment.
        environment = {
            "PATH": "/nonexistent",
            "HOME": str(home),
            "AZURE_CONFIG_DIR": str(profile),
            "XDG_CONFIG_HOME": str(home),
            "TMPDIR": str(self.root),
            "LANG": "C.UTF-8",
        }
        if executable != executable.resolve() or not executable.is_file():
            raise ValueError("worker must be an existing absolute resolved executable")
        if not os.access(executable, os.X_OK):
            raise ValueError("worker must be executable")
        if not profile.is_dir() or list(profile.iterdir()) or list(home.iterdir()):
            raise RuntimeError("synthetic profile safety invariant violated before spawn")
        self.started = time.perf_counter()
        command = [str(executable), "--worker"]
        if sync:
            command.append("--sync")
        self.process = subprocess.Popen(
            command, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=self.root, env=environment, bufsize=0,
        )
        self.sampler = RSSSampler(self.process.pid, sample_interval)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.stderr = bytearray()
        self.stderr_thread = threading.Thread(target=self.read_stderr, daemon=True)
        self.stderr_thread.start()
        try:
            ready = self.receive()
            self.startup_ms = (time.perf_counter() - self.started) * 1000
            if ready != {"type": "ready", "protocol": 1}:
                raise RuntimeError(f"invalid ready frame: {ready}")
            self.ready_rss = self.sampler.sample()
            if self.ready_rss is None:
                raise RuntimeError("worker RSS unavailable after ready")
        except BaseException:
            self.dispose()
            raise

    def read_stderr(self):
        while True:
            chunk = self.process.stderr.read(4096)
            if not chunk:
                return
            self.stderr.extend(chunk)

    def send(self, frame):
        data = json.dumps(frame, separators=(",", ":")).encode() + b"\n"
        if len(data) > 512 * 1024:
            raise RuntimeError("synthetic request exceeds worker input frame cap")
        self.process.stdin.write(data)
        self.process.stdin.flush()

    def receive(self):
        deadline = time.monotonic() + self.timeout
        while True:
            newline = self.buffer.find(b"\n")
            if newline >= 0:
                line = bytes(self.buffer[:newline])
                del self.buffer[:newline + 1]
                return json.loads(line)
            if len(self.buffer) > 1024 * 1024:
                raise RuntimeError("worker response exceeds output frame cap")
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self.selector.select(remaining):
                raise TimeoutError("worker protocol deadline exceeded")
            chunk = os.read(self.process.stdout.fileno(), 65536)
            if not chunk:
                raise RuntimeError(f"worker closed stdout: {self.stderr.decode(errors='replace')}")
            self.buffer.extend(chunk)

    def execute(self, code, expected, host_calls=False, serial=False):
        self.id += 1
        pending = []
        calls_seen = set()
        started = time.perf_counter()
        self.send({"type": "execute", "id": self.id, "code": code,
                   "timeout_ms": int(self.timeout * 1000)})
        while True:
            frame = self.receive()
            if frame.get("id") != self.id:
                raise RuntimeError(f"unexpected execution id: {frame}")
            if frame.get("type") == "host_call":
                index = frame.get("arguments", {}).get("index")
                if not host_calls or frame.get("method") != "az.request":
                    raise RuntimeError(f"unexpected synthetic host call: {frame}")
                if frame["arguments"] != {"index": index, "resourceId": f"synthetic-{index}"}:
                    raise RuntimeError(f"unexpected synthetic host arguments: {frame}")
                if index in calls_seen or index not in range(HOST_CALL_COUNT):
                    raise RuntimeError(f"invalid or duplicate host call index: {index}")
                calls_seen.add(index)
                pending.append(frame)
                if len(pending) == (1 if serial else HOST_REPLY_BATCH):
                    # Reverse each batch so Promise.all must preserve input order.
                    for request in reversed(pending):
                        self.send({"type": "host_call_result", "id": request["id"],
                                   "call_id": request["call_id"], "ok": True,
                                   "value": request["arguments"]})
                    pending.clear()
                continue
            elapsed_ms = (time.perf_counter() - started) * 1000
            if frame.get("type") != "result" or frame.get("value") != expected:
                raise RuntimeError(f"incorrect worker result: {frame}; expected {expected}")
            if frame.get("logs") != [] or frame.get("logs_omitted") != 0:
                raise RuntimeError(f"unexpected worker logs: {frame}")
            if host_calls and (len(calls_seen) != HOST_CALL_COUNT or pending):
                raise RuntimeError("synthetic host call count was incomplete")
            return elapsed_ms

    def close(self):
        self.id += 1
        self.send({"type": "close", "id": self.id})
        frame = self.receive()
        if frame != {"type": "closed", "id": self.id}:
            raise RuntimeError(f"incorrect close response: {frame}")
        self.process.stdin.close()
        if self.process.wait(timeout=5) != 0:
            raise RuntimeError(f"worker close failed: {self.stderr.decode(errors='replace')}")
        self.dispose()

    def dispose(self):
        if self.disposed:
            return
        self.disposed = True
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=5)
        try:
            self.sampler.stop()
        finally:
            self.selector.close()
            self.stderr_thread.join(timeout=3)
            for pipe in (self.process.stdin, self.process.stdout, self.process.stderr):
                if not pipe.closed:
                    pipe.close()
            self.temp.cleanup()


def binary_metadata(executable):
    digest = hashlib.sha256()
    with executable.open("rb") as binary:
        while chunk := binary.read(1024 * 1024):
            digest.update(chunk)
    stat = executable.stat()
    return {
        "path": str(executable), "bytes": stat.st_size, "sha256": digest.hexdigest(),
        "modifiedUTC": datetime.datetime.fromtimestamp(
            stat.st_mtime, datetime.timezone.utc).isoformat(),
    }


def measure(executable, arguments, sync=False):
    result = {"binary": binary_metadata(executable), "startupRuns": []}
    result["hostAPIMode"] = "synchronous" if sync else "asynchronous"
    for _ in range(arguments.samples):
        worker = Worker(executable, arguments.rss_interval_ms / 1000, arguments.timeout, sync)
        try:
            worker.sampler.set_phase("idle")
            result["startupRuns"].append({
                "readyMs": worker.startup_ms, "readyRSSBytes": worker.ready_rss,
                "rss": worker.sampler.snapshot(),
            })
            worker.close()
        finally:
            worker.dispose()
    result["startupReadyMs"] = stats([run["readyMs"] for run in result["startupRuns"]])
    result["startupReadyRSSBytes"] = stats(
        [run["readyRSSBytes"] for run in result["startupRuns"]])
    result["startupSampledPeakRSSBytes"] = stats(
        [run["rss"]["startup"]["peakBytes"] for run in result["startupRuns"]])
    worker = Worker(executable, arguments.rss_interval_ms / 1000, arguments.timeout, sync)
    try:
        worker.sampler.set_phase("setup")
        # Setup constructs ASCII JSON locally; the timed query only parses and aggregates.
        worker.id += 1
        worker.send({"type": "execute", "id": worker.id, "code": ROW_SETUP,
                     "timeout_ms": int(arguments.timeout * 1000)})
        setup = worker.receive()
        if setup.get("type") != "result" or setup.get("value", {}).get("rows") != ROW_COUNT:
            raise RuntimeError(f"synthetic setup failed: {setup}")
        if setup.get("id") != worker.id:
            raise RuntimeError(f"synthetic setup response id mismatch: {setup}")
        result["rowJSONBytes"] = setup["value"]["jsonBytes"]
        worker.sampler.sample()
        worker.sampler.set_phase("warmup")
        expected = expected_row_result()
        host_expected = [{"index": index, "resourceId": f"synthetic-{index}"}
                         for index in range(HOST_CALL_COUNT)]
        serial_query = SYNC_HOST_QUERY if sync else SERIAL_HOST_QUERY
        for _ in range(arguments.warmups):
            worker.execute(ROW_QUERY, expected)
            worker.execute(serial_query, host_expected, host_calls=True, serial=True)
            if not sync:
                worker.execute(HOST_QUERY, host_expected, host_calls=True)
        worker.sampler.set_phase("json_filter_aggregate")
        row_times = [worker.execute(ROW_QUERY, expected) for _ in range(arguments.samples)]
        worker.sampler.sample()
        worker.sampler.set_phase("host_serial")
        serial_times = [worker.execute(serial_query, host_expected, host_calls=True, serial=True)
                        for _ in range(arguments.samples)]
        worker.sampler.sample()
        result["jsonFilterAggregateMs"] = stats(row_times)
        result["jsonFilterAggregateRawMs"] = row_times
        result["hostSerialMs"] = stats(serial_times)
        result["hostSerialRawMs"] = serial_times
        if not sync:
            worker.sampler.set_phase("host_promise_all")
            host_times = [worker.execute(HOST_QUERY, host_expected, host_calls=True)
                          for _ in range(arguments.samples)]
            worker.sampler.sample()
            result["hostPromiseAllMs"] = stats(host_times)
            result["hostPromiseAllRawMs"] = host_times
        result["workloadRSS"] = worker.sampler.snapshot()
        result["verifiedRowResult"] = expected
        result["verifiedHostCallCountPerTurn"] = HOST_CALL_COUNT
        worker.close()
    finally:
        worker.dispose()
    if binary_metadata(executable)["sha256"] != result["binary"]["sha256"]:
        raise RuntimeError("worker executable changed during measurement; freeze a copy before retrying")
    return result


def tool_version(name, arguments):
    executable = shutil.which(name)
    if executable is None:
        return None
    result = subprocess.run([executable, *arguments], capture_output=True, text=True, timeout=10)
    return (result.stdout or result.stderr).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", action="append", required=True, metavar="LABEL=PATH")
    parser.add_argument("--sync-worker", action="append", default=[], metavar="LABEL",
                        help="Append --sync for this label and benchmark direct serial host calls")
    parser.add_argument("--dependency", action="append", default=[], metavar="LABEL=REVISION",
                        help="Pinned JavaScript runtime dependency/revision for this binary")
    parser.add_argument("--samples", type=int, default=20)
    parser.add_argument("--warmups", type=int, default=3)
    parser.add_argument("--rss-interval-ms", type=float, default=10)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--build-mode", required=True,
                        help="Describe how the supplied binaries were built")
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.samples < 2 or arguments.warmups < 0 or arguments.rss_interval_ms <= 0:
        parser.error("samples >= 2, warmups >= 0, and rss interval > 0 are required")
    workers = {}
    for value in arguments.worker:
        label, separator, path = value.partition("=")
        if not separator or not label or label in workers:
            parser.error("--worker requires unique LABEL=PATH entries")
        workers[label] = Path(path).expanduser().resolve(strict=True)
    if not set(arguments.sync_worker).issubset(workers):
        parser.error("--sync-worker labels must identify supplied workers")
    dependencies = {}
    for value in arguments.dependency:
        label, separator, revision = value.partition("=")
        if not separator or label not in workers or not revision or label in dependencies:
            parser.error("--dependency requires unique supplied worker LABEL=REVISION")
        dependencies[label] = revision
    metadata = {
        "observedUTC": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "platform": platform.platform(), "machine": platform.machine(),
        "python": platform.python_version(), "rust": tool_version("rustc", ["--version"]),
        "go": tool_version("go", ["version"]), "buildMode": arguments.build_mode,
        "startupSamples": arguments.samples, "workloadSamples": arguments.samples,
        "workloadWarmups": arguments.warmups, "rssRequestedIntervalMs": arguments.rss_interval_ms,
        "rssMethod": "ps -o rss= -p WORKER_PID (KiB converted to bytes)",
        "rssLimitation": "Sampled peaks are lower bounds; process scheduling and ps add overhead. "
                         "The ready RSS snapshot is included in startup sampled peak.",
        "timingScope": "Startup includes process spawn through ready NDJSON receipt. "
                       "Workload includes request and result NDJSON IPC; setup is excluded. "
                       "Host Promise.all has 32 synthetic calls replied to in reversed batches of 8. "
                       "Serial host mode has 32 calls with one reply immediately per call.",
        "safety": "Only explicit --worker commands; fresh empty HOME/profile, no inherited Azure "
                  "credentials, PATH=/nonexistent, no network or Azure CLI calls.",
        "workloads": {"rows": ROW_COUNT, "rowSetupJS": ROW_SETUP, "rowQueryJS": ROW_QUERY,
                      "hostQueryJS": HOST_QUERY, "serialHostQueryJS": SERIAL_HOST_QUERY,
                      "syncHostQueryJS": SYNC_HOST_QUERY},
    }
    report = {"metadata": metadata, "workers": {}}
    initial_hashes = {path: binary_metadata(path)["sha256"] for path in set(workers.values())}
    for label, executable in workers.items():
        print(f"Measuring {label}: {executable}", flush=True)
        report["workers"][label] = measure(executable, arguments, label in arguments.sync_worker)
        if report["workers"][label]["binary"]["sha256"] != initial_hashes[executable]:
            raise RuntimeError("worker executable changed between modes; freeze a copy before retrying")
        report["workers"][label]["pinnedDependency"] = dependencies.get(label)
        keys = ("startupReadyMs", "startupReadyRSSBytes", "jsonFilterAggregateMs",
                "hostSerialMs", "hostPromiseAllMs")
        print(json.dumps({label: {key: report["workers"][label][key] for key in keys
                                 if key in report["workers"][label]}},
            indent=2), flush=True)
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
