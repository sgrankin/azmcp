#!/usr/bin/env python3
"""Copy the reviewed worker helpers with experimental runtime hook substitutions."""

import argparse
from pathlib import Path


def bootstraps():
    root = Path(__file__).resolve().parents[2]
    source = (root / "crates/azmcp/src/worker.rs").read_text()
    bootstrap = source.split('const WORKER_BOOTSTRAP: &str = r#"\n', 1)[1].split('\n"#;', 1)[0]
    bootstrap = bootstrap.replace(
        "  const op = Deno.core.ops.op_worker_console;",
        "  const op = globalThis.__azmcpConsole;\n  delete globalThis.__azmcpConsole;",
    ).replace(
        "  const hostCall = Deno.core.ops.op_worker_host_call;",
        "  const hostCall = globalThis.__azmcpHostCall;\n  delete globalThis.__azmcpHostCall;",
    )
    synchronous = bootstrap.replace("  const asyncIteratorSymbol = Symbol.asyncIterator;\n", "")
    synchronous = synchronous.replace("writeJsonStream = async (", "writeJsonStream = (")
    synchronous = synchronous.replace("const append = async () =>", "const append = () =>")
    synchronous = synchronous.replace(
        '(typeof values[asyncIteratorSymbol] === "function"\n'
        '        || typeof values[iteratorSymbol] === "function")',
        'typeof values[iteratorSymbol] === "function"',
    )
    synchronous = synchronous.replace("an iterable or async iterable", "a synchronous iterable")
    synchronous = synchronous.replace("for await (", "for (").replace("await ", "")
    return {"bootstrap.js": bootstrap + "\n", "bootstrap_sync.js": synchronous + "\n"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    directory = Path(__file__).resolve().parent
    for name, content in bootstraps().items():
        path = directory / name
        if args.check:
            if not path.exists() or path.read_text() != content:
                raise SystemExit(f"{name} differs from the Rust worker; run {Path(__file__).name}")
        else:
            path.write_text(content)


if __name__ == "__main__":
    main()
