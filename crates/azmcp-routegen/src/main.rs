//! Deterministic CI checker for the reviewed route/schema source manifest.

use std::{env, fs, path::PathBuf, process};

use azmcp_core::route_manifest;

const DEFAULT_MANIFEST: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../",
    "fixtures/reviewed-routes/v1-observability-1.json"
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operation {
    Check,
    Write,
}

fn main() -> Result<(), String> {
    let (operation, manifest_path) = parse_args()?;
    let bytes = fs::read(&manifest_path)
        .map_err(|error| format!("read {}: {error}", manifest_path.display()))?;
    let manifest = route_manifest::parse_manifest(&bytes).map_err(|error| error.to_string())?;
    let canonical =
        route_manifest::canonical_manifest_bytes(&manifest).map_err(|error| error.to_string())?;

    match operation {
        Operation::Check => {
            if bytes != canonical {
                return Err(format!(
                    "{} is not canonical; run azmcp-routegen --write --manifest {}",
                    manifest_path.display(),
                    manifest_path.display()
                ));
            }
        }
        Operation::Write => fs::write(&manifest_path, canonical)
            .map_err(|error| format!("write {}: {error}", manifest_path.display()))?,
    }

    println!(
        "validated {} routes and {} schemas for {}",
        route_manifest::route_count(&manifest),
        route_manifest::schema_count(&manifest),
        route_manifest::policy_version(&manifest)
    );
    Ok(())
}

fn parse_args() -> Result<(Operation, PathBuf), String> {
    let mut operation = Operation::Check;
    let mut manifest_path = PathBuf::from(DEFAULT_MANIFEST);
    let mut args = env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--check" => operation = Operation::Check,
            "--write" => operation = Operation::Write,
            "--manifest" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--manifest requires a path".to_owned())?;
                manifest_path = PathBuf::from(value);
            }
            "--help" | "-h" => {
                println!(
                    "usage: azmcp-routegen [--check|--write] [--manifest PATH]\n\n\
                     --check   validate exact canonical bytes (the default)\n\
                     --write   rewrite PATH with deterministic canonical JSON\n\
                     --manifest PATH  source fixture (defaults to the checked-in v1 fixture)"
                );
                process::exit(0);
            }
            other => return Err(format!("unknown argument `{other}`; use --help")),
        }
    }
    Ok((operation, manifest_path))
}
