//! Deterministic CI checker for the reviewed route/schema source manifest.

use std::{env, fs, path::PathBuf, process};

use azmcp_core::{route_manifest, upstream_catalog};

const DEFAULT_MANIFEST: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../",
    "fixtures/reviewed-routes/v1-observability-1.json"
);
const DEFAULT_UPSTREAM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../",
    "fixtures/upstream/azure-rest-operations-v1.json"
);
const DEFAULT_REVIEW: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../",
    "fixtures/upstream/azure-rest-review-v1.json"
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operation {
    Check,
    Write,
}

fn main() -> Result<(), String> {
    let args = parse_args()?;
    let manifest_path = args.manifest_path;
    let bytes = fs::read(&manifest_path)
        .map_err(|error| format!("read {}: {error}", manifest_path.display()))?;
    let manifest = if args.import_upstream {
        route_manifest::parse_manifest_for_generation(&bytes)
    } else {
        route_manifest::parse_manifest(&bytes)
    }
    .map_err(|error| error.to_string())?;
    let generated = if args.import_upstream {
        let upstream_bytes = fs::read(&args.upstream_path)
            .map_err(|error| format!("read {}: {error}", args.upstream_path.display()))?;
        let review_bytes = fs::read(&args.review_path)
            .map_err(|error| format!("read {}: {error}", args.review_path.display()))?;
        let catalog =
            upstream_catalog::parse_catalog(&upstream_bytes).map_err(|error| error.to_string())?;
        let review =
            upstream_catalog::parse_review(&review_bytes).map_err(|error| error.to_string())?;
        upstream_catalog::regenerate_manifest(&manifest, &catalog, &review)
            .map_err(|error| error.to_string())?
    } else {
        manifest
    };
    let canonical =
        route_manifest::canonical_manifest_bytes(&generated).map_err(|error| error.to_string())?;

    match args.operation {
        Operation::Check => {
            if bytes != canonical {
                let reason = if args.import_upstream {
                    "not current with the pinned route inputs"
                } else {
                    "not canonical"
                };
                return Err(format!(
                    "{} is {reason}; run azmcp-routegen --write --manifest {}",
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
        route_manifest::route_count(&generated),
        route_manifest::schema_count(&generated),
        route_manifest::policy_version(&generated)
    );
    Ok(())
}

struct Arguments {
    operation: Operation,
    manifest_path: PathBuf,
    upstream_path: PathBuf,
    review_path: PathBuf,
    import_upstream: bool,
}

fn parse_args() -> Result<Arguments, String> {
    let mut operation = Operation::Check;
    let mut manifest_path = PathBuf::from(DEFAULT_MANIFEST);
    let mut upstream_path = PathBuf::from(DEFAULT_UPSTREAM);
    let mut review_path = PathBuf::from(DEFAULT_REVIEW);
    let mut upstream_explicit = false;
    let mut review_explicit = false;
    let mut canonical_only = false;
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
            "--upstream" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--upstream requires a path".to_owned())?;
                upstream_path = PathBuf::from(value);
                upstream_explicit = true;
            }
            "--review" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--review requires a path".to_owned())?;
                review_path = PathBuf::from(value);
                review_explicit = true;
            }
            "--canonical-only" => {
                canonical_only = true;
            }
            "--help" | "-h" => {
                println!(
                    "usage: azmcp-routegen [--check|--write] [options]\n\n\
                     --check   validate exact canonical bytes (the default)\n\
                     --write   rewrite PATH with deterministic canonical JSON\n\
                     --manifest PATH  generated fixture (defaults to the checked-in v1 fixture)\n\
                     --upstream PATH  pinned upstream export (enables import; pair with --review)\n\
                     --review PATH    explicit review join (required with --upstream)\n\
                     --canonical-only skip upstream regeneration for a focused manifest check"
                );
                process::exit(0);
            }
            other => return Err(format!("unknown argument `{other}`; use --help")),
        }
    }
    if upstream_explicit != review_explicit {
        return Err("--upstream and --review must be supplied together".to_owned());
    }
    let import_upstream = !canonical_only && upstream_explicit;
    Ok(Arguments {
        operation,
        manifest_path,
        upstream_path,
        review_path,
        import_upstream,
    })
}
