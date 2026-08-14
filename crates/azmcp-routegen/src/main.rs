//! Deterministic CI checker for the reviewed route/schema source manifest.

use std::{env, fs, path::PathBuf, process};

use azmcp_core::{route_manifest, upstream_catalog};

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
    let args = parse_args()?;
    let manifest_path = args.manifest_path;
    let generated = if args.import_upstream {
        let seed_path = args.seed_path.as_ref().expect("import requires seed");
        if seed_path == &manifest_path {
            return Err("--seed and --manifest must name different files".to_owned());
        }
        let seed_bytes = fs::read(seed_path)
            .map_err(|error| format!("read {}: {error}", seed_path.display()))?;
        let seed = route_manifest::parse_manifest_for_generation(&seed_bytes)
            .map_err(|error| error.to_string())?;
        let upstream_path = args
            .upstream_path
            .as_ref()
            .expect("import requires upstream");
        let review_path = args.review_path.as_ref().expect("import requires review");
        let upstream_bytes = fs::read(upstream_path)
            .map_err(|error| format!("read {}: {error}", upstream_path.display()))?;
        let review_bytes = fs::read(review_path)
            .map_err(|error| format!("read {}: {error}", review_path.display()))?;
        let catalog =
            upstream_catalog::parse_catalog(&upstream_bytes).map_err(|error| error.to_string())?;
        let review =
            upstream_catalog::parse_review(&review_bytes).map_err(|error| error.to_string())?;
        upstream_catalog::generate_manifest(&seed, &catalog, &review)
            .map_err(|error| error.to_string())?
    } else {
        let bytes = fs::read(&manifest_path)
            .map_err(|error| format!("read {}: {error}", manifest_path.display()))?;
        route_manifest::parse_manifest(&bytes).map_err(|error| error.to_string())?
    };
    let canonical =
        route_manifest::canonical_manifest_bytes(&generated).map_err(|error| error.to_string())?;

    match args.operation {
        Operation::Check => {
            let bytes = fs::read(&manifest_path)
                .map_err(|error| format!("read {}: {error}", manifest_path.display()))?;
            if args.import_upstream {
                route_manifest::parse_manifest_for_generation(&bytes)
                    .map_err(|error| error.to_string())?;
            }
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
    seed_path: Option<PathBuf>,
    upstream_path: Option<PathBuf>,
    review_path: Option<PathBuf>,
    import_upstream: bool,
}

fn parse_args() -> Result<Arguments, String> {
    let mut operation = Operation::Check;
    let mut manifest_path = PathBuf::from(DEFAULT_MANIFEST);
    let mut seed_path = None;
    let mut upstream_path = None;
    let mut review_path = None;
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
                upstream_path = Some(PathBuf::from(value));
            }
            "--review" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--review requires a path".to_owned())?;
                review_path = Some(PathBuf::from(value));
            }
            "--seed" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--seed requires a path".to_owned())?;
                seed_path = Some(PathBuf::from(value));
            }
            "--help" | "-h" => {
                println!(
                    "usage: azmcp-routegen [--check|--write] [options]\n\n\
                     --check   validate exact canonical bytes (the default)\n\
                     --write   rewrite PATH with deterministic canonical JSON\n\
                     --manifest PATH  generated output (defaults to the checked-in v1 fixture)\n\
                     --seed PATH      immutable reviewed seed (required for import)\n\
                     --upstream PATH  pinned upstream export (required for import)\n\
                     --review PATH    explicit review join (required for import)"
                );
                process::exit(0);
            }
            other => return Err(format!("unknown argument `{other}`; use --help")),
        }
    }
    let any_import_input = seed_path.is_some() || upstream_path.is_some() || review_path.is_some();
    if any_import_input && (seed_path.is_none() || upstream_path.is_none() || review_path.is_none())
    {
        return Err("--seed, --upstream, and --review must be supplied together".to_owned());
    }
    let import_upstream = any_import_input;
    Ok(Arguments {
        operation,
        manifest_path,
        seed_path,
        upstream_path,
        review_path,
        import_upstream,
    })
}
