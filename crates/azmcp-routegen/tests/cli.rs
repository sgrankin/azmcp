use std::{fs, process::Command};

#[test]
fn check_rejects_stale_bytes_without_rewriting_them() {
    let directory = tempfile::tempdir().expect("temporary fixture directory");
    let path = directory.path().join("reviewed-routes.json");
    let mut stale = azmcp_core::route_manifest::checked_in_manifest_bytes().to_vec();
    stale.push(b' ');
    fs::write(&path, &stale).expect("write stale fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_azmcp-routegen"))
        .args(["--check", "--manifest"])
        .arg(&path)
        .output()
        .expect("run checker");

    assert!(!output.status.success());
    assert_eq!(fs::read(&path).expect("read stale fixture"), stale);
    assert!(String::from_utf8_lossy(&output.stderr).contains("not canonical"));
}

#[test]
fn import_requires_a_separate_seed_path() {
    let output = Command::new(env!("CARGO_BIN_EXE_azmcp-routegen"))
        .args([
            "--check",
            "--upstream",
            "catalog.json",
            "--review",
            "review.json",
        ])
        .output()
        .expect("run checker");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--seed"));
}

#[test]
fn explicit_upstream_import_is_deterministic_and_review_gated() {
    let directory = tempfile::tempdir().expect("temporary fixture directory");
    let seed = directory.path().join("seed-routes.json");
    let path = directory.path().join("generated-routes.json");
    fs::write(
        &seed,
        azmcp_core::route_manifest::checked_in_manifest_bytes(),
    )
    .expect("write seed fixture");

    let write = Command::new(env!("CARGO_BIN_EXE_azmcp-routegen"))
        .args(["--write", "--manifest"])
        .arg(&path)
        .args(["--seed"])
        .arg(&seed)
        .args([
            "--upstream",
            "../../fixtures/upstream/azure-rest-operations-v1.json",
            "--review",
            "../../fixtures/upstream/azure-rest-review-v1.json",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run importer");
    assert!(
        write.status.success(),
        "{}",
        String::from_utf8_lossy(&write.stderr)
    );

    let generated: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("read generated fixture"))
            .expect("generated JSON");
    assert_eq!(generated["routes"].as_array().expect("routes").len(), 18);
    assert_eq!(generated["schemas"].as_array().expect("schemas").len(), 12);
    assert!(
        generated["schemas"]
            .as_array()
            .expect("schemas")
            .iter()
            .any(|schema| schema["entryId"] == "AzureCloud.storageAccounts.get")
    );
    assert!(
        !generated["schemas"]
            .as_array()
            .expect("schemas")
            .iter()
            .any(|schema| schema["operation"] == "list")
    );

    let check = Command::new(env!("CARGO_BIN_EXE_azmcp-routegen"))
        .args(["--check", "--manifest"])
        .arg(&path)
        .args(["--seed"])
        .arg(&seed)
        .args([
            "--upstream",
            "../../fixtures/upstream/azure-rest-operations-v1.json",
            "--review",
            "../../fixtures/upstream/azure-rest-review-v1.json",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("check generated fixture");
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn explicit_upstream_check_rejects_stale_generated_bytes() {
    let directory = tempfile::tempdir().expect("temporary fixture directory");
    let seed = directory.path().join("seed-routes.json");
    let path = directory.path().join("generated-routes.json");
    fs::write(
        &seed,
        azmcp_core::route_manifest::checked_in_manifest_bytes(),
    )
    .expect("write seed fixture");
    let write = Command::new(env!("CARGO_BIN_EXE_azmcp-routegen"))
        .args(["--write", "--manifest"])
        .arg(&path)
        .args(["--seed"])
        .arg(&seed)
        .args([
            "--upstream",
            "../../fixtures/upstream/azure-rest-operations-v1.json",
            "--review",
            "../../fixtures/upstream/azure-rest-review-v1.json",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .expect("run importer");
    assert!(write.success());
    let mut stale = fs::read(&path).expect("read generated fixture");
    stale.push(b' ');
    fs::write(&path, &stale).expect("write stale fixture");

    let check = Command::new(env!("CARGO_BIN_EXE_azmcp-routegen"))
        .args(["--check", "--manifest"])
        .arg(&path)
        .args(["--seed"])
        .arg(&seed)
        .args([
            "--upstream",
            "../../fixtures/upstream/azure-rest-operations-v1.json",
            "--review",
            "../../fixtures/upstream/azure-rest-review-v1.json",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("check stale fixture");
    assert!(!check.status.success());
    assert_eq!(fs::read(&path).expect("read stale fixture"), stale);
}

#[test]
fn imported_check_rejects_an_injected_unreviewed_row() {
    let directory = tempfile::tempdir().expect("temporary fixture directory");
    let seed = directory.path().join("seed-routes.json");
    let path = directory.path().join("generated-routes.json");
    fs::write(
        &seed,
        azmcp_core::route_manifest::checked_in_manifest_bytes(),
    )
    .expect("write seed fixture");

    let write = Command::new(env!("CARGO_BIN_EXE_azmcp-routegen"))
        .args(["--write", "--manifest"])
        .arg(&path)
        .args(["--seed"])
        .arg(&seed)
        .args([
            "--upstream",
            "../../fixtures/upstream/azure-rest-operations-v1.json",
            "--review",
            "../../fixtures/upstream/azure-rest-review-v1.json",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .expect("run importer");
    assert!(write.success());

    let mut generated: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("read generated fixture"))
            .expect("generated JSON");
    generated["routes"]
        .as_array_mut()
        .expect("routes")
        .push(serde_json::json!({
            "cloud": "AzureCloud",
            "purpose": "request",
            "method": "GET",
            "pathTemplate": "/subscriptions/{subscription}/providers/Unreviewed",
            "apiVersions": ["2024-01-01"],
            "rbacAction": "Unreviewed/read",
            "armTier": "inspect",
            "allowedQueryParameters": []
        }));
    fs::write(
        &path,
        serde_json::to_vec_pretty(&generated).expect("serialize injected output"),
    )
    .expect("write injected output");

    let check = Command::new(env!("CARGO_BIN_EXE_azmcp-routegen"))
        .args(["--check", "--manifest"])
        .arg(&path)
        .args(["--seed"])
        .arg(&seed)
        .args([
            "--upstream",
            "../../fixtures/upstream/azure-rest-operations-v1.json",
            "--review",
            "../../fixtures/upstream/azure-rest-review-v1.json",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("check injected output");
    assert!(!check.status.success());
}
