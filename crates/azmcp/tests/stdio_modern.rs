#![cfg(unix)]

use std::{
    fs,
    io::Write as _,
    process::{Command, Stdio},
};

use serde_json::{Value, json};

fn metadata() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "azmcp-test", "version": "0.1.0"},
        "io.modelcontextprotocol/clientCapabilities": {}
    })
}

#[test]
fn built_server_starts_without_azure_cli_for_offline_tools() {
    let directory = tempfile::tempdir().expect("tempdir");
    let config = directory.path().join(".config/azmcp/config.toml");
    let profile = directory.path().join(".azure/azureProfile.json");
    let audit = directory.path().join(".local/state/azmcp/requests.jsonl");
    let artifacts = directory.path().join(".local/share/azmcp/artifacts");
    let missing_az = directory.path().join("missing-az");
    fs::create_dir_all(config.parent().expect("config parent")).expect("config directory");
    fs::create_dir_all(profile.parent().expect("profile parent")).expect("profile directory");
    fs::write(&config, "").expect("config");
    fs::write(
        &profile,
        br#"{"subscriptions":[{"id":"11111111-1111-1111-1111-111111111111","name":"synthetic","state":"Enabled","tenantId":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","environmentName":"AzureCloud","user":{"name":"test@example.invalid"}}]}"#,
    )
    .expect("profile");
    let mut child = Command::new(env!("CARGO_BIN_EXE_azmcp"))
        .env_clear()
        .env("HOME", directory.path())
        .env("AZMCP_AZ_EXECUTABLE", &missing_az)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn azmcp");

    let requests = [
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "server/discover",
            "params": {"_meta": metadata()}
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {"_meta": metadata()}
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "azure_accounts", "arguments": {}, "_meta": metadata()}
        }),
    ];
    {
        let stdin = child.stdin.as_mut().expect("child stdin");
        for request in requests {
            serde_json::to_writer(&mut *stdin, &request).expect("write request");
            stdin.write_all(b"\n").expect("request delimiter");
        }
    }
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("wait for azmcp");
    assert!(
        output.status.success(),
        "azmcp stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let responses = String::from_utf8(output.stdout)
        .expect("UTF-8 responses")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("JSON-RPC response"))
        .collect::<Vec<_>>();
    assert_eq!(responses.len(), 3);
    let responses = responses
        .into_iter()
        .map(|response| {
            (
                response["id"].as_u64().expect("numeric response ID"),
                response,
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        responses[&1]["result"]["supportedVersions"],
        json!(["2026-07-28"])
    );
    assert_eq!(
        responses[&2]["result"]["tools"]
            .as_array()
            .unwrap_or_else(|| panic!("tools/list response: {}", responses[&2]))
            .len(),
        6
    );
    assert_eq!(
        responses[&3]["result"]["structuredContent"]["accounts"][0]["subscriptionId"],
        "11111111-1111-1111-1111-111111111111"
    );
    assert!(
        !missing_az.exists(),
        "startup and offline tools must not require Azure CLI"
    );
    assert!(
        !audit.exists(),
        "startup and profile-only discovery must not create request logs"
    );
    assert!(
        !artifacts.exists(),
        "startup and profile-only discovery must not create artifact storage"
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_azmcp"))
        .env_clear()
        .env("HOME", directory.path())
        .env("AZMCP_AZ_EXECUTABLE", &missing_az)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn azmcp for deferred credential failure");
    let request = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "azure_context_open",
            "arguments": {},
            "_meta": metadata()
        }
    });
    serde_json::to_writer(child.stdin.as_mut().expect("child stdin"), &request)
        .expect("write context-open request");
    child
        .stdin
        .as_mut()
        .expect("child stdin")
        .write_all(b"\n")
        .expect("request delimiter");
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("wait for azmcp");
    assert!(
        output.status.success(),
        "azmcp stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response = serde_json::from_slice::<Value>(&output.stdout).expect("JSON-RPC response");
    let result = &response["result"];
    assert_eq!(result["isError"], true);
    assert_eq!(
        result["structuredContent"]["code"],
        "authentication_required"
    );
    assert_eq!(result["structuredContent"]["retryable"], true);
    assert!(
        result["structuredContent"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("Azure CLI could not be started"))
    );
    assert!(
        !artifacts.exists(),
        "a deferred credential failure must not create artifact storage"
    );
}
