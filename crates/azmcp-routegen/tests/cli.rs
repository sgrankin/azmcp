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
