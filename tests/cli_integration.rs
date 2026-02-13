use assert_cmd::Command;

use std::{
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    process::Stdio,
    time::Duration,
};

const DAEMON_WAIT_ATTEMPTS: usize = 100;
const DAEMON_WAIT_STEP_MILLIS: u64 = 20;

fn connect_with_retry(address: &str) -> TcpStream {
    for _ in 0..DAEMON_WAIT_ATTEMPTS {
        if let Ok(stream) = TcpStream::connect(address) {
            return stream;
        }
        std::thread::sleep(Duration::from_millis(DAEMON_WAIT_STEP_MILLIS));
    }
    panic!("daemon endpoint was not reachable in time: {address}");
}

fn reserve_loopback_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

#[test]
fn cli_init() {
    let temp_dir = tempfile::tempdir().unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", temp_dir.path().to_str().unwrap(), "init"])
        .assert()
        .success();

    assert!(temp_dir.path().join("store").exists());
    assert!(temp_dir.path().join("meta").exists());
}

#[test]
fn cli_set_generate() {
    let temp_dir = tempfile::tempdir().unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "set",
            "x",
            "--generate",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    assert!(temp_dir.path().join("store/x.age").exists());
}

#[test]
fn cli_set_duplicate_secret_fails() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", root, "set", "x", "--generate", "--ttl", "1"])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", root, "set", "x", "--generate", "--ttl", "1"])
        .assert()
        .failure();
}

#[test]
fn cli_set_then_get_roundtrip() {
    let temp_dir = tempfile::tempdir().unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "set",
            "x",
            "--value",
            "placeholder-secret",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", temp_dir.path().to_str().unwrap(), "get", "x"])
        .assert()
        .success()
        .stdout(predicates::str::contains("placeholder-secret"));
}

#[test]
fn cli_set_from_stdin() {
    let temp_dir = tempfile::tempdir().unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "set",
            "stdin_secret",
            "--stdin",
            "--ttl",
            "1",
        ])
        .write_stdin("from-stdin\n")
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "get",
            "stdin_secret",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("from-stdin"));
}

#[test]
fn cli_set_empty_stdin_rejected() {
    let temp_dir = tempfile::tempdir().unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "set",
            "stdin_secret",
            "--stdin",
            "--ttl",
            "1",
        ])
        .write_stdin("\n")
        .assert()
        .failure();
}

#[test]
fn cli_set_requires_input_source() {
    let temp_dir = tempfile::tempdir().unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "set",
            "missing_input",
        ])
        .assert()
        .failure();
}

#[test]
fn cli_set_rejects_generate_and_value() {
    let temp_dir = tempfile::tempdir().unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "set",
            "x",
            "--generate",
            "--value",
            "secret",
        ])
        .assert()
        .failure();
}

#[test]
fn cli_set_rejects_empty_value() {
    let temp_dir = tempfile::tempdir().unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "set",
            "x",
            "--value",
            "",
        ])
        .assert()
        .failure();
}

#[test]
fn cli_get_redacted() {
    let temp_dir = tempfile::tempdir().unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "env",
            "x",
            "VAR",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("<REDACTED>"));
}

#[test]
fn cli_get_raw_tty_warning() {
    let temp_dir = tempfile::tempdir().unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("GLOVES_FORCE_TTY_WARNING", "1")
        .args(["--root", temp_dir.path().to_str().unwrap(), "get", "x"])
        .assert()
        .stderr(predicates::str::contains("warning"));
}

#[test]
fn cli_request() {
    let temp_dir = tempfile::tempdir().unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "request",
            "x",
            "--reason",
            "test",
        ])
        .assert()
        .success();

    let pending = std::fs::read_to_string(temp_dir.path().join("pending.json")).unwrap();
    assert!(pending.contains("test"));
}

#[test]
fn cli_request_twice_uses_existing_signing_key() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", root, "request", "x", "--reason", "first"])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", root, "request", "x", "--reason", "second"])
        .assert()
        .success();
}

#[test]
fn cli_request_fails_when_pending_json_is_unreadable() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", root, "init"])
        .assert()
        .success();

    let pending_path = temp_dir.path().join("pending.json");
    std::fs::remove_file(&pending_path).unwrap();
    std::fs::create_dir(&pending_path).unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", root, "request", "x", "--reason", "test"])
        .assert()
        .failure();
}

#[test]
fn cli_approve_request() {
    let temp_dir = tempfile::tempdir().unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "request",
            "x",
            "--reason",
            "test",
        ])
        .assert()
        .success();

    let pending: serde_json::Value =
        serde_json::from_slice(&std::fs::read(temp_dir.path().join("pending.json")).unwrap())
            .unwrap();
    let request_id = pending[0]["id"].as_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "approve",
            request_id,
        ])
        .assert()
        .success();
}

#[test]
fn cli_approve_invalid_uuid_fails() {
    let temp_dir = tempfile::tempdir().unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "approve",
            "not-a-uuid",
        ])
        .assert()
        .failure();
}

#[test]
fn cli_deny_request() {
    let temp_dir = tempfile::tempdir().unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "request",
            "x",
            "--reason",
            "test",
        ])
        .assert()
        .success();

    let pending: serde_json::Value =
        serde_json::from_slice(&std::fs::read(temp_dir.path().join("pending.json")).unwrap())
            .unwrap();
    let request_id = pending[0]["id"].as_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "deny",
            request_id,
        ])
        .assert()
        .success();
}

#[test]
fn cli_list() {
    let temp_dir = tempfile::tempdir().unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", temp_dir.path().to_str().unwrap(), "list"])
        .assert()
        .success()
        .stdout(predicates::str::contains("["));
}

#[test]
fn cli_revoke() {
    let temp_dir = tempfile::tempdir().unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "set",
            "x",
            "--generate",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", temp_dir.path().to_str().unwrap(), "revoke", "x"])
        .assert()
        .success();

    assert!(!temp_dir.path().join("store/x.age").exists());
}

#[test]
fn cli_status() {
    let temp_dir = tempfile::tempdir().unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "request",
            "x",
            "--reason",
            "test",
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", temp_dir.path().to_str().unwrap(), "status", "x"])
        .assert()
        .success()
        .stdout(predicates::str::contains("pending"));
}

#[test]
fn cli_status_defaults_to_fulfilled() {
    let temp_dir = tempfile::tempdir().unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "status",
            "missing",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("fulfilled"));
}

#[test]
fn cli_verify() {
    let temp_dir = tempfile::tempdir().unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", temp_dir.path().to_str().unwrap(), "verify"])
        .assert()
        .success();
}

#[test]
fn cli_verify_fails_on_invalid_metadata_file() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", root, "init"])
        .assert()
        .success();

    let invalid_path = temp_dir.path().join("meta").join("bad.json");
    std::fs::write(invalid_path, b"{invalid-json").unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", root, "verify"])
        .assert()
        .failure();
}

#[test]
fn cli_daemon_check_passes() {
    let temp_dir = tempfile::tempdir().unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "daemon",
            "--check",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("ok"));
}

#[test]
fn cli_daemon_check_rejects_non_loopback_bind() {
    let temp_dir = tempfile::tempdir().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "daemon",
            "--check",
            "--bind",
            "0.0.0.0:7788",
        ])
        .assert()
        .failure();
}

#[test]
fn cli_daemon_check_rejects_zero_port_bind() {
    let temp_dir = tempfile::tempdir().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "daemon",
            "--check",
            "--bind",
            "127.0.0.1:0",
        ])
        .assert()
        .failure();
}

#[test]
fn cli_daemon_ping_roundtrip_over_tcp() {
    let temp_dir = tempfile::tempdir().unwrap();
    let port = reserve_loopback_port();
    let bind = format!("127.0.0.1:{port}");
    let binary = assert_cmd::cargo::cargo_bin!("gloves");

    let mut child = std::process::Command::new(binary)
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "daemon",
            "--bind",
            &bind,
            "--max-requests",
            "1",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let mut stream = connect_with_retry(&bind);
    stream.write_all(br#"{"action":"ping"}"#).unwrap();
    stream.write_all(b"\n").unwrap();

    let mut response_line = String::new();
    let mut reader = BufReader::new(stream);
    reader.read_line(&mut response_line).unwrap();

    assert!(response_line.contains("\"status\":\"ok\""));
    assert!(response_line.contains("\"message\":\"pong\""));

    let status = child.wait().unwrap();
    assert!(status.success());
}

#[test]
fn cli_daemon_invalid_request_returns_error() {
    let temp_dir = tempfile::tempdir().unwrap();
    let port = reserve_loopback_port();
    let bind = format!("127.0.0.1:{port}");
    let binary = assert_cmd::cargo::cargo_bin!("gloves");

    let mut child = std::process::Command::new(binary)
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "daemon",
            "--bind",
            &bind,
            "--max-requests",
            "2",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let mut stream = connect_with_retry(&bind);
    stream.write_all(b"not-json\n").unwrap();

    let mut response_line = String::new();
    let mut reader = BufReader::new(stream);
    reader.read_line(&mut response_line).unwrap();

    assert!(response_line.contains("\"status\":\"error\""));
    assert!(response_line.contains("invalid daemon request"));

    let mut second_stream = connect_with_retry(&bind);
    second_stream.write_all(br#"{"action":"ping"}"#).unwrap();
    second_stream.write_all(b"\n").unwrap();

    let mut second_response_line = String::new();
    let mut second_reader = BufReader::new(second_stream);
    second_reader.read_line(&mut second_response_line).unwrap();
    assert!(second_response_line.contains("\"status\":\"ok\""));

    let status = child.wait().unwrap();
    assert!(status.success());
}
