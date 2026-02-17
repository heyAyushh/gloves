use assert_cmd::Command;

use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::Stdio,
    sync::{Mutex, MutexGuard},
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const DAEMON_WAIT_ATTEMPTS: usize = 100;
const DAEMON_WAIT_STEP_MILLIS: u64 = 20;
static DAEMON_TEST_LOCK: Mutex<()> = Mutex::new(());

fn daemon_test_guard() -> MutexGuard<'static, ()> {
    match DAEMON_TEST_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

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

fn spawn_daemon_with_retry(root: &Path, max_requests: usize) -> (std::process::Child, String) {
    let binary = assert_cmd::cargo::cargo_bin!("gloves");
    let root = root.to_str().unwrap();
    let mut last_bind_error = String::new();

    for _ in 0..DAEMON_WAIT_ATTEMPTS {
        let bind = format!("127.0.0.1:{}", reserve_loopback_port());
        let mut child = std::process::Command::new(binary)
            .args([
                "--root",
                root,
                "daemon",
                "--bind",
                &bind,
                "--max-requests",
                &max_requests.to_string(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        std::thread::sleep(Duration::from_millis(DAEMON_WAIT_STEP_MILLIS));
        match child.try_wait().unwrap() {
            Some(_status) => {
                let mut stderr = String::new();
                if let Some(mut pipe) = child.stderr.take() {
                    let _ = pipe.read_to_string(&mut stderr);
                }
                if stderr.contains("Address already in use") {
                    last_bind_error = stderr;
                    continue;
                }
                panic!("daemon failed to start: {stderr}");
            }
            None => return (child, bind),
        }
    }

    panic!(
        "failed to spawn daemon after retries; last error: {}",
        last_bind_error
    );
}

fn write_config(path: &Path, body: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, body).unwrap();
    #[cfg(unix)]
    {
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(path, permissions).unwrap();
    }
}

#[cfg(unix)]
fn write_executable(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

#[cfg(unix)]
fn install_fake_vault_binaries(bin_dir: &Path) {
    fs::create_dir_all(bin_dir).unwrap();

    write_executable(
        &bin_dir.join("gocryptfs"),
        r#"#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == "-init" ]]; then
  cipher=""
  for arg in "$@"; do
    cipher="$arg"
  done
  mkdir -p "$cipher"
  touch "$cipher/gocryptfs.conf"
  exit 0
fi
mountpoint=""
for arg in "$@"; do
  mountpoint="$arg"
done
mkdir -p "$mountpoint"
touch "$mountpoint/.mounted"
"#,
    );
    write_executable(
        &bin_dir.join("fusermount"),
        r#"#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == "-u" ]]; then
  rm -f "$2/.mounted"
fi
"#,
    );
    write_executable(
        &bin_dir.join("mountpoint"),
        r#"#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" != "-q" ]]; then
  exit 2
fi
if [[ -f "$2/.mounted" ]]; then
  exit 0
fi
exit 1
"#,
    );
}

#[cfg(unix)]
fn with_fake_path(fake_bin: &Path) -> String {
    let current_path = std::env::var("PATH").unwrap_or_default();
    format!("{}:{}", fake_bin.display(), current_path)
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
fn cli_bootstrap_uses_discovered_gloves_toml() {
    let temp_dir = tempfile::tempdir().unwrap();
    let workspace = temp_dir.path().join("workspace");
    let nested = workspace.join("nested/project");
    fs::create_dir_all(&nested).unwrap();

    let config_path = workspace.join(".gloves.toml");
    write_config(
        &config_path,
        r#"
version = 1

[paths]
root = "./runtime-from-config"
"#,
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .current_dir(&nested)
        .args(["init"])
        .assert()
        .success();

    assert!(workspace.join("runtime-from-config/store").exists());
}

#[test]
fn cli_bootstrap_uses_explicit_config_path() {
    let temp_dir = tempfile::tempdir().unwrap();
    let workspace = temp_dir.path().join("workspace");
    let config_dir = temp_dir.path().join("configs");
    fs::create_dir_all(&workspace).unwrap();

    let config_path = config_dir.join("custom.gloves.toml");
    write_config(
        &config_path,
        r#"
version = 1

[paths]
root = "./explicit-root"
"#,
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .current_dir(&workspace)
        .args(["--config", config_path.to_str().unwrap(), "init"])
        .assert()
        .success();

    assert!(config_dir.join("explicit-root/store").exists());
}

#[test]
fn cli_bootstrap_no_config_keeps_existing_defaults() {
    let temp_dir = tempfile::tempdir().unwrap();
    let workspace = temp_dir.path().join("workspace");
    fs::create_dir_all(&workspace).unwrap();
    write_config(
        &workspace.join(".gloves.toml"),
        r#"
version = 1

[paths]
root = "./should-not-be-used"
"#,
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .current_dir(&workspace)
        .args(["--no-config", "init"])
        .assert()
        .success();

    assert!(workspace.join(".openclaw/secrets/store").exists());
    assert!(!workspace.join("should-not-be-used").exists());
}

#[test]
fn cli_config_validate_success() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join(".gloves.toml");
    write_config(&config_path, "version = 1\n");

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "config",
            "validate",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("ok"));
}

#[test]
fn cli_config_validate_required_fails_without_binaries() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join(".gloves.toml");
    let empty_path = temp_dir.path().join("empty-path");
    fs::create_dir_all(&empty_path).unwrap();
    write_config(&config_path, "version = 1\n");

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", empty_path.to_str().unwrap())
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--vault-mode",
            "required",
            "config",
            "validate",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("missing required binaries"));
}

#[test]
fn cli_config_validate_failure_invalid_alias() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join(".gloves.toml");
    write_config(
        &config_path,
        r#"
version = 1

[private_paths]
"bad alias" = "./private"
"#,
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "config",
            "validate",
        ])
        .assert()
        .failure();
}

#[test]
fn cli_access_paths_without_config_fails() {
    let temp_dir = tempfile::tempdir().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .current_dir(temp_dir.path())
        .args(["access", "paths", "--agent", "default-agent"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("no config loaded"));
}

#[test]
fn cli_access_paths_json() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join(".gloves.toml");
    write_config(
        &config_path,
        r#"
version = 1

[private_paths]
runtime_root = "./runtime"

[agents.default-agent]
paths = ["runtime_root"]
operations = ["read", "list"]
"#,
    );

    let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "access",
            "paths",
            "--agent",
            "default-agent",
            "--json",
        ])
        .assert()
        .success();
    let output = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let payload: serde_json::Value = serde_json::from_str(&output).unwrap();

    assert_eq!(payload["agent"], "default-agent");
    assert_eq!(payload["paths"][0]["alias"], "runtime_root");
}

#[test]
fn cli_access_paths_unknown_agent_fails() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join(".gloves.toml");
    write_config(
        &config_path,
        r#"
version = 1

[private_paths]
runtime_root = "./runtime"

[agents.default-agent]
paths = ["runtime_root"]
operations = ["read"]
"#,
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "access",
            "paths",
            "--agent",
            "agent-b",
        ])
        .assert()
        .failure();
}

#[test]
fn cli_vault_mode_disabled_blocks_vault_commands() {
    let temp_dir = tempfile::tempdir().unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "--vault-mode",
            "disabled",
            "vault",
            "list",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("disabled"));
}

#[test]
fn cli_vault_mode_required_fails_without_binaries() {
    let temp_dir = tempfile::tempdir().unwrap();
    let empty_path = temp_dir.path().join("empty-path");
    fs::create_dir_all(&empty_path).unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", empty_path.to_str().unwrap())
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "--vault-mode",
            "required",
            "vault",
            "list",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("gocryptfs"));
}

#[test]
fn cli_vault_mode_auto_allows_non_crypto_commands_without_runtime_bins() {
    let temp_dir = tempfile::tempdir().unwrap();
    let empty_path = temp_dir.path().join("empty-path");
    fs::create_dir_all(&empty_path).unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", empty_path.to_str().unwrap())
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "--vault-mode",
            "auto",
            "list",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("["));
}

#[test]
fn cli_set_and_get_succeed_without_runtime_rage_binaries() {
    let temp_dir = tempfile::tempdir().unwrap();
    let empty_path = temp_dir.path().join("empty-path");
    fs::create_dir_all(&empty_path).unwrap();
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", empty_path.to_str().unwrap())
        .args([
            "--root",
            root,
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
        .env("PATH", empty_path.to_str().unwrap())
        .args(["--root", root, "get", "x"])
        .assert()
        .success()
        .stdout(predicates::str::contains("placeholder-secret"));
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
fn cli_set_rejects_non_positive_ttl() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root", root, "set", "ttl_zero", "--value", "x", "--ttl", "0",
        ])
        .assert()
        .failure();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root,
            "set",
            "ttl_negative",
            "--value",
            "x",
            "--ttl=-1",
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

#[cfg(unix)]
#[test]
fn cli_vault_init() {
    let temp_dir = tempfile::tempdir().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    install_fake_vault_binaries(&fake_bin);

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "vault",
            "init",
            "agent_data",
            "--owner",
            "agent",
        ])
        .assert()
        .success();

    assert!(temp_dir.path().join("vaults/agent_data.toml").exists());
}

#[cfg(unix)]
#[test]
fn cli_vault_mount() {
    let temp_dir = tempfile::tempdir().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    install_fake_vault_binaries(&fake_bin);
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--root",
            root,
            "vault",
            "init",
            "agent_data",
            "--owner",
            "agent",
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--root",
            root,
            "vault",
            "mount",
            "agent_data",
            "--ttl",
            "1h",
        ])
        .assert()
        .success();

    let sessions = std::fs::read_to_string(temp_dir.path().join("vaults/sessions.json")).unwrap();
    assert!(sessions.contains("agent_data"));
}

#[cfg(unix)]
#[test]
fn cli_vault_unmount() {
    let temp_dir = tempfile::tempdir().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    install_fake_vault_binaries(&fake_bin);
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--root",
            root,
            "vault",
            "init",
            "agent_data",
            "--owner",
            "agent",
        ])
        .assert()
        .success();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--root",
            root,
            "vault",
            "mount",
            "agent_data",
            "--ttl",
            "1h",
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args(["--root", root, "vault", "unmount", "agent_data"])
        .assert()
        .success();

    let sessions = std::fs::read_to_string(temp_dir.path().join("vaults/sessions.json")).unwrap();
    assert_eq!(sessions.trim(), "[]");
}

#[cfg(unix)]
#[test]
fn cli_vault_status() {
    let temp_dir = tempfile::tempdir().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    install_fake_vault_binaries(&fake_bin);
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--root",
            root,
            "vault",
            "init",
            "agent_data",
            "--owner",
            "agent",
        ])
        .assert()
        .success();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--root",
            root,
            "vault",
            "mount",
            "agent_data",
            "--ttl",
            "1h",
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args(["--root", root, "vault", "status"])
        .assert()
        .success()
        .stdout(predicates::str::contains("agent_data"))
        .stdout(predicates::str::contains("mounted"));
}

#[cfg(unix)]
#[test]
fn cli_vault_list() {
    let temp_dir = tempfile::tempdir().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    install_fake_vault_binaries(&fake_bin);
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--root",
            root,
            "vault",
            "init",
            "agent_data",
            "--owner",
            "agent",
        ])
        .assert()
        .success();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--root", root, "vault", "init", "personal", "--owner", "human",
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args(["--root", root, "vault", "list"])
        .assert()
        .success()
        .stdout(predicates::str::contains("agent_data"))
        .stdout(predicates::str::contains("personal"));
}

#[cfg(unix)]
#[test]
fn cli_vault_ask_file() {
    let temp_dir = tempfile::tempdir().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    install_fake_vault_binaries(&fake_bin);
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--root",
            root,
            "vault",
            "init",
            "agent_data",
            "--owner",
            "agent",
        ])
        .assert()
        .success();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--root",
            root,
            "vault",
            "mount",
            "agent_data",
            "--ttl",
            "1h",
            "--agent",
            "agent-b",
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--root",
            root,
            "vault",
            "ask-file",
            "agent_data",
            "--file",
            "docs/notes.txt",
            "--trusted-agent",
            "agent-b",
            "--requester",
            "agent-a",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("Agent handoff request"))
        .stdout(predicates::str::contains("Requester: agent-a"))
        .stdout(predicates::str::contains("Trusted agent: agent-b"));
}

#[cfg(unix)]
#[test]
fn cli_vault_ask_file_requires_access() {
    let temp_dir = tempfile::tempdir().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    install_fake_vault_binaries(&fake_bin);
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--root",
            root,
            "vault",
            "init",
            "agent_data",
            "--owner",
            "agent",
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--root",
            root,
            "vault",
            "ask-file",
            "agent_data",
            "--file",
            "docs/notes.txt",
            "--trusted-agent",
            "agent-b",
            "--requester",
            "agent-a",
        ])
        .assert()
        .failure();
}

#[test]
fn cli_daemon_check_passes() {
    let _guard = daemon_test_guard();
    let temp_dir = tempfile::tempdir().unwrap();
    let binary = assert_cmd::cargo::cargo_bin!("gloves");
    let root = temp_dir.path().to_str().unwrap();
    let mut last_bind_error = String::new();

    for _ in 0..DAEMON_WAIT_ATTEMPTS {
        let bind = format!("127.0.0.1:{}", reserve_loopback_port());
        let output = std::process::Command::new(binary)
            .args(["--root", root, "daemon", "--check", "--bind", &bind])
            .output()
            .unwrap();
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.contains("ok"));
            return;
        }

        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        if stderr.contains("Address already in use") {
            last_bind_error = stderr;
            continue;
        }
        panic!("daemon --check failed unexpectedly: {stderr}");
    }

    panic!(
        "daemon --check did not get a free port after retries; last error: {}",
        last_bind_error
    );
}

#[test]
fn cli_daemon_check_rejects_non_loopback_bind() {
    let _guard = daemon_test_guard();
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
    let _guard = daemon_test_guard();
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
fn cli_daemon_check_fails_when_bind_is_in_use() {
    let _guard = daemon_test_guard();
    let temp_dir = tempfile::tempdir().unwrap();
    let busy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let bind = busy_listener.local_addr().unwrap().to_string();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "daemon",
            "--check",
            "--bind",
            &bind,
        ])
        .assert()
        .failure();
}

#[test]
fn cli_daemon_ping_roundtrip_over_tcp() {
    let _guard = daemon_test_guard();
    let temp_dir = tempfile::tempdir().unwrap();
    let (mut child, bind) = spawn_daemon_with_retry(temp_dir.path(), 1);

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
fn cli_daemon_set_generate_with_value_returns_error() {
    let _guard = daemon_test_guard();
    let temp_dir = tempfile::tempdir().unwrap();
    let (mut child, bind) = spawn_daemon_with_retry(temp_dir.path(), 1);

    let mut stream = connect_with_retry(&bind);
    stream
        .write_all(br#"{"action":"set","name":"x","generate":true,"value":"abc"}"#)
        .unwrap();
    stream.write_all(b"\n").unwrap();

    let mut response_line = String::new();
    let mut reader = BufReader::new(stream);
    reader.read_line(&mut response_line).unwrap();

    assert!(response_line.contains("\"status\":\"error\""));
    assert!(response_line.contains("generate cannot be combined with value"));

    let status = child.wait().unwrap();
    assert!(status.success());
}

#[test]
fn cli_daemon_set_rejects_non_positive_ttl() {
    let _guard = daemon_test_guard();
    let temp_dir = tempfile::tempdir().unwrap();
    let (mut child, bind) = spawn_daemon_with_retry(temp_dir.path(), 2);

    let mut stream = connect_with_retry(&bind);
    stream
        .write_all(br#"{"action":"set","name":"x","value":"abc","ttl_days":0}"#)
        .unwrap();
    stream.write_all(b"\n").unwrap();

    let mut response_line = String::new();
    let mut reader = BufReader::new(stream);
    reader.read_line(&mut response_line).unwrap();

    assert!(response_line.contains("\"status\":\"error\""));
    assert!(response_line.contains("ttl_days must be greater than zero"));

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
