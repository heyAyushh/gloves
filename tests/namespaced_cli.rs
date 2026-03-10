use assert_cmd::Command;
use gloves::agent::age_crypto;
use predicates::prelude::*;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const SECRET_PATH: &str = "agents/devy/api-keys/anthropic";
const SECRET_VALUE: &str = "sk-ant-api03-test-secret";

fn gloves_command() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
}

fn write_creation_rules(root: &Path, body: &str) {
    let rules_path = root.join("store/.gloves.yaml");
    fs::create_dir_all(rules_path.parent().unwrap()).unwrap();
    fs::write(rules_path, body).unwrap();
}

fn read_namespace_recipients(root: &Path, namespace: &str) -> Vec<String> {
    let contents =
        fs::read_to_string(root.join("store").join(namespace).join(".age-recipients")).unwrap();
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

fn store_paths(root: &Path, secret_path: &str) -> (PathBuf, PathBuf) {
    let base = root.join("store");
    let ciphertext = base.join(format!("{secret_path}.age"));
    let metadata = base
        .join(".gloves-meta")
        .join(format!("{secret_path}.json"));
    (ciphertext, metadata)
}

fn find_rotated_identity(root: &Path, agent: &str, prefix: &str) -> PathBuf {
    fs::read_dir(root.join("identities"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.starts_with(&format!("{agent}.age.{prefix}")))
        })
        .unwrap_or_else(|| panic!("missing rotated identity for agent {agent}"))
}

fn collect_file_contents(root: &Path) -> Vec<Vec<u8>> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();

    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            files.push(fs::read(path).unwrap());
        }
    }

    files
}

fn set_identity(root: &Path, agent: &str) -> String {
    gloves_command()
        .args([
            "--root",
            root.to_str().unwrap(),
            "set-identity",
            "--agent",
            agent,
        ])
        .assert()
        .success();

    let recipients = read_namespace_recipients(root, &format!("agents/{agent}"));
    assert_eq!(recipients.len(), 1);
    recipients[0].clone()
}

fn set_secret(root: &Path, agent: &str, path: &str, value: &str) {
    gloves_command()
        .args([
            "--root",
            root.to_str().unwrap(),
            "--agent",
            agent,
            "set",
            path,
            "--value",
            value,
        ])
        .assert()
        .success();
}

fn get_secret_raw(root: &Path, agent: &str, path: &str) -> assert_cmd::assert::Assert {
    let mut command = gloves_command();
    command.args([
        "--root",
        root.to_str().unwrap(),
        "--agent",
        agent,
        "get",
        path,
        "--format",
        "raw",
    ]);
    command.assert()
}

fn get_secret_json(root: &Path, agent: &str, path: &str) -> Value {
    let output = gloves_command()
        .args([
            "--root",
            root.to_str().unwrap(),
            "--agent",
            agent,
            "get",
            path,
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&output).unwrap()
}

#[test]
fn set_identity_creates_private_identity_and_namespace_recipients_file() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    let recipient = set_identity(root, "devy");

    let identity_path = root.join("identities/devy.age");
    assert!(identity_path.exists());
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(&identity_path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let recipients_path = root.join("store/agents/devy/.age-recipients");
    assert!(recipients_path.exists());
    assert_eq!(
        fs::read_to_string(recipients_path).unwrap().trim(),
        recipient
    );
}

#[test]
fn set_and_get_support_raw_and_json_output_for_namespaced_secrets() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    set_identity(root, "devy");
    write_creation_rules(
        root,
        "version: 1\ncreation_rules:\n  - path_regex: ^agents/devy/.*$\n",
    );
    set_secret(root, "devy", SECRET_PATH, SECRET_VALUE);

    get_secret_raw(root, "devy", SECRET_PATH)
        .success()
        .stdout(predicate::eq(SECRET_VALUE));

    let payload = get_secret_json(root, "devy", SECRET_PATH);

    assert_eq!(payload["name"], SECRET_PATH);
    assert_eq!(payload["value"], SECRET_VALUE);
    assert_eq!(payload["length"], SECRET_VALUE.len());
    assert_eq!(payload["agent"], "devy");
    assert_eq!(payload["encrypted_to"].as_array().unwrap().len(), 1);

    let (_ciphertext_path, metadata_path) = store_paths(root, SECRET_PATH);
    let metadata_value = fs::read_to_string(metadata_path).unwrap();
    assert!(!metadata_value.contains(SECRET_VALUE));
}

#[test]
fn show_redacted_returns_metadata_without_identity_file() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    set_identity(root, "devy");
    write_creation_rules(
        root,
        "version: 1\ncreation_rules:\n  - path_regex: ^agents/devy/.*$\n",
    );
    set_secret(root, "devy", SECRET_PATH, SECRET_VALUE);
    fs::remove_file(root.join("identities/devy.age")).unwrap();

    gloves_command()
        .args([
            "--root",
            root.to_str().unwrap(),
            "show",
            SECRET_PATH,
            "--redacted",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "name: agents/devy/api-keys/anthropic",
        ))
        .stdout(predicate::str::contains("exists: true"))
        .stdout(predicate::str::contains("agent: devy"))
        .stdout(predicate::str::contains("length: 24"));
}

#[test]
fn show_reports_not_found_for_missing_secret() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    gloves_command()
        .args(["--root", root.to_str().unwrap(), "show", SECRET_PATH])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn get_rejects_agents_outside_the_recipient_set() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    set_identity(root, "devy");
    set_identity(root, "webhook");
    write_creation_rules(
        root,
        "version: 1\ncreation_rules:\n  - path_regex: ^agents/devy/.*$\n",
    );
    set_secret(root, "devy", SECRET_PATH, SECRET_VALUE);

    get_secret_raw(root, "webhook", SECRET_PATH)
        .failure()
        .stderr(predicate::str::contains("unauthorized"));
}

#[test]
fn get_reports_missing_identity_file_for_agent() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    set_identity(root, "devy");
    write_creation_rules(
        root,
        "version: 1\ncreation_rules:\n  - path_regex: ^agents/devy/.*$\n",
    );
    set_secret(root, "devy", SECRET_PATH, SECRET_VALUE);
    fs::remove_file(root.join("identities/devy.age")).unwrap();

    get_secret_raw(root, "devy", SECRET_PATH)
        .failure()
        .stderr(predicate::str::contains("identity file not found"));
}

#[test]
fn set_rejects_matching_rule_without_any_resolved_recipients() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    write_creation_rules(
        root,
        "version: 1\ncreation_rules:\n  - path_regex: ^agents/devy/.*$\n",
    );

    gloves_command()
        .args([
            "--root",
            root.to_str().unwrap(),
            "--agent",
            "devy",
            "set",
            SECRET_PATH,
            "--value",
            SECRET_VALUE,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no recipients resolved"));
}

#[test]
fn set_reports_missing_creation_rules_file() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    set_identity(root, "devy");

    gloves_command()
        .args([
            "--root",
            root.to_str().unwrap(),
            "--agent",
            "devy",
            "set",
            SECRET_PATH,
            "--value",
            SECRET_VALUE,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("creation rules not found"));
}

#[test]
fn set_reports_invalid_creation_rules_file() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    set_identity(root, "devy");
    write_creation_rules(root, "version: [");

    gloves_command()
        .args([
            "--root",
            root.to_str().unwrap(),
            "--agent",
            "devy",
            "set",
            SECRET_PATH,
            "--value",
            SECRET_VALUE,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid creation rules"));
}

#[test]
fn set_overwrite_preserves_created_timestamp() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    set_identity(root, "devy");
    write_creation_rules(
        root,
        "version: 1\ncreation_rules:\n  - path_regex: ^agents/devy/.*$\n",
    );
    set_secret(root, "devy", SECRET_PATH, SECRET_VALUE);
    let first_payload = get_secret_json(root, "devy", SECRET_PATH);

    set_secret(root, "devy", SECRET_PATH, "sk-ant-api03-updated-secret");
    let second_payload = get_secret_json(root, "devy", SECRET_PATH);

    assert_eq!(first_payload["created"], second_payload["created"]);
    assert_eq!(second_payload["value"], "sk-ant-api03-updated-secret");
}

#[test]
fn updatekeys_reencrypts_using_current_namespace_recipients() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    let main_recipient = set_identity(root, "main");
    let devy_recipient = set_identity(root, "devy");
    fs::create_dir_all(root.join("store/shared")).unwrap();
    fs::write(
        root.join("store/shared/.age-recipients"),
        format!("{main_recipient}\n{devy_recipient}\n"),
    )
    .unwrap();
    write_creation_rules(
        root,
        "version: 1\ncreation_rules:\n  - path_regex: ^shared/.*$\n",
    );
    set_secret(root, "main", "shared/database-url", "postgres://db");

    get_secret_raw(root, "devy", "shared/database-url")
        .success()
        .stdout(predicate::eq("postgres://db"));

    fs::write(
        root.join("store/shared/.age-recipients"),
        format!("{main_recipient}\n"),
    )
    .unwrap();

    gloves_command()
        .args([
            "--root",
            root.to_str().unwrap(),
            "updatekeys",
            "--path",
            "shared",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("updated: 1"));

    get_secret_raw(root, "main", "shared/database-url")
        .success()
        .stdout(predicate::eq("postgres://db"));

    get_secret_raw(root, "devy", "shared/database-url")
        .failure()
        .stderr(predicate::str::contains("unauthorized"));
}

#[test]
fn updatekeys_accepts_explicit_identity_override() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    let main_recipient = set_identity(root, "main");
    let devy_recipient = set_identity(root, "devy");
    fs::create_dir_all(root.join("store/shared")).unwrap();
    fs::write(
        root.join("store/shared/.age-recipients"),
        format!("{main_recipient}\n"),
    )
    .unwrap();
    write_creation_rules(
        root,
        "version: 1\ncreation_rules:\n  - path_regex: ^shared/.*$\n",
    );
    set_secret(root, "main", "shared/database-url", "postgres://db");
    fs::write(
        root.join("store/shared/.age-recipients"),
        format!("{main_recipient}\n{devy_recipient}\n"),
    )
    .unwrap();

    gloves_command()
        .args([
            "--root",
            root.to_str().unwrap(),
            "updatekeys",
            "--path",
            "shared",
            "--identity",
            root.join("identities/main.age").to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("updated: 1"));

    get_secret_raw(root, "devy", "shared/database-url")
        .success()
        .stdout(predicate::eq("postgres://db"));
}

#[test]
fn updatekeys_reports_unchanged_when_recipients_already_match() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    set_identity(root, "devy");
    write_creation_rules(
        root,
        "version: 1\ncreation_rules:\n  - path_regex: ^agents/devy/.*$\n",
    );
    set_secret(root, "devy", SECRET_PATH, SECRET_VALUE);

    gloves_command()
        .args([
            "--root",
            root.to_str().unwrap(),
            "updatekeys",
            "--path",
            "agents/devy",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("updated: 0"))
        .stdout(predicate::str::contains("unchanged: 1"))
        .stdout(predicate::str::contains("skipped: 0"));
}

#[test]
fn updatekeys_dry_run_reports_updates_without_reencrypting() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    let devy_recipient = set_identity(root, "devy");
    let main_recipient = set_identity(root, "main");
    write_creation_rules(
        root,
        "version: 1\ncreation_rules:\n  - path_regex: ^agents/devy/.*$\n",
    );
    set_secret(root, "devy", SECRET_PATH, SECRET_VALUE);
    fs::write(
        root.join("store/agents/devy/.age-recipients"),
        format!("{devy_recipient}\n{main_recipient}\n"),
    )
    .unwrap();

    gloves_command()
        .args([
            "--root",
            root.to_str().unwrap(),
            "updatekeys",
            "--path",
            "agents/devy",
            "--dry-run",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("updated: 1"))
        .stdout(predicate::str::contains("unchanged: 0"))
        .stdout(predicate::str::contains("skipped: 0"))
        .stdout(predicate::str::contains("dry_run: true"));

    get_secret_raw(root, "main", SECRET_PATH)
        .failure()
        .stderr(predicate::str::contains("unauthorized"));
}

#[test]
fn updatekeys_fails_when_no_identity_can_decrypt_current_recipients() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    let main_recipient = set_identity(root, "main");
    let devy_recipient = set_identity(root, "devy");
    fs::create_dir_all(root.join("store/shared")).unwrap();
    fs::write(
        root.join("store/shared/.age-recipients"),
        format!("{main_recipient}\n"),
    )
    .unwrap();
    write_creation_rules(
        root,
        "version: 1\ncreation_rules:\n  - path_regex: ^shared/.*$\n",
    );
    set_secret(root, "main", "shared/database-url", "postgres://db");
    fs::write(
        root.join("store/shared/.age-recipients"),
        format!("{main_recipient}\n{devy_recipient}\n"),
    )
    .unwrap();
    fs::remove_dir_all(root.join("identities")).unwrap();

    gloves_command()
        .args([
            "--root",
            root.to_str().unwrap(),
            "updatekeys",
            "--path",
            "shared",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "no identity can decrypt shared/database-url",
        ));
}

#[test]
fn updatekeys_skips_paths_when_rules_resolve_no_recipients() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    set_identity(root, "devy");
    write_creation_rules(
        root,
        "version: 1\ncreation_rules:\n  - path_regex: ^agents/devy/.*$\n",
    );
    set_secret(root, "devy", SECRET_PATH, SECRET_VALUE);
    fs::write(root.join("store/agents/devy/.age-recipients"), "").unwrap();

    gloves_command()
        .args([
            "--root",
            root.to_str().unwrap(),
            "updatekeys",
            "--path",
            "agents/devy",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("updated: 0"))
        .stdout(predicate::str::contains("unchanged: 0"))
        .stdout(predicate::str::contains("skipped: 1"));
}

#[test]
fn rotate_reencrypts_secrets_for_the_new_identity_and_revokes_the_old_one() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    let original_recipient = set_identity(root, "devy");
    write_creation_rules(
        root,
        "version: 1\ncreation_rules:\n  - path_regex: ^agents/devy/.*$\n",
    );
    set_secret(root, "devy", SECRET_PATH, SECRET_VALUE);

    let (ciphertext_path, _metadata_path) = store_paths(root, SECRET_PATH);
    let old_identity_path = root.join("identities/devy.age");
    let old_plaintext = age_crypto::decrypt_file(&ciphertext_path, &old_identity_path).unwrap();
    assert_eq!(String::from_utf8(old_plaintext).unwrap(), SECRET_VALUE);

    gloves_command()
        .args([
            "--root",
            root.to_str().unwrap(),
            "rotate",
            "--agent",
            "devy",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("rotated devy"));

    let updated_recipient = read_namespace_recipients(root, "agents/devy");
    assert_eq!(updated_recipient.len(), 1);
    assert_ne!(updated_recipient[0], original_recipient);

    get_secret_raw(root, "devy", SECRET_PATH)
        .success()
        .stdout(predicate::eq(SECRET_VALUE));

    let revoked_identity_path = find_rotated_identity(root, "devy", "revoked-");
    let revoked_error = age_crypto::decrypt_file(&ciphertext_path, &revoked_identity_path)
        .expect_err("revoked identity should not decrypt rotated secret");
    assert!(revoked_error.to_string().contains("No matching keys"));
}

#[test]
fn rotate_keep_old_archives_previous_identity_without_revocation_prefix() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    set_identity(root, "devy");
    write_creation_rules(
        root,
        "version: 1\ncreation_rules:\n  - path_regex: ^agents/devy/.*$\n",
    );
    set_secret(root, "devy", SECRET_PATH, SECRET_VALUE);

    gloves_command()
        .args([
            "--root",
            root.to_str().unwrap(),
            "rotate",
            "--agent",
            "devy",
            "--keep-old",
        ])
        .assert()
        .success();

    let archived_identity_path = find_rotated_identity(root, "devy", "previous-");
    assert!(archived_identity_path.exists());
}

#[test]
fn rotate_requires_existing_identity_file() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    gloves_command()
        .args([
            "--root",
            root.to_str().unwrap(),
            "rotate",
            "--agent",
            "devy",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("identity file not found"));
}

#[test]
fn get_does_not_persist_plaintext_to_disk() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    set_identity(root, "devy");
    write_creation_rules(
        root,
        "version: 1\ncreation_rules:\n  - path_regex: ^agents/devy/.*$\n",
    );
    set_secret(root, "devy", SECRET_PATH, SECRET_VALUE);

    get_secret_raw(root, "devy", SECRET_PATH)
        .success()
        .stdout(predicate::eq(SECRET_VALUE));

    let plaintext_matches = collect_file_contents(root)
        .into_iter()
        .filter(|bytes| {
            bytes
                .windows(SECRET_VALUE.len())
                .any(|window| window == SECRET_VALUE.as_bytes())
        })
        .count();
    assert_eq!(plaintext_matches, 0);
}
