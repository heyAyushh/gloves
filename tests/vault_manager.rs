use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    },
};

use chrono::{Duration, Utc};
use gloves::{
    audit::AuditLog,
    error::{GlovesError, Result},
    paths::SecretsPaths,
    types::{AgentId, Owner},
    vault::{
        gocryptfs::{FsEncryptionDriver, InitRequest, MountRequest},
        VaultManager, VaultSecretProvider,
    },
};

#[derive(Default)]
struct SecretProviderState {
    generated: Mutex<Vec<String>>,
}

struct MockSecretProvider {
    state: Arc<SecretProviderState>,
}

impl VaultSecretProvider for MockSecretProvider {
    fn ensure_agent_secret(&self, secret_name: &str) -> Result<()> {
        self.state
            .generated
            .lock()
            .unwrap()
            .push(secret_name.to_owned());
        Ok(())
    }
}

#[derive(Default)]
struct DriverState {
    init_calls: Mutex<Vec<InitRequest>>,
    mount_calls: Mutex<Vec<MountRequest>>,
    unmount_calls: Mutex<Vec<PathBuf>>,
    is_mounted_calls: Mutex<Vec<PathBuf>>,
    mounted: Mutex<HashSet<PathBuf>>,
    mount_readiness_lag_checks: Mutex<usize>,
    force_unready: Mutex<bool>,
    fail_is_mounted: Mutex<bool>,
    next_pid: AtomicU32,
}

struct MockDriver {
    state: Arc<DriverState>,
}

impl FsEncryptionDriver for MockDriver {
    fn init(&self, request: &InitRequest) -> Result<()> {
        self.state.init_calls.lock().unwrap().push(request.clone());
        Ok(())
    }

    fn mount(&self, request: &MountRequest) -> Result<u32> {
        self.state.mount_calls.lock().unwrap().push(request.clone());
        self.state
            .mounted
            .lock()
            .unwrap()
            .insert(request.mount_point.clone());
        Ok(self.state.next_pid.fetch_add(1, Ordering::Relaxed) + 1000)
    }

    fn unmount(&self, mount_point: &Path) -> Result<()> {
        self.state
            .unmount_calls
            .lock()
            .unwrap()
            .push(mount_point.to_path_buf());
        self.state.mounted.lock().unwrap().remove(mount_point);
        Ok(())
    }

    fn is_mounted(&self, mount_point: &Path) -> Result<bool> {
        if *self.state.fail_is_mounted.lock().unwrap() {
            return Err(GlovesError::Crypto(
                "injected is_mounted failure".to_owned(),
            ));
        }
        self.state
            .is_mounted_calls
            .lock()
            .unwrap()
            .push(mount_point.to_path_buf());
        let is_present = self.state.mounted.lock().unwrap().contains(mount_point);
        if !is_present {
            return Ok(false);
        }
        if *self.state.force_unready.lock().unwrap() {
            return Ok(false);
        }

        let mut lag_checks = self.state.mount_readiness_lag_checks.lock().unwrap();
        if *lag_checks > 0 {
            *lag_checks -= 1;
            return Ok(false);
        }

        Ok(true)
    }
}

fn build_manager() -> (
    VaultManager<MockDriver, MockSecretProvider>,
    tempfile::TempDir,
    Arc<DriverState>,
    Arc<SecretProviderState>,
) {
    let temp_dir = tempfile::tempdir().unwrap();
    let paths = SecretsPaths::new(temp_dir.path());
    let audit = AuditLog::new(temp_dir.path().join("audit.jsonl")).unwrap();
    let driver_state = Arc::new(DriverState::default());
    let secret_provider_state = Arc::new(SecretProviderState::default());
    let manager = VaultManager::new(
        paths,
        MockDriver {
            state: driver_state.clone(),
        },
        MockSecretProvider {
            state: secret_provider_state.clone(),
        },
        AgentId::new("default-agent").unwrap(),
        audit,
    );
    (manager, temp_dir, driver_state, secret_provider_state)
}

fn read_sessions(path: &Path) -> Vec<serde_json::Value> {
    let raw = fs::read_to_string(path).unwrap();
    serde_json::from_str(&raw).unwrap()
}

#[test]
fn vault_init_agent() {
    let (manager, temp_dir, _driver_state, secret_provider_state) = build_manager();
    manager.init("agent_data", Owner::Agent).unwrap();

    assert!(temp_dir.path().join("vaults/agent_data.toml").exists());
    assert_eq!(
        secret_provider_state.generated.lock().unwrap().as_slice(),
        ["vault/agent_data"]
    );
}

#[test]
fn vault_init_human() {
    let (manager, temp_dir, driver_state, secret_provider_state) = build_manager();
    let _ = manager.init("personal", Owner::Human).unwrap();

    assert!(secret_provider_state.generated.lock().unwrap().is_empty());
    let init_calls = driver_state.init_calls.lock().unwrap();
    assert_eq!(init_calls.len(), 1);
    assert_eq!(init_calls[0].extpass_command, "pass show vault/personal");
    assert_eq!(
        init_calls[0].extpass_environment,
        vec![
            (
                "GLOVES_EXTPASS_ROOT".to_owned(),
                temp_dir.path().display().to_string()
            ),
            (
                "GLOVES_EXTPASS_AGENT".to_owned(),
                "default-agent".to_owned()
            ),
        ]
    );
}

#[test]
fn vault_init_rejects_existing_config() {
    let (manager, _temp_dir, driver_state, secret_provider_state) = build_manager();
    manager.init("personal", Owner::Human).unwrap();

    let result = manager.init("personal", Owner::Human);

    assert!(matches!(result, Err(GlovesError::AlreadyExists)));
    assert_eq!(driver_state.init_calls.lock().unwrap().len(), 1);
    assert!(secret_provider_state.generated.lock().unwrap().is_empty());
}

#[test]
fn vault_mount_creates_session() {
    let (manager, temp_dir, _driver_state, _secret_provider_state) = build_manager();
    manager.init("agent_data", Owner::Agent).unwrap();

    manager
        .mount(
            "agent_data",
            Duration::hours(1),
            None,
            AgentId::new("agent-a").unwrap(),
        )
        .unwrap();

    let sessions = read_sessions(&SecretsPaths::new(temp_dir.path()).vault_sessions_file());
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0]["vault_name"], "agent_data");
}

#[test]
fn vault_mount_requires_existing_config() {
    let (manager, _temp_dir, _driver_state, _secret_provider_state) = build_manager();

    let result = manager.mount(
        "missing",
        Duration::minutes(30),
        None,
        AgentId::new("agent-a").unwrap(),
    );

    assert!(matches!(result, Err(GlovesError::NotFound)));
}

#[test]
fn vault_mount_passes_extpass_and_idle_timeout() {
    let (manager, _temp_dir, driver_state, _secret_provider_state) = build_manager();
    manager.init("agent_data", Owner::Agent).unwrap();

    manager
        .mount(
            "agent_data",
            Duration::hours(1),
            None,
            AgentId::new("agent-a").unwrap(),
        )
        .unwrap();

    let mount_calls = driver_state.mount_calls.lock().unwrap();
    assert_eq!(mount_calls.len(), 1);
    assert_eq!(
        mount_calls[0].extpass_command,
        "gloves extpass-get vault/agent_data"
    );
    assert_eq!(
        mount_calls[0].idle_timeout,
        Some(std::time::Duration::from_secs(30 * 60))
    );
    assert_eq!(
        mount_calls[0].extpass_environment,
        vec![
            (
                "GLOVES_EXTPASS_ROOT".to_owned(),
                _temp_dir.path().display().to_string()
            ),
            (
                "GLOVES_EXTPASS_AGENT".to_owned(),
                "default-agent".to_owned()
            ),
        ]
    );
}

#[test]
fn vault_extpass_quotes_paths() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().join("root with 'quote'");
    let paths = SecretsPaths::new(&root);
    let audit = AuditLog::new(root.join("audit.jsonl")).unwrap();
    let driver_state = Arc::new(DriverState::default());
    let secret_provider_state = Arc::new(SecretProviderState::default());
    let manager = VaultManager::new(
        paths,
        MockDriver {
            state: driver_state.clone(),
        },
        MockSecretProvider {
            state: secret_provider_state,
        },
        AgentId::new("default-agent").unwrap(),
        audit,
    );

    manager.init("agent_data", Owner::Agent).unwrap();
    manager
        .mount(
            "agent_data",
            Duration::minutes(30),
            None,
            AgentId::new("agent-a").unwrap(),
        )
        .unwrap();

    let init_calls = driver_state.init_calls.lock().unwrap();
    assert_eq!(
        init_calls[0].extpass_command,
        "gloves extpass-get vault/agent_data"
    );
    assert_eq!(
        init_calls[0].extpass_environment,
        vec![
            ("GLOVES_EXTPASS_ROOT".to_owned(), root.display().to_string()),
            (
                "GLOVES_EXTPASS_AGENT".to_owned(),
                "default-agent".to_owned()
            ),
        ]
    );
}

#[test]
fn vault_mount_idempotent() {
    let (manager, _temp_dir, driver_state, _secret_provider_state) = build_manager();
    manager.init("agent_data", Owner::Agent).unwrap();
    let first = manager
        .mount(
            "agent_data",
            Duration::minutes(30),
            None,
            AgentId::new("agent-a").unwrap(),
        )
        .unwrap();
    let second = manager
        .mount(
            "agent_data",
            Duration::hours(2),
            None,
            AgentId::new("agent-a").unwrap(),
        )
        .unwrap();

    assert!(second.expires_at > first.expires_at);
    assert_eq!(driver_state.mount_calls.lock().unwrap().len(), 1);
}

#[test]
fn vault_mount_waits_for_mountpoint_readiness() {
    const MOUNT_READINESS_LAG_CHECKS: usize = 3;

    let (manager, _temp_dir, driver_state, _secret_provider_state) = build_manager();
    manager.init("agent_data", Owner::Agent).unwrap();
    *driver_state.mount_readiness_lag_checks.lock().unwrap() = MOUNT_READINESS_LAG_CHECKS;

    manager
        .mount(
            "agent_data",
            Duration::minutes(30),
            None,
            AgentId::new("agent-a").unwrap(),
        )
        .unwrap();

    let is_mounted_call_count = driver_state.is_mounted_calls.lock().unwrap().len();
    assert!(is_mounted_call_count > MOUNT_READINESS_LAG_CHECKS);
}

#[test]
fn vault_mount_readiness_failure_cleans_up_mount() {
    let (manager, temp_dir, driver_state, _secret_provider_state) = build_manager();
    manager.init("agent_data", Owner::Agent).unwrap();
    *driver_state.fail_is_mounted.lock().unwrap() = true;

    let result = manager.mount(
        "agent_data",
        Duration::minutes(30),
        None,
        AgentId::new("agent-a").unwrap(),
    );

    assert!(matches!(result, Err(GlovesError::Crypto(_))));
    assert_eq!(driver_state.unmount_calls.lock().unwrap().len(), 0);
    let sessions = read_sessions(&SecretsPaths::new(temp_dir.path()).vault_sessions_file());
    assert!(sessions.is_empty());
}

#[test]
fn vault_mount_timeout_returns_readiness_error() {
    let (manager, _temp_dir, driver_state, _secret_provider_state) = build_manager();
    manager.init("agent_data", Owner::Agent).unwrap();
    *driver_state.force_unready.lock().unwrap() = true;

    let error = manager
        .mount(
            "agent_data",
            Duration::minutes(30),
            None,
            AgentId::new("agent-a").unwrap(),
        )
        .unwrap_err();

    assert!(error
        .to_string()
        .contains("vault mount did not become ready"));
}

#[test]
fn vault_mount_new_mountpoint_unmounts_previous_session() {
    let (manager, temp_dir, driver_state, _secret_provider_state) = build_manager();
    manager.init("agent_data", Owner::Agent).unwrap();
    manager
        .mount(
            "agent_data",
            Duration::minutes(30),
            None,
            AgentId::new("agent-a").unwrap(),
        )
        .unwrap();
    manager
        .mount(
            "agent_data",
            Duration::minutes(30),
            Some(temp_dir.path().join("custom-mount")),
            AgentId::new("agent-a").unwrap(),
        )
        .unwrap();

    assert_eq!(driver_state.mount_calls.lock().unwrap().len(), 2);
    assert_eq!(driver_state.unmount_calls.lock().unwrap().len(), 1);
}

#[test]
fn vault_unmount_removes_session() {
    let (manager, temp_dir, driver_state, _secret_provider_state) = build_manager();
    manager.init("agent_data", Owner::Agent).unwrap();
    manager
        .mount(
            "agent_data",
            Duration::minutes(30),
            None,
            AgentId::new("agent-a").unwrap(),
        )
        .unwrap();

    manager
        .unmount("agent_data", "explicit", AgentId::new("agent-a").unwrap())
        .unwrap();

    let sessions = read_sessions(&SecretsPaths::new(temp_dir.path()).vault_sessions_file());
    assert!(sessions.is_empty());
    assert_eq!(driver_state.unmount_calls.lock().unwrap().len(), 1);
}

#[test]
fn vault_status_shows_remaining() {
    let (manager, _temp_dir, _driver_state, _secret_provider_state) = build_manager();
    manager.init("agent_data", Owner::Agent).unwrap();
    manager
        .mount(
            "agent_data",
            Duration::minutes(30),
            None,
            AgentId::new("agent-a").unwrap(),
        )
        .unwrap();

    let status = manager.status().unwrap();
    let entry = status
        .iter()
        .find(|item| serde_json::to_value(item).unwrap()["name"] == "agent_data")
        .unwrap();
    let value = serde_json::to_value(entry).unwrap();
    assert_eq!(value["mounted"], true);
    assert!(value["remaining_seconds"].as_i64().unwrap_or_default() > 0);
}

#[test]
fn vault_status_marks_initialized_but_unmounted_vaults_as_unmounted() {
    let (manager, _temp_dir, _driver_state, _secret_provider_state) = build_manager();
    manager.init("personal", Owner::Human).unwrap();

    let status = manager.status().unwrap();
    let value = serde_json::to_value(
        status
            .iter()
            .find(|item| serde_json::to_value(item).unwrap()["name"] == "personal")
            .unwrap(),
    )
    .unwrap();

    assert_eq!(value["mounted"], false);
    assert!(value["mountpoint"].is_null());
    assert!(value["remaining_seconds"].is_null());
}

#[test]
fn vault_status_reports_unmounted_when_driver_loses_mount_state() {
    let (manager, _temp_dir, driver_state, _secret_provider_state) = build_manager();
    manager.init("agent_data", Owner::Agent).unwrap();
    manager
        .mount(
            "agent_data",
            Duration::minutes(30),
            None,
            AgentId::new("agent-a").unwrap(),
        )
        .unwrap();
    driver_state.mounted.lock().unwrap().clear();

    let status = manager.status().unwrap();
    let value = serde_json::to_value(
        status
            .iter()
            .find(|item| serde_json::to_value(item).unwrap()["name"] == "agent_data")
            .unwrap(),
    )
    .unwrap();

    assert_eq!(value["mounted"], false);
    assert!(value["mountpoint"].is_null());
    assert!(value["remaining_seconds"].is_null());
}

#[test]
fn vault_list_shows_all() {
    let (manager, _temp_dir, _driver_state, _secret_provider_state) = build_manager();
    manager.init("agent_data", Owner::Agent).unwrap();
    manager.init("personal", Owner::Human).unwrap();

    let entries = manager.list().unwrap();
    assert_eq!(entries.len(), 2);
    assert!(entries
        .iter()
        .any(|item| serde_json::to_value(item).unwrap()["name"] == "agent_data"));
    assert!(entries
        .iter()
        .any(|item| serde_json::to_value(item).unwrap()["name"] == "personal"));
}

#[test]
fn vault_list_and_status_reject_invalid_config_files() {
    let (manager, temp_dir, _driver_state, _secret_provider_state) = build_manager();
    fs::create_dir_all(temp_dir.path().join("vaults")).unwrap();
    fs::write(temp_dir.path().join("vaults/README.txt"), "ignored").unwrap();
    fs::write(
        temp_dir.path().join("vaults/bad.toml"),
        "not valid toml = [",
    )
    .unwrap();

    let list_error = manager.list().unwrap_err();
    let status_error = manager.status().unwrap_err();

    assert!(
        matches!(list_error, GlovesError::InvalidInput(message) if message.contains("invalid vault config"))
    );
    assert!(
        matches!(status_error, GlovesError::InvalidInput(message) if message.contains("invalid vault config"))
    );
}

#[test]
fn vault_unmount_rejects_missing_session() {
    let (manager, _temp_dir, _driver_state, _secret_provider_state) = build_manager();
    manager.init("agent_data", Owner::Agent).unwrap();

    let result = manager.unmount("agent_data", "explicit", AgentId::new("agent-a").unwrap());

    assert!(matches!(result, Err(GlovesError::NotFound)));
}

#[test]
fn vault_unmount_skips_driver_when_mountpoint_is_already_gone() {
    let (manager, temp_dir, driver_state, _secret_provider_state) = build_manager();
    manager.init("agent_data", Owner::Agent).unwrap();
    manager
        .mount(
            "agent_data",
            Duration::minutes(30),
            None,
            AgentId::new("agent-a").unwrap(),
        )
        .unwrap();
    driver_state.mounted.lock().unwrap().clear();

    manager
        .unmount("agent_data", "explicit", AgentId::new("agent-a").unwrap())
        .unwrap();

    let sessions = read_sessions(&SecretsPaths::new(temp_dir.path()).vault_sessions_file());
    assert!(sessions.is_empty());
    assert!(driver_state.unmount_calls.lock().unwrap().is_empty());
}

#[test]
fn vault_ask_file_prompt_requires_trusted_agent_access() {
    let (manager, _temp_dir, _driver_state, _secret_provider_state) = build_manager();
    manager.init("agent_data", Owner::Agent).unwrap();
    manager
        .mount(
            "agent_data",
            Duration::minutes(30),
            None,
            AgentId::new("agent-b").unwrap(),
        )
        .unwrap();

    let prompt = manager
        .ask_file_prompt(
            "agent_data",
            "docs/notes.txt",
            AgentId::new("agent-a").unwrap(),
            AgentId::new("agent-b").unwrap(),
            Some("Need this file for task handoff".to_owned()),
        )
        .unwrap();

    assert!(prompt.contains("Agent handoff request"));
    assert!(prompt.contains("Requester: agent-a"));
    assert!(prompt.contains("Trusted agent: agent-b"));
    assert!(prompt.contains("Requested file: docs/notes.txt"));
}

#[test]
fn vault_ask_file_prompt_ignores_unrelated_sessions_before_succeeding() {
    let (manager, temp_dir, driver_state, _secret_provider_state) = build_manager();
    manager.init("agent_data", Owner::Agent).unwrap();
    manager.init("other_data", Owner::Agent).unwrap();

    let unrelated_mount = temp_dir.path().join("mounts/other_data");
    let wrong_agent_mount = temp_dir.path().join("mounts/agent_data-wrong");
    let trusted_mount = temp_dir.path().join("mounts/agent_data");
    driver_state.mounted.lock().unwrap().extend([
        unrelated_mount.clone(),
        wrong_agent_mount.clone(),
        trusted_mount.clone(),
    ]);

    fs::write(
        SecretsPaths::new(temp_dir.path()).vault_sessions_file(),
        serde_json::to_vec_pretty(&vec![
            serde_json::json!({
                "vault_name": "other_data",
                "mountpoint": unrelated_mount,
                "mounted_at": Utc::now(),
                "expires_at": Utc::now() + Duration::hours(1),
                "pid": 1001,
                "mounted_by": "trusted-agent",
            }),
            serde_json::json!({
                "vault_name": "agent_data",
                "mountpoint": wrong_agent_mount,
                "mounted_at": Utc::now(),
                "expires_at": Utc::now() + Duration::hours(1),
                "pid": 1002,
                "mounted_by": "other-agent",
            }),
            serde_json::json!({
                "vault_name": "agent_data",
                "mountpoint": trusted_mount,
                "mounted_at": Utc::now(),
                "expires_at": Utc::now() + Duration::hours(1),
                "pid": 1003,
                "mounted_by": "trusted-agent",
            }),
        ])
        .unwrap(),
    )
    .unwrap();

    let prompt = manager
        .ask_file_prompt(
            "agent_data",
            "notes/todo.txt",
            AgentId::new("requester-agent").unwrap(),
            AgentId::new("trusted-agent").unwrap(),
            None,
        )
        .unwrap();

    assert!(prompt.contains("Vault: agent_data"));
    assert!(!prompt.contains("Reason:"));
}

#[test]
fn vault_ask_file_prompt_rejects_stale_mount_session() {
    let (manager, _temp_dir, driver_state, _secret_provider_state) = build_manager();
    manager.init("agent_data", Owner::Agent).unwrap();
    manager
        .mount(
            "agent_data",
            Duration::minutes(30),
            None,
            AgentId::new("agent-b").unwrap(),
        )
        .unwrap();
    driver_state.mounted.lock().unwrap().clear();

    let result = manager.ask_file_prompt(
        "agent_data",
        "docs/notes.txt",
        AgentId::new("agent-a").unwrap(),
        AgentId::new("agent-b").unwrap(),
        None,
    );

    assert!(matches!(result, Err(GlovesError::Forbidden)));
}

#[test]
fn vault_ask_file_prompt_rejects_expired_trusted_session() {
    let (manager, temp_dir, _driver_state, _secret_provider_state) = build_manager();
    manager.init("agent_data", Owner::Agent).unwrap();
    manager
        .mount(
            "agent_data",
            Duration::minutes(30),
            None,
            AgentId::new("agent-b").unwrap(),
        )
        .unwrap();

    let sessions_path = SecretsPaths::new(temp_dir.path()).vault_sessions_file();
    let mut sessions = read_sessions(&sessions_path);
    sessions[0]["expires_at"] = serde_json::json!((Utc::now() - Duration::minutes(1)).to_rfc3339());
    fs::write(
        &sessions_path,
        serde_json::to_string_pretty(&sessions).unwrap(),
    )
    .unwrap();

    let result = manager.ask_file_prompt(
        "agent_data",
        "docs/notes.txt",
        AgentId::new("agent-a").unwrap(),
        AgentId::new("agent-b").unwrap(),
        None,
    );

    assert!(matches!(result, Err(GlovesError::Forbidden)));
}

#[test]
fn vault_ask_file_prompt_fails_without_access() {
    let (manager, _temp_dir, _driver_state, _secret_provider_state) = build_manager();
    manager.init("agent_data", Owner::Agent).unwrap();

    let result = manager.ask_file_prompt(
        "agent_data",
        "docs/notes.txt",
        AgentId::new("agent-a").unwrap(),
        AgentId::new("agent-b").unwrap(),
        None,
    );

    assert!(matches!(result, Err(GlovesError::Forbidden)));
}

#[test]
fn vault_ask_file_prompt_rejects_traversal() {
    let (manager, _temp_dir, _driver_state, _secret_provider_state) = build_manager();
    manager.init("agent_data", Owner::Agent).unwrap();
    manager
        .mount(
            "agent_data",
            Duration::minutes(30),
            None,
            AgentId::new("agent-b").unwrap(),
        )
        .unwrap();

    let result = manager.ask_file_prompt(
        "agent_data",
        "../secrets.txt",
        AgentId::new("agent-a").unwrap(),
        AgentId::new("agent-b").unwrap(),
        None,
    );

    assert!(matches!(result, Err(GlovesError::InvalidInput(_))));
}
