use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

use chrono::{Duration, Utc};
use gloves::{
    audit::AuditLog,
    paths::SecretsPaths,
    reaper::TtlReaper,
    types::AgentId,
    vault::{
        gocryptfs::{FsEncryptionDriver, InitRequest, MountRequest},
        session::VaultSession,
    },
};

#[derive(Default)]
struct MockDriver {
    mounted: Mutex<HashSet<PathBuf>>,
    unmount_calls: Mutex<Vec<PathBuf>>,
}

impl FsEncryptionDriver for MockDriver {
    fn init(&self, _request: &InitRequest) -> gloves::error::Result<()> {
        Ok(())
    }

    fn mount(&self, _request: &MountRequest) -> gloves::error::Result<u32> {
        Ok(1000)
    }

    fn unmount(&self, mount_point: &Path) -> gloves::error::Result<()> {
        self.unmount_calls
            .lock()
            .unwrap()
            .push(mount_point.to_path_buf());
        self.mounted.lock().unwrap().remove(mount_point);
        Ok(())
    }

    fn is_mounted(&self, mount_point: &Path) -> gloves::error::Result<bool> {
        Ok(self.mounted.lock().unwrap().contains(mount_point))
    }
}

fn write_sessions(path: &Path, sessions: &[VaultSession]) {
    let payload = serde_json::to_vec_pretty(sessions).unwrap();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, payload).unwrap();
}

fn read_sessions(path: &Path) -> Vec<serde_json::Value> {
    let raw = fs::read_to_string(path).unwrap();
    serde_json::from_str(&raw).unwrap()
}

#[test]
fn reaper_unmounts_expired_session() {
    let temp_dir = tempfile::tempdir().unwrap();
    let paths = SecretsPaths::new(temp_dir.path());
    let audit = AuditLog::new(temp_dir.path().join("audit.jsonl")).unwrap();
    let driver = MockDriver::default();
    let mountpoint = temp_dir.path().join("mnt/agent_data");
    driver.mounted.lock().unwrap().insert(mountpoint.clone());

    write_sessions(
        &paths.vault_sessions_file(),
        &[VaultSession {
            vault_name: "agent_data".to_owned(),
            mountpoint: mountpoint.clone(),
            mounted_at: Utc::now() - Duration::hours(2),
            expires_at: Utc::now() - Duration::minutes(1),
            pid: 1000,
            mounted_by: AgentId::new("agent-a").unwrap(),
        }],
    );

    TtlReaper::reap_vault_sessions(&driver, &paths, &audit).unwrap();

    assert_eq!(
        driver.unmount_calls.lock().unwrap().as_slice(),
        [mountpoint]
    );
    assert!(read_sessions(&paths.vault_sessions_file()).is_empty());
}

#[test]
fn reaper_ignores_active_session() {
    let temp_dir = tempfile::tempdir().unwrap();
    let paths = SecretsPaths::new(temp_dir.path());
    let audit = AuditLog::new(temp_dir.path().join("audit.jsonl")).unwrap();
    let driver = MockDriver::default();
    let mountpoint = temp_dir.path().join("mnt/agent_data");
    driver.mounted.lock().unwrap().insert(mountpoint.clone());

    write_sessions(
        &paths.vault_sessions_file(),
        &[VaultSession {
            vault_name: "agent_data".to_owned(),
            mountpoint: mountpoint.clone(),
            mounted_at: Utc::now() - Duration::minutes(1),
            expires_at: Utc::now() + Duration::minutes(30),
            pid: 1000,
            mounted_by: AgentId::new("agent-a").unwrap(),
        }],
    );

    TtlReaper::reap_vault_sessions(&driver, &paths, &audit).unwrap();

    assert!(driver.unmount_calls.lock().unwrap().is_empty());
    assert_eq!(read_sessions(&paths.vault_sessions_file()).len(), 1);
}

#[test]
fn reaper_logs_vault_expired() {
    let temp_dir = tempfile::tempdir().unwrap();
    let paths = SecretsPaths::new(temp_dir.path());
    let audit = AuditLog::new(temp_dir.path().join("audit.jsonl")).unwrap();
    let driver = MockDriver::default();

    write_sessions(
        &paths.vault_sessions_file(),
        &[VaultSession {
            vault_name: "agent_data".to_owned(),
            mountpoint: temp_dir.path().join("mnt/agent_data"),
            mounted_at: Utc::now() - Duration::hours(2),
            expires_at: Utc::now() - Duration::minutes(1),
            pid: 1000,
            mounted_by: AgentId::new("agent-a").unwrap(),
        }],
    );

    TtlReaper::reap_vault_sessions(&driver, &paths, &audit).unwrap();

    let text = std::fs::read_to_string(audit.path()).unwrap();
    assert!(text.contains("vault_session_expired"));
}

#[test]
fn reaper_handles_already_unmounted() {
    let temp_dir = tempfile::tempdir().unwrap();
    let paths = SecretsPaths::new(temp_dir.path());
    let audit = AuditLog::new(temp_dir.path().join("audit.jsonl")).unwrap();
    let driver = MockDriver::default();

    write_sessions(
        &paths.vault_sessions_file(),
        &[VaultSession {
            vault_name: "agent_data".to_owned(),
            mountpoint: temp_dir.path().join("mnt/agent_data"),
            mounted_at: Utc::now() - Duration::hours(2),
            expires_at: Utc::now() - Duration::minutes(1),
            pid: 1000,
            mounted_by: AgentId::new("agent-a").unwrap(),
        }],
    );

    TtlReaper::reap_vault_sessions(&driver, &paths, &audit).unwrap();

    assert!(driver.unmount_calls.lock().unwrap().is_empty());
    assert!(read_sessions(&paths.vault_sessions_file()).is_empty());
}
