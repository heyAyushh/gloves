use chrono::{Duration, Utc};
use gloves::{
    types::{AgentId, Owner},
    vault::{config::VaultConfigFile, session::VaultSession},
};
use std::path::PathBuf;

#[test]
fn vault_config_roundtrip() {
    let config = VaultConfigFile::new(
        "agent_data".to_owned(),
        Owner::Agent,
        PathBuf::from("/tmp/cipher"),
        PathBuf::from("/tmp/mount"),
        "vault/agent_data".to_owned(),
        Utc::now(),
    );

    let encoded = toml::to_string(&config).unwrap();
    let decoded: VaultConfigFile = toml::from_str(&encoded).unwrap();
    assert_eq!(decoded, config);
}

#[test]
fn vault_session_roundtrip() {
    let session = VaultSession {
        vault_name: "agent_data".to_owned(),
        mountpoint: PathBuf::from("/tmp/mount"),
        mounted_at: Utc::now() - Duration::minutes(5),
        expires_at: Utc::now() + Duration::minutes(55),
        pid: 42,
        mounted_by: AgentId::new("agent-a").unwrap(),
    };

    let encoded = serde_json::to_string(&session).unwrap();
    let decoded: VaultSession = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, session);
}

#[test]
fn vault_session_expired() {
    let session = VaultSession {
        vault_name: "agent_data".to_owned(),
        mountpoint: PathBuf::from("/tmp/mount"),
        mounted_at: Utc::now() - Duration::minutes(10),
        expires_at: Utc::now() - Duration::seconds(1),
        pid: 42,
        mounted_by: AgentId::new("agent-a").unwrap(),
    };

    assert!(session.is_expired(Utc::now()));
}

#[test]
fn vault_session_active() {
    let session = VaultSession {
        vault_name: "agent_data".to_owned(),
        mountpoint: PathBuf::from("/tmp/mount"),
        mounted_at: Utc::now() - Duration::minutes(10),
        expires_at: Utc::now() + Duration::seconds(1),
        pid: 42,
        mounted_by: AgentId::new("agent-a").unwrap(),
    };

    assert!(!session.is_expired(Utc::now()));
}
