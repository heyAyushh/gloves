use std::collections::HashSet;

use chrono::{Duration, Utc};
use gloves::{
    agent::meta::MetadataStore,
    registry::AgentRegistry,
    types::{AgentId, Owner, SecretId, SecretMeta},
};

#[test]
fn meta_save_load_roundtrip() {
    let temp_dir = tempfile::tempdir().unwrap();
    let store = MetadataStore::new(temp_dir.path()).unwrap();

    let secret_id = SecretId::new("api/token").unwrap();
    let mut recipients = HashSet::new();
    recipients.insert(AgentId::new("agent-a").unwrap());
    let meta = SecretMeta {
        id: secret_id.clone(),
        owner: Owner::Agent,
        created_at: Utc::now(),
        expires_at: Utc::now() + Duration::hours(1),
        recipients,
        created_by: AgentId::new("agent-a").unwrap(),
        last_accessed: None,
        access_count: 0,
        checksum: "abc".to_owned(),
    };

    store.save(&meta).unwrap();
    let loaded = store.load(&secret_id).unwrap();
    assert_eq!(loaded.id, meta.id);
    assert_eq!(loaded.owner, meta.owner);
    assert_eq!(loaded.created_by, meta.created_by);
}

#[test]
fn registry_register_lookup() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mut registry =
        AgentRegistry::load_or_create(temp_dir.path().join("registry.json"), b"hmac-key").unwrap();

    let agent_id = AgentId::new("agent-a").unwrap();
    registry
        .register(agent_id.clone(), "age1publickey".to_owned(), Some(agent_id.clone()))
        .unwrap();

    assert_eq!(registry.get_pubkey(&agent_id), Some("age1publickey"));
}

#[test]
fn registry_reject_duplicate() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mut registry =
        AgentRegistry::load_or_create(temp_dir.path().join("registry.json"), b"hmac-key").unwrap();

    let agent_id = AgentId::new("agent-a").unwrap();
    registry
        .register(agent_id.clone(), "age1publickey".to_owned(), Some(agent_id.clone()))
        .unwrap();
    assert!(registry
        .register(agent_id, "age1other".to_owned(), Some(AgentId::new("agent-a").unwrap()))
        .is_err());
}

#[test]
fn registry_hmac_valid() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("registry.json");
    let mut registry = AgentRegistry::load_or_create(&path, b"hmac-key").unwrap();
    let agent_id = AgentId::new("agent-a").unwrap();
    registry
        .register(agent_id.clone(), "age1publickey".to_owned(), Some(agent_id))
        .unwrap();

    let loaded = AgentRegistry::load_or_create(&path, b"hmac-key").unwrap();
    assert!(loaded.verify_integrity());
}

#[test]
fn registry_hmac_tampered() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("registry.json");
    let mut registry = AgentRegistry::load_or_create(&path, b"hmac-key").unwrap();
    let agent_id = AgentId::new("agent-a").unwrap();
    registry
        .register(agent_id.clone(), "age1publickey".to_owned(), Some(agent_id))
        .unwrap();

    let mut value: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    value["entries"]["agent-a"] = serde_json::Value::String("tampered".to_owned());
    std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();

    let loaded = AgentRegistry::load_or_create(&path, b"hmac-key").unwrap();
    assert!(!loaded.verify_integrity());
}

#[test]
fn registry_voucher_required() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mut registry =
        AgentRegistry::load_or_create(temp_dir.path().join("registry.json"), b"hmac-key").unwrap();

    let first = AgentId::new("agent-a").unwrap();
    registry
        .register(first.clone(), "age1publickey".to_owned(), Some(first.clone()))
        .unwrap();

    assert!(registry
        .register(AgentId::new("agent-b").unwrap(), "age1second".to_owned(), None)
        .is_err());
}

#[test]
fn registry_first_agent_bootstrap() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mut registry =
        AgentRegistry::load_or_create(temp_dir.path().join("registry.json"), b"hmac-key").unwrap();

    let first = AgentId::new("agent-a").unwrap();
    assert!(registry
        .register(first.clone(), "age1publickey".to_owned(), Some(first))
        .is_ok());
}
