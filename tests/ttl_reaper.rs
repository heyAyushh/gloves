mod common;

use std::{collections::HashSet, fs};

use chrono::{Duration, Utc};
use common::generate_identity;
use gloves::{
    agent::{backend::AgentBackend, meta::MetadataStore},
    audit::AuditLog,
    reaper::{secure_delete_file, TtlReaper},
    types::{AgentId, Owner, SecretId, SecretMeta, SecretValue},
};

#[test]
fn reaps_expired() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = AgentBackend::new(temp_dir.path().join("store")).unwrap();
    let meta_store = MetadataStore::new(temp_dir.path().join("meta")).unwrap();
    let audit = AuditLog::new(temp_dir.path().join("audit.jsonl")).unwrap();

    let secret_id = SecretId::new("expired").unwrap();
    let identity = generate_identity(temp_dir.path(), "agent-a");
    backend
        .encrypt(
            &secret_id,
            &SecretValue::new(b"old".to_vec()),
            vec![identity.recipient],
        )
        .unwrap();

    let mut recipients = HashSet::new();
    recipients.insert(AgentId::new("agent-a").unwrap());
    meta_store
        .save(&SecretMeta {
            id: secret_id.clone(),
            owner: Owner::Agent,
            created_at: Utc::now() - Duration::days(2),
            expires_at: Utc::now() - Duration::days(1),
            recipients,
            created_by: AgentId::new("agent-a").unwrap(),
            last_accessed: None,
            access_count: 0,
            checksum: String::new(),
        })
        .unwrap();

    TtlReaper::reap(&backend, &meta_store, &audit).unwrap();

    assert!(!backend.ciphertext_path(&secret_id).exists());
    assert!(meta_store.load(&secret_id).is_err());
}

#[test]
fn keeps_valid() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = AgentBackend::new(temp_dir.path().join("store")).unwrap();
    let meta_store = MetadataStore::new(temp_dir.path().join("meta")).unwrap();
    let audit = AuditLog::new(temp_dir.path().join("audit.jsonl")).unwrap();

    let secret_id = SecretId::new("valid").unwrap();
    let identity = generate_identity(temp_dir.path(), "agent-a");
    backend
        .encrypt(
            &secret_id,
            &SecretValue::new(b"new".to_vec()),
            vec![identity.recipient],
        )
        .unwrap();

    let mut recipients = HashSet::new();
    recipients.insert(AgentId::new("agent-a").unwrap());
    meta_store
        .save(&SecretMeta {
            id: secret_id.clone(),
            owner: Owner::Agent,
            created_at: Utc::now() - Duration::hours(1),
            expires_at: Utc::now() + Duration::days(1),
            recipients,
            created_by: AgentId::new("agent-a").unwrap(),
            last_accessed: None,
            access_count: 0,
            checksum: String::new(),
        })
        .unwrap();

    TtlReaper::reap(&backend, &meta_store, &audit).unwrap();

    assert!(backend.ciphertext_path(&secret_id).exists());
    assert!(meta_store.load(&secret_id).is_ok());
}

#[test]
fn logs_expiry_event() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = AgentBackend::new(temp_dir.path().join("store")).unwrap();
    let meta_store = MetadataStore::new(temp_dir.path().join("meta")).unwrap();
    let audit = AuditLog::new(temp_dir.path().join("audit.jsonl")).unwrap();

    let secret_id = SecretId::new("expired").unwrap();
    let identity = generate_identity(temp_dir.path(), "agent-a");
    backend
        .encrypt(
            &secret_id,
            &SecretValue::new(b"old".to_vec()),
            vec![identity.recipient],
        )
        .unwrap();

    let mut recipients = HashSet::new();
    recipients.insert(AgentId::new("agent-a").unwrap());
    meta_store
        .save(&SecretMeta {
            id: secret_id,
            owner: Owner::Agent,
            created_at: Utc::now() - Duration::days(2),
            expires_at: Utc::now() - Duration::days(1),
            recipients,
            created_by: AgentId::new("agent-a").unwrap(),
            last_accessed: None,
            access_count: 0,
            checksum: String::new(),
        })
        .unwrap();

    TtlReaper::reap(&backend, &meta_store, &audit).unwrap();
    let text = fs::read_to_string(audit.path()).unwrap();
    assert!(text.contains("secret_expired"));
}

#[test]
fn handles_empty_dir() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = AgentBackend::new(temp_dir.path().join("store")).unwrap();
    let meta_store = MetadataStore::new(temp_dir.path().join("meta")).unwrap();
    let audit = AuditLog::new(temp_dir.path().join("audit.jsonl")).unwrap();

    assert!(TtlReaper::reap(&backend, &meta_store, &audit).is_ok());
}

#[test]
fn secure_delete_zeroes() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("to_delete.bin");
    fs::write(&path, b"erase-me").unwrap();

    secure_delete_file(&path).unwrap();
    assert!(!path.exists());
}

#[test]
fn secure_delete_missing_file_is_ok() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("missing.bin");
    secure_delete_file(&path).unwrap();
}

#[test]
fn secure_delete_large_file_is_ok() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("large.bin");
    fs::write(&path, vec![1_u8; 128 * 1024]).unwrap();

    secure_delete_file(&path).unwrap();
    assert!(!path.exists());
}
