use gloves::{
    agent::keys::{derive_agent_key, load_or_create_salt},
    types::AgentId,
};
use std::os::unix::fs::PermissionsExt;

#[test]
fn derive_deterministic() {
    let key_a = derive_agent_key(
        b"master",
        b"01234567890123456789012345678901",
        &AgentId::new("agent-a").unwrap(),
        "vm-1",
    )
    .unwrap();
    let key_b = derive_agent_key(
        b"master",
        b"01234567890123456789012345678901",
        &AgentId::new("agent-a").unwrap(),
        "vm-1",
    )
    .unwrap();
    assert_eq!(key_a, key_b);
}

#[test]
fn derive_different_salt() {
    let key_a = derive_agent_key(
        b"master",
        b"01234567890123456789012345678901",
        &AgentId::new("agent-a").unwrap(),
        "vm-1",
    )
    .unwrap();
    let key_b = derive_agent_key(
        b"master",
        b"abcdefghijabcdefghijabcdefghij12",
        &AgentId::new("agent-a").unwrap(),
        "vm-1",
    )
    .unwrap();
    assert_ne!(key_a, key_b);
}

#[test]
fn derive_different_agent() {
    let key_a = derive_agent_key(
        b"master",
        b"01234567890123456789012345678901",
        &AgentId::new("agent-a").unwrap(),
        "vm-1",
    )
    .unwrap();
    let key_b = derive_agent_key(
        b"master",
        b"01234567890123456789012345678901",
        &AgentId::new("agent-b").unwrap(),
        "vm-1",
    )
    .unwrap();
    assert_ne!(key_a, key_b);
}

#[test]
fn derive_different_vm() {
    let key_a = derive_agent_key(
        b"master",
        b"01234567890123456789012345678901",
        &AgentId::new("agent-a").unwrap(),
        "vm-1",
    )
    .unwrap();
    let key_b = derive_agent_key(
        b"master",
        b"01234567890123456789012345678901",
        &AgentId::new("agent-a").unwrap(),
        "vm-2",
    )
    .unwrap();
    assert_ne!(key_a, key_b);
}

#[test]
fn salt_init_creates_file() {
    let temp_dir = tempfile::tempdir().unwrap();
    let salt_path = temp_dir.path().join("derived.salt");
    let salt = load_or_create_salt(&salt_path).unwrap();
    assert_eq!(salt.len(), 32);
    assert!(salt_path.exists());
    assert_eq!(std::fs::read(&salt_path).unwrap().len(), 32);
}

#[test]
fn salt_init_idempotent() {
    let temp_dir = tempfile::tempdir().unwrap();
    let salt_path = temp_dir.path().join("derived.salt");
    let first = load_or_create_salt(&salt_path).unwrap();
    let second = load_or_create_salt(&salt_path).unwrap();
    assert_eq!(first, second);
}

#[test]
fn salt_invalid_length_fails() {
    let temp_dir = tempfile::tempdir().unwrap();
    let salt_path = temp_dir.path().join("derived.salt");
    std::fs::write(&salt_path, [1_u8; 16]).unwrap();
    assert!(load_or_create_salt(&salt_path).is_err());
}

#[test]
fn salt_permissions_0600() {
    let temp_dir = tempfile::tempdir().unwrap();
    let salt_path = temp_dir.path().join("derived.salt");
    load_or_create_salt(&salt_path).unwrap();
    let mode = std::fs::metadata(&salt_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}
