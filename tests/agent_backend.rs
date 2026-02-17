mod common;

use std::io::Write;
use std::os::unix::fs::PermissionsExt;

use common::generate_identity;
use gloves::{
    agent::backend::AgentBackend,
    error::GlovesError,
    types::{SecretId, SecretValue},
};

#[test]
fn encrypt_decrypt_roundtrip() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = AgentBackend::new(temp_dir.path()).unwrap();
    let secret_id = SecretId::new("db/password").unwrap();

    let identity = generate_identity(temp_dir.path(), "agent-a");
    backend
        .encrypt(
            &secret_id,
            &SecretValue::new(b"hunter2".to_vec()),
            vec![identity.recipient],
        )
        .unwrap();

    let decrypted = backend
        .decrypt(&secret_id, identity.identity_file.as_path())
        .unwrap();
    let value = decrypted.expose(|bytes| bytes.to_vec());
    assert_eq!(value, b"hunter2");
}

#[test]
fn decrypt_wrong_key_fails() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = AgentBackend::new(temp_dir.path()).unwrap();
    let secret_id = SecretId::new("db/password").unwrap();

    let identity = generate_identity(temp_dir.path(), "agent-a");
    backend
        .encrypt(
            &secret_id,
            &SecretValue::new(b"hunter2".to_vec()),
            vec![identity.recipient],
        )
        .unwrap();

    let outsider = generate_identity(temp_dir.path(), "agent-b");
    assert!(backend
        .decrypt(&secret_id, outsider.identity_file.as_path())
        .is_err());
}

#[test]
fn multi_recipient_both_decrypt() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = AgentBackend::new(temp_dir.path()).unwrap();
    let secret_id = SecretId::new("shared").unwrap();

    let identity_a = generate_identity(temp_dir.path(), "agent-a");
    let identity_b = generate_identity(temp_dir.path(), "agent-b");

    backend
        .encrypt(
            &secret_id,
            &SecretValue::new(b"top-secret".to_vec()),
            vec![identity_a.recipient.clone(), identity_b.recipient.clone()],
        )
        .unwrap();

    let value_a = backend
        .decrypt(&secret_id, identity_a.identity_file.as_path())
        .unwrap();
    let value_b = backend
        .decrypt(&secret_id, identity_b.identity_file.as_path())
        .unwrap();
    assert_eq!(value_a.expose(|bytes| bytes.to_vec()), b"top-secret");
    assert_eq!(value_b.expose(|bytes| bytes.to_vec()), b"top-secret");
}

#[test]
fn multi_recipient_outsider_fails() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = AgentBackend::new(temp_dir.path()).unwrap();
    let secret_id = SecretId::new("shared").unwrap();

    let identity_a = generate_identity(temp_dir.path(), "agent-a");
    let identity_b = generate_identity(temp_dir.path(), "agent-b");

    backend
        .encrypt(
            &secret_id,
            &SecretValue::new(b"top-secret".to_vec()),
            vec![identity_a.recipient, identity_b.recipient],
        )
        .unwrap();

    let outsider = generate_identity(temp_dir.path(), "outsider");
    assert!(backend
        .decrypt(&secret_id, outsider.identity_file.as_path())
        .is_err());
}

#[test]
fn encrypt_creates_age_file() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = AgentBackend::new(temp_dir.path()).unwrap();
    let secret_id = SecretId::new("db/password").unwrap();

    let identity = generate_identity(temp_dir.path(), "agent-a");
    backend
        .encrypt(
            &secret_id,
            &SecretValue::new(b"hunter2".to_vec()),
            vec![identity.recipient],
        )
        .unwrap();

    assert!(backend.ciphertext_path(&secret_id).exists());
}

#[test]
fn encrypt_no_overwrite() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = AgentBackend::new(temp_dir.path()).unwrap();
    let secret_id = SecretId::new("db/password").unwrap();

    let identity = generate_identity(temp_dir.path(), "agent-a");
    backend
        .encrypt(
            &secret_id,
            &SecretValue::new(b"hunter2".to_vec()),
            vec![identity.recipient.clone()],
        )
        .unwrap();

    assert!(backend
        .encrypt(
            &secret_id,
            &SecretValue::new(b"other".to_vec()),
            vec![identity.recipient],
        )
        .is_err());
}

#[test]
fn grant_adds_recipient() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = AgentBackend::new(temp_dir.path()).unwrap();
    let secret_id = SecretId::new("shared").unwrap();

    let creator = generate_identity(temp_dir.path(), "creator");
    let new_user = generate_identity(temp_dir.path(), "new-user");

    backend
        .encrypt(
            &secret_id,
            &SecretValue::new(b"rotate-me".to_vec()),
            vec![creator.recipient.clone()],
        )
        .unwrap();
    assert!(backend
        .decrypt(&secret_id, new_user.identity_file.as_path())
        .is_err());

    backend
        .grant(
            &secret_id,
            creator.identity_file.as_path(),
            vec![creator.recipient, new_user.recipient],
        )
        .unwrap();

    let decrypted = backend
        .decrypt(&secret_id, new_user.identity_file.as_path())
        .unwrap();
    assert_eq!(decrypted.expose(|bytes| bytes.to_vec()), b"rotate-me");
}

#[test]
fn file_permissions_0600() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = AgentBackend::new(temp_dir.path()).unwrap();
    let secret_id = SecretId::new("db/password").unwrap();

    let identity = generate_identity(temp_dir.path(), "agent-a");
    backend
        .encrypt(
            &secret_id,
            &SecretValue::new(b"hunter2".to_vec()),
            vec![identity.recipient],
        )
        .unwrap();

    let mode = std::fs::metadata(backend.ciphertext_path(&secret_id))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn encrypt_without_recipients_fails() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = AgentBackend::new(temp_dir.path()).unwrap();
    let secret_id = SecretId::new("db/password").unwrap();

    assert!(backend
        .encrypt(&secret_id, &SecretValue::new(b"hunter2".to_vec()), vec![])
        .is_err());
}

#[test]
fn ciphertext_checksum_changes_after_grant() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = AgentBackend::new(temp_dir.path()).unwrap();
    let secret_id = SecretId::new("shared").unwrap();
    let creator = generate_identity(temp_dir.path(), "creator");

    backend
        .encrypt(
            &secret_id,
            &SecretValue::new(b"rotate-me".to_vec()),
            vec![creator.recipient.clone()],
        )
        .unwrap();
    let before = backend.ciphertext_checksum(&secret_id).unwrap();

    let second = generate_identity(temp_dir.path(), "second");
    backend
        .grant(
            &secret_id,
            creator.identity_file.as_path(),
            vec![creator.recipient, second.recipient],
        )
        .unwrap();
    let after = backend.ciphertext_checksum(&secret_id).unwrap();

    assert_ne!(before, after);
}

#[test]
fn delete_missing_is_ok() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = AgentBackend::new(temp_dir.path()).unwrap();
    let secret_id = SecretId::new("db/missing").unwrap();
    backend.delete(&secret_id).unwrap();
}

#[test]
fn decrypt_invalid_ciphertext_fails() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = AgentBackend::new(temp_dir.path()).unwrap();
    let secret_id = SecretId::new("db/invalid").unwrap();

    let identity = generate_identity(temp_dir.path(), "agent-a");
    let output_path = backend.ciphertext_path(&secret_id);
    std::fs::create_dir_all(output_path.parent().unwrap()).unwrap();
    let mut ciphertext = Vec::new();
    ciphertext.write_all(b"invalid-ciphertext").unwrap();
    std::fs::write(output_path, ciphertext).unwrap();

    assert!(matches!(
        backend.decrypt(&secret_id, identity.identity_file.as_path()),
        Err(GlovesError::Crypto(_))
    ));
}
