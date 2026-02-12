use std::os::unix::fs::PermissionsExt;

use gloves::{
    agent::backend::{identity_recipient, AgentBackend},
    types::{SecretId, SecretValue},
};

#[test]
fn encrypt_decrypt_roundtrip() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = AgentBackend::new(temp_dir.path()).unwrap();
    let secret_id = SecretId::new("db/password").unwrap();

    let identity = age::x25519::Identity::generate();
    let recipient = identity_recipient(&identity);
    backend
        .encrypt(&secret_id, &SecretValue::new(b"hunter2".to_vec()), vec![recipient])
        .unwrap();

    let decrypted = backend.decrypt(&secret_id, vec![identity]).unwrap();
    let value = decrypted.expose(|bytes| bytes.to_vec());
    assert_eq!(value, b"hunter2");
}

#[test]
fn decrypt_wrong_key_fails() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = AgentBackend::new(temp_dir.path()).unwrap();
    let secret_id = SecretId::new("db/password").unwrap();

    let identity = age::x25519::Identity::generate();
    backend
        .encrypt(
            &secret_id,
            &SecretValue::new(b"hunter2".to_vec()),
            vec![identity_recipient(&identity)],
        )
        .unwrap();

    let outsider = age::x25519::Identity::generate();
    assert!(backend.decrypt(&secret_id, vec![outsider]).is_err());
}

#[test]
fn multi_recipient_both_decrypt() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = AgentBackend::new(temp_dir.path()).unwrap();
    let secret_id = SecretId::new("shared").unwrap();

    let identity_a = age::x25519::Identity::generate();
    let identity_b = age::x25519::Identity::generate();

    backend
        .encrypt(
            &secret_id,
            &SecretValue::new(b"top-secret".to_vec()),
            vec![identity_recipient(&identity_a), identity_recipient(&identity_b)],
        )
        .unwrap();

    let a = backend.decrypt(&secret_id, vec![identity_a]).unwrap();
    let b = backend.decrypt(&secret_id, vec![identity_b]).unwrap();
    assert_eq!(a.expose(|bytes| bytes.to_vec()), b"top-secret");
    assert_eq!(b.expose(|bytes| bytes.to_vec()), b"top-secret");
}

#[test]
fn multi_recipient_outsider_fails() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = AgentBackend::new(temp_dir.path()).unwrap();
    let secret_id = SecretId::new("shared").unwrap();

    let identity_a = age::x25519::Identity::generate();
    let identity_b = age::x25519::Identity::generate();

    backend
        .encrypt(
            &secret_id,
            &SecretValue::new(b"top-secret".to_vec()),
            vec![identity_recipient(&identity_a), identity_recipient(&identity_b)],
        )
        .unwrap();

    let outsider = age::x25519::Identity::generate();
    assert!(backend.decrypt(&secret_id, vec![outsider]).is_err());
}

#[test]
fn encrypt_creates_age_file() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = AgentBackend::new(temp_dir.path()).unwrap();
    let secret_id = SecretId::new("db/password").unwrap();

    let identity = age::x25519::Identity::generate();
    backend
        .encrypt(
            &secret_id,
            &SecretValue::new(b"hunter2".to_vec()),
            vec![identity_recipient(&identity)],
        )
        .unwrap();

    assert!(backend.ciphertext_path(&secret_id).exists());
}

#[test]
fn encrypt_no_overwrite() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = AgentBackend::new(temp_dir.path()).unwrap();
    let secret_id = SecretId::new("db/password").unwrap();

    let identity = age::x25519::Identity::generate();
    backend
        .encrypt(
            &secret_id,
            &SecretValue::new(b"hunter2".to_vec()),
            vec![identity_recipient(&identity)],
        )
        .unwrap();

    assert!(backend
        .encrypt(
            &secret_id,
            &SecretValue::new(b"other".to_vec()),
            vec![identity_recipient(&identity)],
        )
        .is_err());
}

#[test]
fn grant_adds_recipient() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = AgentBackend::new(temp_dir.path()).unwrap();
    let secret_id = SecretId::new("shared").unwrap();

    let creator = age::x25519::Identity::generate();
    let new_user = age::x25519::Identity::generate();

    backend
        .encrypt(
            &secret_id,
            &SecretValue::new(b"rotate-me".to_vec()),
            vec![identity_recipient(&creator)],
        )
        .unwrap();
    assert!(backend.decrypt(&secret_id, vec![new_user.clone()]).is_err());

    backend
        .grant(
            &secret_id,
            creator.clone(),
            vec![identity_recipient(&creator), identity_recipient(&new_user)],
        )
        .unwrap();

    let decrypted = backend.decrypt(&secret_id, vec![new_user]).unwrap();
    assert_eq!(decrypted.expose(|bytes| bytes.to_vec()), b"rotate-me");
}

#[test]
fn file_permissions_0600() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = AgentBackend::new(temp_dir.path()).unwrap();
    let secret_id = SecretId::new("db/password").unwrap();

    let identity = age::x25519::Identity::generate();
    backend
        .encrypt(
            &secret_id,
            &SecretValue::new(b"hunter2".to_vec()),
            vec![identity_recipient(&identity)],
        )
        .unwrap();

    let mode = std::fs::metadata(backend.ciphertext_path(&secret_id))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}
