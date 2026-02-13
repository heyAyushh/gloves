use std::io::Write;
use std::os::unix::fs::PermissionsExt;

use gloves::{
    agent::backend::{identity_recipient, parse_identity, AgentBackend},
    error::GlovesError,
    types::{SecretId, SecretValue},
};
use secrecy::ExposeSecret;

#[test]
fn encrypt_decrypt_roundtrip() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = AgentBackend::new(temp_dir.path()).unwrap();
    let secret_id = SecretId::new("db/password").unwrap();

    let identity = age::x25519::Identity::generate();
    let recipient = identity_recipient(&identity);
    backend
        .encrypt(
            &secret_id,
            &SecretValue::new(b"hunter2".to_vec()),
            vec![recipient],
        )
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
            vec![
                identity_recipient(&identity_a),
                identity_recipient(&identity_b),
            ],
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
            vec![
                identity_recipient(&identity_a),
                identity_recipient(&identity_b),
            ],
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
    let creator = age::x25519::Identity::generate();
    let first_recipient = identity_recipient(&creator);

    backend
        .encrypt(
            &secret_id,
            &SecretValue::new(b"rotate-me".to_vec()),
            vec![first_recipient],
        )
        .unwrap();
    let before = backend.ciphertext_checksum(&secret_id).unwrap();

    let second = age::x25519::Identity::generate();
    backend
        .grant(
            &secret_id,
            creator.clone(),
            vec![identity_recipient(&creator), identity_recipient(&second)],
        )
        .unwrap();
    let after = backend.ciphertext_checksum(&secret_id).unwrap();

    assert_ne!(before, after);
}

#[test]
fn parse_identity_roundtrip() {
    let identity = age::x25519::Identity::generate();
    let parsed = parse_identity(identity.to_string().expose_secret()).unwrap();
    assert_eq!(
        parsed.to_string().expose_secret(),
        identity.to_string().expose_secret()
    );
}

#[test]
fn parse_identity_invalid() {
    assert!(matches!(
        parse_identity("not-an-age-key"),
        Err(GlovesError::Crypto(_))
    ));
}

#[test]
fn delete_missing_is_ok() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = AgentBackend::new(temp_dir.path()).unwrap();
    let secret_id = SecretId::new("db/missing").unwrap();
    backend.delete(&secret_id).unwrap();
}

#[test]
fn decrypt_unsupported_header_fails() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = AgentBackend::new(temp_dir.path()).unwrap();
    let secret_id = SecretId::new("db/passphrase").unwrap();
    let passphrase = age::secrecy::SecretString::from("passphrase".to_owned());

    let encryptor = age::Encryptor::with_user_passphrase(passphrase);
    let mut ciphertext = Vec::new();
    let mut writer = encryptor.wrap_output(&mut ciphertext).unwrap();
    writer.write_all(b"secret").unwrap();
    writer.finish().unwrap();
    let output_path = backend.ciphertext_path(&secret_id);
    std::fs::create_dir_all(output_path.parent().unwrap()).unwrap();
    std::fs::write(output_path, ciphertext).unwrap();

    let identity = age::x25519::Identity::generate();
    assert!(matches!(
        backend.decrypt(&secret_id, vec![identity]),
        Err(GlovesError::Crypto(_))
    ));
}
