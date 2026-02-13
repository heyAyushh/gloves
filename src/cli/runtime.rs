use std::{collections::HashSet, fs};

use chrono::Duration;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use secrecy::ExposeSecret;

use crate::{
    agent::{backend::AgentBackend, meta::MetadataStore},
    audit::AuditLog,
    error::{GlovesError, Result},
    fs_secure::{create_private_file_if_missing, ensure_private_dir, write_private_file_atomic},
    human::{backend::HumanBackend, pending::PendingRequestStore},
    manager::{SecretsManager, SetSecretOptions},
    paths::SecretsPaths,
    types::{AgentId, Owner, SecretId, SecretValue},
};

use super::{DEFAULT_AGENT_ID, DEFAULT_VAULT_SECRET_LENGTH_BYTES, DEFAULT_VAULT_SECRET_TTL_DAYS};

pub(crate) fn init_layout(paths: &SecretsPaths) -> Result<()> {
    ensure_private_dir(paths.root())?;
    ensure_private_dir(&paths.store_dir())?;
    ensure_private_dir(&paths.metadata_dir())?;
    ensure_private_dir(&paths.vaults_dir())?;
    ensure_private_dir(&paths.encrypted_dir())?;
    ensure_private_dir(&paths.mounts_dir())?;
    create_private_file_if_missing(&paths.pending_file(), b"[]")?;
    create_private_file_if_missing(&paths.audit_file(), b"")?;
    create_private_file_if_missing(&paths.vault_sessions_file(), b"[]")?;
    Ok(())
}

pub(crate) fn manager_for_paths(paths: &SecretsPaths) -> Result<SecretsManager> {
    init_layout(paths)?;
    let agent_backend = AgentBackend::new(paths.store_dir())?;
    let human_backend = HumanBackend::new();
    let metadata_store = MetadataStore::new(paths.metadata_dir())?;
    let pending_store = PendingRequestStore::new(paths.pending_file())?;
    let audit_log = AuditLog::new(paths.audit_file())?;
    Ok(SecretsManager::new(
        agent_backend,
        human_backend,
        metadata_store,
        pending_store,
        audit_log,
    ))
}

pub(crate) fn load_or_create_default_identity(
    paths: &SecretsPaths,
) -> Result<age::x25519::Identity> {
    let path = paths.default_identity_file();
    if path.exists() {
        let identity = fs::read_to_string(&path)?
            .trim()
            .parse::<age::x25519::Identity>()
            .map_err(|error| GlovesError::Crypto(error.to_string()))?;
        return Ok(identity);
    }

    let identity = age::x25519::Identity::generate();
    let identity_secret = identity.to_string();
    write_private_file_atomic(&path, identity_secret.expose_secret().as_bytes())?;
    Ok(identity)
}

pub(crate) fn load_or_create_default_signing_key(paths: &SecretsPaths) -> Result<SigningKey> {
    let path = paths.default_signing_key_file();
    if path.exists() {
        let bytes = fs::read(&path)?;
        let key_bytes: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| GlovesError::InvalidInput("invalid signing key".to_owned()))?;
        return Ok(SigningKey::from_bytes(&key_bytes));
    }

    let mut key_bytes = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    let key = SigningKey::from_bytes(&key_bytes);
    write_private_file_atomic(&path, &key.to_bytes())?;
    Ok(key)
}

pub(crate) fn validate_ttl_days(ttl_days: i64, field_name: &str) -> Result<i64> {
    if ttl_days <= 0 {
        return Err(GlovesError::InvalidInput(format!(
            "{field_name} must be greater than zero"
        )));
    }
    Ok(ttl_days)
}

pub(crate) fn parse_request_uuid(request_id: &str) -> Result<uuid::Uuid> {
    request_id
        .parse::<uuid::Uuid>()
        .map_err(|error| GlovesError::InvalidInput(error.to_string()))
}

pub(crate) fn ensure_agent_vault_secret(paths: &SecretsPaths, secret_name: &str) -> Result<()> {
    let manager = manager_for_paths(paths)?;
    let secret_id = SecretId::new(secret_name)?;
    if manager.metadata_store.path_for(&secret_id).exists() {
        return Ok(());
    }

    let creator = AgentId::new(DEFAULT_AGENT_ID)?;
    let identity = load_or_create_default_identity(paths)?;
    let recipient = identity.to_public().to_string();
    let mut recipients = HashSet::new();
    recipients.insert(creator.clone());

    let mut secret_bytes = vec![0_u8; DEFAULT_VAULT_SECRET_LENGTH_BYTES];
    rand::thread_rng().fill_bytes(&mut secret_bytes);
    match manager.set(
        secret_id,
        SecretValue::new(secret_bytes),
        SetSecretOptions {
            owner: Owner::Agent,
            ttl: Duration::days(DEFAULT_VAULT_SECRET_TTL_DAYS),
            created_by: creator,
            recipients,
            recipient_keys: vec![recipient],
        },
    ) {
        Ok(_) | Err(GlovesError::AlreadyExists) => Ok(()),
        Err(error) => Err(error),
    }
}
