use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

use chrono::Duration;
use ed25519_dalek::SigningKey;
use rand::RngExt;

use crate::{
    agent::{age_crypto, backend::AgentBackend, meta::MetadataStore},
    audit::AuditLog,
    error::{GlovesError, Result},
    fs_secure::{create_private_file_if_missing, ensure_private_dir, write_private_file_atomic},
    human::{backend::HumanBackend, pending::PendingRequestStore},
    manager::{SecretsManager, SetSecretOptions},
    paths::SecretsPaths,
    types::{AgentId, Owner, SecretId, SecretValue},
};

const REQUEST_ID_COMMAND_HINT: &str = "To find a valid request id:\n  gloves list --pending\n  gloves requests list\nThen run one of:\n  gloves approve <request-id>\n  gloves deny <request-id>\n  gloves requests approve <request-id>\n  gloves requests deny <request-id>";
const REQUEST_ID_EXAMPLE: &str = "123e4567-e89b-12d3-a456-426614174000";

pub(crate) fn init_layout(paths: &SecretsPaths) -> Result<()> {
    ensure_private_dir(paths.root())?;
    ensure_private_dir(&paths.store_dir())?;
    ensure_private_dir(&paths.metadata_dir())?;
    ensure_private_dir(&paths.vaults_dir())?;
    ensure_private_dir(&paths.gpg_homes_dir())?;
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

fn load_or_create_identity_file(identity_file: &Path) -> Result<PathBuf> {
    if identity_file.exists() {
        age_crypto::validate_identity_file(identity_file)?;
        return Ok(identity_file.to_path_buf());
    }

    age_crypto::generate_identity_file(identity_file)?;
    Ok(identity_file.to_path_buf())
}

fn load_or_create_signing_key_file(signing_key_file: &Path) -> Result<SigningKey> {
    if signing_key_file.exists() {
        let bytes = fs::read(signing_key_file)?;
        let key_bytes: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| GlovesError::InvalidInput("invalid signing key".to_owned()))?;
        return Ok(SigningKey::from_bytes(&key_bytes));
    }

    let mut key_bytes = [0_u8; 32];
    rand::rng().fill(&mut key_bytes);
    let key = SigningKey::from_bytes(&key_bytes);
    write_private_file_atomic(signing_key_file, &key.to_bytes())?;
    Ok(key)
}

pub(crate) fn load_or_create_identity_for_agent(
    paths: &SecretsPaths,
    agent_id: &AgentId,
) -> Result<PathBuf> {
    load_or_create_identity_file(&paths.identity_file_for_agent(agent_id.as_str()))
}

pub(crate) fn recipient_from_identity_file(identity_file: &std::path::Path) -> Result<String> {
    age_crypto::recipient_from_identity_file(identity_file)
}

pub(crate) fn load_or_create_recipient_for_agent(
    paths: &SecretsPaths,
    agent_id: &AgentId,
) -> Result<String> {
    let identity_file = load_or_create_identity_for_agent(paths, agent_id)?;
    recipient_from_identity_file(&identity_file)
}

pub(crate) fn load_or_create_signing_key_for_agent(
    paths: &SecretsPaths,
    agent_id: &AgentId,
) -> Result<SigningKey> {
    load_or_create_signing_key_file(&paths.signing_key_file_for_agent(agent_id.as_str()))
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
    let request_id = request_id.trim();
    if request_id.is_empty() {
        return Err(GlovesError::InvalidInput(format!(
            "request id is empty\n{REQUEST_ID_COMMAND_HINT}"
        )));
    }
    if request_id.eq_ignore_ascii_case("request") || request_id.eq_ignore_ascii_case("requests") {
        return Err(GlovesError::InvalidInput(format!(
            "`{request_id}` is a label, not a request id\n{REQUEST_ID_COMMAND_HINT}"
        )));
    }
    request_id
        .parse::<uuid::Uuid>()
        .map_err(|error| {
            GlovesError::InvalidInput(format!(
                "invalid request id `{request_id}`; expected a UUID like `{REQUEST_ID_EXAMPLE}`\n{REQUEST_ID_COMMAND_HINT}\nparser detail: {error}"
            ))
        })
}

pub(crate) fn ensure_agent_vault_secret(
    paths: &SecretsPaths,
    secret_name: &str,
    creator: &AgentId,
    ttl_days: i64,
    length_bytes: usize,
) -> Result<()> {
    let manager = manager_for_paths(paths)?;
    let secret_id = SecretId::new(secret_name)?;
    if manager.metadata_store.path_for(&secret_id).exists() {
        return Ok(());
    }

    let recipient = load_or_create_recipient_for_agent(paths, creator)?;
    let mut recipients = HashSet::new();
    recipients.insert(creator.clone());

    let mut secret_bytes = vec![0_u8; length_bytes];
    rand::rng().fill(secret_bytes.as_mut_slice());
    match manager.set(
        secret_id,
        SecretValue::new(secret_bytes),
        SetSecretOptions {
            owner: Owner::Agent,
            ttl: Duration::days(ttl_days),
            created_by: creator.clone(),
            recipients,
            recipient_keys: vec![recipient],
        },
    ) {
        Ok(_) | Err(GlovesError::AlreadyExists) => Ok(()),
        Err(error) => Err(error),
    }
}
