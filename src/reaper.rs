use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use chrono::Utc;

use crate::{
    agent::{backend::AgentBackend, meta::MetadataStore},
    audit::{AuditEvent, AuditLog},
    error::Result,
    paths::SecretsPaths,
    vault::{self, gocryptfs::FsEncryptionDriver},
};

const SECURE_DELETE_CHUNK_BYTES: usize = 64 * 1024;

/// Reaps expired secrets from storage.
pub struct TtlReaper;

impl TtlReaper {
    /// Deletes expired agent secrets and logs expiry events.
    pub fn reap(
        agent_backend: &AgentBackend,
        metadata_store: &MetadataStore,
        audit_log: &AuditLog,
    ) -> Result<()> {
        for meta in metadata_store.list()? {
            if meta.expires_at <= Utc::now() {
                let ciphertext_path = agent_backend.ciphertext_path(&meta.id);
                secure_delete_file(&ciphertext_path)?;
                metadata_store.delete(&meta.id)?;
                audit_log.log(AuditEvent::SecretExpired {
                    secret_id: meta.id.clone(),
                })?;
            }
        }
        Ok(())
    }

    /// Reaps expired vault mount sessions.
    pub fn reap_vault_sessions<D>(
        driver: &D,
        paths: &SecretsPaths,
        audit_log: &AuditLog,
    ) -> Result<()>
    where
        D: FsEncryptionDriver,
    {
        vault::reap_expired_sessions(driver, paths, audit_log)
    }
}

/// Overwrites a file with zeroes before deletion.
pub fn secure_delete_file(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let mut file = OpenOptions::new().write(true).open(path)?;
    let mut remaining = file.metadata()?.len();
    let zero_chunk = [0_u8; SECURE_DELETE_CHUNK_BYTES];

    while remaining > 0 {
        let chunk_size = remaining.min(SECURE_DELETE_CHUNK_BYTES as u64) as usize;
        file.write_all(&zero_chunk[..chunk_size])?;
        remaining -= chunk_size as u64;
    }
    file.sync_all()?;
    drop(file);
    fs::remove_file(path)?;
    Ok(())
}
