use std::{fs, path::Path};

use chrono::Utc;

use crate::{
    agent::{backend::AgentBackend, meta::MetadataStore},
    audit::{AuditEvent, AuditLog},
    error::Result,
};

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
}

/// Overwrites a file with zeroes before deletion.
pub fn secure_delete_file(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let size = fs::metadata(path)?.len() as usize;
    fs::write(path, vec![0_u8; size])?;
    fs::remove_file(path)?;
    Ok(())
}
