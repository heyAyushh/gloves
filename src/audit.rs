use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};

use crate::{
    error::Result,
    fs_secure::{create_private_file_if_missing, set_permissions, PRIVATE_FILE_MODE},
    types::{AgentId, Owner, SecretId},
};

/// Audit events emitted by the system.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent {
    /// Secret was accessed.
    SecretAccessed {
        /// Secret that was accessed.
        secret_id: SecretId,
        /// Agent that accessed the secret.
        by: AgentId,
    },
    /// Secret expired and was reaped.
    SecretExpired {
        /// Secret that expired.
        secret_id: SecretId,
    },
    /// Secret was created.
    SecretCreated {
        /// Secret that was created.
        secret_id: SecretId,
        /// Agent that created the secret.
        by: AgentId,
    },
    /// Secret was revoked.
    SecretRevoked {
        /// Secret that was revoked.
        secret_id: SecretId,
        /// Agent that revoked the secret.
        by: AgentId,
    },
    /// Vault was created.
    VaultCreated {
        /// Vault logical name.
        vault: String,
        /// Vault owner domain.
        owner: Owner,
    },
    /// Vault was mounted.
    VaultMounted {
        /// Vault logical name.
        vault: String,
        /// Agent that mounted the vault.
        agent: AgentId,
        /// Requested session TTL in minutes.
        ttl_minutes: u64,
    },
    /// Vault was unmounted.
    VaultUnmounted {
        /// Vault logical name.
        vault: String,
        /// Unmount reason.
        reason: String,
        /// Agent associated with the operation.
        agent: AgentId,
    },
    /// Vault session expired.
    VaultSessionExpired {
        /// Vault logical name.
        vault: String,
    },
    /// Vault file handoff prompt was generated.
    VaultHandoffPromptIssued {
        /// Vault logical name.
        vault: String,
        /// Requesting agent.
        requester: AgentId,
        /// Trusted agent expected to retrieve the file.
        trusted_agent: AgentId,
        /// Requested file path inside the vault.
        requested_file: String,
    },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct AuditLine {
    timestamp: DateTime<Utc>,
    #[serde(flatten)]
    event: AuditEvent,
}

/// JSONL append-only audit log writer.
pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    /// Creates a new audit log at `path`.
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let file_path = path.as_ref().to_path_buf();
        create_private_file_if_missing(&file_path, b"")?;
        set_permissions(&file_path, PRIVATE_FILE_MODE)?;
        Ok(Self { path: file_path })
    }

    /// Appends one event as a JSON line.
    pub fn log(&self, event: AuditEvent) -> Result<()> {
        let line = AuditLine {
            timestamp: Utc::now(),
            event,
        };

        let mut file = OpenOptions::new().append(true).open(&self.path)?;
        serde_json::to_writer(&mut file, &line)?;
        file.write_all(b"\n")?;
        Ok(())
    }

    /// Returns the audit file path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}
