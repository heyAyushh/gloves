use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};

use crate::{
    error::Result,
    fs_secure::{create_private_file_if_missing, set_permissions, PRIVATE_FILE_MODE},
    types::{AgentId, SecretId},
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
