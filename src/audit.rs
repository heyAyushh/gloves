use std::{fs::{self, OpenOptions}, io::Write, path::{Path, PathBuf}};

use chrono::{DateTime, Utc};

use crate::{error::Result, types::{AgentId, SecretId}};

/// Audit events emitted by the system.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent {
    /// Secret was accessed.
    SecretAccessed { secret_id: SecretId, by: AgentId },
    /// Secret expired and was reaped.
    SecretExpired { secret_id: SecretId },
    /// Secret was created.
    SecretCreated { secret_id: SecretId, by: AgentId },
    /// Secret was revoked.
    SecretRevoked { secret_id: SecretId, by: AgentId },
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
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if !file_path.exists() {
            OpenOptions::new().create(true).append(true).open(&file_path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&file_path, fs::Permissions::from_mode(0o600))?;
            }
        }
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
