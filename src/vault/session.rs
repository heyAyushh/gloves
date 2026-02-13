use std::path::PathBuf;
use std::{fs, path::Path};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    error::Result,
    fs_secure::{create_private_file_if_missing, write_private_file_atomic},
    types::AgentId,
};

/// Active vault mount session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultSession {
    /// Vault logical name.
    pub vault_name: String,
    /// Mount location.
    pub mountpoint: PathBuf,
    /// Mount timestamp.
    pub mounted_at: DateTime<Utc>,
    /// Session expiry timestamp.
    pub expires_at: DateTime<Utc>,
    /// gocryptfs process id.
    pub pid: u32,
    /// Agent that created the mount session.
    pub mounted_by: AgentId,
}

impl VaultSession {
    /// Returns true when the session expired at `now`.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }
}

pub(crate) fn load_sessions(path: &Path) -> Result<Vec<VaultSession>> {
    create_private_file_if_missing(path, b"[]")?;
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub(crate) fn save_sessions(path: &Path, sessions: &[VaultSession]) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(sessions)?;
    write_private_file_atomic(path, &bytes)
}
