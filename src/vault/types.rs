use std::path::PathBuf;

use chrono::{DateTime, Utc};

use crate::{error::Result, types::Owner};

/// Provider abstraction for agent-owned vault passwords.
pub trait VaultSecretProvider: Send + Sync {
    /// Ensures the agent vault password exists.
    fn ensure_agent_secret(&self, secret_name: &str) -> Result<()>;
}

/// One configured vault entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct VaultListEntry {
    pub(super) name: String,
    pub(super) owner: Owner,
    pub(super) cipher_dir: PathBuf,
    pub(super) created_at: DateTime<Utc>,
}

/// Runtime status for one vault.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct VaultStatusEntry {
    pub(super) name: String,
    pub(super) owner: Owner,
    pub(super) mounted: bool,
    pub(super) mountpoint: Option<PathBuf>,
    pub(super) remaining_seconds: Option<i64>,
}
