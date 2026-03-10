use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::Owner;

const DEFAULT_VAULT_TTL_MINUTES: u64 = 60;
const MAX_VAULT_TTL_MINUTES: u64 = 24 * 60;
const DEFAULT_IDLE_TIMEOUT_MINUTES: u64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
struct VaultHooks {
    #[serde(skip_serializing_if = "Option::is_none")]
    on_mount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    on_unmount: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct VaultConfig {
    pub(crate) name: String,
    pub(crate) owner: Owner,
    pub(crate) cipher_dir: PathBuf,
    pub(crate) default_mountpoint: PathBuf,
    pub(crate) default_ttl_minutes: u64,
    pub(crate) max_ttl_minutes: u64,
    pub(crate) idle_timeout_minutes: u64,
    pub(crate) secret_name: String,
    pub(crate) created_at: DateTime<Utc>,
}

/// TOML container for a vault configuration file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultConfigFile {
    #[serde(skip_serializing_if = "Option::is_none")]
    hooks: Option<VaultHooks>,
    pub(crate) vault: VaultConfig,
}

impl VaultConfigFile {
    /// Constructs a vault config with secure defaults.
    pub fn new(
        name: String,
        owner: Owner,
        cipher_dir: PathBuf,
        default_mountpoint: PathBuf,
        secret_name: String,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            vault: VaultConfig {
                name,
                owner,
                cipher_dir,
                default_mountpoint,
                default_ttl_minutes: DEFAULT_VAULT_TTL_MINUTES,
                max_ttl_minutes: MAX_VAULT_TTL_MINUTES,
                idle_timeout_minutes: DEFAULT_IDLE_TIMEOUT_MINUTES,
                secret_name,
                created_at,
            },
            hooks: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        VaultConfigFile, DEFAULT_IDLE_TIMEOUT_MINUTES, DEFAULT_VAULT_TTL_MINUTES,
        MAX_VAULT_TTL_MINUTES,
    };
    use crate::types::Owner;
    use chrono::Utc;
    use std::path::PathBuf;

    #[test]
    fn new_vault_config_file_uses_secure_defaults() {
        let created_at = Utc::now();
        let config = VaultConfigFile::new(
            "primary".to_owned(),
            Owner::Agent,
            PathBuf::from("/cipher"),
            PathBuf::from("/mount"),
            "vault/primary".to_owned(),
            created_at,
        );

        assert_eq!(config.vault.name, "primary");
        assert_eq!(config.vault.owner, Owner::Agent);
        assert_eq!(config.vault.cipher_dir, PathBuf::from("/cipher"));
        assert_eq!(config.vault.default_mountpoint, PathBuf::from("/mount"));
        assert_eq!(config.vault.default_ttl_minutes, DEFAULT_VAULT_TTL_MINUTES);
        assert_eq!(config.vault.max_ttl_minutes, MAX_VAULT_TTL_MINUTES);
        assert_eq!(
            config.vault.idle_timeout_minutes,
            DEFAULT_IDLE_TIMEOUT_MINUTES
        );
        assert_eq!(config.vault.secret_name, "vault/primary");
        assert_eq!(config.vault.created_at, created_at);
        assert!(config.hooks.is_none());
    }
}
