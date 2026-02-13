//! Vault orchestration for encrypted volumes.

/// Vault configuration schema.
pub mod config;
/// gocryptfs command wrapper.
pub mod gocryptfs;
/// Vault session schema.
pub mod session;

mod manager;
mod reaper;
mod types;
mod validation;

pub use manager::VaultManager;
pub(crate) use reaper::reap_expired_sessions;
pub use types::{VaultListEntry, VaultSecretProvider, VaultStatusEntry};
