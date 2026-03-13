#![deny(missing_docs)]
//! Gloves provides a dual-backend secrets manager.

pub use gloves_config::*;
pub use gloves_core::*;

/// Agent backend modules.
pub mod agent;
/// Audit log module.
pub mod audit;
/// Command-line interface.
pub mod cli;

/// Secure filesystem helpers.
pub mod fs_secure;
/// Human backend modules.
pub mod human;
/// Unified secrets manager.
pub mod manager;
/// TTL reaper.
pub mod reaper;
/// Agent registry.
pub mod registry;
/// Runtime bridge helpers for private operator integrations.
pub mod runtime_bridge;
/// Encrypted volume management.
pub mod vault;

mod namespaced_store;
