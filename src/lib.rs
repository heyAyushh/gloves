#![deny(missing_docs)]
//! Gloves provides a dual-backend secrets manager.

/// Agent backend modules.
pub mod agent;
/// Audit log module.
pub mod audit;
/// Command-line interface.
pub mod cli;
/// Bootstrap config parsing and validation.
pub mod config;
/// Error types.
pub mod error;
/// Secure filesystem helpers.
pub mod fs_secure;
/// Human backend modules.
pub mod human;
/// Unified secrets manager.
pub mod manager;
/// Shared runtime path layout.
pub mod paths;
/// TTL reaper.
pub mod reaper;
/// Agent registry.
pub mod registry;
/// Shared types.
pub mod types;
/// Encrypted volume management.
pub mod vault;
