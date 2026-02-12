//! Gloves provides a dual-backend secrets manager.

/// Agent backend modules.
pub mod agent;
/// Audit log module.
pub mod audit;
/// Command-line interface.
pub mod cli;
/// Error types.
pub mod error;
/// Human backend modules.
pub mod human;
/// Unified secrets manager.
pub mod manager;
/// TTL reaper.
pub mod reaper;
/// Agent registry.
pub mod registry;
/// Shared types.
pub mod types;
