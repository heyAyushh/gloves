#![deny(missing_docs)]
//! Core types, errors, and path utilities for gloves.

/// Error types and result aliases.
pub mod error;
/// Filesystem path definitions.
pub mod paths;
/// Portable secret references.
pub mod secret_ref;
/// Core domain types (SecretId, AgentId, etc.).
pub mod types;

pub use error::{GlovesError, Result, ValidationError};
pub use paths::SecretsPaths;
pub use secret_ref::{SecretRef, SecretRefParseError};
pub use types::{AgentId, Owner, SecretId, SecretValue};
