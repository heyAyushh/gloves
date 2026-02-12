use std::io;

use thiserror::Error;

/// Validation failures for identifiers.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// Secret name is empty or too long.
    #[error("invalid name")]
    InvalidName,
    /// Secret name attempts path traversal.
    #[error("path traversal is not allowed")]
    PathTraversal,
    /// Secret name contains unsupported characters.
    #[error("invalid character in name")]
    InvalidCharacter,
}

/// Top-level application errors.
#[derive(Debug, Error)]
pub enum GlovesError {
    /// Resource was not found.
    #[error("not found")]
    NotFound,
    /// Secret already exists and overwrite is disallowed.
    #[error("already exists")]
    AlreadyExists,
    /// User or agent is unauthorized.
    #[error("unauthorized")]
    Unauthorized,
    /// Operation is forbidden by policy.
    #[error("forbidden")]
    Forbidden,
    /// Secret has expired.
    #[error("expired")]
    Expired,
    /// Secret ciphertext integrity check failed.
    #[error("integrity check failed")]
    IntegrityViolation,
    /// Input was syntactically valid but semantically unsupported.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// GPG access denied by pass.
    #[error("gpg denied")]
    GpgDenied,
    /// Validation failure.
    #[error(transparent)]
    Validation(#[from] ValidationError),
    /// I/O error.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// JSON serialization error.
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    /// UTF-8 conversion error.
    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),
    /// Cryptography failure.
    #[error("crypto error: {0}")]
    Crypto(String),
}

/// A typed result used across the crate.
pub type Result<T> = std::result::Result<T, GlovesError>;
