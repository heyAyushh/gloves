use std::collections::HashSet;

use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ValidationError;

const MAX_SECRET_ID_LENGTH: usize = 128;

/// Distinguishes human-owned and agent-owned secrets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Owner {
    /// Secret originates from a human credential store.
    Human,
    /// Secret originates from the agent backend.
    Agent,
}

/// Opaque secret identifier.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SecretId(String);

impl SecretId {
    /// Creates a validated secret identifier.
    pub fn new(name: &str) -> Result<Self, ValidationError> {
        if name.is_empty() || name.len() > MAX_SECRET_ID_LENGTH {
            return Err(ValidationError::InvalidName);
        }
        if name.contains("..") || name.starts_with('/') {
            return Err(ValidationError::PathTraversal);
        }
        if !name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_./-".contains(character))
        {
            return Err(ValidationError::InvalidCharacter);
        }
        Ok(Self(name.to_owned()))
    }

    /// Returns the identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SecretId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Opaque agent identifier.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AgentId(String);

impl AgentId {
    /// Creates a validated agent identifier.
    pub fn new(value: &str) -> Result<Self, ValidationError> {
        SecretId::new(value)?;
        Ok(Self(value.to_owned()))
    }

    /// Returns the identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Metadata describing a stored secret.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretMeta {
    /// Secret identifier.
    pub id: SecretId,
    /// Secret trust domain owner.
    pub owner: Owner,
    /// Secret creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Secret expiry timestamp.
    pub expires_at: DateTime<Utc>,
    /// Agents authorized for decryption.
    pub recipients: HashSet<AgentId>,
    /// Agent that created the secret.
    pub created_by: AgentId,
    /// Last access timestamp.
    pub last_accessed: Option<DateTime<Utc>>,
    /// Number of successful reads.
    pub access_count: u64,
    /// Optional ciphertext checksum.
    pub checksum: String,
}

/// Secret value wrapper that avoids accidental logging.
pub struct SecretValue {
    inner: Secret<Vec<u8>>,
}

impl SecretValue {
    /// Constructs a secret value from bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            inner: Secret::new(bytes),
        }
    }

    /// Exposes the secret bytes to a closure.
    pub fn expose<F, R>(&self, function: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        function(self.inner.expose_secret())
    }
}

/// Status for a human access request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestStatus {
    /// Request is awaiting human action.
    Pending,
    /// Request was approved.
    Fulfilled,
    /// Request was denied.
    Denied,
    /// Request expired without action.
    Expired,
}

/// Pending request for human-owned secrets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingRequest {
    /// Request id.
    pub id: Uuid,
    /// Secret being requested.
    pub secret_name: SecretId,
    /// Requesting agent id.
    pub requested_by: AgentId,
    /// Human readable reason.
    pub reason: String,
    /// Request creation timestamp.
    pub requested_at: DateTime<Utc>,
    /// Expiry timestamp.
    pub expires_at: DateTime<Utc>,
    /// Request signature payload.
    pub signature: Vec<u8>,
    /// Request lifecycle status.
    pub status: RequestStatus,
}
