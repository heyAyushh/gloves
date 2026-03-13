use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{types::SecretId, ValidationError};

const SECRET_REF_SCHEME: &str = "gloves://";

/// Stable runtime-neutral reference to a stored secret.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretRef {
    secret_id: SecretId,
}

impl SecretRef {
    /// Builds a secret reference from an existing secret identifier.
    pub fn new(secret_id: SecretId) -> Self {
        Self { secret_id }
    }

    /// Returns the referenced secret identifier.
    pub fn secret_id(&self) -> &SecretId {
        &self.secret_id
    }

    /// Returns the canonical ref string.
    pub fn as_str(&self) -> String {
        format!("{SECRET_REF_SCHEME}{}", self.secret_id.as_str())
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_str())
    }
}

impl From<SecretId> for SecretRef {
    fn from(value: SecretId) -> Self {
        Self::new(value)
    }
}

impl From<SecretRef> for String {
    fn from(value: SecretRef) -> Self {
        value.to_string()
    }
}

impl FromStr for SecretRef {
    type Err = SecretRefParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let raw_path = value
            .strip_prefix(SECRET_REF_SCHEME)
            .ok_or(SecretRefParseError::InvalidScheme)?;
        if raw_path.is_empty() {
            return Err(SecretRefParseError::MissingPath);
        }

        let mut segments = Vec::new();
        for segment in raw_path.split('/') {
            if segment.is_empty() {
                return Err(SecretRefParseError::EmptyPathSegment);
            }
            segments.push(segment);
        }

        let secret_path = segments.join("/");
        let secret_id =
            SecretId::new(&secret_path).map_err(SecretRefParseError::InvalidSecretId)?;
        Ok(Self::new(secret_id))
    }
}

impl Serialize for SecretRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for SecretRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

/// Validation errors for portable secret references.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum SecretRefParseError {
    /// The ref did not use the `gloves://` scheme.
    #[error("invalid secret ref scheme: expected `gloves://`")]
    InvalidScheme,
    /// The ref omitted the secret path.
    #[error("invalid secret ref: missing secret path")]
    MissingPath,
    /// The ref contained an empty path segment.
    #[error("invalid secret ref: empty path segment")]
    EmptyPathSegment,
    /// The embedded secret id was invalid.
    #[error(transparent)]
    InvalidSecretId(#[from] ValidationError),
}

#[cfg(test)]
mod tests {
    use super::{SecretRef, SecretRefParseError};
    use crate::types::SecretId;

    #[test]
    fn secret_ref_roundtrips_agent_paths() {
        let secret_ref: SecretRef = "gloves://agents/devy/api-keys/openai".parse().unwrap();

        assert_eq!(
            secret_ref.secret_id().as_str(),
            "agents/devy/api-keys/openai"
        );
        assert_eq!(
            secret_ref.to_string(),
            "gloves://agents/devy/api-keys/openai"
        );
    }

    #[test]
    fn secret_ref_from_secret_id_uses_canonical_format() {
        let secret_ref = SecretRef::from(SecretId::new("shared/database-url").unwrap());

        assert_eq!(secret_ref.to_string(), "gloves://shared/database-url");
    }

    #[test]
    fn secret_ref_rejects_invalid_shapes() {
        assert!(matches!(
            "https://agents/devy/api-key".parse::<SecretRef>(),
            Err(SecretRefParseError::InvalidScheme)
        ));
        assert!(matches!(
            "gloves://".parse::<SecretRef>(),
            Err(SecretRefParseError::MissingPath)
        ));
        assert!(matches!(
            "gloves://agents//api-key".parse::<SecretRef>(),
            Err(SecretRefParseError::EmptyPathSegment)
        ));
        assert!("gloves://agents/devy/../api-key"
            .parse::<SecretRef>()
            .is_err());
    }
}
