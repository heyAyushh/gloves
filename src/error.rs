use std::io;

use thiserror::Error;

/// Validation failures for identifiers.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// Secret name is empty or too long.
    #[error("invalid name: must be 1..=128 characters")]
    InvalidName,
    /// Secret name attempts path traversal.
    #[error("invalid path: traversal is not allowed")]
    PathTraversal,
    /// Secret name contains unsupported characters.
    #[error("invalid character in name: use only A-Za-z0-9._/-")]
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

/// Generic invalid-input error.
pub const ERROR_CODE_INVALID_INPUT: &str = "E100";
/// Secret identifier validation error.
pub const ERROR_CODE_SECRET_ID: &str = "E101";
/// Request identifier validation error.
pub const ERROR_CODE_REQUEST_ID: &str = "E102";
/// Missing runtime dependency or binary.
pub const ERROR_CODE_MISSING_RUNTIME: &str = "E103";
/// Operation is blocked by policy.
pub const ERROR_CODE_FORBIDDEN: &str = "E200";
/// Caller identity is not authorized.
pub const ERROR_CODE_UNAUTHORIZED: &str = "E201";
/// Resource lookup failed.
pub const ERROR_CODE_NOT_FOUND: &str = "E300";
/// Resource already exists.
pub const ERROR_CODE_ALREADY_EXISTS: &str = "E301";
/// Resource expired.
pub const ERROR_CODE_EXPIRED: &str = "E302";
/// Human backend GPG/pass denied access.
pub const ERROR_CODE_GPG_DENIED: &str = "E400";
/// Integrity check failed.
pub const ERROR_CODE_INTEGRITY: &str = "E500";
/// Filesystem or stream I/O failed.
pub const ERROR_CODE_IO: &str = "E900";
/// Internal serialization/crypto/encoding failure.
pub const ERROR_CODE_INTERNAL: &str = "E999";

const ERROR_EXPLANATION_E100: &str = r#"E100 invalid input

The command arguments are syntactically valid but semantically unsupported.

Common fixes:
  - Run `gloves help <command>` for exact argument usage.
  - For TTL fields, use a positive day value (example: `--ttl 1`).
  - For piping policy errors, configure `GLOVES_GET_PIPE_ALLOWLIST` or `.gloves.toml` policy."#;
const ERROR_EXPLANATION_E101: &str = r#"E101 invalid secret identifier

Secret names must be 1..=128 chars, avoid traversal, and use only:
  A-Z a-z 0-9 . _ / -

Examples:
  - Valid: `service/token`
  - Invalid: `/root/token`, `../token`, `db pass`"#;
const ERROR_EXPLANATION_E102: &str = r#"E102 invalid request identifier

Request ids must be UUID values from pending requests.

Recovery:
  gloves list --pending
  gloves approve <request-id>
  gloves deny <request-id>

Tip:
  `requests` is a label, not a request id."#;
const ERROR_EXPLANATION_E103: &str = r#"E103 missing runtime dependency

The command requires one or more binaries that were not found in PATH.

Recovery:
  - Install the missing binary (for example `gpg`, `gocryptfs`, `mountpoint`, `fusermount`).
  - Verify PATH in the current shell/session.
  - Retry the command."#;
const ERROR_EXPLANATION_E200: &str = r#"E200 forbidden by policy

The operation is blocked by ACL or configured policy rules.

Recovery:
  gloves access paths --agent <id> --json
  gloves help request
  gloves help approve"#;
const ERROR_EXPLANATION_E201: &str = r#"E201 unauthorized caller

The current caller identity is not allowed for the requested operation.

Recovery:
  - Check `--agent` identity.
  - Confirm request/approval state if using human-gated access."#;
const ERROR_EXPLANATION_E300: &str = r#"E300 resource not found

The referenced secret/request/key could not be located.

Recovery:
  gloves list
  gloves list --pending"#;
const ERROR_EXPLANATION_E301: &str = r#"E301 resource already exists

The target name is already present and overwrite is not allowed.

Recovery:
  - Choose a different name.
  - Or remove existing value with `gloves revoke <name>` and retry."#;
const ERROR_EXPLANATION_E302: &str = r#"E302 expired resource

The secret or request has exceeded its TTL.

Recovery:
  - Create a new value or request.
  - Run `gloves verify` to reap and normalize expired state."#;
const ERROR_EXPLANATION_E400: &str = r#"E400 GPG/pass denied

Human backend access was denied by pass/GPG.

Recovery:
  - Verify the active GPG session can read the value directly:
    `pass show <secret-name>`
  - Check agent-specific key setup:
    `gloves --agent <id> gpg create`"#;
const ERROR_EXPLANATION_E500: &str = r#"E500 integrity verification failed

Stored ciphertext and metadata checksum validation did not match.

Recovery:
  - Run `gloves verify`.
  - Rotate the affected secret and investigate storage integrity."#;
const ERROR_EXPLANATION_E900: &str = r#"E900 I/O failure

Filesystem or stream operations failed.

Recovery:
  - Verify `--root` exists and is writable.
  - Check file permissions and available disk space."#;
const ERROR_EXPLANATION_E999: &str = r#"E999 internal runtime failure

An internal serialization, decoding, or crypto error occurred.

Recovery:
  - Retry once with the same inputs.
  - If it persists, collect command, inputs, and stderr for diagnosis."#;

const KNOWN_ERROR_CODES: [&str; 13] = [
    ERROR_CODE_INVALID_INPUT,
    ERROR_CODE_SECRET_ID,
    ERROR_CODE_REQUEST_ID,
    ERROR_CODE_MISSING_RUNTIME,
    ERROR_CODE_FORBIDDEN,
    ERROR_CODE_UNAUTHORIZED,
    ERROR_CODE_NOT_FOUND,
    ERROR_CODE_ALREADY_EXISTS,
    ERROR_CODE_EXPIRED,
    ERROR_CODE_GPG_DENIED,
    ERROR_CODE_INTEGRITY,
    ERROR_CODE_IO,
    ERROR_CODE_INTERNAL,
];

/// Returns the stable error code for a runtime error.
pub fn classify_error_code(error: &GlovesError) -> &'static str {
    match error {
        GlovesError::Validation(_) => ERROR_CODE_SECRET_ID,
        GlovesError::InvalidInput(message) => classify_invalid_input_code(message),
        GlovesError::Forbidden => ERROR_CODE_FORBIDDEN,
        GlovesError::Unauthorized => ERROR_CODE_UNAUTHORIZED,
        GlovesError::NotFound => ERROR_CODE_NOT_FOUND,
        GlovesError::AlreadyExists => ERROR_CODE_ALREADY_EXISTS,
        GlovesError::Expired => ERROR_CODE_EXPIRED,
        GlovesError::GpgDenied => ERROR_CODE_GPG_DENIED,
        GlovesError::IntegrityViolation => ERROR_CODE_INTEGRITY,
        GlovesError::Io(_) => ERROR_CODE_IO,
        GlovesError::Serde(_) | GlovesError::Utf8(_) | GlovesError::Crypto(_) => {
            ERROR_CODE_INTERNAL
        }
    }
}

fn classify_invalid_input_code(message: &str) -> &'static str {
    let lowered = message.to_ascii_lowercase();
    if lowered.contains("request id") {
        return ERROR_CODE_REQUEST_ID;
    }
    if lowered.contains("required binary not found")
        || lowered.contains("missing required binaries")
        || lowered.contains("vault mode 'required' is set but missing required binaries")
    {
        return ERROR_CODE_MISSING_RUNTIME;
    }
    if lowered.contains("not found") {
        return ERROR_CODE_NOT_FOUND;
    }
    ERROR_CODE_INVALID_INPUT
}

/// Normalizes a user-provided error code for lookups.
pub fn normalize_error_code(raw: &str) -> String {
    raw.trim().to_ascii_uppercase()
}

/// Returns an explanation block for a known error code.
pub fn explain_error_code(raw: &str) -> Option<&'static str> {
    let normalized = normalize_error_code(raw);
    match normalized.as_str() {
        ERROR_CODE_INVALID_INPUT => Some(ERROR_EXPLANATION_E100),
        ERROR_CODE_SECRET_ID => Some(ERROR_EXPLANATION_E101),
        ERROR_CODE_REQUEST_ID => Some(ERROR_EXPLANATION_E102),
        ERROR_CODE_MISSING_RUNTIME => Some(ERROR_EXPLANATION_E103),
        ERROR_CODE_FORBIDDEN => Some(ERROR_EXPLANATION_E200),
        ERROR_CODE_UNAUTHORIZED => Some(ERROR_EXPLANATION_E201),
        ERROR_CODE_NOT_FOUND => Some(ERROR_EXPLANATION_E300),
        ERROR_CODE_ALREADY_EXISTS => Some(ERROR_EXPLANATION_E301),
        ERROR_CODE_EXPIRED => Some(ERROR_EXPLANATION_E302),
        ERROR_CODE_GPG_DENIED => Some(ERROR_EXPLANATION_E400),
        ERROR_CODE_INTEGRITY => Some(ERROR_EXPLANATION_E500),
        ERROR_CODE_IO => Some(ERROR_EXPLANATION_E900),
        ERROR_CODE_INTERNAL => Some(ERROR_EXPLANATION_E999),
        _ => None,
    }
}

/// Stable list of explainable error codes.
pub fn known_error_codes() -> &'static [&'static str] {
    &KNOWN_ERROR_CODES
}

#[cfg(test)]
mod unit_tests {
    use super::{
        classify_error_code, explain_error_code, known_error_codes, GlovesError,
        ERROR_CODE_MISSING_RUNTIME, ERROR_CODE_NOT_FOUND, ERROR_CODE_REQUEST_ID,
    };

    #[test]
    fn classify_invalid_request_id_input() {
        let error = GlovesError::InvalidInput("invalid request id `requests`".to_owned());
        assert_eq!(classify_error_code(&error), ERROR_CODE_REQUEST_ID);
    }

    #[test]
    fn classify_missing_runtime_binary() {
        let error = GlovesError::InvalidInput("required binary not found: gpg".to_owned());
        assert_eq!(classify_error_code(&error), ERROR_CODE_MISSING_RUNTIME);
    }

    #[test]
    fn classify_not_found_message_from_invalid_input() {
        let error = GlovesError::InvalidInput("secret `missing` was not found".to_owned());
        assert_eq!(classify_error_code(&error), ERROR_CODE_NOT_FOUND);
    }

    #[test]
    fn explain_request_id_code_contains_recovery_steps() {
        let explanation = explain_error_code("e102").unwrap();
        assert!(explanation.contains("gloves list --pending"));
        assert!(explanation.contains("gloves approve <request-id>"));
    }

    #[test]
    fn explain_unknown_code_returns_none() {
        assert!(explain_error_code("e000").is_none());
    }

    #[test]
    fn known_codes_include_request_id_code() {
        assert!(known_error_codes().contains(&ERROR_CODE_REQUEST_ID));
    }
}
