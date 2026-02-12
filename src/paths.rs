use std::path::{Path, PathBuf};

/// Canonical path layout for secrets runtime files.
#[derive(Debug, Clone)]
pub struct SecretsPaths {
    root: PathBuf,
}

impl SecretsPaths {
    /// Creates a path layout rooted at `root`.
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    /// Root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Agent ciphertext store directory.
    pub fn store_dir(&self) -> PathBuf {
        self.root.join("store")
    }

    /// Secret metadata directory.
    pub fn metadata_dir(&self) -> PathBuf {
        self.root.join("meta")
    }

    /// Pending requests JSON file.
    pub fn pending_file(&self) -> PathBuf {
        self.root.join("pending.json")
    }

    /// Audit log JSONL file.
    pub fn audit_file(&self) -> PathBuf {
        self.root.join("audit.jsonl")
    }

    /// Default age identity file for CLI agent.
    pub fn default_identity_file(&self) -> PathBuf {
        self.root.join("default-agent.agekey")
    }

    /// Default Ed25519 signing key file for CLI agent.
    pub fn default_signing_key_file(&self) -> PathBuf {
        self.root.join("default-agent.signing.key")
    }
}
