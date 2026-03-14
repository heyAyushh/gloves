use std::path::{Path, PathBuf};

const DEFAULT_AGENT_ID: &str = "default-agent";
const AGENTS_DIR_NAME: &str = "agents";
const AGE_KEY_FILE_NAME: &str = "age.key";
const SIGNING_KEY_FILE_NAME: &str = "signing.key";
const GPG_DIR_NAME: &str = "gpg";

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
        self.identity_file_for_agent(DEFAULT_AGENT_ID)
    }

    /// Canonical per-agent identity root.
    pub fn agents_dir(&self) -> PathBuf {
        self.root.join(AGENTS_DIR_NAME)
    }

    /// Canonical per-agent runtime directory.
    pub fn agent_dir(&self, agent_id: &str) -> PathBuf {
        self.agents_dir().join(agent_id)
    }

    /// Age identity file for one agent id.
    pub fn identity_file_for_agent(&self, agent_id: &str) -> PathBuf {
        self.agent_dir(agent_id).join(AGE_KEY_FILE_NAME)
    }

    /// Legacy root-level age identity file for one agent id.
    pub fn legacy_identity_file_for_agent(&self, agent_id: &str) -> PathBuf {
        self.root.join(format!("{agent_id}.agekey"))
    }

    /// Legacy namespaced-store age identity file for one agent id.
    pub fn namespaced_identity_file_for_agent(&self, agent_id: &str) -> PathBuf {
        self.root.join("identities").join(format!("{agent_id}.age"))
    }

    /// Default Ed25519 signing key file for CLI agent.
    pub fn default_signing_key_file(&self) -> PathBuf {
        self.signing_key_file_for_agent(DEFAULT_AGENT_ID)
    }

    /// Ed25519 signing key file for one agent id.
    pub fn signing_key_file_for_agent(&self, agent_id: &str) -> PathBuf {
        self.agent_dir(agent_id).join(SIGNING_KEY_FILE_NAME)
    }

    /// Legacy root-level Ed25519 signing key file for one agent id.
    pub fn legacy_signing_key_file_for_agent(&self, agent_id: &str) -> PathBuf {
        self.root.join(format!("{agent_id}.signing.key"))
    }

    /// Vault configuration directory.
    pub fn vaults_dir(&self) -> PathBuf {
        self.root.join("vaults")
    }

    /// Per-agent GPG homedir root.
    pub fn gpg_homes_dir(&self) -> PathBuf {
        self.agents_dir()
    }

    /// GPG homedir for one agent id.
    pub fn gpg_home(&self, agent_id: &str) -> PathBuf {
        self.agent_dir(agent_id).join(GPG_DIR_NAME)
    }

    /// Legacy GPG homedir for one agent id.
    pub fn legacy_gpg_home(&self, agent_id: &str) -> PathBuf {
        self.root.join(GPG_DIR_NAME).join(agent_id)
    }

    /// Vault session metadata file.
    pub fn vault_sessions_file(&self) -> PathBuf {
        self.vaults_dir().join("sessions.json")
    }

    /// Encrypted vault payload root directory.
    pub fn encrypted_dir(&self) -> PathBuf {
        self.root.join("encrypted")
    }

    /// Default vault mount root directory.
    pub fn mounts_dir(&self) -> PathBuf {
        self.root.join("mnt")
    }

    /// Path to one vault config file.
    pub fn vault_config_file(&self, vault_name: &str) -> PathBuf {
        self.vaults_dir().join(format!("{vault_name}.toml"))
    }

    /// Path to one vault ciphertext directory.
    pub fn vault_cipher_dir(&self, vault_name: &str) -> PathBuf {
        self.encrypted_dir().join(vault_name)
    }

    /// Path to one vault mountpoint.
    pub fn vault_mountpoint(&self, vault_name: &str) -> PathBuf {
        self.mounts_dir().join(vault_name)
    }
}
