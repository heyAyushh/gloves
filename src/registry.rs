use std::{collections::HashMap, fs, path::{Path, PathBuf}};

use sha2::{Digest, Sha256};

use crate::{
    error::{GlovesError, Result},
    types::AgentId,
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RegistryData {
    entries: HashMap<AgentId, String>,
    vouchers: HashMap<AgentId, AgentId>,
    integrity_tag: String,
}

impl RegistryData {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            vouchers: HashMap::new(),
            integrity_tag: String::new(),
        }
    }
}

/// Registry mapping agents to recipient public keys.
pub struct AgentRegistry {
    path: PathBuf,
    hmac_secret: Vec<u8>,
    data: RegistryData,
}

impl AgentRegistry {
    /// Loads or initializes a registry file.
    pub fn load_or_create(path: impl AsRef<Path>, hmac_secret: &[u8]) -> Result<Self> {
        let file_path = path.as_ref().to_path_buf();
        let data = if file_path.exists() {
            serde_json::from_slice(&fs::read(&file_path)?)?
        } else {
            RegistryData::new()
        };
        Ok(Self {
            path: file_path,
            hmac_secret: hmac_secret.to_vec(),
            data,
        })
    }

    /// Registers a new agent public key.
    pub fn register(
        &mut self,
        agent_id: AgentId,
        recipient_public_key: String,
        voucher: Option<AgentId>,
    ) -> Result<()> {
        if self.data.entries.contains_key(&agent_id) {
            return Err(GlovesError::AlreadyExists);
        }

        if !self.data.entries.is_empty() {
            let voucher_id = voucher.ok_or(GlovesError::Forbidden)?;
            if !self.data.entries.contains_key(&voucher_id) {
                return Err(GlovesError::Forbidden);
            }
            self.data.vouchers.insert(agent_id.clone(), voucher_id);
        } else {
            // bootstrap: self-vouch for first agent
            self.data.vouchers.insert(agent_id.clone(), agent_id.clone());
        }

        self.data.entries.insert(agent_id, recipient_public_key);
        self.persist()
    }

    /// Gets a public key for an agent.
    pub fn get_pubkey(&self, agent_id: &AgentId) -> Option<&str> {
        self.data.entries.get(agent_id).map(String::as_str)
    }

    /// Validates registry integrity tag.
    pub fn verify_integrity(&self) -> bool {
        self.integrity_tag() == self.data.integrity_tag
    }

    fn persist(&mut self) -> Result<()> {
        self.data.integrity_tag = self.integrity_tag();
        fs::write(&self.path, serde_json::to_vec_pretty(&self.data)?)?;
        Ok(())
    }

    fn integrity_tag(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.hmac_secret);
        let mut entries: Vec<_> = self.data.entries.iter().collect();
        entries.sort_by_key(|(agent_id, _)| agent_id.as_str().to_owned());
        for (agent_id, recipient) in entries {
            hasher.update(agent_id.as_str().as_bytes());
            hasher.update(recipient.as_bytes());
        }
        format!("{:x}", hasher.finalize())
    }
}
