use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{
    error::{GlovesError, Result},
    fs_secure::{set_permissions, write_private_file_atomic, PRIVATE_FILE_MODE},
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
        if !file_path.exists() {
            ensure_parent_dir(&file_path)?;
            let initial = RegistryData::new();
            write_private_file_atomic(&file_path, &serde_json::to_vec_pretty(&initial)?)?;
        }
        let data = serde_json::from_slice(&fs::read(&file_path)?)?;
        set_permissions(&file_path, PRIVATE_FILE_MODE)?;
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
            self.data
                .vouchers
                .insert(agent_id.clone(), agent_id.clone());
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
        write_private_file_atomic(&self.path, &serde_json::to_vec_pretty(&self.data)?)?;
        Ok(())
    }

    fn integrity_tag(&self) -> String {
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(&self.hmac_secret)
            .expect("HMAC-SHA256 accepts keys of any size");
        let mut entries: Vec<_> = self.data.entries.iter().collect();
        entries.sort_by_key(|(agent_id, _)| agent_id.as_str().to_owned());
        for (agent_id, recipient) in entries {
            mac.update(agent_id.as_str().as_bytes());
            mac.update(recipient.as_bytes());
        }
        let bytes = mac.finalize().into_bytes();
        bytes
            .iter()
            .map(|value| format!("{value:02x}"))
            .collect::<String>()
    }
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    let parent = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::AgentRegistry;
    use crate::{error::GlovesError, types::AgentId};
    use std::fs;

    #[test]
    fn registry_bootstraps_registers_and_verifies_integrity() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("registry/agents.json");
        let mut registry = AgentRegistry::load_or_create(&path, b"registry-secret").unwrap();
        let main = AgentId::new("main").unwrap();
        let devy = AgentId::new("devy").unwrap();

        registry
            .register(main.clone(), "age1main".to_owned(), None)
            .unwrap();
        registry
            .register(devy.clone(), "age1devy".to_owned(), Some(main.clone()))
            .unwrap();

        assert_eq!(registry.get_pubkey(&main), Some("age1main"));
        assert_eq!(registry.get_pubkey(&devy), Some("age1devy"));
        assert!(registry.verify_integrity());

        let reloaded = AgentRegistry::load_or_create(&path, b"registry-secret").unwrap();
        assert_eq!(reloaded.get_pubkey(&devy), Some("age1devy"));
        assert!(reloaded.verify_integrity());
    }

    #[test]
    fn registry_rejects_duplicates_and_missing_vouchers() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("registry.json");
        let mut registry = AgentRegistry::load_or_create(&path, b"registry-secret").unwrap();
        let main = AgentId::new("main").unwrap();
        let devy = AgentId::new("devy").unwrap();
        let unknown = AgentId::new("ghost").unwrap();

        registry
            .register(main.clone(), "age1main".to_owned(), None)
            .unwrap();

        let duplicate = registry
            .register(main.clone(), "age1other".to_owned(), None)
            .unwrap_err();
        assert!(matches!(duplicate, GlovesError::AlreadyExists));

        let missing_voucher = registry
            .register(devy.clone(), "age1devy".to_owned(), None)
            .unwrap_err();
        assert!(matches!(missing_voucher, GlovesError::Forbidden));

        let unknown_voucher = registry
            .register(devy, "age1devy".to_owned(), Some(unknown))
            .unwrap_err();
        assert!(matches!(unknown_voucher, GlovesError::Forbidden));
    }

    #[test]
    fn registry_detects_tampered_integrity_tag() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("registry.json");
        let mut registry = AgentRegistry::load_or_create(&path, b"registry-secret").unwrap();
        let main = AgentId::new("main").unwrap();
        registry
            .register(main.clone(), "age1main".to_owned(), None)
            .unwrap();

        let mut payload: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        payload["entries"]["main"] = serde_json::json!("age1tampered");
        fs::write(&path, serde_json::to_vec_pretty(&payload).unwrap()).unwrap();

        let tampered = AgentRegistry::load_or_create(&path, b"registry-secret").unwrap();
        assert_eq!(tampered.get_pubkey(&main), Some("age1tampered"));
        assert!(!tampered.verify_integrity());
    }
}
