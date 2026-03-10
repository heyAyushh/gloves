use std::{fs, path::Path};

use hkdf::Hkdf;
use rand::RngExt;
use sha2::Sha256;

use crate::{error::Result, fs_secure::write_private_file_atomic, types::AgentId};

const DERIVED_KEY_SIZE: usize = 32;

/// Loads an existing salt or creates a new 32-byte salt file.
pub fn load_or_create_salt(path: &Path) -> Result<[u8; DERIVED_KEY_SIZE]> {
    if path.exists() {
        let bytes = fs::read(path)?;
        if bytes.len() != DERIVED_KEY_SIZE {
            return Err(crate::error::GlovesError::Crypto(
                "invalid salt length".to_owned(),
            ));
        }
        let mut salt = [0_u8; DERIVED_KEY_SIZE];
        salt.copy_from_slice(&bytes);
        return Ok(salt);
    }

    let mut salt = [0_u8; DERIVED_KEY_SIZE];
    rand::rng().fill(&mut salt);
    write_private_file_atomic(path, &salt)?;
    Ok(salt)
}

/// Derives a deterministic 32-byte key using HKDF-SHA256.
pub fn derive_agent_key(
    master_secret: &[u8],
    salt: &[u8],
    agent_id: &AgentId,
    vm_instance_id: &str,
) -> Result<[u8; DERIVED_KEY_SIZE]> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), master_secret);
    let info = format!("gloves:agent:{}:vm:{}", agent_id.as_str(), vm_instance_id);
    let mut output = [0_u8; DERIVED_KEY_SIZE];
    hkdf.expand(info.as_bytes(), &mut output)
        .map_err(|error| crate::error::GlovesError::Crypto(error.to_string()))?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{derive_agent_key, load_or_create_salt, DERIVED_KEY_SIZE};
    use crate::{error::GlovesError, types::AgentId};
    use std::fs;

    #[test]
    fn load_or_create_salt_round_trips_and_validates_length() {
        let temp_dir = tempfile::tempdir().unwrap();
        let salt_path = temp_dir.path().join("salt.bin");

        let created = load_or_create_salt(&salt_path).unwrap();
        assert!(salt_path.exists());
        assert_eq!(fs::read(&salt_path).unwrap(), created);

        let loaded = load_or_create_salt(&salt_path).unwrap();
        assert_eq!(loaded, created);

        fs::write(&salt_path, [7u8; DERIVED_KEY_SIZE - 1]).unwrap();
        let error = load_or_create_salt(&salt_path).unwrap_err();
        assert!(
            matches!(error, GlovesError::Crypto(message) if message.contains("invalid salt length"))
        );
    }

    #[test]
    fn derive_agent_key_is_deterministic_and_scoped() {
        let agent = AgentId::new("devy").unwrap();
        let other_agent = AgentId::new("main").unwrap();
        let master_secret = b"master-secret";
        let salt = [42u8; DERIVED_KEY_SIZE];

        let first = derive_agent_key(master_secret, &salt, &agent, "vm-a").unwrap();
        let second = derive_agent_key(master_secret, &salt, &agent, "vm-a").unwrap();
        let other_vm = derive_agent_key(master_secret, &salt, &agent, "vm-b").unwrap();
        let other_agent_key = derive_agent_key(master_secret, &salt, &other_agent, "vm-a").unwrap();

        assert_eq!(first, second);
        assert_ne!(first, other_vm);
        assert_ne!(first, other_agent_key);
    }
}
