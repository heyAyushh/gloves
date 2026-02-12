use std::{fs, path::Path};

use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

use crate::{error::Result, types::AgentId};

const DERIVED_KEY_SIZE: usize = 32;

/// Loads an existing salt or creates a new 32-byte salt file.
pub fn load_or_create_salt(path: &Path) -> Result<[u8; DERIVED_KEY_SIZE]> {
    if path.exists() {
        let bytes = fs::read(path)?;
        let mut salt = [0_u8; DERIVED_KEY_SIZE];
        salt.copy_from_slice(&bytes[..DERIVED_KEY_SIZE]);
        return Ok(salt);
    }

    let mut salt = [0_u8; DERIVED_KEY_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);
    fs::write(path, salt)?;
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
