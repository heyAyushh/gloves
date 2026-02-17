use std::{
    fs,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use crate::{
    agent::age_crypto,
    error::{GlovesError, Result},
    fs_secure::write_private_file_atomic,
    types::{SecretId, SecretValue},
};

/// Encrypted storage backend for agent-owned secrets.
pub struct AgentBackend {
    store_dir: PathBuf,
}

impl AgentBackend {
    /// Creates a backend rooted at `store_dir`.
    pub fn new(store_dir: impl AsRef<Path>) -> Result<Self> {
        let directory = store_dir.as_ref().to_path_buf();
        fs::create_dir_all(&directory)?;
        Ok(Self {
            store_dir: directory,
        })
    }

    /// Encrypts and stores a secret for the provided recipients.
    pub fn encrypt(
        &self,
        secret_id: &SecretId,
        secret_value: &SecretValue,
        recipient_keys: Vec<String>,
    ) -> Result<PathBuf> {
        let ciphertext_path = self.ciphertext_path(secret_id);
        if ciphertext_path.exists() {
            return Err(GlovesError::AlreadyExists);
        }
        ensure_parent_dir(&ciphertext_path)?;
        self.encrypt_to_path(secret_value, &recipient_keys, &ciphertext_path)?;

        Ok(ciphertext_path)
    }

    /// Decrypts a stored secret with the supplied identity file.
    pub fn decrypt(&self, secret_id: &SecretId, identity_file: &Path) -> Result<SecretValue> {
        let plaintext = age_crypto::decrypt_file(&self.ciphertext_path(secret_id), identity_file)?;
        Ok(SecretValue::new(plaintext))
    }

    /// Re-encrypts a secret with an updated recipient set.
    pub fn grant(
        &self,
        secret_id: &SecretId,
        decrypting_identity_file: &Path,
        recipient_keys: Vec<String>,
    ) -> Result<()> {
        let plaintext = self.decrypt(secret_id, decrypting_identity_file)?;
        let path = self.ciphertext_path(secret_id);
        self.encrypt_to_path(&plaintext, &recipient_keys, &path)?;
        Ok(())
    }

    /// Deletes encrypted file for a secret.
    pub fn delete(&self, secret_id: &SecretId) -> Result<()> {
        let path = self.ciphertext_path(secret_id);
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    /// Returns path to encrypted file.
    pub fn ciphertext_path(&self, secret_id: &SecretId) -> PathBuf {
        self.store_dir.join(format!("{}.age", secret_id.as_str()))
    }

    /// Computes the SHA-256 checksum (hex) of stored ciphertext.
    pub fn ciphertext_checksum(&self, secret_id: &SecretId) -> Result<String> {
        let bytes = fs::read(self.ciphertext_path(secret_id))?;
        Ok(checksum_hex(&bytes))
    }

    fn encrypt_to_path(
        &self,
        secret_value: &SecretValue,
        recipient_keys: &[String],
        output_path: &Path,
    ) -> Result<()> {
        if recipient_keys.is_empty() {
            return Err(GlovesError::Crypto("no recipients provided".to_owned()));
        }
        ensure_parent_dir(output_path)?;

        let ciphertext = secret_value
            .expose(|value| age_crypto::encrypt_for_recipients(value, recipient_keys))?;
        write_private_file_atomic(output_path, &ciphertext)?;
        Ok(())
    }
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    let parent = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    Ok(())
}

fn checksum_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
