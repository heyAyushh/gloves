use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use age::{Decryptor, Encryptor};
use sha2::{Digest, Sha256};

use crate::{
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
        recipients: Vec<age::x25519::Recipient>,
    ) -> Result<PathBuf> {
        let ciphertext_path = self.ciphertext_path(secret_id);
        if ciphertext_path.exists() {
            return Err(GlovesError::AlreadyExists);
        }
        ensure_parent_dir(&ciphertext_path)?;
        self.encrypt_to_path(secret_value, recipients, &ciphertext_path)?;

        Ok(ciphertext_path)
    }

    /// Decrypts a stored secret using one of the supplied identities.
    pub fn decrypt(
        &self,
        secret_id: &SecretId,
        identities: Vec<age::x25519::Identity>,
    ) -> Result<SecretValue> {
        let ciphertext = fs::read(self.ciphertext_path(secret_id))?;
        let decryptor = Decryptor::new(&ciphertext[..])
            .map_err(|error: age::DecryptError| GlovesError::Crypto(error.to_string()))?;

        match decryptor {
            Decryptor::Recipients(recipient_decryptor) => {
                let identity_refs: Vec<&dyn age::Identity> = identities
                    .iter()
                    .map(|identity| identity as &dyn age::Identity)
                    .collect();
                let mut reader = recipient_decryptor
                    .decrypt(identity_refs.into_iter())
                    .map_err(|error| GlovesError::Crypto(error.to_string()))?;
                let mut plaintext = Vec::new();
                std::io::Read::read_to_end(&mut reader, &mut plaintext)?;
                Ok(SecretValue::new(plaintext))
            }
            _ => Err(GlovesError::Crypto("unsupported age header".to_owned())),
        }
    }

    /// Re-encrypts a secret with an updated recipient set.
    pub fn grant(
        &self,
        secret_id: &SecretId,
        decrypting_identity: age::x25519::Identity,
        recipients: Vec<age::x25519::Recipient>,
    ) -> Result<()> {
        let plaintext = self.decrypt(secret_id, vec![decrypting_identity])?;
        let path = self.ciphertext_path(secret_id);
        self.encrypt_to_path(&plaintext, recipients, &path)?;
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
        recipients: Vec<age::x25519::Recipient>,
        output_path: &Path,
    ) -> Result<()> {
        ensure_parent_dir(output_path)?;
        let recipients = recipients
            .into_iter()
            .map(|recipient| Box::new(recipient) as Box<dyn age::Recipient + Send>)
            .collect();
        let encryptor = Encryptor::with_recipients(recipients)
            .ok_or_else(|| GlovesError::Crypto("no recipients provided".to_owned()))?;

        let mut ciphertext = Vec::new();
        let mut writer = encryptor
            .wrap_output(&mut ciphertext)
            .map_err(|error: age::EncryptError| GlovesError::Crypto(error.to_string()))?;
        secret_value.expose(|value| writer.write_all(value))?;
        writer
            .finish()
            .map_err(|error: std::io::Error| GlovesError::Crypto(error.to_string()))?;

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

/// Parses an age recipient string.
pub fn parse_recipient(recipient: &str) -> Result<age::x25519::Recipient> {
    recipient
        .parse::<age::x25519::Recipient>()
        .map_err(|error| GlovesError::Crypto(error.to_string()))
}

/// Returns an age recipient from an identity.
pub fn identity_recipient(identity: &age::x25519::Identity) -> age::x25519::Recipient {
    identity.to_public()
}

/// Parses an age identity string.
pub fn parse_identity(identity: &str) -> Result<age::x25519::Identity> {
    identity
        .parse::<age::x25519::Identity>()
        .map_err(|error| GlovesError::Crypto(error.to_string()))
}
