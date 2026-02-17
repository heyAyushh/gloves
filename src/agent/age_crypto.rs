use std::{
    fs,
    io::{Read, Write},
    path::Path,
};

use age::{Decryptor, Encryptor};
use secrecy::ExposeSecret;

use crate::{
    error::{GlovesError, Result},
    fs_secure::{set_permissions, write_private_file_atomic, PRIVATE_FILE_MODE},
};

/// Generates a new identity file in age format.
pub fn generate_identity_file(identity_file: &Path) -> Result<()> {
    ensure_parent_dir(identity_file)?;
    let identity = age::x25519::Identity::generate();
    let encoded_identity = identity.to_string();
    write_private_file_atomic(identity_file, encoded_identity.expose_secret().as_bytes())?;
    set_permissions(identity_file, PRIVATE_FILE_MODE)?;
    Ok(())
}

/// Validates an identity file by parsing its contents.
pub fn validate_identity_file(identity_file: &Path) -> Result<()> {
    let _ = parse_identity_file(identity_file)?;
    Ok(())
}

/// Derives an age-format recipient key from an identity file.
pub fn recipient_from_identity_file(identity_file: &Path) -> Result<String> {
    let identity = parse_identity_file(identity_file)?;
    Ok(identity.to_public().to_string())
}

/// Encrypts plaintext bytes for the provided recipients.
pub fn encrypt_for_recipients(plaintext: &[u8], recipients: &[String]) -> Result<Vec<u8>> {
    if recipients.is_empty() {
        return Err(GlovesError::Crypto("no recipients provided".to_owned()));
    }

    let mut recipient_keys = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        recipient_keys.push(parse_recipient(recipient)?);
    }
    let encryptor = Encryptor::with_recipients(
        recipient_keys
            .iter()
            .map(|recipient| recipient as &dyn age::Recipient),
    )
    .map_err(|error: age::EncryptError| GlovesError::Crypto(error.to_string()))?;

    let mut ciphertext = Vec::new();
    let mut writer = encryptor.wrap_output(&mut ciphertext)?;
    writer.write_all(plaintext)?;
    writer.finish()?;
    Ok(ciphertext)
}

/// Decrypts a ciphertext file using one identity file.
pub fn decrypt_file(ciphertext_file: &Path, identity_file: &Path) -> Result<Vec<u8>> {
    let ciphertext = fs::read(ciphertext_file)?;
    let decryptor = Decryptor::new(&ciphertext[..])
        .map_err(|error: age::DecryptError| GlovesError::Crypto(error.to_string()))?;
    let identity = parse_identity_file(identity_file)?;
    let identities: [&dyn age::Identity; 1] = [&identity];

    let mut reader = decryptor
        .decrypt(identities.into_iter())
        .map_err(|error: age::DecryptError| GlovesError::Crypto(error.to_string()))?;
    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext)?;
    Ok(plaintext)
}

fn parse_identity_file(identity_file: &Path) -> Result<age::x25519::Identity> {
    let raw_identity = fs::read_to_string(identity_file)?;
    for (line_index, line) in raw_identity.lines().enumerate() {
        let trimmed_line = line.trim();
        if trimmed_line.is_empty() || trimmed_line.starts_with('#') {
            continue;
        }

        return parse_identity_line(trimmed_line, identity_file, line_index + 1);
    }

    Err(GlovesError::Crypto(format!(
        "identity file has no key material: {}",
        identity_file.display()
    )))
}

fn parse_identity_line(
    encoded_identity: &str,
    identity_file: &Path,
    line_number: usize,
) -> Result<age::x25519::Identity> {
    encoded_identity
        .parse::<age::x25519::Identity>()
        .map_err(|error| {
            GlovesError::Crypto(format!(
                "invalid identity in {} at line {}: {error}",
                identity_file.display(),
                line_number
            ))
        })
}

fn parse_recipient(recipient: &str) -> Result<age::x25519::Recipient> {
    recipient
        .parse::<age::x25519::Recipient>()
        .map_err(|error| GlovesError::Crypto(format!("invalid recipient: {error}")))
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{recipient_from_identity_file, validate_identity_file};

    use secrecy::ExposeSecret;

    #[test]
    fn recipient_from_identity_file_accepts_comment_prefixed_identity() {
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_file = temp_dir.path().join("default-agent.agekey");
        let identity = age::x25519::Identity::generate();
        let identity_secret = identity.to_string();
        let content = format!(
            "# created: 2026-02-17T12:00:00Z\n{}\n",
            identity_secret.expose_secret()
        );
        std::fs::write(&identity_file, content).unwrap();

        let derived_recipient = recipient_from_identity_file(&identity_file).unwrap();
        assert_eq!(derived_recipient, identity.to_public().to_string());
    }

    #[test]
    fn validate_identity_file_rejects_files_without_key_material() {
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_file = temp_dir.path().join("default-agent.agekey");
        std::fs::write(&identity_file, "# generated by rage-keygen\n\n").unwrap();

        assert!(validate_identity_file(&identity_file).is_err());
    }
}
