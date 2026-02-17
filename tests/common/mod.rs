use std::path::{Path, PathBuf};

use secrecy::ExposeSecret;

/// Identity material generated for in-process age-format encryption.
#[allow(dead_code)]
pub struct IdentityMaterial {
    /// Path to private identity file.
    pub identity_file: PathBuf,
    /// Derived public recipient key.
    pub recipient: String,
}

/// Generates one identity file and recipient key using the age Rust library.
pub fn generate_identity(root: &Path, label: &str) -> IdentityMaterial {
    let identity_file = root.join(format!("{label}.agekey"));
    let identity = age::x25519::Identity::generate();
    std::fs::write(
        &identity_file,
        identity.to_string().expose_secret().as_bytes(),
    )
    .unwrap_or_else(|error| {
        panic!(
            "failed to write identity {}: {error}",
            identity_file.display()
        )
    });

    let recipient = identity.to_public().to_string();
    assert!(!recipient.is_empty(), "generated empty recipient");

    IdentityMaterial {
        identity_file,
        recipient,
    }
}
