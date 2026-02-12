use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::{
    error::Result,
    fs_secure::write_private_file_atomic,
    types::{SecretId, SecretMeta},
};

/// Store for secret metadata JSON files.
pub struct MetadataStore {
    root: PathBuf,
}

impl MetadataStore {
    /// Creates metadata store rooted at `root`.
    pub fn new(root: impl AsRef<Path>) -> Result<Self> {
        let path = root.as_ref().to_path_buf();
        fs::create_dir_all(&path)?;
        Ok(Self { root: path })
    }

    /// Saves metadata for one secret.
    pub fn save(&self, meta: &SecretMeta) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(meta)?;
        let path = self.path_for(&meta.id);
        write_private_file_atomic(&path, &bytes)?;
        Ok(())
    }

    /// Loads metadata by secret id.
    pub fn load(&self, secret_id: &SecretId) -> Result<SecretMeta> {
        let bytes = fs::read(self.path_for(secret_id))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Deletes metadata if it exists.
    pub fn delete(&self, secret_id: &SecretId) -> Result<()> {
        let path = self.path_for(secret_id);
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    /// Lists all metadata entries.
    pub fn list(&self) -> Result<Vec<SecretMeta>> {
        let mut entries = Vec::new();
        let mut directories = vec![self.root.clone()];

        while let Some(directory) = directories.pop() {
            for entry in fs::read_dir(directory)? {
                let path = entry?.path();
                if path.is_dir() {
                    directories.push(path);
                } else if path.extension().and_then(|value| value.to_str()) == Some("json") {
                    let bytes = fs::read(path)?;
                    entries.push(serde_json::from_slice(&bytes)?);
                }
            }
        }
        Ok(entries)
    }

    /// Returns metadata path for a secret id.
    pub fn path_for(&self, secret_id: &SecretId) -> PathBuf {
        self.root.join(format!("{}.json", secret_id.as_str()))
    }
}
