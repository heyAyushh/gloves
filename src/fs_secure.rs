use std::{
    fs,
    path::{Path, PathBuf},
};

use uuid::Uuid;

use crate::error::Result;

/// Default Unix mode for private directories.
pub const PRIVATE_DIR_MODE: u32 = 0o700;
/// Default Unix mode for private files.
pub const PRIVATE_FILE_MODE: u32 = 0o600;

/// Ensures a directory exists and applies restricted permissions.
pub fn ensure_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    set_permissions(path, PRIVATE_DIR_MODE)
}

/// Writes a file atomically with restricted permissions.
pub fn write_private_file_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    create_parent_dir(path)?;

    let temp_path = temp_path_for(path);
    fs::write(&temp_path, bytes)?;
    set_permissions(&temp_path, PRIVATE_FILE_MODE)?;
    fs::rename(&temp_path, path)?;
    set_permissions(path, PRIVATE_FILE_MODE)
}

/// Writes a private file only if it does not exist.
pub fn create_private_file_if_missing(path: &Path, bytes: &[u8]) -> Result<()> {
    if !path.exists() {
        write_private_file_atomic(path, bytes)?;
    }
    Ok(())
}

/// Applies Unix permissions when supported.
pub fn set_permissions(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

fn temp_path_for(path: &Path) -> PathBuf {
    let suffix = Uuid::new_v4();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("tmp");
    let temp_name = format!(".{file_name}.{suffix}.tmp");
    path.with_file_name(temp_name)
}

fn create_parent_dir(path: &Path) -> Result<()> {
    let parent = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    Ok(())
}
