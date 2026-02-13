use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

use crate::error::{GlovesError, Result};

/// Request payload for initializing a gocryptfs directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitRequest {
    /// Ciphertext directory to initialize.
    pub cipher_dir: PathBuf,
    /// External password command.
    pub extpass_command: String,
}

/// Request payload for mounting a gocryptfs directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountRequest {
    /// Ciphertext directory.
    pub cipher_dir: PathBuf,
    /// Plaintext mountpoint.
    pub mount_point: PathBuf,
    /// External password command.
    pub extpass_command: String,
    /// Optional idle timeout for auto-unmount.
    pub idle_timeout: Option<Duration>,
}

/// Filesystem encryption orchestration abstraction.
pub trait FsEncryptionDriver: Send + Sync {
    /// Initializes a new encrypted directory.
    fn init(&self, request: &InitRequest) -> Result<()>;
    /// Mounts an encrypted directory and returns driver pid.
    fn mount(&self, request: &MountRequest) -> Result<u32>;
    /// Unmounts one mountpoint.
    fn unmount(&self, mount_point: &Path) -> Result<()>;
    /// Returns mount status for one mountpoint.
    fn is_mounted(&self, mount_point: &Path) -> Result<bool>;
}

/// System gocryptfs/fuse command driver.
#[derive(Debug, Clone)]
pub struct GocryptfsDriver {
    gocryptfs_binary: String,
    fusermount_binary: String,
    mountpoint_binary: String,
}

impl GocryptfsDriver {
    /// Constructs a driver using default binary names.
    pub fn new() -> Self {
        Self {
            gocryptfs_binary: "gocryptfs".to_owned(),
            fusermount_binary: "fusermount".to_owned(),
            mountpoint_binary: "mountpoint".to_owned(),
        }
    }

    /// Constructs a driver with custom binaries.
    pub fn with_binaries(
        gocryptfs_binary: impl Into<String>,
        fusermount_binary: impl Into<String>,
        mountpoint_binary: impl Into<String>,
    ) -> Self {
        Self {
            gocryptfs_binary: gocryptfs_binary.into(),
            fusermount_binary: fusermount_binary.into(),
            mountpoint_binary: mountpoint_binary.into(),
        }
    }
}

impl Default for GocryptfsDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl FsEncryptionDriver for GocryptfsDriver {
    fn init(&self, request: &InitRequest) -> Result<()> {
        fs::create_dir_all(&request.cipher_dir)?;

        let output = Command::new(&self.gocryptfs_binary)
            .args(["-init", "-extpass"])
            .arg(&request.extpass_command)
            .arg(&request.cipher_dir)
            .output()?;
        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        Err(GlovesError::Crypto(format!(
            "gocryptfs init failed: {stderr}"
        )))
    }

    fn mount(&self, request: &MountRequest) -> Result<u32> {
        fs::create_dir_all(&request.mount_point)?;

        let mut command = Command::new(&self.gocryptfs_binary);
        command
            .args(["-extpass"])
            .arg(&request.extpass_command)
            .args(["-nosyslog", "-fg"]);
        if let Some(timeout) = request.idle_timeout {
            command.args(["-idle", &format!("{}s", timeout.as_secs())]);
        }
        command
            .arg(&request.cipher_dir)
            .arg(&request.mount_point)
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let child = command.spawn()?;
        Ok(child.id())
    }

    fn unmount(&self, mount_point: &Path) -> Result<()> {
        let status = Command::new(&self.fusermount_binary)
            .args(["-u"])
            .arg(mount_point)
            .status()?;
        if status.success() {
            return Ok(());
        }
        Err(GlovesError::Crypto("gocryptfs unmount failed".to_owned()))
    }

    fn is_mounted(&self, mount_point: &Path) -> Result<bool> {
        Ok(Command::new(&self.mountpoint_binary)
            .arg("-q")
            .arg(mount_point)
            .status()
            .map(|status| status.success())
            .unwrap_or(false))
    }
}
