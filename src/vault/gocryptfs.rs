use std::{
    fs, io,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::Duration,
};

use crate::error::{GlovesError, Result};

const EXEC_BUSY_RETRY_ATTEMPTS: usize = 20;
const EXEC_BUSY_RETRY_DELAY: Duration = Duration::from_millis(10);
/// Root path environment key used by the internal extpass helper.
pub const EXTPASS_ROOT_ENV_VAR: &str = "GLOVES_EXTPASS_ROOT";
/// Agent id environment key used by the internal extpass helper.
pub const EXTPASS_AGENT_ENV_VAR: &str = "GLOVES_EXTPASS_AGENT";

/// Request payload for initializing a gocryptfs directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitRequest {
    /// Ciphertext directory to initialize.
    pub cipher_dir: PathBuf,
    /// External password command.
    pub extpass_command: String,
    /// Extra environment variables for the extpass command.
    pub extpass_environment: Vec<(String, String)>,
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
    /// Extra environment variables for the extpass command.
    pub extpass_environment: Vec<(String, String)>,
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

        let output = retry_exec_busy(|| {
            let mut command = Command::new(&self.gocryptfs_binary);
            command
                .args(["-init", "-extpass"])
                .arg(&request.extpass_command)
                .arg(&request.cipher_dir);
            apply_extpass_environment(&mut command, &request.extpass_environment);
            command.output()
        })
        .map_err(|error| map_command_execution_error(&self.gocryptfs_binary, error))?;
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
        apply_extpass_environment(&mut command, &request.extpass_environment);

        let child = retry_exec_busy(|| command.spawn())
            .map_err(|error| map_command_execution_error(&self.gocryptfs_binary, error))?;
        Ok(child.id())
    }

    fn unmount(&self, mount_point: &Path) -> Result<()> {
        let status = retry_exec_busy(|| {
            Command::new(&self.fusermount_binary)
                .args(["-u"])
                .arg(mount_point)
                .status()
        })
        .map_err(|error| map_command_execution_error(&self.fusermount_binary, error))?;
        if status.success() {
            return Ok(());
        }
        Err(GlovesError::Crypto("gocryptfs unmount failed".to_owned()))
    }

    fn is_mounted(&self, mount_point: &Path) -> Result<bool> {
        let status = retry_exec_busy(|| {
            Command::new(&self.mountpoint_binary)
                .arg("-q")
                .arg(mount_point)
                .status()
        })
        .map_err(|error| map_command_execution_error(&self.mountpoint_binary, error))?;
        Ok(status.success())
    }
}

fn apply_extpass_environment(command: &mut Command, extpass_environment: &[(String, String)]) {
    for (key, value) in extpass_environment {
        command.env(key, value);
    }
}

fn map_command_execution_error(binary: &str, error: io::Error) -> GlovesError {
    if error.kind() == io::ErrorKind::NotFound {
        return GlovesError::Crypto(format!("required binary not found: {binary}"));
    }
    GlovesError::Io(error)
}

fn retry_exec_busy<T, F>(mut operation: F) -> io::Result<T>
where
    F: FnMut() -> io::Result<T>,
{
    let mut last_error = None;
    for attempt in 0..EXEC_BUSY_RETRY_ATTEMPTS {
        match operation() {
            Ok(value) => return Ok(value),
            Err(error) if is_exec_busy_error(&error) && attempt + 1 < EXEC_BUSY_RETRY_ATTEMPTS => {
                last_error = Some(error);
                thread::sleep(EXEC_BUSY_RETRY_DELAY);
            }
            Err(error) => return Err(error),
        }
    }

    Err(last_error.unwrap_or_else(|| io::Error::other("command execution failed")))
}

fn is_exec_busy_error(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::ExecutableFileBusy || error.raw_os_error() == Some(26)
}
