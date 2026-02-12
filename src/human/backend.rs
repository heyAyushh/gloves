use std::process::Command;

use crate::{
    error::{GlovesError, Result},
    types::SecretValue,
};

/// Result type produced by pass command execution.
#[derive(Debug, Clone)]
pub struct PassOutput {
    /// Exit status code.
    pub status_code: i32,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
}

/// Executor abstraction for `pass` commands.
pub trait PassExecutor: Send + Sync {
    /// Executes pass with command-line arguments.
    fn exec(&self, args: &[&str]) -> Result<PassOutput>;
}

/// Real executor that calls the system `pass` binary.
pub struct SystemPassExecutor {
    binary: String,
}

impl SystemPassExecutor {
    /// Creates a system executor using the `pass` binary.
    pub fn new() -> Self {
        Self {
            binary: "pass".to_owned(),
        }
    }

    /// Creates a system executor with a custom binary path.
    pub fn with_binary(binary: impl Into<String>) -> Self {
        Self {
            binary: binary.into(),
        }
    }
}

impl Default for SystemPassExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl PassExecutor for SystemPassExecutor {
    fn exec(&self, args: &[&str]) -> Result<PassOutput> {
        let output = Command::new(&self.binary).args(args).output()?;
        Ok(PassOutput {
            status_code: output.status.code().unwrap_or(1),
            stdout: String::from_utf8(output.stdout)?,
            stderr: String::from_utf8(output.stderr)?,
        })
    }
}

/// Backend for reading human-owned secrets through `pass`.
pub struct HumanBackend {
    executor: Box<dyn PassExecutor>,
}

impl HumanBackend {
    /// Creates backend with default system executor.
    pub fn new() -> Self {
        Self {
            executor: Box::new(SystemPassExecutor::new()),
        }
    }

    /// Creates backend with a custom executor, useful for tests.
    pub fn with_executor(executor: Box<dyn PassExecutor>) -> Self {
        Self { executor }
    }

    /// Reads one secret from pass.
    pub fn get(&self, secret_name: &str) -> Result<SecretValue> {
        let output = self.executor.exec(&["show", secret_name])?;
        if output.status_code == 0 {
            let parsed = output.stdout.trim_end_matches('\n').as_bytes().to_vec();
            return Ok(SecretValue::new(parsed));
        }

        if output.stderr.contains("is not in the password store") {
            return Err(GlovesError::NotFound);
        }
        if output.stderr.contains("decryption failed") {
            return Err(GlovesError::GpgDenied);
        }

        Err(GlovesError::Crypto(output.stderr))
    }

    /// Checks whether a secret exists in pass.
    pub fn exists(&self, secret_name: &str) -> Result<bool> {
        let output = self.executor.exec(&["show", secret_name])?;
        Ok(output.status_code == 0)
    }
}

impl Default for HumanBackend {
    fn default() -> Self {
        Self::new()
    }
}
