mod commands;
mod daemon;
mod output;
mod runtime;
mod secret_input;
mod vault_cmd;

use std::path::PathBuf;

use chrono::Duration;
use clap::{Parser, Subcommand, ValueEnum};

use crate::{config::VaultMode, error::Result, types::Owner};

const DEFAULT_AGENT_ID: &str = "default-agent";
const DEFAULT_ROOT_DIR: &str = ".openclaw/secrets";
const DEFAULT_TTL_DAYS: i64 = 1;
const DEFAULT_TTL_SECONDS: i64 = 86_400;
const DEFAULT_DAEMON_REQUEST_LIMIT_BYTES: usize = 16 * 1024;
const DEFAULT_DAEMON_BIND: &str = "127.0.0.1:7788";
const DEFAULT_DAEMON_IO_TIMEOUT_SECONDS: u64 = 5;
const DEFAULT_VAULT_MOUNT_TTL: &str = "1h";
const DEFAULT_VAULT_SECRET_TTL_DAYS: i64 = 365;
const DEFAULT_VAULT_SECRET_LENGTH_BYTES: usize = 64;

/// Top-level command line parser.
#[derive(Debug, Parser)]
#[command(name = "gloves")]
pub struct Cli {
    /// Root storage directory override.
    #[arg(long)]
    pub root: Option<PathBuf>,
    /// Config file override path.
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Disable config loading and discovery.
    #[arg(long)]
    pub no_config: bool,
    /// Vault runtime mode override.
    #[arg(long, value_enum)]
    pub vault_mode: Option<VaultModeArg>,
    /// Subcommand.
    #[command(subcommand)]
    pub command: Command,
}

/// Supported CLI commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Initializes directory tree.
    Init,
    /// Sets an agent secret.
    Set {
        /// Secret name.
        name: String,
        /// Generate random value.
        #[arg(long)]
        generate: bool,
        /// Inline secret value (less secure than stdin).
        #[arg(long)]
        value: Option<String>,
        /// Read secret value from stdin.
        #[arg(long)]
        stdin: bool,
        /// TTL in days.
        #[arg(long)]
        ttl: Option<i64>,
    },
    /// Gets a secret value.
    Get {
        /// Secret name.
        name: String,
    },
    /// Prints redacted env export text.
    Env {
        /// Secret name.
        name: String,
        /// Variable name.
        var: String,
    },
    /// Creates a pending human request.
    Request {
        /// Secret name.
        name: String,
        /// Justification.
        #[arg(long)]
        reason: String,
    },
    /// Approves a pending request by id.
    Approve {
        /// Request UUID.
        request_id: String,
    },
    /// Denies a pending request by id.
    Deny {
        /// Request UUID.
        request_id: String,
    },
    /// Lists entries.
    List,
    /// Revokes a secret.
    Revoke {
        /// Secret name.
        name: String,
    },
    /// Shows request status by secret name.
    Status {
        /// Secret name.
        name: String,
    },
    /// Verifies registry and expiry state.
    Verify,
    /// Runs local sidecar daemon.
    Daemon {
        /// TCP bind address for daemon mode.
        #[arg(long)]
        bind: Option<String>,
        /// Perform strict startup checks and exit.
        #[arg(long)]
        check: bool,
        /// Maximum handled requests before exiting. Intended for tests.
        #[arg(long, hide = true, default_value_t = 0)]
        max_requests: usize,
    },
    /// Manages encrypted vaults.
    Vault {
        /// Vault operation.
        #[command(subcommand)]
        command: VaultCommand,
    },
    /// Validates loaded config state.
    Config {
        /// Config operation.
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Shows access visibility for configured private paths.
    Access {
        /// Access operation.
        #[command(subcommand)]
        command: AccessCommand,
    },
    /// Internal helper to print one secret for gocryptfs -extpass.
    #[command(hide = true)]
    ExtpassGet {
        /// Secret name.
        name: String,
    },
}

/// Vault owner argument.
#[derive(Debug, Clone, ValueEnum)]
pub enum VaultOwnerArg {
    /// Agent-controlled vault.
    Agent,
    /// Human-approved vault.
    Human,
}

impl From<VaultOwnerArg> for Owner {
    fn from(value: VaultOwnerArg) -> Self {
        match value {
            VaultOwnerArg::Agent => Owner::Agent,
            VaultOwnerArg::Human => Owner::Human,
        }
    }
}

/// Vault runtime mode argument.
#[derive(Debug, Clone, ValueEnum)]
pub enum VaultModeArg {
    /// Opportunistic vault mode.
    Auto,
    /// Vault dependencies are mandatory.
    Required,
    /// Vault commands are blocked.
    Disabled,
}

impl From<VaultModeArg> for VaultMode {
    fn from(value: VaultModeArg) -> Self {
        match value {
            VaultModeArg::Auto => VaultMode::Auto,
            VaultModeArg::Required => VaultMode::Required,
            VaultModeArg::Disabled => VaultMode::Disabled,
        }
    }
}

/// Supported vault subcommands.
#[derive(Debug, Subcommand)]
pub enum VaultCommand {
    /// Initializes a new vault.
    Init {
        /// Vault name.
        name: String,
        /// Vault owner.
        #[arg(long, value_enum)]
        owner: VaultOwnerArg,
    },
    /// Mounts a vault.
    Mount {
        /// Vault name.
        name: String,
        /// Mount session TTL.
        #[arg(long)]
        ttl: Option<String>,
        /// Optional mountpoint override.
        #[arg(long)]
        mountpoint: Option<PathBuf>,
        /// Agent identity for this mount session.
        #[arg(long)]
        agent: Option<String>,
    },
    /// Unmounts a vault.
    Unmount {
        /// Vault name.
        name: String,
        /// Agent identity associated with unmount audit event.
        #[arg(long)]
        agent: Option<String>,
    },
    /// Shows vault mount status.
    Status,
    /// Lists configured vaults.
    List,
    /// Generates a trusted-agent handoff prompt for one file.
    AskFile {
        /// Vault name.
        name: String,
        /// File path relative to vault root.
        #[arg(long)]
        file: String,
        /// Agent that is requesting the file.
        #[arg(long)]
        requester: Option<String>,
        /// Trusted agent expected to have mount access.
        #[arg(long)]
        trusted_agent: String,
        /// Optional reason shown in the prompt.
        #[arg(long)]
        reason: Option<String>,
    },
}

/// Supported config subcommands.
#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Validates the effective config and runtime policy checks.
    Validate,
}

/// Supported access subcommands.
#[derive(Debug, Subcommand)]
pub enum AccessCommand {
    /// Shows one agent's configured private path visibility.
    Paths {
        /// Agent identifier.
        #[arg(long)]
        agent: String,
        /// Print JSON output.
        #[arg(long)]
        json: bool,
    },
}

/// Runs CLI and returns process exit code.
pub fn run(cli: Cli) -> Result<i32> {
    commands::run(cli)
}

#[allow(dead_code)]
fn ttl_seconds(ttl: Duration) -> i64 {
    ttl.num_seconds().max(DEFAULT_TTL_SECONDS)
}

#[cfg(test)]
mod unit_tests {
    use super::{
        runtime::{
            load_or_create_default_identity, load_or_create_default_signing_key, validate_ttl_days,
        },
        secret_input::{parse_duration_value, resolve_secret_input},
        ttl_seconds,
    };
    use crate::error::GlovesError;
    use crate::paths::SecretsPaths;
    use chrono::Duration;

    #[test]
    fn resolve_secret_input_generate_ok() {
        let bytes = resolve_secret_input(true, None, false).unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn resolve_secret_input_generate_conflict() {
        assert!(matches!(
            resolve_secret_input(true, Some("abc".to_owned()), false),
            Err(GlovesError::InvalidInput(_))
        ));
    }

    #[test]
    fn resolve_secret_input_value_ok() {
        let bytes = resolve_secret_input(false, Some("abc".to_owned()), false).unwrap();
        assert_eq!(bytes, b"abc");
    }

    #[test]
    fn resolve_secret_input_empty_value_rejected() {
        assert!(matches!(
            resolve_secret_input(false, Some(String::new()), false),
            Err(GlovesError::InvalidInput(_))
        ));
    }

    #[test]
    fn resolve_secret_input_requires_source() {
        assert!(matches!(
            resolve_secret_input(false, None, false),
            Err(GlovesError::InvalidInput(_))
        ));
    }

    #[test]
    fn ttl_seconds_enforces_default_floor() {
        let below_floor = ttl_seconds(Duration::seconds(1));
        assert!(below_floor >= 86_400);
    }

    #[test]
    fn validate_ttl_days_rejects_non_positive_values() {
        assert!(matches!(
            validate_ttl_days(0, "--ttl"),
            Err(GlovesError::InvalidInput(_))
        ));
        assert!(matches!(
            validate_ttl_days(-1, "--ttl"),
            Err(GlovesError::InvalidInput(_))
        ));
    }

    #[test]
    fn validate_ttl_days_accepts_positive_value() {
        let ttl_days = validate_ttl_days(7, "--ttl").unwrap();
        assert_eq!(ttl_days, 7);
    }

    #[test]
    fn parse_duration_value_accepts_hours() {
        let duration = parse_duration_value("2h", "--ttl").unwrap();
        assert_eq!(duration, Duration::hours(2));
    }

    #[test]
    fn parse_duration_value_rejects_invalid_units() {
        assert!(matches!(
            parse_duration_value("2w", "--ttl"),
            Err(GlovesError::InvalidInput(_))
        ));
    }

    #[test]
    fn parse_duration_value_rejects_non_positive_values() {
        assert!(matches!(
            parse_duration_value("0h", "--ttl"),
            Err(GlovesError::InvalidInput(_))
        ));
    }

    #[test]
    fn load_or_create_default_identity_rejects_invalid_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        std::fs::write(temp_dir.path().join("default-agent.agekey"), "invalid").unwrap();
        let paths = SecretsPaths::new(temp_dir.path());
        assert!(load_or_create_default_identity(&paths).is_err());
    }

    #[test]
    fn load_or_create_default_signing_key_rejects_invalid_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        std::fs::write(temp_dir.path().join("default-agent.signing.key"), [1_u8; 8]).unwrap();
        let paths = SecretsPaths::new(temp_dir.path());
        assert!(matches!(
            load_or_create_default_signing_key(&paths),
            Err(GlovesError::InvalidInput(_))
        ));
    }
}
