mod commands;
mod daemon;
mod navigator;
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
const SECRET_NAME_ARG_HELP: &str =
    "Secret id (example: `service/token`). Allowed characters: letters, digits, `.`, `_`, `-`, and `/`.";
const REQUEST_ID_ARG_HELP: &str =
    "Request UUID from `gloves list --pending` (example: `123e4567-e89b-12d3-a456-426614174000`).";
const ERROR_CODE_ARG_HELP: &str = "Error code from CLI stderr (example: `E102`).";
const ERROR_FORMAT_ARG_HELP: &str = "Error output format (`text` or `json`).";
const CLI_AFTER_HELP: &str = r#"Examples:
  gloves --root .openclaw/secrets init
  gloves --root .openclaw/secrets set service/token --generate --ttl 1
  gloves --root .openclaw/secrets get service/token --pipe-to cat
  gloves --root .openclaw/secrets request prod/db --reason "run migration"
  gloves --root .openclaw/secrets requests list
  gloves --root .openclaw/secrets grant service/token --to agent-b
  gloves explain E102
  gloves --error-format json approve 123e4567-e89b-12d3-a456-426614174000

Version:
  gloves --version
  gloves version --json

More help:
  gloves help <command>
  gloves help vault
"#;
const SET_COMMAND_AFTER_HELP: &str = r#"Examples:
  gloves set service/token --generate --ttl 1
  printf 'secret-value' | gloves set service/token --stdin --ttl 7

Tips:
  - Use `--generate` or `--stdin` for safer input handling.
  - `--ttl` expects a positive number of days (example: `--ttl 1`).
"#;
const REQUEST_COMMAND_AFTER_HELP: &str = r#"Examples:
  gloves request prod/db --reason "run migration"
  gloves list --pending
  gloves approve <request-id>
"#;
const REQUESTS_COMMAND_AFTER_HELP: &str = r#"Examples:
  gloves requests list
  gloves requests approve <request-id>
  gloves req deny <request-id>

Tip:
  Use this command group when you want noun-first navigation.
"#;
const APPROVE_COMMAND_AFTER_HELP: &str = r#"Examples:
  gloves list --pending
  gloves approve <request-id>

Tip:
  `<request-id>` must be a UUID from `gloves list --pending`.
"#;
const DENY_COMMAND_AFTER_HELP: &str = r#"Examples:
  gloves list --pending
  gloves deny <request-id>

Tip:
  `<request-id>` must be a UUID from `gloves list --pending`.
"#;
const LIST_COMMAND_AFTER_HELP: &str = r#"Examples:
  gloves list
  gloves list --pending
"#;
const GRANT_COMMAND_AFTER_HELP: &str = r#"Examples:
  gloves grant service/token --to agent-b
  gloves --agent default-agent grant service/token --to reviewer-a

Notes:
  - Grant updates recipient access for an existing agent-owned secret.
  - The caller must be the original creator of the secret.
"#;
const GET_COMMAND_AFTER_HELP: &str = r#"Examples:
  gloves get service/token
  gloves get service/token --pipe-to cat

Recovery:
  If the secret does not exist, run `gloves list`.
"#;
const REVOKE_COMMAND_AFTER_HELP: &str = r#"Examples:
  gloves revoke service/token

Recovery:
  Use `gloves list` to confirm the exact secret id before revoking.
"#;
const STATUS_COMMAND_AFTER_HELP: &str = r#"Examples:
  gloves status prod/db
  gloves list --pending
"#;
const VERSION_COMMAND_AFTER_HELP: &str = r#"Examples:
  gloves --version
  gloves version
  gloves version --json
"#;
const EXPLAIN_COMMAND_AFTER_HELP: &str = r#"Examples:
  gloves explain E102
  gloves explain e200

Tip:
  Error codes are shown in stderr output, for example `error[E102]: ...`.
"#;
const TUI_COMMAND_AFTER_HELP: &str = r#"Examples:
  gloves tui

Controls:
  - Up/Down or j/k: move command tree
  - Left/Right or h/l: collapse/expand command groups
  - Enter: toggle selected command group
  - Tab / Shift+Tab: switch panes
  - e: edit selected text field
  - Space: toggle booleans
  - Left/Right: change choice fields in field panes
  - r or F5: execute selected command with live streaming output
  - Ctrl+C: cancel active run (q/Esc waits for cancellation first)
  - ? : run `gloves help` for selected command in output pane
  - / : filter command tree
  - Home or g: jump output to top and disable follow-tail
  - End or G: jump output to tail and re-enable follow-tail
  - c: clear output history cards
  - q or Esc: quit
"#;
const GPG_COMMAND_AFTER_HELP: &str = r#"Examples:
  gloves --agent agent-main gpg create
  gloves --agent agent-main gpg fingerprint
"#;
const GPG_CREATE_COMMAND_AFTER_HELP: &str = r#"Examples:
  gloves --agent agent-main gpg create

Notes:
  - Creates a key only when missing (idempotent).
"#;
const GPG_FINGERPRINT_COMMAND_AFTER_HELP: &str = r#"Examples:
  gloves --agent agent-main gpg fingerprint

Recovery:
  If no key exists yet, run `gloves --agent <id> gpg create` first.
"#;

/// Top-level command line parser.
#[derive(Debug, Parser)]
#[command(
    name = "gloves",
    version,
    about = "Secure secrets control plane for OpenClaw and multi-agent runtimes.",
    after_help = CLI_AFTER_HELP,
    infer_subcommands = true,
    arg_required_else_help = true,
    next_line_help = true
)]
pub struct Cli {
    /// Root storage directory override.
    /// Default when unset and no config override is active: `.openclaw/secrets`.
    #[arg(long)]
    pub root: Option<PathBuf>,
    /// Agent identifier override for this invocation.
    /// Default when unset and no config override is active: `default-agent`.
    #[arg(long)]
    pub agent: Option<String>,
    /// Config file override path.
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Disable config loading and discovery.
    #[arg(long)]
    pub no_config: bool,
    /// Vault runtime mode override.
    #[arg(long, value_enum)]
    pub vault_mode: Option<VaultModeArg>,
    /// Error output format.
    #[arg(long, value_enum, default_value_t = ErrorFormatArg::Text, help = ERROR_FORMAT_ARG_HELP)]
    pub error_format: ErrorFormatArg,
    /// Subcommand.
    #[command(subcommand)]
    pub command: Command,
}

/// Supported CLI commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Initializes directory tree.
    Init,
    /// Prints version and runtime defaults.
    #[command(visible_alias = "ver", after_help = VERSION_COMMAND_AFTER_HELP)]
    Version {
        /// Print structured JSON output.
        #[arg(long)]
        json: bool,
    },
    /// Explains a stable error code with recovery guidance.
    #[command(after_help = EXPLAIN_COMMAND_AFTER_HELP)]
    Explain {
        /// Error code from stderr (for example: `E102`).
        #[arg(help = ERROR_CODE_ARG_HELP)]
        code: String,
    },
    /// Opens an interactive command navigator.
    #[command(visible_alias = "ui", after_help = TUI_COMMAND_AFTER_HELP)]
    Tui,
    /// Sets an agent secret.
    #[command(after_help = SET_COMMAND_AFTER_HELP)]
    Set {
        /// Secret name.
        #[arg(help = SECRET_NAME_ARG_HELP)]
        name: String,
        /// Generate random value.
        #[arg(long)]
        generate: bool,
        /// Inline secret value (less secure than stdin).
        #[arg(long)]
        value: Option<String>,
        /// Read secret value from stdin (trims trailing CR/LF).
        #[arg(long)]
        stdin: bool,
        /// TTL in days.
        #[arg(long)]
        ttl: Option<i64>,
    },
    /// Gets a secret value.
    #[command(after_help = GET_COMMAND_AFTER_HELP)]
    Get {
        /// Secret name.
        #[arg(help = SECRET_NAME_ARG_HELP)]
        name: String,
        /// Pipe secret bytes to an approved command.
        #[arg(long, conflicts_with = "pipe_to_args")]
        pipe_to: Option<String>,
        /// Execute an approved command template with `{secret}` interpolation.
        #[arg(long, conflicts_with = "pipe_to")]
        pipe_to_args: Option<String>,
    },
    /// Prints redacted env export text.
    Env {
        /// Secret name.
        #[arg(help = SECRET_NAME_ARG_HELP)]
        name: String,
        /// Variable name.
        var: String,
    },
    /// Creates a pending human request.
    #[command(after_help = REQUEST_COMMAND_AFTER_HELP)]
    Request {
        /// Secret name.
        #[arg(help = SECRET_NAME_ARG_HELP)]
        name: String,
        /// Justification.
        #[arg(long)]
        reason: String,
        /// Optional allowlist of requestable secret patterns.
        /// Format: comma-separated patterns (`*`, `namespace/*`, or exact id).
        #[arg(long)]
        allowlist: Option<String>,
        /// Optional blocklist of disallowed secret patterns.
        /// Format: comma-separated patterns (`*`, `namespace/*`, or exact id).
        #[arg(long)]
        blocklist: Option<String>,
    },
    /// Groups request workflows (list/approve/deny) for noun-first navigation.
    #[command(visible_alias = "req", after_help = REQUESTS_COMMAND_AFTER_HELP)]
    Requests {
        /// Request operation.
        #[command(subcommand)]
        command: RequestsCommand,
    },
    /// Approves a pending request by id.
    #[command(after_help = APPROVE_COMMAND_AFTER_HELP)]
    Approve {
        /// Request UUID.
        #[arg(help = REQUEST_ID_ARG_HELP)]
        request_id: String,
    },
    /// Denies a pending request by id.
    #[command(after_help = DENY_COMMAND_AFTER_HELP)]
    Deny {
        /// Request UUID.
        #[arg(help = REQUEST_ID_ARG_HELP)]
        request_id: String,
    },
    /// Lists entries.
    #[command(visible_alias = "ls", after_help = LIST_COMMAND_AFTER_HELP)]
    List {
        /// Show only pending request entries.
        #[arg(long)]
        pending: bool,
    },
    /// Grants an existing secret to another agent.
    #[command(after_help = GRANT_COMMAND_AFTER_HELP)]
    Grant {
        /// Secret name.
        #[arg(help = SECRET_NAME_ARG_HELP)]
        name: String,
        /// Agent id to grant access to.
        #[arg(long)]
        to: String,
    },
    /// Revokes a secret.
    #[command(after_help = REVOKE_COMMAND_AFTER_HELP)]
    Revoke {
        /// Secret name.
        #[arg(help = SECRET_NAME_ARG_HELP)]
        name: String,
    },
    /// Shows request status by secret name.
    #[command(after_help = STATUS_COMMAND_AFTER_HELP)]
    Status {
        /// Secret name.
        #[arg(help = SECRET_NAME_ARG_HELP)]
        name: String,
    },
    /// Views audit events.
    Audit {
        /// Show only the latest N events.
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Print JSON output instead of table lines.
        #[arg(long)]
        json: bool,
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
    /// Manages per-agent GPG keys used for human secret workflows.
    #[command(after_help = GPG_COMMAND_AFTER_HELP)]
    Gpg {
        /// GPG operation.
        #[command(subcommand)]
        command: GpgCommand,
    },
    /// Internal helper to print one secret for gocryptfs -extpass.
    #[command(hide = true)]
    ExtpassGet {
        /// Secret name.
        #[arg(help = SECRET_NAME_ARG_HELP)]
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
    /// Mounts a vault, runs a command, and unmounts automatically.
    Exec {
        /// Vault name.
        name: String,
        /// Mount session TTL.
        #[arg(long)]
        ttl: Option<String>,
        /// Optional mountpoint override.
        #[arg(long)]
        mountpoint: Option<PathBuf>,
        /// Agent identity for this exec session.
        #[arg(long)]
        agent: Option<String>,
        /// Command and arguments to execute after mount.
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
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

/// Supported request-group subcommands.
#[derive(Debug, Subcommand)]
pub enum RequestsCommand {
    /// Lists only pending request entries.
    List,
    /// Approves a pending request by id.
    Approve {
        /// Request UUID.
        #[arg(help = REQUEST_ID_ARG_HELP)]
        request_id: String,
    },
    /// Denies a pending request by id.
    Deny {
        /// Request UUID.
        #[arg(help = REQUEST_ID_ARG_HELP)]
        request_id: String,
    },
}

/// Error format argument.
#[derive(Debug, Clone, Copy, ValueEnum, Eq, PartialEq)]
pub enum ErrorFormatArg {
    /// Human-readable text diagnostics.
    Text,
    /// Machine-readable JSON diagnostics.
    Json,
}

/// Supported GPG subcommands.
#[derive(Debug, Subcommand)]
pub enum GpgCommand {
    /// Creates a GPG key for the selected agent if one does not exist.
    #[command(after_help = GPG_CREATE_COMMAND_AFTER_HELP)]
    Create,
    /// Prints the selected agent GPG key fingerprint.
    #[command(after_help = GPG_FINGERPRINT_COMMAND_AFTER_HELP)]
    Fingerprint,
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
            load_or_create_identity_for_agent, load_or_create_signing_key_for_agent,
            validate_ttl_days,
        },
        secret_input::{parse_duration_value, resolve_secret_input},
        ttl_seconds, Cli, Command, ErrorFormatArg, RequestsCommand,
    };
    use crate::error::GlovesError;
    use crate::paths::SecretsPaths;
    use crate::types::AgentId;
    use chrono::Duration;
    use clap::{error::ErrorKind, CommandFactory, Parser};

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
    fn load_or_create_identity_for_agent_rejects_invalid_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        std::fs::write(temp_dir.path().join("default-agent.agekey"), "invalid").unwrap();
        let paths = SecretsPaths::new(temp_dir.path());
        let agent_id = AgentId::new("default-agent").unwrap();
        assert!(load_or_create_identity_for_agent(&paths, &agent_id).is_err());
    }

    #[test]
    fn load_or_create_signing_key_for_agent_rejects_invalid_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        std::fs::write(temp_dir.path().join("default-agent.signing.key"), [1_u8; 8]).unwrap();
        let paths = SecretsPaths::new(temp_dir.path());
        let agent_id = AgentId::new("default-agent").unwrap();
        assert!(matches!(
            load_or_create_signing_key_for_agent(&paths, &agent_id),
            Err(GlovesError::InvalidInput(_))
        ));
    }

    #[test]
    fn load_or_create_identity_for_agent_uses_agent_specific_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let paths = SecretsPaths::new(temp_dir.path());
        let agent_id = AgentId::new("agent-main").unwrap();
        let identity_file = load_or_create_identity_for_agent(&paths, &agent_id).unwrap();

        assert!(identity_file.ends_with("agent-main.agekey"));
        assert!(identity_file.exists());
        assert!(!paths.default_identity_file().exists());
    }

    #[test]
    fn load_or_create_signing_key_for_agent_uses_agent_specific_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let paths = SecretsPaths::new(temp_dir.path());
        let agent_id = AgentId::new("agent-main").unwrap();
        let key = load_or_create_signing_key_for_agent(&paths, &agent_id).unwrap();

        assert!(temp_dir.path().join("agent-main.signing.key").exists());
        assert!(!paths.default_signing_key_file().exists());
        assert_eq!(key.to_bytes().len(), 32);
    }

    #[test]
    fn cli_help_includes_examples_and_help_hint() {
        let mut command = Cli::command();
        let help = command.render_long_help().to_string();
        assert!(help.contains("Examples:"));
        assert!(help.contains("gloves --version"));
        assert!(help.contains("gloves version --json"));
        assert!(help.contains("gloves help <command>"));
        assert!(!help.contains("gloves --error-format json approve requests"));
    }

    #[test]
    fn cli_version_flag_is_available() {
        let error = Cli::try_parse_from(["gloves", "--version"]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DisplayVersion);
    }

    #[test]
    fn cli_short_version_flag_is_available() {
        let error = Cli::try_parse_from(["gloves", "-V"]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DisplayVersion);
    }

    #[test]
    fn cli_approve_help_includes_request_lookup_example() {
        let error = Cli::try_parse_from(["gloves", "help", "approve"]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DisplayHelp);
        let help = error.to_string();
        assert!(help.contains("gloves list --pending"));
        assert!(help.contains("gloves approve <request-id>"));
    }

    #[test]
    fn cli_set_help_includes_input_examples() {
        let error = Cli::try_parse_from(["gloves", "help", "set"]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DisplayHelp);
        let help = error.to_string();
        assert!(help.contains("gloves set service/token --generate --ttl 1"));
        assert!(help.contains("--ttl 1"));
    }

    #[test]
    fn cli_requests_alias_parses_to_requests_command() {
        let cli = Cli::try_parse_from(["gloves", "req", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Requests {
                command: RequestsCommand::List
            }
        ));
    }

    #[test]
    fn cli_list_alias_parses_to_list_command() {
        let cli = Cli::try_parse_from(["gloves", "ls"]).unwrap();
        assert!(matches!(cli.command, Command::List { pending: false }));
    }

    #[test]
    fn cli_grant_parses_to_grant_command() {
        let cli =
            Cli::try_parse_from(["gloves", "grant", "service/token", "--to", "agent-b"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Grant { name, to } if name == "service/token" && to == "agent-b"
        ));
    }

    #[test]
    fn cli_infer_subcommand_allows_version_prefix() {
        let cli = Cli::try_parse_from(["gloves", "ver"]).unwrap();
        assert!(matches!(cli.command, Command::Version { json: false }));
    }

    #[test]
    fn cli_explain_help_mentions_error_codes() {
        let error = Cli::try_parse_from(["gloves", "help", "explain"]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DisplayHelp);
        let help = error.to_string();
        assert!(help.contains("gloves explain E102"));
        assert!(help.contains("error[E102]"));
    }

    #[test]
    fn cli_error_format_defaults_to_text() {
        let cli = Cli::try_parse_from(["gloves", "version"]).unwrap();
        assert_eq!(cli.error_format, ErrorFormatArg::Text);
    }

    #[test]
    fn cli_error_format_accepts_json() {
        let cli = Cli::try_parse_from(["gloves", "--error-format", "json", "version"]).unwrap();
        assert_eq!(cli.error_format, ErrorFormatArg::Json);
    }
}
