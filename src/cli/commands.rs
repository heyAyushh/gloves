use std::collections::HashSet;
use std::env::VarError;
use std::path::Path;

use chrono::Duration;

use crate::{
    config::{resolve_config_path, GlovesConfig, PathOperation, VaultMode},
    error::{GlovesError, Result},
    paths::SecretsPaths,
    reaper::TtlReaper,
    types::{AgentId, Owner, SecretId, SecretValue},
    vault::gocryptfs::{GocryptfsDriver, EXTPASS_AGENT_ENV_VAR, EXTPASS_ROOT_ENV_VAR},
};

use super::{
    daemon,
    output::{self, OutputStatus},
    runtime, secret_input,
    vault_cmd::{self, VaultCommandDefaults},
    AccessCommand, Cli, Command, ConfigCommand, DEFAULT_AGENT_ID, DEFAULT_DAEMON_BIND,
    DEFAULT_DAEMON_IO_TIMEOUT_SECONDS, DEFAULT_DAEMON_REQUEST_LIMIT_BYTES, DEFAULT_ROOT_DIR,
    DEFAULT_TTL_DAYS, DEFAULT_VAULT_MOUNT_TTL, DEFAULT_VAULT_SECRET_LENGTH_BYTES,
    DEFAULT_VAULT_SECRET_TTL_DAYS,
};

const REQUIRED_VAULT_BINARIES: [&str; 3] = ["gocryptfs", "fusermount", "mountpoint"];

#[derive(Debug, Clone)]
struct EffectiveCliState {
    paths: SecretsPaths,
    loaded_config: Option<GlovesConfig>,
    default_agent_id: AgentId,
    default_secret_ttl_days: i64,
    default_vault_mount_ttl: String,
    default_vault_secret_ttl_days: i64,
    default_vault_secret_length_bytes: usize,
    daemon_bind: String,
    daemon_io_timeout_seconds: u64,
    daemon_request_limit_bytes: usize,
    vault_mode: VaultMode,
}

pub(crate) fn run(cli: Cli) -> Result<i32> {
    if let Command::ExtpassGet { name } = &cli.command {
        return run_extpass_get(name);
    }

    let state = load_effective_state(&cli)?;
    enforce_vault_mode(&state.vault_mode, &cli.command)?;

    match cli.command {
        Command::Init => {
            runtime::init_layout(&state.paths)?;
            if let Some(code) = stdout_line_or_exit("initialized")? {
                return Ok(code);
            }
        }
        Command::Set {
            name,
            generate,
            value,
            stdin,
            ttl,
        } => {
            let manager = runtime::manager_for_paths(&state.paths)?;
            let secret_id = SecretId::new(&name)?;
            let creator = state.default_agent_id.clone();
            let recipient = runtime::load_or_create_default_recipient(&state.paths)?;
            let mut recipients = HashSet::new();
            recipients.insert(creator.clone());
            let ttl_days =
                runtime::validate_ttl_days(ttl.unwrap_or(state.default_secret_ttl_days), "--ttl")?;
            let value =
                SecretValue::new(secret_input::resolve_secret_input(generate, value, stdin)?);
            manager.set(
                secret_id,
                value,
                crate::manager::SetSecretOptions {
                    owner: Owner::Agent,
                    ttl: Duration::days(ttl_days),
                    created_by: creator,
                    recipients,
                    recipient_keys: vec![recipient],
                },
            )?;
            if let Some(code) = stdout_line_or_exit("ok")? {
                return Ok(code);
            }
        }
        Command::Get { name } => {
            let force_tty_warning = std::env::var("GLOVES_FORCE_TTY_WARNING")
                .map(|value| value == "1")
                .unwrap_or(false);
            if atty::is(atty::Stream::Stdout) || force_tty_warning {
                let _ = stderr_line_ignore_broken_pipe("warning: raw secret output on tty");
            }
            let manager = runtime::manager_for_paths(&state.paths)?;
            let secret_id = SecretId::new(&name)?;
            let caller = state.default_agent_id.clone();
            let identity_file = runtime::load_or_create_default_identity(&state.paths)?;
            let value = manager.get(&secret_id, &caller, Some(identity_file.as_path()));
            match value {
                Ok(secret) => {
                    let secret_bytes = secret.expose(ToOwned::to_owned);
                    if let Some(code) = stdout_bytes_or_exit(&secret_bytes)? {
                        return Ok(code);
                    }
                }
                Err(error) => {
                    let _ = stderr_line_ignore_broken_pipe(&format!("error: {error}"));
                    return Ok(1);
                }
            }
        }
        Command::Env { name, var } => {
            let _ = name;
            if let Some(code) = stdout_line_or_exit(&format!("export {var}=<REDACTED>"))? {
                return Ok(code);
            }
        }
        Command::Request { name, reason } => {
            let manager = runtime::manager_for_paths(&state.paths)?;
            let secret_id = SecretId::new(&name)?;
            let requester = state.default_agent_id.clone();
            let signing_key = runtime::load_or_create_default_signing_key(&state.paths)?;
            manager.request(
                secret_id,
                requester,
                reason,
                Duration::days(state.default_secret_ttl_days),
                &signing_key,
            )?;
            if let Some(code) = stdout_line_or_exit("pending")? {
                return Ok(code);
            }
        }
        Command::Approve { request_id } => {
            let manager = runtime::manager_for_paths(&state.paths)?;
            let request_id = runtime::parse_request_uuid(&request_id)?;
            manager.approve_request(request_id)?;
            if let Some(code) = stdout_line_or_exit("approved")? {
                return Ok(code);
            }
        }
        Command::Deny { request_id } => {
            let manager = runtime::manager_for_paths(&state.paths)?;
            let request_id = runtime::parse_request_uuid(&request_id)?;
            manager.deny_request(request_id)?;
            if let Some(code) = stdout_line_or_exit("denied")? {
                return Ok(code);
            }
        }
        Command::List => {
            let manager = runtime::manager_for_paths(&state.paths)?;
            if let Some(code) =
                stdout_line_or_exit(&serde_json::to_string_pretty(&manager.list_all()?)?)?
            {
                return Ok(code);
            }
        }
        Command::Revoke { name } => {
            let manager = runtime::manager_for_paths(&state.paths)?;
            let secret_id = SecretId::new(&name)?;
            let caller = state.default_agent_id.clone();
            manager.revoke(&secret_id, &caller)?;
            if let Some(code) = stdout_line_or_exit("revoked")? {
                return Ok(code);
            }
        }
        Command::Status { name } => {
            let manager = runtime::manager_for_paths(&state.paths)?;
            let pending = manager.pending_store.load_all()?;
            let status = pending
                .into_iter()
                .find(|request| request.secret_name.as_str() == name)
                .map(|request| request.status)
                .unwrap_or(crate::types::RequestStatus::Fulfilled);
            if let Some(code) = stdout_line_or_exit(&serde_json::to_string(&status)?)? {
                return Ok(code);
            }
        }
        Command::Verify => {
            let manager = runtime::manager_for_paths(&state.paths)?;
            TtlReaper::reap(
                &manager.agent_backend,
                &manager.metadata_store,
                &manager.audit_log,
            )?;
            TtlReaper::reap_vault_sessions(
                &GocryptfsDriver::new(),
                &state.paths,
                &manager.audit_log,
            )?;
            if let Some(code) = stdout_line_or_exit("ok")? {
                return Ok(code);
            }
        }
        Command::Daemon {
            bind,
            check,
            max_requests,
        } => {
            let bind = bind.unwrap_or_else(|| state.daemon_bind.clone());
            daemon::run_daemon(
                &state.paths,
                &bind,
                daemon::DaemonRuntimeOptions {
                    io_timeout_seconds: state.daemon_io_timeout_seconds,
                    request_limit_bytes: state.daemon_request_limit_bytes,
                },
                check,
                max_requests,
            )?;
        }
        Command::Vault { command } => {
            vault_cmd::run_vault_command(
                &state.paths,
                command,
                &VaultCommandDefaults {
                    mount_ttl: state.default_vault_mount_ttl.clone(),
                    agent_id: state.default_agent_id.clone(),
                    vault_secret_ttl_days: state.default_vault_secret_ttl_days,
                    vault_secret_length_bytes: state.default_vault_secret_length_bytes,
                },
            )?;
        }
        Command::Config { command } => match command {
            ConfigCommand::Validate => {
                if matches!(state.vault_mode, VaultMode::Required) {
                    ensure_vault_dependencies()?;
                }
                if let Some(code) = stdout_line_or_exit("ok")? {
                    return Ok(code);
                }
            }
        },
        Command::Access { command } => match command {
            AccessCommand::Paths { agent, json } => {
                let config = state.loaded_config.as_ref().ok_or_else(|| {
                    GlovesError::InvalidInput(
                        "no config loaded; use --config, GLOVES_CONFIG, or .gloves.toml discovery"
                            .to_owned(),
                    )
                })?;
                let agent_id = AgentId::new(&agent)?;
                let entries = config.agent_paths(&agent_id)?;
                if json {
                    let payload = serde_json::json!({
                        "agent": agent_id.as_str(),
                        "paths": entries,
                    });
                    if let Some(code) =
                        stdout_line_or_exit(&serde_json::to_string_pretty(&payload)?)?
                    {
                        return Ok(code);
                    }
                } else {
                    for entry in entries {
                        let operations = entry
                            .operations
                            .iter()
                            .map(path_operation_label)
                            .collect::<Vec<_>>()
                            .join(",");
                        if let Some(code) = stdout_line_or_exit(&format!(
                            "{}\t{}\t{}",
                            entry.alias,
                            entry.path.display(),
                            operations
                        ))? {
                            return Ok(code);
                        }
                    }
                }
            }
        },
        Command::ExtpassGet { .. } => {}
    }
    Ok(0)
}

fn stdout_line_or_exit(line: &str) -> Result<Option<i32>> {
    match output::stdout_line(line) {
        Ok(OutputStatus::Written) => Ok(None),
        Ok(OutputStatus::BrokenPipe) => Ok(Some(0)),
        Err(error) => Err(GlovesError::Io(error)),
    }
}

fn stdout_bytes_or_exit(bytes: &[u8]) -> Result<Option<i32>> {
    match output::stdout_bytes(bytes) {
        Ok(OutputStatus::Written) => Ok(None),
        Ok(OutputStatus::BrokenPipe) => Ok(Some(0)),
        Err(error) => Err(GlovesError::Io(error)),
    }
}

fn stderr_line_ignore_broken_pipe(line: &str) -> std::io::Result<()> {
    match output::stderr_line(line) {
        Ok(OutputStatus::Written | OutputStatus::BrokenPipe) => Ok(()),
        Err(error) => Err(error),
    }
}

fn run_extpass_get(secret_name: &str) -> Result<i32> {
    let root = read_required_env_var(EXTPASS_ROOT_ENV_VAR)?;
    let agent = read_required_env_var(EXTPASS_AGENT_ENV_VAR)?;

    let paths = SecretsPaths::new(root);
    let manager = runtime::manager_for_paths(&paths)?;
    let secret_id = SecretId::new(secret_name)?;
    let caller = AgentId::new(&agent)?;
    let identity_file = runtime::load_or_create_default_identity(&paths)?;
    let secret = manager.get(&secret_id, &caller, Some(identity_file.as_path()))?;
    let secret_bytes = secret.expose(ToOwned::to_owned);
    if let Some(code) = stdout_bytes_or_exit(&secret_bytes)? {
        return Ok(code);
    }
    Ok(0)
}

fn read_required_env_var(key: &str) -> Result<String> {
    match std::env::var(key) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        Ok(_) => Err(GlovesError::InvalidInput(format!(
            "{key} must not be empty"
        ))),
        Err(VarError::NotPresent) => Err(GlovesError::InvalidInput(format!(
            "missing required environment variable: {key}"
        ))),
        Err(VarError::NotUnicode(_)) => Err(GlovesError::InvalidInput(format!(
            "{key} must be valid UTF-8"
        ))),
    }
}

fn load_effective_state(cli: &Cli) -> Result<EffectiveCliState> {
    let current_dir = std::env::current_dir()?;
    let env_path = read_config_env_var()?;
    let selection = resolve_config_path(
        cli.config.as_deref(),
        env_path.as_deref(),
        cli.no_config,
        &current_dir,
    )?;
    let loaded_config = match selection.path {
        Some(path) => Some(GlovesConfig::load_from_path(path)?),
        None => None,
    };

    let root = cli
        .root
        .clone()
        .or_else(|| loaded_config.as_ref().map(|config| config.root.clone()))
        .unwrap_or_else(|| std::path::PathBuf::from(DEFAULT_ROOT_DIR));
    let default_agent_id = loaded_config
        .as_ref()
        .map(|config| config.defaults.agent_id.clone())
        .unwrap_or(AgentId::new(DEFAULT_AGENT_ID)?);
    let default_secret_ttl_days = loaded_config
        .as_ref()
        .map(|config| config.defaults.secret_ttl_days)
        .unwrap_or(DEFAULT_TTL_DAYS);
    let default_vault_mount_ttl = loaded_config
        .as_ref()
        .map(|config| config.defaults.vault_mount_ttl.clone())
        .unwrap_or_else(|| DEFAULT_VAULT_MOUNT_TTL.to_owned());
    let default_vault_secret_ttl_days = loaded_config
        .as_ref()
        .map(|config| config.defaults.vault_secret_ttl_days)
        .unwrap_or(DEFAULT_VAULT_SECRET_TTL_DAYS);
    let default_vault_secret_length_bytes = loaded_config
        .as_ref()
        .map(|config| config.defaults.vault_secret_length_bytes)
        .unwrap_or(DEFAULT_VAULT_SECRET_LENGTH_BYTES);
    let daemon_bind = loaded_config
        .as_ref()
        .map(|config| config.daemon.bind.clone())
        .unwrap_or_else(|| DEFAULT_DAEMON_BIND.to_owned());
    let daemon_io_timeout_seconds = loaded_config
        .as_ref()
        .map(|config| config.daemon.io_timeout_seconds)
        .unwrap_or(DEFAULT_DAEMON_IO_TIMEOUT_SECONDS);
    let daemon_request_limit_bytes = loaded_config
        .as_ref()
        .map(|config| config.daemon.request_limit_bytes)
        .unwrap_or(DEFAULT_DAEMON_REQUEST_LIMIT_BYTES);
    let vault_mode = cli
        .vault_mode
        .clone()
        .map(Into::into)
        .or_else(|| loaded_config.as_ref().map(|config| config.vault.mode))
        .unwrap_or(VaultMode::Auto);

    Ok(EffectiveCliState {
        paths: SecretsPaths::new(root),
        loaded_config,
        default_agent_id,
        default_secret_ttl_days,
        default_vault_mount_ttl,
        default_vault_secret_ttl_days,
        default_vault_secret_length_bytes,
        daemon_bind,
        daemon_io_timeout_seconds,
        daemon_request_limit_bytes,
        vault_mode,
    })
}

fn read_config_env_var() -> Result<Option<String>> {
    match std::env::var("GLOVES_CONFIG") {
        Ok(value) => Ok(Some(value)),
        Err(VarError::NotPresent) => Ok(None),
        Err(VarError::NotUnicode(_)) => Err(GlovesError::InvalidInput(
            "GLOVES_CONFIG must be valid UTF-8".to_owned(),
        )),
    }
}

fn enforce_vault_mode(vault_mode: &VaultMode, command: &Command) -> Result<()> {
    if matches!(vault_mode, VaultMode::Disabled) && matches!(command, Command::Vault { .. }) {
        return Err(GlovesError::InvalidInput(
            "vault commands are disabled (vault mode is 'disabled')".to_owned(),
        ));
    }
    if matches!(vault_mode, VaultMode::Required) && command_requires_vault_dependencies(command) {
        ensure_vault_dependencies()?;
    }
    Ok(())
}

fn command_requires_vault_dependencies(command: &Command) -> bool {
    matches!(command, Command::Vault { .. } | Command::Verify)
}

fn ensure_vault_dependencies() -> Result<()> {
    let missing = REQUIRED_VAULT_BINARIES
        .iter()
        .copied()
        .filter(|binary| !is_binary_available(binary))
        .collect::<Vec<_>>();
    if missing.is_empty() {
        return Ok(());
    }

    Err(GlovesError::InvalidInput(format!(
        "vault mode 'required' is set but missing required binaries: {}",
        missing.join(", ")
    )))
}

fn is_binary_available(binary: &str) -> bool {
    let candidate = Path::new(binary);
    if candidate
        .parent()
        .is_some_and(|parent| !parent.as_os_str().is_empty())
    {
        return is_executable_file(candidate);
    }

    let Some(path_var) = std::env::var_os("PATH") else {
        return false;
    };
    for directory in std::env::split_paths(&path_var) {
        let path_candidate = directory.join(binary);
        if is_executable_file(&path_candidate) {
            return true;
        }
        #[cfg(windows)]
        {
            for suffix in [".exe", ".cmd", ".bat"] {
                if is_executable_file(&directory.join(format!("{binary}{suffix}"))) {
                    return true;
                }
            }
        }
    }
    false
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }

    #[cfg(not(unix))]
    {
        true
    }
}

fn path_operation_label(operation: &PathOperation) -> &'static str {
    match operation {
        PathOperation::Read => "read",
        PathOperation::Write => "write",
        PathOperation::List => "list",
        PathOperation::Mount => "mount",
    }
}
