use std::collections::{HashMap, HashSet};
use std::env::VarError;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};

use chrono::{DateTime, Duration, Utc};
use clap::{error::ErrorKind, Parser};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{
    audit::{AuditEvent, AuditLog},
    config::{
        discover_config, resolve_config_path, ConfigSource, GlovesConfig, PathOperation,
        SecretAclOperation, VaultMode, CONFIG_SCHEMA_VERSION,
    },
    error::{explain_error_code, known_error_codes, normalize_error_code, GlovesError, Result},
    fs_secure::ensure_private_dir,
    manager::ListItem,
    namespaced_store::NamespacedStore,
    paths::SecretsPaths,
    reaper::TtlReaper,
    types::{AgentId, Owner, SecretId, SecretValue},
    vault::gocryptfs::{GocryptfsDriver, EXTPASS_AGENT_ENV_VAR, EXTPASS_ROOT_ENV_VAR},
    SecretRef,
};

#[cfg(feature = "tui")]
use super::navigator;
use super::{
    daemon,
    output::{self, OutputStatus},
    runtime, secret_input,
    vault_cmd::{self, VaultCommandDefaults},
    AccessCommand, Cli, Command, ConfigCommand, ErrorFormatArg, ExecCommand, GpgCommand,
    RequestsCommand, SecretReadFormatArg, SecretShowFormatArg, SecretsCommand, VaultModeArg,
    DEFAULT_AGENT_ID, DEFAULT_DAEMON_BIND, DEFAULT_DAEMON_IO_TIMEOUT_SECONDS,
    DEFAULT_DAEMON_REQUEST_LIMIT_BYTES, DEFAULT_ROOT_DIR, DEFAULT_TTL_DAYS,
    DEFAULT_VAULT_MOUNT_TTL, DEFAULT_VAULT_SECRET_LENGTH_BYTES, DEFAULT_VAULT_SECRET_TTL_DAYS,
};

const REQUIRED_VAULT_BINARIES: [&str; 3] = ["gocryptfs", "fusermount", "mountpoint"];
const SECRET_PIPE_ALLOWLIST_ENV_VAR: &str = "GLOVES_GET_PIPE_ALLOWLIST";
const SECRET_PIPE_ARG_POLICY_ENV_VAR: &str = "GLOVES_GET_PIPE_ARG_POLICY";
const SECRET_PIPE_URL_POLICY_ENV_VAR: &str = "GLOVES_GET_PIPE_URL_POLICY";
const SECRET_PIPE_ALLOWLIST_SEPARATOR: char = ',';
const SECRET_PIPE_TEMPLATE_PLACEHOLDER: &str = "{secret}";
const SECRET_PIPE_TEMPLATE_SOURCE: &str = "--pipe-to-args";
const SECRET_PIPE_URL_SAMPLE_TOKEN: &str = "gloves-secret";
const URL_SCHEME_HTTP_PREFIX: &str = "http://";
const URL_SCHEME_HTTPS_PREFIX: &str = "https://";
const REQUEST_ALLOWLIST_ENV_VAR: &str = "GLOVES_REQUEST_ALLOWLIST";
const REQUEST_BLOCKLIST_ENV_VAR: &str = "GLOVES_REQUEST_BLOCKLIST";
const SECRET_PATTERN_SEPARATOR: char = ',';
const GPG_BINARY: &str = "gpg";
const GPG_FINGERPRINT_RECORD_PREFIX: &str = "fpr:";
const GPG_FINGERPRINT_FIELD_INDEX: usize = 9;
const GPG_KEY_ALGORITHM: &str = "default";
const GPG_KEY_USAGE: &str = "default";
const GPG_KEY_EXPIRY: &str = "never";
const GPG_AGENT_USER_ID_PREFIX: &str = "gloves-agent-";
const CLI_ACTION_INTERFACE: &str = "cli";
const CLI_HELP_HINT: &str = "gloves --help";
const CLI_COMMAND_HELP_HINT: &str = "gloves help [topic...]";
const PENDING_REQUEST_LOOKUP_COMMAND: &str = "gloves requests list";
const SECRET_LOOKUP_COMMAND: &str = "gloves list";
#[cfg(feature = "tui")]
const TUI_FLAG_ROOT: &str = "--root";
#[cfg(feature = "tui")]
const TUI_FLAG_AGENT: &str = "--agent";
#[cfg(feature = "tui")]
const TUI_FLAG_CONFIG: &str = "--config";
#[cfg(feature = "tui")]
const TUI_FLAG_NO_CONFIG: &str = "--no-config";
#[cfg(feature = "tui")]
const TUI_FLAG_VAULT_MODE: &str = "--vault-mode";
#[cfg(feature = "tui")]
const TUI_FLAG_ERROR_FORMAT: &str = "--error-format";
#[cfg(feature = "tui")]
const TUI_FLAG_JSON: &str = "--json";

#[derive(Debug, Clone)]
struct EffectiveCliState {
    paths: SecretsPaths,
    loaded_config: Option<GlovesConfig>,
    secret_acl_config: Option<GlovesConfig>,
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

#[cfg(feature = "tui")]
#[derive(Debug, Clone, Default)]
struct TuiBootstrapArgs {
    root: Option<PathBuf>,
    agent: Option<String>,
    config: Option<PathBuf>,
    no_config: bool,
    vault_mode: Option<VaultModeArg>,
    error_format: Option<ErrorFormatArg>,
    json: bool,
    command_args: Vec<String>,
}

#[derive(Debug, Clone)]
enum SecretOutputTarget {
    Stdout,
    PipeCommand(String),
    PipeCommandArgs(String),
}

#[derive(Debug, serde::Serialize)]
struct GpgCreateOutput {
    agent: String,
    fingerprint: String,
    created: bool,
}

#[derive(Debug, serde::Serialize)]
struct GpgFingerprintOutput {
    agent: String,
    fingerprint: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct AuditRecord {
    timestamp: DateTime<Utc>,
    #[serde(flatten)]
    event: AuditEvent,
}

#[derive(Debug, serde::Serialize)]
struct RequestReviewOutput {
    action: String,
    request_id: String,
    secret_name: String,
    requested_by: String,
    reason: String,
    requested_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    status: crate::types::RequestStatus,
    pending: bool,
    approved_at: Option<DateTime<Utc>>,
    approved_by: Option<String>,
    denied_at: Option<DateTime<Utc>>,
    denied_by: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct GrantOutput {
    action: &'static str,
    secret_name: String,
    granted_to: String,
    granted_by: String,
    changed: bool,
}

#[derive(Debug, serde::Serialize)]
struct VersionOutput {
    name: &'static str,
    version: &'static str,
    config_schema_version: u32,
    default_root: &'static str,
    default_agent: &'static str,
}

struct GpgHomedir {
    path: PathBuf,
}

impl GpgHomedir {
    fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Debug, Clone)]
struct ExecutionEnvBinding {
    variable_name: String,
    secret_ref: SecretRef,
}

#[derive(Debug, Clone)]
enum ExecutionDeliveryStrategy {
    Env,
}

#[derive(Debug, Clone)]
struct ExecutionRequest {
    strategy: ExecutionDeliveryStrategy,
    env_bindings: Vec<ExecutionEnvBinding>,
    command: Vec<String>,
}

#[derive(Debug, Clone)]
struct ResolvedExecutionRequest {
    command: Vec<String>,
    environment: Vec<(String, String)>,
    injected_variables: Vec<String>,
}

#[derive(Debug, Clone)]
struct ExecutionResult {
    executable: String,
    exit_code: i32,
    injected_variables: Vec<String>,
}

pub(crate) fn run(mut cli: Cli) -> Result<i32> {
    if let Command::ExtpassGet { name } = &cli.command {
        return run_extpass_get(name);
    }

    #[cfg(feature = "tui")]
    let tui_bootstrap = prepare_tui_bootstrap(&mut cli)?;
    #[cfg(feature = "tui")]
    let tui_launch_options = tui_bootstrap
        .as_ref()
        .map(|bootstrap| navigator_launch_options(&cli, bootstrap));

    let state = load_effective_state(&cli)?;
    enforce_vault_mode(&state.vault_mode, &cli.command)?;
    runtime::init_layout(&state.paths)?;
    let json_output = cli.json || matches!(cli.error_format, ErrorFormatArg::Json);

    match cli.command {
        Command::Init => {
            runtime::init_layout(&state.paths)?;
            log_command_executed(&state.paths, &state.default_agent_id, "init", None);
            let root_path = state.paths.root().display().to_string();
            if let Some(code) = emit_command_json_or_text(
                "init",
                serde_json::json!({
                    "status": "initialized",
                    "root": root_path,
                }),
                &format!("initialized {}", root_path),
                json_output,
            )? {
                return Ok(code);
            }
        }
        Command::SetIdentity {
            agent,
            force,
            post_quantum,
        } => {
            if post_quantum {
                return Err(GlovesError::InvalidInput(
                    "--post-quantum is not supported yet".to_owned(),
                ));
            }
            let agent_id = AgentId::new(&agent)?;
            let store = NamespacedStore::new(state.paths.root());
            let result = store.create_identity(&agent_id, force)?;
            log_command_executed(
                &state.paths,
                &state.default_agent_id,
                "set-identity",
                Some(agent.clone()),
            );
            let line = format!(
                "Identity created: {}\nPublic key: {}\nRecipients file updated: {}",
                result.identity_path.display(),
                result.public_key,
                result.recipients_file.display()
            );
            if let Some(code) = stdout_line_or_exit(&line)? {
                return Ok(code);
            }
        }
        Command::Set { path, value, stdin } => {
            let store = NamespacedStore::new(state.paths.root());
            let agent = state.default_agent_id.clone();
            let secret_id = SecretId::new(&path)?;
            let bytes = secret_input::resolve_secret_input(false, value, stdin)?;
            let result = store.set_secret(&secret_id, &agent, &bytes)?;
            log_command_executed(&state.paths, &state.default_agent_id, "set", Some(path));
            let line = format!(
                "stored {} for {} ({} recipients)",
                result.name,
                result.agent,
                result.encrypted_to.len()
            );
            if let Some(code) = stdout_line_or_exit(&line)? {
                return Ok(code);
            }
        }
        Command::Get { path, format } => {
            let store = NamespacedStore::new(state.paths.root());
            let agent = state.default_agent_id.clone();
            let secret_id = SecretId::new(&path)?;
            let result = store.get_secret(&secret_id, &agent)?;
            log_command_executed(&state.paths, &state.default_agent_id, "get", Some(path));
            match format {
                SecretReadFormatArg::Raw => {
                    if let Some(code) = stdout_bytes_or_exit(result.value.as_bytes())? {
                        return Ok(code);
                    }
                }
                SecretReadFormatArg::Json => {
                    if let Some(code) = stdout_line_or_exit(&serde_json::to_string(&result)?)? {
                        return Ok(code);
                    }
                }
            }
        }
        Command::Run { env, command } => {
            let result = execute_generic_command(
                &state,
                ExecutionRequest {
                    strategy: ExecutionDeliveryStrategy::Env,
                    env_bindings: parse_execution_env_bindings(&env)?,
                    command,
                },
                "run",
            )?;
            let target = Some(format!(
                "{} ({} env bindings)",
                result.executable,
                result.injected_variables.len()
            ));
            log_command_executed(&state.paths, &state.default_agent_id, "run", target);
            return Ok(result.exit_code);
        }
        Command::Exec { command } => {
            let (action_name, result) = match command {
                ExecCommand::Env { env, command } => (
                    "exec-env",
                    execute_generic_command(
                        &state,
                        ExecutionRequest {
                            strategy: ExecutionDeliveryStrategy::Env,
                            env_bindings: parse_execution_env_bindings(&env)?,
                            command,
                        },
                        "exec env",
                    )?,
                ),
            };
            let target = Some(format!(
                "{} ({} env bindings)",
                result.executable,
                result.injected_variables.len()
            ));
            log_command_executed(&state.paths, &state.default_agent_id, action_name, target);
            return Ok(result.exit_code);
        }
        Command::Show {
            path,
            redacted: _,
            format,
        } => {
            let store = NamespacedStore::new(state.paths.root());
            let secret_id = SecretId::new(&path)?;
            let result = store.show_secret(&secret_id)?;
            log_command_executed(&state.paths, &state.default_agent_id, "show", Some(path));
            match format {
                SecretShowFormatArg::Text => {
                    let encrypted_to = if result.encrypted_to.is_empty() {
                        String::new()
                    } else {
                        result.encrypted_to.join(", ")
                    };
                    let line = format!(
                        "name: {}\nexists: {}\nlength: {}\nagent: {}\nencrypted_to: {}\ncreated: {}\nmodified: {}\nlast_rotated: {}\nfile_size: {} bytes",
                        result.name,
                        result.exists,
                        result.length,
                        result.agent,
                        encrypted_to,
                        result.created.to_rfc3339(),
                        result.modified.to_rfc3339(),
                        result.last_rotated.to_rfc3339(),
                        result.file_size
                    );
                    if let Some(code) = stdout_line_or_exit(&line)? {
                        return Ok(code);
                    }
                }
                SecretShowFormatArg::Json => {
                    if let Some(code) = stdout_line_or_exit(&serde_json::to_string(&result)?)? {
                        return Ok(code);
                    }
                }
            }
        }
        Command::Updatekeys {
            path,
            dry_run,
            identity,
        } => {
            let store = NamespacedStore::new(state.paths.root());
            let result = store.update_keys(path.as_deref(), identity.as_deref(), dry_run)?;
            log_command_executed(
                &state.paths,
                &state.default_agent_id,
                "updatekeys",
                path.clone(),
            );
            let line = format!(
                "updated: {}\nunchanged: {}\nskipped: {}\ndry_run: {}",
                result.updated, result.unchanged, result.skipped, result.dry_run
            );
            if let Some(code) = stdout_line_or_exit(&line)? {
                return Ok(code);
            }
        }
        Command::Rotate { agent, keep_old } => {
            let store = NamespacedStore::new(state.paths.root());
            let agent_id = AgentId::new(&agent)?;
            let result = store.rotate_identity(&agent_id, keep_old)?;
            log_command_executed(
                &state.paths,
                &state.default_agent_id,
                "rotate",
                Some(agent.clone()),
            );
            let line = format!(
                "rotated {} from {} to {}\narchived_identity: {}\nupdated: {}\nunchanged: {}\nskipped: {}",
                result.agent,
                result.old_public_key,
                result.new_public_key,
                result.archived_identity_path.display(),
                result.updated,
                result.unchanged,
                result.skipped
            );
            if let Some(code) = stdout_line_or_exit(&line)? {
                return Ok(code);
            }
        }
        Command::Explain { code } => {
            let normalized_code = normalize_error_code(&code);
            if let Some(exit_code) = run_explain_command(&code, json_output)? {
                return Ok(exit_code);
            }
            log_command_executed(
                &state.paths,
                &state.default_agent_id,
                "explain",
                Some(normalized_code),
            );
        }
        #[cfg(feature = "tui")]
        Command::Tui { .. } => {
            let launch_options =
                tui_launch_options.unwrap_or_else(navigator::NavigatorLaunchOptions::default);
            navigator::run_command_navigator(launch_options)?;
            log_command_executed(&state.paths, &state.default_agent_id, "tui", None);
        }
        Command::Help { topic } => {
            if let Some(code) = run_help_command(&topic, json_output)? {
                return Ok(code);
            }
        }
        Command::Secrets { command } => match command {
            SecretsCommand::Help { topic } => {
                if let Some(code) = run_help_command_with_prefix(&["secrets"], &topic, json_output)?
                {
                    return Ok(code);
                }
            }
            SecretsCommand::Set {
                name,
                generate,
                value,
                stdin,
                ttl,
            } => {
                let manager = runtime::manager_for_paths(&state.paths)?;
                let secret_id = SecretId::new(&name)?;
                let secret_name = secret_id.as_str().to_owned();
                ensure_secret_acl_allowed(&state, SecretAclOperation::Write, Some(&secret_id))?;
                let creator = state.default_agent_id.clone();
                let creator_str = creator.as_str().to_owned();
                let recipient =
                    runtime::load_or_create_recipient_for_agent(&state.paths, &creator)?;
                let mut recipients = HashSet::new();
                recipients.insert(creator.clone());
                let ttl = runtime::parse_secret_ttl_argument(
                    ttl.as_deref(),
                    state.default_secret_ttl_days,
                    "--ttl",
                )?;
                let value =
                    SecretValue::new(secret_input::resolve_secret_input(generate, value, stdin)?);
                manager.set(
                    secret_id.clone(),
                    value,
                    crate::manager::SetSecretOptions {
                        owner: Owner::Agent,
                        ttl: ttl.duration(),
                        created_by: creator,
                        recipients,
                        recipient_keys: vec![recipient],
                    },
                )?;
                let expires_at = manager.metadata_store.load(&secret_id)?.expires_at;
                let never_expires = ttl.never_expires();
                let text = match expires_at {
                    Some(expires_at) => format!(
                        "secret {} created (TTL: {} days, expires at {})",
                        secret_name,
                        ttl.ttl_days().unwrap_or_default(),
                        expires_at.to_rfc3339()
                    ),
                    None => format!("secret {} created (TTL: never, never expires)", secret_name),
                };
                log_command_executed(&state.paths, &state.default_agent_id, "set", Some(name));
                if let Some(code) = emit_command_json_or_text(
                    "secrets-set",
                    serde_json::json!({
                        "secret": secret_name,
                        "status": "created",
                        "ttl_days": ttl.ttl_days(),
                        "expires_at": expires_at,
                        "never_expires": never_expires,
                        "owner": "agent",
                        "created_by": creator_str,
                    }),
                    &text,
                    json_output,
                )? {
                    return Ok(code);
                }
            }
            SecretsCommand::Get {
                name,
                pipe_to,
                pipe_to_args,
            } => {
                let secret_id = SecretId::new(&name)?;
                ensure_secret_acl_allowed(&state, SecretAclOperation::Read, Some(&secret_id))?;
                let manager = runtime::manager_for_paths(&state.paths)?;
                if !manager.metadata_store.path_for(&secret_id).exists() {
                    return Err(secret_not_found_error(secret_id.as_str(), "get"));
                }
                let force_tty_warning = std::env::var("GLOVES_FORCE_TTY_WARNING")
                    .map(|value| value == "1")
                    .unwrap_or(false);
                let stdout_is_tty = atty::is(atty::Stream::Stdout);
                let force_raw_stdout_warning =
                    force_tty_warning && pipe_to.is_none() && pipe_to_args.is_none();
                if force_raw_stdout_warning {
                    let _ = stderr_line_ignore_broken_pipe("warning: raw secret output on tty");
                }
                let output_target = resolve_secret_output_target(
                    pipe_to,
                    pipe_to_args,
                    stdout_is_tty,
                    state.loaded_config.as_ref(),
                )?;
                if matches!(&output_target, SecretOutputTarget::Stdout)
                    && stdout_is_tty
                    && !force_raw_stdout_warning
                {
                    let _ = stderr_line_ignore_broken_pipe("warning: raw secret output on tty");
                }
                let caller = state.default_agent_id.clone();
                let identity_file =
                    runtime::load_or_create_identity_for_agent(&state.paths, &caller)?;
                let value = manager.get(&secret_id, &caller, Some(identity_file.as_path()));
                match value {
                    Ok(secret) => {
                        let mut secret_bytes = secret.expose(ToOwned::to_owned);
                        let output_result = match output_target {
                            SecretOutputTarget::Stdout => {
                                if json_output {
                                    emit_command_json(
                                        "secrets-get",
                                        serde_json::json!({
                                            "secret": secret_id.as_str(),
                                            "value": secret_bytes_json_value(&secret_bytes),
                                        }),
                                    )
                                } else {
                                    stdout_bytes_or_exit(&secret_bytes)
                                }
                            }
                            SecretOutputTarget::PipeCommand(pipe_command) => {
                                pipe_secret_to_command(&pipe_command, &secret_bytes).map(|_| None)
                            }
                            SecretOutputTarget::PipeCommandArgs(template) => {
                                pipe_secret_to_command_args(&template, &secret_bytes).map(|_| None)
                            }
                        };
                        secret_bytes.zeroize();
                        let output_code = output_result?;
                        log_command_executed(
                            &state.paths,
                            &state.default_agent_id,
                            "get",
                            Some(secret_id.as_str().to_owned()),
                        );
                        if let Some(code) = output_code {
                            return Ok(code);
                        }
                    }
                    Err(GlovesError::NotFound) => {
                        return Err(secret_not_found_error(secret_id.as_str(), "get"));
                    }
                    Err(error) => {
                        return Err(error);
                    }
                }
            }
            SecretsCommand::Grant { name, to } => {
                if let Some(code) = run_grant_command(&state, &name, &to)? {
                    return Ok(code);
                }
            }
            SecretsCommand::Revoke { name } => {
                let manager = runtime::manager_for_paths(&state.paths)?;
                let secret_id = SecretId::new(&name)?;
                ensure_secret_acl_allowed(&state, SecretAclOperation::Revoke, Some(&secret_id))?;
                if !manager.metadata_store.path_for(&secret_id).exists() {
                    return Err(secret_not_found_error(secret_id.as_str(), "revoke"));
                }
                let caller = state.default_agent_id.clone();
                match manager.revoke(&secret_id, &caller) {
                    Ok(()) => {}
                    Err(GlovesError::NotFound) => {
                        return Err(secret_not_found_error(secret_id.as_str(), "revoke"));
                    }
                    Err(error) => return Err(error),
                }
                log_command_executed(
                    &state.paths,
                    &state.default_agent_id,
                    "revoke",
                    Some(secret_id.as_str().to_owned()),
                );
                if let Some(code) = emit_command_json_or_text(
                    "secrets-revoke",
                    serde_json::json!({
                        "secret": secret_id.as_str(),
                        "status": "revoked",
                    }),
                    "revoked",
                    json_output,
                )? {
                    return Ok(code);
                }
            }
            SecretsCommand::Status { name } => {
                let secret_id = SecretId::new(&name)?;
                ensure_secret_acl_allowed(&state, SecretAclOperation::Status, Some(&secret_id))?;
                let manager = runtime::manager_for_paths(&state.paths)?;
                let pending = manager.pending_store.load_all()?;
                let status = pending
                    .into_iter()
                    .find(|request| request.secret_name.as_str() == secret_id.as_str())
                    .map(|request| request.status)
                    .unwrap_or(crate::types::RequestStatus::Fulfilled);
                log_command_executed(
                    &state.paths,
                    &state.default_agent_id,
                    "status",
                    Some(secret_id.as_str().to_owned()),
                );
                if json_output {
                    if let Some(code) = emit_command_json(
                        "secrets-status",
                        serde_json::json!({
                            "secret": secret_id.as_str(),
                            "status": status,
                        }),
                    )? {
                        return Ok(code);
                    }
                } else if let Some(code) = stdout_line_or_exit(&serde_json::to_string(&status)?)? {
                    return Ok(code);
                }
            }
        },
        Command::Env { name, var } => {
            log_command_executed(&state.paths, &state.default_agent_id, "env", Some(name));
            if let Some(code) = emit_command_json_or_text(
                "env",
                serde_json::json!({
                    "export": format!("export {var}=<REDACTED>"),
                    "variable": var,
                }),
                &format!("export {var}=<REDACTED>"),
                json_output,
            )? {
                return Ok(code);
            }
        }
        Command::Request {
            name,
            reason,
            allowlist,
            blocklist,
        } => {
            let manager = runtime::manager_for_paths(&state.paths)?;
            let secret_id = SecretId::new(&name)?;
            ensure_secret_acl_allowed(&state, SecretAclOperation::Request, Some(&secret_id))?;
            let request_policy =
                resolve_request_policy(allowlist.as_deref(), blocklist.as_deref())?;
            ensure_request_policy_allows(&secret_id, &request_policy, "request")?;
            let requester = state.default_agent_id.clone();
            let signing_key =
                runtime::load_or_create_signing_key_for_agent(&state.paths, &requester)?;
            let pending_request = manager.request(
                secret_id,
                requester,
                reason,
                Duration::days(state.default_secret_ttl_days),
                &signing_key,
            )?;
            log_command_executed(
                &state.paths,
                &state.default_agent_id,
                "request",
                Some(name.clone()),
            );
            if let Some(code) = emit_command_json_or_text(
                "request",
                serde_json::json!({
                    "secret": name,
                    "status": "pending",
                    "request_id": pending_request.id,
                    "expires_at": pending_request.expires_at,
                }),
                &format!("request {} created for secret {}", pending_request.id, name),
                json_output,
            )? {
                return Ok(code);
            }
        }
        Command::Requests { command } => match command {
            RequestsCommand::Help { topic } => {
                if let Some(code) =
                    run_help_command_with_prefix(&["requests"], &topic, json_output)?
                {
                    return Ok(code);
                }
            }
            RequestsCommand::List => {
                if let Some(code) = run_list_command(&state, true, "requests-list")? {
                    return Ok(code);
                }
            }
            RequestsCommand::Approve { request_id } => {
                if let Some(code) =
                    run_request_approve_command(&state, &request_id, "requests-approve")?
                {
                    return Ok(code);
                }
            }
            RequestsCommand::Deny { request_id } => {
                if let Some(code) = run_request_deny_command(&state, &request_id, "requests-deny")?
                {
                    return Ok(code);
                }
            }
        },
        Command::Approve { request_id } => {
            if let Some(code) = run_request_approve_command(&state, &request_id, "approve")? {
                return Ok(code);
            }
        }
        Command::Deny { request_id } => {
            if let Some(code) = run_request_deny_command(&state, &request_id, "deny")? {
                return Ok(code);
            }
        }
        Command::List { pending } => {
            if let Some(code) = run_list_command(&state, pending, "list")? {
                return Ok(code);
            }
        }
        Command::Audit { limit } => {
            let records = load_audit_records(&state.paths.audit_file())?;
            let sliced_records = latest_audit_records(records, limit);
            log_command_executed(
                &state.paths,
                &state.default_agent_id,
                "audit",
                Some(format!("limit={limit}")),
            );
            if json_output {
                if let Some(code) = emit_command_json(
                    "audit",
                    serde_json::json!({
                        "limit": limit,
                        "entries": sliced_records,
                    }),
                )? {
                    return Ok(code);
                }
            } else {
                for record in sliced_records {
                    if let Some(code) = stdout_line_or_exit(&format_audit_record_line(&record))? {
                        return Ok(code);
                    }
                }
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
            log_command_executed(&state.paths, &state.default_agent_id, "verify", None);
            if let Some(code) = emit_command_message_or_json(
                "verify",
                "verified and reaped expired entries",
                json_output,
            )? {
                return Ok(code);
            }
        }
        Command::Daemon {
            bind,
            check,
            max_requests,
        } => {
            let bind = bind.unwrap_or_else(|| state.daemon_bind.clone());
            log_command_executed(
                &state.paths,
                &state.default_agent_id,
                "daemon",
                Some(bind.clone()),
            );
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
            let (action, target) = vault_command_descriptor(&command);
            if let super::VaultCommand::Help { topic } = &command {
                if let Some(code) = run_help_command_with_prefix(&["vault"], topic, json_output)? {
                    return Ok(code);
                }
                return Ok(0);
            }
            if let Some(code) = vault_cmd::run_vault_command(
                &state.paths,
                command,
                &VaultCommandDefaults {
                    mount_ttl: state.default_vault_mount_ttl.clone(),
                    agent_id: state.default_agent_id.clone(),
                    vault_secret_ttl_days: state.default_vault_secret_ttl_days,
                    vault_secret_length_bytes: state.default_vault_secret_length_bytes,
                },
                json_output,
            )? {
                log_command_executed(
                    &state.paths,
                    &state.default_agent_id,
                    action,
                    target.clone(),
                );
                return Ok(code);
            }
            log_command_executed(&state.paths, &state.default_agent_id, action, target);
        }
        Command::Config { command } => match command {
            ConfigCommand::Help { topic } => {
                if let Some(code) = run_help_command_with_prefix(&["config"], &topic, json_output)?
                {
                    return Ok(code);
                }
            }
            ConfigCommand::Validate => {
                if matches!(state.vault_mode, VaultMode::Required) {
                    ensure_vault_dependencies()?;
                }
                log_command_executed(
                    &state.paths,
                    &state.default_agent_id,
                    "config-validate",
                    None,
                );
                let config_info = state
                    .loaded_config
                    .as_ref()
                    .map(|c| format!("valid ({})", c.source_path.display()))
                    .unwrap_or_else(|| "valid (no config file)".to_owned());
                if let Some(code) = emit_command_json_or_text(
                    "config-validate",
                    serde_json::json!({
                        "status": "ok",
                        "config_path": state.loaded_config.as_ref().map(|c| c.source_path.display().to_string()),
                    }),
                    &config_info,
                    json_output,
                )? {
                    return Ok(code);
                }
            }
        },
        Command::Access { command } => match command {
            AccessCommand::Help { topic } => {
                if let Some(code) = run_help_command_with_prefix(&["access"], &topic, json_output)?
                {
                    return Ok(code);
                }
            }
            AccessCommand::Paths { agent } => {
                let config = state.loaded_config.as_ref().ok_or_else(|| {
                    GlovesError::InvalidInput(
                        "no config loaded; use --config, GLOVES_CONFIG, or .gloves.toml discovery"
                            .to_owned(),
                    )
                })?;
                let agent_id = AgentId::new(&agent)?;
                let entries = config.agent_paths(&agent_id)?;
                log_command_executed(
                    &state.paths,
                    &state.default_agent_id,
                    "access-paths",
                    Some(agent_id.as_str().to_owned()),
                );
                if json_output {
                    if let Some(code) = emit_command_json(
                        "access-paths",
                        serde_json::json!({
                            "agent": agent_id.as_str(),
                            "paths": entries,
                        }),
                    )? {
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
        Command::Gpg { command } => {
            if let GpgCommand::Help { topic } = &command {
                if let Some(code) = run_help_command_with_prefix(&["gpg"], topic, json_output)? {
                    return Ok(code);
                }
                return Ok(0);
            }
            let (action, target) = gpg_command_descriptor(&state.default_agent_id, &command);
            if let Some(code) = run_gpg_command(&state, command)? {
                log_command_executed(&state.paths, &state.default_agent_id, action, target);
                return Ok(code);
            }
            log_command_executed(&state.paths, &state.default_agent_id, action, target);
        }
        Command::ExtpassGet { .. } => {}
    }
    Ok(0)
}

#[cfg(feature = "tui")]
fn prepare_tui_bootstrap(cli: &mut Cli) -> Result<Option<TuiBootstrapArgs>> {
    let args = match &cli.command {
        Command::Tui { args } => args.clone(),
        _ => return Ok(None),
    };
    let bootstrap = parse_tui_bootstrap_args(&args)?;

    if let Some(root) = bootstrap.root.as_ref() {
        cli.root = Some(root.clone());
    }
    if let Some(agent) = bootstrap.agent.as_ref() {
        cli.agent = Some(agent.clone());
    }
    if let Some(config) = bootstrap.config.as_ref() {
        cli.config = Some(config.clone());
    }
    if bootstrap.no_config {
        cli.no_config = true;
    }
    if let Some(vault_mode) = bootstrap.vault_mode.as_ref() {
        cli.vault_mode = Some(vault_mode.clone());
    }
    if let Some(error_format) = bootstrap.error_format {
        cli.error_format = error_format;
    }
    if bootstrap.json {
        cli.json = true;
        cli.error_format = ErrorFormatArg::Json;
    }

    Ok(Some(bootstrap))
}

#[cfg(feature = "tui")]
fn parse_tui_bootstrap_args(args: &[String]) -> Result<TuiBootstrapArgs> {
    let mut bootstrap = TuiBootstrapArgs::default();
    let mut index = 0usize;

    while index < args.len() {
        let token = &args[index];
        if token == "--" {
            index += 1;
            break;
        }
        if !token.starts_with("--") {
            break;
        }

        let (flag, inline_value) = split_long_option_token(token);
        match flag {
            TUI_FLAG_ROOT => {
                let value = if let Some(value) = inline_value {
                    value.to_owned()
                } else {
                    let Some(next_value) = args.get(index + 1) else {
                        return Err(GlovesError::InvalidInput(
                            "`gloves tui --root` requires a path value".to_owned(),
                        ));
                    };
                    index += 1;
                    next_value.to_owned()
                };
                bootstrap.root = Some(PathBuf::from(value));
            }
            TUI_FLAG_AGENT => {
                let value = if let Some(value) = inline_value {
                    value.to_owned()
                } else {
                    let Some(next_value) = args.get(index + 1) else {
                        return Err(GlovesError::InvalidInput(
                            "`gloves tui --agent` requires an id value".to_owned(),
                        ));
                    };
                    index += 1;
                    next_value.to_owned()
                };
                bootstrap.agent = Some(value);
            }
            TUI_FLAG_CONFIG => {
                let value = if let Some(value) = inline_value {
                    value.to_owned()
                } else {
                    let Some(next_value) = args.get(index + 1) else {
                        return Err(GlovesError::InvalidInput(
                            "`gloves tui --config` requires a path value".to_owned(),
                        ));
                    };
                    index += 1;
                    next_value.to_owned()
                };
                bootstrap.config = Some(PathBuf::from(value));
            }
            TUI_FLAG_NO_CONFIG => {
                if inline_value.is_some() {
                    return Err(GlovesError::InvalidInput(
                        "`gloves tui --no-config` does not take a value".to_owned(),
                    ));
                }
                bootstrap.no_config = true;
            }
            TUI_FLAG_VAULT_MODE => {
                let value = if let Some(value) = inline_value {
                    value.to_owned()
                } else {
                    let Some(next_value) = args.get(index + 1) else {
                        return Err(GlovesError::InvalidInput(
                            "`gloves tui --vault-mode` requires one of: auto, required, disabled"
                                .to_owned(),
                        ));
                    };
                    index += 1;
                    next_value.to_owned()
                };
                bootstrap.vault_mode = Some(parse_vault_mode_arg_for_tui(&value)?);
            }
            TUI_FLAG_ERROR_FORMAT => {
                let value = if let Some(value) = inline_value {
                    value.to_owned()
                } else {
                    let Some(next_value) = args.get(index + 1) else {
                        return Err(GlovesError::InvalidInput(
                            "`gloves tui --error-format` requires one of: text, json".to_owned(),
                        ));
                    };
                    index += 1;
                    next_value.to_owned()
                };
                bootstrap.error_format = Some(parse_error_format_arg_for_tui(&value)?);
            }
            TUI_FLAG_JSON => {
                if inline_value.is_some() {
                    return Err(GlovesError::InvalidInput(
                        "`gloves tui --json` does not take a value".to_owned(),
                    ));
                }
                bootstrap.json = true;
                bootstrap.error_format = Some(ErrorFormatArg::Json);
            }
            _ => {
                break;
            }
        }

        index += 1;
    }

    bootstrap.command_args = args[index..].to_vec();
    Ok(bootstrap)
}

#[cfg(feature = "tui")]
fn parse_vault_mode_arg_for_tui(value: &str) -> Result<VaultModeArg> {
    match value {
        "auto" => Ok(VaultModeArg::Auto),
        "required" => Ok(VaultModeArg::Required),
        "disabled" => Ok(VaultModeArg::Disabled),
        _ => Err(GlovesError::InvalidInput(format!(
            "invalid `--vault-mode` value `{value}` for `gloves tui`; expected auto, required, or disabled"
        ))),
    }
}

#[cfg(feature = "tui")]
fn parse_error_format_arg_for_tui(value: &str) -> Result<ErrorFormatArg> {
    match value {
        "text" => Ok(ErrorFormatArg::Text),
        "json" => Ok(ErrorFormatArg::Json),
        _ => Err(GlovesError::InvalidInput(format!(
            "invalid `--error-format` value `{value}` for `gloves tui`; expected text or json"
        ))),
    }
}

#[cfg(feature = "tui")]
fn split_long_option_token(token: &str) -> (&str, Option<&str>) {
    if let Some((flag, value)) = token.split_once('=') {
        (flag, Some(value))
    } else {
        (token, None)
    }
}

#[cfg(feature = "tui")]
fn navigator_launch_options(
    cli: &Cli,
    bootstrap: &TuiBootstrapArgs,
) -> navigator::NavigatorLaunchOptions {
    navigator::NavigatorLaunchOptions {
        root: cli.root.as_ref().map(|value| value.display().to_string()),
        agent: cli.agent.clone(),
        config: cli.config.as_ref().map(|value| value.display().to_string()),
        no_config: cli.no_config,
        vault_mode: cli.vault_mode.as_ref().map(|value| match value {
            VaultModeArg::Auto => "auto".to_owned(),
            VaultModeArg::Required => "required".to_owned(),
            VaultModeArg::Disabled => "disabled".to_owned(),
        }),
        error_format: Some(
            if cli.json || matches!(cli.error_format, ErrorFormatArg::Json) {
                "json".to_owned()
            } else {
                "text".to_owned()
            },
        ),
        command_args: bootstrap.command_args.clone(),
    }
}

fn emit_command_json(command: &str, result: serde_json::Value) -> Result<Option<i32>> {
    let payload = serde_json::json!({
        "status": "ok",
        "command": command,
        "result": result,
    });
    stdout_line_or_exit(&serde_json::to_string_pretty(&payload)?)
}

fn emit_command_json_or_text(
    command: &str,
    result: serde_json::Value,
    text: &str,
    json_output: bool,
) -> Result<Option<i32>> {
    if json_output {
        return emit_command_json(command, result);
    }
    stdout_line_or_exit(text)
}

fn emit_command_message_or_json(
    command: &str,
    message: &str,
    json_output: bool,
) -> Result<Option<i32>> {
    emit_command_json_or_text(
        command,
        serde_json::json!({
            "message": message,
        }),
        message,
        json_output,
    )
}

fn secret_bytes_json_value(secret_bytes: &[u8]) -> serde_json::Value {
    if let Ok(value) = std::str::from_utf8(secret_bytes) {
        return serde_json::json!({
            "encoding": "utf8",
            "data": value,
        });
    }

    serde_json::json!({
        "encoding": "hex",
        "data": bytes_to_hex(secret_bytes),
    })
}

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX_LOWER[(byte >> 4) as usize] as char);
        encoded.push(HEX_LOWER[(byte & 0x0f) as usize] as char);
    }
    encoded
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

fn log_command_executed(
    paths: &SecretsPaths,
    actor: &AgentId,
    command: &str,
    target: Option<String>,
) {
    let audit_log = match AuditLog::new(paths.audit_file()) {
        Ok(log) => log,
        Err(_) => return,
    };
    let _ = audit_log.log(AuditEvent::CommandExecuted {
        by: actor.clone(),
        interface: CLI_ACTION_INTERFACE.to_owned(),
        command: command.to_owned(),
        target,
    });
}

fn load_audit_records(audit_path: &Path) -> Result<Vec<AuditRecord>> {
    if !audit_path.exists() {
        return Ok(Vec::new());
    }

    let file = fs::File::open(audit_path)?;
    let reader = BufReader::new(file);
    let mut records = Vec::new();
    for (line_index, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let record = serde_json::from_str::<AuditRecord>(&line).map_err(|error| {
            GlovesError::InvalidInput(format!(
                "invalid audit entry at line {}: {error}",
                line_index + 1
            ))
        })?;
        records.push(record);
    }
    Ok(records)
}

fn latest_audit_records(records: Vec<AuditRecord>, limit: usize) -> Vec<AuditRecord> {
    if limit == 0 || records.len() <= limit {
        return records;
    }
    let start_index = records.len() - limit;
    records.into_iter().skip(start_index).collect()
}

fn format_audit_record_line(record: &AuditRecord) -> String {
    let timestamp = record.timestamp.to_rfc3339();
    let event_name = audit_event_name(&record.event);
    let summary = audit_event_summary(&record.event);
    format!("{timestamp}\t{event_name}\t{summary}")
}

fn audit_event_name(event: &AuditEvent) -> &'static str {
    match event {
        AuditEvent::SecretAccessed { .. } => "secret_accessed",
        AuditEvent::SecretExpired { .. } => "secret_expired",
        AuditEvent::SecretCreated { .. } => "secret_created",
        AuditEvent::SecretRevoked { .. } => "secret_revoked",
        AuditEvent::RequestCreated { .. } => "request_created",
        AuditEvent::RequestApproved { .. } => "request_approved",
        AuditEvent::RequestDenied { .. } => "request_denied",
        AuditEvent::VaultCreated { .. } => "vault_created",
        AuditEvent::VaultMounted { .. } => "vault_mounted",
        AuditEvent::VaultUnmounted { .. } => "vault_unmounted",
        AuditEvent::VaultSessionExpired { .. } => "vault_session_expired",
        AuditEvent::VaultHandoffPromptIssued { .. } => "vault_handoff_prompt_issued",
        AuditEvent::GpgKeyCreated { .. } => "gpg_key_created",
        AuditEvent::CommandExecuted { .. } => "command_executed",
    }
}

fn audit_event_summary(event: &AuditEvent) -> String {
    match event {
        AuditEvent::SecretAccessed { secret_id, by } => {
            format!("secret={} by={}", secret_id.as_str(), by.as_str())
        }
        AuditEvent::SecretExpired { secret_id } => format!("secret={}", secret_id.as_str()),
        AuditEvent::SecretCreated { secret_id, by } => {
            format!("secret={} by={}", secret_id.as_str(), by.as_str())
        }
        AuditEvent::SecretRevoked { secret_id, by } => {
            format!("secret={} by={}", secret_id.as_str(), by.as_str())
        }
        AuditEvent::RequestCreated {
            request_id,
            secret_id,
            requested_by,
            expires_at,
            ..
        } => format!(
            "request_id={request_id} secret={} requested_by={} expires_at={}",
            secret_id.as_str(),
            requested_by.as_str(),
            expires_at.to_rfc3339()
        ),
        AuditEvent::RequestApproved {
            request_id,
            secret_id,
            requested_by,
            approved_by,
        } => format!(
            "request_id={request_id} secret={} requested_by={} approved_by={}",
            secret_id.as_str(),
            requested_by.as_str(),
            approved_by.as_str()
        ),
        AuditEvent::RequestDenied {
            request_id,
            secret_id,
            requested_by,
            denied_by,
        } => format!(
            "request_id={request_id} secret={} requested_by={} denied_by={}",
            secret_id.as_str(),
            requested_by.as_str(),
            denied_by.as_str()
        ),
        AuditEvent::VaultCreated { vault, owner } => format!("vault={vault} owner={owner:?}"),
        AuditEvent::VaultMounted {
            vault,
            agent,
            ttl_minutes,
        } => format!(
            "vault={vault} agent={} ttl_minutes={ttl_minutes}",
            agent.as_str()
        ),
        AuditEvent::VaultUnmounted {
            vault,
            reason,
            agent,
        } => format!("vault={vault} reason={reason} agent={}", agent.as_str()),
        AuditEvent::VaultSessionExpired { vault } => format!("vault={vault}"),
        AuditEvent::VaultHandoffPromptIssued {
            vault,
            requester,
            trusted_agent,
            requested_file,
        } => format!(
            "vault={vault} requester={} trusted_agent={} file={requested_file}",
            requester.as_str(),
            trusted_agent.as_str()
        ),
        AuditEvent::GpgKeyCreated { agent, fingerprint } => {
            format!("agent={} fingerprint={fingerprint}", agent.as_str())
        }
        AuditEvent::CommandExecuted {
            by,
            interface,
            command,
            target,
        } => match target {
            Some(target) => format!(
                "by={} interface={interface} command={command} target={target}",
                by.as_str()
            ),
            None => format!("by={} interface={interface} command={command}", by.as_str()),
        },
    }
}

fn vault_command_descriptor(command: &super::VaultCommand) -> (&'static str, Option<String>) {
    match command {
        super::VaultCommand::Help { .. } => ("vault-help", None),
        super::VaultCommand::Init { name, .. } => ("vault-init", Some(name.clone())),
        super::VaultCommand::Mount { name, .. } => ("vault-mount", Some(name.clone())),
        super::VaultCommand::Exec { name, .. } => ("vault-exec", Some(name.clone())),
        super::VaultCommand::Unmount { name, .. } => ("vault-unmount", Some(name.clone())),
        super::VaultCommand::Status => ("vault-status", None),
        super::VaultCommand::List => ("vault-list", None),
        super::VaultCommand::AskFile { name, .. } => ("vault-ask-file", Some(name.clone())),
    }
}

fn gpg_command_descriptor(
    default_agent_id: &AgentId,
    command: &GpgCommand,
) -> (&'static str, Option<String>) {
    let target = Some(default_agent_id.as_str().to_owned());
    match command {
        GpgCommand::Help { .. } => ("gpg-help", None),
        GpgCommand::Create => ("gpg-create", target),
        GpgCommand::Fingerprint => ("gpg-fingerprint", target),
    }
}

fn run_gpg_command(state: &EffectiveCliState, command: GpgCommand) -> Result<Option<i32>> {
    match command {
        GpgCommand::Help { .. } => Ok(None),
        GpgCommand::Create => run_gpg_create(state),
        GpgCommand::Fingerprint => run_gpg_fingerprint(state),
    }
}

fn run_gpg_create(state: &EffectiveCliState) -> Result<Option<i32>> {
    ensure_gpg_binary_available()?;

    let agent = state.default_agent_id.clone();
    let gpg_home_actual = state.paths.gpg_home(agent.as_str());
    ensure_private_dir(&gpg_home_actual)?;
    let gpg_home = resolve_gpg_homedir(&gpg_home_actual)?;

    if let Some(fingerprint) = read_gpg_fingerprint(gpg_home.path())? {
        let payload = GpgCreateOutput {
            agent: agent.as_str().to_owned(),
            fingerprint,
            created: false,
        };
        return stdout_line_or_exit(&serde_json::to_string(&payload)?);
    }

    create_gpg_key(gpg_home.path(), &agent)?;
    let fingerprint = read_gpg_fingerprint(gpg_home.path())?.ok_or_else(|| {
        GlovesError::InvalidInput(
            "gpg key generation succeeded but no fingerprint was found".to_owned(),
        )
    })?;

    let manager = runtime::manager_for_paths(&state.paths)?;
    manager.audit_log.log(AuditEvent::GpgKeyCreated {
        agent: agent.clone(),
        fingerprint: fingerprint.clone(),
    })?;

    let payload = GpgCreateOutput {
        agent: agent.as_str().to_owned(),
        fingerprint,
        created: true,
    };
    stdout_line_or_exit(&serde_json::to_string(&payload)?)
}

fn run_gpg_fingerprint(state: &EffectiveCliState) -> Result<Option<i32>> {
    ensure_gpg_binary_available()?;

    let agent = state.default_agent_id.clone();
    let gpg_home_actual = state.paths.gpg_home(agent.as_str());
    if !gpg_home_actual.exists() {
        return Err(gpg_key_not_found_error(&agent));
    }
    let gpg_home = resolve_gpg_homedir(&gpg_home_actual)?;
    let fingerprint =
        read_gpg_fingerprint(gpg_home.path())?.ok_or_else(|| gpg_key_not_found_error(&agent))?;
    let payload = GpgFingerprintOutput {
        agent: agent.as_str().to_owned(),
        fingerprint,
    };
    stdout_line_or_exit(&serde_json::to_string(&payload)?)
}

fn ensure_gpg_binary_available() -> Result<()> {
    if is_binary_available(GPG_BINARY) {
        return Ok(());
    }
    Err(GlovesError::InvalidInput(format!(
        "required binary not found: {GPG_BINARY}"
    )))
}

fn resolve_gpg_homedir(actual_home: &Path) -> Result<GpgHomedir> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let canonical_home = canonical_or_absolute_path(actual_home)?;

        // GnuPG places sockets under the homedir path on some platforms.
        // Deep runtime roots can exceed socket path limits, so route through
        // a short, stable alias path while keeping key material in the real home.
        let mut hasher = Sha256::new();
        hasher.update(canonical_home.to_string_lossy().as_bytes());
        let digest = hasher.finalize();
        let alias_id = digest[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let alias_root = Path::new("/tmp").join(format!("gloves-gpg-{alias_id}"));
        ensure_private_dir(&alias_root)?;
        let alias_home = alias_root.join("home");

        match fs::symlink_metadata(&alias_home) {
            Ok(metadata) => {
                if !metadata.file_type().is_symlink() {
                    reset_gpg_homedir_alias(&alias_home, &canonical_home)?;
                } else {
                    let target = fs::read_link(&alias_home)?;
                    let resolved_target =
                        resolve_relative_symlink_target(&target, alias_home.parent());
                    let normalized_target = canonical_or_absolute_path(&resolved_target)?;
                    if normalized_target != canonical_home {
                        reset_gpg_homedir_alias(&alias_home, &canonical_home)?;
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                symlink(&canonical_home, &alias_home).map_err(|error| {
                    GlovesError::InvalidInput(format!(
                        "failed to prepare gpg homedir alias: {error}"
                    ))
                })?;
            }
            Err(error) => return Err(GlovesError::Io(error)),
        }

        Ok(GpgHomedir { path: alias_home })
    }

    #[cfg(not(unix))]
    {
        Ok(GpgHomedir {
            path: actual_home.to_path_buf(),
        })
    }
}

#[cfg(unix)]
fn canonical_or_absolute_path(path: &Path) -> Result<PathBuf> {
    match fs::canonicalize(path) {
        Ok(canonical) => Ok(canonical),
        Err(_) if path.is_absolute() => Ok(path.to_path_buf()),
        Err(_) => Ok(std::env::current_dir()?.join(path)),
    }
}

#[cfg(unix)]
fn resolve_relative_symlink_target(target: &Path, alias_parent: Option<&Path>) -> PathBuf {
    if target.is_absolute() {
        return target.to_path_buf();
    }

    alias_parent.unwrap_or(Path::new("/")).join(target)
}

#[cfg(unix)]
fn reset_gpg_homedir_alias(alias_home: &Path, target: &Path) -> Result<()> {
    use std::os::unix::fs::symlink;

    match fs::symlink_metadata(alias_home) {
        Ok(metadata) => {
            if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
                fs::remove_dir_all(alias_home)?;
            } else {
                fs::remove_file(alias_home)?;
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(GlovesError::Io(error)),
    }

    symlink(target, alias_home).map_err(|error| {
        GlovesError::InvalidInput(format!("failed to prepare gpg homedir alias: {error}"))
    })
}

fn create_gpg_key(gpg_home: &Path, agent: &AgentId) -> Result<()> {
    let output = ProcessCommand::new(GPG_BINARY)
        .args(["--batch", "--yes"])
        .args(["--pinentry-mode", "loopback"])
        .args(["--passphrase", ""])
        .arg("--homedir")
        .arg(gpg_home)
        .arg("--quick-generate-key")
        .arg(gpg_user_id_for_agent(agent))
        .arg(GPG_KEY_ALGORITHM)
        .arg(GPG_KEY_USAGE)
        .arg(GPG_KEY_EXPIRY)
        .output()?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8(output.stderr)?;
    let details = compact_process_error(&stderr);
    Err(GlovesError::InvalidInput(format!(
        "failed to generate gpg key for agent '{}': {details}",
        agent.as_str()
    )))
}

fn read_gpg_fingerprint(gpg_home: &Path) -> Result<Option<String>> {
    let output = ProcessCommand::new(GPG_BINARY)
        .args(["--batch", "--with-colons"])
        .arg("--homedir")
        .arg(gpg_home)
        .args(["--list-secret-keys", "--fingerprint"])
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8(output.stderr)?;
        let details = compact_process_error(&stderr);
        return Err(GlovesError::InvalidInput(format!(
            "failed to inspect gpg keys: {details}"
        )));
    }

    let stdout = String::from_utf8(output.stdout)?;
    Ok(parse_first_gpg_fingerprint(&stdout))
}

fn parse_first_gpg_fingerprint(output: &str) -> Option<String> {
    for line in output.lines() {
        if !line.starts_with(GPG_FINGERPRINT_RECORD_PREFIX) {
            continue;
        }
        let fingerprint = line
            .split(':')
            .nth(GPG_FINGERPRINT_FIELD_INDEX)
            .unwrap_or_default()
            .trim();
        if !fingerprint.is_empty() {
            return Some(fingerprint.to_owned());
        }
    }
    None
}

fn gpg_user_id_for_agent(agent: &AgentId) -> String {
    format!(
        "{GPG_AGENT_USER_ID_PREFIX}{}",
        sanitize_for_gpg_user_id(agent.as_str())
    )
}

fn sanitize_for_gpg_user_id(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

fn execute_generic_command(
    state: &EffectiveCliState,
    request: ExecutionRequest,
    action_name: &str,
) -> Result<ExecutionResult> {
    let executable = request.command.first().cloned().ok_or_else(|| {
        GlovesError::InvalidInput(format!("{action_name} requires a command after '--'"))
    })?;
    let mut resolved_request = resolve_execution_request(state, request)?;
    let command_result = vault_cmd::run_child_command(
        &resolved_request.command,
        &resolved_request.environment,
        &[EXTPASS_ROOT_ENV_VAR, EXTPASS_AGENT_ENV_VAR],
        action_name,
    );
    resolved_request
        .environment
        .iter_mut()
        .for_each(|(_, value)| value.zeroize());
    let exit_code = command_result?;
    Ok(ExecutionResult {
        executable,
        exit_code,
        injected_variables: resolved_request.injected_variables,
    })
}

fn parse_execution_env_bindings(bindings: &[String]) -> Result<Vec<ExecutionEnvBinding>> {
    if bindings.is_empty() {
        return Err(GlovesError::InvalidInput(
            "process execution requires at least one --env binding".to_owned(),
        ));
    }

    let mut parsed_bindings = Vec::with_capacity(bindings.len());
    let mut seen_variables = HashSet::new();
    for literal in bindings {
        let binding = parse_execution_env_binding(literal)?;
        if !seen_variables.insert(binding.variable_name.clone()) {
            return Err(GlovesError::InvalidInput(format!(
                "duplicate environment variable in --env: {}",
                binding.variable_name
            )));
        }
        parsed_bindings.push(binding);
    }
    Ok(parsed_bindings)
}

fn parse_execution_env_binding(literal: &str) -> Result<ExecutionEnvBinding> {
    let trimmed_literal = literal.trim();
    if trimmed_literal.is_empty() {
        return Err(GlovesError::InvalidInput(
            "--env bindings must not be empty".to_owned(),
        ));
    }
    let (variable_name, secret_ref) = trimmed_literal.split_once('=').ok_or_else(|| {
        GlovesError::InvalidInput(
            "--env bindings must use NAME=gloves://namespace/secret-path".to_owned(),
        )
    })?;
    let variable_name = validate_execution_env_variable_name(variable_name.trim())?;
    let secret_ref = secret_ref.trim().parse::<SecretRef>().map_err(|error| {
        GlovesError::InvalidInput(format!(
            "invalid secret ref `{}` in --env binding: {}",
            secret_ref.trim(),
            error
        ))
    })?;
    Ok(ExecutionEnvBinding {
        variable_name,
        secret_ref,
    })
}

fn resolve_execution_request(
    state: &EffectiveCliState,
    request: ExecutionRequest,
) -> Result<ResolvedExecutionRequest> {
    match request.strategy {
        ExecutionDeliveryStrategy::Env => {
            resolve_execution_env_request(state, request.command, request.env_bindings)
        }
    }
}

fn resolve_execution_env_request(
    state: &EffectiveCliState,
    command: Vec<String>,
    env_bindings: Vec<ExecutionEnvBinding>,
) -> Result<ResolvedExecutionRequest> {
    let store = NamespacedStore::new(state.paths.root());
    let agent = state.default_agent_id.clone();
    let mut environment = Vec::with_capacity(env_bindings.len());
    let mut injected_variables = Vec::with_capacity(env_bindings.len());
    for binding in env_bindings {
        let secret_id = binding.secret_ref.secret_id().clone();
        ensure_secret_acl_allowed(state, SecretAclOperation::Read, Some(&secret_id))?;
        let result = match store.get_secret(&secret_id, &agent) {
            Ok(result) => result,
            Err(GlovesError::NotFound) => {
                return Err(run_secret_not_found_error(
                    binding.secret_ref.secret_id().as_str(),
                ))
            }
            Err(error) => return Err(error),
        };
        injected_variables.push(binding.variable_name.clone());
        environment.push((binding.variable_name, result.value));
    }
    Ok(ResolvedExecutionRequest {
        command,
        environment,
        injected_variables,
    })
}

fn validate_execution_env_variable_name(variable_name: &str) -> Result<String> {
    let trimmed_name = variable_name.trim();
    if trimmed_name.is_empty() {
        return Err(GlovesError::InvalidInput(
            "--env variable name must not be empty".to_owned(),
        ));
    }
    let mut characters = trimmed_name.chars();
    let Some(first_character) = characters.next() else {
        return Err(GlovesError::InvalidInput(
            "--env variable name must not be empty".to_owned(),
        ));
    };
    if !matches!(first_character, 'A'..='Z' | 'a'..='z' | '_') {
        return Err(GlovesError::InvalidInput(format!(
            "invalid environment variable name `{trimmed_name}` in --env"
        )));
    }
    if !characters.all(|character| matches!(character, 'A'..='Z' | 'a'..='z' | '0'..='9' | '_')) {
        return Err(GlovesError::InvalidInput(format!(
            "invalid environment variable name `{trimmed_name}` in --env"
        )));
    }
    Ok(trimmed_name.to_owned())
}

fn compact_process_error(stderr: &str) -> String {
    let compacted = stderr.trim();
    if compacted.is_empty() {
        "no diagnostic output".to_owned()
    } else {
        compacted.to_owned()
    }
}

fn ensure_secret_acl_allowed(
    state: &EffectiveCliState,
    operation: SecretAclOperation,
    secret_id: Option<&SecretId>,
) -> Result<()> {
    let Some(config) = state.secret_acl_config.as_ref() else {
        return Ok(());
    };

    let policy = config
        .secret_access_policy(&state.default_agent_id)
        .ok_or(GlovesError::Forbidden)?;
    if !policy.allows_operation(operation) {
        return Err(GlovesError::Forbidden);
    }
    if let Some(secret_id) = secret_id {
        if !policy.allows_secret(secret_id.as_str()) {
            return Err(GlovesError::Forbidden);
        }
    }
    Ok(())
}

fn filter_list_items_for_secret_acl(
    state: &EffectiveCliState,
    entries: Vec<ListItem>,
) -> Result<Vec<ListItem>> {
    let Some(config) = state.secret_acl_config.as_ref() else {
        return Ok(entries);
    };

    let policy = config
        .secret_access_policy(&state.default_agent_id)
        .ok_or(GlovesError::Forbidden)?;
    Ok(entries
        .into_iter()
        .filter(|item| match item {
            ListItem::Secret(meta) => policy.allows_secret(meta.id.as_str()),
            ListItem::Pending(request) => policy.allows_secret(request.secret_name.as_str()),
        })
        .collect())
}

fn pending_request_for_id(
    manager: &crate::manager::SecretsManager,
    request_id: uuid::Uuid,
    action: &str,
) -> Result<crate::types::PendingRequest> {
    manager
        .pending_store
        .load_all()?
        .into_iter()
        .find(|request| request.id == request_id)
        .ok_or_else(|| {
            GlovesError::InvalidInput(format!(
                "request id `{request_id}` was not found in pending requests\nRun `{PENDING_REQUEST_LOOKUP_COMMAND}` and retry with `gloves requests {action} <request-id>`"
            ))
        })
}

fn secret_not_found_error(secret_name: &str, action: &str) -> GlovesError {
    GlovesError::InvalidInput(format!(
        "secret `{secret_name}` was not found\nRun `{SECRET_LOOKUP_COMMAND}` to inspect available secrets, then retry `gloves secrets {action} <secret-name>`"
    ))
}

fn run_secret_not_found_error(secret_name: &str) -> GlovesError {
    GlovesError::InvalidInput(format!(
        "secret `{secret_name}` was not found\nRun `{SECRET_LOOKUP_COMMAND}` to inspect available secrets, then retry `gloves run --env NAME=gloves://... -- <command...>`"
    ))
}

fn gpg_key_not_found_error(agent: &AgentId) -> GlovesError {
    let agent_name = agent.as_str();
    GlovesError::InvalidInput(format!(
        "no GPG key found for agent `{agent_name}`\nRun `gloves --agent {agent_name} gpg create` and retry `gloves --agent {agent_name} gpg fingerprint`"
    ))
}

fn run_list_command(
    state: &EffectiveCliState,
    pending_only: bool,
    command_name: &str,
) -> Result<Option<i32>> {
    let manager = runtime::manager_for_paths(&state.paths)?;
    ensure_secret_acl_allowed(state, SecretAclOperation::List, None)?;
    let mut entries = filter_list_items_for_secret_acl(state, manager.list_all()?)?;
    if pending_only {
        entries.retain(|entry| {
            matches!(
                entry,
                ListItem::Pending(request) if request.status == crate::types::RequestStatus::Pending
            )
        });
    }
    let list_target = if pending_only {
        Some("pending".to_owned())
    } else {
        None
    };
    log_command_executed(
        &state.paths,
        &state.default_agent_id,
        command_name,
        list_target,
    );
    stdout_line_or_exit(&serde_json::to_string_pretty(&entries)?)
}

fn run_grant_command(
    state: &EffectiveCliState,
    secret_name: &str,
    recipient_agent: &str,
) -> Result<Option<i32>> {
    let manager = runtime::manager_for_paths(&state.paths)?;
    let secret_id = SecretId::new(secret_name)?;
    ensure_secret_acl_allowed(state, SecretAclOperation::Write, Some(&secret_id))?;
    if !manager.metadata_store.path_for(&secret_id).exists() {
        return Err(secret_not_found_error(secret_id.as_str(), "grant"));
    }

    let granter = state.default_agent_id.clone();
    let metadata = manager.metadata_store.load(&secret_id)?;
    if metadata.owner != Owner::Agent {
        return Err(GlovesError::InvalidInput(format!(
            "secret `{}` is not agent-owned and cannot be granted",
            secret_id.as_str()
        )));
    }
    if metadata.created_by != granter {
        return Err(GlovesError::InvalidInput(format!(
            "secret `{}` can only be granted by its creator `{}`\nRetry with `gloves --agent {} secrets grant {} --to {}`",
            secret_id.as_str(),
            metadata.created_by.as_str(),
            metadata.created_by.as_str(),
            secret_id.as_str(),
            recipient_agent
        )));
    }

    let new_recipient = AgentId::new(recipient_agent)?;
    if metadata.recipients.contains(&new_recipient) {
        let payload = GrantOutput {
            action: "already_granted",
            secret_name: secret_id.as_str().to_owned(),
            granted_to: new_recipient.as_str().to_owned(),
            granted_by: granter.as_str().to_owned(),
            changed: false,
        };
        return stdout_line_or_exit(&serde_json::to_string_pretty(&payload)?);
    }

    let mut all_recipients = metadata.recipients;
    all_recipients.insert(new_recipient.clone());
    let recipient_keys = recipient_keys_for_agents(&state.paths, all_recipients)?;
    let granter_identity_file = runtime::load_or_create_identity_for_agent(&state.paths, &granter)?;
    manager.grant(
        &secret_id,
        &granter,
        granter_identity_file.as_path(),
        new_recipient.clone(),
        &recipient_keys,
    )?;

    log_command_executed(
        &state.paths,
        &state.default_agent_id,
        "grant",
        Some(format!(
            "{}->{}",
            secret_id.as_str(),
            new_recipient.as_str()
        )),
    );
    let payload = GrantOutput {
        action: "granted",
        secret_name: secret_id.as_str().to_owned(),
        granted_to: new_recipient.as_str().to_owned(),
        granted_by: granter.as_str().to_owned(),
        changed: true,
    };
    stdout_line_or_exit(&serde_json::to_string_pretty(&payload)?)
}

fn recipient_keys_for_agents(
    paths: &SecretsPaths,
    recipients: HashSet<AgentId>,
) -> Result<Vec<String>> {
    let mut sorted_recipients = recipients.into_iter().collect::<Vec<_>>();
    sorted_recipients.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    sorted_recipients
        .into_iter()
        .map(|recipient| runtime::load_or_create_recipient_for_agent(paths, &recipient))
        .collect()
}

fn run_request_approve_command(
    state: &EffectiveCliState,
    request_id_literal: &str,
    command_name: &str,
) -> Result<Option<i32>> {
    let manager = runtime::manager_for_paths(&state.paths)?;
    let request_id = runtime::parse_request_uuid(request_id_literal)?;
    let pending_request = pending_request_for_id(&manager, request_id, "approve")?;
    ensure_secret_acl_allowed(
        state,
        SecretAclOperation::Approve,
        Some(&pending_request.secret_name),
    )?;
    let request_policy = resolve_request_policy(None, None)?;
    ensure_request_policy_allows(&pending_request.secret_name, &request_policy, "approve")?;
    let approved = manager.approve_request(request_id, state.default_agent_id.clone())?;
    let payload = request_review_output("approved", &approved);
    log_command_executed(
        &state.paths,
        &state.default_agent_id,
        command_name,
        Some(request_id.to_string()),
    );
    stdout_line_or_exit(&serde_json::to_string_pretty(&payload)?)
}

fn run_request_deny_command(
    state: &EffectiveCliState,
    request_id_literal: &str,
    command_name: &str,
) -> Result<Option<i32>> {
    let manager = runtime::manager_for_paths(&state.paths)?;
    let request_id = runtime::parse_request_uuid(request_id_literal)?;
    let pending_request = pending_request_for_id(&manager, request_id, "deny")?;
    ensure_secret_acl_allowed(
        state,
        SecretAclOperation::Deny,
        Some(&pending_request.secret_name),
    )?;
    let denied = manager.deny_request(request_id, state.default_agent_id.clone())?;
    let payload = request_review_output("denied", &denied);
    log_command_executed(
        &state.paths,
        &state.default_agent_id,
        command_name,
        Some(request_id.to_string()),
    );
    stdout_line_or_exit(&serde_json::to_string_pretty(&payload)?)
}

fn run_explain_command(code: &str, json_output: bool) -> Result<Option<i32>> {
    if let Some(explanation) = explain_error_code(code) {
        if json_output {
            return emit_command_json(
                "explain",
                serde_json::json!({
                    "code": normalize_error_code(code),
                    "content": explanation,
                }),
            );
        }
        return stdout_line_or_exit(explanation);
    }
    let normalized_code = normalize_error_code(code);
    Err(GlovesError::InvalidInput(format!(
            "unknown error code `{normalized_code}`\nKnown codes: {}\nTry `gloves help explain` for usage",
            known_error_codes().join(", ")
        )))
}

fn run_help_command(topic: &[String], json_output: bool) -> Result<Option<i32>> {
    run_help_command_with_prefix(&[], topic, json_output)
}

fn run_help_command_with_prefix(
    prefix: &[&str],
    topic: &[String],
    json_output: bool,
) -> Result<Option<i32>> {
    let mut args = Vec::with_capacity(2 + prefix.len() + topic.len());
    args.push("gloves".to_owned());
    args.extend(prefix.iter().map(|segment| (*segment).to_owned()));
    args.extend(topic.iter().cloned());
    args.push("--help".to_owned());

    match Cli::try_parse_from(args) {
        Err(help_error)
            if matches!(
                help_error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            let rendered = format_help_output(&help_error.to_string());
            if json_output {
                let topic_path = if topic.is_empty() {
                    prefix.join(" ")
                } else {
                    let mut combined = prefix.join(" ");
                    if !combined.is_empty() {
                        combined.push(' ');
                    }
                    combined.push_str(&topic.join(" "));
                    combined
                };
                emit_command_json(
                    "help",
                    serde_json::json!({
                        "topic": topic_path,
                        "content": rendered,
                    }),
                )
            } else {
                stdout_line_or_exit(&rendered)
            }
        }
        Err(parse_error) => {
            let joined_topic = if topic.is_empty() {
                prefix.join(" ")
            } else {
                let mut joined = prefix.join(" ");
                if !joined.is_empty() {
                    joined.push(' ');
                }
                joined.push_str(&topic.join(" "));
                joined
            };
            Err(GlovesError::InvalidInput(format!(
                "unknown help topic `{joined_topic}`\n{parse_error}\nTry `gloves help` for command index"
            )))
        }
        Ok(_) => Ok(None),
    }
}

fn format_help_output(raw_help: &str) -> String {
    let mut lines = Vec::new();
    for raw_line in raw_help.lines() {
        let line = raw_line.trim_end();
        if let Some(usage) = line.strip_prefix("Usage:") {
            if !lines.is_empty() && !lines.last().is_some_and(String::is_empty) {
                lines.push(String::new());
            }
            lines.push("USAGE:".to_owned());
            lines.push(format!("  {}", usage.trim()));
            continue;
        }
        let heading = match line {
            "Commands:" => Some("COMMANDS:"),
            "Subcommands:" => Some("SUBCOMMANDS:"),
            "Arguments:" => Some("ARGS:"),
            "Options:" => Some("OPTIONS:"),
            _ => None,
        };
        if let Some(heading) = heading {
            if !lines.is_empty() && !lines.last().is_some_and(String::is_empty) {
                lines.push(String::new());
            }
            lines.push(heading.to_owned());
            continue;
        }
        lines.push(line.to_owned());
    }
    while lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    format!("{}\n", lines.join("\n"))
}

fn run_version_command(json: bool) -> Result<Option<i32>> {
    let version_output = VersionOutput {
        name: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
        config_schema_version: CONFIG_SCHEMA_VERSION,
        default_root: DEFAULT_ROOT_DIR,
        default_agent: DEFAULT_AGENT_ID,
    };
    if json {
        return stdout_line_or_exit(&serde_json::to_string_pretty(&version_output)?);
    }
    let rendered = format!(
        "{} {}\nconfig schema version: {}\ndefault root: {}\ndefault agent: {}\nhelp: {}\ncommand help: {}",
        version_output.name,
        version_output.version,
        version_output.config_schema_version,
        version_output.default_root,
        version_output.default_agent,
        CLI_HELP_HINT,
        CLI_COMMAND_HELP_HINT,
    );
    stdout_line_or_exit(&rendered)
}

pub(super) fn emit_version_output(json: bool) -> Result<i32> {
    Ok(run_version_command(json)?.unwrap_or(0))
}

fn request_review_output(
    action: &str,
    request: &crate::types::PendingRequest,
) -> RequestReviewOutput {
    RequestReviewOutput {
        action: action.to_owned(),
        request_id: request.id.to_string(),
        secret_name: request.secret_name.as_str().to_owned(),
        requested_by: request.requested_by.as_str().to_owned(),
        reason: request.reason.clone(),
        requested_at: request.requested_at,
        expires_at: request.expires_at,
        status: request.status.clone(),
        pending: request.pending,
        approved_at: request.approved_at,
        approved_by: request
            .approved_by
            .as_ref()
            .map(|agent| agent.as_str().to_owned()),
        denied_at: request.denied_at,
        denied_by: request
            .denied_by
            .as_ref()
            .map(|agent| agent.as_str().to_owned()),
    }
}

struct RequestPolicy {
    allowlist: Vec<String>,
    blocklist: Vec<String>,
}

fn resolve_request_policy(
    cli_allowlist: Option<&str>,
    cli_blocklist: Option<&str>,
) -> Result<RequestPolicy> {
    Ok(RequestPolicy {
        allowlist: resolve_secret_pattern_source(REQUEST_ALLOWLIST_ENV_VAR, cli_allowlist)?,
        blocklist: resolve_secret_pattern_source(REQUEST_BLOCKLIST_ENV_VAR, cli_blocklist)?,
    })
}

fn resolve_secret_pattern_source(env_key: &str, cli_value: Option<&str>) -> Result<Vec<String>> {
    if let Some(raw) = cli_value {
        return parse_secret_pattern_list(raw, env_key);
    }
    match std::env::var(env_key) {
        Ok(raw) => parse_secret_pattern_list(&raw, env_key),
        Err(VarError::NotPresent) => Ok(Vec::new()),
        Err(VarError::NotUnicode(_)) => Err(GlovesError::InvalidInput(format!(
            "{env_key} must be valid UTF-8"
        ))),
    }
}

fn parse_secret_pattern_list(raw: &str, source: &str) -> Result<Vec<String>> {
    let mut patterns = Vec::new();
    let mut seen = HashSet::new();
    for item in raw.split(SECRET_PATTERN_SEPARATOR) {
        let pattern = item.trim();
        if pattern.is_empty() {
            return Err(GlovesError::InvalidInput(format!(
                "{source} contains an empty pattern entry"
            )));
        }
        validate_secret_pattern(pattern, source)?;
        if seen.insert(pattern.to_owned()) {
            patterns.push(pattern.to_owned());
        }
    }
    Ok(patterns)
}

fn validate_secret_pattern(pattern: &str, source: &str) -> Result<()> {
    if pattern == "*" {
        return Ok(());
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        if prefix.is_empty() {
            return Err(GlovesError::InvalidInput(format!(
                "{source} pattern '/*' is invalid; use '*' for all secrets"
            )));
        }
        if prefix.contains('*') {
            return Err(GlovesError::InvalidInput(format!(
                "{source} pattern '{pattern}' may only include one trailing '*'"
            )));
        }
        SecretId::new(prefix).map_err(|_| {
            GlovesError::InvalidInput(format!(
                "{source} pattern '{pattern}' has an invalid namespace prefix"
            ))
        })?;
        return Ok(());
    }
    if pattern.contains('*') {
        return Err(GlovesError::InvalidInput(format!(
            "{source} pattern '{pattern}' must be '*', '<namespace>/*', or exact secret id"
        )));
    }
    SecretId::new(pattern).map_err(|_| {
        GlovesError::InvalidInput(format!(
            "{source} pattern '{pattern}' is not a valid secret id"
        ))
    })?;
    Ok(())
}

fn secret_pattern_matches(pattern: &str, secret_name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return secret_name.len() > prefix.len()
            && secret_name.starts_with(prefix)
            && secret_name.as_bytes().get(prefix.len()) == Some(&b'/');
    }
    secret_name == pattern
}

fn ensure_request_policy_allows(
    secret_id: &SecretId,
    request_policy: &RequestPolicy,
    operation: &str,
) -> Result<()> {
    let secret_name = secret_id.as_str();
    if request_policy
        .blocklist
        .iter()
        .any(|pattern| secret_pattern_matches(pattern, secret_name))
    {
        return Err(GlovesError::InvalidInput(format!(
            "secret '{secret_name}' is blocked for {operation}"
        )));
    }
    if !request_policy.allowlist.is_empty()
        && !request_policy
            .allowlist
            .iter()
            .any(|pattern| secret_pattern_matches(pattern, secret_name))
    {
        return Err(GlovesError::InvalidInput(format!(
            "secret '{secret_name}' is not allowlisted for {operation}"
        )));
    }
    Ok(())
}

fn resolve_secret_output_target(
    pipe_to: Option<String>,
    pipe_to_args: Option<String>,
    stdout_is_tty: bool,
    loaded_config: Option<&GlovesConfig>,
) -> Result<SecretOutputTarget> {
    if pipe_to.is_some() && pipe_to_args.is_some() {
        return Err(GlovesError::InvalidInput(
            "--pipe-to and --pipe-to-args cannot be combined".to_owned(),
        ));
    }

    if let Some(pipe_command) = pipe_to {
        validate_pipe_command_name(&pipe_command, "--pipe-to")?;
        ensure_pipe_command_allowed(&pipe_command)?;
        return Ok(SecretOutputTarget::PipeCommand(pipe_command));
    }

    if let Some(command_template) = pipe_to_args {
        validate_pipe_command_template(&command_template, "--pipe-to-args")?;
        let executable =
            pipe_command_executable_from_template(&command_template, "--pipe-to-args")?;
        ensure_pipe_command_allowed(&executable)?;
        ensure_pipe_command_template_allowed(&command_template, &executable, loaded_config)?;
        return Ok(SecretOutputTarget::PipeCommandArgs(command_template));
    }

    if stdout_is_tty {
        return Ok(SecretOutputTarget::Stdout);
    }

    Err(GlovesError::InvalidInput(
        "refusing to write secret bytes to non-tty stdout; use --pipe-to <command> with an allowlisted command".to_owned(),
    ))
}

fn ensure_pipe_command_allowed(command: &str) -> Result<()> {
    let allowlist = read_secret_pipe_allowlist()?;
    if allowlist.is_empty() {
        return Err(GlovesError::InvalidInput(format!(
            "secret piping is disabled; set {SECRET_PIPE_ALLOWLIST_ENV_VAR} to a comma-separated allowlist"
        )));
    }
    if allowlist.contains(command) {
        return Ok(());
    }

    let mut allowed_commands = allowlist.into_iter().collect::<Vec<_>>();
    allowed_commands.sort();
    Err(GlovesError::InvalidInput(format!(
        "pipe command '{command}' is not allowlisted; allowed commands: {}",
        allowed_commands.join(", ")
    )))
}

fn ensure_pipe_command_template_allowed(
    command_template: &str,
    executable: &str,
    loaded_config: Option<&GlovesConfig>,
) -> Result<()> {
    let normalized_template =
        parse_pipe_command_template(command_template, SECRET_PIPE_TEMPLATE_SOURCE)?;
    ensure_pipe_command_template_matches_arg_policy(&normalized_template, executable)?;
    ensure_pipe_command_template_matches_url_policy(
        &normalized_template,
        executable,
        loaded_config,
    )?;
    Ok(())
}

fn ensure_pipe_command_template_matches_arg_policy(
    normalized_template: &[String],
    executable: &str,
) -> Result<()> {
    let Some(policy) = read_secret_pipe_arg_policy()? else {
        return Ok(());
    };

    let allowed_templates = policy.get(executable).ok_or_else(|| {
        GlovesError::InvalidInput(format!(
            "pipe command '{executable}' is not allowed by {SECRET_PIPE_ARG_POLICY_ENV_VAR}; add an explicit template rule"
        ))
    })?;
    if allowed_templates
        .iter()
        .any(|template_parts| template_parts == normalized_template)
    {
        return Ok(());
    }

    let allowed = allowed_templates
        .iter()
        .map(|template_parts| template_parts.join(" "))
        .collect::<Vec<_>>();
    Err(GlovesError::InvalidInput(format!(
        "pipe command template for '{executable}' is not allowlisted by {SECRET_PIPE_ARG_POLICY_ENV_VAR}; allowed templates: {}",
        allowed.join(" | ")
    )))
}

fn ensure_pipe_command_template_matches_url_policy(
    normalized_template: &[String],
    executable: &str,
    loaded_config: Option<&GlovesConfig>,
) -> Result<()> {
    if let Some(policy) =
        loaded_config.and_then(|config| config.secret_pipe_command_policy(executable))
    {
        return ensure_pipe_command_template_matches_resolved_url_policy(
            normalized_template,
            executable,
            policy.require_url,
            &policy.url_prefixes,
            URL_POLICY_SOURCE_CONFIG,
        );
    }

    let Some(policy) = read_secret_pipe_url_policy()? else {
        return Ok(());
    };
    let Some(allowed_url_prefixes) = policy.get(executable) else {
        return Ok(());
    };

    ensure_pipe_command_template_matches_resolved_url_policy(
        normalized_template,
        executable,
        true,
        allowed_url_prefixes,
        URL_POLICY_SOURCE_ENV,
    )
}

const URL_POLICY_SOURCE_ENV: &str = "env";
const URL_POLICY_SOURCE_CONFIG: &str = "config";

fn ensure_pipe_command_template_matches_resolved_url_policy(
    normalized_template: &[String],
    executable: &str,
    require_url: bool,
    allowed_url_prefixes: &[String],
    source: &str,
) -> Result<()> {
    if allowed_url_prefixes.is_empty() && !require_url {
        return Ok(());
    }

    let requested_urls = normalized_template
        .iter()
        .skip(1)
        .filter(|argument| is_http_url_argument(argument))
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if requested_urls.is_empty() && require_url {
        return Err(url_policy_requires_url_error(executable, source));
    }
    if requested_urls.is_empty() {
        return Ok(());
    }

    let parsed_prefixes = allowed_url_prefixes
        .iter()
        .map(|prefix| parse_policy_url_prefix(prefix))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|reason| {
            GlovesError::InvalidInput(format!(
                "configured URL prefix for '{executable}' is invalid: {reason}"
            ))
        })?;

    let disallowed_urls = requested_urls
        .iter()
        .filter(|url| {
            let Ok(parsed_url) = parse_policy_url_argument(url) else {
                return true;
            };
            !parsed_prefixes
                .iter()
                .any(|prefix| policy_url_matches_prefix(&parsed_url, prefix))
        })
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if disallowed_urls.is_empty() {
        return Ok(());
    }

    Err(url_policy_disallowed_urls_error(
        executable,
        source,
        &disallowed_urls,
        allowed_url_prefixes,
    ))
}

fn url_policy_requires_url_error(executable: &str, source: &str) -> GlovesError {
    let message = match source {
        URL_POLICY_SOURCE_CONFIG => format!(
            "pipe command template for '{executable}' must include at least one http(s) URL argument when .gloves.toml [secrets.pipe.commands.{executable}] sets require_url = true"
        ),
        _ => format!(
            "pipe command template for '{executable}' must include at least one http(s) URL argument when {SECRET_PIPE_URL_POLICY_ENV_VAR} defines rules for this command"
        ),
    };
    GlovesError::InvalidInput(message)
}

fn url_policy_disallowed_urls_error(
    executable: &str,
    source: &str,
    disallowed_urls: &[String],
    allowed_url_prefixes: &[String],
) -> GlovesError {
    let message = match source {
        URL_POLICY_SOURCE_CONFIG => format!(
            "pipe command template for '{executable}' has URL arguments not allowlisted by .gloves.toml [secrets.pipe.commands.{executable}]: {}; allowed URL prefixes: {}",
            disallowed_urls.join(", "),
            allowed_url_prefixes.join(" | ")
        ),
        _ => format!(
            "pipe command template for '{executable}' has URL arguments not allowlisted by {SECRET_PIPE_URL_POLICY_ENV_VAR}: {}; allowed URL prefixes: {}",
            disallowed_urls.join(", "),
            allowed_url_prefixes.join(" | ")
        ),
    };
    GlovesError::InvalidInput(message)
}

#[derive(Debug, Clone)]
struct ParsedPolicyUrl {
    scheme: String,
    authority: String,
    path: String,
}

fn parse_policy_url_prefix(url_prefix: &str) -> std::result::Result<ParsedPolicyUrl, String> {
    parse_policy_url(url_prefix, false)
}

fn parse_policy_url_argument(argument: &str) -> std::result::Result<ParsedPolicyUrl, String> {
    let normalized_argument = argument.replace(
        SECRET_PIPE_TEMPLATE_PLACEHOLDER,
        SECRET_PIPE_URL_SAMPLE_TOKEN,
    );
    parse_policy_url(&normalized_argument, true)
}

fn parse_policy_url(
    url_literal: &str,
    allow_query_or_fragment: bool,
) -> std::result::Result<ParsedPolicyUrl, String> {
    let (scheme, remainder) = if let Some(rest) = url_literal.strip_prefix(URL_SCHEME_HTTP_PREFIX) {
        ("http", rest)
    } else if let Some(rest) = url_literal.strip_prefix(URL_SCHEME_HTTPS_PREFIX) {
        ("https", rest)
    } else {
        return Err("must start with http:// or https://".to_owned());
    };

    if remainder.is_empty() {
        return Err("must include an authority after scheme".to_owned());
    }

    let delimiter_index = remainder
        .find(|character: char| ['/', '?', '#'].contains(&character))
        .unwrap_or(remainder.len());
    let authority = &remainder[..delimiter_index];
    if authority.is_empty() {
        return Err("must include an authority after scheme".to_owned());
    }
    if authority.chars().any(char::is_whitespace) {
        return Err("must not contain whitespace in authority".to_owned());
    }

    let suffix = &remainder[delimiter_index..];
    if !allow_query_or_fragment
        && suffix
            .chars()
            .any(|character| character == '?' || character == '#')
    {
        return Err("must not include query or fragment components".to_owned());
    }

    let path = if suffix.is_empty() {
        "/".to_owned()
    } else if suffix.starts_with('/') {
        let path_end = suffix
            .find(|character: char| ['?', '#'].contains(&character))
            .unwrap_or(suffix.len());
        suffix[..path_end].to_owned()
    } else {
        "/".to_owned()
    };

    Ok(ParsedPolicyUrl {
        scheme: scheme.to_owned(),
        authority: authority.to_ascii_lowercase(),
        path,
    })
}

fn policy_url_matches_prefix(url: &ParsedPolicyUrl, prefix: &ParsedPolicyUrl) -> bool {
    if url.scheme != prefix.scheme || url.authority != prefix.authority {
        return false;
    }
    policy_path_matches_prefix(&url.path, &prefix.path)
}

fn policy_path_matches_prefix(path: &str, prefix: &str) -> bool {
    if path == prefix {
        return true;
    }
    if prefix.ends_with('/') {
        return path.starts_with(prefix);
    }
    path.starts_with(prefix) && path.as_bytes().get(prefix.len()) == Some(&b'/')
}

fn read_secret_pipe_allowlist() -> Result<HashSet<String>> {
    match std::env::var(SECRET_PIPE_ALLOWLIST_ENV_VAR) {
        Ok(raw) => parse_secret_pipe_allowlist(&raw),
        Err(VarError::NotPresent) => Ok(HashSet::new()),
        Err(VarError::NotUnicode(_)) => Err(GlovesError::InvalidInput(format!(
            "{SECRET_PIPE_ALLOWLIST_ENV_VAR} must be valid UTF-8"
        ))),
    }
}

fn read_secret_pipe_arg_policy() -> Result<Option<HashMap<String, Vec<Vec<String>>>>> {
    match std::env::var(SECRET_PIPE_ARG_POLICY_ENV_VAR) {
        Ok(raw) => parse_secret_pipe_arg_policy(&raw).map(Some),
        Err(VarError::NotPresent) => Ok(None),
        Err(VarError::NotUnicode(_)) => Err(GlovesError::InvalidInput(format!(
            "{SECRET_PIPE_ARG_POLICY_ENV_VAR} must be valid UTF-8"
        ))),
    }
}

fn read_secret_pipe_url_policy() -> Result<Option<HashMap<String, Vec<String>>>> {
    match std::env::var(SECRET_PIPE_URL_POLICY_ENV_VAR) {
        Ok(raw) => parse_secret_pipe_url_policy(&raw).map(Some),
        Err(VarError::NotPresent) => Ok(None),
        Err(VarError::NotUnicode(_)) => Err(GlovesError::InvalidInput(format!(
            "{SECRET_PIPE_URL_POLICY_ENV_VAR} must be valid UTF-8"
        ))),
    }
}

fn parse_secret_pipe_arg_policy(raw: &str) -> Result<HashMap<String, Vec<Vec<String>>>> {
    let parsed: HashMap<String, Vec<String>> = serde_json::from_str(raw).map_err(|error| {
        GlovesError::InvalidInput(format!(
            "{SECRET_PIPE_ARG_POLICY_ENV_VAR} must be valid JSON: {error}"
        ))
    })?;

    let mut normalized_policy = HashMap::new();
    for (command, templates) in parsed {
        validate_pipe_command_name(&command, SECRET_PIPE_ARG_POLICY_ENV_VAR)?;
        if templates.is_empty() {
            return Err(GlovesError::InvalidInput(format!(
                "{SECRET_PIPE_ARG_POLICY_ENV_VAR} command '{command}' must include at least one template"
            )));
        }

        let mut normalized_templates = Vec::with_capacity(templates.len());
        for template in templates {
            validate_pipe_command_template(&template, SECRET_PIPE_ARG_POLICY_ENV_VAR)?;
            let parsed_template =
                parse_pipe_command_template(&template, SECRET_PIPE_ARG_POLICY_ENV_VAR)?;
            if parsed_template[0] != command {
                return Err(GlovesError::InvalidInput(format!(
                    "{SECRET_PIPE_ARG_POLICY_ENV_VAR} template '{template}' must start with command '{command}'"
                )));
            }
            normalized_templates.push(parsed_template);
        }
        normalized_policy.insert(command, normalized_templates);
    }
    Ok(normalized_policy)
}

fn parse_secret_pipe_url_policy(raw: &str) -> Result<HashMap<String, Vec<String>>> {
    let parsed: HashMap<String, Vec<String>> = serde_json::from_str(raw).map_err(|error| {
        GlovesError::InvalidInput(format!(
            "{SECRET_PIPE_URL_POLICY_ENV_VAR} must be valid JSON: {error}"
        ))
    })?;
    if parsed.is_empty() {
        return Err(GlovesError::InvalidInput(format!(
            "{SECRET_PIPE_URL_POLICY_ENV_VAR} must include at least one command entry"
        )));
    }

    let mut normalized_policy = HashMap::new();
    for (command, url_prefixes) in parsed {
        validate_pipe_command_name(&command, SECRET_PIPE_URL_POLICY_ENV_VAR)?;
        if url_prefixes.is_empty() {
            return Err(GlovesError::InvalidInput(format!(
                "{SECRET_PIPE_URL_POLICY_ENV_VAR} command '{command}' must include at least one URL prefix"
            )));
        }

        let mut normalized_prefixes = Vec::with_capacity(url_prefixes.len());
        for url_prefix in url_prefixes {
            validate_pipe_url_prefix(&command, &url_prefix)?;
            normalized_prefixes.push(url_prefix);
        }
        normalized_policy.insert(command, normalized_prefixes);
    }
    Ok(normalized_policy)
}

fn parse_secret_pipe_allowlist(raw: &str) -> Result<HashSet<String>> {
    let mut allowlist = HashSet::new();
    for item in raw.split(SECRET_PIPE_ALLOWLIST_SEPARATOR) {
        let command = item.trim();
        if command.is_empty() {
            return Err(GlovesError::InvalidInput(format!(
                "{SECRET_PIPE_ALLOWLIST_ENV_VAR} contains an empty command entry"
            )));
        }
        validate_pipe_command_name(command, SECRET_PIPE_ALLOWLIST_ENV_VAR)?;
        allowlist.insert(command.to_owned());
    }
    Ok(allowlist)
}

fn validate_pipe_command_name(command: &str, source: &str) -> Result<()> {
    if command.is_empty()
        || !command
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._+-".contains(character))
    {
        return Err(GlovesError::InvalidInput(format!(
            "{source} command '{command}' must be a bare executable name"
        )));
    }
    Ok(())
}

fn validate_pipe_url_prefix(command: &str, url_prefix: &str) -> Result<()> {
    if url_prefix.trim().is_empty() {
        return Err(GlovesError::InvalidInput(format!(
            "{SECRET_PIPE_URL_POLICY_ENV_VAR} command '{command}' contains an empty URL prefix"
        )));
    }
    if let Err(reason) = parse_policy_url_prefix(url_prefix) {
        return Err(GlovesError::InvalidInput(format!(
            "{SECRET_PIPE_URL_POLICY_ENV_VAR} command '{command}' URL prefix '{url_prefix}' {reason}"
        )));
    }
    Ok(())
}

fn is_http_url_argument(argument: &str) -> bool {
    argument.starts_with(URL_SCHEME_HTTP_PREFIX) || argument.starts_with(URL_SCHEME_HTTPS_PREFIX)
}

fn validate_pipe_command_template(command_template: &str, source: &str) -> Result<()> {
    let parsed_parts = parse_pipe_command_template(command_template, source)?;
    if !parsed_parts
        .iter()
        .any(|part| part.contains(SECRET_PIPE_TEMPLATE_PLACEHOLDER))
    {
        return Err(GlovesError::InvalidInput(format!(
            "{source} must include {SECRET_PIPE_TEMPLATE_PLACEHOLDER} placeholder"
        )));
    }
    if parsed_parts[0].contains(SECRET_PIPE_TEMPLATE_PLACEHOLDER) {
        return Err(GlovesError::InvalidInput(format!(
            "{source} executable must not contain {SECRET_PIPE_TEMPLATE_PLACEHOLDER}"
        )));
    }
    Ok(())
}

fn parse_pipe_command_template(command_template: &str, source: &str) -> Result<Vec<String>> {
    if command_template.trim().is_empty() {
        return Err(GlovesError::InvalidInput(format!(
            "{source} command template must not be empty"
        )));
    }
    let parsed_parts = shlex::split(command_template).ok_or_else(|| {
        GlovesError::InvalidInput(format!(
            "{source} command template has invalid shell quoting"
        ))
    })?;
    if parsed_parts.is_empty() {
        return Err(GlovesError::InvalidInput(format!(
            "{source} command template must include an executable"
        )));
    }
    Ok(parsed_parts)
}

fn pipe_command_executable_from_template(command_template: &str, source: &str) -> Result<String> {
    let parsed_parts = parse_pipe_command_template(command_template, source)?;
    let executable = parsed_parts[0].clone();
    validate_pipe_command_name(&executable, source)?;
    Ok(executable)
}

fn pipe_secret_to_command(pipe_command: &str, secret_bytes: &[u8]) -> Result<()> {
    let mut child = ProcessCommand::new(pipe_command)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| {
            GlovesError::InvalidInput(format!(
                "failed to start pipe command '{pipe_command}': {error}"
            ))
        })?;

    if let Some(mut stdin) = child.stdin.take() {
        write_secret_to_stdin(&mut stdin, secret_bytes)?;
    } else {
        return Err(GlovesError::InvalidInput(format!(
            "failed to open stdin for pipe command '{pipe_command}'"
        )));
    }

    let status = child.wait()?;
    if status.success() {
        return Ok(());
    }

    match status.code() {
        Some(code) => Err(GlovesError::InvalidInput(format!(
            "pipe command '{pipe_command}' failed with exit code {code}"
        ))),
        None => Err(GlovesError::InvalidInput(format!(
            "pipe command '{pipe_command}' terminated by signal"
        ))),
    }
}

fn pipe_secret_to_command_args(command_template: &str, secret_bytes: &[u8]) -> Result<()> {
    let mut parsed_parts =
        parse_pipe_command_template(command_template, SECRET_PIPE_TEMPLATE_SOURCE)?;
    let executable = parsed_parts.remove(0);
    validate_pipe_command_name(&executable, SECRET_PIPE_TEMPLATE_SOURCE)?;

    let secret_literal = std::str::from_utf8(secret_bytes).map_err(|_| {
        GlovesError::InvalidInput(format!(
            "secret is not valid UTF-8; {SECRET_PIPE_TEMPLATE_SOURCE} only supports UTF-8 secrets"
        ))
    })?;
    ensure_secret_is_safe_for_argument_interpolation(secret_literal)?;

    let mut replaced_any = false;
    let mut resolved_arguments = parsed_parts
        .iter()
        .map(|part| {
            if part.contains(SECRET_PIPE_TEMPLATE_PLACEHOLDER) {
                replaced_any = true;
                part.replace(SECRET_PIPE_TEMPLATE_PLACEHOLDER, secret_literal)
            } else {
                part.clone()
            }
        })
        .collect::<Vec<_>>();

    if !replaced_any {
        return Err(GlovesError::InvalidInput(format!(
            "{SECRET_PIPE_TEMPLATE_SOURCE} must include {SECRET_PIPE_TEMPLATE_PLACEHOLDER} placeholder"
        )));
    }

    let status_result = ProcessCommand::new(&executable)
        .args(&resolved_arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|error| {
            GlovesError::InvalidInput(format!(
                "failed to start pipe command '{executable}': {error}"
            ))
        });

    for argument in &mut resolved_arguments {
        argument.zeroize();
    }

    let status = status_result?;

    if status.success() {
        return Ok(());
    }

    match status.code() {
        Some(code) => Err(GlovesError::InvalidInput(format!(
            "pipe command '{executable}' failed with exit code {code}"
        ))),
        None => Err(GlovesError::InvalidInput(format!(
            "pipe command '{executable}' terminated by signal"
        ))),
    }
}

fn ensure_secret_is_safe_for_argument_interpolation(secret_literal: &str) -> Result<()> {
    if secret_literal.chars().any(char::is_control) {
        return Err(GlovesError::InvalidInput(format!(
            "secret contains control characters; use --pipe-to for raw byte-safe forwarding instead of {SECRET_PIPE_TEMPLATE_SOURCE}"
        )));
    }
    Ok(())
}

fn write_secret_to_stdin(handle: &mut impl Write, bytes: &[u8]) -> Result<()> {
    match handle.write_all(bytes).and_then(|_| handle.flush()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(GlovesError::Io(error)),
    }
}

fn run_extpass_get(secret_name: &str) -> Result<i32> {
    let root = read_required_env_var(EXTPASS_ROOT_ENV_VAR)?;
    let agent = read_required_env_var(EXTPASS_AGENT_ENV_VAR)?;

    let paths = SecretsPaths::new(root);
    let manager = runtime::manager_for_paths(&paths)?;
    let secret_id = SecretId::new(secret_name)?;
    let caller = AgentId::new(&agent)?;
    let identity_file = runtime::load_or_create_identity_for_agent(&paths, &caller)?;
    let secret = manager.get(&secret_id, &caller, Some(identity_file.as_path()))?;
    let mut secret_bytes = secret.expose(ToOwned::to_owned);
    if let Some(code) = stdout_bytes_or_exit(&secret_bytes)? {
        secret_bytes.zeroize();
        return Ok(code);
    }
    secret_bytes.zeroize();
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
    let mut selection = resolve_config_path(
        cli.config.as_deref(),
        env_path.as_deref(),
        cli.no_config,
        &current_dir,
    )?;
    if selection.path.is_none() && !cli.no_config {
        if let Some(root_override) = cli.root.as_deref() {
            let discovery_start = if root_override.is_absolute() {
                root_override.to_path_buf()
            } else {
                current_dir.join(root_override)
            };
            if let Some(discovered) = discover_config(discovery_start) {
                selection = crate::config::ConfigSelection {
                    source: ConfigSource::Discovered,
                    path: Some(discovered),
                };
            }
        }
    }
    let loaded_config = match selection.path {
        Some(path) => Some(GlovesConfig::load_from_path(path)?),
        None => None,
    };

    let root = cli
        .root
        .clone()
        .or_else(|| loaded_config.as_ref().map(|config| config.root.clone()))
        .unwrap_or_else(|| std::path::PathBuf::from(DEFAULT_ROOT_DIR));
    let secret_acl_config =
        resolve_secret_acl_config(cli, loaded_config.as_ref(), &root, &current_dir)?;
    let default_agent_id = match cli.agent.as_deref() {
        Some(agent_literal) => AgentId::new(agent_literal)?,
        None => loaded_config
            .as_ref()
            .map(|config| config.defaults.agent_id.clone())
            .unwrap_or(AgentId::new(DEFAULT_AGENT_ID)?),
    };
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
        secret_acl_config,
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

fn resolve_secret_acl_config(
    cli: &Cli,
    loaded_config: Option<&GlovesConfig>,
    effective_root: &std::path::Path,
    current_dir: &std::path::Path,
) -> Result<Option<GlovesConfig>> {
    if let Some(config) = loaded_config {
        if config.has_secret_acl() {
            return Ok(Some(config.clone()));
        }
        return Ok(None);
    }

    if !cli.no_config {
        return Ok(None);
    }

    let absolute_root = if effective_root.is_absolute() {
        effective_root.to_path_buf()
    } else {
        current_dir.join(effective_root)
    };
    let Some(path) = discover_config(&absolute_root) else {
        return Ok(None);
    };
    let config = GlovesConfig::load_from_path(path)?;
    if !config.has_secret_acl() {
        return Ok(None);
    }
    let normalized_root =
        std::fs::canonicalize(&absolute_root).unwrap_or_else(|_| absolute_root.clone());
    if config.root != normalized_root && config.root != absolute_root {
        return Ok(None);
    }
    Ok(Some(config))
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

#[cfg(test)]
mod tests {
    use super::{
        audit_event_name, audit_event_summary, bytes_to_hex, format_audit_record_line,
        is_binary_available, is_executable_file, latest_audit_records, load_audit_records,
        parse_execution_env_binding, parse_policy_url_argument, parse_policy_url_prefix,
        parse_tui_bootstrap_args, path_operation_label, policy_url_matches_prefix,
        secret_bytes_json_value, validate_execution_env_variable_name, validate_pipe_url_prefix,
        AuditRecord, ErrorFormatArg, PathOperation, VaultModeArg, SECRET_PIPE_URL_POLICY_ENV_VAR,
    };
    #[cfg(unix)]
    use super::{
        canonical_or_absolute_path, reset_gpg_homedir_alias, resolve_gpg_homedir,
        resolve_relative_symlink_target,
    };
    use crate::{
        audit::AuditEvent,
        types::{AgentId, Owner, SecretId},
    };
    use chrono::{Duration, Utc};
    #[cfg(unix)]
    use std::{
        env, fs,
        os::unix::fs::PermissionsExt,
        path::Path,
        sync::{Mutex, OnceLock},
    };
    #[cfg(unix)]
    use tempfile::tempdir;

    #[cfg(unix)]
    static PATH_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    #[test]
    fn parse_execution_env_binding_requires_explicit_secret_ref_binding() {
        let explicit = parse_execution_env_binding("API_KEY=gloves://shared/github-token").unwrap();
        assert_eq!(explicit.variable_name, "API_KEY");
        assert_eq!(
            explicit.secret_ref.secret_id().as_str(),
            "shared/github-token"
        );

        let missing_equals = parse_execution_env_binding("gloves://shared/db-url").unwrap_err();
        assert!(missing_equals
            .to_string()
            .contains("must use NAME=gloves://namespace/secret-path"));
    }

    #[test]
    fn parse_execution_env_binding_rejects_invalid_secret_refs() {
        let error = parse_execution_env_binding("API_KEY=shared/github-token").unwrap_err();
        assert!(error.to_string().contains("invalid secret ref"));
    }

    #[test]
    fn validate_execution_env_variable_name_rejects_invalid_values() {
        let error = validate_execution_env_variable_name("1INVALID").unwrap_err();
        assert!(error
            .to_string()
            .contains("invalid environment variable name"));
    }

    #[test]
    fn parse_policy_url_prefix_rejects_query_and_fragment() {
        let query_error = parse_policy_url_prefix("https://api.example.com/v1?token=abc")
            .expect_err("query suffix must be rejected");
        assert!(query_error.contains("must not include query or fragment"));

        let fragment_error = parse_policy_url_prefix("https://api.example.com/v1#frag")
            .expect_err("fragment suffix must be rejected");
        assert!(fragment_error.contains("must not include query or fragment"));
    }

    #[test]
    fn parse_policy_url_argument_supports_secret_placeholder() {
        let parsed = parse_policy_url_argument("https://api.example.com/v1/items?token={secret}")
            .expect("template URL with {secret} must parse");
        assert_eq!(parsed.scheme, "https");
        assert_eq!(parsed.authority, "api.example.com");
        assert_eq!(parsed.path, "/v1/items");
    }

    #[test]
    fn parse_policy_url_argument_defaults_to_root_path_when_missing() {
        let parsed = parse_policy_url_argument("https://api.example.com?token={secret}")
            .expect("URL without explicit path must parse");
        assert_eq!(parsed.path, "/");
    }

    #[test]
    fn policy_url_matches_prefix_enforces_host_boundary() {
        let prefix = parse_policy_url_prefix("https://api.example.com").unwrap();
        let allowed = parse_policy_url_argument("https://api.example.com/v1").unwrap();
        let denied = parse_policy_url_argument("https://api.example.com.evil/v1").unwrap();

        assert!(policy_url_matches_prefix(&allowed, &prefix));
        assert!(!policy_url_matches_prefix(&denied, &prefix));
    }

    #[test]
    fn policy_url_matches_prefix_enforces_path_segment_boundary() {
        let prefix = parse_policy_url_prefix("https://api.example.com/v1").unwrap();
        let exact = parse_policy_url_argument("https://api.example.com/v1").unwrap();
        let nested = parse_policy_url_argument("https://api.example.com/v1/contacts").unwrap();
        let sibling = parse_policy_url_argument("https://api.example.com/v10/contacts").unwrap();

        assert!(policy_url_matches_prefix(&exact, &prefix));
        assert!(policy_url_matches_prefix(&nested, &prefix));
        assert!(!policy_url_matches_prefix(&sibling, &prefix));
    }

    #[test]
    fn validate_pipe_url_prefix_reports_policy_source() {
        let error = validate_pipe_url_prefix("curl", "https://api.example.com/v1?x=1")
            .expect_err("query in URL prefix must be rejected");
        let text = error.to_string();
        assert!(text.contains(SECRET_PIPE_URL_POLICY_ENV_VAR));
        assert!(text.contains("must not include query or fragment"));
    }

    #[test]
    fn parse_tui_bootstrap_args_extracts_global_overrides_and_command_tail() {
        let parsed = parse_tui_bootstrap_args(&[
            "--config".to_owned(),
            "/etc/gloves/prod.gloves.toml".to_owned(),
            "audit".to_owned(),
            "--limit".to_owned(),
            "100".to_owned(),
        ])
        .expect("tui bootstrap args should parse");

        assert_eq!(
            parsed
                .config
                .as_ref()
                .map(|path| path.display().to_string())
                .as_deref(),
            Some("/etc/gloves/prod.gloves.toml")
        );
        assert_eq!(
            parsed.command_args,
            vec!["audit".to_owned(), "--limit".to_owned(), "100".to_owned()]
        );
    }

    #[test]
    fn parse_tui_bootstrap_args_supports_inline_values() {
        let parsed = parse_tui_bootstrap_args(&[
            "--root=/tmp/gloves".to_owned(),
            "--agent=agent-main".to_owned(),
            "--vault-mode=required".to_owned(),
            "--error-format=json".to_owned(),
            "requests".to_owned(),
            "list".to_owned(),
        ])
        .expect("inline tui bootstrap args should parse");

        assert_eq!(
            parsed
                .root
                .as_ref()
                .map(|path| path.display().to_string())
                .as_deref(),
            Some("/tmp/gloves")
        );
        assert_eq!(parsed.agent.as_deref(), Some("agent-main"));
        assert!(matches!(parsed.vault_mode, Some(VaultModeArg::Required)));
        assert!(matches!(parsed.error_format, Some(ErrorFormatArg::Json)));
        assert!(!parsed.json);
        assert_eq!(
            parsed.command_args,
            vec!["requests".to_owned(), "list".to_owned()]
        );
    }

    #[test]
    fn parse_tui_bootstrap_args_supports_json_shorthand() {
        let parsed = parse_tui_bootstrap_args(&[
            "--json".to_owned(),
            "audit".to_owned(),
            "--limit".to_owned(),
            "100".to_owned(),
        ])
        .expect("json shorthand should parse");

        assert!(parsed.json);
        assert!(matches!(parsed.error_format, Some(ErrorFormatArg::Json)));
        assert_eq!(
            parsed.command_args,
            vec!["audit".to_owned(), "--limit".to_owned(), "100".to_owned()]
        );
    }

    #[test]
    fn parse_tui_bootstrap_args_rejects_invalid_vault_mode() {
        let error = parse_tui_bootstrap_args(&["--vault-mode=fast".to_owned()])
            .expect_err("invalid vault mode should fail");
        assert!(error
            .to_string()
            .contains("expected auto, required, or disabled"));
    }

    #[test]
    fn audit_helpers_format_all_supported_event_variants() {
        let secret_id = SecretId::new("service/token").unwrap();
        let requested_file = "docs/spec.md".to_owned();
        let agent = AgentId::new("devy").unwrap();
        let reviewer = AgentId::new("main").unwrap();
        let request_id = uuid::Uuid::new_v4();
        let expires_at = Utc::now() + Duration::minutes(30);
        let cases = [
            (
                AuditEvent::SecretAccessed {
                    secret_id: secret_id.clone(),
                    by: agent.clone(),
                },
                "secret_accessed",
                vec!["secret=service/token", "by=devy"],
            ),
            (
                AuditEvent::SecretExpired {
                    secret_id: secret_id.clone(),
                },
                "secret_expired",
                vec!["secret=service/token"],
            ),
            (
                AuditEvent::SecretCreated {
                    secret_id: secret_id.clone(),
                    by: agent.clone(),
                },
                "secret_created",
                vec!["secret=service/token", "by=devy"],
            ),
            (
                AuditEvent::SecretRevoked {
                    secret_id: secret_id.clone(),
                    by: reviewer.clone(),
                },
                "secret_revoked",
                vec!["secret=service/token", "by=main"],
            ),
            (
                AuditEvent::RequestCreated {
                    request_id,
                    secret_id: secret_id.clone(),
                    requested_by: agent.clone(),
                    reason: "need testing".to_owned(),
                    expires_at,
                },
                "request_created",
                vec![
                    "request_id=",
                    "secret=service/token",
                    "requested_by=devy",
                    "expires_at=",
                ],
            ),
            (
                AuditEvent::RequestApproved {
                    request_id,
                    secret_id: secret_id.clone(),
                    requested_by: agent.clone(),
                    approved_by: reviewer.clone(),
                },
                "request_approved",
                vec!["approved_by=main", "requested_by=devy"],
            ),
            (
                AuditEvent::RequestDenied {
                    request_id,
                    secret_id: secret_id.clone(),
                    requested_by: agent.clone(),
                    denied_by: reviewer.clone(),
                },
                "request_denied",
                vec!["denied_by=main", "requested_by=devy"],
            ),
            (
                AuditEvent::VaultCreated {
                    vault: "primary".to_owned(),
                    owner: Owner::Agent,
                },
                "vault_created",
                vec!["vault=primary", "owner=Agent"],
            ),
            (
                AuditEvent::VaultMounted {
                    vault: "primary".to_owned(),
                    agent: agent.clone(),
                    ttl_minutes: 30,
                },
                "vault_mounted",
                vec!["vault=primary", "agent=devy", "ttl_minutes=30"],
            ),
            (
                AuditEvent::VaultUnmounted {
                    vault: "primary".to_owned(),
                    reason: "idle_timeout".to_owned(),
                    agent: reviewer.clone(),
                },
                "vault_unmounted",
                vec!["vault=primary", "reason=idle_timeout", "agent=main"],
            ),
            (
                AuditEvent::VaultSessionExpired {
                    vault: "primary".to_owned(),
                },
                "vault_session_expired",
                vec!["vault=primary"],
            ),
            (
                AuditEvent::VaultHandoffPromptIssued {
                    vault: "primary".to_owned(),
                    requester: agent.clone(),
                    trusted_agent: reviewer.clone(),
                    requested_file: requested_file.clone(),
                },
                "vault_handoff_prompt_issued",
                vec![
                    "vault=primary",
                    "requester=devy",
                    "trusted_agent=main",
                    "file=docs/spec.md",
                ],
            ),
            (
                AuditEvent::GpgKeyCreated {
                    agent: reviewer.clone(),
                    fingerprint: "ABC123".to_owned(),
                },
                "gpg_key_created",
                vec!["agent=main", "fingerprint=ABC123"],
            ),
            (
                AuditEvent::CommandExecuted {
                    by: reviewer.clone(),
                    interface: "mcp".to_owned(),
                    command: "gloves_get".to_owned(),
                    target: Some("agents/devy/api-keys/anthropic".to_owned()),
                },
                "command_executed",
                vec![
                    "by=main",
                    "interface=mcp",
                    "command=gloves_get",
                    "target=agents/devy/api-keys/anthropic",
                ],
            ),
        ];

        for (event, expected_name, expected_fragments) in cases {
            assert_eq!(audit_event_name(&event), expected_name);
            let summary = audit_event_summary(&event);
            for fragment in expected_fragments {
                assert!(
                    summary.contains(fragment),
                    "summary `{summary}` must contain `{fragment}`"
                );
            }
        }
    }

    #[test]
    fn audit_helpers_format_lines_and_apply_limits() {
        let first = AuditRecord {
            timestamp: Utc::now() - Duration::minutes(2),
            event: AuditEvent::SecretExpired {
                secret_id: SecretId::new("service/old").unwrap(),
            },
        };
        let second = AuditRecord {
            timestamp: Utc::now() - Duration::minutes(1),
            event: AuditEvent::SecretCreated {
                secret_id: SecretId::new("service/new").unwrap(),
                by: AgentId::new("devy").unwrap(),
            },
        };
        let third = AuditRecord {
            timestamp: Utc::now(),
            event: AuditEvent::CommandExecuted {
                by: AgentId::new("main").unwrap(),
                interface: "cli".to_owned(),
                command: "list".to_owned(),
                target: None,
            },
        };

        let formatted = format_audit_record_line(&third);
        assert!(formatted.contains("command_executed"));
        assert!(formatted.contains("command=list"));

        let limited = latest_audit_records(vec![first.clone(), second.clone(), third.clone()], 2);
        assert_eq!(limited.len(), 2);
        assert_eq!(limited[0].timestamp, second.timestamp);
        assert_eq!(limited[1].timestamp, third.timestamp);

        let unlimited = latest_audit_records(vec![first, second, third], 0);
        assert_eq!(unlimited.len(), 3);
    }

    #[test]
    fn secret_bytes_helpers_cover_utf8_and_binary_inputs() {
        let utf8 = secret_bytes_json_value(b"hello");
        assert_eq!(utf8["encoding"], "utf8");
        assert_eq!(utf8["data"], "hello");

        let binary = secret_bytes_json_value(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(binary["encoding"], "hex");
        assert_eq!(binary["data"], "deadbeef");

        assert_eq!(bytes_to_hex(&[0x00, 0x0f, 0x10, 0xff]), "000f10ff");
    }

    #[test]
    fn load_audit_records_skips_blank_lines_and_reports_invalid_entries() {
        let temp = tempfile::tempdir().unwrap();
        let audit_path = temp.path().join("audit.jsonl");
        std::fs::write(
            &audit_path,
            format!(
                "{}\n\n{}\n",
                serde_json::to_string(&AuditRecord {
                    timestamp: Utc::now(),
                    event: AuditEvent::CommandExecuted {
                        by: AgentId::new("main").unwrap(),
                        interface: "cli".to_owned(),
                        command: "list".to_owned(),
                        target: None,
                    },
                })
                .unwrap(),
                "not-json"
            ),
        )
        .unwrap();

        let error = load_audit_records(&audit_path).unwrap_err();
        assert!(error.to_string().contains("invalid audit entry at line 3"));

        std::fs::write(
            &audit_path,
            format!(
                "{}\n\n",
                serde_json::to_string(&AuditRecord {
                    timestamp: Utc::now(),
                    event: AuditEvent::CommandExecuted {
                        by: AgentId::new("main").unwrap(),
                        interface: "cli".to_owned(),
                        command: "list".to_owned(),
                        target: None,
                    },
                })
                .unwrap()
            ),
        )
        .unwrap();
        let records = load_audit_records(&audit_path).unwrap();
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn path_operation_label_covers_all_variants() {
        assert_eq!(path_operation_label(&PathOperation::Read), "read");
        assert_eq!(path_operation_label(&PathOperation::Write), "write");
        assert_eq!(path_operation_label(&PathOperation::List), "list");
        assert_eq!(path_operation_label(&PathOperation::Mount), "mount");
    }

    #[cfg(unix)]
    #[test]
    fn executable_detection_checks_modes_and_path_resolution() {
        let temp_dir = tempdir().unwrap();
        let binary_dir = temp_dir.path().join("bin");
        fs::create_dir_all(&binary_dir).unwrap();
        let binary_path = binary_dir.join("gloves-helper");
        fs::write(&binary_path, "#!/bin/sh\nexit 0\n").unwrap();

        let mut non_executable_permissions = fs::metadata(&binary_path).unwrap().permissions();
        non_executable_permissions.set_mode(0o644);
        fs::set_permissions(&binary_path, non_executable_permissions).unwrap();
        assert!(!is_executable_file(&binary_path));
        assert!(!is_binary_available(binary_path.to_str().unwrap()));

        let mut executable_permissions = fs::metadata(&binary_path).unwrap().permissions();
        executable_permissions.set_mode(0o755);
        fs::set_permissions(&binary_path, executable_permissions).unwrap();
        assert!(is_executable_file(&binary_path));
        assert!(is_binary_available(binary_path.to_str().unwrap()));

        let _lock = PATH_ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        let original_path = env::var_os("PATH");
        env::set_var("PATH", &binary_dir);
        assert!(is_binary_available("gloves-helper"));
        assert!(!is_binary_available("missing-helper"));
        env::remove_var("PATH");
        assert!(!is_binary_available("gloves-helper"));
        match original_path {
            Some(value) => env::set_var("PATH", value),
            None => env::remove_var("PATH"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn canonical_or_absolute_path_returns_canonical_existing_path() {
        let temp_dir = tempdir().expect("temp dir");
        let actual_home = temp_dir.path().join("actual-home");
        fs::create_dir_all(&actual_home).expect("create actual home");

        let resolved = canonical_or_absolute_path(&actual_home).expect("canonical path");
        assert_eq!(
            resolved,
            fs::canonicalize(&actual_home).expect("canonicalized actual home")
        );
    }

    #[cfg(unix)]
    #[test]
    fn canonical_or_absolute_path_preserves_missing_absolute_path() {
        let temp_dir = tempdir().expect("temp dir");
        let missing_path = temp_dir.path().join("missing-home");

        let resolved = canonical_or_absolute_path(&missing_path).expect("absolute fallback");
        assert_eq!(resolved, missing_path);
    }

    #[cfg(unix)]
    #[test]
    fn resolve_relative_symlink_target_joins_alias_parent_for_relative_paths() {
        let alias_parent = Path::new("/tmp/gloves-gpg-test");
        let relative_target =
            resolve_relative_symlink_target(Path::new("../real-home"), Some(alias_parent));
        assert_eq!(
            relative_target,
            Path::new("/tmp/gloves-gpg-test/../real-home")
        );

        let absolute_target =
            resolve_relative_symlink_target(Path::new("/var/run/gloves-home"), Some(alias_parent));
        assert_eq!(absolute_target, Path::new("/var/run/gloves-home"));
    }

    #[cfg(unix)]
    #[test]
    fn reset_gpg_homedir_alias_replaces_existing_directory_with_symlink() {
        let temp_dir = tempdir().expect("temp dir");
        let alias_home = temp_dir.path().join("alias-home");
        let target_home = temp_dir.path().join("target-home");
        fs::create_dir_all(alias_home.join("stale")).expect("create stale alias directory");
        fs::create_dir_all(&target_home).expect("create target home");

        reset_gpg_homedir_alias(&alias_home, &target_home).expect("replace alias directory");

        let metadata = fs::symlink_metadata(&alias_home).expect("alias metadata");
        assert!(metadata.file_type().is_symlink());
        assert_eq!(
            fs::read_link(&alias_home).expect("alias target"),
            target_home
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_gpg_homedir_creates_short_alias_symlink() {
        let temp_dir = tempdir().expect("temp dir");
        let actual_home = temp_dir.path().join("very/deep/runtime/gpg/home");
        fs::create_dir_all(&actual_home).expect("create actual gpg home");

        let gpg_home = resolve_gpg_homedir(&actual_home).expect("resolve gpg homedir");
        let alias_path = gpg_home.path().to_path_buf();
        let alias_root = alias_path.parent().expect("alias root").to_path_buf();

        assert_ne!(alias_path, actual_home);
        assert!(alias_path.starts_with("/tmp"));
        assert!(fs::symlink_metadata(&alias_path)
            .expect("alias metadata")
            .file_type()
            .is_symlink());
        let alias_target = fs::read_link(&alias_path).expect("alias target");
        assert_eq!(
            fs::canonicalize(resolve_relative_symlink_target(
                &alias_target,
                alias_path.parent()
            ))
            .expect("canonical alias target"),
            fs::canonicalize(&actual_home).expect("canonical actual home")
        );

        fs::remove_dir_all(alias_root).expect("cleanup alias root");
    }

    #[cfg(unix)]
    #[test]
    fn resolve_gpg_homedir_repairs_mismatched_alias_target() {
        let temp_dir = tempdir().expect("temp dir");
        let actual_home = temp_dir.path().join("runtime/gpg/home");
        let wrong_home = temp_dir.path().join("wrong-home");
        fs::create_dir_all(&actual_home).expect("create actual gpg home");
        fs::create_dir_all(&wrong_home).expect("create wrong gpg home");

        let gpg_home = resolve_gpg_homedir(&actual_home).expect("resolve gpg homedir");
        let alias_path = gpg_home.path().to_path_buf();
        let alias_root = alias_path.parent().expect("alias root").to_path_buf();

        fs::remove_file(&alias_path).expect("remove original alias");
        std::os::unix::fs::symlink(&wrong_home, &alias_path).expect("seed wrong alias");

        let repaired = resolve_gpg_homedir(&actual_home).expect("repair alias target");
        let repaired_target = fs::read_link(repaired.path()).expect("repaired target");
        assert_eq!(
            fs::canonicalize(resolve_relative_symlink_target(
                &repaired_target,
                repaired.path().parent()
            ))
            .expect("canonical repaired target"),
            fs::canonicalize(&actual_home).expect("canonical actual home")
        );

        fs::remove_dir_all(alias_root).expect("cleanup alias root");
    }
}
