use std::process::{Command as ProcessCommand, Stdio};

use crate::{
    audit::AuditLog,
    error::{GlovesError, Result},
    paths::SecretsPaths,
    types::AgentId,
    vault::{
        gocryptfs::{GocryptfsDriver, EXTPASS_AGENT_ENV_VAR, EXTPASS_ROOT_ENV_VAR},
        VaultManager, VaultSecretProvider,
    },
};

use super::{
    output::{self, OutputStatus},
    runtime, secret_input, VaultCommand,
};

#[derive(Debug, Clone)]
pub(crate) struct VaultCommandDefaults {
    pub mount_ttl: String,
    pub agent_id: AgentId,
    pub vault_secret_ttl_days: i64,
    pub vault_secret_length_bytes: usize,
}

#[derive(Debug, Clone)]
struct CliVaultSecretProvider {
    paths: SecretsPaths,
    agent_id: AgentId,
    ttl_days: i64,
    length_bytes: usize,
}

impl VaultSecretProvider for CliVaultSecretProvider {
    fn ensure_agent_secret(&self, secret_name: &str) -> Result<()> {
        runtime::ensure_agent_vault_secret(
            &self.paths,
            secret_name,
            &self.agent_id,
            self.ttl_days,
            self.length_bytes,
        )
    }
}

fn vault_manager_for_paths(
    paths: &SecretsPaths,
    defaults: &VaultCommandDefaults,
    extpass_agent: &AgentId,
) -> Result<VaultManager<GocryptfsDriver, CliVaultSecretProvider>> {
    runtime::init_layout(paths)?;
    let audit_log = AuditLog::new(paths.audit_file())?;
    Ok(VaultManager::new(
        paths.clone(),
        GocryptfsDriver::new(),
        CliVaultSecretProvider {
            paths: paths.clone(),
            agent_id: defaults.agent_id.clone(),
            ttl_days: defaults.vault_secret_ttl_days,
            length_bytes: defaults.vault_secret_length_bytes,
        },
        extpass_agent.clone(),
        audit_log,
    ))
}

fn resolve_agent_id(raw: Option<String>, default_agent: &AgentId) -> Result<AgentId> {
    match raw {
        Some(value) => Ok(AgentId::new(&value)?),
        None => Ok(default_agent.clone()),
    }
}

pub(crate) fn run_vault_command(
    paths: &SecretsPaths,
    command: VaultCommand,
    defaults: &VaultCommandDefaults,
    json_output: bool,
) -> Result<Option<i32>> {
    match command {
        VaultCommand::Help { .. } => {}
        VaultCommand::Init { name, owner } => {
            let manager = vault_manager_for_paths(paths, defaults, &defaults.agent_id)?;
            manager.init(&name, owner.into())?;
            emit_text_or_json(
                "initialized",
                serde_json::json!({
                    "status": "initialized",
                    "vault": name,
                }),
                json_output,
            )?;
        }
        VaultCommand::Mount {
            name,
            ttl,
            mountpoint,
            agent,
        } => {
            let ttl_literal = ttl.unwrap_or_else(|| defaults.mount_ttl.clone());
            let ttl_duration = secret_input::parse_duration_value(&ttl_literal, "--ttl")?;
            let mounted_by = resolve_agent_id(agent, &defaults.agent_id)?;
            let manager = vault_manager_for_paths(paths, defaults, &mounted_by)?;
            manager.mount(&name, ttl_duration, mountpoint, mounted_by)?;
            emit_text_or_json(
                "mounted",
                serde_json::json!({
                    "status": "mounted",
                    "vault": name,
                }),
                json_output,
            )?;
        }
        VaultCommand::Exec {
            name,
            ttl,
            mountpoint,
            agent,
            command,
        } => {
            let ttl_literal = ttl.unwrap_or_else(|| defaults.mount_ttl.clone());
            let ttl_duration = secret_input::parse_duration_value(&ttl_literal, "--ttl")?;
            let mounted_by = resolve_agent_id(agent, &defaults.agent_id)?;
            let manager = vault_manager_for_paths(paths, defaults, &mounted_by)?;
            manager.mount(&name, ttl_duration, mountpoint, mounted_by.clone())?;

            let command_exit_code = run_vault_exec_command(&command);
            let unmount_reason = if command_exit_code.is_ok() {
                "exec-complete"
            } else {
                "exec-error"
            };
            let unmount_result = manager.unmount(&name, unmount_reason, mounted_by);
            match (command_exit_code, unmount_result) {
                (Ok(exit_code), Ok(())) => return Ok(Some(exit_code)),
                (Ok(exit_code), Err(unmount_error)) => {
                    return Err(GlovesError::InvalidInput(format!(
                        "vault exec command exited with code {exit_code}, but unmount failed: {unmount_error}"
                    )));
                }
                (Err(command_error), Ok(())) => return Err(command_error),
                (Err(command_error), Err(unmount_error)) => {
                    return Err(GlovesError::InvalidInput(format!(
                        "vault exec command failed: {command_error}; additionally failed to unmount vault: {unmount_error}"
                    )));
                }
            }
        }
        VaultCommand::Unmount { name, agent } => {
            let manager = vault_manager_for_paths(paths, defaults, &defaults.agent_id)?;
            let mounted_by = resolve_agent_id(agent, &defaults.agent_id)?;
            manager.unmount(&name, "explicit", mounted_by)?;
            emit_text_or_json(
                "unmounted",
                serde_json::json!({
                    "status": "unmounted",
                    "vault": name,
                }),
                json_output,
            )?;
        }
        VaultCommand::Status => {
            let manager = vault_manager_for_paths(paths, defaults, &defaults.agent_id)?;
            let status = manager.status()?;
            emit_stdout_line(&serde_json::to_string_pretty(&status)?)?;
        }
        VaultCommand::List => {
            let manager = vault_manager_for_paths(paths, defaults, &defaults.agent_id)?;
            let entries = manager.list()?;
            emit_stdout_line(&serde_json::to_string_pretty(&entries)?)?;
        }
        VaultCommand::AskFile {
            name,
            file,
            requester,
            trusted_agent,
            reason,
        } => {
            let manager = vault_manager_for_paths(paths, defaults, &defaults.agent_id)?;
            let requester = resolve_agent_id(requester, &defaults.agent_id)?;
            let prompt = manager.ask_file_prompt(
                &name,
                &file,
                requester,
                AgentId::new(&trusted_agent)?,
                reason,
            )?;
            emit_text_or_json(
                &prompt,
                serde_json::json!({
                    "vault": name,
                    "file": file,
                    "prompt": prompt,
                }),
                json_output,
            )?;
        }
    }
    Ok(None)
}

fn emit_stdout_line(line: &str) -> Result<()> {
    match output::stdout_line(line) {
        Ok(OutputStatus::Written | OutputStatus::BrokenPipe) => Ok(()),
        Err(error) => Err(GlovesError::Io(error)),
    }
}

fn emit_text_or_json(text: &str, payload: serde_json::Value, json_output: bool) -> Result<()> {
    if json_output {
        emit_stdout_line(&serde_json::to_string_pretty(&payload)?)
    } else {
        emit_stdout_line(text)
    }
}

fn run_vault_exec_command(command: &[String]) -> Result<i32> {
    if command.is_empty() {
        return Err(GlovesError::InvalidInput(
            "vault exec requires a command after '--'".to_owned(),
        ));
    }

    let executable = &command[0];
    let status = ProcessCommand::new(executable)
        .args(&command[1..])
        .env_remove(EXTPASS_ROOT_ENV_VAR)
        .env_remove(EXTPASS_AGENT_ENV_VAR)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|error| {
            GlovesError::InvalidInput(format!(
                "failed to start vault exec command '{executable}': {error}"
            ))
        })?;
    match status.code() {
        Some(code) => Ok(code),
        None => Err(GlovesError::InvalidInput(format!(
            "vault exec command '{executable}' terminated by signal"
        ))),
    }
}
