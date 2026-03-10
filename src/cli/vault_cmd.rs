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
            return finalize_vault_exec(command_exit_code, unmount_result);
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
    emit_stdout_line(&render_text_or_json(text, payload, json_output)?)
}

fn render_text_or_json(
    text: &str,
    payload: serde_json::Value,
    json_output: bool,
) -> Result<String> {
    if json_output {
        return Ok(serde_json::to_string_pretty(&payload)?);
    }
    Ok(text.to_owned())
}

fn finalize_vault_exec(
    command_exit_code: Result<i32>,
    unmount_result: Result<()>,
) -> Result<Option<i32>> {
    match (command_exit_code, unmount_result) {
        (Ok(exit_code), Ok(())) => Ok(Some(exit_code)),
        (Ok(exit_code), Err(unmount_error)) => Err(GlovesError::InvalidInput(format!(
            "vault exec command exited with code {exit_code}, but unmount failed: {unmount_error}"
        ))),
        (Err(command_error), Ok(())) => Err(command_error),
        (Err(command_error), Err(unmount_error)) => Err(GlovesError::InvalidInput(format!(
            "vault exec command failed: {command_error}; additionally failed to unmount vault: {unmount_error}"
        ))),
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

#[cfg(test)]
mod tests {
    use super::{
        finalize_vault_exec, render_text_or_json, resolve_agent_id, run_vault_command,
        run_vault_exec_command, VaultCommandDefaults,
    };
    use crate::{cli::VaultCommand, paths::SecretsPaths, types::AgentId};

    #[test]
    fn resolve_agent_id_uses_explicit_or_default_value() {
        let default_agent = AgentId::new("main").unwrap();
        assert_eq!(
            resolve_agent_id(Some("devy".to_owned()), &default_agent)
                .unwrap()
                .as_str(),
            "devy"
        );
        assert_eq!(
            resolve_agent_id(None, &default_agent).unwrap().as_str(),
            "main"
        );
    }

    #[test]
    fn resolve_agent_id_rejects_invalid_values() {
        let default_agent = AgentId::new("main").unwrap();
        let error = resolve_agent_id(Some("../bad".to_owned()), &default_agent).unwrap_err();
        assert!(error.to_string().contains("invalid"));
    }

    #[test]
    fn run_vault_exec_command_rejects_missing_command() {
        let error = run_vault_exec_command(&[]).unwrap_err();
        assert!(error.to_string().contains("requires a command after '--'"));
    }

    #[test]
    fn render_text_or_json_returns_text_and_json_payloads() {
        let payload = serde_json::json!({ "status": "ok", "vault": "agent-data" });
        assert_eq!(
            render_text_or_json("mounted", payload.clone(), false).unwrap(),
            "mounted"
        );

        let rendered_json = render_text_or_json("mounted", payload, true).unwrap();
        assert!(rendered_json.contains("\"status\": \"ok\""));
        assert!(rendered_json.contains("\"vault\": \"agent-data\""));
    }

    #[test]
    fn finalize_vault_exec_covers_all_command_and_unmount_outcomes() {
        assert_eq!(finalize_vault_exec(Ok(7), Ok(())).unwrap(), Some(7));

        let unmount_error =
            finalize_vault_exec(Ok(3), Err(crate::error::GlovesError::Forbidden)).unwrap_err();
        assert!(unmount_error
            .to_string()
            .contains("vault exec command exited with code 3"));

        let command_error =
            finalize_vault_exec(Err(crate::error::GlovesError::Unauthorized), Ok(())).unwrap_err();
        assert!(matches!(
            command_error,
            crate::error::GlovesError::Unauthorized
        ));

        let combined_error = finalize_vault_exec(
            Err(crate::error::GlovesError::Forbidden),
            Err(crate::error::GlovesError::NotFound),
        )
        .unwrap_err();
        assert!(combined_error
            .to_string()
            .contains("additionally failed to unmount vault"));
    }

    #[test]
    fn run_vault_command_help_returns_without_side_effects() {
        let temp_dir = tempfile::tempdir().unwrap();
        let paths = SecretsPaths::new(temp_dir.path());
        let defaults = VaultCommandDefaults {
            mount_ttl: "1h".to_owned(),
            agent_id: AgentId::new("main").unwrap(),
            vault_secret_ttl_days: 1,
            vault_secret_length_bytes: 32,
        };

        let result = run_vault_command(
            &paths,
            VaultCommand::Help { topic: Vec::new() },
            &defaults,
            false,
        )
        .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn run_vault_exec_command_reports_start_failures() {
        let error =
            run_vault_exec_command(&["/definitely/missing/gloves-command".to_owned()]).unwrap_err();
        assert!(error
            .to_string()
            .contains("failed to start vault exec command"));
    }

    #[cfg(unix)]
    #[test]
    fn run_vault_exec_command_returns_exit_code_and_signal_errors() {
        let success =
            run_vault_exec_command(&["/bin/sh".to_owned(), "-c".to_owned(), "exit 7".to_owned()])
                .unwrap();
        assert_eq!(success, 7);

        let signal_error = run_vault_exec_command(&[
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            "kill -TERM $$".to_owned(),
        ])
        .unwrap_err();
        assert!(signal_error.to_string().contains("terminated by signal"));
    }
}
