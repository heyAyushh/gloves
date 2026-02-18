use crate::{
    audit::AuditLog,
    error::{GlovesError, Result},
    paths::SecretsPaths,
    types::AgentId,
    vault::{gocryptfs::GocryptfsDriver, VaultManager, VaultSecretProvider},
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
        defaults.agent_id.clone(),
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
) -> Result<()> {
    let manager = vault_manager_for_paths(paths, defaults)?;
    match command {
        VaultCommand::Init { name, owner } => {
            manager.init(&name, owner.into())?;
            emit_stdout_line("initialized")?;
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
            manager.mount(&name, ttl_duration, mountpoint, mounted_by)?;
            emit_stdout_line("mounted")?;
        }
        VaultCommand::Unmount { name, agent } => {
            let mounted_by = resolve_agent_id(agent, &defaults.agent_id)?;
            manager.unmount(&name, "explicit", mounted_by)?;
            emit_stdout_line("unmounted")?;
        }
        VaultCommand::Status => {
            let status = manager.status()?;
            emit_stdout_line(&serde_json::to_string_pretty(&status)?)?;
        }
        VaultCommand::List => {
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
            let requester = resolve_agent_id(requester, &defaults.agent_id)?;
            let prompt = manager.ask_file_prompt(
                &name,
                &file,
                requester,
                AgentId::new(&trusted_agent)?,
                reason,
            )?;
            emit_stdout_line(&prompt)?;
        }
    }
    Ok(())
}

fn emit_stdout_line(line: &str) -> Result<()> {
    match output::stdout_line(line) {
        Ok(OutputStatus::Written | OutputStatus::BrokenPipe) => Ok(()),
        Err(error) => Err(GlovesError::Io(error)),
    }
}
