use crate::{
    audit::AuditLog,
    error::Result,
    paths::SecretsPaths,
    types::AgentId,
    vault::{gocryptfs::GocryptfsDriver, VaultManager, VaultSecretProvider},
};

use super::{runtime, secret_input, VaultCommand};

#[derive(Debug, Clone)]
pub(crate) struct VaultCommandDefaults {
    pub mount_ttl: String,
    pub agent_id: AgentId,
}

#[derive(Debug, Clone)]
struct CliVaultSecretProvider {
    paths: SecretsPaths,
}

impl VaultSecretProvider for CliVaultSecretProvider {
    fn ensure_agent_secret(&self, secret_name: &str) -> Result<()> {
        runtime::ensure_agent_vault_secret(&self.paths, secret_name)
    }
}

fn vault_manager_for_paths(
    paths: &SecretsPaths,
) -> Result<VaultManager<GocryptfsDriver, CliVaultSecretProvider>> {
    runtime::init_layout(paths)?;
    let audit_log = AuditLog::new(paths.audit_file())?;
    Ok(VaultManager::new(
        paths.clone(),
        GocryptfsDriver::new(),
        CliVaultSecretProvider {
            paths: paths.clone(),
        },
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
    let manager = vault_manager_for_paths(paths)?;
    match command {
        VaultCommand::Init { name, owner } => {
            manager.init(&name, owner.into())?;
            println!("initialized");
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
            println!("mounted");
        }
        VaultCommand::Unmount { name, agent } => {
            let mounted_by = resolve_agent_id(agent, &defaults.agent_id)?;
            manager.unmount(&name, "explicit", mounted_by)?;
            println!("unmounted");
        }
        VaultCommand::Status => {
            let status = manager.status()?;
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        VaultCommand::List => {
            let entries = manager.list()?;
            println!("{}", serde_json::to_string_pretty(&entries)?);
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
            println!("{prompt}");
        }
    }
    Ok(())
}
