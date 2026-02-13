use crate::{
    audit::AuditLog,
    error::Result,
    paths::SecretsPaths,
    types::AgentId,
    vault::{gocryptfs::GocryptfsDriver, VaultManager, VaultSecretProvider},
};

use super::{runtime, secret_input, VaultCommand};

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

pub(crate) fn run_vault_command(paths: &SecretsPaths, command: VaultCommand) -> Result<()> {
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
            let ttl_duration = secret_input::parse_duration_value(&ttl, "--ttl")?;
            manager.mount(&name, ttl_duration, mountpoint, AgentId::new(&agent)?)?;
            println!("mounted");
        }
        VaultCommand::Unmount { name, agent } => {
            manager.unmount(&name, "explicit", AgentId::new(&agent)?)?;
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
            let prompt = manager.ask_file_prompt(
                &name,
                &file,
                AgentId::new(&requester)?,
                AgentId::new(&trusted_agent)?,
                reason,
            )?;
            println!("{prompt}");
        }
    }
    Ok(())
}
