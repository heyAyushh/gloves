use std::collections::HashSet;

use chrono::Duration;

use crate::{
    error::Result,
    reaper::TtlReaper,
    types::{AgentId, Owner, SecretId, SecretValue},
    vault::gocryptfs::GocryptfsDriver,
};

use super::{
    daemon, runtime, secret_input, vault_cmd, Cli, Command, DEFAULT_AGENT_ID, DEFAULT_TTL_DAYS,
};

pub(crate) fn run(cli: Cli) -> Result<i32> {
    let paths = crate::paths::SecretsPaths::new(&cli.root);
    match cli.command {
        Command::Init => {
            runtime::init_layout(&paths)?;
            println!("initialized");
        }
        Command::Set {
            name,
            generate,
            value,
            stdin,
            ttl,
        } => {
            let manager = runtime::manager_for_paths(&paths)?;
            let secret_id = SecretId::new(&name)?;
            let creator = AgentId::new(DEFAULT_AGENT_ID)?;
            let identity = runtime::load_or_create_default_identity(&paths)?;
            let recipient = identity.to_public().to_string();
            let mut recipients = HashSet::new();
            recipients.insert(creator.clone());
            let ttl_days = runtime::validate_ttl_days(ttl, "--ttl")?;
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
            println!("ok");
        }
        Command::Get { name } => {
            let force_tty_warning = std::env::var("GLOVES_FORCE_TTY_WARNING")
                .map(|value| value == "1")
                .unwrap_or(false);
            if atty::is(atty::Stream::Stdout) || force_tty_warning {
                eprintln!("warning: raw secret output on tty");
            }
            let manager = runtime::manager_for_paths(&paths)?;
            let secret_id = SecretId::new(&name)?;
            let caller = AgentId::new(DEFAULT_AGENT_ID)?;
            let identity = runtime::load_or_create_default_identity(&paths)?;
            let value = manager.get(&secret_id, &caller, Some(identity));
            match value {
                Ok(secret) => secret.expose(|bytes| println!("{}", String::from_utf8_lossy(bytes))),
                Err(error) => {
                    eprintln!("error: {error}");
                    return Ok(1);
                }
            }
        }
        Command::Env { name, var } => {
            let _ = name;
            println!("export {var}=<REDACTED>");
        }
        Command::Request { name, reason } => {
            let manager = runtime::manager_for_paths(&paths)?;
            let secret_id = SecretId::new(&name)?;
            let requester = AgentId::new(DEFAULT_AGENT_ID)?;
            let signing_key = runtime::load_or_create_default_signing_key(&paths)?;
            manager.request(
                secret_id,
                requester,
                reason,
                Duration::days(DEFAULT_TTL_DAYS),
                &signing_key,
            )?;
            println!("pending");
        }
        Command::Approve { request_id } => {
            let manager = runtime::manager_for_paths(&paths)?;
            let request_id = runtime::parse_request_uuid(&request_id)?;
            manager.approve_request(request_id)?;
            println!("approved");
        }
        Command::Deny { request_id } => {
            let manager = runtime::manager_for_paths(&paths)?;
            let request_id = runtime::parse_request_uuid(&request_id)?;
            manager.deny_request(request_id)?;
            println!("denied");
        }
        Command::List => {
            let manager = runtime::manager_for_paths(&paths)?;
            println!("{}", serde_json::to_string_pretty(&manager.list_all()?)?);
        }
        Command::Revoke { name } => {
            let manager = runtime::manager_for_paths(&paths)?;
            let secret_id = SecretId::new(&name)?;
            let caller = AgentId::new(DEFAULT_AGENT_ID)?;
            manager.revoke(&secret_id, &caller)?;
            println!("revoked");
        }
        Command::Status { name } => {
            let manager = runtime::manager_for_paths(&paths)?;
            let pending = manager.pending_store.load_all()?;
            let status = pending
                .into_iter()
                .find(|request| request.secret_name.as_str() == name)
                .map(|request| request.status)
                .unwrap_or(crate::types::RequestStatus::Fulfilled);
            println!("{}", serde_json::to_string(&status)?);
        }
        Command::Verify => {
            let manager = runtime::manager_for_paths(&paths)?;
            TtlReaper::reap(
                &manager.agent_backend,
                &manager.metadata_store,
                &manager.audit_log,
            )?;
            TtlReaper::reap_vault_sessions(&GocryptfsDriver::new(), &paths, &manager.audit_log)?;
            println!("ok");
        }
        Command::Daemon {
            bind,
            check,
            max_requests,
        } => {
            daemon::run_daemon(&paths, &bind, check, max_requests)?;
        }
        Command::Vault { command } => {
            vault_cmd::run_vault_command(&paths, command)?;
        }
    }
    Ok(0)
}
