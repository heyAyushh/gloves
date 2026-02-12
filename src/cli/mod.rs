use std::{collections::HashSet, fs, path::{Path, PathBuf}};

use clap::{Parser, Subcommand};
use chrono::Duration;

use crate::{
    agent::{backend::AgentBackend, meta::MetadataStore},
    audit::AuditLog,
    error::Result,
    human::{backend::HumanBackend, pending::PendingRequestStore},
    manager::SecretsManager,
    reaper::TtlReaper,
    types::{AgentId, Owner, SecretId, SecretValue},
};

const DEFAULT_AGENT_ID: &str = "default-agent";
const DEFAULT_TTL_SECONDS: i64 = 86_400;

/// Top-level command line parser.
#[derive(Debug, Parser)]
#[command(name = "gloves")]
pub struct Cli {
    /// Root storage directory.
    #[arg(long, default_value = ".openclaw/secrets")]
    pub root: PathBuf,
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
        /// TTL in days.
        #[arg(long, default_value_t = 1)]
        ttl: i64,
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
}

/// Runs CLI and returns process exit code.
pub fn run(cli: Cli) -> Result<i32> {
    match cli.command {
        Command::Init => {
            init_layout(&cli.root)?;
            println!("initialized");
        }
        Command::Set {
            name,
            generate,
            ttl,
        } => {
            let manager = manager_for_root(&cli.root)?;
            let secret_id = SecretId::new(&name)?;
            let creator = AgentId::new(DEFAULT_AGENT_ID)?;
            let identity = age::x25519::Identity::generate();
            let recipient = identity.to_public().to_string();
            let mut recipients = HashSet::new();
            recipients.insert(creator.clone());
            let value = if generate {
                SecretValue::new(uuid::Uuid::new_v4().to_string().into_bytes())
            } else {
                SecretValue::new(b"placeholder-secret".to_vec())
            };
            manager.set(
                secret_id,
                Owner::Agent,
                value,
                Duration::days(ttl),
                creator,
                recipients,
                &[recipient],
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
            let manager = manager_for_root(&cli.root)?;
            let secret_id = SecretId::new(&name)?;
            let caller = AgentId::new(DEFAULT_AGENT_ID)?;
            let identity = age::x25519::Identity::generate();
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
            let manager = manager_for_root(&cli.root)?;
            let secret_id = SecretId::new(&name)?;
            let requester = AgentId::new(DEFAULT_AGENT_ID)?;
            manager.request(secret_id, requester, reason, Duration::days(1))?;
            println!("pending");
        }
        Command::List => {
            let manager = manager_for_root(&cli.root)?;
            println!("{}", serde_json::to_string_pretty(&manager.list_all()?)?);
        }
        Command::Revoke { name } => {
            let manager = manager_for_root(&cli.root)?;
            let secret_id = SecretId::new(&name)?;
            let caller = AgentId::new(DEFAULT_AGENT_ID)?;
            manager.revoke(&secret_id, &caller)?;
            println!("revoked");
        }
        Command::Status { name } => {
            let manager = manager_for_root(&cli.root)?;
            let pending = manager.pending_store.load_all()?;
            let status = pending
                .into_iter()
                .find(|request| request.secret_name.as_str() == name)
                .map(|request| request.status)
                .unwrap_or(crate::types::RequestStatus::Fulfilled);
            println!("{}", serde_json::to_string(&status)?);
        }
        Command::Verify => {
            let manager = manager_for_root(&cli.root)?;
            TtlReaper::reap(&manager.agent_backend, &manager.metadata_store, &manager.audit_log)?;
            println!("ok");
        }
    }
    Ok(0)
}

fn init_layout(root: &Path) -> Result<()> {
    fs::create_dir_all(root.join("store"))?;
    fs::create_dir_all(root.join("meta"))?;
    if !root.join("pending.json").exists() {
        fs::write(root.join("pending.json"), "[]")?;
    }
    if !root.join("audit.jsonl").exists() {
        fs::write(root.join("audit.jsonl"), "")?;
    }
    Ok(())
}

fn manager_for_root(root: &Path) -> Result<SecretsManager> {
    init_layout(root)?;
    let agent_backend = AgentBackend::new(root.join("store"))?;
    let human_backend = HumanBackend::new();
    let metadata_store = MetadataStore::new(root.join("meta"))?;
    let pending_store = PendingRequestStore::new(root.join("pending.json"))?;
    let audit_log = AuditLog::new(root.join("audit.jsonl"))?;
    Ok(SecretsManager::new(
        agent_backend,
        human_backend,
        metadata_store,
        pending_store,
        audit_log,
    ))
}

#[allow(dead_code)]
fn ttl_seconds(ttl: Duration) -> i64 {
    ttl.num_seconds().max(DEFAULT_TTL_SECONDS)
}
