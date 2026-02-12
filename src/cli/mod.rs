use std::{collections::HashSet, fs, io::Read, path::PathBuf};

use chrono::Duration;
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand::RngCore;
use secrecy::ExposeSecret;

use crate::{
    agent::{backend::AgentBackend, meta::MetadataStore},
    audit::AuditLog,
    error::Result,
    fs_secure::{create_private_file_if_missing, ensure_private_dir, write_private_file_atomic},
    human::{backend::HumanBackend, pending::PendingRequestStore},
    manager::{SecretsManager, SetSecretOptions},
    paths::SecretsPaths,
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
        /// Inline secret value (less secure than stdin).
        #[arg(long)]
        value: Option<String>,
        /// Read secret value from stdin.
        #[arg(long)]
        stdin: bool,
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
    /// Approves a pending request by id.
    Approve {
        /// Request UUID.
        request_id: String,
    },
    /// Denies a pending request by id.
    Deny {
        /// Request UUID.
        request_id: String,
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
    let paths = SecretsPaths::new(&cli.root);
    match cli.command {
        Command::Init => {
            init_layout(&paths)?;
            println!("initialized");
        }
        Command::Set {
            name,
            generate,
            value,
            stdin,
            ttl,
        } => {
            let manager = manager_for_paths(&paths)?;
            let secret_id = SecretId::new(&name)?;
            let creator = AgentId::new(DEFAULT_AGENT_ID)?;
            let identity = load_or_create_default_identity(&paths)?;
            let recipient = identity.to_public().to_string();
            let mut recipients = HashSet::new();
            recipients.insert(creator.clone());
            let value = SecretValue::new(resolve_secret_input(generate, value, stdin)?);
            manager.set(
                secret_id,
                value,
                SetSecretOptions {
                    owner: Owner::Agent,
                    ttl: Duration::days(ttl),
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
            let manager = manager_for_paths(&paths)?;
            let secret_id = SecretId::new(&name)?;
            let caller = AgentId::new(DEFAULT_AGENT_ID)?;
            let identity = load_or_create_default_identity(&paths)?;
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
            let manager = manager_for_paths(&paths)?;
            let secret_id = SecretId::new(&name)?;
            let requester = AgentId::new(DEFAULT_AGENT_ID)?;
            let signing_key = load_or_create_default_signing_key(&paths)?;
            manager.request(
                secret_id,
                requester,
                reason,
                Duration::days(1),
                &signing_key,
            )?;
            println!("pending");
        }
        Command::Approve { request_id } => {
            let manager = manager_for_paths(&paths)?;
            let request_id = request_id
                .parse::<uuid::Uuid>()
                .map_err(|error| crate::error::GlovesError::InvalidInput(error.to_string()))?;
            manager.approve_request(request_id)?;
            println!("approved");
        }
        Command::Deny { request_id } => {
            let manager = manager_for_paths(&paths)?;
            let request_id = request_id
                .parse::<uuid::Uuid>()
                .map_err(|error| crate::error::GlovesError::InvalidInput(error.to_string()))?;
            manager.deny_request(request_id)?;
            println!("denied");
        }
        Command::List => {
            let manager = manager_for_paths(&paths)?;
            println!("{}", serde_json::to_string_pretty(&manager.list_all()?)?);
        }
        Command::Revoke { name } => {
            let manager = manager_for_paths(&paths)?;
            let secret_id = SecretId::new(&name)?;
            let caller = AgentId::new(DEFAULT_AGENT_ID)?;
            manager.revoke(&secret_id, &caller)?;
            println!("revoked");
        }
        Command::Status { name } => {
            let manager = manager_for_paths(&paths)?;
            let pending = manager.pending_store.load_all()?;
            let status = pending
                .into_iter()
                .find(|request| request.secret_name.as_str() == name)
                .map(|request| request.status)
                .unwrap_or(crate::types::RequestStatus::Fulfilled);
            println!("{}", serde_json::to_string(&status)?);
        }
        Command::Verify => {
            let manager = manager_for_paths(&paths)?;
            TtlReaper::reap(
                &manager.agent_backend,
                &manager.metadata_store,
                &manager.audit_log,
            )?;
            println!("ok");
        }
    }
    Ok(0)
}

fn init_layout(paths: &SecretsPaths) -> Result<()> {
    ensure_private_dir(paths.root())?;
    ensure_private_dir(&paths.store_dir())?;
    ensure_private_dir(&paths.metadata_dir())?;
    create_private_file_if_missing(&paths.pending_file(), b"[]")?;
    create_private_file_if_missing(&paths.audit_file(), b"")?;
    Ok(())
}

fn manager_for_paths(paths: &SecretsPaths) -> Result<SecretsManager> {
    init_layout(paths)?;
    let agent_backend = AgentBackend::new(paths.store_dir())?;
    let human_backend = HumanBackend::new();
    let metadata_store = MetadataStore::new(paths.metadata_dir())?;
    let pending_store = PendingRequestStore::new(paths.pending_file())?;
    let audit_log = AuditLog::new(paths.audit_file())?;
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

fn load_or_create_default_identity(paths: &SecretsPaths) -> Result<age::x25519::Identity> {
    let path = paths.default_identity_file();
    if path.exists() {
        let identity = fs::read_to_string(&path)?
            .trim()
            .parse::<age::x25519::Identity>()
            .map_err(|error| crate::error::GlovesError::Crypto(error.to_string()))?;
        return Ok(identity);
    }

    let identity = age::x25519::Identity::generate();
    let identity_secret = identity.to_string();
    write_private_file_atomic(&path, identity_secret.expose_secret().as_bytes())?;
    Ok(identity)
}

fn load_or_create_default_signing_key(paths: &SecretsPaths) -> Result<SigningKey> {
    let path = paths.default_signing_key_file();
    if path.exists() {
        let bytes = fs::read(&path)?;
        let key_bytes: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            crate::error::GlovesError::InvalidInput("invalid signing key".to_owned())
        })?;
        return Ok(SigningKey::from_bytes(&key_bytes));
    }

    let mut key_bytes = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    let key = SigningKey::from_bytes(&key_bytes);
    write_private_file_atomic(&path, &key.to_bytes())?;
    Ok(key)
}

fn resolve_secret_input(generate: bool, value: Option<String>, stdin: bool) -> Result<Vec<u8>> {
    if generate {
        if value.is_some() || stdin {
            return Err(crate::error::GlovesError::InvalidInput(
                "--generate cannot be combined with --value/--stdin".to_owned(),
            ));
        }
        return Ok(uuid::Uuid::new_v4().to_string().into_bytes());
    }

    match (value, stdin) {
        (Some(input), false) => {
            if input.is_empty() {
                return Err(crate::error::GlovesError::InvalidInput(
                    "secret value cannot be empty".to_owned(),
                ));
            }
            Ok(input.into_bytes())
        }
        (None, true) => {
            let mut bytes = Vec::new();
            std::io::stdin().read_to_end(&mut bytes)?;
            while bytes.last().copied() == Some(b'\n') || bytes.last().copied() == Some(b'\r') {
                bytes.pop();
            }
            if bytes.is_empty() {
                return Err(crate::error::GlovesError::InvalidInput(
                    "stdin secret is empty".to_owned(),
                ));
            }
            Ok(bytes)
        }
        _ => Err(crate::error::GlovesError::InvalidInput(
            "choose one input source: --generate, --value, or --stdin".to_owned(),
        )),
    }
}

#[cfg(test)]
mod unit_tests {
    use super::{
        load_or_create_default_identity, load_or_create_default_signing_key, resolve_secret_input,
        ttl_seconds,
    };
    use crate::error::GlovesError;
    use crate::paths::SecretsPaths;
    use chrono::Duration;

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
    fn load_or_create_default_identity_rejects_invalid_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        std::fs::write(temp_dir.path().join("default-agent.agekey"), "invalid").unwrap();
        let paths = SecretsPaths::new(temp_dir.path());
        assert!(load_or_create_default_identity(&paths).is_err());
    }

    #[test]
    fn load_or_create_default_signing_key_rejects_invalid_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        std::fs::write(temp_dir.path().join("default-agent.signing.key"), [1_u8; 8]).unwrap();
        let paths = SecretsPaths::new(temp_dir.path());
        assert!(matches!(
            load_or_create_default_signing_key(&paths),
            Err(GlovesError::InvalidInput(_))
        ));
    }
}
