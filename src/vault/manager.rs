use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    thread,
    time::{Duration as StdDuration, Instant},
};

use chrono::{Duration, Utc};

use crate::{
    audit::{AuditEvent, AuditLog},
    error::{GlovesError, Result},
    fs_secure::{create_private_file_if_missing, ensure_private_dir, write_private_file_atomic},
    paths::SecretsPaths,
    types::{AgentId, Owner},
};

use super::{
    config::VaultConfigFile,
    gocryptfs::{FsEncryptionDriver, InitRequest, MountRequest},
    session::{load_sessions, save_sessions, VaultSession},
    types::{VaultListEntry, VaultSecretProvider, VaultStatusEntry},
    validation::{validate_requested_file_path, validate_ttl_minutes, validate_vault_name},
};

const MOUNT_READY_TIMEOUT: StdDuration = StdDuration::from_secs(3);
const MOUNT_READY_POLL_INTERVAL: StdDuration = StdDuration::from_millis(25);

/// Coordinator for vault lifecycle operations.
pub struct VaultManager<D, P>
where
    D: FsEncryptionDriver,
    P: VaultSecretProvider,
{
    paths: SecretsPaths,
    driver: D,
    secret_provider: P,
    audit_log: AuditLog,
}

impl<D, P> VaultManager<D, P>
where
    D: FsEncryptionDriver,
    P: VaultSecretProvider,
{
    /// Constructs a vault manager.
    pub fn new(paths: SecretsPaths, driver: D, secret_provider: P, audit_log: AuditLog) -> Self {
        Self {
            paths,
            driver,
            secret_provider,
            audit_log,
        }
    }

    /// Creates and initializes a new vault.
    pub fn init(&self, vault_name: &str, owner: Owner) -> Result<VaultConfigFile> {
        validate_vault_name(vault_name)?;
        self.ensure_layout()?;

        let config_path = self.paths.vault_config_file(vault_name);
        if config_path.exists() {
            return Err(GlovesError::AlreadyExists);
        }

        let secret_name = format!("vault/{vault_name}");
        if owner == Owner::Agent {
            self.secret_provider.ensure_agent_secret(&secret_name)?;
        }

        let config = VaultConfigFile::new(
            vault_name.to_owned(),
            owner.clone(),
            self.paths.vault_cipher_dir(vault_name),
            self.paths.vault_mountpoint(vault_name),
            secret_name,
            Utc::now(),
        );

        self.driver.init(&InitRequest {
            cipher_dir: config.vault.cipher_dir.clone(),
            extpass_command: extpass_command(
                &self.paths,
                &config.vault.owner,
                &config.vault.secret_name,
            ),
        })?;

        let encoded = toml::to_string_pretty(&config).map_err(|error| {
            GlovesError::InvalidInput(format!("failed to serialize vault config: {error}"))
        })?;
        write_private_file_atomic(&config_path, encoded.as_bytes())?;
        self.audit_log.log(AuditEvent::VaultCreated {
            vault: vault_name.to_owned(),
            owner,
        })?;
        Ok(config)
    }

    /// Mounts a vault and records a TTL session.
    pub fn mount(
        &self,
        vault_name: &str,
        ttl: Duration,
        mountpoint_override: Option<PathBuf>,
        mounted_by: AgentId,
    ) -> Result<VaultSession> {
        validate_vault_name(vault_name)?;
        self.ensure_layout()?;

        let config = self.load_config(vault_name)?;
        let ttl_minutes = validate_ttl_minutes(ttl, config.vault.max_ttl_minutes)?;
        let mountpoint =
            mountpoint_override.unwrap_or_else(|| config.vault.default_mountpoint.clone());

        let sessions_path = self.paths.vault_sessions_file();
        let mut sessions = load_sessions(&sessions_path)?;
        if let Some(index) = sessions
            .iter()
            .position(|session| session.vault_name == vault_name)
        {
            let mut existing = sessions.remove(index);
            let existing_mounted = self.driver.is_mounted(&existing.mountpoint)?;
            if existing.mountpoint == mountpoint && existing_mounted {
                existing.expires_at = Utc::now() + ttl;
                existing.mounted_by = mounted_by.clone();
                sessions.push(existing.clone());
                save_sessions(&sessions_path, &sessions)?;
                self.audit_log.log(AuditEvent::VaultMounted {
                    vault: vault_name.to_owned(),
                    agent: mounted_by,
                    ttl_minutes,
                })?;
                return Ok(existing);
            }
            if existing_mounted {
                self.driver.unmount(&existing.mountpoint)?;
            }
        }

        let idle_timeout = Duration::minutes(config.vault.idle_timeout_minutes as i64)
            .to_std()
            .map_err(|_| GlovesError::InvalidInput("invalid idle timeout".to_owned()))?;
        let pid = self.driver.mount(&MountRequest {
            cipher_dir: config.vault.cipher_dir.clone(),
            mount_point: mountpoint.clone(),
            extpass_command: extpass_command(
                &self.paths,
                &config.vault.owner,
                &config.vault.secret_name,
            ),
            idle_timeout: Some(idle_timeout),
        })?;
        self.wait_for_mount_readiness(&mountpoint)?;
        let now = Utc::now();
        let session = VaultSession {
            vault_name: vault_name.to_owned(),
            mountpoint,
            mounted_at: now,
            expires_at: now + ttl,
            pid,
            mounted_by: mounted_by.clone(),
        };
        sessions.retain(|item| item.vault_name != vault_name);
        sessions.push(session.clone());
        save_sessions(&sessions_path, &sessions)?;
        self.audit_log.log(AuditEvent::VaultMounted {
            vault: vault_name.to_owned(),
            agent: mounted_by,
            ttl_minutes,
        })?;
        Ok(session)
    }

    /// Unmounts a vault and removes the active session.
    pub fn unmount(&self, vault_name: &str, reason: &str, mounted_by: AgentId) -> Result<()> {
        validate_vault_name(vault_name)?;
        self.ensure_layout()?;

        let sessions_path = self.paths.vault_sessions_file();
        let mut sessions = load_sessions(&sessions_path)?;
        let index = sessions
            .iter()
            .position(|session| session.vault_name == vault_name)
            .ok_or(GlovesError::NotFound)?;
        let session = sessions.remove(index);

        if self.driver.is_mounted(&session.mountpoint)? {
            self.driver.unmount(&session.mountpoint)?;
        }

        save_sessions(&sessions_path, &sessions)?;
        self.audit_log.log(AuditEvent::VaultUnmounted {
            vault: vault_name.to_owned(),
            reason: reason.to_owned(),
            agent: mounted_by,
        })?;
        Ok(())
    }

    /// Builds a trusted-agent handoff prompt for one vault file.
    pub fn ask_file_prompt(
        &self,
        vault_name: &str,
        requested_file: &str,
        requester: AgentId,
        trusted_agent: AgentId,
        reason: Option<String>,
    ) -> Result<String> {
        validate_vault_name(vault_name)?;
        validate_requested_file_path(requested_file)?;
        self.ensure_layout()?;

        let now = Utc::now();
        let mut has_access = false;
        for session in load_sessions(&self.paths.vault_sessions_file())? {
            if session.vault_name != vault_name {
                continue;
            }
            if session.mounted_by != trusted_agent {
                continue;
            }
            if session.is_expired(now) {
                continue;
            }
            if self.driver.is_mounted(&session.mountpoint)? {
                has_access = true;
                break;
            }
        }
        if !has_access {
            return Err(GlovesError::Forbidden);
        }

        let mut prompt = format!(
            "Agent handoff request\nVault: {vault_name}\nRequester: {requester}\nTrusted agent: {trusted_agent}\nRequested file: {requested_file}\nTrust statement: {requester} trusts {trusted_agent} (with access) to retrieve and return the requested file."
        );
        if let Some(reason_text) = reason {
            prompt.push_str(&format!("\nReason: {reason_text}"));
        }
        self.audit_log.log(AuditEvent::VaultHandoffPromptIssued {
            vault: vault_name.to_owned(),
            requester: requester.clone(),
            trusted_agent: trusted_agent.clone(),
            requested_file: requested_file.to_owned(),
        })?;
        Ok(prompt)
    }

    /// Returns runtime status for all configured vaults.
    pub fn status(&self) -> Result<Vec<VaultStatusEntry>> {
        self.ensure_layout()?;
        let now = Utc::now();
        let configs = self.load_all_configs()?;
        let sessions_by_name = load_sessions(&self.paths.vault_sessions_file())?
            .into_iter()
            .map(|session| (session.vault_name.clone(), session))
            .collect::<HashMap<_, _>>();

        let mut entries = Vec::with_capacity(configs.len());
        for config in configs {
            if let Some(session) = sessions_by_name.get(&config.vault.name) {
                let mounted = self.driver.is_mounted(&session.mountpoint)?;
                let remaining_seconds = if mounted {
                    Some((session.expires_at - now).num_seconds().max(0))
                } else {
                    None
                };
                entries.push(VaultStatusEntry {
                    name: config.vault.name.clone(),
                    owner: config.vault.owner.clone(),
                    mounted,
                    mountpoint: mounted.then(|| session.mountpoint.clone()),
                    remaining_seconds,
                });
            } else {
                entries.push(VaultStatusEntry {
                    name: config.vault.name.clone(),
                    owner: config.vault.owner.clone(),
                    mounted: false,
                    mountpoint: None,
                    remaining_seconds: None,
                });
            }
        }
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(entries)
    }

    /// Lists all configured vaults.
    pub fn list(&self) -> Result<Vec<VaultListEntry>> {
        self.ensure_layout()?;
        let mut entries = self
            .load_all_configs()?
            .into_iter()
            .map(|config| VaultListEntry {
                name: config.vault.name,
                owner: config.vault.owner,
                cipher_dir: config.vault.cipher_dir,
                created_at: config.vault.created_at,
            })
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(entries)
    }

    fn wait_for_mount_readiness(&self, mountpoint: &Path) -> Result<()> {
        let deadline = Instant::now() + MOUNT_READY_TIMEOUT;
        loop {
            if self.driver.is_mounted(mountpoint)? {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(GlovesError::Crypto(format!(
                    "vault mount did not become ready: {}",
                    mountpoint.display()
                )));
            }
            thread::sleep(MOUNT_READY_POLL_INTERVAL);
        }
    }

    fn ensure_layout(&self) -> Result<()> {
        ensure_private_dir(self.paths.root())?;
        ensure_private_dir(&self.paths.vaults_dir())?;
        ensure_private_dir(&self.paths.encrypted_dir())?;
        ensure_private_dir(&self.paths.mounts_dir())?;
        create_private_file_if_missing(&self.paths.vault_sessions_file(), b"[]")?;
        Ok(())
    }

    fn load_config(&self, vault_name: &str) -> Result<VaultConfigFile> {
        let path = self.paths.vault_config_file(vault_name);
        if !path.exists() {
            return Err(GlovesError::NotFound);
        }
        let raw = fs::read_to_string(path)?;
        toml::from_str::<VaultConfigFile>(&raw)
            .map_err(|error| GlovesError::InvalidInput(format!("invalid vault config: {error}")))
    }

    fn load_all_configs(&self) -> Result<Vec<VaultConfigFile>> {
        let mut entries = Vec::new();
        for entry in fs::read_dir(self.paths.vaults_dir())? {
            let path = entry?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("toml") {
                continue;
            }
            let raw = fs::read_to_string(path)?;
            entries.push(toml::from_str::<VaultConfigFile>(&raw).map_err(|error| {
                GlovesError::InvalidInput(format!("invalid vault config: {error}"))
            })?);
        }
        Ok(entries)
    }
}

fn extpass_command(paths: &SecretsPaths, owner: &Owner, secret_name: &str) -> String {
    match owner {
        Owner::Agent => format!(
            "gloves --root {} get {}",
            shell_quote(&paths.root().display().to_string()),
            shell_quote(secret_name)
        ),
        Owner::Human => format!("pass show {}", shell_quote(secret_name)),
    }
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_owned();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}
