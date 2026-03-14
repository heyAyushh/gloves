use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use serde::{Deserialize, Serialize};

use gloves_core::error::{GlovesError, Result};
use gloves_core::types::{AgentId, SecretId};

const CONFIG_VERSION_V1: u32 = 1;
const CONFIG_VERSION_V2: u32 = 2;
const DEFAULT_ROOT: &str = ".openclaw/secrets";
const DEFAULT_DAEMON_BIND: &str = "127.0.0.1:7788";
const DEFAULT_DAEMON_IO_TIMEOUT_SECONDS: u64 = 5;
const DEFAULT_DAEMON_REQUEST_LIMIT_BYTES: usize = 16 * 1024;
const DEFAULT_AGENT_ID: &str = "default-agent";
/// Built-in default secret and request TTL in days when config does not override it.
pub const DEFAULT_SECRET_TTL_DAYS: i64 = 30;
const DEFAULT_VAULT_MOUNT_TTL: &str = "1h";
const DEFAULT_VAULT_SECRET_TTL_DAYS: i64 = 365;
const DEFAULT_VAULT_SECRET_LENGTH_BYTES: usize = 64;
const URL_SCHEME_HTTP_PREFIX: &str = "http://";
const URL_SCHEME_HTTPS_PREFIX: &str = "https://";

/// Default bootstrap config file name.
pub const CONFIG_FILE_NAME: &str = ".gloves.toml";
/// Supported bootstrap config schema version.
pub const CONFIG_SCHEMA_VERSION: u32 = CONFIG_VERSION_V2;

/// Source used to select the effective config file.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConfigSource {
    /// Selected via `--config` CLI flag.
    Flag,
    /// Selected via `GLOVES_CONFIG` environment variable.
    Env,
    /// Selected by walking from the current working directory to root.
    Discovered,
    /// No config file selected.
    None,
}

/// Resolved config selection before parsing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigSelection {
    /// Source used for selection.
    pub source: ConfigSource,
    /// Selected path when a config file was found.
    pub path: Option<PathBuf>,
}

/// Allowed operations for one agent's private-path visibility.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum PathOperation {
    /// Read file contents.
    Read,
    /// Write or modify files.
    Write,
    /// List directory entries.
    List,
    /// Mount encrypted volumes.
    Mount,
}

/// Allowed operations for one agent's secret ACL.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum SecretAclOperation {
    /// Read secret values.
    Read,
    /// Create/update secrets.
    Write,
    /// List visible secrets.
    List,
    /// Revoke secrets.
    Revoke,
    /// Create human access requests.
    Request,
    /// Read request status for a secret.
    Status,
    /// Approve pending requests.
    Approve,
    /// Deny pending requests.
    Deny,
}

/// Runtime mode for vault command availability and dependency enforcement.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VaultMode {
    /// Vault commands run when dependencies are available.
    Auto,
    /// Vault dependencies are mandatory and validated up front.
    Required,
    /// Vault commands are blocked intentionally.
    Disabled,
}

/// Raw TOML shape for one `.gloves.toml` file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GlovesConfigFile {
    /// Schema version.
    pub version: u32,
    /// Optional path overrides.
    #[serde(default)]
    pub paths: ConfigPathsFile,
    /// Private path aliases and values.
    #[serde(default)]
    pub private_paths: BTreeMap<String, String>,
    /// Daemon defaults.
    #[serde(default)]
    pub daemon: DaemonConfigFile,
    /// Vault runtime mode defaults.
    #[serde(default)]
    pub vault: VaultConfigFile,
    /// Global defaults.
    #[serde(default)]
    pub defaults: DefaultsConfigFile,
    /// Integration declarations.
    #[serde(default)]
    pub integrations: BTreeMap<String, IntegrationConfigFile>,
    /// Agent path visibility policies.
    #[serde(default)]
    pub agents: BTreeMap<String, AgentAccessFile>,
    /// Secret ACL policies.
    #[serde(default)]
    pub secrets: SecretsConfigFile,
}

/// Raw `[paths]` section from TOML.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConfigPathsFile {
    /// Runtime root override.
    pub root: Option<String>,
}

/// Raw `[daemon]` section from TOML.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfigFile {
    /// Bind address for daemon mode.
    pub bind: Option<String>,
    /// Read/write timeout in seconds.
    pub io_timeout_seconds: Option<u64>,
    /// Maximum request size in bytes.
    pub request_limit_bytes: Option<usize>,
}

/// Raw `[vault]` section from TOML.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VaultConfigFile {
    /// Vault runtime mode.
    pub mode: Option<VaultMode>,
    /// Named vault mount locations.
    #[serde(default)]
    pub mounts: BTreeMap<String, String>,
}

/// Raw `[defaults]` section from TOML.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DefaultsConfigFile {
    /// Default agent identifier.
    pub agent_id: Option<String>,
    /// Default secret TTL in days.
    pub secret_ttl_days: Option<i64>,
    /// Default vault mount TTL literal.
    pub vault_mount_ttl: Option<String>,
    /// Default vault secret TTL in days.
    pub vault_secret_ttl_days: Option<i64>,
    /// Default generated vault secret length in bytes.
    pub vault_secret_length_bytes: Option<usize>,
}

/// Raw `[secrets]` section from TOML.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecretsConfigFile {
    /// Per-agent ACL rules for secret operations.
    #[serde(default)]
    pub acl: BTreeMap<String, SecretAccessFile>,
    /// Per-command pipe safety policies.
    #[serde(default)]
    pub pipe: SecretPipePoliciesFile,
}

/// Raw per-agent secret ACL from TOML.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecretAccessFile {
    /// Secret ref patterns (`*`, `foo/*`, or exact secret id).
    #[serde(default, alias = "paths")]
    pub refs: Vec<String>,
    /// Allowed secret operations.
    #[serde(default)]
    pub operations: Vec<SecretAclOperation>,
}

/// Raw per-command pipe policy set from TOML.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecretPipePoliciesFile {
    /// Command policy entries keyed by executable name.
    #[serde(default)]
    pub commands: BTreeMap<String, SecretPipeCommandPolicyFile>,
}

/// Raw pipe policy for one command from TOML.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecretPipeCommandPolicyFile {
    /// Require at least one URL argument and enforce allowed URL prefixes.
    #[serde(default)]
    pub require_url: bool,
    /// Allowed URL prefixes for this command.
    #[serde(default)]
    pub url_prefixes: Vec<String>,
}

/// Raw per-agent access policy from TOML.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentAccessFile {
    /// Alias names from `[private_paths]` visible to this agent.
    #[serde(default)]
    pub paths: Vec<String>,
    /// Allowed operations.
    #[serde(default)]
    pub operations: Vec<PathOperation>,
    /// Secret ref access policy for this agent.
    #[serde(default)]
    pub secrets: Option<AgentSecretsAccessFile>,
    /// Vault mount access policy for this agent.
    #[serde(default)]
    pub vault: Option<AgentVaultAccessFile>,
}

/// Raw per-agent secret access policy from TOML.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentSecretsAccessFile {
    /// Secret ref patterns (`*`, `foo/*`, or exact secret id).
    #[serde(default, alias = "paths")]
    pub refs: Vec<String>,
    /// Allowed secret operations.
    #[serde(default)]
    pub operations: Vec<SecretAclOperation>,
}

/// Raw per-agent vault access policy from TOML.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentVaultAccessFile {
    /// Named vault mounts visible to this agent.
    #[serde(default)]
    pub mounts: Vec<String>,
    /// Allowed mount operations.
    #[serde(default)]
    pub operations: Vec<PathOperation>,
}

/// Raw integration entry from TOML.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IntegrationConfigFile {
    /// Owning or default operator agent for this integration.
    pub agent: Option<String>,
    /// Optional account/profile names. Omitted implies `default`.
    #[serde(default)]
    pub profiles: Vec<String>,
    /// Optional secret slots inferred under each profile.
    #[serde(default)]
    pub slots: Vec<String>,
}

/// Effective daemon config after defaults and validation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonBootstrapConfig {
    /// Bind address for daemon mode.
    pub bind: String,
    /// Read/write timeout in seconds.
    pub io_timeout_seconds: u64,
    /// Maximum request size in bytes.
    pub request_limit_bytes: usize,
}

/// Effective vault mode after defaults and validation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultBootstrapConfig {
    /// Effective vault runtime mode.
    pub mode: VaultMode,
    /// Named vault mount locations.
    pub mounts: BTreeMap<String, PathBuf>,
}

/// Effective default values after defaults and validation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DefaultBootstrapConfig {
    /// Default agent identifier.
    pub agent_id: AgentId,
    /// Default secret TTL in days.
    pub secret_ttl_days: i64,
    /// Default vault mount TTL literal.
    pub vault_mount_ttl: String,
    /// Default vault secret TTL in days.
    pub vault_secret_ttl_days: i64,
    /// Default generated vault secret length in bytes.
    pub vault_secret_length_bytes: usize,
}

/// Effective access policy for one configured agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentAccessPolicy {
    /// Alias names from `[private_paths]` visible to this agent.
    pub path_aliases: Vec<String>,
    /// Allowed operations.
    pub operations: Vec<PathOperation>,
}

/// Effective secret ACL policy for one configured agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretAccessPolicy {
    /// Secret ref patterns (`*`, `foo/*`, or exact secret id).
    pub refs: Vec<String>,
    /// Allowed secret operations.
    pub operations: Vec<SecretAclOperation>,
}

/// Effective vault access policy for one configured agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentVaultAccessPolicy {
    /// Named mounts visible to this agent.
    pub mount_names: Vec<String>,
    /// Allowed operations.
    pub operations: Vec<PathOperation>,
}

/// Effective integration config after defaults and validation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrationConfig {
    /// Integration identifier.
    pub name: String,
    /// Owning or default agent for this integration.
    pub agent: AgentId,
    /// Declared profiles. Empty means `default`.
    pub profiles: Vec<String>,
    /// Declared secret slots under each profile.
    pub slots: Vec<String>,
}

/// Effective pipe policy for one command.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretPipeCommandPolicy {
    /// Require URL enforcement for this command.
    pub require_url: bool,
    /// Allowed URL prefixes.
    pub url_prefixes: Vec<String>,
}

/// Effective and validated `.gloves.toml` configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GlovesConfig {
    /// Absolute config file path.
    pub source_path: PathBuf,
    /// Effective runtime root.
    pub root: PathBuf,
    /// Private path aliases resolved to absolute paths.
    pub private_paths: BTreeMap<String, PathBuf>,
    /// Effective daemon defaults.
    pub daemon: DaemonBootstrapConfig,
    /// Effective vault mode.
    pub vault: VaultBootstrapConfig,
    /// Effective global defaults.
    pub defaults: DefaultBootstrapConfig,
    /// Agent access policies.
    pub agents: BTreeMap<String, AgentAccessPolicy>,
    /// Agent secret ACL policies.
    pub secret_access: BTreeMap<String, SecretAccessPolicy>,
    /// Agent vault access policies.
    pub agent_vault_access: BTreeMap<String, AgentVaultAccessPolicy>,
    /// Configured integrations.
    pub integrations: BTreeMap<String, IntegrationConfig>,
    /// Per-command secret pipe policies.
    pub secret_pipe_commands: BTreeMap<String, SecretPipeCommandPolicy>,
}

/// Resolved path visibility entry for one agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolvedAgentPathAccess {
    /// Alias from `[private_paths]`.
    pub alias: String,
    /// Resolved path.
    pub path: PathBuf,
    /// Allowed operations for this agent.
    pub operations: Vec<PathOperation>,
}

impl GlovesConfig {
    /// Loads and validates a config file from disk.
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self> {
        let cwd = std::env::current_dir()?;
        let absolute_path = absolutize_path(path.as_ref(), &cwd);
        if !absolute_path.exists() {
            return Err(GlovesError::InvalidInput(format!(
                "config file does not exist: {}",
                absolute_path.display()
            )));
        }

        let raw = fs::read_to_string(&absolute_path)?;
        let parsed = toml::from_str::<GlovesConfigFile>(&raw)
            .map_err(|error| GlovesError::InvalidInput(format!("invalid config TOML: {error}")))?;
        validate_config_file_permissions(&absolute_path, !parsed.private_paths.is_empty())?;
        build_config(parsed, &absolute_path)
    }

    /// Parses and validates config from TOML text.
    pub fn parse_from_str(raw: &str, source_path: impl AsRef<Path>) -> Result<Self> {
        let parsed = toml::from_str::<GlovesConfigFile>(raw)
            .map_err(|error| GlovesError::InvalidInput(format!("invalid config TOML: {error}")))?;
        build_config(parsed, source_path.as_ref())
    }

    /// Returns resolved private-path visibility for one agent.
    pub fn agent_paths(&self, agent: &AgentId) -> Result<Vec<ResolvedAgentPathAccess>> {
        let policy = self
            .agents
            .get(agent.as_str())
            .ok_or(GlovesError::NotFound)?;

        let mut entries = Vec::with_capacity(policy.path_aliases.len());
        for alias in &policy.path_aliases {
            let path = self.private_paths.get(alias).ok_or_else(|| {
                GlovesError::InvalidInput(format!(
                    "agent '{}' references unknown private path alias '{}'",
                    agent.as_str(),
                    alias
                ))
            })?;
            entries.push(ResolvedAgentPathAccess {
                alias: alias.clone(),
                path: path.clone(),
                operations: policy.operations.clone(),
            });
        }
        Ok(entries)
    }

    /// Returns `true` when the config enables per-agent secret ACLs.
    pub fn has_secret_acl(&self) -> bool {
        !self.secret_access.is_empty()
    }

    /// Returns secret ACL policy for one agent.
    pub fn secret_access_policy(&self, agent: &AgentId) -> Option<&SecretAccessPolicy> {
        self.secret_access.get(agent.as_str())
    }

    /// Returns vault access policy for one agent.
    pub fn agent_vault_access_policy(&self, agent: &AgentId) -> Option<&AgentVaultAccessPolicy> {
        self.agent_vault_access.get(agent.as_str())
    }

    /// Returns one configured vault mount path.
    pub fn vault_mount_path(&self, mount_name: &str) -> Option<&PathBuf> {
        self.vault.mounts.get(mount_name)
    }

    /// Returns one configured integration.
    pub fn integration(&self, name: &str) -> Option<&IntegrationConfig> {
        self.integrations.get(name)
    }

    /// Returns inferred secret refs for one configured integration.
    pub fn inferred_integration_refs(&self, name: &str) -> Result<Vec<String>> {
        let integration = self.integrations.get(name).ok_or(GlovesError::NotFound)?;
        let profiles = if integration.profiles.is_empty() {
            vec!["default".to_owned()]
        } else {
            integration.profiles.clone()
        };
        if integration.slots.is_empty() {
            return Ok(Vec::new());
        }

        let mut refs = Vec::with_capacity(profiles.len() * integration.slots.len());
        for profile in profiles {
            for slot in &integration.slots {
                refs.push(format!("{name}/{profile}/{slot}"));
            }
        }
        Ok(refs)
    }

    /// Returns secret pipe policy for one executable command.
    pub fn secret_pipe_command_policy(&self, command: &str) -> Option<&SecretPipeCommandPolicy> {
        self.secret_pipe_commands.get(command)
    }
}

impl SecretAccessPolicy {
    /// Returns `true` when this policy allows an operation.
    pub fn allows_operation(&self, operation: SecretAclOperation) -> bool {
        self.operations.contains(&operation)
    }

    /// Returns `true` when this policy allows one secret name.
    pub fn allows_secret(&self, secret_name: &str) -> bool {
        self.refs
            .iter()
            .any(|pattern| secret_pattern_matches(pattern, secret_name))
    }
}

/// Resolves one config path based on precedence rules.
pub fn resolve_config_path(
    explicit_path: Option<&Path>,
    env_path: Option<&str>,
    no_config: bool,
    cwd: impl AsRef<Path>,
) -> Result<ConfigSelection> {
    if no_config {
        return Ok(ConfigSelection {
            source: ConfigSource::None,
            path: None,
        });
    }

    let cwd = cwd.as_ref();
    if let Some(path) = explicit_path {
        let candidate = absolutize_path(path, cwd);
        if !is_regular_config_candidate(&candidate) {
            return Err(GlovesError::InvalidInput(format!(
                "config file must be a regular file: {}",
                candidate.display()
            )));
        }
        return Ok(ConfigSelection {
            source: ConfigSource::Flag,
            path: Some(candidate),
        });
    }

    if let Some(value) = env_path {
        if value.trim().is_empty() {
            return Err(GlovesError::InvalidInput(
                "GLOVES_CONFIG cannot be empty".to_owned(),
            ));
        }

        let candidate = absolutize_path(Path::new(value), cwd);
        if !is_regular_config_candidate(&candidate) {
            return Err(GlovesError::InvalidInput(format!(
                "config file must be a regular file: {}",
                candidate.display()
            )));
        }
        return Ok(ConfigSelection {
            source: ConfigSource::Env,
            path: Some(candidate),
        });
    }

    if let Some(discovered) = discover_config(cwd) {
        return Ok(ConfigSelection {
            source: ConfigSource::Discovered,
            path: Some(discovered),
        });
    }

    Ok(ConfigSelection {
        source: ConfigSource::None,
        path: None,
    })
}

/// Discovers `.gloves.toml` by walking from `start_dir` to filesystem root.
pub fn discover_config(start_dir: impl AsRef<Path>) -> Option<PathBuf> {
    let mut current = start_dir.as_ref();
    loop {
        let candidate = current.join(CONFIG_FILE_NAME);
        if is_regular_config_candidate(&candidate) {
            return Some(candidate);
        }

        let parent = current.parent()?;
        current = parent;
    }
}

fn build_config(raw: GlovesConfigFile, source_path: &Path) -> Result<GlovesConfig> {
    validate_raw_config(&raw)?;

    let source_path = absolutize_path(source_path, &std::env::current_dir()?);
    let source_dir = source_path.parent().unwrap_or(Path::new("."));

    let root_literal = raw.paths.root.as_deref().unwrap_or(DEFAULT_ROOT).to_owned();
    let root = resolve_path_value(&root_literal, source_dir)?;

    let mut private_paths = BTreeMap::new();
    for (alias, value) in &raw.private_paths {
        validate_alias(alias)?;
        let resolved = resolve_path_value(value, source_dir)?;
        private_paths.insert(alias.clone(), resolved);
    }

    let daemon = resolve_daemon_config(&raw.daemon)?;
    let vault = resolve_vault_config(&raw.vault, source_dir)?;
    let defaults = resolve_default_config(&raw.defaults)?;

    let mut agents = BTreeMap::new();
    let mut agent_vault_access = BTreeMap::new();
    for (agent_name, policy) in &raw.agents {
        AgentId::new(agent_name)?;
        validate_agent_policy(agent_name, policy, &private_paths, &vault.mounts)?;
        if !policy.paths.is_empty() || !policy.operations.is_empty() {
            agents.insert(
                agent_name.clone(),
                AgentAccessPolicy {
                    path_aliases: policy.paths.clone(),
                    operations: policy.operations.clone(),
                },
            );
        }
        if let Some(vault_policy) = policy.vault.as_ref() {
            agent_vault_access.insert(
                agent_name.clone(),
                AgentVaultAccessPolicy {
                    mount_names: vault_policy.mounts.clone(),
                    operations: vault_policy.operations.clone(),
                },
            );
        }
    }

    let mut secret_access: BTreeMap<String, SecretAccessPolicy> = BTreeMap::new();
    for (agent_name, policy) in &raw.secrets.acl {
        AgentId::new(agent_name)?;
        validate_secret_access_policy(agent_name, policy)?;
        merge_secret_access_policy(
            &mut secret_access,
            agent_name,
            SecretAccessPolicy {
                refs: policy.refs.clone(),
                operations: policy.operations.clone(),
            },
        );
    }
    for (agent_name, policy) in &raw.agents {
        if let Some(secret_policy) = policy.secrets.as_ref() {
            merge_secret_access_policy(
                &mut secret_access,
                agent_name,
                SecretAccessPolicy {
                    refs: secret_policy.refs.clone(),
                    operations: secret_policy.operations.clone(),
                },
            );
        }
    }

    let mut integrations = BTreeMap::new();
    for (name, integration) in &raw.integrations {
        validate_integration_config(name, integration)?;
        let agent_literal = integration.agent.as_deref().ok_or_else(|| {
            GlovesError::InvalidInput(format!("integration '{name}' must declare an owning agent"))
        })?;
        integrations.insert(
            name.clone(),
            IntegrationConfig {
                name: name.clone(),
                agent: AgentId::new(agent_literal)?,
                profiles: normalized_integration_segments(&integration.profiles, "profiles", name)?,
                slots: normalized_integration_segments(&integration.slots, "slots", name)?,
            },
        );
    }

    let mut secret_pipe_commands = BTreeMap::new();
    for (command, policy) in &raw.secrets.pipe.commands {
        validate_secret_pipe_command_policy(command, policy)?;
        secret_pipe_commands.insert(
            command.clone(),
            SecretPipeCommandPolicy {
                require_url: policy.require_url,
                url_prefixes: policy.url_prefixes.clone(),
            },
        );
    }

    Ok(GlovesConfig {
        source_path,
        root,
        private_paths,
        daemon,
        vault,
        defaults,
        agents,
        secret_access,
        agent_vault_access,
        integrations,
        secret_pipe_commands,
    })
}

fn validate_raw_config(config: &GlovesConfigFile) -> Result<()> {
    if !matches!(config.version, CONFIG_VERSION_V1 | CONFIG_VERSION_V2) {
        return Err(GlovesError::InvalidInput(format!(
            "unsupported config version {} (expected {} or {})",
            config.version, CONFIG_VERSION_V1, CONFIG_VERSION_V2
        )));
    }

    if let Some(root) = config.paths.root.as_ref() {
        validate_path_literal(root, "paths.root")?;
    }

    for (alias, value) in &config.private_paths {
        validate_alias(alias)?;
        validate_path_literal(value, &format!("private_paths.{alias}"))?;
    }

    let _ = resolve_daemon_config(&config.daemon)?;
    let _ = resolve_vault_config(&config.vault, Path::new("."))?;
    let _ = resolve_default_config(&config.defaults)?;

    for (agent_name, policy) in &config.secrets.acl {
        AgentId::new(agent_name)?;
        validate_secret_access_policy(agent_name, policy)?;
    }
    for (agent_name, policy) in &config.agents {
        AgentId::new(agent_name)?;
        validate_agent_policy(
            agent_name,
            policy,
            &BTreeMap::<String, PathBuf>::new(),
            &config.vault.mounts,
        )?;
    }
    for (name, integration) in &config.integrations {
        validate_integration_config(name, integration)?;
    }
    for (command, policy) in &config.secrets.pipe.commands {
        validate_secret_pipe_command_policy(command, policy)?;
    }

    Ok(())
}

fn resolve_vault_config(raw: &VaultConfigFile, source_dir: &Path) -> Result<VaultBootstrapConfig> {
    let mut mounts = BTreeMap::new();
    for (mount_name, mount_path_literal) in &raw.mounts {
        validate_alias(mount_name)?;
        validate_path_literal(mount_path_literal, &format!("vault.mounts.{mount_name}"))?;
        mounts.insert(
            mount_name.clone(),
            resolve_path_value(mount_path_literal, source_dir)?,
        );
    }

    Ok(VaultBootstrapConfig {
        mode: raw.mode.unwrap_or(VaultMode::Auto),
        mounts,
    })
}

fn resolve_daemon_config(raw: &DaemonConfigFile) -> Result<DaemonBootstrapConfig> {
    let bind = raw
        .bind
        .clone()
        .unwrap_or_else(|| DEFAULT_DAEMON_BIND.to_owned());
    let bind_addr = bind.parse::<std::net::SocketAddr>().map_err(|error| {
        GlovesError::InvalidInput(format!("invalid daemon bind address: {error}"))
    })?;
    if bind_addr.port() == 0 {
        return Err(GlovesError::InvalidInput(
            "daemon bind port must be non-zero".to_owned(),
        ));
    }
    if !bind_addr.ip().is_loopback() {
        return Err(GlovesError::InvalidInput(
            "daemon bind address must be loopback".to_owned(),
        ));
    }

    let io_timeout_seconds = raw
        .io_timeout_seconds
        .unwrap_or(DEFAULT_DAEMON_IO_TIMEOUT_SECONDS);
    if io_timeout_seconds == 0 {
        return Err(GlovesError::InvalidInput(
            "daemon io_timeout_seconds must be greater than zero".to_owned(),
        ));
    }

    let request_limit_bytes = raw
        .request_limit_bytes
        .unwrap_or(DEFAULT_DAEMON_REQUEST_LIMIT_BYTES);
    if request_limit_bytes == 0 {
        return Err(GlovesError::InvalidInput(
            "daemon request_limit_bytes must be greater than zero".to_owned(),
        ));
    }

    Ok(DaemonBootstrapConfig {
        bind,
        io_timeout_seconds,
        request_limit_bytes,
    })
}

fn merge_secret_access_policy(
    policies: &mut BTreeMap<String, SecretAccessPolicy>,
    agent_name: &str,
    next_policy: SecretAccessPolicy,
) {
    let entry = policies
        .entry(agent_name.to_owned())
        .or_insert_with(|| SecretAccessPolicy {
            refs: Vec::new(),
            operations: Vec::new(),
        });
    entry.refs.extend(next_policy.refs);
    entry.operations.extend(next_policy.operations);
    dedup_preserving_order(&mut entry.refs);
    dedup_preserving_order(&mut entry.operations);
}

fn dedup_preserving_order<T>(values: &mut Vec<T>)
where
    T: Clone + Ord,
{
    let mut seen = BTreeSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

fn resolve_default_config(raw: &DefaultsConfigFile) -> Result<DefaultBootstrapConfig> {
    let agent_literal = raw
        .agent_id
        .as_deref()
        .unwrap_or(DEFAULT_AGENT_ID)
        .to_owned();
    let agent_id = AgentId::new(&agent_literal)?;

    let secret_ttl_days = raw.secret_ttl_days.unwrap_or(DEFAULT_SECRET_TTL_DAYS);
    if secret_ttl_days <= 0 {
        return Err(GlovesError::InvalidInput(
            "defaults.secret_ttl_days must be greater than zero".to_owned(),
        ));
    }

    let vault_mount_ttl = raw
        .vault_mount_ttl
        .as_deref()
        .unwrap_or(DEFAULT_VAULT_MOUNT_TTL)
        .to_owned();
    validate_duration_literal(&vault_mount_ttl, "defaults.vault_mount_ttl")?;

    let vault_secret_ttl_days = raw
        .vault_secret_ttl_days
        .unwrap_or(DEFAULT_VAULT_SECRET_TTL_DAYS);
    if vault_secret_ttl_days <= 0 {
        return Err(GlovesError::InvalidInput(
            "defaults.vault_secret_ttl_days must be greater than zero".to_owned(),
        ));
    }

    let vault_secret_length_bytes = raw
        .vault_secret_length_bytes
        .unwrap_or(DEFAULT_VAULT_SECRET_LENGTH_BYTES);
    if vault_secret_length_bytes == 0 {
        return Err(GlovesError::InvalidInput(
            "defaults.vault_secret_length_bytes must be greater than zero".to_owned(),
        ));
    }

    Ok(DefaultBootstrapConfig {
        agent_id,
        secret_ttl_days,
        vault_mount_ttl,
        vault_secret_ttl_days,
        vault_secret_length_bytes,
    })
}

fn validate_agent_policy<PrivatePathValue, VaultMountValue>(
    agent_name: &str,
    policy: &AgentAccessFile,
    private_paths: &BTreeMap<String, PrivatePathValue>,
    vault_mounts: &BTreeMap<String, VaultMountValue>,
) -> Result<()> {
    let has_legacy_path_policy = !policy.paths.is_empty() || !policy.operations.is_empty();
    let has_secret_policy = policy.secrets.is_some();
    let has_vault_policy = policy.vault.is_some();

    if !has_legacy_path_policy && !has_secret_policy && !has_vault_policy {
        return Err(GlovesError::InvalidInput(format!(
            "agent '{agent_name}' must include at least one access policy"
        )));
    }

    if policy.paths.is_empty() != policy.operations.is_empty() {
        return Err(GlovesError::InvalidInput(format!(
            "agent '{agent_name}' must define both paths and operations for legacy private path access"
        )));
    }

    if has_legacy_path_policy {
        let mut path_aliases = BTreeSet::new();
        for alias in &policy.paths {
            if !path_aliases.insert(alias.as_str()) {
                return Err(GlovesError::InvalidInput(format!(
                    "agent '{agent_name}' contains duplicate private path alias '{alias}'"
                )));
            }
            if !private_paths.is_empty() && !private_paths.contains_key(alias) {
                return Err(GlovesError::InvalidInput(format!(
                    "agent '{agent_name}' references unknown private path alias '{alias}'"
                )));
            }
        }

        let mut operations = BTreeSet::new();
        for operation in &policy.operations {
            if !operations.insert(*operation) {
                return Err(GlovesError::InvalidInput(format!(
                    "agent '{agent_name}' contains duplicate operation '{operation:?}'"
                )));
            }
        }
    }

    if let Some(secret_policy) = policy.secrets.as_ref() {
        validate_agent_secret_access_policy(agent_name, secret_policy)?;
    }
    if let Some(vault_policy) = policy.vault.as_ref() {
        validate_agent_vault_access_policy(agent_name, vault_policy, vault_mounts)?;
    }

    Ok(())
}

fn validate_agent_secret_access_policy(
    agent_name: &str,
    policy: &AgentSecretsAccessFile,
) -> Result<()> {
    let policy = SecretAccessFile {
        refs: policy.refs.clone(),
        operations: policy.operations.clone(),
    };
    validate_secret_access_policy(agent_name, &policy)
}

fn validate_agent_vault_access_policy(
    agent_name: &str,
    policy: &AgentVaultAccessFile,
    vault_mounts: &BTreeMap<String, impl Sized>,
) -> Result<()> {
    if policy.mounts.is_empty() {
        return Err(GlovesError::InvalidInput(format!(
            "vault access for agent '{agent_name}' must include at least one mount"
        )));
    }
    if policy.operations.is_empty() {
        return Err(GlovesError::InvalidInput(format!(
            "vault access for agent '{agent_name}' must include at least one operation"
        )));
    }

    let mut mount_names = BTreeSet::new();
    for mount_name in &policy.mounts {
        if !mount_names.insert(mount_name.as_str()) {
            return Err(GlovesError::InvalidInput(format!(
                "vault access for agent '{agent_name}' contains duplicate mount '{mount_name}'"
            )));
        }
        if mount_name != "*" && !vault_mounts.is_empty() && !vault_mounts.contains_key(mount_name) {
            return Err(GlovesError::InvalidInput(format!(
                "vault access for agent '{agent_name}' references unknown mount '{mount_name}'"
            )));
        }
    }

    let mut operations = BTreeSet::new();
    for operation in &policy.operations {
        if !operations.insert(*operation) {
            return Err(GlovesError::InvalidInput(format!(
                "vault access for agent '{agent_name}' contains duplicate operation '{operation:?}'"
            )));
        }
    }

    Ok(())
}

fn validate_secret_access_policy(agent_name: &str, policy: &SecretAccessFile) -> Result<()> {
    if policy.refs.is_empty() {
        return Err(GlovesError::InvalidInput(format!(
            "secret ACL for agent '{agent_name}' must include at least one ref pattern"
        )));
    }
    if policy.operations.is_empty() {
        return Err(GlovesError::InvalidInput(format!(
            "secret ACL for agent '{agent_name}' must include at least one operation"
        )));
    }

    let mut patterns = BTreeSet::new();
    for pattern in &policy.refs {
        validate_secret_pattern(pattern)?;
        if !patterns.insert(pattern.as_str()) {
            return Err(GlovesError::InvalidInput(format!(
                "secret ACL for agent '{agent_name}' contains duplicate pattern '{pattern}'"
            )));
        }
    }

    let mut operations = BTreeSet::new();
    for operation in &policy.operations {
        if !operations.insert(*operation) {
            return Err(GlovesError::InvalidInput(format!(
                "secret ACL for agent '{agent_name}' contains duplicate operation '{operation:?}'"
            )));
        }
    }

    Ok(())
}

fn validate_integration_config(name: &str, integration: &IntegrationConfigFile) -> Result<()> {
    validate_alias(name)?;
    let agent_literal = integration.agent.as_deref().ok_or_else(|| {
        GlovesError::InvalidInput(format!("integration '{name}' must declare an owning agent"))
    })?;
    AgentId::new(agent_literal)?;
    let _ = normalized_integration_segments(&integration.profiles, "profiles", name)?;
    let _ = normalized_integration_segments(&integration.slots, "slots", name)?;
    Ok(())
}

fn normalized_integration_segments(
    values: &[String],
    field_name: &str,
    integration_name: &str,
) -> Result<Vec<String>> {
    let mut normalized = Vec::with_capacity(values.len());
    let mut seen = BTreeSet::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(GlovesError::InvalidInput(format!(
                "integration '{integration_name}' contains an empty {field_name} entry"
            )));
        }
        validate_alias(trimmed).map_err(|_| {
            GlovesError::InvalidInput(format!(
                "integration '{integration_name}' has invalid {field_name} entry '{trimmed}'"
            ))
        })?;
        if !seen.insert(trimmed.to_owned()) {
            return Err(GlovesError::InvalidInput(format!(
                "integration '{integration_name}' contains duplicate {field_name} entry '{trimmed}'"
            )));
        }
        normalized.push(trimmed.to_owned());
    }
    Ok(normalized)
}

fn validate_secret_pipe_command_policy(
    command: &str,
    policy: &SecretPipeCommandPolicyFile,
) -> Result<()> {
    validate_pipe_command_name(command)?;

    if !policy.require_url && policy.url_prefixes.is_empty() {
        return Err(GlovesError::InvalidInput(format!(
            "secrets.pipe.commands.{command} must set require_url = true or include at least one url_prefix"
        )));
    }
    if policy.require_url && policy.url_prefixes.is_empty() {
        return Err(GlovesError::InvalidInput(format!(
            "secrets.pipe.commands.{command} requires at least one url_prefix"
        )));
    }

    let mut unique_prefixes = BTreeSet::new();
    for url_prefix in &policy.url_prefixes {
        validate_pipe_url_prefix(command, url_prefix)?;
        if !unique_prefixes.insert(url_prefix.as_str()) {
            return Err(GlovesError::InvalidInput(format!(
                "secrets.pipe.commands.{command} contains duplicate url_prefix '{url_prefix}'"
            )));
        }
    }

    Ok(())
}

fn validate_pipe_command_name(command: &str) -> Result<()> {
    if command.is_empty()
        || !command
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._+-".contains(character))
    {
        return Err(GlovesError::InvalidInput(format!(
            "secrets.pipe.commands.{command} must be a bare executable name"
        )));
    }
    Ok(())
}

fn validate_pipe_url_prefix(command: &str, url_prefix: &str) -> Result<()> {
    if url_prefix.trim().is_empty() {
        return Err(GlovesError::InvalidInput(format!(
            "secrets.pipe.commands.{command} contains an empty url_prefix"
        )));
    }
    if let Err(reason) = parse_policy_url_prefix(url_prefix) {
        return Err(GlovesError::InvalidInput(format!(
            "secrets.pipe.commands.{command} url_prefix '{url_prefix}' {reason}"
        )));
    }
    Ok(())
}

fn parse_policy_url_prefix(url_prefix: &str) -> std::result::Result<(), String> {
    let remainder = if let Some(rest) = url_prefix.strip_prefix(URL_SCHEME_HTTP_PREFIX) {
        rest
    } else if let Some(rest) = url_prefix.strip_prefix(URL_SCHEME_HTTPS_PREFIX) {
        rest
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
    if suffix
        .chars()
        .any(|character| character == '?' || character == '#')
    {
        return Err("must not include query or fragment components".to_owned());
    }
    Ok(())
}

fn validate_secret_pattern(pattern: &str) -> Result<()> {
    if pattern == "*" {
        return Ok(());
    }

    if let Some(prefix) = pattern.strip_suffix("/*") {
        if prefix.is_empty() {
            return Err(GlovesError::InvalidInput(
                "secret ACL pattern '/*' is not allowed; use '*' for all secrets".to_owned(),
            ));
        }
        if prefix.contains('*') {
            return Err(GlovesError::InvalidInput(format!(
                "secret ACL pattern '{pattern}' may only use one trailing '*'"
            )));
        }
        SecretId::new(prefix).map_err(|_| {
            GlovesError::InvalidInput(format!(
                "secret ACL pattern '{pattern}' has an invalid namespace prefix"
            ))
        })?;
        return Ok(());
    }

    if pattern.contains('*') {
        return Err(GlovesError::InvalidInput(format!(
            "secret ACL pattern '{pattern}' must be '*', '<namespace>/*', or an exact secret id"
        )));
    }

    SecretId::new(pattern).map_err(|_| {
        GlovesError::InvalidInput(format!(
            "secret ACL pattern '{pattern}' is not a valid secret id"
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

fn resolve_path_value(value: &str, source_dir: &Path) -> Result<PathBuf> {
    validate_path_literal(value, "path")?;

    let expanded = expand_home(value)?;
    let absolute = if expanded.is_absolute() {
        expanded
    } else {
        source_dir.join(expanded)
    };

    if let Ok(canonical) = fs::canonicalize(&absolute) {
        return Ok(canonical);
    }
    Ok(normalize_path(&absolute))
}

fn validate_path_literal(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(GlovesError::InvalidInput(format!(
            "{label} cannot be empty"
        )));
    }
    Ok(())
}

fn validate_alias(alias: &str) -> Result<()> {
    if alias.is_empty() {
        return Err(GlovesError::InvalidInput(
            "private path alias cannot be empty".to_owned(),
        ));
    }
    if !alias
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '_' || character == '-')
    {
        return Err(GlovesError::InvalidInput(format!(
            "invalid private path alias '{}': use [a-zA-Z0-9_-]",
            alias
        )));
    }
    Ok(())
}

fn validate_duration_literal(value: &str, label: &str) -> Result<()> {
    if value.is_empty() {
        return Err(GlovesError::InvalidInput(format!(
            "{label} cannot be empty"
        )));
    }

    let (number, unit) = value.split_at(value.len().saturating_sub(1));
    let amount = number.parse::<i64>().map_err(|_| {
        GlovesError::InvalidInput(format!("{label} must be a duration like 30m, 1h, or 7d"))
    })?;
    if amount <= 0 {
        return Err(GlovesError::InvalidInput(format!(
            "{label} must be greater than zero"
        )));
    }

    if !matches!(unit, "s" | "m" | "h" | "d") {
        return Err(GlovesError::InvalidInput(format!(
            "{label} must use one of s, m, h, d"
        )));
    }

    Ok(())
}

fn expand_home(value: &str) -> Result<PathBuf> {
    if value == "~" {
        let home = std::env::var_os("HOME")
            .ok_or_else(|| GlovesError::InvalidInput("HOME is not set".to_owned()))?;
        return Ok(PathBuf::from(home));
    }

    if let Some(rest) = value.strip_prefix("~/") {
        let home = std::env::var_os("HOME")
            .ok_or_else(|| GlovesError::InvalidInput("HOME is not set".to_owned()))?;
        return Ok(PathBuf::from(home).join(rest));
    }

    if value.starts_with('~') {
        return Err(GlovesError::InvalidInput(
            "only '~' and '~/' home expansion are supported".to_owned(),
        ));
    }

    Ok(PathBuf::from(value))
}

fn normalize_path(path: &Path) -> PathBuf {
    let is_absolute = path.is_absolute();
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() && !is_absolute {
                    normalized.push("..");
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }

    if normalized.as_os_str().is_empty() {
        if is_absolute {
            PathBuf::from(std::path::MAIN_SEPARATOR.to_string())
        } else {
            PathBuf::from(".")
        }
    } else {
        normalized
    }
}

fn absolutize_path(path: &Path, cwd: &Path) -> PathBuf {
    if path.is_absolute() {
        normalize_path(path)
    } else {
        normalize_path(&cwd.join(path))
    }
}

fn validate_config_file_permissions(path: &Path, has_private_paths: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(GlovesError::InvalidInput(format!(
            "config path must be a regular file: {}",
            path.display()
        )));
    }

    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o022 != 0 {
            return Err(GlovesError::InvalidInput(format!(
                "config file must not be group/world writable: {}",
                path.display()
            )));
        }

        if has_private_paths {
            let has_exec_bits = mode & 0o111 != 0;
            let has_world_bits = mode & 0o007 != 0;
            let has_group_write_or_exec = mode & 0o030 != 0;
            if has_exec_bits || has_world_bits || has_group_write_or_exec {
                return Err(GlovesError::InvalidInput(format!(
                    "config file with private paths must be private (recommended 0600/0640): {}",
                    path.display()
                )));
            }
        }
    }

    Ok(())
}

fn is_regular_config_candidate(path: &Path) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    !metadata.file_type().is_symlink() && metadata.file_type().is_file()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        ffi::OsString,
        sync::{Mutex, OnceLock},
        time::{SystemTime, UNIX_EPOCH},
    };

    #[cfg(unix)]
    use std::os::unix::fs::{symlink, PermissionsExt};

    static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temp_root = PathBuf::from("/tmp");
        let base_dir = if temp_root.is_dir() {
            temp_root
        } else {
            std::env::temp_dir()
        };
        let path = base_dir.join(format!(
            "gloves-config-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn cleanup_dir(path: &Path) {
        let _ = fs::remove_dir_all(path);
    }

    fn valid_config(root_literal: &str, private_path_literal: &str) -> String {
        format!(
            r#"
version = 1

[paths]
root = "{root_literal}"

[private_paths]
runtime = "{private_path_literal}"

[daemon]
bind = "127.0.0.1:7789"
io_timeout_seconds = 9
request_limit_bytes = 32768

[vault]
mode = "required"

[defaults]
agent_id = "devy"
secret_ttl_days = 7
vault_mount_ttl = "2h"
vault_secret_ttl_days = 90
vault_secret_length_bytes = 48

[agents.devy]
paths = ["runtime"]
operations = ["read", "write"]

[secrets.acl.devy]
paths = ["agents/devy/*", "shared/database-url"]
operations = ["read", "list"]

[secrets.pipe.commands.curl]
require_url = true
url_prefixes = ["https://api.example.com/v1/"]
"#
        )
    }

    struct HomeGuard {
        previous_home: Option<OsString>,
    }

    impl HomeGuard {
        fn set(home: &Path) -> Self {
            let previous_home = std::env::var_os("HOME");
            std::env::set_var("HOME", home);
            Self { previous_home }
        }
    }

    impl Drop for HomeGuard {
        fn drop(&mut self) {
            if let Some(previous_home) = &self.previous_home {
                std::env::set_var("HOME", previous_home);
            } else {
                std::env::remove_var("HOME");
            }
        }
    }

    #[test]
    fn parse_from_str_builds_effective_config_and_accessors() {
        let _lock = test_lock();
        let temp_dir = unique_temp_dir("parse");
        let source_path = temp_dir.join(CONFIG_FILE_NAME);
        let root_dir = temp_dir.join("secrets-root");
        let private_dir = temp_dir.join("private").join("runtime");
        fs::create_dir_all(&root_dir).unwrap();
        fs::create_dir_all(&private_dir).unwrap();

        let config = GlovesConfig::parse_from_str(
            &valid_config("./secrets-root", "./private/runtime"),
            &source_path,
        )
        .unwrap();

        assert_eq!(config.source_path, source_path);
        assert_eq!(config.root, fs::canonicalize(&root_dir).unwrap());
        assert_eq!(
            config.private_paths.get("runtime"),
            Some(&fs::canonicalize(&private_dir).unwrap())
        );
        assert_eq!(config.daemon.bind, "127.0.0.1:7789");
        assert_eq!(config.daemon.io_timeout_seconds, 9);
        assert_eq!(config.daemon.request_limit_bytes, 32768);
        assert_eq!(config.vault.mode, VaultMode::Required);
        assert_eq!(config.defaults.agent_id.as_str(), "devy");
        assert_eq!(config.defaults.secret_ttl_days, 7);
        assert_eq!(config.defaults.vault_mount_ttl, "2h");
        assert_eq!(config.defaults.vault_secret_ttl_days, 90);
        assert_eq!(config.defaults.vault_secret_length_bytes, 48);
        assert!(config.has_secret_acl());

        let agent_id = AgentId::new("devy").unwrap();
        let paths = config.agent_paths(&agent_id).unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].alias, "runtime");
        assert_eq!(
            paths[0].operations,
            vec![PathOperation::Read, PathOperation::Write]
        );

        let secret_policy = config.secret_access_policy(&agent_id).unwrap();
        assert!(secret_policy.allows_operation(SecretAclOperation::Read));
        assert!(secret_policy.allows_secret("agents/devy/api-keys/anthropic"));
        assert!(secret_policy.allows_secret("shared/database-url"));
        assert!(!secret_policy.allows_secret("agents/webhook/api-keys/anthropic"));

        let pipe_policy = config.secret_pipe_command_policy("curl").unwrap();
        assert!(pipe_policy.require_url);
        assert_eq!(
            pipe_policy.url_prefixes,
            vec!["https://api.example.com/v1/".to_owned()]
        );
        assert!(config
            .secret_access_policy(&AgentId::new("webhook").unwrap())
            .is_none());
        assert!(config.secret_pipe_command_policy("wget").is_none());

        let mut config_without_acl = config.clone();
        config_without_acl.secret_access.clear();
        assert!(!config_without_acl.has_secret_acl());

        cleanup_dir(&temp_dir);
    }

    #[test]
    fn resolve_config_path_honors_flag_env_discovery_and_no_config() {
        let _lock = test_lock();
        let temp_dir = unique_temp_dir("resolve");
        let nested_dir = temp_dir.join("workspace").join("nested");
        fs::create_dir_all(&nested_dir).unwrap();

        let discovered_path = temp_dir.join("workspace").join(CONFIG_FILE_NAME);
        fs::write(&discovered_path, "version = 1\n").unwrap();

        let flag_path = nested_dir.join("custom.toml");
        fs::write(&flag_path, "version = 1\n").unwrap();
        let env_path = nested_dir.join("env.toml");
        fs::write(&env_path, "version = 1\n").unwrap();

        let flag_selection =
            resolve_config_path(Some(Path::new("custom.toml")), None, false, &nested_dir).unwrap();
        assert_eq!(flag_selection.source, ConfigSource::Flag);
        assert_eq!(flag_selection.path, Some(flag_path.clone()));

        let env_selection =
            resolve_config_path(None, Some("env.toml"), false, &nested_dir).unwrap();
        assert_eq!(env_selection.source, ConfigSource::Env);
        assert_eq!(env_selection.path, Some(env_path.clone()));

        let discovered_selection = resolve_config_path(None, None, false, &nested_dir).unwrap();
        assert_eq!(discovered_selection.source, ConfigSource::Discovered);
        assert_eq!(discovered_selection.path, Some(discovered_path.clone()));

        let none_selection = resolve_config_path(None, None, true, &nested_dir).unwrap();
        assert_eq!(none_selection.source, ConfigSource::None);
        assert!(none_selection.path.is_none());

        let env_error = resolve_config_path(None, Some("   "), false, &nested_dir).unwrap_err();
        assert!(env_error
            .to_string()
            .contains("GLOVES_CONFIG cannot be empty"));

        let missing_error =
            resolve_config_path(Some(Path::new("missing.toml")), None, false, &nested_dir)
                .unwrap_err();
        assert!(missing_error
            .to_string()
            .contains("config file must be a regular file"));

        cleanup_dir(&temp_dir);
    }

    #[test]
    fn helper_functions_cover_path_resolution_and_home_expansion() {
        let _lock = test_lock();
        let temp_dir = unique_temp_dir("paths");
        let home_dir = temp_dir.join("home");
        fs::create_dir_all(&home_dir).unwrap();
        let _home_guard = HomeGuard::set(&home_dir);

        assert_eq!(expand_home("~").unwrap(), home_dir);
        assert_eq!(expand_home("~/bin").unwrap(), home_dir.join("bin"));
        assert!(expand_home("~other/bin")
            .unwrap_err()
            .to_string()
            .contains("only '~' and '~/' home expansion are supported"));

        assert_eq!(
            normalize_path(Path::new("foo/./bar/../baz")),
            PathBuf::from("foo/baz")
        );
        assert_eq!(
            normalize_path(Path::new("/tmp/../var/./lib")),
            PathBuf::from("/var/lib")
        );
        assert_eq!(
            absolutize_path(Path::new("nested/../config.toml"), Path::new("/tmp/work")),
            PathBuf::from("/tmp/work/config.toml")
        );
        assert_eq!(
            absolutize_path(Path::new("/tmp/./gloves.toml"), Path::new("/unused")),
            PathBuf::from("/tmp/gloves.toml")
        );

        let resolved_existing = resolve_path_value("~/bin", Path::new("/unused")).unwrap();
        assert_eq!(resolved_existing, home_dir.join("bin"));
        let resolved_relative = resolve_path_value("./secrets/../secrets-root", &temp_dir).unwrap();
        assert_eq!(resolved_relative, temp_dir.join("secrets-root"));

        assert!(validate_path_literal("", "paths.root")
            .unwrap_err()
            .to_string()
            .contains("paths.root cannot be empty"));

        cleanup_dir(&temp_dir);
    }

    #[test]
    fn daemon_defaults_and_vault_validation_cover_failure_modes() {
        let daemon_defaults = resolve_daemon_config(&DaemonConfigFile::default()).unwrap();
        assert_eq!(daemon_defaults.bind, DEFAULT_DAEMON_BIND);
        assert_eq!(
            daemon_defaults.io_timeout_seconds,
            DEFAULT_DAEMON_IO_TIMEOUT_SECONDS
        );
        assert_eq!(
            daemon_defaults.request_limit_bytes,
            DEFAULT_DAEMON_REQUEST_LIMIT_BYTES
        );

        assert!(resolve_daemon_config(&DaemonConfigFile {
            bind: Some("127.0.0.1:0".to_owned()),
            io_timeout_seconds: None,
            request_limit_bytes: None,
        })
        .unwrap_err()
        .to_string()
        .contains("daemon bind port must be non-zero"));
        assert!(resolve_daemon_config(&DaemonConfigFile {
            bind: Some("0.0.0.0:7788".to_owned()),
            io_timeout_seconds: None,
            request_limit_bytes: None,
        })
        .unwrap_err()
        .to_string()
        .contains("daemon bind address must be loopback"));
        assert!(resolve_daemon_config(&DaemonConfigFile {
            bind: None,
            io_timeout_seconds: Some(0),
            request_limit_bytes: None,
        })
        .unwrap_err()
        .to_string()
        .contains("io_timeout_seconds must be greater than zero"));
        assert!(resolve_daemon_config(&DaemonConfigFile {
            bind: None,
            io_timeout_seconds: None,
            request_limit_bytes: Some(0),
        })
        .unwrap_err()
        .to_string()
        .contains("request_limit_bytes must be greater than zero"));

        let default_config = resolve_default_config(&DefaultsConfigFile::default()).unwrap();
        assert_eq!(default_config.agent_id.as_str(), DEFAULT_AGENT_ID);
        assert_eq!(default_config.secret_ttl_days, DEFAULT_SECRET_TTL_DAYS);
        assert_eq!(default_config.vault_mount_ttl, DEFAULT_VAULT_MOUNT_TTL);
        assert_eq!(
            default_config.vault_secret_ttl_days,
            DEFAULT_VAULT_SECRET_TTL_DAYS
        );
        assert_eq!(
            default_config.vault_secret_length_bytes,
            DEFAULT_VAULT_SECRET_LENGTH_BYTES
        );

        assert!(resolve_default_config(&DefaultsConfigFile {
            agent_id: Some("bad agent".to_owned()),
            ..DefaultsConfigFile::default()
        })
        .is_err());
        assert!(resolve_default_config(&DefaultsConfigFile {
            secret_ttl_days: Some(0),
            ..DefaultsConfigFile::default()
        })
        .unwrap_err()
        .to_string()
        .contains("secret_ttl_days must be greater than zero"));
        assert!(resolve_default_config(&DefaultsConfigFile {
            vault_mount_ttl: Some("12x".to_owned()),
            ..DefaultsConfigFile::default()
        })
        .unwrap_err()
        .to_string()
        .contains("vault_mount_ttl must use one of s, m, h, d"));
        assert!(resolve_default_config(&DefaultsConfigFile {
            vault_secret_ttl_days: Some(0),
            ..DefaultsConfigFile::default()
        })
        .unwrap_err()
        .to_string()
        .contains("vault_secret_ttl_days must be greater than zero"));
        assert!(resolve_default_config(&DefaultsConfigFile {
            vault_secret_length_bytes: Some(0),
            ..DefaultsConfigFile::default()
        })
        .unwrap_err()
        .to_string()
        .contains("vault_secret_length_bytes must be greater than zero"));

        assert_eq!(
            resolve_vault_config(&VaultConfigFile::default(), Path::new("."))
                .unwrap()
                .mode,
            VaultMode::Auto
        );
        assert_eq!(
            resolve_vault_config(
                &VaultConfigFile {
                    mode: Some(VaultMode::Disabled),
                    mounts: BTreeMap::new(),
                },
                Path::new(".")
            )
            .unwrap()
            .mode,
            VaultMode::Disabled
        );

        assert!(validate_duration_literal("", "defaults.vault_mount_ttl")
            .unwrap_err()
            .to_string()
            .contains("defaults.vault_mount_ttl cannot be empty"));
        assert!(validate_duration_literal("0h", "defaults.vault_mount_ttl")
            .unwrap_err()
            .to_string()
            .contains("defaults.vault_mount_ttl must be greater than zero"));
    }

    #[test]
    fn policy_validation_helpers_cover_duplicates_and_invalid_patterns() {
        let private_paths = BTreeMap::from([("runtime".to_owned(), PathBuf::from("/tmp/runtime"))]);
        let vault_mounts =
            BTreeMap::from([("contacts".to_owned(), PathBuf::from("/tmp/contacts"))]);

        assert!(validate_agent_policy(
            "devy",
            &AgentAccessFile {
                paths: Vec::new(),
                operations: vec![PathOperation::Read],
                secrets: None,
                vault: None,
            },
            &private_paths,
            &vault_mounts,
        )
        .unwrap_err()
        .to_string()
        .contains("must define both paths and operations"));
        assert!(validate_agent_policy(
            "devy",
            &AgentAccessFile {
                paths: vec!["runtime".to_owned()],
                operations: Vec::new(),
                secrets: None,
                vault: None,
            },
            &private_paths,
            &vault_mounts,
        )
        .unwrap_err()
        .to_string()
        .contains("must define both paths and operations"));
        assert!(validate_agent_policy(
            "devy",
            &AgentAccessFile {
                paths: vec!["missing".to_owned()],
                operations: vec![PathOperation::Read],
                secrets: None,
                vault: None,
            },
            &private_paths,
            &vault_mounts,
        )
        .unwrap_err()
        .to_string()
        .contains("references unknown private path alias"));
        assert!(validate_agent_policy(
            "devy",
            &AgentAccessFile {
                paths: vec!["runtime".to_owned(), "runtime".to_owned()],
                operations: vec![PathOperation::Read],
                secrets: None,
                vault: None,
            },
            &private_paths,
            &vault_mounts,
        )
        .unwrap_err()
        .to_string()
        .contains("duplicate private path alias"));
        assert!(validate_agent_policy(
            "devy",
            &AgentAccessFile {
                paths: vec!["runtime".to_owned()],
                operations: vec![PathOperation::Read, PathOperation::Read],
                secrets: None,
                vault: None,
            },
            &private_paths,
            &vault_mounts,
        )
        .unwrap_err()
        .to_string()
        .contains("duplicate operation"));

        let valid_secret_policy = SecretAccessFile {
            refs: vec!["agents/devy/*".to_owned(), "shared/database-url".to_owned()],
            operations: vec![SecretAclOperation::Read, SecretAclOperation::List],
        };
        validate_secret_access_policy("devy", &valid_secret_policy).unwrap();
        assert!(validate_secret_access_policy(
            "devy",
            &SecretAccessFile {
                refs: Vec::new(),
                operations: vec![SecretAclOperation::Read],
            },
        )
        .unwrap_err()
        .to_string()
        .contains("must include at least one ref pattern"));
        assert!(validate_secret_access_policy(
            "devy",
            &SecretAccessFile {
                refs: vec!["*".to_owned()],
                operations: Vec::new(),
            },
        )
        .unwrap_err()
        .to_string()
        .contains("must include at least one operation"));
        assert!(validate_secret_access_policy(
            "devy",
            &SecretAccessFile {
                refs: vec!["*".to_owned(), "*".to_owned()],
                operations: vec![SecretAclOperation::Read],
            },
        )
        .unwrap_err()
        .to_string()
        .contains("duplicate pattern"));
        assert!(validate_secret_access_policy(
            "devy",
            &SecretAccessFile {
                refs: vec!["*".to_owned()],
                operations: vec![SecretAclOperation::Read, SecretAclOperation::Read],
            },
        )
        .unwrap_err()
        .to_string()
        .contains("duplicate operation"));

        validate_secret_pattern("*").unwrap();
        validate_secret_pattern("agents/devy/*").unwrap();
        validate_secret_pattern("shared/database-url").unwrap();
        assert!(validate_secret_pattern("/*")
            .unwrap_err()
            .to_string()
            .contains("is not allowed"));
        assert!(validate_secret_pattern("agents/*/broken")
            .unwrap_err()
            .to_string()
            .contains("must be '*', '<namespace>/*', or an exact secret id"));
        assert!(validate_secret_pattern("agents/devy*")
            .unwrap_err()
            .to_string()
            .contains("must be '*', '<namespace>/*', or an exact secret id"));
        assert!(validate_secret_pattern("bad secret")
            .unwrap_err()
            .to_string()
            .contains("is not a valid secret id"));

        assert!(secret_pattern_matches("*", "shared/database-url"));
        assert!(secret_pattern_matches(
            "agents/devy/*",
            "agents/devy/api-keys/anthropic"
        ));
        assert!(!secret_pattern_matches("agents/devy/*", "agents/devy"));
        assert!(!secret_pattern_matches(
            "agents/devy/*",
            "agents/webhook/api-keys/anthropic"
        ));
        assert!(secret_pattern_matches(
            "shared/database-url",
            "shared/database-url"
        ));
    }

    #[test]
    fn pipe_policy_and_raw_config_validation_cover_edge_cases() {
        validate_secret_pipe_command_policy(
            "curl",
            &SecretPipeCommandPolicyFile {
                require_url: true,
                url_prefixes: vec!["https://api.example.com/".to_owned()],
            },
        )
        .unwrap();

        assert!(validate_pipe_command_name("curl").is_ok());
        assert!(validate_pipe_command_name("curl --fail")
            .unwrap_err()
            .to_string()
            .contains("must be a bare executable name"));
        assert!(validate_secret_pipe_command_policy(
            "curl",
            &SecretPipeCommandPolicyFile::default(),
        )
        .unwrap_err()
        .to_string()
        .contains("must set require_url = true or include at least one url_prefix"));
        assert!(validate_secret_pipe_command_policy(
            "curl",
            &SecretPipeCommandPolicyFile {
                require_url: true,
                url_prefixes: Vec::new(),
            },
        )
        .unwrap_err()
        .to_string()
        .contains("requires at least one url_prefix"));
        assert!(validate_secret_pipe_command_policy(
            "curl",
            &SecretPipeCommandPolicyFile {
                require_url: false,
                url_prefixes: vec![
                    "https://api.example.com/".to_owned(),
                    "https://api.example.com/".to_owned()
                ],
            },
        )
        .unwrap_err()
        .to_string()
        .contains("duplicate url_prefix"));
        assert!(validate_pipe_url_prefix("curl", "   ")
            .unwrap_err()
            .to_string()
            .contains("contains an empty url_prefix"));

        assert!(parse_policy_url_prefix("ftp://example.com")
            .unwrap_err()
            .contains("must start with http:// or https://"));
        assert!(parse_policy_url_prefix("https://")
            .unwrap_err()
            .contains("must include an authority after scheme"));
        assert!(parse_policy_url_prefix("https://bad host/path")
            .unwrap_err()
            .contains("must not contain whitespace in authority"));
        assert!(parse_policy_url_prefix("https://example.com/path?query")
            .unwrap_err()
            .contains("must not include query or fragment components"));
        assert!(parse_policy_url_prefix("https://example.com/path#fragment")
            .unwrap_err()
            .contains("must not include query or fragment components"));

        assert!(validate_alias("runtime-1").is_ok());
        assert!(validate_alias("")
            .unwrap_err()
            .to_string()
            .contains("alias cannot be empty"));
        assert!(validate_alias("bad/alias")
            .unwrap_err()
            .to_string()
            .contains("invalid private path alias"));

        assert!(
            GlovesConfig::parse_from_str("version = 3\n", Path::new("/tmp/.gloves.toml"))
                .unwrap_err()
                .to_string()
                .contains("unsupported config version")
        );
        assert!(GlovesConfig::parse_from_str(
            "version = 1\nunknown = true\n",
            Path::new("/tmp/.gloves.toml")
        )
        .unwrap_err()
        .to_string()
        .contains("invalid config TOML"));
    }

    #[test]
    fn agent_paths_reports_unknown_alias_when_config_is_mutated() {
        let mut config = GlovesConfig {
            source_path: PathBuf::from("/tmp/.gloves.toml"),
            root: PathBuf::from("/tmp/root"),
            private_paths: BTreeMap::new(),
            daemon: DaemonBootstrapConfig {
                bind: DEFAULT_DAEMON_BIND.to_owned(),
                io_timeout_seconds: DEFAULT_DAEMON_IO_TIMEOUT_SECONDS,
                request_limit_bytes: DEFAULT_DAEMON_REQUEST_LIMIT_BYTES,
            },
            vault: VaultBootstrapConfig {
                mode: VaultMode::Auto,
                mounts: BTreeMap::new(),
            },
            defaults: DefaultBootstrapConfig {
                agent_id: AgentId::new(DEFAULT_AGENT_ID).unwrap(),
                secret_ttl_days: DEFAULT_SECRET_TTL_DAYS,
                vault_mount_ttl: DEFAULT_VAULT_MOUNT_TTL.to_owned(),
                vault_secret_ttl_days: DEFAULT_VAULT_SECRET_TTL_DAYS,
                vault_secret_length_bytes: DEFAULT_VAULT_SECRET_LENGTH_BYTES,
            },
            agents: BTreeMap::from([(
                "devy".to_owned(),
                AgentAccessPolicy {
                    path_aliases: vec!["runtime".to_owned()],
                    operations: vec![PathOperation::Read],
                },
            )]),
            secret_access: BTreeMap::new(),
            agent_vault_access: BTreeMap::new(),
            integrations: BTreeMap::new(),
            secret_pipe_commands: BTreeMap::new(),
        };

        let error = config
            .agent_paths(&AgentId::new("devy").unwrap())
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("references unknown private path alias"));

        config
            .private_paths
            .insert("runtime".to_owned(), PathBuf::from("/tmp/runtime"));
        let missing_agent = config
            .agent_paths(&AgentId::new("webhook").unwrap())
            .unwrap_err();
        assert!(matches!(missing_agent, GlovesError::NotFound));
    }

    #[test]
    fn discover_config_walks_upward_and_ignores_missing_candidates() {
        let _lock = test_lock();
        let temp_dir = unique_temp_dir("discover");
        let workspace_dir = temp_dir.join("workspace");
        let nested_dir = workspace_dir.join("nested").join("child");
        fs::create_dir_all(&nested_dir).unwrap();

        let config_path = workspace_dir.join(CONFIG_FILE_NAME);
        fs::write(&config_path, "version = 1\n").unwrap();

        assert_eq!(discover_config(&nested_dir), Some(config_path.clone()));
        assert!(is_regular_config_candidate(&config_path));
        assert!(!is_regular_config_candidate(&workspace_dir));
        assert_eq!(discover_config(temp_dir.join("missing")), None);

        cleanup_dir(&temp_dir);
    }

    #[cfg(unix)]
    #[test]
    fn load_from_path_and_permission_validation_cover_unix_rules() {
        let _lock = test_lock();
        let temp_dir = unique_temp_dir("load");
        let config_path = temp_dir.join(CONFIG_FILE_NAME);
        let regular_path = temp_dir.join("regular.toml");
        let symlink_path = temp_dir.join("config-link.toml");
        fs::create_dir_all(temp_dir.join("private").join("runtime")).unwrap();
        fs::create_dir_all(temp_dir.join("secrets-root")).unwrap();

        fs::write(
            &config_path,
            valid_config("./secrets-root", "./private/runtime"),
        )
        .unwrap();
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o640)).unwrap();
        let loaded = GlovesConfig::load_from_path(&config_path).unwrap();
        assert_eq!(loaded.defaults.agent_id.as_str(), "devy");

        fs::write(&regular_path, "version = 1\n").unwrap();
        fs::set_permissions(&regular_path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(validate_config_file_permissions(&regular_path, false)
            .unwrap_err()
            .to_string()
            .contains("must not be group/world writable"));

        fs::set_permissions(&regular_path, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(validate_config_file_permissions(&regular_path, true)
            .unwrap_err()
            .to_string()
            .contains("must be private"));

        symlink(&regular_path, &symlink_path).unwrap();
        assert!(validate_config_file_permissions(&symlink_path, false)
            .unwrap_err()
            .to_string()
            .contains("must be a regular file"));

        assert!(GlovesConfig::load_from_path(temp_dir.join("missing.toml"))
            .unwrap_err()
            .to_string()
            .contains("config file does not exist"));

        cleanup_dir(&temp_dir);
    }
}
