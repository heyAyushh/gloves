use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use serde::{Deserialize, Serialize};

use crate::{
    error::{GlovesError, Result},
    types::{AgentId, SecretId},
};

const CONFIG_VERSION_V1: u32 = 1;
const DEFAULT_ROOT: &str = ".openclaw/secrets";
const DEFAULT_DAEMON_BIND: &str = "127.0.0.1:7788";
const DEFAULT_DAEMON_IO_TIMEOUT_SECONDS: u64 = 5;
const DEFAULT_DAEMON_REQUEST_LIMIT_BYTES: usize = 16 * 1024;
const DEFAULT_AGENT_ID: &str = "default-agent";
const DEFAULT_SECRET_TTL_DAYS: i64 = 1;
const DEFAULT_VAULT_MOUNT_TTL: &str = "1h";
const DEFAULT_VAULT_SECRET_TTL_DAYS: i64 = 365;
const DEFAULT_VAULT_SECRET_LENGTH_BYTES: usize = 64;

/// Default bootstrap config file name.
pub const CONFIG_FILE_NAME: &str = ".gloves.toml";

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
    /// Secret path patterns (`*`, `foo/*`, or exact secret id).
    #[serde(default)]
    pub paths: Vec<String>,
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
    pub paths: Vec<String>,
    /// Allowed operations.
    pub operations: Vec<PathOperation>,
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
    /// Secret path patterns (`*`, `foo/*`, or exact secret id).
    pub paths: Vec<String>,
    /// Allowed secret operations.
    pub operations: Vec<SecretAclOperation>,
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
        self.paths
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
    let vault = resolve_vault_config(&raw.vault);
    let defaults = resolve_default_config(&raw.defaults)?;

    let mut agents = BTreeMap::new();
    for (agent_name, policy) in &raw.agents {
        AgentId::new(agent_name)?;
        validate_agent_policy(agent_name, policy, &private_paths)?;
        agents.insert(
            agent_name.clone(),
            AgentAccessPolicy {
                path_aliases: policy.paths.clone(),
                operations: policy.operations.clone(),
            },
        );
    }

    let mut secret_access = BTreeMap::new();
    for (agent_name, policy) in &raw.secrets.acl {
        AgentId::new(agent_name)?;
        validate_secret_access_policy(agent_name, policy)?;
        secret_access.insert(
            agent_name.clone(),
            SecretAccessPolicy {
                paths: policy.paths.clone(),
                operations: policy.operations.clone(),
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
        secret_pipe_commands,
    })
}

fn validate_raw_config(config: &GlovesConfigFile) -> Result<()> {
    if config.version != CONFIG_VERSION_V1 {
        return Err(GlovesError::InvalidInput(format!(
            "unsupported config version {} (expected {})",
            config.version, CONFIG_VERSION_V1
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
    let _ = resolve_vault_config(&config.vault);
    let _ = resolve_default_config(&config.defaults)?;

    for (agent_name, policy) in &config.secrets.acl {
        AgentId::new(agent_name)?;
        validate_secret_access_policy(agent_name, policy)?;
    }
    for (command, policy) in &config.secrets.pipe.commands {
        validate_secret_pipe_command_policy(command, policy)?;
    }

    Ok(())
}

fn resolve_vault_config(raw: &VaultConfigFile) -> VaultBootstrapConfig {
    VaultBootstrapConfig {
        mode: raw.mode.unwrap_or(VaultMode::Auto),
    }
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

fn validate_agent_policy(
    agent_name: &str,
    policy: &AgentAccessFile,
    private_paths: &BTreeMap<String, PathBuf>,
) -> Result<()> {
    if policy.paths.is_empty() {
        return Err(GlovesError::InvalidInput(format!(
            "agent '{agent_name}' must include at least one private path alias"
        )));
    }
    if policy.operations.is_empty() {
        return Err(GlovesError::InvalidInput(format!(
            "agent '{agent_name}' must include at least one operation"
        )));
    }

    let mut path_aliases = BTreeSet::new();
    for alias in &policy.paths {
        if !path_aliases.insert(alias.as_str()) {
            return Err(GlovesError::InvalidInput(format!(
                "agent '{agent_name}' contains duplicate private path alias '{alias}'"
            )));
        }
        if !private_paths.contains_key(alias) {
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

    Ok(())
}

fn validate_secret_access_policy(agent_name: &str, policy: &SecretAccessFile) -> Result<()> {
    if policy.paths.is_empty() {
        return Err(GlovesError::InvalidInput(format!(
            "secret ACL for agent '{agent_name}' must include at least one path pattern"
        )));
    }
    if policy.operations.is_empty() {
        return Err(GlovesError::InvalidInput(format!(
            "secret ACL for agent '{agent_name}' must include at least one operation"
        )));
    }

    let mut patterns = BTreeSet::new();
    for pattern in &policy.paths {
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
    if url_prefix.chars().any(char::is_whitespace) {
        return Err(GlovesError::InvalidInput(format!(
            "secrets.pipe.commands.{command} url_prefix '{url_prefix}' must not contain whitespace"
        )));
    }
    if !is_http_url_prefix(url_prefix) {
        return Err(GlovesError::InvalidInput(format!(
            "secrets.pipe.commands.{command} url_prefix '{url_prefix}' must start with http:// or https://"
        )));
    }
    Ok(())
}

fn is_http_url_prefix(url_prefix: &str) -> bool {
    url_prefix.starts_with("http://") || url_prefix.starts_with("https://")
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
