use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Component, Path, PathBuf},
    process::{Command, Output, Stdio},
};

use serde::{Deserialize, Serialize};

use crate::{
    agent::age_crypto,
    audit::{AuditEvent, AuditLog},
    error::{GlovesError, Result},
    fs_secure::{ensure_private_dir, write_private_file_atomic},
    paths::SecretsPaths,
    types::AgentId,
    SecretRef,
};

const DOCKER_BRIDGE_CONFIG_ENV_VAR: &str = "GLOVES_DOCKER_BRIDGE_CONFIG";
const DOCKER_REAL_BIN_ENV_VAR: &str = "GLOVES_DOCKER_REAL_BIN";
const DEFAULT_SECRET_MOUNT_ROOT: &str = "/run/secrets";
const DEFAULT_TMPFS_SPEC: &str = "/run/secrets:size=1M,mode=0700,noexec,nosuid,nodev";
const DOCKER_SUBCOMMAND_CREATE: &str = "create";
const DOCKER_SUBCOMMAND_EXEC: &str = "exec";
const DOCKER_SUBCOMMAND_RM: &str = "rm";
const DOCKER_SUBCOMMAND_RUN: &str = "run";
const DOCKER_SUBCOMMAND_START: &str = "start";
const DOCKER_SUBCOMMAND_STOP: &str = "stop";
const DOCKER_EXEC_SHELL: &str = "umask 077 && mkdir -p \"$1\" && cat > \"$2\" && chmod 0400 \"$2\"";
const OPERATION_INJECT: &str = "inject_ref";
const OPERATION_MATCH: &str = "match_container";

/// Reads a secret ref using an existing runtime root and agent identity.
pub fn resolve_secret_ref(
    root: &Path,
    secret_ref: &SecretRef,
    agent_id: &AgentId,
) -> Result<Vec<u8>> {
    let paths = SecretsPaths::new(root);
    let identity_path = validated_identity_path(&paths, agent_id)?;
    let ciphertext_path = root
        .join("store")
        .join(format!("{}.age", secret_ref.secret_id().as_str()));
    age_crypto::decrypt_file(&ciphertext_path, identity_path.as_path())
}

/// Dispatches one docker-wrapper invocation using env-driven bridge config.
pub fn run_docker_bridge(arguments: &[String]) -> Result<i32> {
    let config_path = std::env::var(DOCKER_BRIDGE_CONFIG_ENV_VAR).map_err(|_| {
        GlovesError::InvalidInput(format!(
            "{DOCKER_BRIDGE_CONFIG_ENV_VAR} must point to a bridge config file"
        ))
    })?;
    let config = DockerBridgeConfig::load(Path::new(&config_path))?;
    config.execute(arguments)
}

fn validated_identity_path(paths: &SecretsPaths, agent_id: &AgentId) -> Result<PathBuf> {
    let candidate_paths = [
        PathBuf::from(paths.root())
            .join("identities")
            .join(format!("{}.age", agent_id.as_str())),
        paths.identity_file_for_agent(agent_id.as_str()),
    ];
    let Some(identity_path) = candidate_paths.into_iter().find(|path| path.exists()) else {
        return Err(GlovesError::InvalidInput(format!(
            "missing identity file for agent `{}` under {}",
            agent_id.as_str(),
            paths.root().display()
        )));
    };
    if !identity_path.exists() {
        return Err(GlovesError::InvalidInput(format!(
            "missing identity file for agent `{}` at {}",
            agent_id.as_str(),
            identity_path.display()
        )));
    }
    age_crypto::validate_identity_file(&identity_path)?;
    Ok(identity_path)
}

/// Operator-controlled Docker bridge configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerBridgeConfig {
    /// Schema version for operator configs.
    pub version: u8,
    /// Host-side gloves runtime root.
    pub gloves_root: PathBuf,
    /// Private host-side state directory for bridge state and shim files.
    pub runtime_root: PathBuf,
    /// Optional explicit path to the gloves CLI binary.
    #[serde(default)]
    pub gloves_bin: Option<PathBuf>,
    /// Optional explicit path to the real docker binary.
    #[serde(default)]
    pub docker_bin: Option<PathBuf>,
    /// Optional audit actor used for bridge-side audit events.
    #[serde(default)]
    pub audit_agent: Option<String>,
    /// Target tmpfs root inside containers.
    #[serde(default = "default_secret_mount_root")]
    pub secret_mount_root: String,
    /// Docker `--tmpfs` spec to add when a matched container lacks the target mount.
    #[serde(default = "default_tmpfs_spec")]
    pub tmpfs_spec: String,
    /// Secret delivery plans matched against docker create/run metadata.
    #[serde(default)]
    pub targets: Vec<DockerSecretTarget>,
}

impl DockerBridgeConfig {
    /// Loads a bridge config from TOML.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)?;
        let config: Self = toml::from_str(&raw).map_err(|error| {
            GlovesError::InvalidInput(format!("invalid bridge config: {error}"))
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Executes one docker-wrapper invocation using this config.
    pub fn execute(&self, arguments: &[String]) -> Result<i32> {
        let invocation = DockerInvocation::parse(arguments)?;
        let state_store = BridgeStateStore::new(self.runtime_root.join("docker-bridge"))?;

        match invocation.subcommand.as_str() {
            DOCKER_SUBCOMMAND_CREATE => self.handle_create_or_run(invocation, &state_store, false),
            DOCKER_SUBCOMMAND_RUN => self.handle_create_or_run(invocation, &state_store, true),
            DOCKER_SUBCOMMAND_START => self.handle_start(invocation, &state_store),
            DOCKER_SUBCOMMAND_EXEC => self.handle_exec(invocation, &state_store),
            DOCKER_SUBCOMMAND_STOP => self.handle_stop(invocation, &state_store),
            DOCKER_SUBCOMMAND_RM => self.handle_rm(invocation, &state_store),
            _ => self.forward(arguments).map(|output| emit_output(&output)),
        }
    }

    fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(GlovesError::InvalidInput(format!(
                "unsupported docker bridge config version `{}`",
                self.version
            )));
        }
        if self.targets.is_empty() {
            return Err(GlovesError::InvalidInput(
                "docker bridge config must define at least one secret target".to_owned(),
            ));
        }
        if !self.secret_mount_root.starts_with('/') {
            return Err(GlovesError::InvalidInput(
                "secret_mount_root must be an absolute container path".to_owned(),
            ));
        }
        for target in &self.targets {
            target.validate(&self.secret_mount_root)?;
        }
        Ok(())
    }

    fn handle_create_or_run(
        &self,
        mut invocation: DockerInvocation,
        state_store: &BridgeStateStore,
        is_run: bool,
    ) -> Result<i32> {
        let Some(initial_create_spec) = invocation.create_spec.clone() else {
            return self
                .forward(&invocation.original_arguments)
                .map(|output| emit_output(&output));
        };
        let matched_targets = self.match_targets(&initial_create_spec)?;
        if matched_targets.is_empty() {
            return self
                .forward(&invocation.original_arguments)
                .map(|output| emit_output(&output));
        }
        if is_run && !initial_create_spec.detach {
            return Err(GlovesError::InvalidInput(
                "matched docker run must use --detach so the bridge can inject before later execs"
                    .to_owned(),
            ));
        }

        ensure_private_dir(&self.runtime_root)?;
        self.audit_match(&initial_create_spec, matched_targets.len())?;
        if !initial_create_spec.has_tmpfs_root(&self.secret_mount_root) {
            invocation.append_tmpfs(self.tmpfs_spec.clone());
        }
        let create_spec = invocation
            .create_spec
            .clone()
            .ok_or_else(|| GlovesError::InvalidInput("missing docker create spec".to_owned()))?;

        let output = self.forward(&invocation.forward_arguments())?;
        let exit_code = emit_output(&output);
        if exit_code != 0 {
            return Ok(exit_code);
        }

        let container_aliases = container_aliases_for_create(is_run, &create_spec, &output.stdout)?;
        state_store.upsert(BridgeContainerState::new(
            container_aliases.clone(),
            matched_targets,
        ))?;

        if is_run && create_spec.detach {
            self.inject_pending(&container_aliases, state_store)?;
            if create_spec.remove_after_exit {
                state_store.remove_by_aliases(&container_aliases)?;
            }
        }

        Ok(exit_code)
    }

    fn handle_start(
        &self,
        invocation: DockerInvocation,
        state_store: &BridgeStateStore,
    ) -> Result<i32> {
        let container_refs = invocation.container_refs.clone();
        let output = self.forward(&invocation.original_arguments)?;
        let exit_code = emit_output(&output);
        if exit_code == 0 {
            self.inject_pending(&container_refs, state_store)?;
        }
        Ok(exit_code)
    }

    fn handle_exec(
        &self,
        invocation: DockerInvocation,
        state_store: &BridgeStateStore,
    ) -> Result<i32> {
        self.inject_pending(&invocation.container_refs, state_store)?;
        self.forward(&invocation.original_arguments)
            .map(|output| emit_output(&output))
    }

    fn handle_stop(
        &self,
        invocation: DockerInvocation,
        state_store: &BridgeStateStore,
    ) -> Result<i32> {
        let output = self.forward(&invocation.original_arguments)?;
        let exit_code = emit_output(&output);
        if exit_code == 0 {
            state_store.mark_not_injected(&invocation.container_refs)?;
        }
        Ok(exit_code)
    }

    fn handle_rm(
        &self,
        invocation: DockerInvocation,
        state_store: &BridgeStateStore,
    ) -> Result<i32> {
        let output = self.forward(&invocation.original_arguments)?;
        let exit_code = emit_output(&output);
        if exit_code == 0 {
            state_store.remove_by_aliases(&invocation.container_refs)?;
        }
        Ok(exit_code)
    }

    fn match_targets(
        &self,
        create_spec: &DockerCreateSpec,
    ) -> Result<Vec<ResolvedDockerSecretTarget>> {
        let mut matched = Vec::new();
        for target in &self.targets {
            if !target.selector.matches(create_spec) {
                continue;
            }
            let container_path = target.normalized_container_path(&self.secret_mount_root)?;
            let agent_id = target.resolve_agent_id()?;
            matched.push(ResolvedDockerSecretTarget {
                secret_ref: target.secret_ref.clone(),
                agent_id,
                container_path,
            });
        }
        Ok(matched)
    }

    fn inject_pending(
        &self,
        container_refs: &[String],
        state_store: &BridgeStateStore,
    ) -> Result<()> {
        for container_ref in container_refs {
            let Some(mut state) = state_store.find_by_alias(container_ref)? else {
                continue;
            };
            if state.injected {
                continue;
            }
            for target in &state.targets {
                let secret_bytes = resolve_secret_ref(
                    self.gloves_root.as_path(),
                    &target.secret_ref,
                    &target.agent_id,
                )?;
                self.inject_secret(container_ref, &target.container_path, &secret_bytes)?;
                self.audit_injection(container_ref, target)?;
            }
            state.injected = true;
            state_store.upsert(state)?;
        }
        Ok(())
    }

    fn inject_secret(
        &self,
        container_ref: &str,
        container_path: &str,
        secret_bytes: &[u8],
    ) -> Result<()> {
        let parent = Path::new(container_path).parent().ok_or_else(|| {
            GlovesError::InvalidInput(format!("container path `{container_path}` has no parent"))
        })?;
        let mut child = self
            .real_docker_command(&[
                DOCKER_SUBCOMMAND_EXEC,
                "-i",
                container_ref,
                "/bin/sh",
                "-lc",
                DOCKER_EXEC_SHELL,
                "gloves-docker-bridge",
                parent.to_string_lossy().as_ref(),
                container_path,
            ])?
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(secret_bytes)?;
        }
        let output = child.wait_with_output()?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        let message = if stderr.is_empty() {
            format!("docker exec failed with {}", output.status)
        } else {
            stderr
        };
        Err(GlovesError::InvalidInput(format!(
            "failed to inject secret into `{container_ref}`: {message}"
        )))
    }

    fn audit_match(&self, create_spec: &DockerCreateSpec, target_count: usize) -> Result<()> {
        let Some(agent_id) = self.audit_agent_id()? else {
            return Ok(());
        };
        let audit_log = AuditLog::new(SecretsPaths::new(&self.gloves_root).audit_file())?;
        audit_log.log(AuditEvent::CommandExecuted {
            by: agent_id,
            interface: "docker_bridge".to_owned(),
            command: OPERATION_MATCH.to_owned(),
            target: Some(format!(
                "{}:{}:{}",
                create_spec.image,
                create_spec.name.clone().unwrap_or_default(),
                target_count
            )),
        })
    }

    fn audit_injection(
        &self,
        container_ref: &str,
        target: &ResolvedDockerSecretTarget,
    ) -> Result<()> {
        let Some(agent_id) = self.audit_agent_id()? else {
            return Ok(());
        };
        let audit_log = AuditLog::new(SecretsPaths::new(&self.gloves_root).audit_file())?;
        audit_log.log(AuditEvent::CommandExecuted {
            by: agent_id,
            interface: "docker_bridge".to_owned(),
            command: OPERATION_INJECT.to_owned(),
            target: Some(format!("{container_ref}:{}", target.secret_ref)),
        })
    }

    fn audit_agent_id(&self) -> Result<Option<AgentId>> {
        self.audit_agent
            .as_deref()
            .map(AgentId::new)
            .transpose()
            .map_err(GlovesError::from)
    }

    fn forward(&self, arguments: &[String]) -> Result<Output> {
        let mut child = self.real_docker_command(arguments)?;
        child.output().map_err(GlovesError::from)
    }

    fn real_docker_command(&self, arguments: &[impl AsRef<str>]) -> Result<Command> {
        let docker_bin = std::env::var_os(DOCKER_REAL_BIN_ENV_VAR)
            .map(PathBuf::from)
            .or_else(|| self.docker_bin.clone())
            .ok_or_else(|| {
                GlovesError::InvalidInput(format!(
                    "set docker_bin in the bridge config or export {DOCKER_REAL_BIN_ENV_VAR}"
                ))
            })?;
        let mut command = Command::new(docker_bin);
        for argument in arguments {
            command.arg(argument.as_ref());
        }
        Ok(command)
    }
}

fn emit_output(output: &Output) -> i32 {
    let _ = std::io::stdout().write_all(&output.stdout);
    let _ = std::io::stderr().write_all(&output.stderr);
    output.status.code().unwrap_or(1)
}

fn default_secret_mount_root() -> String {
    DEFAULT_SECRET_MOUNT_ROOT.to_owned()
}

fn default_tmpfs_spec() -> String {
    DEFAULT_TMPFS_SPEC.to_owned()
}

fn container_aliases_for_create(
    is_run: bool,
    create_spec: &DockerCreateSpec,
    stdout: &[u8],
) -> Result<Vec<String>> {
    let mut aliases = BTreeSet::new();
    if let Some(name) = &create_spec.name {
        aliases.insert(name.clone());
    }
    if !is_run || create_spec.detach {
        let container_id = String::from_utf8_lossy(stdout).trim().to_owned();
        if !container_id.is_empty() {
            aliases.insert(container_id);
        }
    }
    if aliases.is_empty() {
        return Err(GlovesError::InvalidInput(
            "matched docker create/run did not expose a usable container id or name".to_owned(),
        ));
    }
    Ok(aliases.into_iter().collect())
}

/// One secret injection target bound to a container selector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerSecretTarget {
    /// Secret ref resolved on the host.
    pub secret_ref: SecretRef,
    /// Absolute container path that will receive the secret bytes.
    pub container_path: String,
    /// Optional explicit agent id used to decrypt the secret.
    #[serde(default)]
    pub agent_id: Option<String>,
    /// Container metadata selector.
    #[serde(default)]
    pub selector: DockerContainerSelector,
}

impl DockerSecretTarget {
    fn validate(&self, secret_mount_root: &str) -> Result<()> {
        self.normalized_container_path(secret_mount_root)?;
        if self.selector.is_empty() {
            return Err(GlovesError::InvalidInput(
                "docker bridge target selectors must match at least one container property"
                    .to_owned(),
            ));
        }
        self.resolve_agent_id().map(|_| ())
    }

    fn normalized_container_path(&self, secret_mount_root: &str) -> Result<String> {
        let normalized_mount_root =
            normalize_container_path(secret_mount_root, "secret_mount_root")?;
        let normalized_container_path =
            normalize_container_path(&self.container_path, "container_path")?;
        if normalized_container_path == normalized_mount_root
            || !normalized_container_path.starts_with(&normalized_mount_root)
        {
            return Err(GlovesError::InvalidInput(format!(
                "container_path `{}` must stay under `{secret_mount_root}`",
                self.container_path
            )));
        }
        Ok(normalized_container_path.to_string_lossy().into_owned())
    }

    fn resolve_agent_id(&self) -> Result<AgentId> {
        if let Some(agent_id) = &self.agent_id {
            return AgentId::new(agent_id).map_err(GlovesError::from);
        }

        let secret_path = self.secret_ref.secret_id().as_str();
        let mut segments = secret_path.split('/');
        match (segments.next(), segments.next()) {
            (Some("agents"), Some(agent_id)) => AgentId::new(agent_id).map_err(GlovesError::from),
            _ => Err(GlovesError::InvalidInput(format!(
                "target `{}` must declare agent_id because it does not use an `agents/<agent>/...` ref",
                self.secret_ref
            ))),
        }
    }
}

/// Selects docker create/run containers by metadata already present in the command line.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DockerContainerSelector {
    /// Optional container name prefix.
    #[serde(default)]
    pub name_prefix: Option<String>,
    /// Optional exact image match.
    #[serde(default)]
    pub image: Option<String>,
    /// Required labels.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// Required environment variables.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

impl DockerContainerSelector {
    fn is_empty(&self) -> bool {
        self.name_prefix.is_none()
            && self.image.is_none()
            && self.labels.is_empty()
            && self.env.is_empty()
    }

    fn matches(&self, spec: &DockerCreateSpec) -> bool {
        if let Some(prefix) = &self.name_prefix {
            let Some(name) = spec.name.as_ref() else {
                return false;
            };
            if !name.starts_with(prefix) {
                return false;
            }
        }
        if let Some(image) = &self.image {
            if &spec.image != image {
                return false;
            }
        }
        if !map_contains_all(&spec.labels, &self.labels) || !map_contains_all(&spec.env, &self.env)
        {
            return false;
        }
        true
    }
}

fn map_contains_all(left: &BTreeMap<String, String>, required: &BTreeMap<String, String>) -> bool {
    required.iter().all(|(key, value)| {
        left.get(key)
            .map(|candidate| candidate == value)
            .unwrap_or(false)
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResolvedDockerSecretTarget {
    secret_ref: SecretRef,
    agent_id: AgentId,
    container_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BridgeContainerState {
    aliases: Vec<String>,
    injected: bool,
    targets: Vec<ResolvedDockerSecretTarget>,
}

impl BridgeContainerState {
    fn new(aliases: Vec<String>, targets: Vec<ResolvedDockerSecretTarget>) -> Self {
        Self {
            aliases,
            injected: false,
            targets,
        }
    }
}

#[derive(Debug)]
struct BridgeStateStore {
    state_path: PathBuf,
}

impl BridgeStateStore {
    fn new(root: PathBuf) -> Result<Self> {
        ensure_private_dir(&root)?;
        Ok(Self {
            state_path: root.join("state.json"),
        })
    }

    fn find_by_alias(&self, alias: &str) -> Result<Option<BridgeContainerState>> {
        Ok(self
            .load()?
            .into_iter()
            .find(|state| state.aliases.iter().any(|candidate| candidate == alias)))
    }

    fn upsert(&self, state: BridgeContainerState) -> Result<()> {
        let mut states = self.load()?;
        states.retain(|existing| !share_alias(existing, &state.aliases));
        states.push(state);
        self.save(&states)
    }

    fn mark_not_injected(&self, aliases: &[String]) -> Result<()> {
        let mut states = self.load()?;
        for state in &mut states {
            if aliases
                .iter()
                .any(|alias| state.aliases.iter().any(|candidate| candidate == alias))
            {
                state.injected = false;
            }
        }
        self.save(&states)
    }

    fn remove_by_aliases(&self, aliases: &[String]) -> Result<()> {
        let mut states = self.load()?;
        states.retain(|state| {
            !aliases
                .iter()
                .any(|alias| state.aliases.iter().any(|candidate| candidate == alias))
        });
        self.save(&states)
    }

    fn load(&self) -> Result<Vec<BridgeContainerState>> {
        if !self.state_path.exists() {
            return Ok(Vec::new());
        }
        let raw = fs::read(&self.state_path)?;
        serde_json::from_slice(&raw).map_err(GlovesError::from)
    }

    fn save(&self, states: &[BridgeContainerState]) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(states)?;
        write_private_file_atomic(&self.state_path, &bytes)
    }
}

fn share_alias(state: &BridgeContainerState, aliases: &[String]) -> bool {
    aliases
        .iter()
        .any(|alias| state.aliases.iter().any(|candidate| candidate == alias))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DockerInvocation {
    subcommand: String,
    original_arguments: Vec<String>,
    create_spec: Option<DockerCreateSpec>,
    container_refs: Vec<String>,
}

impl DockerInvocation {
    fn parse(arguments: &[String]) -> Result<Self> {
        let Some(subcommand) = arguments.first() else {
            return Err(GlovesError::InvalidInput(
                "docker bridge requires a docker subcommand".to_owned(),
            ));
        };
        let create_spec = match subcommand.as_str() {
            DOCKER_SUBCOMMAND_CREATE | DOCKER_SUBCOMMAND_RUN => {
                Some(DockerCreateSpec::parse(arguments)?)
            }
            _ => None,
        };
        let container_refs = match subcommand.as_str() {
            DOCKER_SUBCOMMAND_START | DOCKER_SUBCOMMAND_STOP | DOCKER_SUBCOMMAND_RM => {
                parse_container_refs(arguments)?
            }
            DOCKER_SUBCOMMAND_EXEC => parse_exec_container_ref(arguments)?.into_iter().collect(),
            _ => Vec::new(),
        };
        Ok(Self {
            subcommand: subcommand.clone(),
            original_arguments: arguments.to_vec(),
            create_spec,
            container_refs,
        })
    }

    fn append_tmpfs(&mut self, tmpfs_spec: String) {
        self.original_arguments.insert(1, "--tmpfs".to_owned());
        self.original_arguments.insert(2, tmpfs_spec);
        if let Some(create_spec) = &mut self.create_spec {
            create_spec
                .tmpfs_mounts
                .push(self.original_arguments[2].clone());
        }
    }

    fn forward_arguments(&self) -> Vec<String> {
        self.original_arguments.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DockerCreateSpec {
    name: Option<String>,
    image: String,
    labels: BTreeMap<String, String>,
    env: BTreeMap<String, String>,
    tmpfs_mounts: Vec<String>,
    detach: bool,
    remove_after_exit: bool,
}

impl DockerCreateSpec {
    fn parse(arguments: &[String]) -> Result<Self> {
        let mut name = None;
        let mut image = None;
        let mut labels = BTreeMap::new();
        let mut env = BTreeMap::new();
        let mut tmpfs_mounts = Vec::new();
        let mut detach = false;
        let mut remove_after_exit = false;
        let mut index = 1;

        while index < arguments.len() {
            let token = &arguments[index];
            if !token.starts_with('-') {
                image = Some(token.clone());
                break;
            }
            if token == "-d" || token == "--detach" {
                detach = true;
                index += 1;
                continue;
            }
            if token == "--rm" {
                remove_after_exit = true;
                index += 1;
                continue;
            }
            if let Some(value) = parse_option_value(arguments, &mut index, "--name", None)? {
                name = Some(value);
                continue;
            }
            if let Some(value) = parse_option_value(arguments, &mut index, "--label", Some("-l"))? {
                let (key, value) = split_key_value("label", &value)?;
                labels.insert(key, value);
                continue;
            }
            if let Some(value) = parse_option_value(arguments, &mut index, "--env", Some("-e"))? {
                let (key, value) = split_key_value("env", &value)?;
                env.insert(key, value);
                continue;
            }
            if let Some(value) = parse_option_value(arguments, &mut index, "--tmpfs", None)? {
                tmpfs_mounts.push(value);
                continue;
            }
            index += consume_option(arguments, index);
        }

        let image = image.ok_or_else(|| {
            GlovesError::InvalidInput(
                "docker create/run command did not include an image".to_owned(),
            )
        })?;
        Ok(Self {
            name,
            image,
            labels,
            env,
            tmpfs_mounts,
            detach,
            remove_after_exit,
        })
    }

    fn has_tmpfs_root(&self, secret_mount_root: &str) -> bool {
        self.tmpfs_mounts.iter().any(|mount| {
            mount == secret_mount_root
                || mount
                    .strip_prefix(secret_mount_root)
                    .map(|suffix| suffix.starts_with(':'))
                    .unwrap_or(false)
        })
    }
}

fn parse_container_refs(arguments: &[String]) -> Result<Vec<String>> {
    let mut refs = Vec::new();
    let mut index = 1;
    while index < arguments.len() {
        let token = &arguments[index];
        if token.starts_with('-') {
            index += consume_option(arguments, index);
            continue;
        }
        refs.push(token.clone());
        index += 1;
    }
    if refs.is_empty() {
        return Err(GlovesError::InvalidInput(
            "docker command did not include a container reference".to_owned(),
        ));
    }
    Ok(refs)
}

fn parse_exec_container_ref(arguments: &[String]) -> Result<Option<String>> {
    let mut index = 1;
    while index < arguments.len() {
        let token = &arguments[index];
        if token.starts_with('-') {
            index += consume_option(arguments, index);
            continue;
        }
        return Ok(Some(token.clone()));
    }
    Err(GlovesError::InvalidInput(
        "docker exec command did not include a container reference".to_owned(),
    ))
}

fn parse_option_value(
    arguments: &[String],
    index: &mut usize,
    long_name: &str,
    short_name: Option<&str>,
) -> Result<Option<String>> {
    let token = &arguments[*index];
    if let Some(rest) = token.strip_prefix(&format!("{long_name}=")) {
        *index += 1;
        return Ok(Some(rest.to_owned()));
    }
    if token == long_name || short_name.map(|value| value == token).unwrap_or(false) {
        let value_index = *index + 1;
        let value = arguments.get(value_index).ok_or_else(|| {
            GlovesError::InvalidInput(format!("docker option `{token}` requires a value"))
        })?;
        *index += 2;
        return Ok(Some(value.clone()));
    }
    Ok(None)
}

fn consume_option(arguments: &[String], index: usize) -> usize {
    let token = &arguments[index];
    if token.contains('=') {
        return 1;
    }
    if option_takes_value(token) && arguments.get(index + 1).is_some() {
        return 2;
    }
    1
}

fn option_takes_value(token: &str) -> bool {
    matches!(
        token,
        "--add-host"
            | "--annotation"
            | "--cap-add"
            | "--cap-drop"
            | "--cgroup-parent"
            | "--cidfile"
            | "--cpu-period"
            | "--cpu-quota"
            | "--cpu-rt-period"
            | "--cpu-rt-runtime"
            | "--cpus"
            | "--cpuset-cpus"
            | "--cpuset-mems"
            | "--device"
            | "--dns"
            | "--dns-option"
            | "--dns-search"
            | "--entrypoint"
            | "--env"
            | "-e"
            | "--env-file"
            | "--expose"
            | "--gpus"
            | "--group-add"
            | "--health-cmd"
            | "--health-interval"
            | "--health-retries"
            | "--health-start-period"
            | "--health-timeout"
            | "--hostname"
            | "--ip"
            | "--ipc"
            | "--isolation"
            | "--label"
            | "-l"
            | "--label-file"
            | "--log-driver"
            | "--log-opt"
            | "--mac-address"
            | "--memory"
            | "--memory-reservation"
            | "--memory-swap"
            | "--mount"
            | "--name"
            | "--network"
            | "--network-alias"
            | "--pid"
            | "--pids-limit"
            | "--platform"
            | "--privileged"
            | "--publish"
            | "-p"
            | "--restart"
            | "--runtime"
            | "--security-opt"
            | "--shm-size"
            | "--stop-signal"
            | "--stop-timeout"
            | "--storage-opt"
            | "--tmpfs"
            | "--ulimit"
            | "--user"
            | "-u"
            | "--uts"
            | "--volume"
            | "-v"
            | "--workdir"
            | "-w"
    )
}

fn split_key_value(label: &str, value: &str) -> Result<(String, String)> {
    if value.is_empty() {
        return Err(GlovesError::InvalidInput(format!(
            "docker {label} key must not be empty"
        )));
    }
    match value.split_once('=') {
        Some((key, value)) if !key.is_empty() => Ok((key.to_owned(), value.to_owned())),
        Some(_) => Err(GlovesError::InvalidInput(format!(
            "docker {label} key must not be empty"
        ))),
        None => Ok((value.to_owned(), String::new())),
    }
}

fn normalize_container_path(path: &str, label: &str) -> Result<PathBuf> {
    let original_path = Path::new(path);
    if !original_path.is_absolute() {
        return Err(GlovesError::InvalidInput(format!(
            "{label} must be an absolute container path"
        )));
    }

    let mut normalized_path = PathBuf::from(Path::new("/"));
    for component in original_path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(segment) => normalized_path.push(segment),
            Component::CurDir | Component::ParentDir => {
                return Err(GlovesError::InvalidInput(format!(
                    "{label} must not contain path traversal segments"
                )))
            }
            Component::Prefix(_) => {
                return Err(GlovesError::InvalidInput(format!(
                    "{label} must be a Unix-style absolute container path"
                )))
            }
        }
    }
    Ok(normalized_path)
}

#[cfg(test)]
mod tests {
    use super::{
        container_aliases_for_create, DockerBridgeConfig, DockerContainerSelector,
        DockerCreateSpec, DockerInvocation, DockerSecretTarget,
    };
    use crate::secret_ref::SecretRef;
    use std::{collections::BTreeMap, path::PathBuf};
    use tempfile::tempdir;

    #[test]
    fn docker_create_parser_extracts_name_labels_env_and_image() {
        let arguments = vec![
            "create".to_owned(),
            "--name".to_owned(),
            "openclaw-agent-devy".to_owned(),
            "--label".to_owned(),
            "openclaw.agent=devy".to_owned(),
            "--env".to_owned(),
            "OPENCLAW_SESSION_ID=session-1".to_owned(),
            "--tmpfs".to_owned(),
            "/run/secrets:size=1M".to_owned(),
            "ghcr.io/openclaw/agent:latest".to_owned(),
            "sleep".to_owned(),
            "60".to_owned(),
        ];

        let spec = DockerCreateSpec::parse(&arguments).unwrap();

        assert_eq!(spec.name.as_deref(), Some("openclaw-agent-devy"));
        assert_eq!(spec.image, "ghcr.io/openclaw/agent:latest");
        assert_eq!(
            spec.labels.get("openclaw.agent").map(String::as_str),
            Some("devy")
        );
        assert_eq!(
            spec.env.get("OPENCLAW_SESSION_ID").map(String::as_str),
            Some("session-1")
        );
        assert!(spec.has_tmpfs_root("/run/secrets"));
    }

    #[test]
    fn docker_create_parser_accepts_key_only_env_and_label_flags() {
        let arguments = vec![
            "create".to_owned(),
            "--label".to_owned(),
            "sandbox".to_owned(),
            "--env".to_owned(),
            "OPENCLAW_SESSION_ID".to_owned(),
            "ghcr.io/openclaw/agent:latest".to_owned(),
        ];

        let spec = DockerCreateSpec::parse(&arguments).unwrap();

        assert_eq!(spec.labels.get("sandbox").map(String::as_str), Some(""));
        assert_eq!(
            spec.env.get("OPENCLAW_SESSION_ID").map(String::as_str),
            Some("")
        );
    }

    #[test]
    fn docker_exec_and_start_parsers_extract_container_refs() {
        let exec = DockerInvocation::parse(&[
            "exec".to_owned(),
            "-i".to_owned(),
            "sandbox-123".to_owned(),
            "sh".to_owned(),
        ])
        .unwrap();
        let start = DockerInvocation::parse(&[
            "start".to_owned(),
            "-a".to_owned(),
            "sandbox-123".to_owned(),
        ])
        .unwrap();

        assert_eq!(exec.container_refs, vec!["sandbox-123".to_owned()]);
        assert_eq!(start.container_refs, vec!["sandbox-123".to_owned()]);
    }

    #[test]
    fn bridge_config_requires_agent_identity_for_non_agent_refs() {
        let target = DockerSecretTarget {
            secret_ref: "gloves://shared/database-url".parse::<SecretRef>().unwrap(),
            container_path: "/run/secrets/database-url".to_owned(),
            agent_id: None,
            selector: DockerContainerSelector {
                name_prefix: Some("openclaw-".to_owned()),
                ..Default::default()
            },
        };

        let error = target.validate("/run/secrets").unwrap_err();
        assert!(error.to_string().contains("agent_id"));
    }

    #[test]
    fn bridge_config_rejects_container_path_traversal() {
        let target = DockerSecretTarget {
            secret_ref: "gloves://agents/devy/api-keys/openai"
                .parse::<SecretRef>()
                .unwrap(),
            container_path: "/run/secrets/../etc/passwd".to_owned(),
            agent_id: None,
            selector: DockerContainerSelector {
                name_prefix: Some("openclaw-".to_owned()),
                ..Default::default()
            },
        };

        let error = target.validate("/run/secrets").unwrap_err();
        assert!(error
            .to_string()
            .contains("must not contain path traversal segments"));
    }

    #[test]
    fn bridge_config_rejects_paths_outside_secret_mount_root() {
        let target = DockerSecretTarget {
            secret_ref: "gloves://agents/devy/api-keys/openai"
                .parse::<SecretRef>()
                .unwrap(),
            container_path: "/run/secretsx/openai".to_owned(),
            agent_id: None,
            selector: DockerContainerSelector {
                name_prefix: Some("openclaw-".to_owned()),
                ..Default::default()
            },
        };

        let error = target.validate("/run/secrets").unwrap_err();
        assert!(error.to_string().contains("must stay under"));
    }

    #[test]
    fn matched_foreground_run_is_rejected_before_forwarding() {
        let temp_dir = tempdir().unwrap();
        let config = DockerBridgeConfig {
            version: 1,
            gloves_root: temp_dir.path().join("gloves"),
            runtime_root: temp_dir.path().join("runtime"),
            gloves_bin: None,
            docker_bin: Some(PathBuf::from("/definitely-not-used")),
            audit_agent: Some("openclaw".to_owned()),
            secret_mount_root: "/run/secrets".to_owned(),
            tmpfs_spec: "/run/secrets:size=1M,mode=0700".to_owned(),
            targets: vec![DockerSecretTarget {
                secret_ref: "gloves://agents/devy/api-keys/openai".parse().unwrap(),
                container_path: "/run/secrets/openai".to_owned(),
                agent_id: None,
                selector: DockerContainerSelector {
                    labels: BTreeMap::from([("openclaw.agent".to_owned(), "devy".to_owned())]),
                    ..Default::default()
                },
            }],
        };

        let error = config
            .execute(&[
                "run".to_owned(),
                "--name".to_owned(),
                "openclaw-agent-devy".to_owned(),
                "--label".to_owned(),
                "openclaw.agent=devy".to_owned(),
                "ghcr.io/openclaw/agent:latest".to_owned(),
                "sleep".to_owned(),
                "1".to_owned(),
            ])
            .unwrap_err();

        assert!(error.to_string().contains("must use --detach"));
    }

    #[test]
    fn selector_matches_on_name_label_and_env() {
        let spec = DockerCreateSpec {
            name: Some("openclaw-agent-devy".to_owned()),
            image: "ghcr.io/openclaw/agent:latest".to_owned(),
            labels: BTreeMap::from([("openclaw.agent".to_owned(), "devy".to_owned())]),
            env: BTreeMap::from([("OPENCLAW_SESSION_ID".to_owned(), "session-1".to_owned())]),
            tmpfs_mounts: Vec::new(),
            detach: false,
            remove_after_exit: false,
        };
        let selector = DockerContainerSelector {
            name_prefix: Some("openclaw-agent-".to_owned()),
            image: Some("ghcr.io/openclaw/agent:latest".to_owned()),
            labels: BTreeMap::from([("openclaw.agent".to_owned(), "devy".to_owned())]),
            env: BTreeMap::from([("OPENCLAW_SESSION_ID".to_owned(), "session-1".to_owned())]),
        };

        assert!(selector.matches(&spec));
    }

    #[test]
    fn create_output_aliases_include_name_and_container_id() {
        let spec = DockerCreateSpec {
            name: Some("sandbox-123".to_owned()),
            image: "image".to_owned(),
            labels: BTreeMap::new(),
            env: BTreeMap::new(),
            tmpfs_mounts: Vec::new(),
            detach: false,
            remove_after_exit: false,
        };

        let aliases = container_aliases_for_create(false, &spec, b"1234567890\n").unwrap();

        assert_eq!(
            aliases,
            vec!["1234567890".to_owned(), "sandbox-123".to_owned()]
        );
    }

    #[test]
    fn bridge_config_validates_release_shape() {
        let config = DockerBridgeConfig {
            version: 1,
            gloves_root: PathBuf::from("/tmp/gloves"),
            runtime_root: PathBuf::from("/tmp/runtime"),
            gloves_bin: None,
            docker_bin: Some(PathBuf::from("/usr/bin/docker")),
            audit_agent: Some("openclaw".to_owned()),
            secret_mount_root: "/run/secrets".to_owned(),
            tmpfs_spec: "/run/secrets:size=1M,mode=0700".to_owned(),
            targets: vec![DockerSecretTarget {
                secret_ref: "gloves://agents/devy/api-keys/openai".parse().unwrap(),
                container_path: "/run/secrets/openai".to_owned(),
                agent_id: None,
                selector: DockerContainerSelector {
                    labels: BTreeMap::from([("openclaw.agent".to_owned(), "devy".to_owned())]),
                    ..Default::default()
                },
            }],
        };

        assert!(config.validate().is_ok());
    }
}
