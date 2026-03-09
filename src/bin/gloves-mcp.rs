use std::{
    collections::BTreeSet,
    env,
    fs::{self, OpenOptions},
    io::{self, BufRead, BufReader, Write},
    path::{Component, Path, PathBuf},
    thread,
    time::{Duration as StdDuration, Instant},
};

use chrono::{DateTime, Duration, Utc};
use clap::Parser;
use ed25519_dalek::SigningKey;
use gloves::{
    agent::age_crypto,
    error::{GlovesError, Result},
    fs_secure::{ensure_private_dir, write_private_file_atomic},
    human::pending::PendingRequestStore,
    types::{AgentId, RequestStatus, SecretId},
};
use rand::{Rng, RngExt};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use uuid::Uuid;

const JSON_RPC_VERSION: &str = "2.0";
const MCP_PROTOCOL_VERSION: &str = "2025-06-18";
const AUTH_FAILED_CODE: i64 = -32001;
const APPROVAL_DENIED_CODE: i64 = -32002;
const APPROVAL_TIMEOUT_CODE: i64 = -32003;
const SECRET_NOT_FOUND_CODE: i64 = -32004;
const PERMISSION_DENIED_CODE: i64 = -32005;
const IDENTITY_ERROR_CODE: i64 = -32008;
const CRYPTO_ERROR_CODE: i64 = -32009;
const INVALID_PARAMS_CODE: i64 = -32602;
const INTERNAL_ERROR_CODE: i64 = -32603;
const SESSION_TOKEN_BYTES: usize = 32;
const DEFAULT_APPROVAL_TIMEOUT_SECONDS: u64 = 120;
const APPROVAL_POLL_INTERVAL_MILLIS: u64 = 25;
const RULES_FILE_NAME: &str = ".gloves.yaml";
const RECIPIENTS_FILE_NAME: &str = ".age-recipients";
const PENDING_REQUESTS_FILE_NAME: &str = ".gloves-pending.json";
const TOOLS_LIST_METHOD: &str = "tools/list";
const TOOLS_CALL_METHOD: &str = "tools/call";
const INITIALIZE_METHOD: &str = "initialize";
const INITIALIZED_NOTIFICATION_METHOD: &str = "notifications/initialized";
const GLOVES_LIST_TOOL: &str = "gloves_list";
const GLOVES_SHOW_TOOL: &str = "gloves_show";
const GLOVES_GET_TOOL: &str = "gloves_get";
const GLOVES_SET_TOOL: &str = "gloves_set";
const GLOVES_DELETE_TOOL: &str = "gloves_delete";
const GLOVES_APPROVE_TOOL: &str = "gloves_approve";
const SESSION_TOKEN_ENV_VAR: &str = "GLOVES_SESSION_TOKEN_PATH";
const HOME_ENV_VAR: &str = "HOME";
const STORE_SECTION_DEFAULT: &str = "store";
const IDENTITIES_SECTION_DEFAULT: &str = "identities";
const AUDIT_SECTION_DEFAULT: &str = "audit";

#[derive(Debug, Parser)]
#[command(
    name = "gloves-mcp",
    version,
    about = "MCP bridge for namespaced gloves secrets"
)]
struct Cli {
    /// Path to the MCP configuration file.
    #[arg(long)]
    config: PathBuf,
    /// Fallback agent id when initialize metadata omits `agentId`.
    #[arg(long)]
    agent: Option<String>,
}

#[derive(Debug, Deserialize)]
struct McpConfigFile {
    #[serde(default)]
    daemon: DaemonSection,
    #[serde(default)]
    store: StoreSection,
    #[serde(default)]
    identities: OptionalPathSection,
    #[serde(default)]
    audit: OptionalPathSection,
}

#[derive(Debug, Default, Deserialize)]
struct DaemonSection {
    session_token_path: Option<String>,
    #[serde(default)]
    approval: DaemonApprovalSection,
}

#[derive(Debug, Default, Deserialize)]
struct DaemonApprovalSection {
    default_channel: Option<String>,
    timeout_seconds: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct StoreSection {
    path: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct OptionalPathSection {
    path: Option<String>,
}

#[derive(Debug, Clone)]
struct ResolvedConfig {
    store_path: PathBuf,
    identities_path: PathBuf,
    audit_path: PathBuf,
    session_token_path: PathBuf,
    approval_channel: ApprovalChannel,
    approval_timeout_seconds: u64,
}

#[derive(Debug, Clone)]
struct SessionContext {
    agent_id: AgentId,
    agent_recipient: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApprovalChannel {
    Auto,
    Tty,
    Webhook,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApprovalTier {
    Auto,
    Human,
    Deny,
}

#[derive(Debug, Clone, Copy)]
struct ApprovalResolution {
    status: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecretMetadataRecord {
    name: String,
    length: usize,
    created: DateTime<Utc>,
    modified: DateTime<Utc>,
    last_rotated: DateTime<Utc>,
    last_accessed: Option<DateTime<Utc>>,
    agent: String,
    encrypted_to: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct CreationRulesFile {
    #[serde(default, rename = "version")]
    _version: Option<u32>,
    #[serde(default)]
    creation_rules: Vec<CreationRule>,
}

#[derive(Debug, Clone, Deserialize)]
struct CreationRule {
    path_regex: String,
    #[serde(default)]
    age: Option<RecipientList>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum RecipientList {
    Csv(String),
    List(Vec<String>),
}

impl RecipientList {
    fn values(&self) -> Vec<String> {
        match self {
            Self::Csv(value) => value
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(str::to_owned)
                .collect(),
            Self::List(values) => values
                .iter()
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
struct ListSecretsResult {
    secrets: Vec<String>,
    count: usize,
}

#[derive(Debug, Serialize)]
struct ShowSecretResult {
    name: String,
    exists: bool,
    length: usize,
    agent: String,
    encrypted_to: Vec<String>,
    created: DateTime<Utc>,
    modified: DateTime<Utc>,
    last_rotated: DateTime<Utc>,
    last_accessed: Option<DateTime<Utc>>,
    file_size: u64,
}

#[derive(Debug, Serialize)]
struct GetSecretResult {
    path: String,
    agent: String,
    injected: bool,
    inject_method: &'static str,
    secret_length: usize,
    approval_status: &'static str,
}

#[derive(Debug, Serialize)]
struct SetSecretResult {
    path: String,
    agent: String,
    recipient_count: usize,
    approval_status: &'static str,
}

#[derive(Debug, Serialize)]
struct ApprovalResult {
    request_id: String,
    decision: String,
    reviewer: String,
}

#[derive(Debug, Serialize)]
struct AuditRecord<'a> {
    version: u8,
    timestamp: DateTime<Utc>,
    event_type: &'a str,
    agent_id: Option<&'a str>,
    tool: Option<&'a str>,
    path: Option<&'a str>,
    result: &'a str,
    error: Option<&'a str>,
}

fn main() {
    if let Err(error) = run() {
        let _ = writeln!(io::stderr(), "{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let config = ResolvedConfig::load(&cli.config)?;
    ensure_private_dir(&config.audit_path)?;
    let session_token = write_session_token(&config.session_token_path)?;
    append_audit_record(
        &config,
        AuditRecord {
            version: 1,
            timestamp: Utc::now(),
            event_type: "daemon_start",
            agent_id: cli.agent.as_deref(),
            tool: None,
            path: None,
            result: "started",
            error: None,
        },
    )?;

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = stdout.lock();
    let session = match authenticate_session(
        &mut reader,
        &mut writer,
        &config,
        &session_token,
        cli.agent.as_deref(),
    )? {
        Some(session) => session,
        None => return Ok(()),
    };

    serve_session(&mut reader, &mut writer, &config, &session)
}

impl ResolvedConfig {
    fn load(config_path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(config_path)?;
        let parsed = toml::from_str::<McpConfigFile>(&raw).map_err(|error| {
            GlovesError::InvalidInput(format!("invalid gloves-mcp config: {error}"))
        })?;
        let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
        let store_path = resolve_config_path(
            parsed.store.path.as_deref(),
            config_dir,
            Some(STORE_SECTION_DEFAULT),
            "store.path",
        )?;
        let identities_path = resolve_config_path(
            parsed.identities.path.as_deref(),
            config_dir,
            Some(IDENTITIES_SECTION_DEFAULT),
            "identities.path",
        )?;
        let audit_path = resolve_config_path(
            parsed.audit.path.as_deref(),
            config_dir,
            Some(AUDIT_SECTION_DEFAULT),
            "audit.path",
        )?;
        let session_token_path = resolve_config_path(
            env::var(SESSION_TOKEN_ENV_VAR)
                .ok()
                .as_deref()
                .or(parsed.daemon.session_token_path.as_deref()),
            config_dir,
            None,
            "daemon.session_token_path",
        )?;
        let approval_channel = ApprovalChannel::parse(
            parsed
                .daemon
                .approval
                .default_channel
                .as_deref()
                .unwrap_or("auto"),
        )?;
        let approval_timeout_seconds = parsed
            .daemon
            .approval
            .timeout_seconds
            .unwrap_or(DEFAULT_APPROVAL_TIMEOUT_SECONDS);

        Ok(Self {
            store_path,
            identities_path,
            audit_path,
            session_token_path,
            approval_channel,
            approval_timeout_seconds,
        })
    }
}

impl ApprovalChannel {
    fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "tty" => Ok(Self::Tty),
            "webhook" => Ok(Self::Webhook),
            other => Err(GlovesError::InvalidInput(format!(
                "unsupported approval channel `{other}`"
            ))),
        }
    }
}

fn authenticate_session<R, W>(
    reader: &mut R,
    writer: &mut W,
    config: &ResolvedConfig,
    session_token: &str,
    fallback_agent: Option<&str>,
) -> Result<Option<SessionContext>>
where
    R: BufRead,
    W: Write,
{
    let Some(request) = read_json_line(reader)? else {
        return Ok(None);
    };
    let request_id = request.get("id").cloned().unwrap_or(Value::Null);
    if request.get("method").and_then(Value::as_str) != Some(INITIALIZE_METHOD) {
        write_error_response(
            writer,
            request_id,
            AUTH_FAILED_CODE,
            "Session authentication failed",
            json!({ "reason": "missing_initialize" }),
        )?;
        append_audit_record(
            config,
            AuditRecord {
                version: 1,
                timestamp: Utc::now(),
                event_type: "auth_failure",
                agent_id: fallback_agent,
                tool: None,
                path: None,
                result: "denied",
                error: Some("missing_initialize"),
            },
        )?;
        return Ok(None);
    }

    let params = request
        .get("params")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            GlovesError::InvalidInput("initialize params must be an object".to_owned())
        })?;
    let meta = params
        .get("_meta")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            GlovesError::InvalidInput("initialize params must include _meta".to_owned())
        })?;
    let provided_token = meta
        .get("sessionToken")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if provided_token != session_token {
        write_error_response(
            writer,
            request_id,
            AUTH_FAILED_CODE,
            "Session authentication failed",
            json!({ "reason": "invalid_token" }),
        )?;
        append_audit_record(
            config,
            AuditRecord {
                version: 1,
                timestamp: Utc::now(),
                event_type: "auth_failure",
                agent_id: fallback_agent,
                tool: None,
                path: None,
                result: "denied",
                error: Some("invalid_token"),
            },
        )?;
        return Ok(None);
    }

    let requested_agent = meta
        .get("agentId")
        .and_then(Value::as_str)
        .or(fallback_agent)
        .ok_or_else(|| {
            GlovesError::InvalidInput("initialize params must include agentId".to_owned())
        })?;
    let agent_id = AgentId::new(requested_agent)?;
    let agent_recipient = load_agent_recipient(config, &agent_id)?;

    write_result_response(
        writer,
        request_id,
        json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {
                "tools": {
                    "listChanged": false
                }
            },
            "serverInfo": {
                "name": "gloves-mcp",
                "version": env!("CARGO_PKG_VERSION")
            }
        }),
    )?;

    Ok(Some(SessionContext {
        agent_id,
        agent_recipient,
    }))
}

fn serve_session<R, W>(
    reader: &mut R,
    writer: &mut W,
    config: &ResolvedConfig,
    session: &SessionContext,
) -> Result<()>
where
    R: BufRead,
    W: Write,
{
    while let Some(request) = read_json_line(reader)? {
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if method == INITIALIZED_NOTIFICATION_METHOD {
            continue;
        }

        let request_id = request.get("id").cloned().unwrap_or(Value::Null);
        match method {
            TOOLS_LIST_METHOD => {
                let result = json!({
                    "tools": tool_definitions()
                });
                write_result_response(writer, request_id, result)?;
            }
            TOOLS_CALL_METHOD => {
                let response = handle_tool_call(config, session, request.get("params"));
                match response {
                    Ok(result) => write_result_response(writer, request_id, result)?,
                    Err((code, message, data)) => {
                        write_error_response(writer, request_id, code, message, data)?
                    }
                }
            }
            _ => {
                write_error_response(
                    writer,
                    request_id,
                    INTERNAL_ERROR_CODE,
                    "Unsupported method",
                    json!({ "method": method }),
                )?;
            }
        }
    }

    Ok(())
}

fn handle_tool_call(
    config: &ResolvedConfig,
    session: &SessionContext,
    params: Option<&Value>,
) -> std::result::Result<Value, (i64, &'static str, Value)> {
    let params = params
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_params_error("tool call params must be an object"))?;
    let tool_name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_params_error("tool call params must include `name`"))?;
    let arguments = params
        .get("arguments")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    match tool_name {
        GLOVES_LIST_TOOL => handle_list_tool(config, session, &arguments),
        GLOVES_SHOW_TOOL => handle_show_tool(config, session, &arguments),
        GLOVES_GET_TOOL => handle_get_tool(config, session, &arguments),
        GLOVES_SET_TOOL => handle_set_tool(config, session, &arguments),
        GLOVES_DELETE_TOOL => handle_delete_tool(config, session, &arguments),
        GLOVES_APPROVE_TOOL => handle_approve_tool(config, session, &arguments),
        _ => Err((
            INTERNAL_ERROR_CODE,
            "Unsupported tool",
            json!({ "tool": tool_name }),
        )),
    }
}

fn handle_list_tool(
    config: &ResolvedConfig,
    session: &SessionContext,
    arguments: &Map<String, Value>,
) -> std::result::Result<Value, (i64, &'static str, Value)> {
    let prefix = optional_string_argument(arguments, "prefix")?;
    let secrets =
        list_visible_secret_names(config, session, prefix.as_deref()).map_err(map_runtime_error)?;
    let payload = ListSecretsResult {
        count: secrets.len(),
        secrets,
    };
    append_audit_record(
        config,
        AuditRecord {
            version: 1,
            timestamp: Utc::now(),
            event_type: "secret_list",
            agent_id: Some(session.agent_id.as_str()),
            tool: Some(GLOVES_LIST_TOOL),
            path: prefix.as_deref(),
            result: "approved",
            error: None,
        },
    )
    .map_err(|_| internal_error("failed to write audit log"))?;

    Ok(tool_success_response(
        format!("Listed {} visible secrets", payload.count),
        serde_json::to_value(payload)
            .map_err(|_| internal_error("failed to serialize list result"))?,
    ))
}

fn handle_show_tool(
    config: &ResolvedConfig,
    session: &SessionContext,
    arguments: &Map<String, Value>,
) -> std::result::Result<Value, (i64, &'static str, Value)> {
    let path = required_string_argument(arguments, "path")?;
    let show_result = show_secret(config, &path).map_err(map_runtime_error)?;
    append_audit_record(
        config,
        AuditRecord {
            version: 1,
            timestamp: Utc::now(),
            event_type: "secret_list",
            agent_id: Some(session.agent_id.as_str()),
            tool: Some(GLOVES_SHOW_TOOL),
            path: Some(&path),
            result: "approved",
            error: None,
        },
    )
    .map_err(|_| internal_error("failed to write audit log"))?;

    Ok(tool_success_response(
        format!("Metadata for `{path}` loaded"),
        serde_json::to_value(show_result)
            .map_err(|_| internal_error("failed to serialize show result"))?,
    ))
}

fn handle_get_tool(
    config: &ResolvedConfig,
    session: &SessionContext,
    arguments: &Map<String, Value>,
) -> std::result::Result<Value, (i64, &'static str, Value)> {
    let path = required_string_argument(arguments, "path")?;
    let approval = resolve_approval(config, session, GLOVES_GET_TOOL, &path)?;
    let get_result = get_secret(config, session, &path, approval).map_err(map_runtime_error)?;
    append_audit_record(
        config,
        AuditRecord {
            version: 1,
            timestamp: Utc::now(),
            event_type: "secret_access",
            agent_id: Some(session.agent_id.as_str()),
            tool: Some(GLOVES_GET_TOOL),
            path: Some(&path),
            result: "approved",
            error: None,
        },
    )
    .map_err(|_| internal_error("failed to write audit log"))?;

    Ok(tool_success_response(
        format!(
            "Secret '{}' ({} chars) injected as {}",
            get_result.path, get_result.secret_length, path
        ),
        serde_json::to_value(get_result)
            .map_err(|_| internal_error("failed to serialize get result"))?,
    ))
}

fn handle_set_tool(
    config: &ResolvedConfig,
    session: &SessionContext,
    arguments: &Map<String, Value>,
) -> std::result::Result<Value, (i64, &'static str, Value)> {
    let path = required_string_argument(arguments, "path")?;
    let from_env = required_string_argument(arguments, "from_env")?;
    let approval = resolve_approval(config, session, GLOVES_SET_TOOL, &path)?;
    let secret_value = env::var(&from_env).map_err(|_| {
        invalid_params_error(&format!(
            "environment variable `{from_env}` is not set for `gloves_set`"
        ))
    })?;
    let set_result = set_secret_value(config, session, &path, secret_value.as_bytes(), approval)
        .map_err(map_runtime_error)?;
    append_audit_record(
        config,
        AuditRecord {
            version: 1,
            timestamp: Utc::now(),
            event_type: "secret_write",
            agent_id: Some(session.agent_id.as_str()),
            tool: Some(GLOVES_SET_TOOL),
            path: Some(&path),
            result: "approved",
            error: None,
        },
    )
    .map_err(|_| internal_error("failed to write audit log"))?;

    Ok(tool_success_response(
        format!("Stored secret `{path}`"),
        serde_json::to_value(set_result)
            .map_err(|_| internal_error("failed to serialize set result"))?,
    ))
}

fn handle_delete_tool(
    config: &ResolvedConfig,
    session: &SessionContext,
    arguments: &Map<String, Value>,
) -> std::result::Result<Value, (i64, &'static str, Value)> {
    let path = required_string_argument(arguments, "path")?;
    resolve_approval(config, session, GLOVES_DELETE_TOOL, &path)?;
    Err((
        APPROVAL_DENIED_CODE,
        "Operation denied",
        json!({ "reason": "destructive_operations_denied" }),
    ))
}

fn handle_approve_tool(
    config: &ResolvedConfig,
    session: &SessionContext,
    arguments: &Map<String, Value>,
) -> std::result::Result<Value, (i64, &'static str, Value)> {
    let request_id = required_string_argument(arguments, "request_id")?;
    let decision = required_string_argument(arguments, "decision")?;
    let parsed_request_id = request_id
        .parse::<Uuid>()
        .map_err(|_| invalid_params_error("`request_id` must be a valid UUID"))?;
    let store = pending_request_store(config).map_err(map_runtime_error)?;
    match decision.as_str() {
        "approve" => {
            store
                .approve(parsed_request_id, session.agent_id.clone())
                .map_err(map_runtime_error)?;
        }
        "deny" => {
            store
                .deny(parsed_request_id, session.agent_id.clone())
                .map_err(map_runtime_error)?;
        }
        _ => {
            return Err(invalid_params_error(
                "`decision` must be `approve` or `deny`",
            ))
        }
    }

    append_audit_record(
        config,
        AuditRecord {
            version: 1,
            timestamp: Utc::now(),
            event_type: "approval_decision",
            agent_id: Some(session.agent_id.as_str()),
            tool: Some(GLOVES_APPROVE_TOOL),
            path: Some(&request_id),
            result: decision.as_str(),
            error: None,
        },
    )
    .map_err(|_| internal_error("failed to write audit log"))?;

    Ok(tool_success_response(
        format!("Request `{request_id}` {decision}d"),
        serde_json::to_value(ApprovalResult {
            request_id,
            decision,
            reviewer: session.agent_id.as_str().to_owned(),
        })
        .map_err(|_| internal_error("failed to serialize approval result"))?,
    ))
}

fn get_secret(
    config: &ResolvedConfig,
    session: &SessionContext,
    path: &str,
    approval: ApprovalResolution,
) -> Result<GetSecretResult> {
    let secret_id = SecretId::new(path)?;
    let mut metadata = read_secret_metadata(config, secret_id.as_str())?;
    if !metadata
        .encrypted_to
        .iter()
        .any(|recipient| recipient == &session.agent_recipient)
    {
        return Err(GlovesError::Unauthorized);
    }

    let plaintext = age_crypto::decrypt_file(
        &secret_ciphertext_path(config, secret_id.as_str()),
        &identity_path(config, &session.agent_id),
    )?;
    let accessed_at = Utc::now();
    metadata.last_accessed = Some(accessed_at);
    write_secret_metadata(config, secret_id.as_str(), &metadata)?;

    Ok(GetSecretResult {
        path: secret_id.as_str().to_owned(),
        agent: session.agent_id.as_str().to_owned(),
        injected: true,
        inject_method: "env",
        secret_length: plaintext.len(),
        approval_status: approval.status,
    })
}

fn set_secret_value(
    config: &ResolvedConfig,
    session: &SessionContext,
    path: &str,
    value: &[u8],
    approval: ApprovalResolution,
) -> Result<SetSecretResult> {
    ensure_private_dir(&config.store_path)?;
    ensure_private_dir(&metadata_root(config))?;

    let secret_id = SecretId::new(path)?;
    let namespace = namespace_for_secret_path(secret_id.as_str())?;
    let recipients = resolve_recipients(config, secret_id.as_str(), &namespace)?;
    write_namespace_recipients(config, &namespace, &recipients, false)?;

    let ciphertext = age_crypto::encrypt_for_recipients(value, &recipients)?;
    write_private_file_atomic(
        &secret_ciphertext_path(config, secret_id.as_str()),
        &ciphertext,
    )?;

    let now = Utc::now();
    let created = match read_secret_metadata(config, secret_id.as_str()) {
        Ok(existing) => existing.created,
        Err(GlovesError::NotFound) => now,
        Err(error) => return Err(error),
    };
    let metadata = SecretMetadataRecord {
        name: secret_id.as_str().to_owned(),
        length: value.len(),
        created,
        modified: now,
        last_rotated: now,
        last_accessed: None,
        agent: scope_agent(secret_id.as_str()),
        encrypted_to: recipients.clone(),
    };
    write_secret_metadata(config, secret_id.as_str(), &metadata)?;

    Ok(SetSecretResult {
        path: secret_id.as_str().to_owned(),
        agent: session.agent_id.as_str().to_owned(),
        recipient_count: recipients.len(),
        approval_status: approval.status,
    })
}

fn show_secret(config: &ResolvedConfig, path: &str) -> Result<ShowSecretResult> {
    let secret_id = SecretId::new(path)?;
    let metadata = read_secret_metadata(config, secret_id.as_str())?;
    let file_size = fs::metadata(secret_ciphertext_path(config, secret_id.as_str()))?.len();

    Ok(ShowSecretResult {
        name: metadata.name,
        exists: true,
        length: metadata.length,
        agent: metadata.agent,
        encrypted_to: metadata.encrypted_to,
        created: metadata.created,
        modified: metadata.modified,
        last_rotated: metadata.last_rotated,
        last_accessed: metadata.last_accessed,
        file_size,
    })
}

fn list_visible_secret_names(
    config: &ResolvedConfig,
    session: &SessionContext,
    prefix: Option<&str>,
) -> Result<Vec<String>> {
    let mut pending = vec![config.store_path.clone()];
    let metadata_root = metadata_root(config);
    let normalized_prefix = prefix.map(|value| value.trim_matches('/').to_owned());
    let mut secrets = Vec::new();

    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let path = entry?.path();
            if path == metadata_root {
                continue;
            }
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            if path.extension().and_then(|value| value.to_str()) != Some("age") {
                continue;
            }

            let relative = path
                .strip_prefix(&config.store_path)
                .map_err(|error| GlovesError::InvalidInput(error.to_string()))?;
            let mut secret_path = relative.to_path_buf();
            secret_path.set_extension("");
            let secret_name = secret_path.to_string_lossy().replace('\\', "/");
            if normalized_prefix
                .as_ref()
                .is_some_and(|candidate| !secret_name.starts_with(candidate))
            {
                continue;
            }

            let metadata = read_secret_metadata(config, &secret_name)?;
            if metadata
                .encrypted_to
                .iter()
                .any(|recipient| recipient == &session.agent_recipient)
            {
                secrets.push(secret_name);
            }
        }
    }

    secrets.sort();
    Ok(secrets)
}

fn resolve_approval(
    config: &ResolvedConfig,
    session: &SessionContext,
    tool_name: &str,
    path: &str,
) -> std::result::Result<ApprovalResolution, (i64, &'static str, Value)> {
    match approval_tier_for_tool(tool_name) {
        ApprovalTier::Auto => Ok(ApprovalResolution { status: "auto" }),
        ApprovalTier::Deny => {
            append_audit_record(
                config,
                AuditRecord {
                    version: 1,
                    timestamp: Utc::now(),
                    event_type: "approval_denied",
                    agent_id: Some(session.agent_id.as_str()),
                    tool: Some(tool_name),
                    path: Some(path),
                    result: "denied",
                    error: Some("destructive_operations_denied"),
                },
            )
            .map_err(|_| internal_error("failed to write audit log"))?;
            Err((
                APPROVAL_DENIED_CODE,
                "Operation denied",
                json!({ "reason": "destructive_operations_denied" }),
            ))
        }
        ApprovalTier::Human => match config.approval_channel {
            ApprovalChannel::Auto => Ok(ApprovalResolution { status: "auto" }),
            ApprovalChannel::Tty | ApprovalChannel::Webhook => {
                wait_for_external_approval(config, session, tool_name, path)
            }
        },
    }
}

fn approval_tier_for_tool(tool_name: &str) -> ApprovalTier {
    match tool_name {
        GLOVES_LIST_TOOL | GLOVES_SHOW_TOOL | GLOVES_APPROVE_TOOL => ApprovalTier::Auto,
        GLOVES_GET_TOOL | GLOVES_SET_TOOL => ApprovalTier::Human,
        GLOVES_DELETE_TOOL => ApprovalTier::Deny,
        _ => ApprovalTier::Deny,
    }
}

fn wait_for_external_approval(
    config: &ResolvedConfig,
    session: &SessionContext,
    tool_name: &str,
    path: &str,
) -> std::result::Result<ApprovalResolution, (i64, &'static str, Value)> {
    let store = pending_request_store(config).map_err(map_runtime_error)?;
    let signing_key = generate_signing_key();
    let request = store
        .create(
            SecretId::new(path)
                .map_err(GlovesError::from)
                .map_err(map_runtime_error)?,
            session.agent_id.clone(),
            format!("{tool_name}:{path}"),
            Duration::seconds(config.approval_timeout_seconds as i64),
            &signing_key,
        )
        .map_err(map_runtime_error)?;

    let _ = writeln!(
        io::stderr(),
        "approval required: request_id={} tool={} agent={} path={}",
        request.id,
        tool_name,
        session.agent_id.as_str(),
        path
    );
    append_audit_record(
        config,
        AuditRecord {
            version: 1,
            timestamp: Utc::now(),
            event_type: "approval_requested",
            agent_id: Some(session.agent_id.as_str()),
            tool: Some(tool_name),
            path: Some(path),
            result: "pending",
            error: None,
        },
    )
    .map_err(|_| internal_error("failed to write audit log"))?;

    let deadline = Instant::now() + StdDuration::from_secs(config.approval_timeout_seconds);
    loop {
        let requests = store.load_all().map_err(map_runtime_error)?;
        if let Some(pending_request) = requests.into_iter().find(|entry| entry.id == request.id) {
            match pending_request.status {
                RequestStatus::Fulfilled => {
                    return Ok(ApprovalResolution { status: "approved" });
                }
                RequestStatus::Denied => {
                    return Err((
                        APPROVAL_DENIED_CODE,
                        "Approval denied",
                        json!({ "reason": "request_denied", "request_id": request.id.to_string() }),
                    ));
                }
                RequestStatus::Expired => {
                    return Err((
                        APPROVAL_TIMEOUT_CODE,
                        "Approval timeout",
                        json!({ "reason": "request_expired", "request_id": request.id.to_string() }),
                    ));
                }
                RequestStatus::Pending => {}
            }
        }

        if Instant::now() >= deadline {
            return Err((
                APPROVAL_TIMEOUT_CODE,
                "Approval timeout",
                json!({ "reason": "approval_timeout", "request_id": request.id.to_string() }),
            ));
        }
        thread::sleep(StdDuration::from_millis(APPROVAL_POLL_INTERVAL_MILLIS));
    }
}

fn pending_request_store(config: &ResolvedConfig) -> Result<PendingRequestStore> {
    PendingRequestStore::new(pending_requests_path(config))
}

fn pending_requests_path(config: &ResolvedConfig) -> PathBuf {
    config.store_path.join(PENDING_REQUESTS_FILE_NAME)
}

fn generate_signing_key() -> SigningKey {
    let mut key_bytes = [0_u8; 32];
    rand::rng().fill(&mut key_bytes);
    SigningKey::from_bytes(&key_bytes)
}

fn resolve_recipients(
    config: &ResolvedConfig,
    secret_path: &str,
    namespace: &Path,
) -> Result<Vec<String>> {
    let rules = load_creation_rules(config)?;
    let explicit_recipients = rules
        .creation_rules
        .into_iter()
        .find_map(|rule| {
            let regex = Regex::new(&rule.path_regex).ok()?;
            regex
                .is_match(secret_path)
                .then(|| rule.age.map(|entry| entry.values()).unwrap_or_default())
        })
        .ok_or_else(|| {
            GlovesError::InvalidInput(format!("no matching creation rule for path {secret_path}"))
        })?;
    let namespace_recipients = read_namespace_recipients(config, namespace)?;
    Ok(explicit_recipients
        .into_iter()
        .chain(namespace_recipients)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

fn load_creation_rules(config: &ResolvedConfig) -> Result<CreationRulesFile> {
    let rules_path = config.store_path.join(RULES_FILE_NAME);
    let raw = fs::read_to_string(&rules_path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            GlovesError::InvalidInput(format!(
                "creation rules not found: {}",
                rules_path.display()
            ))
        } else {
            GlovesError::Io(error)
        }
    })?;
    serde_yaml::from_str(&raw)
        .map_err(|error| GlovesError::InvalidInput(format!("invalid creation rules: {error}")))
}

fn write_namespace_recipients(
    config: &ResolvedConfig,
    namespace: &Path,
    recipients: &[String],
    replace: bool,
) -> Result<()> {
    let existing = if replace {
        Vec::new()
    } else {
        read_namespace_recipients(config, namespace)?
    };
    let merged = existing
        .into_iter()
        .chain(recipients.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let contents = if merged.is_empty() {
        String::new()
    } else {
        format!("{}\n", merged.join("\n"))
    };
    write_private_file_atomic(
        &namespace_recipients_file(config, namespace),
        contents.as_bytes(),
    )
}

fn read_namespace_recipients(config: &ResolvedConfig, namespace: &Path) -> Result<Vec<String>> {
    let raw = fs::read_to_string(namespace_recipients_file(config, namespace)).unwrap_or_default();
    Ok(raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect())
}

fn namespace_recipients_file(config: &ResolvedConfig, namespace: &Path) -> PathBuf {
    config.store_path.join(namespace).join(RECIPIENTS_FILE_NAME)
}

fn namespace_for_secret_path(secret_path: &str) -> Result<PathBuf> {
    let relative_path = validated_relative_path(secret_path)?;
    let mut components = relative_path.components();
    let first = match components.next() {
        Some(Component::Normal(value)) => value.to_string_lossy().to_string(),
        _ => {
            return Err(GlovesError::InvalidInput(
                "secret path must not be empty".to_owned(),
            ))
        }
    };
    if first == "agents" {
        let second = match components.next() {
            Some(Component::Normal(value)) => value.to_string_lossy().to_string(),
            _ => {
                return Err(GlovesError::InvalidInput(format!(
                    "agent namespace is missing in {secret_path}"
                )))
            }
        };
        return Ok(PathBuf::from(first).join(second));
    }
    Ok(PathBuf::from(first))
}

fn validated_relative_path(secret_path: &str) -> Result<PathBuf> {
    let secret_id = SecretId::new(secret_path)?;
    let relative_path = PathBuf::from(secret_id.as_str());
    if relative_path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(GlovesError::InvalidInput(format!(
            "path traversal is not allowed: {secret_path}"
        )));
    }
    Ok(relative_path)
}

fn scope_agent(secret_path: &str) -> String {
    let parts = Path::new(secret_path)
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().to_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    if parts.first().map(String::as_str) == Some("agents") && parts.len() >= 2 {
        return parts[1].clone();
    }
    parts
        .first()
        .cloned()
        .unwrap_or_else(|| "unknown".to_owned())
}

fn load_agent_recipient(config: &ResolvedConfig, agent_id: &AgentId) -> Result<String> {
    let identity = identity_path(config, agent_id);
    if !identity.exists() {
        return Err(GlovesError::InvalidInput(format!(
            "identity file not found: {}",
            identity.display()
        )));
    }
    age_crypto::recipient_from_identity_file(&identity)
}

fn read_secret_metadata(
    config: &ResolvedConfig,
    secret_path: &str,
) -> Result<SecretMetadataRecord> {
    let metadata_path = secret_metadata_path(config, secret_path);
    let bytes = fs::read(&metadata_path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            GlovesError::NotFound
        } else {
            GlovesError::Io(error)
        }
    })?;
    serde_json::from_slice(&bytes).map_err(GlovesError::from)
}

fn write_secret_metadata(
    config: &ResolvedConfig,
    secret_path: &str,
    metadata: &SecretMetadataRecord,
) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(metadata)?;
    write_private_file_atomic(&secret_metadata_path(config, secret_path), &bytes)
}

fn secret_ciphertext_path(config: &ResolvedConfig, secret_path: &str) -> PathBuf {
    config.store_path.join(format!("{secret_path}.age"))
}

fn secret_metadata_path(config: &ResolvedConfig, secret_path: &str) -> PathBuf {
    metadata_root(config).join(format!("{secret_path}.json"))
}

fn metadata_root(config: &ResolvedConfig) -> PathBuf {
    config.store_path.join(".gloves-meta")
}

fn identity_path(config: &ResolvedConfig, agent_id: &AgentId) -> PathBuf {
    config
        .identities_path
        .join(format!("{}.age", agent_id.as_str()))
}

fn resolve_config_path(
    configured_value: Option<&str>,
    config_dir: &Path,
    default_child: Option<&str>,
    field_name: &str,
) -> Result<PathBuf> {
    let raw = if let Some(value) = configured_value {
        value.to_owned()
    } else if let Some(child) = default_child {
        config_dir.join(child).display().to_string()
    } else {
        return Err(GlovesError::InvalidInput(format!(
            "missing required configuration field `{field_name}`"
        )));
    };

    let expanded = expand_tilde(&raw)?;
    let path = PathBuf::from(expanded);
    if path.is_absolute() {
        return Ok(path);
    }
    Ok(config_dir.join(path))
}

fn expand_tilde(value: &str) -> Result<String> {
    if value == "~" {
        return env::var(HOME_ENV_VAR)
            .map_err(|_| GlovesError::InvalidInput("HOME must be set to expand `~`".to_owned()));
    }
    if let Some(rest) = value.strip_prefix("~/") {
        let home = env::var(HOME_ENV_VAR)
            .map_err(|_| GlovesError::InvalidInput("HOME must be set to expand `~`".to_owned()))?;
        return Ok(Path::new(&home).join(rest).display().to_string());
    }
    Ok(value.to_owned())
}

fn write_session_token(token_path: &Path) -> Result<String> {
    if let Some(parent) = token_path.parent() {
        ensure_private_dir(parent)?;
    }
    let mut bytes = [0_u8; SESSION_TOKEN_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    let token = hex_encode(&bytes);
    write_private_file_atomic(token_path, token.as_bytes())?;
    Ok(token)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn append_audit_record(config: &ResolvedConfig, record: AuditRecord<'_>) -> Result<()> {
    ensure_private_dir(&config.audit_path)?;
    let audit_file = config
        .audit_path
        .join(format!("{}.jsonl", Utc::now().format("%Y-%m-%d")));
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(audit_file)?;
    let payload = serde_json::to_vec(&record)?;
    file.write_all(&payload)?;
    file.write_all(b"\n")?;
    Ok(())
}

fn read_json_line<R>(reader: &mut R) -> Result<Option<Value>>
where
    R: BufRead,
{
    let mut line = String::new();
    let read = reader.read_line(&mut line)?;
    if read == 0 {
        return Ok(None);
    }
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    serde_json::from_str(trimmed)
        .map(Some)
        .map_err(|error| GlovesError::InvalidInput(format!("invalid JSON-RPC payload: {error}")))
}

fn write_result_response<W>(writer: &mut W, request_id: Value, result: Value) -> Result<()>
where
    W: Write,
{
    write_json_line(
        writer,
        json!({
            "jsonrpc": JSON_RPC_VERSION,
            "id": request_id,
            "result": result
        }),
    )
}

fn write_error_response<W>(
    writer: &mut W,
    request_id: Value,
    code: i64,
    message: &str,
    data: Value,
) -> Result<()>
where
    W: Write,
{
    write_json_line(
        writer,
        json!({
            "jsonrpc": JSON_RPC_VERSION,
            "id": request_id,
            "error": {
                "code": code,
                "message": message,
                "data": data
            }
        }),
    )
}

fn write_json_line<W>(writer: &mut W, payload: Value) -> Result<()>
where
    W: Write,
{
    serde_json::to_writer(&mut *writer, &payload)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn required_string_argument(
    arguments: &Map<String, Value>,
    key: &'static str,
) -> std::result::Result<String, (i64, &'static str, Value)> {
    arguments
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| invalid_params_error(&format!("missing required argument `{key}`")))
}

fn optional_string_argument(
    arguments: &Map<String, Value>,
    key: &'static str,
) -> std::result::Result<Option<String>, (i64, &'static str, Value)> {
    match arguments.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.trim().is_empty() => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(invalid_params_error(&format!(
            "argument `{key}` must be a string"
        ))),
    }
}

fn tool_success_response(message: String, structured_content: Value) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": message
            }
        ],
        "isError": false,
        "structuredContent": structured_content
    })
}

fn invalid_params_error(message: &str) -> (i64, &'static str, Value) {
    (
        INVALID_PARAMS_CODE,
        "Invalid params",
        json!({ "reason": message }),
    )
}

fn internal_error(message: &str) -> (i64, &'static str, Value) {
    (
        INTERNAL_ERROR_CODE,
        "Internal error",
        json!({ "reason": message }),
    )
}

fn map_runtime_error(error: GlovesError) -> (i64, &'static str, Value) {
    match error {
        GlovesError::NotFound => (
            SECRET_NOT_FOUND_CODE,
            "Secret not found",
            json!({ "reason": "secret_not_found" }),
        ),
        GlovesError::Unauthorized => (
            PERMISSION_DENIED_CODE,
            "Permission denied",
            json!({ "reason": "agent_not_recipient" }),
        ),
        GlovesError::InvalidInput(message) if message.contains("identity file not found") => (
            IDENTITY_ERROR_CODE,
            "Identity error",
            json!({ "reason": message }),
        ),
        GlovesError::InvalidInput(message) => (
            INVALID_PARAMS_CODE,
            "Invalid params",
            json!({ "reason": message }),
        ),
        GlovesError::Crypto(message) => (
            CRYPTO_ERROR_CODE,
            "Crypto error",
            json!({ "reason": message }),
        ),
        GlovesError::Io(error) => (
            INTERNAL_ERROR_CODE,
            "Internal error",
            json!({ "reason": error.to_string() }),
        ),
        GlovesError::Serde(error) => (
            INTERNAL_ERROR_CODE,
            "Internal error",
            json!({ "reason": error.to_string() }),
        ),
        GlovesError::Utf8(error) => (
            CRYPTO_ERROR_CODE,
            "Crypto error",
            json!({ "reason": error.to_string() }),
        ),
        GlovesError::Validation(error) => (
            INVALID_PARAMS_CODE,
            "Invalid params",
            json!({ "reason": error.to_string() }),
        ),
        GlovesError::AlreadyExists => (
            INVALID_PARAMS_CODE,
            "Invalid params",
            json!({ "reason": "already_exists" }),
        ),
        GlovesError::Forbidden => (
            PERMISSION_DENIED_CODE,
            "Permission denied",
            json!({ "reason": "forbidden" }),
        ),
        GlovesError::Expired => (
            INTERNAL_ERROR_CODE,
            "Internal error",
            json!({ "reason": "expired" }),
        ),
        GlovesError::GpgDenied => (
            PERMISSION_DENIED_CODE,
            "Permission denied",
            json!({ "reason": "gpg_denied" }),
        ),
        GlovesError::IntegrityViolation => (
            CRYPTO_ERROR_CODE,
            "Crypto error",
            json!({ "reason": "integrity_violation" }),
        ),
    }
}

fn tool_definitions() -> Vec<Value> {
    vec![
        json!({
            "name": GLOVES_LIST_TOOL,
            "description": "List available secret names for the authenticated agent",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "prefix": {
                        "type": "string",
                        "description": "Optional path prefix to filter results"
                    }
                }
            },
            "annotations": {
                "readOnlyHint": true,
                "destructiveHint": false,
                "idempotentHint": true,
                "openWorldHint": false
            }
        }),
        json!({
            "name": GLOVES_SHOW_TOOL,
            "description": "Show redacted metadata for a secret without decrypting it",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Secret path relative to the store root"
                    }
                },
                "required": ["path"]
            },
            "annotations": {
                "readOnlyHint": true,
                "destructiveHint": false,
                "idempotentHint": true,
                "openWorldHint": false
            }
        }),
        json!({
            "name": GLOVES_GET_TOOL,
            "description": "Authorize access to a secret and return only redacted injection metadata",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Secret path relative to the store root"
                    }
                },
                "required": ["path"]
            },
            "annotations": {
                "readOnlyHint": true,
                "destructiveHint": false,
                "idempotentHint": true,
                "openWorldHint": false
            }
        }),
        json!({
            "name": GLOVES_SET_TOOL,
            "description": "Store a new secret by reading its value from a process environment variable",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Secret path relative to the store root"
                    },
                    "from_env": {
                        "type": "string",
                        "description": "Environment variable containing the secret value"
                    }
                },
                "required": ["path", "from_env"]
            },
            "annotations": {
                "readOnlyHint": false,
                "destructiveHint": false,
                "idempotentHint": false,
                "openWorldHint": false
            }
        }),
        json!({
            "name": GLOVES_DELETE_TOOL,
            "description": "Delete a secret. This operation is intentionally denied by server policy.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Secret path relative to the store root"
                    }
                },
                "required": ["path"]
            },
            "annotations": {
                "readOnlyHint": false,
                "destructiveHint": true,
                "idempotentHint": true,
                "openWorldHint": false
            }
        }),
        json!({
            "name": GLOVES_APPROVE_TOOL,
            "description": "Approve or deny a pending secret access request",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "request_id": {
                        "type": "string",
                        "description": "Pending request identifier"
                    },
                    "decision": {
                        "type": "string",
                        "enum": ["approve", "deny"],
                        "description": "Approval decision"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Optional operator reason"
                    }
                },
                "required": ["request_id", "decision"]
            },
            "annotations": {
                "readOnlyHint": false,
                "destructiveHint": false,
                "idempotentHint": true,
                "openWorldHint": false
            }
        }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    use tempfile::TempDir;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    const TEST_AGENT: &str = "devy";
    const TEST_OTHER_AGENT: &str = "webhook";
    const TEST_SECRET_PATH: &str = "agents/devy/api-keys/anthropic";
    const TEST_SECRET_VALUE: &str = "sk-ant-api03-unit-test";
    const TEST_SESSION_TOKEN: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    struct TestHarness {
        _temp: TempDir,
        config: ResolvedConfig,
        agent_id: AgentId,
        other_agent_id: AgentId,
    }

    impl TestHarness {
        fn new() -> Self {
            let temp = TempDir::new().unwrap();
            let root = temp.path().join("root");
            let config = ResolvedConfig {
                store_path: root.join("store"),
                identities_path: root.join("identities"),
                audit_path: root.join("audit"),
                session_token_path: temp.path().join("session-token"),
                approval_channel: ApprovalChannel::Auto,
                approval_timeout_seconds: DEFAULT_APPROVAL_TIMEOUT_SECONDS,
            };
            ensure_private_dir(&config.store_path).unwrap();
            ensure_private_dir(&config.identities_path).unwrap();
            ensure_private_dir(&config.audit_path).unwrap();

            let agent_id = AgentId::new(TEST_AGENT).unwrap();
            let other_agent_id = AgentId::new(TEST_OTHER_AGENT).unwrap();
            age_crypto::generate_identity_file(&identity_path(&config, &agent_id)).unwrap();
            age_crypto::generate_identity_file(&identity_path(&config, &other_agent_id)).unwrap();

            Self {
                _temp: temp,
                config,
                agent_id,
                other_agent_id,
            }
        }

        fn write_secret(&self, secret_path: &str, recipients: &[String], value: &str) {
            let ciphertext =
                age_crypto::encrypt_for_recipients(value.as_bytes(), recipients).unwrap();
            write_private_file_atomic(
                &secret_ciphertext_path(&self.config, secret_path),
                &ciphertext,
            )
            .unwrap();
            let now = Utc::now();
            let metadata = SecretMetadataRecord {
                name: secret_path.to_owned(),
                length: value.len(),
                created: now,
                modified: now,
                last_rotated: now,
                last_accessed: None,
                agent: scope_agent_for_tests(secret_path),
                encrypted_to: recipients.to_vec(),
            };
            write_secret_metadata(&self.config, secret_path, &metadata).unwrap();
        }

        fn session_for(&self, agent_id: &AgentId) -> SessionContext {
            SessionContext {
                agent_id: agent_id.clone(),
                agent_recipient: load_agent_recipient(&self.config, agent_id).unwrap(),
            }
        }
    }

    #[test]
    fn resolved_config_load_reads_expected_paths() {
        let temp = TempDir::new().unwrap();
        let config_path = temp.path().join("gloves.toml");
        let store_path = temp.path().join("store-root");
        let identities_path = temp.path().join("ids");
        let audit_path = temp.path().join("audit-log");
        let token_path = temp.path().join("session-token");
        fs::write(
            &config_path,
            format!(
                "[daemon]\nsession_token_path = {:?}\n[store]\npath = {:?}\n[identities]\npath = {:?}\n[audit]\npath = {:?}\n",
                token_path, store_path, identities_path, audit_path
            ),
        )
        .unwrap();

        let resolved = ResolvedConfig::load(&config_path).unwrap();
        assert_eq!(resolved.store_path, store_path);
        assert_eq!(resolved.identities_path, identities_path);
        assert_eq!(resolved.audit_path, audit_path);
        assert_eq!(resolved.session_token_path, token_path);
        assert_eq!(resolved.approval_channel, ApprovalChannel::Auto);
        assert_eq!(
            resolved.approval_timeout_seconds,
            DEFAULT_APPROVAL_TIMEOUT_SECONDS
        );
    }

    #[test]
    fn write_session_token_creates_private_hex_file() {
        let temp = TempDir::new().unwrap();
        let token_path = temp.path().join("session-token");

        let token = write_session_token(&token_path).unwrap();

        assert_eq!(token.len(), SESSION_TOKEN_BYTES * 2);
        assert_eq!(fs::read_to_string(&token_path).unwrap(), token);
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&token_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn authenticate_session_accepts_valid_initialize_request() {
        let harness = TestHarness::new();
        let mut input = BufReader::new(Cursor::new(format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\"protocolVersion\":\"{MCP_PROTOCOL_VERSION}\",\"capabilities\":{{}},\"clientInfo\":{{\"name\":\"test\",\"version\":\"1.0.0\"}},\"_meta\":{{\"sessionToken\":\"{TEST_SESSION_TOKEN}\",\"agentId\":\"{TEST_AGENT}\"}}}}}}\n"
        )));
        let mut output = Vec::new();

        let session = authenticate_session(
            &mut input,
            &mut output,
            &harness.config,
            TEST_SESSION_TOKEN,
            None,
        )
        .unwrap()
        .unwrap();

        assert_eq!(session.agent_id.as_str(), TEST_AGENT);
        let response: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(response["result"]["serverInfo"]["name"], "gloves-mcp");
    }

    #[test]
    fn authenticate_session_rejects_invalid_token() {
        let harness = TestHarness::new();
        let mut input = BufReader::new(Cursor::new(format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\"_meta\":{{\"sessionToken\":\"bad-token\",\"agentId\":\"{TEST_AGENT}\"}}}}}}\n"
        )));
        let mut output = Vec::new();

        let session = authenticate_session(
            &mut input,
            &mut output,
            &harness.config,
            TEST_SESSION_TOKEN,
            None,
        )
        .unwrap();

        assert!(session.is_none());
        let response: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(response["error"]["code"], AUTH_FAILED_CODE);
        assert_eq!(response["error"]["data"]["reason"], "invalid_token");
    }

    #[test]
    fn list_show_and_get_follow_recipient_scope() {
        let harness = TestHarness::new();
        let recipient = load_agent_recipient(&harness.config, &harness.agent_id).unwrap();
        harness.write_secret(TEST_SECRET_PATH, &[recipient], TEST_SECRET_VALUE);
        let session = harness.session_for(&harness.agent_id);

        let listed =
            list_visible_secret_names(&harness.config, &session, Some("agents/devy")).unwrap();
        assert_eq!(listed, vec![TEST_SECRET_PATH.to_owned()]);

        let shown = show_secret(&harness.config, TEST_SECRET_PATH).unwrap();
        assert_eq!(shown.name, TEST_SECRET_PATH);
        assert_eq!(shown.length, TEST_SECRET_VALUE.len());

        let get_result = get_secret(
            &harness.config,
            &session,
            TEST_SECRET_PATH,
            ApprovalResolution { status: "auto" },
        )
        .unwrap();
        assert_eq!(get_result.path, TEST_SECRET_PATH);
        assert_eq!(get_result.secret_length, TEST_SECRET_VALUE.len());

        let metadata = read_secret_metadata(&harness.config, TEST_SECRET_PATH).unwrap();
        assert!(metadata.last_accessed.is_some());
    }

    #[test]
    fn get_secret_rejects_agents_outside_recipient_set() {
        let harness = TestHarness::new();
        let recipient = load_agent_recipient(&harness.config, &harness.agent_id).unwrap();
        harness.write_secret(TEST_SECRET_PATH, &[recipient], TEST_SECRET_VALUE);
        let other_session = harness.session_for(&harness.other_agent_id);

        let error = get_secret(
            &harness.config,
            &other_session,
            TEST_SECRET_PATH,
            ApprovalResolution { status: "auto" },
        )
        .unwrap_err();
        assert!(matches!(error, GlovesError::Unauthorized));
    }

    #[test]
    fn handle_tool_call_returns_redacted_payloads() {
        let harness = TestHarness::new();
        let recipient = load_agent_recipient(&harness.config, &harness.agent_id).unwrap();
        harness.write_secret(TEST_SECRET_PATH, &[recipient], TEST_SECRET_VALUE);
        let session = harness.session_for(&harness.agent_id);

        let list_response = handle_tool_call(
            &harness.config,
            &session,
            Some(&json!({
                "name": GLOVES_LIST_TOOL,
                "arguments": { "prefix": "agents/devy" }
            })),
        )
        .unwrap();
        assert_eq!(list_response["structuredContent"]["count"], 1);

        let show_response = handle_tool_call(
            &harness.config,
            &session,
            Some(&json!({
                "name": GLOVES_SHOW_TOOL,
                "arguments": { "path": TEST_SECRET_PATH }
            })),
        )
        .unwrap();
        assert_eq!(show_response["structuredContent"]["name"], TEST_SECRET_PATH);

        let get_response = handle_tool_call(
            &harness.config,
            &session,
            Some(&json!({
                "name": GLOVES_GET_TOOL,
                "arguments": { "path": TEST_SECRET_PATH }
            })),
        )
        .unwrap();
        let content_text = get_response["content"][0]["text"].as_str().unwrap();
        assert!(content_text.contains("injected"));
        assert!(!content_text.contains(TEST_SECRET_VALUE));
    }

    #[test]
    fn handle_tool_call_rejects_invalid_arguments_and_unknown_tools() {
        let harness = TestHarness::new();
        let session = harness.session_for(&harness.agent_id);

        let invalid = handle_tool_call(
            &harness.config,
            &session,
            Some(&json!({
                "name": GLOVES_SHOW_TOOL,
                "arguments": {}
            })),
        )
        .unwrap_err();
        assert_eq!(invalid.0, INVALID_PARAMS_CODE);

        let unsupported = handle_tool_call(
            &harness.config,
            &session,
            Some(&json!({
                "name": "gloves_rotate",
                "arguments": {}
            })),
        )
        .unwrap_err();
        assert_eq!(unsupported.0, INTERNAL_ERROR_CODE);
    }

    #[test]
    fn map_runtime_error_preserves_security_specific_codes() {
        let permission_error = map_runtime_error(GlovesError::Unauthorized);
        assert_eq!(permission_error.0, PERMISSION_DENIED_CODE);

        let not_found_error = map_runtime_error(GlovesError::NotFound);
        assert_eq!(not_found_error.0, SECRET_NOT_FOUND_CODE);

        let crypto_error = map_runtime_error(GlovesError::Crypto("boom".to_owned()));
        assert_eq!(crypto_error.0, CRYPTO_ERROR_CODE);
    }

    #[test]
    fn append_audit_record_writes_jsonl_line() {
        let harness = TestHarness::new();
        append_audit_record(
            &harness.config,
            AuditRecord {
                version: 1,
                timestamp: Utc::now(),
                event_type: "secret_access",
                agent_id: Some(TEST_AGENT),
                tool: Some(GLOVES_GET_TOOL),
                path: Some(TEST_SECRET_PATH),
                result: "approved",
                error: None,
            },
        )
        .unwrap();

        let audit_file = harness
            .config
            .audit_path
            .join(format!("{}.jsonl", Utc::now().format("%Y-%m-%d")));
        let contents = fs::read_to_string(audit_file).unwrap();
        assert!(contents.contains("\"event_type\":\"secret_access\""));
        assert!(contents.contains(TEST_SECRET_PATH));
    }

    #[test]
    fn expand_tilde_uses_home_directory() {
        let home = env::var(HOME_ENV_VAR).unwrap();
        let expanded = expand_tilde("~/gloves-test").unwrap();
        assert_eq!(
            expanded,
            Path::new(&home).join("gloves-test").display().to_string()
        );
    }

    #[test]
    fn tool_definitions_expose_expected_names() {
        let names = tool_definitions()
            .into_iter()
            .map(|tool| tool["name"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                GLOVES_LIST_TOOL,
                GLOVES_SHOW_TOOL,
                GLOVES_GET_TOOL,
                GLOVES_SET_TOOL,
                GLOVES_DELETE_TOOL,
                GLOVES_APPROVE_TOOL,
            ]
        );
    }

    fn scope_agent_for_tests(secret_path: &str) -> String {
        secret_path.split('/').nth(1).unwrap_or("shared").to_owned()
    }
}
