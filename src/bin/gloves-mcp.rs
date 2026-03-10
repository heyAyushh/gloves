use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::{self, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Component, Path, PathBuf},
    process::{Command as ProcessCommand, Stdio},
    sync::{Arc, Mutex, OnceLock},
    thread,
    time::{Duration as StdDuration, Instant},
};

#[cfg(unix)]
use tokio::net::UnixListener;

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
use hmac::{Hmac, Mac};
use rand::{Rng, RngExt};
use regex::Regex;
use rmcp::{
    model::{
        CallToolRequestParams, CallToolResult, CustomNotification, ErrorCode, Implementation,
        InitializeRequestParams, ListToolsResult, Meta, PaginatedRequestParams, ProtocolVersion,
        ServerCapabilities, ServerInfo, ServerNotification, Tool,
    },
    service::{RequestContext, RoleServer},
    transport::stdio,
    ErrorData as McpError, ServerHandler, ServiceExt,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::Sha256;
use tokio::task;
use uuid::Uuid;
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
const SECRET_NOTIFICATION_METHOD: &str = "gloves/secret";
const GLOVES_LIST_TOOL: &str = "gloves_list";
const GLOVES_SHOW_TOOL: &str = "gloves_show";
const GLOVES_GET_TOOL: &str = "gloves_get";
const GLOVES_SET_TOOL: &str = "gloves_set";
const GLOVES_DELETE_TOOL: &str = "gloves_delete";
const GLOVES_APPROVE_TOOL: &str = "gloves_approve";
const GLOVES_ROTATE_TOOL: &str = "gloves_rotate";
const SESSION_TOKEN_ENV_VAR: &str = "GLOVES_SESSION_TOKEN_PATH";
const HOME_ENV_VAR: &str = "HOME";
const STORE_SECTION_DEFAULT: &str = "store";
const IDENTITIES_SECTION_DEFAULT: &str = "identities";
const AUDIT_SECTION_DEFAULT: &str = "audit";
const GLOVES_BINARY_NAME: &str = "gloves";
const DEFAULT_METRICS_BIND_ADDRESS: &str = "127.0.0.1:7789";
const METRICS_RESPONSE_CONTENT_TYPE: &str = "text/plain; version=0.0.4";
const WEBHOOK_CALLBACK_APPROVER_AGENT_ID: &str = "webhook";
const WEBHOOK_CURL_BIN_ENV_VAR: &str = "GLOVES_CURL_BIN";
const WEBHOOK_CURL_MAX_TIME_SECONDS: u64 = 10;

static METRICS_STATE: OnceLock<Arc<MetricsState>> = OnceLock::new();

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
    /// Force stdio request handling even when daemon.socket_path is configured.
    #[arg(long, default_value_t = false)]
    stdio: bool,
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
    socket_path: Option<String>,
    #[serde(default)]
    metrics: DaemonMetricsSection,
    #[serde(default)]
    approval: DaemonApprovalSection,
}

#[derive(Debug, Default, Deserialize)]
struct DaemonApprovalSection {
    default_channel: Option<String>,
    timeout_seconds: Option<u64>,
    webhook_url: Option<String>,
    webhook_secret: Option<String>,
    callback_bind: Option<String>,
    callback_token: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct DaemonMetricsSection {
    enabled: Option<bool>,
    bind: Option<String>,
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
    socket_path: Option<PathBuf>,
    metrics_enabled: bool,
    metrics_bind: Option<String>,
    approval_channel: ApprovalChannel,
    approval_timeout_seconds: u64,
    webhook_url: Option<String>,
    webhook_secret: Option<String>,
    webhook_callback_token: Option<String>,
}

#[derive(Debug, Clone)]
struct SessionContext {
    agent_id: AgentId,
    agent_recipient: String,
}

#[derive(Debug)]
struct GlovesMcpServer {
    config: ResolvedConfig,
    expected_session_token: String,
    fallback_agent: Option<String>,
    allow_secret_notifications: bool,
    session: Mutex<Option<SessionContext>>,
}

impl GlovesMcpServer {
    fn new(
        config: ResolvedConfig,
        expected_session_token: String,
        fallback_agent: Option<String>,
        allow_secret_notifications: bool,
    ) -> Self {
        Self {
            config,
            expected_session_token,
            fallback_agent,
            allow_secret_notifications,
            session: Mutex::new(None),
        }
    }

    fn authenticated_session(&self) -> std::result::Result<SessionContext, McpError> {
        self.session
            .lock()
            .map_err(|_| McpError::internal_error("session mutex poisoned", None))?
            .clone()
            .ok_or_else(|| {
                McpError::internal_error(
                    "session not initialized",
                    Some(json!({ "reason": "missing_session" })),
                )
            })
    }
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

#[derive(Debug)]
struct DecryptedSecretResult {
    metadata: GetSecretResult,
    value: String,
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
struct RotateAgentResult {
    agent: String,
    approval_status: &'static str,
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

#[derive(Debug)]
struct ToolExecutionResult {
    payload: Value,
    secret_value: Option<String>,
    secret_path: Option<String>,
}

#[derive(Debug, Default)]
struct MetricsSnapshot {
    secret_access_totals: BTreeMap<(String, String, String), u64>,
    approval_latency_observations: Vec<(String, String, f64)>,
    encryption_ops_totals: BTreeMap<String, u64>,
}

#[derive(Debug)]
struct MetricsState {
    started_at: Instant,
    snapshot: Mutex<MetricsSnapshot>,
}

impl MetricsState {
    fn new() -> Self {
        Self {
            started_at: Instant::now(),
            snapshot: Mutex::new(MetricsSnapshot::default()),
        }
    }

    fn record_secret_access(&self, agent: &str, path: &str, result: &str) {
        let mut snapshot = self.snapshot.lock().expect("metrics mutex poisoned");
        *snapshot
            .secret_access_totals
            .entry((agent.to_owned(), path.to_owned(), result.to_owned()))
            .or_insert(0) += 1;
    }

    fn record_approval_latency(&self, agent: &str, channel: &str, latency_seconds: f64) {
        let mut snapshot = self.snapshot.lock().expect("metrics mutex poisoned");
        snapshot.approval_latency_observations.push((
            agent.to_owned(),
            channel.to_owned(),
            latency_seconds,
        ));
    }

    fn record_encryption_op(&self, operation: &str) {
        let mut snapshot = self.snapshot.lock().expect("metrics mutex poisoned");
        *snapshot
            .encryption_ops_totals
            .entry(operation.to_owned())
            .or_insert(0) += 1;
    }

    fn render_prometheus(&self) -> String {
        let snapshot = self.snapshot.lock().expect("metrics mutex poisoned");
        let mut lines = Vec::new();
        lines.push(
            "# HELP gloves_secret_access_total Count of secret access attempts by outcome.\n# TYPE gloves_secret_access_total counter".to_owned(),
        );
        for ((agent, path, result), count) in &snapshot.secret_access_totals {
            lines.push(format!(
                "gloves_secret_access_total{{agent=\"{}\",path=\"{}\",result=\"{}\"}} {count}",
                escape_metric_label(agent),
                escape_metric_label(path),
                escape_metric_label(result),
            ));
        }

        lines.push(
            "# HELP gloves_approval_latency_seconds Approval latency histogram.\n# TYPE gloves_approval_latency_seconds histogram".to_owned(),
        );
        append_approval_histogram_lines(&mut lines, &snapshot.approval_latency_observations);

        lines.push(
            "# HELP gloves_daemon_uptime_seconds Daemon uptime in seconds.\n# TYPE gloves_daemon_uptime_seconds gauge".to_owned(),
        );
        lines.push(format!(
            "gloves_daemon_uptime_seconds {:.3}",
            self.started_at.elapsed().as_secs_f64()
        ));

        lines.push(
            "# HELP gloves_encryption_ops_total Count of encryption and decryption operations.\n# TYPE gloves_encryption_ops_total counter".to_owned(),
        );
        for (operation, count) in &snapshot.encryption_ops_totals {
            lines.push(format!(
                "gloves_encryption_ops_total{{operation=\"{}\"}} {count}",
                escape_metric_label(operation),
            ));
        }

        lines.join("\n") + "\n"
    }
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        let _ = writeln!(io::stderr(), "{error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let config = ResolvedConfig::load(&cli.config)?;
    let metrics_state = METRICS_STATE
        .get_or_init(|| Arc::new(MetricsState::new()))
        .clone();
    ensure_private_dir(&config.audit_path)?;
    let session_token = write_session_token(&config.session_token_path)?;
    start_http_control_server(&config, metrics_state)?;
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

    if config.socket_path.is_some() && !cli.stdio {
        return run_socket_server(config, session_token, cli.agent).await;
    }

    run_stdio_server(config, session_token, cli.agent).await
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
        let socket_path =
            resolve_optional_config_path(parsed.daemon.socket_path.as_deref(), config_dir)?;
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
        let metrics_enabled = parsed.daemon.metrics.enabled.unwrap_or(false);
        let webhook_url = parsed.daemon.approval.webhook_url.clone();
        let webhook_secret = parsed.daemon.approval.webhook_secret.clone();
        let webhook_callback_token = if approval_channel == ApprovalChannel::Webhook {
            if webhook_url.is_none() {
                return Err(GlovesError::InvalidInput(
                    "daemon.approval.webhook_url is required when default_channel = \"webhook\""
                        .to_owned(),
                ));
            }
            Some(
                parsed
                    .daemon
                    .approval
                    .callback_token
                    .unwrap_or_else(|| generate_hex_token(SESSION_TOKEN_BYTES)),
            )
        } else {
            None
        };
        let metrics_bind = if metrics_enabled {
            Some(
                parsed
                    .daemon
                    .metrics
                    .bind
                    .clone()
                    .unwrap_or_else(|| DEFAULT_METRICS_BIND_ADDRESS.to_owned()),
            )
        } else if approval_channel == ApprovalChannel::Webhook {
            Some(
                parsed
                    .daemon
                    .approval
                    .callback_bind
                    .clone()
                    .unwrap_or_else(|| DEFAULT_METRICS_BIND_ADDRESS.to_owned()),
            )
        } else {
            None
        };

        Ok(Self {
            store_path,
            identities_path,
            audit_path,
            session_token_path,
            socket_path,
            metrics_enabled,
            metrics_bind,
            approval_channel,
            approval_timeout_seconds,
            webhook_url,
            webhook_secret,
            webhook_callback_token,
        })
    }
}

#[cfg(unix)]
async fn run_socket_server(
    config: ResolvedConfig,
    session_token: String,
    fallback_agent: Option<String>,
) -> Result<()> {
    let socket_path = config.socket_path.as_ref().ok_or_else(|| {
        GlovesError::InvalidInput("daemon.socket_path is required for socket mode".to_owned())
    })?;
    if let Some(parent) = socket_path.parent() {
        ensure_private_dir(parent)?;
    }
    if socket_path.exists() {
        fs::remove_file(socket_path)?;
    }
    let listener = UnixListener::bind(socket_path).map_err(GlovesError::Io)?;
    loop {
        let (stream, _) = listener.accept().await.map_err(GlovesError::Io)?;
        let server = GlovesMcpServer::new(
            config.clone(),
            session_token.clone(),
            fallback_agent.clone(),
            true,
        );
        tokio::spawn(async move {
            if let Err(error) = serve_rmcp_connection(server, stream).await {
                let _ = writeln!(io::stderr(), "socket connection failed: {error}");
            }
        });
    }
}

#[cfg(not(unix))]
async fn run_socket_server(
    _config: ResolvedConfig,
    _session_token: String,
    _fallback_agent: Option<String>,
) -> Result<()> {
    Err(GlovesError::InvalidInput(
        "daemon.socket_path is only supported on unix platforms".to_owned(),
    ))
}

async fn run_stdio_server(
    config: ResolvedConfig,
    session_token: String,
    fallback_agent: Option<String>,
) -> Result<()> {
    let server = GlovesMcpServer::new(config, session_token, fallback_agent, false);
    serve_rmcp_connection(server, stdio())
        .await
        .map_err(map_rmcp_error)
}

async fn serve_rmcp_connection<T, E, A>(
    server: GlovesMcpServer,
    transport: T,
) -> std::result::Result<(), rmcp::RmcpError>
where
    T: rmcp::transport::IntoTransport<RoleServer, E, A>,
    E: std::error::Error + Send + Sync + 'static,
{
    let service = server.serve(transport).await?;
    service.waiting().await?;
    Ok(())
}

fn start_http_control_server(
    config: &ResolvedConfig,
    metrics_state: Arc<MetricsState>,
) -> Result<()> {
    let Some(bind_address) = config.metrics_bind.clone() else {
        return Ok(());
    };
    let config = config.clone();
    thread::spawn(move || {
        let listener = match TcpListener::bind(&bind_address) {
            Ok(listener) => listener,
            Err(error) => {
                let _ = writeln!(
                    io::stderr(),
                    "failed to bind control endpoint at {bind_address}: {error}"
                );
                return;
            }
        };
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                continue;
            };
            if let Err(error) = write_http_control_response(&mut stream, &config, &metrics_state) {
                let _ = writeln!(io::stderr(), "failed to serve control request: {error}");
            }
        }
    });
    Ok(())
}

fn write_http_control_response<S>(
    stream: &mut S,
    config: &ResolvedConfig,
    metrics_state: &MetricsState,
) -> Result<()>
where
    S: Read + Write,
{
    let (request_line, request_path, authorization_header) = {
        let mut request_reader = BufReader::new(&mut *stream);
        let mut request_line = String::new();
        request_reader.read_line(&mut request_line)?;
        let request_path = request_line
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .to_owned();
        let authorization_header = read_authorization_header(&mut request_reader)?;
        (request_line, request_path, authorization_header)
    };

    let (status_line, body) = if request_line.starts_with("GET /metrics ") && config.metrics_enabled
    {
        ("HTTP/1.1 200 OK", metrics_state.render_prometheus())
    } else if request_line.starts_with("POST /api/v1/approve/") {
        handle_webhook_callback(config, &request_path, authorization_header.as_deref(), true)?
    } else if request_line.starts_with("POST /api/v1/deny/") {
        handle_webhook_callback(
            config,
            &request_path,
            authorization_header.as_deref(),
            false,
        )?
    } else {
        ("HTTP/1.1 404 Not Found", "not found\n".to_owned())
    };
    write_http_response(stream, status_line, METRICS_RESPONSE_CONTENT_TYPE, &body)
}

fn write_http_response<W>(
    stream: &mut W,
    status_line: &str,
    content_type: &str,
    body: &str,
) -> Result<()>
where
    W: Write,
{
    write!(
        stream,
        "{status_line}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()?;
    Ok(())
}

fn read_authorization_header<R>(reader: &mut R) -> Result<Option<String>>
where
    R: BufRead,
{
    let mut authorization = None;
    loop {
        let mut line = String::new();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 || line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("authorization") {
                authorization = Some(value.trim().to_owned());
            }
        }
    }
    Ok(authorization)
}

fn handle_webhook_callback(
    config: &ResolvedConfig,
    request_path: &str,
    authorization_header: Option<&str>,
    approve: bool,
) -> Result<(&'static str, String)> {
    let expected_token = config.webhook_callback_token.as_deref().ok_or_else(|| {
        GlovesError::InvalidInput("webhook callback token is not configured".to_owned())
    })?;
    let provided_token = authorization_header
        .and_then(|header| header.strip_prefix("Bearer "))
        .unwrap_or_default();
    if provided_token != expected_token {
        return Ok(("HTTP/1.1 401 Unauthorized", "unauthorized\n".to_owned()));
    }

    let request_id = request_path
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .parse::<Uuid>()
        .map_err(|_| GlovesError::InvalidInput("invalid webhook request id".to_owned()))?;
    let reviewer = AgentId::new(WEBHOOK_CALLBACK_APPROVER_AGENT_ID)?;
    let store = pending_request_store(config)?;
    if approve {
        store.approve(request_id, reviewer)?;
        Ok(("HTTP/1.1 200 OK", "approved\n".to_owned()))
    } else {
        store.deny(request_id, reviewer)?;
        Ok(("HTTP/1.1 200 OK", "denied\n".to_owned()))
    }
}

fn escape_metric_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

const APPROVAL_HISTOGRAM_BUCKETS: [f64; 8] = [0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 120.0];

fn append_approval_histogram_lines(
    lines: &mut Vec<String>,
    observations: &[(String, String, f64)],
) {
    let mut grouped = BTreeMap::<(String, String), Vec<f64>>::new();
    for (agent, channel, latency_seconds) in observations {
        grouped
            .entry((agent.clone(), channel.clone()))
            .or_default()
            .push(*latency_seconds);
    }

    for ((agent, channel), samples) in grouped {
        let sum: f64 = samples.iter().sum();
        for bucket in APPROVAL_HISTOGRAM_BUCKETS {
            let cumulative_count = samples.iter().filter(|value| **value <= bucket).count();
            lines.push(format!(
                "gloves_approval_latency_seconds_bucket{{agent=\"{}\",channel=\"{}\",le=\"{}\"}} {}",
                escape_metric_label(&agent),
                escape_metric_label(&channel),
                bucket,
                cumulative_count,
            ));
        }
        lines.push(format!(
            "gloves_approval_latency_seconds_bucket{{agent=\"{}\",channel=\"{}\",le=\"+Inf\"}} {}",
            escape_metric_label(&agent),
            escape_metric_label(&channel),
            samples.len(),
        ));
        lines.push(format!(
            "gloves_approval_latency_seconds_sum{{agent=\"{}\",channel=\"{}\"}} {:.6}",
            escape_metric_label(&agent),
            escape_metric_label(&channel),
            sum,
        ));
        lines.push(format!(
            "gloves_approval_latency_seconds_count{{agent=\"{}\",channel=\"{}\"}} {}",
            escape_metric_label(&agent),
            escape_metric_label(&channel),
            samples.len(),
        ));
    }
}

fn record_secret_access_metric(agent: &str, path: &str, result: &str) {
    if let Some(metrics_state) = METRICS_STATE.get() {
        metrics_state.record_secret_access(agent, path, result);
    }
}

fn record_approval_latency_metric(agent: &str, channel: &str, latency_seconds: f64) {
    if let Some(metrics_state) = METRICS_STATE.get() {
        metrics_state.record_approval_latency(agent, channel, latency_seconds);
    }
}

fn record_encryption_operation_metric(operation: &str) {
    if let Some(metrics_state) = METRICS_STATE.get() {
        metrics_state.record_encryption_op(operation);
    }
}

fn secret_access_result_label(error: &GlovesError) -> &'static str {
    match error {
        GlovesError::Unauthorized => "denied",
        GlovesError::NotFound => "not_found",
        GlovesError::Forbidden => "denied",
        GlovesError::Expired => "expired",
        GlovesError::AlreadyExists => "error",
        GlovesError::Validation(_)
        | GlovesError::Io(_)
        | GlovesError::Serde(_)
        | GlovesError::Utf8(_)
        | GlovesError::Crypto(_)
        | GlovesError::InvalidInput(_)
        | GlovesError::IntegrityViolation
        | GlovesError::GpgDenied => "error",
    }
}

fn mcp_server_info() -> ServerInfo {
    ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
        .with_protocol_version(ProtocolVersion::V_2025_06_18)
        .with_server_info(Implementation::new("gloves-mcp", env!("CARGO_PKG_VERSION")))
        .with_instructions("Gloves brokered secret transport".to_owned())
}

fn authenticate_initialize_request(
    config: &ResolvedConfig,
    expected_session_token: &str,
    meta: &Meta,
    fallback_agent: Option<&str>,
) -> std::result::Result<SessionContext, McpError> {
    let provided_token = meta
        .get("sessionToken")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if provided_token != expected_session_token {
        let _ = append_audit_record(
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
        );
        return Err(McpError::new(
            ErrorCode(AUTH_FAILED_CODE as i32),
            "Session authentication failed",
            Some(json!({ "reason": "invalid_token" })),
        ));
    }

    let requested_agent = meta
        .get("agentId")
        .and_then(Value::as_str)
        .or(fallback_agent)
        .ok_or_else(|| McpError::invalid_params("initialize params must include agentId", None))?;
    let agent_id = AgentId::new(requested_agent)
        .map_err(|error| tuple_to_mcp_error_from_runtime(error.into()))?;
    let agent_recipient =
        load_agent_recipient(config, &agent_id).map_err(tuple_to_mcp_error_from_runtime)?;

    Ok(SessionContext {
        agent_id,
        agent_recipient,
    })
}

fn deserialize_tool_definitions() -> std::result::Result<Vec<Tool>, McpError> {
    tool_definitions()
        .into_iter()
        .map(|tool| {
            serde_json::from_value(tool).map_err(|error| {
                McpError::internal_error(
                    format!("failed to deserialize tool definition: {error}"),
                    None,
                )
            })
        })
        .collect()
}

async fn send_secret_notification(
    context: &RequestContext<RoleServer>,
    secret_path: &str,
    secret_value: &str,
) -> std::result::Result<(), McpError> {
    context
        .peer
        .send_notification(ServerNotification::CustomNotification(
            CustomNotification::new(
                SECRET_NOTIFICATION_METHOD,
                Some(json!({
                    "requestId": context.id,
                    "path": secret_path,
                    "value": secret_value
                })),
            ),
        ))
        .await
        .map_err(|error| {
            McpError::internal_error(format!("failed to send secret side-channel: {error}"), None)
        })
}

impl ServerHandler for GlovesMcpServer {
    fn get_info(&self) -> ServerInfo {
        mcp_server_info()
    }

    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<ServerInfo, McpError> {
        if context.peer.peer_info().is_none() {
            context.peer.set_peer_info(request.clone());
        }
        let session = authenticate_initialize_request(
            &self.config,
            &self.expected_session_token,
            &context.meta,
            self.fallback_agent.as_deref(),
        )?;
        *self
            .session
            .lock()
            .map_err(|_| McpError::internal_error("session mutex poisoned", None))? = Some(session);
        Ok(mcp_server_info())
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> std::result::Result<ListToolsResult, McpError> {
        Ok(ListToolsResult {
            tools: deserialize_tool_definitions()?,
            ..Default::default()
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<CallToolResult, McpError> {
        let session = self.authenticated_session()?;
        let config = self.config.clone();
        let request_value = serde_json::to_value(&request).map_err(|error| {
            McpError::internal_error(format!("failed to serialize tool request: {error}"), None)
        })?;
        let execution =
            task::spawn_blocking(move || handle_tool_call(&config, &session, Some(&request_value)))
                .await
                .map_err(|error| {
                    McpError::internal_error(format!("tool task failed: {error}"), None)
                })?;
        let execution = execution.map_err(tuple_to_mcp_error)?;

        if self.allow_secret_notifications {
            if let (Some(secret_value), Some(secret_path)) = (
                execution.secret_value.as_deref(),
                execution.secret_path.as_deref(),
            ) {
                send_secret_notification(&context, secret_path, secret_value).await?;
            }
        }

        serde_json::from_value(execution.payload).map_err(|error| {
            McpError::internal_error(format!("failed to serialize tool response: {error}"), None)
        })
    }
}

fn map_rmcp_error(error: rmcp::RmcpError) -> GlovesError {
    GlovesError::InvalidInput(error.to_string())
}

fn tuple_to_mcp_error(error: (i64, &'static str, Value)) -> McpError {
    McpError::new(ErrorCode(error.0 as i32), error.1, Some(error.2))
}

fn tuple_to_mcp_error_from_runtime(error: GlovesError) -> McpError {
    tuple_to_mcp_error(map_runtime_error(error))
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

    fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Tty => "tty",
            Self::Webhook => "webhook",
        }
    }
}

fn handle_tool_call(
    config: &ResolvedConfig,
    session: &SessionContext,
    params: Option<&Value>,
) -> std::result::Result<ToolExecutionResult, (i64, &'static str, Value)> {
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
        GLOVES_ROTATE_TOOL => handle_rotate_tool(config, session, &arguments),
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
) -> std::result::Result<ToolExecutionResult, (i64, &'static str, Value)> {
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

    Ok(ToolExecutionResult {
        payload: tool_success_response(
            format!("Listed {} visible secrets", payload.count),
            serde_json::to_value(payload)
                .map_err(|_| internal_error("failed to serialize list result"))?,
        ),
        secret_value: None,
        secret_path: None,
    })
}

fn handle_show_tool(
    config: &ResolvedConfig,
    session: &SessionContext,
    arguments: &Map<String, Value>,
) -> std::result::Result<ToolExecutionResult, (i64, &'static str, Value)> {
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

    Ok(ToolExecutionResult {
        payload: tool_success_response(
            format!("Metadata for `{path}` loaded"),
            serde_json::to_value(show_result)
                .map_err(|_| internal_error("failed to serialize show result"))?,
        ),
        secret_value: None,
        secret_path: None,
    })
}

fn handle_get_tool(
    config: &ResolvedConfig,
    session: &SessionContext,
    arguments: &Map<String, Value>,
) -> std::result::Result<ToolExecutionResult, (i64, &'static str, Value)> {
    let path = required_string_argument(arguments, "path")?;
    let approval = resolve_approval(config, session, GLOVES_GET_TOOL, &path)?;
    let get_result = match get_secret(config, session, &path, approval) {
        Ok(result) => {
            record_secret_access_metric(session.agent_id.as_str(), &path, "approved");
            record_encryption_operation_metric("decrypt");
            result
        }
        Err(error) => {
            record_secret_access_metric(
                session.agent_id.as_str(),
                &path,
                secret_access_result_label(&error),
            );
            return Err(map_runtime_error(error));
        }
    };
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

    Ok(ToolExecutionResult {
        payload: tool_success_response(
            format!(
                "Secret '{}' ({} chars) injected as {}",
                get_result.metadata.path, get_result.metadata.secret_length, path
            ),
            serde_json::to_value(&get_result.metadata)
                .map_err(|_| internal_error("failed to serialize get result"))?,
        ),
        secret_value: Some(get_result.value),
        secret_path: Some(path),
    })
}

fn handle_set_tool(
    config: &ResolvedConfig,
    session: &SessionContext,
    arguments: &Map<String, Value>,
) -> std::result::Result<ToolExecutionResult, (i64, &'static str, Value)> {
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
    record_encryption_operation_metric("encrypt");
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

    Ok(ToolExecutionResult {
        payload: tool_success_response(
            format!("Stored secret `{path}`"),
            serde_json::to_value(set_result)
                .map_err(|_| internal_error("failed to serialize set result"))?,
        ),
        secret_value: None,
        secret_path: None,
    })
}

fn handle_delete_tool(
    config: &ResolvedConfig,
    session: &SessionContext,
    arguments: &Map<String, Value>,
) -> std::result::Result<ToolExecutionResult, (i64, &'static str, Value)> {
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
) -> std::result::Result<ToolExecutionResult, (i64, &'static str, Value)> {
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

    Ok(ToolExecutionResult {
        payload: tool_success_response(
            format!("Request `{request_id}` {decision}d"),
            serde_json::to_value(ApprovalResult {
                request_id,
                decision,
                reviewer: session.agent_id.as_str().to_owned(),
            })
            .map_err(|_| internal_error("failed to serialize approval result"))?,
        ),
        secret_value: None,
        secret_path: None,
    })
}

fn handle_rotate_tool(
    config: &ResolvedConfig,
    session: &SessionContext,
    arguments: &Map<String, Value>,
) -> std::result::Result<ToolExecutionResult, (i64, &'static str, Value)> {
    let agent_id = required_string_argument(arguments, "agent_id")?;
    if agent_id != session.agent_id.as_str() {
        return Err((
            PERMISSION_DENIED_CODE,
            "Permission denied",
            json!({ "reason": "cross_agent_rotation_denied" }),
        ));
    }
    let approval = resolve_approval(config, session, GLOVES_ROTATE_TOOL, &agent_id)?;
    run_gloves_rotate(config, &agent_id).map_err(map_runtime_error)?;
    record_encryption_operation_metric("rotate");
    append_audit_record(
        config,
        AuditRecord {
            version: 1,
            timestamp: Utc::now(),
            event_type: "key_rotation",
            agent_id: Some(session.agent_id.as_str()),
            tool: Some(GLOVES_ROTATE_TOOL),
            path: Some(&agent_id),
            result: "approved",
            error: None,
        },
    )
    .map_err(|_| internal_error("failed to write audit log"))?;

    Ok(ToolExecutionResult {
        payload: tool_success_response(
            format!("Rotated identity `{agent_id}`"),
            serde_json::to_value(RotateAgentResult {
                agent: agent_id,
                approval_status: approval.status,
            })
            .map_err(|_| internal_error("failed to serialize rotate result"))?,
        ),
        secret_value: None,
        secret_path: None,
    })
}

fn get_secret(
    config: &ResolvedConfig,
    session: &SessionContext,
    path: &str,
    approval: ApprovalResolution,
) -> Result<DecryptedSecretResult> {
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
    let value = String::from_utf8(plaintext)?;
    let accessed_at = Utc::now();
    metadata.last_accessed = Some(accessed_at);
    write_secret_metadata(config, secret_id.as_str(), &metadata)?;

    Ok(DecryptedSecretResult {
        metadata: GetSecretResult {
            path: secret_id.as_str().to_owned(),
            agent: session.agent_id.as_str().to_owned(),
            injected: true,
            inject_method: "env",
            secret_length: value.len(),
            approval_status: approval.status,
        },
        value,
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

fn send_webhook_approval_request(
    config: &ResolvedConfig,
    session: &SessionContext,
    tool_name: &str,
    path: &str,
    request_id: Uuid,
    requested_at: DateTime<Utc>,
) -> Result<()> {
    let webhook_url = config.webhook_url.as_deref().ok_or_else(|| {
        GlovesError::InvalidInput("daemon.approval.webhook_url is required".to_owned())
    })?;
    let callback_bind = config.metrics_bind.as_deref().ok_or_else(|| {
        GlovesError::InvalidInput("webhook callbacks require an HTTP bind address".to_owned())
    })?;
    let timeout_at = requested_at + Duration::seconds(config.approval_timeout_seconds as i64);
    let payload = json!({
        "version": 1,
        "request_id": request_id.to_string(),
        "event": "approval_request",
        "agent_id": session.agent_id.as_str(),
        "tool": tool_name,
        "path": path,
        "timestamp": requested_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "timeout_at": timeout_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "actions": {
            "approve": format!("http://{callback_bind}/api/v1/approve/{request_id}"),
            "deny": format!("http://{callback_bind}/api/v1/deny/{request_id}")
        }
    });
    let body = serde_json::to_vec(&payload)?;
    let signature = webhook_signature(config.webhook_secret.as_deref(), &body)?;
    post_json(webhook_url, &body, Some(&signature))
}

fn webhook_signature(secret: Option<&str>, body: &[u8]) -> Result<String> {
    let Some(secret) = secret else {
        return Ok(String::new());
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| GlovesError::InvalidInput("invalid webhook secret".to_owned()))?;
    mac.update(body);
    Ok(format!(
        "sha256={}",
        hex_encode(&mac.finalize().into_bytes())
    ))
}

fn post_json(url: &str, body: &[u8], signature: Option<&str>) -> Result<()> {
    if url.starts_with("https://") {
        return post_json_over_https(url, body, signature);
    }
    let parsed = parse_http_url(url)?;
    let mut stream = TcpStream::connect((parsed.host.as_str(), parsed.port))?;
    post_json_over_stream(&mut stream, &parsed.host, &parsed.path, body, signature)
}

fn post_json_over_stream<S>(
    stream: &mut S,
    host: &str,
    path: &str,
    body: &[u8],
    signature: Option<&str>,
) -> Result<()>
where
    S: Read + Write,
{
    write_http_json_post_request(stream, host, path, body, signature)?;
    stream.flush()?;
    ensure_http_success_response(stream)
}

fn write_http_json_post_request<W>(
    stream: &mut W,
    host: &str,
    path: &str,
    body: &[u8],
    signature: Option<&str>,
) -> Result<()>
where
    W: Write,
{
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    )?;
    if let Some(signature) = signature.filter(|value| !value.is_empty()) {
        write!(stream, "X-Gloves-Signature: {signature}\r\n")?;
    }
    write!(stream, "\r\n")?;
    stream.write_all(body)?;
    Ok(())
}

fn ensure_http_success_response<R>(reader: &mut R) -> Result<()>
where
    R: Read,
{
    let mut response = String::new();
    BufReader::new(reader).read_to_string(&mut response)?;
    if !response.starts_with("HTTP/1.1 200") && !response.starts_with("HTTP/1.0 200") {
        return Err(GlovesError::InvalidInput(format!(
            "webhook returned non-success response: {}",
            response.lines().next().unwrap_or("unknown")
        )));
    }
    Ok(())
}

fn post_json_over_https(url: &str, body: &[u8], signature: Option<&str>) -> Result<()> {
    let curl_binary = env::var(WEBHOOK_CURL_BIN_ENV_VAR).unwrap_or_else(|_| "curl".to_owned());
    let mut command = ProcessCommand::new(&curl_binary);
    command
        .arg("--silent")
        .arg("--show-error")
        .arg("--fail")
        .arg("--request")
        .arg("POST")
        .arg("--header")
        .arg("Content-Type: application/json")
        .arg("--data-binary")
        .arg("@-")
        .arg("--max-time")
        .arg(WEBHOOK_CURL_MAX_TIME_SECONDS.to_string())
        .arg(url)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some(signature) = signature.filter(|value| !value.is_empty()) {
        command
            .arg("--header")
            .arg(format!("X-Gloves-Signature: {signature}"));
    }

    let mut child = command.spawn().map_err(|error| {
        GlovesError::InvalidInput(format!(
            "failed to spawn `{curl_binary}` for HTTPS webhook delivery: {error}"
        ))
    })?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(body)?;
    }
    let output = child.wait_with_output().map_err(GlovesError::Io)?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let failure_reason = if stderr.is_empty() {
        format!("exit status {}", output.status)
    } else {
        stderr
    };
    Err(GlovesError::InvalidInput(format!(
        "HTTPS webhook delivery failed: {failure_reason}"
    )))
}

#[derive(Debug)]
struct ParsedHttpUrl {
    host: String,
    port: u16,
    path: String,
}

fn parse_http_url(url: &str) -> Result<ParsedHttpUrl> {
    let without_scheme = url.strip_prefix("http://").ok_or_else(|| {
        GlovesError::InvalidInput("only http:// webhook urls are supported".to_owned())
    })?;
    let (authority, path) = match without_scheme.split_once('/') {
        Some((authority, rest)) => (authority, format!("/{}", rest)),
        None => (without_scheme, "/".to_owned()),
    };
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (
            host.to_owned(),
            port.parse::<u16>()
                .map_err(|_| GlovesError::InvalidInput("invalid webhook port".to_owned()))?,
        ),
        None => (authority.to_owned(), 80),
    };
    if host.is_empty() {
        return Err(GlovesError::InvalidInput(
            "webhook host must not be empty".to_owned(),
        ));
    }
    Ok(ParsedHttpUrl { host, port, path })
}

fn approval_tier_for_tool(tool_name: &str) -> ApprovalTier {
    match tool_name {
        GLOVES_LIST_TOOL | GLOVES_SHOW_TOOL | GLOVES_APPROVE_TOOL => ApprovalTier::Auto,
        GLOVES_GET_TOOL | GLOVES_SET_TOOL | GLOVES_ROTATE_TOOL => ApprovalTier::Human,
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
    let requested_at = Instant::now();
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
    if config.approval_channel == ApprovalChannel::Webhook {
        send_webhook_approval_request(
            config,
            session,
            tool_name,
            path,
            request.id,
            request.requested_at,
        )
        .map_err(map_runtime_error)?;
    }

    let deadline = Instant::now() + StdDuration::from_secs(config.approval_timeout_seconds);
    loop {
        let requests = store.load_all().map_err(map_runtime_error)?;
        if let Some(pending_request) = requests.into_iter().find(|entry| entry.id == request.id) {
            match pending_request.status {
                RequestStatus::Fulfilled => {
                    record_approval_latency_metric(
                        session.agent_id.as_str(),
                        config.approval_channel.as_str(),
                        requested_at.elapsed().as_secs_f64(),
                    );
                    return Ok(ApprovalResolution { status: "approved" });
                }
                RequestStatus::Denied => {
                    record_approval_latency_metric(
                        session.agent_id.as_str(),
                        config.approval_channel.as_str(),
                        requested_at.elapsed().as_secs_f64(),
                    );
                    return Err((
                        APPROVAL_DENIED_CODE,
                        "Approval denied",
                        json!({ "reason": "request_denied", "request_id": request.id.to_string() }),
                    ));
                }
                RequestStatus::Expired => {
                    record_approval_latency_metric(
                        session.agent_id.as_str(),
                        config.approval_channel.as_str(),
                        requested_at.elapsed().as_secs_f64(),
                    );
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
            record_approval_latency_metric(
                session.agent_id.as_str(),
                config.approval_channel.as_str(),
                requested_at.elapsed().as_secs_f64(),
            );
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

fn run_gloves_rotate(config: &ResolvedConfig, agent_id: &str) -> Result<()> {
    let root_path = config.store_path.parent().ok_or_else(|| {
        GlovesError::InvalidInput("store.path must have a parent root directory".to_owned())
    })?;
    let output = ProcessCommand::new(gloves_binary_path())
        .args([
            "--root",
            root_path.to_str().ok_or_else(|| {
                GlovesError::InvalidInput("root path must be valid UTF-8".to_owned())
            })?,
            "rotate",
            "--agent",
            agent_id,
        ])
        .output()?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    if stderr.is_empty() {
        return Err(GlovesError::InvalidInput(
            "gloves rotate failed without stderr output".to_owned(),
        ));
    }
    Err(GlovesError::InvalidInput(stderr))
}

fn gloves_binary_path() -> PathBuf {
    let sibling_binary = env::current_exe()
        .ok()
        .map(|path| path.with_file_name(executable_name(GLOVES_BINARY_NAME)));
    match sibling_binary {
        Some(path) if path.exists() => path,
        _ => PathBuf::from(GLOVES_BINARY_NAME),
    }
}

fn executable_name(base_name: &str) -> String {
    if cfg!(windows) {
        format!("{base_name}.exe")
    } else {
        base_name.to_owned()
    }
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

fn resolve_optional_config_path(
    configured_value: Option<&str>,
    config_dir: &Path,
) -> Result<Option<PathBuf>> {
    configured_value
        .map(|value| resolve_config_path(Some(value), config_dir, None, "optional.path"))
        .transpose()
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
    let token = generate_hex_token(SESSION_TOKEN_BYTES);
    write_private_file_atomic(token_path, token.as_bytes())?;
    Ok(token)
}

fn generate_hex_token(byte_count: usize) -> String {
    let mut bytes = vec![0_u8; byte_count];
    rand::rng().fill_bytes(&mut bytes);
    hex_encode(&bytes)
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
        json!({
            "name": GLOVES_ROTATE_TOOL,
            "description": "Rotate the authenticated agent identity and re-encrypt affected secrets",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {
                        "type": "string",
                        "description": "Agent identifier to rotate"
                    }
                },
                "required": ["agent_id"]
            },
            "annotations": {
                "readOnlyHint": false,
                "destructiveHint": true,
                "idempotentHint": false,
                "openWorldHint": false
            }
        }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::service::NotificationContext;
    use rmcp::{ClientHandler, RoleClient, ServiceExt};

    use std::io::Cursor;
    use tempfile::TempDir;
    use tokio::sync::{Mutex as AsyncMutex, Notify};

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[cfg(unix)]
    static CURL_BIN_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    static HOME_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    #[cfg(unix)]
    static PATH_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    const TEST_AGENT: &str = "devy";
    const TEST_OTHER_AGENT: &str = "webhook";
    const TEST_SECRET_PATH: &str = "agents/devy/api-keys/anthropic";
    const TEST_SECRET_VALUE: &str = "sk-ant-api03-unit-test";
    const TEST_SESSION_TOKEN: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    struct MemoryStream {
        reader: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl MemoryStream {
        fn new(read_data: impl Into<Vec<u8>>) -> Self {
            Self {
                reader: Cursor::new(read_data.into()),
                written: Vec::new(),
            }
        }

        fn written_string(&self) -> String {
            String::from_utf8(self.written.clone()).unwrap()
        }
    }

    impl Read for MemoryStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reader.read(buf)
        }
    }

    impl Write for MemoryStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

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
                socket_path: None,
                metrics_enabled: false,
                metrics_bind: None,
                approval_channel: ApprovalChannel::Auto,
                approval_timeout_seconds: DEFAULT_APPROVAL_TIMEOUT_SECONDS,
                webhook_url: None,
                webhook_secret: None,
                webhook_callback_token: None,
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

    #[derive(Clone)]
    struct SecretCapturingClient {
        info: rmcp::model::ClientInfo,
        signal: Arc<Notify>,
        payload: Arc<AsyncMutex<Option<Value>>>,
    }

    impl SecretCapturingClient {
        fn new(info: rmcp::model::ClientInfo) -> Self {
            Self {
                info,
                signal: Arc::new(Notify::new()),
                payload: Arc::new(AsyncMutex::new(None)),
            }
        }
    }

    impl ClientHandler for SecretCapturingClient {
        fn get_info(&self) -> rmcp::model::ClientInfo {
            self.info.clone()
        }

        async fn on_custom_notification(
            &self,
            notification: CustomNotification,
            _context: NotificationContext<RoleClient>,
        ) {
            if notification.method == SECRET_NOTIFICATION_METHOD {
                *self.payload.lock().await = notification.params;
                self.signal.notify_one();
            }
        }
    }

    fn client_info_with_session_meta(
        session_token: &str,
        agent_id: &str,
    ) -> rmcp::model::ClientInfo {
        let mut client_info =
            rmcp::model::ClientInfo::new(Default::default(), Implementation::new("test", "1.0.0"))
                .with_protocol_version(ProtocolVersion::V_2025_06_18);
        let mut meta = Meta::new();
        meta.insert("sessionToken".to_owned(), json!(session_token));
        meta.insert("agentId".to_owned(), json!(agent_id));
        client_info.meta = Some(meta);
        client_info
    }

    fn send_http_control_request(
        config: &ResolvedConfig,
        metrics_state: MetricsState,
        request: &str,
    ) -> String {
        let mut stream = MemoryStream::new(request.as_bytes());
        write_http_control_response(&mut stream, config, &metrics_state).unwrap();
        stream.written_string()
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
    fn resolved_config_load_requires_webhook_url_for_webhook_channel() {
        let temp = TempDir::new().unwrap();
        let config_path = temp.path().join("gloves.toml");
        fs::write(
            &config_path,
            format!(
                "[daemon]\nsession_token_path = {:?}\n[daemon.approval]\ndefault_channel = \"webhook\"\n[store]\npath = {:?}\n[identities]\npath = {:?}\n[audit]\npath = {:?}\n",
                temp.path().join("session-token"),
                temp.path().join("store"),
                temp.path().join("identities"),
                temp.path().join("audit"),
            ),
        )
        .unwrap();

        let error = ResolvedConfig::load(&config_path).unwrap_err();
        assert!(error
            .to_string()
            .contains("daemon.approval.webhook_url is required"));
    }

    #[test]
    fn resolved_config_load_defaults_webhook_callback_bind_and_token() {
        let temp = TempDir::new().unwrap();
        let config_path = temp.path().join("gloves.toml");
        fs::write(
            &config_path,
            format!(
                "[daemon]\nsession_token_path = {:?}\n[daemon.approval]\ndefault_channel = \"webhook\"\nwebhook_url = \"http://127.0.0.1:9000/approve\"\n[store]\npath = {:?}\n[identities]\npath = {:?}\n[audit]\npath = {:?}\n",
                temp.path().join("session-token"),
                temp.path().join("store"),
                temp.path().join("identities"),
                temp.path().join("audit"),
            ),
        )
        .unwrap();

        let resolved = ResolvedConfig::load(&config_path).unwrap();
        assert_eq!(
            resolved.metrics_bind.as_deref(),
            Some(DEFAULT_METRICS_BIND_ADDRESS)
        );
        assert!(resolved
            .webhook_callback_token
            .as_deref()
            .is_some_and(|token| !token.is_empty()));
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

    #[cfg(unix)]
    #[test]
    fn https_webhook_delivery_uses_configured_curl_binary() {
        let _lock = CURL_BIN_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        let temp = TempDir::new().unwrap();
        let script_path = temp.path().join("mock-curl.sh");
        let args_path = temp.path().join("curl-args.txt");
        let body_path = temp.path().join("curl-body.bin");
        fs::write(
            &script_path,
            format!(
                "#!/bin/sh\nprintf '%s\n' \"$@\" > \"{}\"\n/bin/cat > \"{}\"\n",
                args_path.display(),
                body_path.display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755)).unwrap();

        let previous_curl_bin = env::var_os(WEBHOOK_CURL_BIN_ENV_VAR);
        env::set_var(WEBHOOK_CURL_BIN_ENV_VAR, &script_path);
        let body = br#"{"hello":"world"}"#;
        let result = post_json(
            "https://hooks.example.test/approve",
            body,
            Some("sha256=test-signature"),
        );
        match previous_curl_bin {
            Some(value) => env::set_var(WEBHOOK_CURL_BIN_ENV_VAR, value),
            None => env::remove_var(WEBHOOK_CURL_BIN_ENV_VAR),
        }

        assert!(result.is_ok());
        let args = fs::read_to_string(args_path).unwrap();
        assert!(args.contains("--request"));
        assert!(args.contains("POST"));
        assert!(args.contains("--data-binary"));
        assert!(args.contains("@-"));
        assert!(args.contains("Content-Type: application/json"));
        assert!(args.contains("X-Gloves-Signature: sha256=test-signature"));
        assert!(args.contains("https://hooks.example.test/approve"));
        assert_eq!(fs::read(body_path).unwrap(), body);
    }

    #[cfg(unix)]
    #[test]
    fn https_webhook_delivery_reports_curl_failures() {
        let _lock = CURL_BIN_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        let temp = TempDir::new().unwrap();
        let script_path = temp.path().join("mock-curl-fail.sh");
        fs::write(&script_path, "#!/bin/sh\necho 'curl failed' >&2\nexit 22\n").unwrap();
        fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755)).unwrap();

        let previous_curl_bin = env::var_os(WEBHOOK_CURL_BIN_ENV_VAR);
        env::set_var(WEBHOOK_CURL_BIN_ENV_VAR, &script_path);
        let error = post_json("https://hooks.example.test/approve", br#"{}"#, None).unwrap_err();
        match previous_curl_bin {
            Some(value) => env::set_var(WEBHOOK_CURL_BIN_ENV_VAR, value),
            None => env::remove_var(WEBHOOK_CURL_BIN_ENV_VAR),
        }

        assert!(error.to_string().contains("HTTPS webhook delivery failed"));
        assert!(error.to_string().contains("curl failed"));
    }

    #[test]
    fn approval_tier_matches_current_tool_policy() {
        assert_eq!(approval_tier_for_tool(GLOVES_LIST_TOOL), ApprovalTier::Auto);
        assert_eq!(approval_tier_for_tool(GLOVES_SHOW_TOOL), ApprovalTier::Auto);
        assert_eq!(
            approval_tier_for_tool(GLOVES_APPROVE_TOOL),
            ApprovalTier::Auto
        );
        assert_eq!(approval_tier_for_tool(GLOVES_GET_TOOL), ApprovalTier::Human);
        assert_eq!(approval_tier_for_tool(GLOVES_SET_TOOL), ApprovalTier::Human);
        assert_eq!(
            approval_tier_for_tool(GLOVES_ROTATE_TOOL),
            ApprovalTier::Human
        );
        assert_eq!(
            approval_tier_for_tool(GLOVES_DELETE_TOOL),
            ApprovalTier::Deny
        );
        assert_eq!(approval_tier_for_tool("gloves_unknown"), ApprovalTier::Deny);
    }

    #[test]
    fn parse_http_url_supports_default_and_explicit_ports() {
        let default_port = parse_http_url("http://localhost/path/to/hook").unwrap();
        assert_eq!(default_port.host, "localhost");
        assert_eq!(default_port.port, 80);
        assert_eq!(default_port.path, "/path/to/hook");

        let explicit_port = parse_http_url("http://127.0.0.1:7789/api/v1/approve").unwrap();
        assert_eq!(explicit_port.host, "127.0.0.1");
        assert_eq!(explicit_port.port, 7789);
        assert_eq!(explicit_port.path, "/api/v1/approve");
    }

    #[test]
    fn parse_http_url_rejects_https_scheme() {
        let error = parse_http_url("https://hooks.example.test/approve").unwrap_err();
        assert!(error
            .to_string()
            .contains("only http:// webhook urls are supported"));
    }

    #[test]
    fn webhook_signature_handles_optional_secret() {
        let body = br#"{"event":"approval_request"}"#;
        assert_eq!(webhook_signature(None, body).unwrap(), "");

        let signature = webhook_signature(Some("test-secret"), body).unwrap();
        assert!(signature.starts_with("sha256="));
        assert_eq!(signature.len(), "sha256=".len() + 64);
    }

    #[test]
    fn metrics_state_renders_prometheus_series() {
        let metrics = MetricsState::new();
        metrics.record_secret_access(TEST_AGENT, TEST_SECRET_PATH, "approved");
        metrics.record_approval_latency(TEST_AGENT, "webhook", 4.521);
        metrics.record_encryption_op("decrypt");

        let output = metrics.render_prometheus();
        assert!(output.contains("gloves_secret_access_total"));
        assert!(output.contains(&format!("agent=\"{TEST_AGENT}\"")));
        assert!(output.contains(&format!("path=\"{TEST_SECRET_PATH}\"")));
        assert!(output.contains("gloves_approval_latency_seconds_bucket"));
        assert!(output.contains("channel=\"webhook\""));
        assert!(output.contains("gloves_encryption_ops_total{operation=\"decrypt\"} 1"));
    }

    #[test]
    fn write_http_control_response_serves_metrics_and_unknown_routes() {
        let harness = TestHarness::new();
        let mut config = harness.config.clone();
        config.metrics_enabled = true;
        let metrics = MetricsState::new();
        metrics.record_secret_access(TEST_AGENT, TEST_SECRET_PATH, "approved");

        let metrics_response = send_http_control_request(
            &config,
            metrics,
            "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        assert!(metrics_response.starts_with("HTTP/1.1 200 OK"));
        assert!(metrics_response.contains("gloves_secret_access_total"));

        let not_found_response = send_http_control_request(
            &config,
            MetricsState::new(),
            "GET /missing HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        assert!(not_found_response.starts_with("HTTP/1.1 404 Not Found"));
        assert!(not_found_response.ends_with("not found\n"));
    }

    #[test]
    fn webhook_callback_rejects_invalid_bearer_token() {
        let harness = TestHarness::new();
        let mut config = harness.config.clone();
        config.webhook_callback_token = Some("expected-callback-token".to_owned());

        let (status, body) = handle_webhook_callback(
            &config,
            "/api/v1/approve/00000000-0000-0000-0000-000000000000",
            Some("Bearer wrong-token"),
            true,
        )
        .unwrap();

        assert_eq!(status, "HTTP/1.1 401 Unauthorized");
        assert_eq!(body, "unauthorized\n");
    }

    #[test]
    fn webhook_callback_approves_pending_request() {
        let harness = TestHarness::new();
        let mut config = harness.config.clone();
        config.webhook_callback_token = Some("expected-callback-token".to_owned());
        let pending_store = pending_request_store(&config).unwrap();
        let signing_key = generate_signing_key();
        let request = pending_store
            .create(
                SecretId::new(TEST_SECRET_PATH).unwrap(),
                harness.agent_id.clone(),
                "integration approval".to_owned(),
                Duration::seconds(30),
                &signing_key,
            )
            .unwrap();

        let (status, body) = handle_webhook_callback(
            &config,
            &format!("/api/v1/approve/{}", request.id),
            Some("Bearer expected-callback-token"),
            true,
        )
        .unwrap();

        assert_eq!(status, "HTTP/1.1 200 OK");
        assert_eq!(body, "approved\n");

        let stored_request = pending_store
            .load_all()
            .unwrap()
            .into_iter()
            .find(|candidate| candidate.id == request.id)
            .unwrap();
        assert_eq!(stored_request.status, RequestStatus::Fulfilled);
        assert_eq!(
            stored_request.approved_by.as_ref().map(AgentId::as_str),
            Some(WEBHOOK_CALLBACK_APPROVER_AGENT_ID)
        );
    }

    #[test]
    fn write_http_control_response_denies_pending_requests() {
        let harness = TestHarness::new();
        let mut config = harness.config.clone();
        config.webhook_callback_token = Some("expected-callback-token".to_owned());
        let pending_store = pending_request_store(&config).unwrap();
        let signing_key = generate_signing_key();
        let request = pending_store
            .create(
                SecretId::new(TEST_SECRET_PATH).unwrap(),
                harness.agent_id.clone(),
                "integration denial".to_owned(),
                Duration::seconds(30),
                &signing_key,
            )
            .unwrap();

        let response = send_http_control_request(
            &config,
            MetricsState::new(),
            &format!(
                "POST /api/v1/deny/{request_id} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer expected-callback-token\r\n\r\n",
                request_id = request.id
            ),
        );
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.ends_with("denied\n"));

        let stored_request = pending_store
            .load_all()
            .unwrap()
            .into_iter()
            .find(|candidate| candidate.id == request.id)
            .unwrap();
        assert_eq!(stored_request.status, RequestStatus::Denied);
    }

    #[test]
    fn authenticate_initialize_request_accepts_valid_meta() {
        let harness = TestHarness::new();
        let mut request =
            InitializeRequestParams::new(Default::default(), Implementation::new("test", "1.0.0"))
                .with_protocol_version(ProtocolVersion::V_2025_06_18);
        let mut meta = rmcp::model::Meta::new();
        meta.insert("sessionToken".to_owned(), json!(TEST_SESSION_TOKEN));
        meta.insert("agentId".to_owned(), json!(TEST_AGENT));
        request.meta = Some(meta);

        let session = authenticate_initialize_request(
            &harness.config,
            TEST_SESSION_TOKEN,
            request.meta.as_ref().unwrap(),
            None,
        )
        .unwrap();

        assert_eq!(session.agent_id.as_str(), TEST_AGENT);
        assert_eq!(mcp_server_info().server_info.name, "gloves-mcp");
    }

    #[test]
    fn authenticate_initialize_request_rejects_invalid_token() {
        let harness = TestHarness::new();
        let mut request =
            InitializeRequestParams::new(Default::default(), Implementation::new("test", "1.0.0"))
                .with_protocol_version(ProtocolVersion::V_2025_06_18);
        let mut meta = rmcp::model::Meta::new();
        meta.insert("sessionToken".to_owned(), json!("bad-token"));
        meta.insert("agentId".to_owned(), json!(TEST_AGENT));
        request.meta = Some(meta);

        let error = authenticate_initialize_request(
            &harness.config,
            TEST_SESSION_TOKEN,
            request.meta.as_ref().unwrap(),
            None,
        )
        .unwrap_err();

        assert_eq!(i64::from(error.code.0), AUTH_FAILED_CODE);
        assert_eq!(
            error
                .data
                .as_ref()
                .and_then(|value| value.get("reason"))
                .and_then(Value::as_str),
            Some("invalid_token")
        );
    }

    #[test]
    fn gloves_mcp_server_rejects_tool_calls_before_initialize() {
        let harness = TestHarness::new();
        let server = GlovesMcpServer::new(
            harness.config.clone(),
            TEST_SESSION_TOKEN.to_owned(),
            Some(TEST_AGENT.to_owned()),
            true,
        );

        let error = server.authenticated_session().unwrap_err();
        assert_eq!(error.message, "session not initialized");
        assert_eq!(
            error.data.as_ref().and_then(|value| value.get("reason")),
            Some(&json!("missing_session"))
        );
    }

    #[tokio::test]
    async fn gloves_mcp_server_supports_in_process_rmcp_secret_flow() {
        let harness = TestHarness::new();
        let recipient = load_agent_recipient(&harness.config, &harness.agent_id).unwrap();
        harness.write_secret(TEST_SECRET_PATH, &[recipient], TEST_SECRET_VALUE);

        let server = GlovesMcpServer::new(
            harness.config.clone(),
            TEST_SESSION_TOKEN.to_owned(),
            Some(TEST_AGENT.to_owned()),
            true,
        );
        let (server_transport, client_transport) = tokio::io::duplex(4096);
        let server_task =
            tokio::spawn(async move { serve_rmcp_connection(server, server_transport).await });

        let client_handler = SecretCapturingClient::new(client_info_with_session_meta(
            TEST_SESSION_TOKEN,
            TEST_AGENT,
        ));
        let client = client_handler
            .clone()
            .serve(client_transport)
            .await
            .unwrap();

        let tools = client.list_tools(Default::default()).await.unwrap();
        assert!(tools.tools.iter().any(|tool| tool.name == GLOVES_GET_TOOL));

        let get_result = client
            .call_tool(
                CallToolRequestParams::new(GLOVES_GET_TOOL).with_arguments(
                    json!({ "path": TEST_SECRET_PATH })
                        .as_object()
                        .unwrap()
                        .clone(),
                ),
            )
            .await
            .unwrap();
        assert_eq!(
            get_result
                .structured_content
                .as_ref()
                .and_then(|value| value.get("path"))
                .and_then(Value::as_str),
            Some(TEST_SECRET_PATH)
        );

        tokio::time::timeout(StdDuration::from_secs(5), client_handler.signal.notified())
            .await
            .unwrap();
        let notification_payload = client_handler.payload.lock().await.clone().unwrap();
        assert_eq!(notification_payload["path"], TEST_SECRET_PATH);
        assert_eq!(notification_payload["value"], TEST_SECRET_VALUE);

        client.cancel().await.unwrap();
        server_task.await.unwrap().unwrap();
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
        assert_eq!(get_result.metadata.path, TEST_SECRET_PATH);
        assert_eq!(get_result.metadata.secret_length, TEST_SECRET_VALUE.len());

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
        assert_eq!(list_response.payload["structuredContent"]["count"], 1);

        let show_response = handle_tool_call(
            &harness.config,
            &session,
            Some(&json!({
                "name": GLOVES_SHOW_TOOL,
                "arguments": { "path": TEST_SECRET_PATH }
            })),
        )
        .unwrap();
        assert_eq!(
            show_response.payload["structuredContent"]["name"],
            TEST_SECRET_PATH
        );

        let get_response = handle_tool_call(
            &harness.config,
            &session,
            Some(&json!({
                "name": GLOVES_GET_TOOL,
                "arguments": { "path": TEST_SECRET_PATH }
            })),
        )
        .unwrap();
        let content_text = get_response.payload["content"][0]["text"].as_str().unwrap();
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
                "name": "gloves_unknown",
                "arguments": {}
            })),
        )
        .unwrap_err();
        assert_eq!(unsupported.0, INTERNAL_ERROR_CODE);
    }

    #[test]
    fn handle_set_tool_requires_environment_variable() {
        let harness = TestHarness::new();
        let session = harness.session_for(&harness.agent_id);
        let path = "agents/devy/api-keys/openai";
        let arguments = Map::from_iter([
            ("path".to_owned(), json!(path)),
            ("from_env".to_owned(), json!("GLOVES_TEST_MISSING_SECRET")),
        ]);
        env::remove_var("GLOVES_TEST_MISSING_SECRET");

        let error = handle_set_tool(&harness.config, &session, &arguments).unwrap_err();
        assert_eq!(error.0, INVALID_PARAMS_CODE);
        assert!(error.2["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("environment variable `GLOVES_TEST_MISSING_SECRET` is not set"));
    }

    #[test]
    fn handle_approve_tool_rejects_invalid_requests_and_decisions() {
        let harness = TestHarness::new();
        let session = harness.session_for(&harness.agent_id);

        let invalid_uuid = Map::from_iter([
            ("request_id".to_owned(), json!("not-a-uuid")),
            ("decision".to_owned(), json!("approve")),
        ]);
        let uuid_error = handle_approve_tool(&harness.config, &session, &invalid_uuid).unwrap_err();
        assert_eq!(uuid_error.0, INVALID_PARAMS_CODE);

        let invalid_decision = Map::from_iter([
            ("request_id".to_owned(), json!(Uuid::new_v4().to_string())),
            ("decision".to_owned(), json!("later")),
        ]);
        let decision_error =
            handle_approve_tool(&harness.config, &session, &invalid_decision).unwrap_err();
        assert_eq!(decision_error.0, INVALID_PARAMS_CODE);
        assert!(decision_error.2["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("`decision` must be `approve` or `deny`"));
    }

    #[test]
    fn handle_rotate_tool_rejects_cross_agent_rotation() {
        let harness = TestHarness::new();
        let session = harness.session_for(&harness.agent_id);
        let arguments = Map::from_iter([("agent_id".to_owned(), json!(TEST_OTHER_AGENT))]);

        let error = handle_rotate_tool(&harness.config, &session, &arguments).unwrap_err();
        assert_eq!(error.0, PERMISSION_DENIED_CODE);
        assert_eq!(error.2["reason"], "cross_agent_rotation_denied");
    }

    #[test]
    fn handle_set_and_delete_tools_cover_success_and_deny_paths() {
        let harness = TestHarness::new();
        let session = harness.session_for(&harness.agent_id);
        let path = "agents/devy/api-keys/openai";
        let env_var = "GLOVES_TEST_SET_SECRET";
        let recipient = load_agent_recipient(&harness.config, &harness.agent_id).unwrap();
        fs::write(
            harness.config.store_path.join(RULES_FILE_NAME),
            format!(
                "version: 1\ncreation_rules:\n  - path_regex: ^agents/devy/.*$\n    age:\n      - {recipient}\n"
            ),
        )
        .unwrap();
        env::set_var(env_var, "sk-live-test");

        let set_arguments = Map::from_iter([
            ("path".to_owned(), json!(path)),
            ("from_env".to_owned(), json!(env_var)),
        ]);
        let set_result = handle_set_tool(&harness.config, &session, &set_arguments).unwrap();
        env::remove_var(env_var);

        assert_eq!(set_result.payload["structuredContent"]["path"], path);
        assert_eq!(set_result.payload["structuredContent"]["agent"], TEST_AGENT);
        assert!(set_result.secret_value.is_none());

        let shown = show_secret(&harness.config, path).unwrap();
        assert_eq!(shown.length, "sk-live-test".len());

        let delete_arguments = Map::from_iter([("path".to_owned(), json!(path))]);
        let delete_error =
            handle_delete_tool(&harness.config, &session, &delete_arguments).unwrap_err();
        assert_eq!(delete_error.0, APPROVAL_DENIED_CODE);
        assert_eq!(delete_error.2["reason"], "destructive_operations_denied");
    }

    #[test]
    fn handle_approve_tool_updates_pending_request_states() {
        let harness = TestHarness::new();
        let session = harness.session_for(&harness.agent_id);
        let store = pending_request_store(&harness.config).unwrap();
        let signing_key = generate_signing_key();
        let first_request = store
            .create(
                SecretId::new(TEST_SECRET_PATH).unwrap(),
                harness.agent_id.clone(),
                "approve me".to_owned(),
                Duration::seconds(30),
                &signing_key,
            )
            .unwrap();
        let second_request = store
            .create(
                SecretId::new(TEST_SECRET_PATH).unwrap(),
                harness.agent_id.clone(),
                "deny me".to_owned(),
                Duration::seconds(30),
                &signing_key,
            )
            .unwrap();

        let approve_arguments = Map::from_iter([
            ("request_id".to_owned(), json!(first_request.id.to_string())),
            ("decision".to_owned(), json!("approve")),
        ]);
        let approve_result =
            handle_approve_tool(&harness.config, &session, &approve_arguments).unwrap();
        assert_eq!(
            approve_result.payload["structuredContent"]["decision"],
            "approve"
        );

        let deny_arguments = Map::from_iter([
            (
                "request_id".to_owned(),
                json!(second_request.id.to_string()),
            ),
            ("decision".to_owned(), json!("deny")),
        ]);
        let deny_result = handle_approve_tool(&harness.config, &session, &deny_arguments).unwrap();
        assert_eq!(deny_result.payload["structuredContent"]["decision"], "deny");

        let requests = store.load_all().unwrap();
        let approved = requests
            .iter()
            .find(|request| request.id == first_request.id)
            .unwrap();
        assert_eq!(approved.status, RequestStatus::Fulfilled);
        let denied = requests
            .iter()
            .find(|request| request.id == second_request.id)
            .unwrap();
        assert_eq!(denied.status, RequestStatus::Denied);
    }

    #[test]
    fn wait_for_external_approval_handles_approved_and_denied_requests() {
        let approval_timeout_seconds = 3;
        let harness = TestHarness::new();
        let mut config = harness.config.clone();
        config.approval_channel = ApprovalChannel::Tty;
        config.approval_timeout_seconds = approval_timeout_seconds;
        let session = harness.session_for(&harness.agent_id);

        let approve_config = config.clone();
        let approve_agent = harness.agent_id.clone();
        let approve_secret = TEST_SECRET_PATH.to_owned();
        let approver = std::thread::spawn(move || {
            let store = pending_request_store(&approve_config).unwrap();
            let deadline =
                std::time::Instant::now() + StdDuration::from_secs(approval_timeout_seconds);
            loop {
                if let Some(request) = store
                    .load_all()
                    .unwrap()
                    .into_iter()
                    .find(|request| request.secret_name.as_str() == approve_secret)
                {
                    store.approve(request.id, approve_agent.clone()).unwrap();
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "approval request missing"
                );
                std::thread::sleep(StdDuration::from_millis(10));
            }
        });
        let approved =
            wait_for_external_approval(&config, &session, GLOVES_GET_TOOL, TEST_SECRET_PATH)
                .unwrap();
        approver.join().unwrap();
        assert_eq!(approved.status, "approved");

        let deny_secret = "agents/devy/api-keys/stripe";
        let deny_config = config.clone();
        let deny_agent = harness.agent_id.clone();
        let denier = std::thread::spawn(move || {
            let store = pending_request_store(&deny_config).unwrap();
            let deadline =
                std::time::Instant::now() + StdDuration::from_secs(approval_timeout_seconds);
            loop {
                if let Some(request) = store
                    .load_all()
                    .unwrap()
                    .into_iter()
                    .find(|request| request.secret_name.as_str() == deny_secret)
                {
                    store.deny(request.id, deny_agent.clone()).unwrap();
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "denial request missing"
                );
                std::thread::sleep(StdDuration::from_millis(10));
            }
        });
        let denied = wait_for_external_approval(&config, &session, GLOVES_GET_TOOL, deny_secret)
            .unwrap_err();
        denier.join().unwrap();
        assert_eq!(denied.0, APPROVAL_DENIED_CODE);
        assert_eq!(denied.2["reason"], "request_denied");
    }

    #[test]
    fn map_runtime_error_covers_identity_and_runtime_variants() {
        let identity_error = map_runtime_error(GlovesError::InvalidInput(
            "identity file not found: /tmp/devy.age".to_owned(),
        ));
        assert_eq!(identity_error.0, IDENTITY_ERROR_CODE);

        let invalid = map_runtime_error(GlovesError::InvalidInput("bad input".to_owned()));
        assert_eq!(invalid.0, INVALID_PARAMS_CODE);

        let forbidden = map_runtime_error(GlovesError::Forbidden);
        assert_eq!(forbidden.0, PERMISSION_DENIED_CODE);

        let already_exists = map_runtime_error(GlovesError::AlreadyExists);
        assert_eq!(already_exists.2["reason"], "already_exists");

        let expired = map_runtime_error(GlovesError::Expired);
        assert_eq!(expired.2["reason"], "expired");

        let gpg_denied = map_runtime_error(GlovesError::GpgDenied);
        assert_eq!(gpg_denied.2["reason"], "gpg_denied");

        let integrity = map_runtime_error(GlovesError::IntegrityViolation);
        assert_eq!(integrity.0, CRYPTO_ERROR_CODE);
    }

    #[test]
    fn approval_and_argument_helpers_cover_edge_cases() {
        assert_eq!(
            ApprovalChannel::parse("AUTO").unwrap(),
            ApprovalChannel::Auto
        );
        assert_eq!(ApprovalChannel::Webhook.as_str(), "webhook");
        assert!(ApprovalChannel::parse("smtp").is_err());

        let mut arguments = Map::new();
        arguments.insert("value".to_owned(), json!("secret"));
        arguments.insert("empty".to_owned(), json!("   "));
        arguments.insert("number".to_owned(), json!(42));
        assert_eq!(
            required_string_argument(&arguments, "value").unwrap(),
            "secret"
        );
        assert_eq!(optional_string_argument(&arguments, "empty").unwrap(), None);
        assert_eq!(
            optional_string_argument(&arguments, "missing").unwrap(),
            None
        );
        assert_eq!(
            optional_string_argument(&arguments, "number")
                .unwrap_err()
                .0,
            INVALID_PARAMS_CODE
        );
        assert_eq!(
            required_string_argument(&arguments, "missing")
                .unwrap_err()
                .0,
            INVALID_PARAMS_CODE
        );
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
    fn map_rmcp_error_and_tool_deserialization_preserve_payload_shape() {
        let mapped = map_rmcp_error(rmcp::RmcpError::TaskError("bad frame".to_owned()));
        assert!(mapped.to_string().contains("bad frame"));

        let mcp_error = tuple_to_mcp_error(invalid_params_error("bad input"));
        assert_eq!(i64::from(mcp_error.code.0), INVALID_PARAMS_CODE);
        assert_eq!(mcp_error.message, "Invalid params");

        let runtime_error = tuple_to_mcp_error_from_runtime(GlovesError::Unauthorized);
        assert_eq!(i64::from(runtime_error.code.0), PERMISSION_DENIED_CODE);

        let tools = deserialize_tool_definitions().unwrap();
        assert_eq!(tools.len(), tool_definitions().len());
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
    fn path_and_recipient_helpers_resolve_namespaces_and_merge_rules() {
        let harness = TestHarness::new();
        let namespace = Path::new("agents/devy");
        ensure_private_dir(&harness.config.store_path.join(namespace)).unwrap();
        fs::write(
            harness.config.store_path.join(RULES_FILE_NAME),
            "version: 1\ncreation_rules:\n  - path_regex: ^agents/devy/.*$\n    age:\n      - age1-rule\n      - age1-shared\n",
        )
        .unwrap();
        write_namespace_recipients(
            &harness.config,
            namespace,
            &["age1-namespace".to_owned(), "age1-shared".to_owned()],
            true,
        )
        .unwrap();
        fs::write(
            namespace_recipients_file(&harness.config, namespace),
            "# ignored\nage1-namespace\n\nage1-shared\n",
        )
        .unwrap();

        let resolved = resolve_recipients(&harness.config, TEST_SECRET_PATH, namespace).unwrap();
        assert_eq!(
            resolved,
            vec![
                "age1-namespace".to_owned(),
                "age1-rule".to_owned(),
                "age1-shared".to_owned(),
            ]
        );
        assert_eq!(
            namespace_for_secret_path(TEST_SECRET_PATH).unwrap(),
            PathBuf::from("agents").join(TEST_AGENT)
        );
        assert_eq!(
            namespace_for_secret_path("shared/database-url").unwrap(),
            PathBuf::from("shared")
        );
        assert_eq!(scope_agent("shared/database-url"), "shared");
        assert!(namespace_for_secret_path("agents").is_err());
        assert!(validated_relative_path("../escape").is_err());
    }

    #[test]
    fn resolve_approval_covers_auto_deny_and_timeout_paths() {
        let harness = TestHarness::new();
        let session = harness.session_for(&harness.agent_id);

        let auto_resolution =
            resolve_approval(&harness.config, &session, GLOVES_GET_TOOL, TEST_SECRET_PATH).unwrap();
        assert_eq!(auto_resolution.status, "auto");

        let deny_error = resolve_approval(
            &harness.config,
            &session,
            GLOVES_DELETE_TOOL,
            TEST_SECRET_PATH,
        )
        .unwrap_err();
        assert_eq!(deny_error.0, APPROVAL_DENIED_CODE);

        let mut tty_config = harness.config.clone();
        tty_config.approval_channel = ApprovalChannel::Tty;
        tty_config.approval_timeout_seconds = 0;
        let timeout_error =
            resolve_approval(&tty_config, &session, GLOVES_GET_TOOL, TEST_SECRET_PATH).unwrap_err();
        assert_eq!(timeout_error.0, APPROVAL_TIMEOUT_CODE);

        let audit_file = harness
            .config
            .audit_path
            .join(format!("{}.jsonl", Utc::now().format("%Y-%m-%d")));
        let contents = fs::read_to_string(audit_file).unwrap();
        assert!(contents.contains("\"event_type\":\"approval_denied\""));
        assert!(contents.contains("\"event_type\":\"approval_requested\""));
    }

    #[test]
    fn send_webhook_approval_request_requires_callback_bind() {
        let harness = TestHarness::new();
        let session = harness.session_for(&harness.agent_id);
        let mut config = harness.config.clone();
        config.webhook_url = Some("http://127.0.0.1:9000/approve".to_owned());
        config.metrics_bind = None;

        let error = send_webhook_approval_request(
            &config,
            &session,
            GLOVES_GET_TOOL,
            TEST_SECRET_PATH,
            Uuid::new_v4(),
            Utc::now(),
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("webhook callbacks require an HTTP bind address"));
    }

    #[test]
    fn config_path_helpers_cover_default_relative_absolute_and_missing_values() {
        let temp = TempDir::new().unwrap();
        let config_dir = temp.path();
        let absolute = temp.path().join("daemon.sock");

        assert_eq!(
            resolve_config_path(Some("store"), config_dir, None, "store.path").unwrap(),
            config_dir.join("store")
        );
        assert_eq!(
            resolve_config_path(None, config_dir, Some("audit"), "audit.path").unwrap(),
            config_dir.join("audit")
        );
        assert_eq!(
            resolve_config_path(
                Some(absolute.to_str().unwrap()),
                config_dir,
                None,
                "daemon.socket_path"
            )
            .unwrap(),
            absolute
        );
        assert_eq!(
            resolve_optional_config_path(Some("daemon.sock"), config_dir).unwrap(),
            Some(config_dir.join("daemon.sock"))
        );
        assert_eq!(
            resolve_optional_config_path(None, config_dir).unwrap(),
            None
        );

        let error =
            resolve_config_path(None, config_dir, None, "daemon.session_token_path").unwrap_err();
        assert!(error
            .to_string()
            .contains("missing required configuration field"));
    }

    #[test]
    fn post_json_sends_http_payload_and_reports_non_success_responses() {
        let body = br#"{"hello":"world"}"#;
        let mut success_stream =
            MemoryStream::new("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        post_json_over_stream(
            &mut success_stream,
            "localhost",
            "/approve",
            body,
            Some("sha256=test-signature"),
        )
        .unwrap();

        let written_request = success_stream.written_string();
        let mut reader = BufReader::new(Cursor::new(written_request.into_bytes()));
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        let mut headers = BTreeMap::new();
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
            let (name, value) = line.split_once(':').unwrap();
            let value = value.trim().to_owned();
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse().unwrap();
            }
            headers.insert(name.to_ascii_lowercase(), value);
        }
        let mut received_body = vec![0_u8; content_length];
        reader.read_exact(&mut received_body).unwrap();

        assert_eq!(request_line.trim(), "POST /approve HTTP/1.1");
        assert_eq!(headers.get("host"), Some(&"localhost".to_owned()));
        assert_eq!(
            headers.get("x-gloves-signature"),
            Some(&"sha256=test-signature".to_owned())
        );
        assert_eq!(received_body, body);

        let mut error_stream = MemoryStream::new(
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        let error = post_json_over_stream(&mut error_stream, "localhost", "/reject", b"{}", None)
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("webhook returned non-success response"));
    }

    #[test]
    fn http_helper_functions_cover_auth_and_callback_edge_cases() {
        let harness = TestHarness::new();
        let mut config = harness.config.clone();
        config.webhook_callback_token = Some("expected-callback-token".to_owned());

        let mut reader = BufReader::new(Cursor::new(
            b"Host: localhost\r\nAuthorization: Bearer expected-callback-token\r\n\r\n".to_vec(),
        ));
        assert_eq!(
            read_authorization_header(&mut reader).unwrap(),
            Some("Bearer expected-callback-token".to_owned())
        );

        let missing_token_error =
            handle_webhook_callback(&harness.config, "/api/v1/approve/not-a-uuid", None, true)
                .unwrap_err();
        assert!(missing_token_error
            .to_string()
            .contains("webhook callback token is not configured"));

        let invalid_uuid_error = handle_webhook_callback(
            &config,
            "/api/v1/approve/not-a-uuid",
            Some("Bearer expected-callback-token"),
            true,
        )
        .unwrap_err();
        assert!(invalid_uuid_error
            .to_string()
            .contains("invalid webhook request id"));
    }

    #[test]
    fn approval_histogram_lines_escape_labels_and_emit_summaries() {
        let mut lines = Vec::new();
        append_approval_histogram_lines(
            &mut lines,
            &[
                ("de\"vy".to_owned(), "web\\hook".to_owned(), 0.4),
                ("de\"vy".to_owned(), "web\\hook".to_owned(), 6.0),
            ],
        );

        assert_eq!(
            escape_metric_label("line\\break\"test\n"),
            "line\\\\break\\\"test\\n"
        );
        assert!(lines
            .iter()
            .any(|line| line.contains("channel=\"web\\\\hook\"")));
        assert!(lines.iter().any(|line| line.contains("agent=\"de\\\"vy\"")));
        assert!(lines.iter().any(|line| line.contains("le=\"+Inf\"")));
        assert!(lines.iter().any(|line| line.contains("_sum")));
        assert!(lines.iter().any(|line| line.contains("_count")));
    }

    #[cfg(unix)]
    #[test]
    fn run_gloves_rotate_surfaces_subprocess_failures() {
        let _lock = PATH_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        let harness = TestHarness::new();
        let temp = TempDir::new().unwrap();
        let script_path = temp.path().join(GLOVES_BINARY_NAME);
        fs::write(
            &script_path,
            "#!/bin/sh\necho 'rotate failed for test' >&2\nexit 1\n",
        )
        .unwrap();
        fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755)).unwrap();

        let previous_path = env::var_os("PATH");
        env::set_var("PATH", temp.path());
        let error = run_gloves_rotate(&harness.config, TEST_AGENT).unwrap_err();
        match previous_path {
            Some(value) => env::set_var("PATH", value),
            None => env::remove_var("PATH"),
        }

        assert!(error.to_string().contains("rotate failed for test"));
    }

    #[cfg(unix)]
    #[test]
    fn run_gloves_rotate_reports_empty_stderr_failures() {
        let _lock = PATH_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        let harness = TestHarness::new();
        let temp = TempDir::new().unwrap();
        let script_path = temp.path().join(GLOVES_BINARY_NAME);
        fs::write(&script_path, "#!/bin/sh\nexit 1\n").unwrap();
        fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755)).unwrap();

        let previous_path = env::var_os("PATH");
        env::set_var("PATH", temp.path());
        let error = run_gloves_rotate(&harness.config, TEST_AGENT).unwrap_err();
        match previous_path {
            Some(value) => env::set_var("PATH", value),
            None => env::remove_var("PATH"),
        }

        assert!(error
            .to_string()
            .contains("gloves rotate failed without stderr output"));
    }

    #[test]
    fn expand_tilde_uses_home_directory() {
        let _lock = HOME_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        let home = env::var(HOME_ENV_VAR).unwrap();
        assert_eq!(expand_tilde("~").unwrap(), home);
        let expanded = expand_tilde("~/gloves-test").unwrap();
        assert_eq!(
            expanded,
            Path::new(&home).join("gloves-test").display().to_string()
        );

        let previous_home = env::var_os(HOME_ENV_VAR);
        env::remove_var(HOME_ENV_VAR);
        let missing_home_error = expand_tilde("~").unwrap_err();
        match previous_home {
            Some(value) => env::set_var(HOME_ENV_VAR, value),
            None => env::remove_var(HOME_ENV_VAR),
        }
        assert!(missing_home_error
            .to_string()
            .contains("HOME must be set to expand `~`"));
    }

    #[test]
    fn resolve_config_paths_handle_required_relative_and_optional_values() {
        let temp = TempDir::new().unwrap();
        let config_dir = temp.path();

        let relative = resolve_config_path(Some("store"), config_dir, None, "store.path").unwrap();
        assert_eq!(relative, config_dir.join("store"));

        let defaulted = resolve_config_path(None, config_dir, Some("audit"), "audit.path").unwrap();
        assert_eq!(defaulted, config_dir.join("audit"));

        let optional = resolve_optional_config_path(Some("socket.sock"), config_dir).unwrap();
        assert_eq!(optional, Some(config_dir.join("socket.sock")));
        assert_eq!(
            resolve_optional_config_path(None, config_dir).unwrap(),
            None
        );

        let error =
            resolve_config_path(None, config_dir, None, "daemon.session_token_path").unwrap_err();
        assert!(error
            .to_string()
            .contains("missing required configuration field"));
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
                GLOVES_ROTATE_TOOL,
            ]
        );
    }

    fn scope_agent_for_tests(secret_path: &str) -> String {
        secret_path.split('/').nth(1).unwrap_or("shared").to_owned()
    }
}
