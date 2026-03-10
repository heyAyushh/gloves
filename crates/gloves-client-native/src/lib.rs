use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::net::UnixStream;

use napi::{bindgen_prelude::AsyncTask, Error, Status, Task};
use napi_derive::napi;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const DEFAULT_TIMEOUT_MS: u64 = 10_000;
const INITIALIZE_METHOD: &str = "initialize";
const INITIALIZED_NOTIFICATION: &str = "notifications/initialized";
const TOOLS_CALL_METHOD: &str = "tools/call";
const SECRET_NOTIFICATION_METHOD: &str = "gloves/secret";
const SESSION_TOKEN_ENV_VAR: &str = "GLOVES_SESSION_TOKEN_PATH";

#[derive(Clone)]
struct NativeClientConfig {
    _root: String,
    agent_id: String,
    mcp_config_path: String,
    token_path: String,
    socket_path: Option<String>,
    gloves_mcp_bin: String,
    cwd: Option<String>,
    timeout_ms: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct JsonRpcMessage {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize, Serialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

#[derive(Clone, Debug)]
struct ToolCallResult {
    response: Value,
    secret_value: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[napi(object)]
pub struct NativeSecretMetadata {
    pub name: String,
    pub exists: bool,
    pub length: u32,
    pub agent: String,
    #[napi(js_name = "encryptedTo")]
    pub encrypted_to: Vec<String>,
    pub created: String,
    pub modified: String,
    #[napi(js_name = "lastRotated")]
    pub last_rotated: String,
    #[napi(js_name = "lastAccessed")]
    pub last_accessed: Option<String>,
    #[napi(js_name = "fileSize")]
    pub file_size: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[napi(object)]
pub struct NativeGetSecretResult {
    pub value: String,
    pub metadata: NativeSecretMetadata,
    #[napi(js_name = "approvalStatus")]
    pub approval_status: String,
    #[napi(js_name = "approvalLatencyMs")]
    pub approval_latency_ms: f64,
}

#[napi]
pub struct NativeGlovesClient {
    config: NativeClientConfig,
}

#[napi]
impl NativeGlovesClient {
    #[napi(constructor)]
    pub fn new(
        root: String,
        agent_id: String,
        mcp_config_path: String,
        token_path: String,
        socket_path: Option<String>,
        _gloves_bin: Option<String>,
        gloves_mcp_bin: Option<String>,
        cwd: Option<String>,
        timeout_ms: Option<u32>,
    ) -> Self {
        Self {
            config: NativeClientConfig {
                _root: root,
                agent_id,
                mcp_config_path,
                token_path,
                socket_path,
                gloves_mcp_bin: gloves_mcp_bin.unwrap_or_else(|| "gloves-mcp".to_owned()),
                cwd,
                timeout_ms: timeout_ms.map(u64::from).unwrap_or(DEFAULT_TIMEOUT_MS),
            },
        }
    }

    #[napi]
    pub fn list(&self, prefix: Option<String>) -> AsyncTask<ListSecretsTask> {
        AsyncTask::new(ListSecretsTask {
            config: self.config.clone(),
            prefix,
        })
    }

    #[napi]
    pub fn show(&self, path: String) -> AsyncTask<ShowSecretTask> {
        AsyncTask::new(ShowSecretTask {
            config: self.config.clone(),
            path,
        })
    }

    #[napi]
    pub fn get(&self, path: String) -> AsyncTask<GetSecretTask> {
        AsyncTask::new(GetSecretTask {
            config: self.config.clone(),
            path,
        })
    }

    #[napi]
    pub fn set(&self, path: String, value: String) -> AsyncTask<SetSecretTask> {
        AsyncTask::new(SetSecretTask {
            config: self.config.clone(),
            path,
            value,
        })
    }

    #[napi]
    pub fn delete(&self, path: String) -> AsyncTask<DeleteSecretTask> {
        AsyncTask::new(DeleteSecretTask {
            config: self.config.clone(),
            path,
        })
    }

    #[napi]
    pub fn rotate(&self, agent_id: String) -> AsyncTask<RotateAgentTask> {
        AsyncTask::new(RotateAgentTask {
            config: self.config.clone(),
            agent_id,
        })
    }

    #[napi]
    pub fn approve(
        &self,
        request_id: String,
        decision: String,
        reason: Option<String>,
    ) -> AsyncTask<ApproveRequestTask> {
        AsyncTask::new(ApproveRequestTask {
            config: self.config.clone(),
            request_id,
            decision,
            reason,
        })
    }
}

pub struct ListSecretsTask {
    config: NativeClientConfig,
    prefix: Option<String>,
}

impl Task for ListSecretsTask {
    type Output = Vec<String>;
    type JsValue = Vec<String>;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        list_secrets(&self.config, self.prefix.clone())
    }

    fn resolve(&mut self, _: napi::Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(output)
    }
}

pub struct ShowSecretTask {
    config: NativeClientConfig,
    path: String,
}

impl Task for ShowSecretTask {
    type Output = NativeSecretMetadata;
    type JsValue = NativeSecretMetadata;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        show_secret(&self.config, self.path.clone())
    }

    fn resolve(&mut self, _: napi::Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(output)
    }
}

pub struct GetSecretTask {
    config: NativeClientConfig,
    path: String,
}

impl Task for GetSecretTask {
    type Output = NativeGetSecretResult;
    type JsValue = NativeGetSecretResult;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        get_secret(&self.config, self.path.clone())
    }

    fn resolve(&mut self, _: napi::Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(output)
    }
}

pub struct SetSecretTask {
    config: NativeClientConfig,
    path: String,
    value: String,
}

impl Task for SetSecretTask {
    type Output = ();
    type JsValue = ();

    fn compute(&mut self) -> napi::Result<Self::Output> {
        set_secret(&self.config, self.path.clone(), self.value.clone())
    }

    fn resolve(&mut self, _: napi::Env, _: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(())
    }
}

pub struct DeleteSecretTask {
    config: NativeClientConfig,
    path: String,
}

impl Task for DeleteSecretTask {
    type Output = ();
    type JsValue = ();

    fn compute(&mut self) -> napi::Result<Self::Output> {
        delete_secret(&self.config, self.path.clone())
    }

    fn resolve(&mut self, _: napi::Env, _: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(())
    }
}

pub struct RotateAgentTask {
    config: NativeClientConfig,
    agent_id: String,
}

impl Task for RotateAgentTask {
    type Output = ();
    type JsValue = ();

    fn compute(&mut self) -> napi::Result<Self::Output> {
        rotate_agent_identity(&self.config, self.agent_id.clone())
    }

    fn resolve(&mut self, _: napi::Env, _: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(())
    }
}

pub struct ApproveRequestTask {
    config: NativeClientConfig,
    request_id: String,
    decision: String,
    reason: Option<String>,
}

impl Task for ApproveRequestTask {
    type Output = ();
    type JsValue = ();

    fn compute(&mut self) -> napi::Result<Self::Output> {
        approve_request(
            &self.config,
            self.request_id.clone(),
            self.decision.clone(),
            self.reason.clone(),
        )
    }

    fn resolve(&mut self, _: napi::Env, _: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(())
    }
}

fn list_secrets(config: &NativeClientConfig, prefix: Option<String>) -> napi::Result<Vec<String>> {
    let result = call_tool(
        config,
        "gloves_list",
        prefix.map_or_else(|| json!({}), |value| json!({ "prefix": value })),
        None,
    )?;
    let secrets = result
        .response
        .get("structuredContent")
        .and_then(|value| value.get("secrets"))
        .and_then(Value::as_array)
        .ok_or_else(|| native_error("gloves_list did not return a secret list"))?;
    Ok(secrets
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect())
}

fn show_secret(config: &NativeClientConfig, path: String) -> napi::Result<NativeSecretMetadata> {
    let result = call_tool(config, "gloves_show", json!({ "path": path }), None)?;
    parse_metadata(result.response.get("structuredContent"))
}

fn get_secret(config: &NativeClientConfig, path: String) -> napi::Result<NativeGetSecretResult> {
    let started_at = Instant::now();
    let result = call_tool(config, "gloves_get", json!({ "path": path.clone() }), None)?;
    let secret_value = result
        .secret_value
        .ok_or_else(|| native_error("gloves_get did not deliver a secret side-channel payload"))?;
    let metadata = show_secret(config, path)?;
    let approval_status = result
        .response
        .get("structuredContent")
        .and_then(|value| value.get("approval_status"))
        .and_then(Value::as_str)
        .unwrap_or("auto")
        .to_owned();
    Ok(NativeGetSecretResult {
        value: secret_value,
        metadata,
        approval_status,
        approval_latency_ms: started_at.elapsed().as_secs_f64() * 1000.0,
    })
}

fn set_secret(config: &NativeClientConfig, path: String, value: String) -> napi::Result<()> {
    let env_name = create_set_env_name(&path);
    call_tool(
        config,
        "gloves_set",
        json!({ "path": path, "from_env": env_name }),
        Some(vec![(env_name, value)]),
    )?;
    Ok(())
}

fn delete_secret(config: &NativeClientConfig, path: String) -> napi::Result<()> {
    call_tool(config, "gloves_delete", json!({ "path": path }), None)?;
    Ok(())
}

fn rotate_agent_identity(config: &NativeClientConfig, agent_id: String) -> napi::Result<()> {
    call_tool(
        config,
        "gloves_rotate",
        json!({ "agent_id": agent_id }),
        None,
    )?;
    Ok(())
}

fn approve_request(
    config: &NativeClientConfig,
    request_id: String,
    decision: String,
    reason: Option<String>,
) -> napi::Result<()> {
    let arguments = match reason {
        Some(reason) => json!({
            "request_id": request_id,
            "decision": decision,
            "reason": reason
        }),
        None => json!({
            "request_id": request_id,
            "decision": decision
        }),
    };
    call_tool(config, "gloves_approve", arguments, None)?;
    Ok(())
}

fn call_tool(
    config: &NativeClientConfig,
    name: &str,
    arguments: Value,
    env_overrides: Option<Vec<(String, String)>>,
) -> napi::Result<ToolCallResult> {
    let request = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": TOOLS_CALL_METHOD,
        "params": {
            "name": name,
            "arguments": arguments
        }
    });
    let result = if env_overrides.is_some() || config.socket_path.is_none() {
        call_via_stdio(config, request, env_overrides)?
    } else {
        call_via_socket(config, request)?
    };
    if let Some(error) = result
        .response
        .get("error")
        .filter(|value| !value.is_null())
    {
        let code = error
            .get("code")
            .and_then(Value::as_i64)
            .unwrap_or_default();
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("gloves native client request failed");
        return Err(native_error(&format!("{message} ({code})")));
    }
    Ok(ToolCallResult {
        response: result
            .response
            .get("result")
            .cloned()
            .unwrap_or(Value::Null),
        secret_value: result.secret_value,
    })
}

fn call_via_socket(
    config: &NativeClientConfig,
    tool_request: Value,
) -> napi::Result<ToolCallResult> {
    #[cfg(unix)]
    {
        let socket_path = config
            .socket_path
            .as_deref()
            .ok_or_else(|| native_error("socketPath is required for native socket mode"))?;
        let mut stream = UnixStream::connect(socket_path).map_err(|error| {
            native_error(&format!("failed to connect to gloves socket: {error}"))
        })?;
        stream
            .set_read_timeout(Some(Duration::from_millis(config.timeout_ms)))
            .map_err(|error| {
                native_error(&format!("failed to configure socket timeout: {error}"))
            })?;
        stream
            .set_write_timeout(Some(Duration::from_millis(config.timeout_ms)))
            .map_err(|error| {
                native_error(&format!("failed to configure socket timeout: {error}"))
            })?;
        let mut reader =
            BufReader::new(stream.try_clone().map_err(|error| {
                native_error(&format!("failed to clone gloves socket: {error}"))
            })?);
        let initialize = initialize_request(
            config,
            wait_for_token(&config.token_path, config.timeout_ms)?,
        );
        write_json_line(&mut stream, &initialize)?;
        let initialize_response = read_response(&mut reader, initialize.get("id").cloned())?;
        if initialize_response.response.get("error").is_some() {
            return Err(native_error(&format_response_error(
                &initialize_response.response,
            )));
        }
        write_json_line(
            &mut stream,
            &json!({
                "jsonrpc": "2.0",
                "method": INITIALIZED_NOTIFICATION,
                "params": {}
            }),
        )?;
        write_json_line(&mut stream, &tool_request)?;
        return read_response(&mut reader, tool_request.get("id").cloned());
    }
    #[cfg(not(unix))]
    {
        let _ = config;
        let _ = tool_request;
        Err(native_error(
            "native socket transport is only supported on unix platforms",
        ))
    }
}

fn call_via_stdio(
    config: &NativeClientConfig,
    tool_request: Value,
    env_overrides: Option<Vec<(String, String)>>,
) -> napi::Result<ToolCallResult> {
    let session_token_override = create_stdio_token_path(&config.token_path);
    let previous_token = read_token_file(&session_token_override);
    let mut command = Command::new(&config.gloves_mcp_bin);
    command
        .arg("--config")
        .arg(&config.mcp_config_path)
        .arg("--agent")
        .arg(&config.agent_id)
        .arg("--stdio")
        .env(SESSION_TOKEN_ENV_VAR, &session_token_override)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = &config.cwd {
        command.current_dir(cwd);
    }
    if let Some(overrides) = env_overrides {
        for (key, value) in overrides {
            command.env(key, value);
        }
    }

    let mut child = command
        .spawn()
        .map_err(|error| native_error(&format!("failed to spawn gloves-mcp: {error}")))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| native_error("gloves-mcp did not expose stdin"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| native_error("gloves-mcp did not expose stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| native_error("gloves-mcp did not expose stderr"))?;
    let mut reader = BufReader::new(stdout);
    let initialize = initialize_request(
        config,
        wait_for_fresh_token(
            &session_token_override,
            previous_token.as_deref(),
            config.timeout_ms,
        )?,
    );
    write_json_line(&mut stdin, &initialize)?;
    let initialize_response = read_response(&mut reader, initialize.get("id").cloned())?;
    if initialize_response.response.get("error").is_some() {
        let _ = child.kill();
        let _ = fs::remove_file(&session_token_override);
        return Err(native_error(&format_response_error(
            &initialize_response.response,
        )));
    }
    write_json_line(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": INITIALIZED_NOTIFICATION,
            "params": {}
        }),
    )?;
    write_json_line(&mut stdin, &tool_request)?;
    let result = read_response(&mut reader, tool_request.get("id").cloned());
    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_file(&session_token_override);
    if result.is_err() {
        let mut stderr_reader = BufReader::new(stderr);
        let mut stderr_contents = String::new();
        let _ = stderr_reader.read_to_string(&mut stderr_contents);
    }
    result
}

fn initialize_request(config: &NativeClientConfig, session_token: String) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": INITIALIZE_METHOD,
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {
                "tools": { "listChanged": true }
            },
            "clientInfo": {
                "name": "@gloves/client-native",
                "version": "0.1.0"
            },
            "_meta": {
                "sessionToken": session_token,
                "agentId": config.agent_id
            }
        }
    })
}

fn write_json_line<W>(writer: &mut W, payload: &Value) -> napi::Result<()>
where
    W: Write,
{
    let encoded = serde_json::to_vec(payload)
        .map_err(|error| native_error(&format!("failed to encode JSON-RPC payload: {error}")))?;
    writer
        .write_all(&encoded)
        .and_then(|_| writer.write_all(b"\n"))
        .and_then(|_| writer.flush())
        .map_err(|error| native_error(&format!("failed to write JSON-RPC payload: {error}")))?;
    Ok(())
}

fn read_response<R>(reader: &mut R, request_id: Option<Value>) -> napi::Result<ToolCallResult>
where
    R: BufRead,
{
    let expected_id = request_id.unwrap_or(Value::Null);
    let mut secret_value = None;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).map_err(|error| {
            native_error(&format!("failed to read gloves-mcp response: {error}"))
        })?;
        if line.is_empty() {
            return Err(native_error("gloves-mcp closed before sending a response"));
        }
        let message: JsonRpcMessage = serde_json::from_str(line.trim_end()).map_err(|error| {
            native_error(&format!("failed to parse gloves-mcp response: {error}"))
        })?;
        if message.method.as_deref() == Some(SECRET_NOTIFICATION_METHOD) {
            if let Some(params) = message.params {
                if params.get("requestId") == Some(&expected_id) {
                    secret_value = params
                        .get("value")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                }
            }
            continue;
        }
        if message.id.as_ref().cloned().unwrap_or(Value::Null) == expected_id {
            let response = serde_json::to_value(message)
                .map_err(|error| native_error(&format!("failed to normalize response: {error}")))?;
            return Ok(ToolCallResult {
                response,
                secret_value,
            });
        }
    }
}

fn parse_metadata(value: Option<&Value>) -> napi::Result<NativeSecretMetadata> {
    let record = value.ok_or_else(|| native_error("gloves_show did not return metadata"))?;
    Ok(NativeSecretMetadata {
        name: required_string(record, "name")?,
        exists: record
            .get("exists")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        length: required_u32(record, "length")?,
        agent: required_string(record, "agent")?,
        encrypted_to: record
            .get("encrypted_to")
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        created: required_string(record, "created")?,
        modified: required_string(record, "modified")?,
        last_rotated: required_string(record, "last_rotated")?,
        last_accessed: record
            .get("last_accessed")
            .and_then(Value::as_str)
            .map(str::to_owned),
        file_size: required_u32(record, "file_size")?,
    })
}

fn required_string(record: &Value, field: &str) -> napi::Result<String> {
    record
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| native_error(&format!("missing `{field}` in gloves response")))
}

fn required_u32(record: &Value, field: &str) -> napi::Result<u32> {
    record
        .get(field)
        .and_then(Value::as_u64)
        .map(|value| value as u32)
        .ok_or_else(|| native_error(&format!("missing `{field}` in gloves response")))
}

fn format_response_error(response: &Value) -> String {
    response
        .get("error")
        .and_then(|value| value.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("gloves native client request failed")
        .to_owned()
}

fn wait_for_token(token_path: &str, timeout_ms: u64) -> napi::Result<String> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        if let Some(token) = read_token_file(token_path) {
            return Ok(token);
        }
        if Instant::now() >= deadline {
            return Err(native_error(&format!(
                "timed out waiting for session token at {token_path}"
            )));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn wait_for_fresh_token(
    token_path: &str,
    previous_token: Option<&str>,
    timeout_ms: u64,
) -> napi::Result<String> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        if let Some(token) = read_token_file(token_path) {
            if previous_token.is_none() || previous_token != Some(token.as_str()) {
                return Ok(token);
            }
        }
        if Instant::now() >= deadline {
            return Err(native_error(&format!(
                "timed out waiting for session token at {token_path}"
            )));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn read_token_file(token_path: &str) -> Option<String> {
    fs::read_to_string(token_path)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn create_stdio_token_path(token_path: &str) -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("{token_path}.stdio-{}-{timestamp}", std::process::id())
}

fn create_set_env_name(path: &str) -> String {
    let suffix = path
        .split('/')
        .last()
        .unwrap_or("SECRET")
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("GLOVES_SET_{suffix}_{timestamp}")
}

fn native_error(message: &str) -> Error {
    Error::new(Status::GenericFailure, message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs, io,
        path::{Path, PathBuf},
        sync::{Mutex, OnceLock},
        thread,
    };

    #[cfg(unix)]
    use std::{
        os::unix::{fs::PermissionsExt, net::UnixListener},
        time::Duration as StdDuration,
    };

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
            "gloves-client-native-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn cleanup_dir(path: &Path) {
        let _ = fs::remove_dir_all(path);
    }

    fn test_config(gloves_mcp_bin: &Path, token_path: &Path) -> NativeClientConfig {
        NativeClientConfig {
            _root: "/tmp/gloves".to_owned(),
            agent_id: "devy".to_owned(),
            mcp_config_path: "/tmp/gloves.toml".to_owned(),
            token_path: token_path.display().to_string(),
            socket_path: None,
            gloves_mcp_bin: gloves_mcp_bin.display().to_string(),
            cwd: None,
            timeout_ms: 2_000,
        }
    }

    #[cfg(unix)]
    fn write_executable_script(path: &Path, body: &str) {
        fs::write(path, body).unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }

    #[cfg(unix)]
    fn success_script_contents() -> &'static str {
        r#"#!/bin/sh
set -eu
printf '%s\n' "native-session-token" > "$GLOVES_SESSION_TOKEN_PATH"
IFS= read -r _init_line
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"gloves","version":"0.1.0"}}}'
IFS= read -r _initialized_line
IFS= read -r request_line
case "$request_line" in
  *'"name":"gloves_list"'*)
    printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"structuredContent":{"secrets":["agents/devy/api-keys/anthropic","shared/database-url"]}}}'
    ;;
  *'"name":"gloves_show"'*)
    printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"structuredContent":{"name":"agents/devy/api-keys/anthropic","exists":true,"length":9,"agent":"devy","encrypted_to":["age1devy"],"created":"2026-03-01T00:00:00Z","modified":"2026-03-02T00:00:00Z","last_rotated":"2026-03-03T00:00:00Z","last_accessed":"2026-03-04T00:00:00Z","file_size":247}}}'
    ;;
  *'"name":"gloves_get"'*)
    printf '%s\n' '{"jsonrpc":"2.0","method":"gloves/secret","params":{"requestId":2,"value":"sk-native"}}'
    printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"structuredContent":{"approval_status":"approved"}}}'
    ;;
  *'"name":"gloves_set"'*)
    env | grep '^GLOVES_SET_' >/dev/null
    printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"structuredContent":{"stored":true}}}'
    ;;
  *'"name":"gloves_delete"'*|*'"name":"gloves_rotate"'*|*'"name":"gloves_approve"'*)
    printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"structuredContent":{"ok":true}}}'
    ;;
  *)
    printf '%s\n' '{"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"unexpected tool"}}'
    ;;
esac
"#
    }

    #[cfg(unix)]
    fn error_script_contents() -> &'static str {
        r#"#!/bin/sh
set -eu
printf '%s\n' "native-session-token" > "$GLOVES_SESSION_TOKEN_PATH"
IFS= read -r _init_line
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"gloves","version":"0.1.0"}}}'
IFS= read -r _initialized_line
IFS= read -r _request_line
printf '%s\n' '{"jsonrpc":"2.0","id":2,"error":{"code":-32005,"message":"permission denied"}}'
"#
    }

    #[cfg(unix)]
    fn script_config(script_body: &str) -> (PathBuf, NativeClientConfig) {
        let temp_dir = unique_temp_dir("stdio");
        let script_path = temp_dir.join("fake-gloves-mcp.sh");
        let token_path = temp_dir.join("session-token");
        write_executable_script(&script_path, script_body);
        (temp_dir.clone(), test_config(&script_path, &token_path))
    }

    struct BrokenWriter;

    impl Write for BrokenWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn native_client_exposes_all_task_entrypoints() {
        let client = NativeGlovesClient::new(
            "/tmp/gloves".to_owned(),
            "devy".to_owned(),
            "/tmp/gloves.toml".to_owned(),
            "/tmp/token".to_owned(),
            Some("/tmp/gloves.sock".to_owned()),
            None,
            Some("gloves-mcp".to_owned()),
            Some("/tmp".to_owned()),
            Some(250),
        );

        let _ = client.list(Some("agents/devy".to_owned()));
        let _ = client.show("agents/devy/api-keys/anthropic".to_owned());
        let _ = client.get("agents/devy/api-keys/anthropic".to_owned());
        let _ = client.set(
            "agents/devy/api-keys/anthropic".to_owned(),
            "sk-native".to_owned(),
        );
        let _ = client.delete("agents/devy/api-keys/anthropic".to_owned());
        let _ = client.rotate("devy".to_owned());
        let _ = client.approve("req-123".to_owned(), "approve".to_owned(), None);
    }

    #[test]
    fn helper_functions_parse_metadata_and_errors() {
        let metadata = parse_metadata(Some(&json!({
            "name": "agents/devy/api-keys/anthropic",
            "exists": true,
            "length": 42,
            "agent": "devy",
            "encrypted_to": ["age1devy"],
            "created": "2026-03-01T00:00:00Z",
            "modified": "2026-03-02T00:00:00Z",
            "last_rotated": "2026-03-03T00:00:00Z",
            "last_accessed": "2026-03-04T00:00:00Z",
            "file_size": 247
        })))
        .unwrap();
        assert_eq!(metadata.name, "agents/devy/api-keys/anthropic");
        assert_eq!(metadata.length, 42);
        assert_eq!(metadata.file_size, 247);
        assert_eq!(
            metadata.last_accessed.as_deref(),
            Some("2026-03-04T00:00:00Z")
        );

        let missing = parse_metadata(Some(&json!({ "exists": true }))).unwrap_err();
        assert!(missing.reason.contains("missing `name`"));

        let required_string_error = required_string(&json!({}), "name").unwrap_err();
        assert!(required_string_error.reason.contains("missing `name`"));
        let required_u32_error = required_u32(&json!({}), "length").unwrap_err();
        assert!(required_u32_error.reason.contains("missing `length`"));

        assert_eq!(
            format_response_error(&json!({"error": {"message": "denied"}})),
            "denied"
        );
        assert_eq!(
            format_response_error(&json!({"result": {}})),
            "gloves native client request failed"
        );
        assert_eq!(native_error("boom").status, Status::GenericFailure);
    }

    #[test]
    fn token_and_name_helpers_cover_success_and_timeout_paths() {
        let _lock = test_lock();
        let temp_dir = unique_temp_dir("tokens");
        let token_path = temp_dir.join("session-token");
        let token_path_string = token_path.display().to_string();

        assert!(read_token_file(&token_path_string).is_none());
        fs::write(&token_path, "  native-token \n").unwrap();
        assert_eq!(
            read_token_file(&token_path_string).as_deref(),
            Some("native-token")
        );

        assert_eq!(
            wait_for_token(&token_path_string, 10).unwrap(),
            "native-token"
        );

        let old_token = token_path.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));
            fs::write(old_token, "next-token").unwrap();
        });
        assert_eq!(
            wait_for_fresh_token(&token_path_string, Some("native-token"), 250).unwrap(),
            "next-token"
        );

        let timeout_error =
            wait_for_fresh_token(&token_path_string, Some("next-token"), 10).unwrap_err();
        assert!(timeout_error
            .reason
            .contains("timed out waiting for session token"));

        let missing_error =
            wait_for_token(&temp_dir.join("missing").display().to_string(), 10).unwrap_err();
        assert!(missing_error
            .reason
            .contains("timed out waiting for session token"));

        let stdio_token_path = create_stdio_token_path(&token_path_string);
        assert!(stdio_token_path.starts_with(&format!("{token_path_string}.stdio-")));
        let set_env_name = create_set_env_name("agents/devy/api-keys/anthropic-key");
        assert!(set_env_name.starts_with("GLOVES_SET_ANTHROPIC_KEY_"));

        cleanup_dir(&temp_dir);
    }

    #[test]
    fn read_and_write_protocol_helpers_cover_success_and_failure() {
        let mut output = Vec::new();
        write_json_line(&mut output, &json!({"jsonrpc": "2.0", "id": 1})).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "{\"id\":1,\"jsonrpc\":\"2.0\"}\n"
        );

        let write_error = write_json_line(&mut BrokenWriter, &json!({"id": 1})).unwrap_err();
        assert!(write_error
            .reason
            .contains("failed to write JSON-RPC payload"));

        let mut reader = BufReader::new(
            br#"{"jsonrpc":"2.0","method":"gloves/secret","params":{"requestId":2,"value":"sk-native"}}
{"jsonrpc":"2.0","id":2,"result":{"structuredContent":{"approval_status":"approved"}}}
"#
            .as_slice(),
        );
        let result = read_response(&mut reader, Some(json!(2))).unwrap();
        assert_eq!(result.secret_value.as_deref(), Some("sk-native"));
        assert_eq!(
            result
                .response
                .get("result")
                .and_then(|value| value.get("structuredContent"))
                .and_then(|value| value.get("approval_status"))
                .and_then(Value::as_str),
            Some("approved")
        );

        let eof_error = read_response(&mut BufReader::new(&b""[..]), Some(json!(2))).unwrap_err();
        assert!(eof_error
            .reason
            .contains("closed before sending a response"));

        let parse_error =
            read_response(&mut BufReader::new(&b"not-json\n"[..]), Some(json!(2))).unwrap_err();
        assert!(parse_error
            .reason
            .contains("failed to parse gloves-mcp response"));
    }

    #[cfg(unix)]
    #[test]
    fn stdio_tasks_cover_success_and_error_paths() {
        let _lock = test_lock();
        let (success_dir, success_config) = script_config(success_script_contents());

        let mut list_task = ListSecretsTask {
            config: success_config.clone(),
            prefix: Some("agents/devy".to_owned()),
        };
        assert_eq!(
            <ListSecretsTask as Task>::compute(&mut list_task).unwrap(),
            vec![
                "agents/devy/api-keys/anthropic".to_owned(),
                "shared/database-url".to_owned()
            ]
        );

        let mut show_task = ShowSecretTask {
            config: success_config.clone(),
            path: "agents/devy/api-keys/anthropic".to_owned(),
        };
        let metadata = <ShowSecretTask as Task>::compute(&mut show_task).unwrap();
        assert_eq!(metadata.agent, "devy");

        let mut get_task = GetSecretTask {
            config: success_config.clone(),
            path: "agents/devy/api-keys/anthropic".to_owned(),
        };
        let get_result = <GetSecretTask as Task>::compute(&mut get_task).unwrap();
        assert_eq!(get_result.value, "sk-native");
        assert_eq!(get_result.approval_status, "approved");

        let mut set_task = SetSecretTask {
            config: success_config.clone(),
            path: "agents/devy/api-keys/anthropic".to_owned(),
            value: "sk-native".to_owned(),
        };
        <SetSecretTask as Task>::compute(&mut set_task).unwrap();

        let mut delete_task = DeleteSecretTask {
            config: success_config.clone(),
            path: "agents/devy/api-keys/anthropic".to_owned(),
        };
        <DeleteSecretTask as Task>::compute(&mut delete_task).unwrap();

        let mut rotate_task = RotateAgentTask {
            config: success_config.clone(),
            agent_id: "devy".to_owned(),
        };
        <RotateAgentTask as Task>::compute(&mut rotate_task).unwrap();

        let mut approve_task = ApproveRequestTask {
            config: success_config.clone(),
            request_id: "req-123".to_owned(),
            decision: "approve".to_owned(),
            reason: Some("needed".to_owned()),
        };
        <ApproveRequestTask as Task>::compute(&mut approve_task).unwrap();

        let (error_dir, error_config) = script_config(error_script_contents());
        let error = list_secrets(&error_config, None).unwrap_err();
        assert!(error.reason.contains("permission denied (-32005)"));

        cleanup_dir(&success_dir);
        cleanup_dir(&error_dir);
    }

    #[cfg(unix)]
    #[test]
    fn socket_transport_covers_handshake_and_tool_dispatch() {
        let _lock = test_lock();
        let temp_dir = unique_temp_dir("socket");
        let socket_path = temp_dir.join("s.sock");
        let token_path = temp_dir.join("session-token");
        fs::write(&token_path, "socket-token").unwrap();

        let listener = UnixListener::bind(&socket_path).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(StdDuration::from_millis(500)))
                .unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());

            let mut initialize = String::new();
            reader.read_line(&mut initialize).unwrap();
            let initialize_request: Value = serde_json::from_str(initialize.trim_end()).unwrap();
            assert_eq!(
                initialize_request.get("method").and_then(Value::as_str),
                Some(INITIALIZE_METHOD)
            );
            write_json_line(
                &mut stream,
                &json!({"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"gloves","version":"0.1.0"}}}),
            )
            .unwrap();

            let mut initialized = String::new();
            reader.read_line(&mut initialized).unwrap();
            let initialized_message: Value = serde_json::from_str(initialized.trim_end()).unwrap();
            assert_eq!(
                initialized_message.get("method").and_then(Value::as_str),
                Some(INITIALIZED_NOTIFICATION)
            );

            let mut tool_call = String::new();
            reader.read_line(&mut tool_call).unwrap();
            let tool_request: Value = serde_json::from_str(tool_call.trim_end()).unwrap();
            assert_eq!(
                tool_request.get("method").and_then(Value::as_str),
                Some(TOOLS_CALL_METHOD)
            );
            write_json_line(
                &mut stream,
                &json!({"jsonrpc":"2.0","id":2,"result":{"structuredContent":{"secrets":["shared/database-url"]}}}),
            )
            .unwrap();
        });

        let mut config = test_config(Path::new("/bin/false"), &token_path);
        config.socket_path = Some(socket_path.display().to_string());
        let listed = list_secrets(&config, None).unwrap();
        assert_eq!(listed, vec!["shared/database-url".to_owned()]);

        server.join().unwrap();
        cleanup_dir(&temp_dir);
    }
}
