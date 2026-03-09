use assert_cmd::Command;
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Stdio},
    thread,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::net::UnixStream;

const SECRET_PATH: &str = "agents/devy/api-keys/anthropic";
const SECRET_VALUE: &str = "sk-ant-api03-mcp-secret";
const AUTO_SET_SECRET_PATH: &str = "agents/devy/api-keys/openai";
const AUTO_SET_SECRET_VALUE: &str = "sk-proj-auto-approved";
const INIT_PROTOCOL_VERSION: &str = "2025-06-18";
const TOKEN_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
const TOKEN_WAIT_INTERVAL: Duration = Duration::from_millis(25);
const PENDING_WAIT_TIMEOUT: Duration = Duration::from_secs(5);

fn gloves_command() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("gloves"))
}

fn write_creation_rules(root: &Path, body: &str) {
    let rules_path = root.join("store/.gloves.yaml");
    fs::create_dir_all(rules_path.parent().unwrap()).unwrap();
    fs::write(rules_path, body).unwrap();
}

fn set_identity(root: &Path, agent: &str) {
    gloves_command()
        .args([
            "--root",
            root.to_str().unwrap(),
            "set-identity",
            "--agent",
            agent,
        ])
        .assert()
        .success();
}

fn set_secret(root: &Path, agent: &str, path: &str, value: &str) {
    gloves_command()
        .args([
            "--root",
            root.to_str().unwrap(),
            "--agent",
            agent,
            "set",
            path,
            "--value",
            value,
        ])
        .assert()
        .success();
}

fn write_mcp_config(
    config_path: &Path,
    root: &Path,
    token_path: &Path,
    approval_channel: &str,
    socket_path: Option<&Path>,
) {
    let audit_path = root.join("audit");
    let socket_line = socket_path
        .map(|path| format!("socket_path = {:?}\n", path))
        .unwrap_or_default();
    let config = format!(
        "[daemon]\n\
         session_token_path = {:?}\n\
         {}\
         [daemon.approval]\n\
         default_channel = {:?}\n\
         timeout_seconds = 5\n\
         [store]\n\
         path = {:?}\n\
         [identities]\n\
         path = {:?}\n\
        [audit]\n\
         path = {:?}\n",
        token_path,
        socket_line,
        approval_channel,
        root.join("store"),
        root.join("identities"),
        audit_path
    );
    fs::write(config_path, config).unwrap();
}

fn append_metrics_config(config_path: &Path, bind: &str) {
    let mut config = fs::read_to_string(config_path).unwrap();
    config.push_str(&format!(
        "[daemon.metrics]\nenabled = true\nbind = {:?}\n",
        bind
    ));
    fs::write(config_path, config).unwrap();
}

fn read_pending_request_id(root: &Path) -> String {
    let deadline = Instant::now() + PENDING_WAIT_TIMEOUT;
    let pending_path = root.join("store/.gloves-pending.json");
    loop {
        if let Ok(raw) = fs::read_to_string(&pending_path) {
            let payload: Value = serde_json::from_str(&raw).unwrap();
            if let Some(request_id) = payload
                .as_array()
                .and_then(|entries| entries.first())
                .and_then(|entry| entry["id"].as_str())
            {
                return request_id.to_owned();
            }
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for pending request"
        );
        thread::sleep(TOKEN_WAIT_INTERVAL);
    }
}

fn wait_for_token(token_path: &Path) -> String {
    let deadline = Instant::now() + TOKEN_WAIT_TIMEOUT;
    loop {
        if let Ok(token) = fs::read_to_string(token_path) {
            let token = token.trim().to_owned();
            if !token.is_empty() {
                return token;
            }
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for session token"
        );
        thread::sleep(TOKEN_WAIT_INTERVAL);
    }
}

fn wait_for_changed_token(token_path: &Path, previous_token: &str) -> String {
    let deadline = Instant::now() + TOKEN_WAIT_TIMEOUT;
    loop {
        let token = wait_for_token(token_path);
        if token != previous_token {
            return token;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for refreshed session token"
        );
        thread::sleep(TOKEN_WAIT_INTERVAL);
    }
}

fn allocate_loopback_bind_address() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let bind = listener.local_addr().unwrap().to_string();
    drop(listener);
    bind
}

fn fetch_metrics(bind: &str) -> String {
    let deadline = Instant::now() + TOKEN_WAIT_TIMEOUT;
    loop {
        if let Ok(mut stream) = TcpStream::connect(bind) {
            stream
                .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            if let Some((_, body)) = response.split_once("\r\n\r\n") {
                return body.to_owned();
            }
        }

        assert!(
            Instant::now() < deadline,
            "timed out waiting for metrics endpoint"
        );
        thread::sleep(TOKEN_WAIT_INTERVAL);
    }
}

struct McpSession {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

#[cfg(unix)]
struct SocketMcpSession {
    stream: UnixStream,
    reader: BufReader<UnixStream>,
}

#[cfg(unix)]
impl SocketMcpSession {
    fn connect(socket_path: &Path) -> Self {
        let stream = UnixStream::connect(socket_path).unwrap();
        let reader = BufReader::new(stream.try_clone().unwrap());
        Self { stream, reader }
    }

    fn send(&mut self, payload: Value) {
        let encoded = serde_json::to_vec(&payload).unwrap();
        self.stream.write_all(&encoded).unwrap();
        self.stream.write_all(b"\n").unwrap();
        self.stream.flush().unwrap();
    }

    fn recv_line(&mut self) -> Value {
        let mut line = String::new();
        self.reader.read_line(&mut line).unwrap();
        assert!(!line.is_empty(), "expected JSON line from socket daemon");
        serde_json::from_str(line.trim_end()).unwrap()
    }

    fn initialize(&mut self, token: &str, agent_id: &str) -> Value {
        self.send(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": INIT_PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {
                        "listChanged": true
                    }
                },
                "clientInfo": {
                    "name": "socket-integration-test",
                    "version": "1.0.0"
                },
                "_meta": {
                    "sessionToken": token,
                    "agentId": agent_id
                }
            }
        }));
        self.recv_line()
    }

    fn notify_initialized(&mut self) {
        self.send(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));
    }

    fn call_tool_with_secret(&mut self, id: i64, name: &str, arguments: Value) -> (Value, String) {
        self.send(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments
            }
        }));

        let first = self.recv_line();
        let second = self.recv_line();
        let secret_frame = if first.get("method").and_then(Value::as_str) == Some("gloves/secret") {
            first.clone()
        } else {
            second.clone()
        };
        let response = if secret_frame == first { second } else { first };
        let secret = secret_frame["params"]["value"].as_str().unwrap().to_owned();
        (response, secret)
    }
}

struct DaemonChild {
    child: Child,
}

impl DaemonChild {
    fn spawn(config_path: &Path, agent: Option<&str>) -> Self {
        let mut command = std::process::Command::new(assert_cmd::cargo::cargo_bin!("gloves-mcp"));
        command
            .arg("--config")
            .arg(config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        if let Some(agent) = agent {
            command.arg("--agent").arg(agent);
        }
        Self {
            child: command.spawn().unwrap(),
        }
    }
}

impl Drop for DaemonChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl McpSession {
    fn spawn(config_path: &Path, agent: Option<&str>) -> (Self, PathBuf) {
        Self::spawn_with_options(config_path, agent, &[], false)
    }

    fn spawn_with_env(
        config_path: &Path,
        agent: Option<&str>,
        env_pairs: &[(&str, &str)],
    ) -> (Self, PathBuf) {
        Self::spawn_with_options(config_path, agent, env_pairs, false)
    }

    fn spawn_stdio_with_env(
        config_path: &Path,
        agent: Option<&str>,
        env_pairs: &[(&str, &str)],
    ) -> (Self, PathBuf) {
        Self::spawn_with_options(config_path, agent, env_pairs, true)
    }

    fn spawn_with_options(
        config_path: &Path,
        agent: Option<&str>,
        env_pairs: &[(&str, &str)],
        force_stdio: bool,
    ) -> (Self, PathBuf) {
        let token_path = config_path.parent().unwrap().join("session-token");
        let mut command = std::process::Command::new(assert_cmd::cargo::cargo_bin!("gloves-mcp"));
        command
            .arg("--config")
            .arg(config_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(agent) = agent {
            command.arg("--agent").arg(agent);
        }
        if force_stdio {
            command.arg("--stdio");
        }
        for (key, value) in env_pairs {
            command.env(key, value);
        }
        let mut child = command.spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        (
            Self {
                child,
                stdin,
                stdout,
            },
            token_path,
        )
    }

    fn send(&mut self, payload: Value) {
        let encoded = serde_json::to_vec(&payload).unwrap();
        self.stdin.write_all(&encoded).unwrap();
        self.stdin.write_all(b"\n").unwrap();
        self.stdin.flush().unwrap();
    }

    fn recv(&mut self) -> Value {
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        assert!(!line.is_empty(), "expected JSON-RPC response");
        serde_json::from_str(line.trim_end()).unwrap()
    }

    fn initialize(&mut self, token: &str, agent_id: &str) -> Value {
        self.send(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": INIT_PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {
                        "listChanged": true
                    }
                },
                "clientInfo": {
                    "name": "integration-test",
                    "version": "1.0.0"
                },
                "_meta": {
                    "sessionToken": token,
                    "agentId": agent_id
                }
            }
        }));
        self.recv()
    }

    fn notify_initialized(&mut self) {
        self.send(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));
    }

    fn list_tools(&mut self) -> Value {
        self.send(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }));
        self.recv()
    }

    fn call_tool(&mut self, id: i64, name: &str, arguments: Value) -> Value {
        self.send(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments
            }
        }));
        self.recv()
    }

    fn send_tool_call(&mut self, id: i64, name: &str, arguments: Value) {
        self.send(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments
            }
        }));
    }
}

impl Drop for McpSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn rejects_initialize_without_valid_session_token() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    let config_path = temp.path().join("gloves.toml");
    let token_path = temp.path().join("session-token");
    write_mcp_config(&config_path, &root, &token_path, "auto", None);

    let (mut session, created_token_path) = McpSession::spawn(&config_path, None);
    let valid_token = wait_for_token(&created_token_path);
    assert_eq!(valid_token.len(), 64);

    let response = session.initialize("deadbeef", "devy");
    assert_eq!(response["error"]["code"], -32001);
    assert_eq!(
        response["error"]["message"],
        "Session authentication failed"
    );
    assert_eq!(response["error"]["data"]["reason"], "invalid_token");
}

#[test]
fn authenticated_sessions_can_list_tools_and_read_redacted_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    let config_path = temp.path().join("gloves.toml");
    let token_path = temp.path().join("session-token");

    set_identity(&root, "devy");
    write_creation_rules(
        &root,
        "version: 1\ncreation_rules:\n  - path_regex: ^agents/devy/.*$\n",
    );
    set_secret(&root, "devy", SECRET_PATH, SECRET_VALUE);
    write_mcp_config(&config_path, &root, &token_path, "auto", None);

    let (mut session, created_token_path) = McpSession::spawn(&config_path, Some("devy"));
    let token = wait_for_token(&created_token_path);
    let init_response = session.initialize(&token, "devy");
    assert_eq!(
        init_response["result"]["protocolVersion"],
        INIT_PROTOCOL_VERSION
    );
    assert_eq!(init_response["result"]["serverInfo"]["name"], "gloves-mcp");

    session.notify_initialized();

    let tools_response = session.list_tools();
    let tool_names = tools_response["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        tool_names,
        vec![
            "gloves_list",
            "gloves_show",
            "gloves_get",
            "gloves_set",
            "gloves_delete",
            "gloves_approve",
            "gloves_rotate"
        ]
    );

    let show_response = session.call_tool(3, "gloves_show", json!({ "path": SECRET_PATH }));
    assert_eq!(show_response["result"]["isError"], false);
    assert_eq!(
        show_response["result"]["structuredContent"]["name"],
        SECRET_PATH
    );
    assert_eq!(
        show_response["result"]["structuredContent"]["agent"],
        "devy"
    );
    assert_eq!(
        show_response["result"]["structuredContent"]["length"],
        SECRET_VALUE.len()
    );

    let get_response = session.call_tool(4, "gloves_get", json!({ "path": SECRET_PATH }));
    assert_eq!(get_response["result"]["isError"], false);
    assert_eq!(
        get_response["result"]["structuredContent"]["path"],
        SECRET_PATH
    );
    assert_eq!(
        get_response["result"]["structuredContent"]["secret_length"],
        SECRET_VALUE.len()
    );
    let content_text = get_response["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    assert!(content_text.contains("injected"));
    assert!(!content_text.contains(SECRET_VALUE));
}

#[test]
fn get_rejects_cross_agent_access() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    let config_path = temp.path().join("gloves.toml");
    let token_path = temp.path().join("session-token");

    set_identity(&root, "devy");
    set_identity(&root, "webhook");
    write_creation_rules(
        &root,
        "version: 1\ncreation_rules:\n  - path_regex: ^agents/devy/.*$\n",
    );
    set_secret(&root, "devy", SECRET_PATH, SECRET_VALUE);
    write_mcp_config(&config_path, &root, &token_path, "auto", None);

    let (mut session, created_token_path) = McpSession::spawn(&config_path, Some("webhook"));
    let token = wait_for_token(&created_token_path);
    let init_response = session.initialize(&token, "webhook");
    assert!(init_response.get("result").is_some());

    session.notify_initialized();

    let response = session.call_tool(2, "gloves_get", json!({ "path": SECRET_PATH }));
    assert_eq!(response["error"]["code"], -32005);
    assert_eq!(response["error"]["message"], "Permission denied");
    assert_eq!(response["error"]["data"]["reason"], "agent_not_recipient");
}

#[test]
fn list_only_returns_secrets_visible_to_the_authenticated_agent() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    let config_path = temp.path().join("gloves.toml");
    let token_path = temp.path().join("session-token");

    set_identity(&root, "devy");
    set_identity(&root, "webhook");
    write_creation_rules(
        &root,
        "version: 1\ncreation_rules:\n  - path_regex: ^agents/devy/.*$\n  - path_regex: ^agents/webhook/.*$\n",
    );
    set_secret(
        &root,
        "devy",
        "agents/devy/api-keys/anthropic",
        "devy-secret",
    );
    set_secret(
        &root,
        "webhook",
        "agents/webhook/tokens/github-pat",
        "webhook-secret",
    );
    write_mcp_config(&config_path, &root, &token_path, "auto", None);

    let (mut session, created_token_path) = McpSession::spawn(&config_path, Some("devy"));
    let token = wait_for_token(&created_token_path);
    let init_response = session.initialize(&token, "devy");
    assert!(init_response.get("result").is_some());

    session.notify_initialized();

    let response = session.call_tool(2, "gloves_list", json!({ "prefix": "agents/" }));
    assert_eq!(response["result"]["isError"], false);
    let secrets = response["result"]["structuredContent"]["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(secrets, vec!["agents/devy/api-keys/anthropic"]);
}

#[test]
fn set_reads_secret_from_environment_under_auto_approval() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    let config_path = temp.path().join("gloves.toml");
    let token_path = temp.path().join("session-token");

    set_identity(&root, "devy");
    write_creation_rules(
        &root,
        "version: 1\ncreation_rules:\n  - path_regex: ^agents/devy/.*$\n",
    );
    write_mcp_config(&config_path, &root, &token_path, "auto", None);

    let (mut session, created_token_path) = McpSession::spawn_with_env(
        &config_path,
        Some("devy"),
        &[("MCP_SET_SECRET", AUTO_SET_SECRET_VALUE)],
    );
    let token = wait_for_token(&created_token_path);
    let init_response = session.initialize(&token, "devy");
    assert!(init_response.get("result").is_some());
    session.notify_initialized();

    let response = session.call_tool(
        2,
        "gloves_set",
        json!({
            "path": AUTO_SET_SECRET_PATH,
            "from_env": "MCP_SET_SECRET"
        }),
    );
    assert_eq!(response["result"]["isError"], false);
    assert_eq!(
        response["result"]["structuredContent"]["path"],
        AUTO_SET_SECRET_PATH
    );

    gloves_command()
        .args([
            "--root",
            root.to_str().unwrap(),
            "--agent",
            "devy",
            "get",
            AUTO_SET_SECRET_PATH,
            "--format",
            "raw",
        ])
        .assert()
        .success()
        .stdout(predicates::str::diff(AUTO_SET_SECRET_VALUE));
}

#[test]
fn stdio_override_supports_env_backed_set_when_socket_is_configured() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    let config_path = temp.path().join("gloves.toml");
    let token_path = temp.path().join("session-token");
    let socket_path = temp.path().join("gloves.sock");

    set_identity(&root, "devy");
    write_creation_rules(
        &root,
        "version: 1\ncreation_rules:\n  - path_regex: ^agents/devy/.*$\n",
    );
    write_mcp_config(&config_path, &root, &token_path, "auto", Some(&socket_path));

    let (mut session, created_token_path) = McpSession::spawn_stdio_with_env(
        &config_path,
        Some("devy"),
        &[("MCP_SET_SECRET", AUTO_SET_SECRET_VALUE)],
    );
    let token = wait_for_token(&created_token_path);
    let init_response = session.initialize(&token, "devy");
    assert!(init_response.get("result").is_some());
    session.notify_initialized();

    let response = session.call_tool(
        2,
        "gloves_set",
        json!({
            "path": AUTO_SET_SECRET_PATH,
            "from_env": "MCP_SET_SECRET"
        }),
    );
    assert_eq!(response["result"]["isError"], false);
    assert_eq!(
        response["result"]["structuredContent"]["path"],
        AUTO_SET_SECRET_PATH
    );

    gloves_command()
        .args([
            "--root",
            root.to_str().unwrap(),
            "--agent",
            "devy",
            "get",
            AUTO_SET_SECRET_PATH,
            "--format",
            "raw",
        ])
        .assert()
        .success()
        .stdout(predicates::str::diff(AUTO_SET_SECRET_VALUE));
}

#[test]
fn get_waits_for_manual_approval_and_resolves_after_approve_tool_call() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    let config_path = temp.path().join("gloves.toml");
    let token_path = temp.path().join("session-token");

    set_identity(&root, "devy");
    set_identity(&root, "main");
    write_creation_rules(
        &root,
        "version: 1\ncreation_rules:\n  - path_regex: ^agents/devy/.*$\n",
    );
    set_secret(&root, "devy", SECRET_PATH, SECRET_VALUE);
    write_mcp_config(&config_path, &root, &token_path, "tty", None);

    let (mut requester, requester_token_path) = McpSession::spawn(&config_path, Some("devy"));
    let requester_token = wait_for_token(&requester_token_path);
    let requester_init = requester.initialize(&requester_token, "devy");
    assert!(requester_init.get("result").is_some());
    requester.notify_initialized();
    requester.send_tool_call(2, "gloves_get", json!({ "path": SECRET_PATH }));

    let request_id = read_pending_request_id(&root);

    let (mut approver, approver_token_path) = McpSession::spawn(&config_path, Some("main"));
    let approver_token = wait_for_changed_token(&approver_token_path, &requester_token);
    let approver_init = approver.initialize(&approver_token, "main");
    assert!(approver_init.get("result").is_some());
    approver.notify_initialized();

    let approval_response = approver.call_tool(
        3,
        "gloves_approve",
        json!({
            "request_id": request_id,
            "decision": "approve",
            "reason": "integration-test"
        }),
    );
    assert_eq!(approval_response["result"]["isError"], false);
    assert_eq!(
        approval_response["result"]["structuredContent"]["decision"],
        "approve"
    );

    let get_response = requester.recv();
    assert_eq!(get_response["result"]["isError"], false);
    assert_eq!(
        get_response["result"]["structuredContent"]["path"],
        SECRET_PATH
    );
}

#[test]
fn metrics_endpoint_reports_secret_access_and_encryption_operations() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    let config_path = temp.path().join("gloves.toml");
    let token_path = temp.path().join("session-token");
    let socket_path = temp.path().join("gloves.sock");
    let metrics_bind = allocate_loopback_bind_address();

    set_identity(&root, "devy");
    write_creation_rules(
        &root,
        "version: 1\ncreation_rules:\n  - path_regex: ^agents/devy/.*$\n",
    );
    set_secret(&root, "devy", SECRET_PATH, SECRET_VALUE);
    write_mcp_config(&config_path, &root, &token_path, "auto", Some(&socket_path));
    append_metrics_config(&config_path, &metrics_bind);

    let _daemon = DaemonChild::spawn(&config_path, Some("devy"));
    let token = wait_for_token(&token_path);
    let mut session = SocketMcpSession::connect(&socket_path);
    let init_response = session.initialize(&token, "devy");
    assert!(init_response.get("result").is_some());
    session.notify_initialized();

    let (_response, secret) = session.call_tool_with_secret(
        2,
        "gloves_get",
        json!({
            "path": SECRET_PATH
        }),
    );
    assert_eq!(secret, SECRET_VALUE);

    let metrics = fetch_metrics(&metrics_bind);
    assert!(metrics.contains("gloves_secret_access_total"));
    assert!(metrics.contains("agent=\"devy\""));
    assert!(metrics.contains(&format!("path=\"{SECRET_PATH}\"")));
    assert!(metrics.contains("result=\"approved\""));
    assert!(metrics.contains("gloves_daemon_uptime_seconds"));
    assert!(metrics.contains("gloves_encryption_ops_total{operation=\"decrypt\"} 1"));
}

#[test]
fn delete_tool_is_denied_with_explanation() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    let config_path = temp.path().join("gloves.toml");
    let token_path = temp.path().join("session-token");

    set_identity(&root, "devy");
    write_creation_rules(
        &root,
        "version: 1\ncreation_rules:\n  - path_regex: ^agents/devy/.*$\n",
    );
    set_secret(&root, "devy", SECRET_PATH, SECRET_VALUE);
    write_mcp_config(&config_path, &root, &token_path, "auto", None);

    let (mut session, created_token_path) = McpSession::spawn(&config_path, Some("devy"));
    let token = wait_for_token(&created_token_path);
    let init_response = session.initialize(&token, "devy");
    assert!(init_response.get("result").is_some());
    session.notify_initialized();

    let response = session.call_tool(2, "gloves_delete", json!({ "path": SECRET_PATH }));
    assert_eq!(response["error"]["code"], -32002);
    assert_eq!(response["error"]["message"], "Operation denied");
}

#[test]
fn rotate_tool_reencrypts_current_agent_secrets_under_auto_approval() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    let config_path = temp.path().join("gloves.toml");
    let token_path = temp.path().join("session-token");

    set_identity(&root, "devy");
    write_creation_rules(
        &root,
        "version: 1\ncreation_rules:\n  - path_regex: ^agents/devy/.*$\n",
    );
    set_secret(&root, "devy", SECRET_PATH, SECRET_VALUE);
    let original_recipients =
        fs::read_to_string(root.join("store/agents/devy/.age-recipients")).unwrap();
    write_mcp_config(&config_path, &root, &token_path, "auto", None);

    let (mut session, created_token_path) = McpSession::spawn(&config_path, Some("devy"));
    let token = wait_for_token(&created_token_path);
    let init_response = session.initialize(&token, "devy");
    assert!(init_response.get("result").is_some());
    session.notify_initialized();

    let rotate_response = session.call_tool(2, "gloves_rotate", json!({ "agent_id": "devy" }));
    assert_eq!(rotate_response["result"]["isError"], false);
    assert_eq!(
        rotate_response["result"]["structuredContent"]["agent"],
        "devy"
    );

    let rotated_recipients =
        fs::read_to_string(root.join("store/agents/devy/.age-recipients")).unwrap();
    assert_ne!(rotated_recipients, original_recipients);

    gloves_command()
        .args([
            "--root",
            root.to_str().unwrap(),
            "--agent",
            "devy",
            "get",
            SECRET_PATH,
            "--format",
            "raw",
        ])
        .assert()
        .success()
        .stdout(predicates::str::diff(SECRET_VALUE));
}

#[cfg(unix)]
#[test]
fn unix_socket_server_delivers_secret_over_side_channel() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    let config_path = temp.path().join("gloves.toml");
    let token_path = temp.path().join("session-token");
    let socket_path = temp.path().join("gloves.sock");

    set_identity(&root, "devy");
    write_creation_rules(
        &root,
        "version: 1\ncreation_rules:\n  - path_regex: ^agents/devy/.*$\n",
    );
    set_secret(&root, "devy", SECRET_PATH, SECRET_VALUE);
    write_mcp_config(&config_path, &root, &token_path, "auto", Some(&socket_path));

    let _daemon = DaemonChild::spawn(&config_path, Some("devy"));
    let token = wait_for_token(&token_path);
    let mut session = SocketMcpSession::connect(&socket_path);
    let init_response = session.initialize(&token, "devy");
    assert!(init_response.get("result").is_some());
    session.notify_initialized();

    let (get_response, secret) =
        session.call_tool_with_secret(2, "gloves_get", json!({ "path": SECRET_PATH }));
    assert_eq!(secret, SECRET_VALUE);
    assert_eq!(get_response["result"]["isError"], false);
    let content_text = get_response["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    assert!(content_text.contains("injected"));
    assert!(!content_text.contains(SECRET_VALUE));
}
