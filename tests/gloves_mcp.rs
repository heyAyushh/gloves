use assert_cmd::Command;
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Stdio},
    thread,
    time::{Duration, Instant},
};

const SECRET_PATH: &str = "agents/devy/api-keys/anthropic";
const SECRET_VALUE: &str = "sk-ant-api03-mcp-secret";
const INIT_PROTOCOL_VERSION: &str = "2025-06-18";
const TOKEN_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
const TOKEN_WAIT_INTERVAL: Duration = Duration::from_millis(25);

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

fn write_mcp_config(config_path: &Path, root: &Path, token_path: &Path) {
    let audit_path = root.join("audit");
    let config = format!(
        "[daemon]\n\
         session_token_path = {:?}\n\
         [store]\n\
         path = {:?}\n\
         [identities]\n\
         path = {:?}\n\
         [audit]\n\
         path = {:?}\n",
        token_path,
        root.join("store"),
        root.join("identities"),
        audit_path
    );
    fs::write(config_path, config).unwrap();
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

struct McpSession {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl McpSession {
    fn spawn(config_path: &Path, agent: Option<&str>) -> (Self, PathBuf) {
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
    write_mcp_config(&config_path, &root, &token_path);

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
    write_mcp_config(&config_path, &root, &token_path);

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
    assert_eq!(tool_names, vec!["gloves_list", "gloves_show", "gloves_get"]);

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
    write_mcp_config(&config_path, &root, &token_path);

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
    write_mcp_config(&config_path, &root, &token_path);

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
