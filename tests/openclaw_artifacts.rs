use assert_cmd::Command;
use serde_json::Value;
use std::{fs, path::Path};

fn repo_path(relative: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

#[test]
fn openclaw_json5_bridge_contains_expected_server_and_plugin_fields() {
    let contents = fs::read_to_string(repo_path("integrations/openclaw/gloves.json5")).unwrap();

    assert!(contents.contains("openclaw plugins add @gloves/openclaw"));
    assert!(contents.contains("entries: {"));
    assert!(contents.contains("glovesBin: \"gloves\""));
    assert!(contents.contains("operatorAgentId: \"openclaw\""));
    assert!(contents.contains("group:plugins:gloves"));
    assert!(contents.contains("root: \"/var/lib/openclaw/gloves\""));
    assert!(!contents.contains("mcpConfigPath"));
    assert!(!contents.contains("tokenPath"));
    assert!(!contents.contains("socketPath"));
    assert!(!contents.contains("/home/exedev"));
    assert!(!contents.contains("GLOVES_SOCKET"));
    assert!(!contents.contains("/gloves.sock"));
}

#[test]
fn gloves_openclaw_skill_teaches_redacted_and_pipe_first_workflow() {
    let contents = fs::read_to_string(repo_path("skills/gloves-openclaw/SKILL.md")).unwrap();

    assert!(contents.contains("@gloves/openclaw"));
    assert!(contents.contains("safe metadata and approval tools"));
    assert!(contents.contains("gloves show <path> --redacted"));
    assert!(contents.contains("gloves get <path> --format raw | <target-command>"));
    assert!(contents.contains("gloves set <path> --stdin"));
    assert!(contents.contains("gloves_requests_list"));
    assert!(contents.contains("gloves_request_approve"));
    assert!(contents.contains("gloves://"));
    assert!(contents.contains(
        "Do not bind `~/.cargo/bin`, daemon sockets, token files, or host secret directories"
    ));
    assert!(contents.contains("Never print, echo, or restate a secret value"));
}

#[test]
fn bun_benchmark_reports_latency_summary_for_namespaced_get() {
    if Command::new("bun").arg("--version").output().is_err() {
        return;
    }

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let root_string = root.to_str().unwrap();
    let secret_path = "agents/devy/api-keys/anthropic";
    let gloves_binary = assert_cmd::cargo::cargo_bin!("gloves");

    Command::new(gloves_binary)
        .args(["--root", root_string, "set-identity", "--agent", "devy"])
        .assert()
        .success();

    fs::create_dir_all(root.join("store")).unwrap();
    fs::write(
        root.join("store/.gloves.yaml"),
        "version: 1\ncreation_rules:\n  - path_regex: ^agents/devy/.*$\n",
    )
    .unwrap();

    Command::new(gloves_binary)
        .args([
            "--root",
            root_string,
            "--agent",
            "devy",
            "set",
            secret_path,
            "--value",
            "sk-ant-api03-benchmark",
        ])
        .assert()
        .success();

    let output = Command::new("bun")
        .args([
            "run",
            repo_path("scripts/benchmark-gloves-get.ts")
                .to_str()
                .unwrap(),
            "--root",
            root_string,
            "--agent",
            "devy",
            "--path",
            secret_path,
            "--iterations",
            "3",
            "--warmups",
            "1",
        ])
        .env("GLOVES_BIN", gloves_binary)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let payload: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(payload["command"], "gloves get");
    assert_eq!(payload["agent"], "devy");
    assert_eq!(payload["path"], secret_path);
    assert_eq!(payload["iterations"], 3);
    assert_eq!(payload["warmups"], 1);
    assert!(payload["avg_ms"].as_f64().unwrap() >= 0.0);
    assert_eq!(payload["samples_ms"].as_array().unwrap().len(), 3);
}

#[test]
fn security_and_architecture_docs_cover_openclaw_secret_broker_model() {
    let security = fs::read_to_string(repo_path("SECURITY.md")).unwrap();
    let architecture = fs::read_to_string(repo_path("ARCHITECTURE.md")).unwrap();
    let readme = fs::read_to_string(repo_path("README.md")).unwrap();

    assert!(security.contains("never appear in the LLM context"));
    assert!(security.contains("@gloves/openclaw"));
    assert!(security.contains("gloves-docker-bridge"));
    assert!(architecture.contains("gloves-mcp"));
    assert!(architecture.contains("gloves://"));
    assert!(architecture.contains("@gloves/openclaw"));
    assert!(readme.contains("group:plugins:gloves"));
}

#[test]
fn openclaw_plugin_package_exposes_current_gateway_manifest() {
    let root_package_json = fs::read_to_string(repo_path("package.json")).unwrap();
    let client_package_json =
        fs::read_to_string(repo_path("packages/gloves-client/package.json")).unwrap();
    let package_json =
        fs::read_to_string(repo_path("packages/gloves-openclaw/package.json")).unwrap();
    let manifest =
        fs::read_to_string(repo_path("packages/gloves-openclaw/openclaw.plugin.json")).unwrap();

    assert!(root_package_json.contains(
        "bun run --cwd packages/gloves-client test && bun run --cwd packages/gloves-openclaw test"
    ));
    assert!(client_package_json.contains("\"@gloves/mcp-client\""));
    assert!(client_package_json.contains("\"files\""));
    assert!(client_package_json.contains("\"src/index.ts\""));
    assert!(package_json.contains("\"@gloves/openclaw\""));
    assert!(package_json.contains("\"./dist/index.js\""));
    assert!(package_json.contains("\"extensions\""));
    assert!(manifest.contains("\"id\": \"gloves\""));
    assert!(manifest.contains("\"tools\": true"));
    assert!(manifest.contains("\"operatorAgentId\""));
    assert!(manifest.contains("Host path to the gloves runtime root"));
}

#[test]
fn docker_bridge_examples_cover_private_runtime_launch_flow() {
    let bridge_config =
        fs::read_to_string(repo_path("integrations/openclaw/docker-bridge.toml")).unwrap();
    let launcher = fs::read_to_string(repo_path(
        "integrations/openclaw/launch-openclaw-with-gloves.sh",
    ))
    .unwrap();
    let bridge_doc = fs::read_to_string(repo_path("docs/openclaw-runtime-bridge.md")).unwrap();

    assert!(bridge_config.contains("secret_ref = \"gloves://agents/devy/api-keys/openai\""));
    assert!(bridge_config.contains("container_path = \"/run/secrets/openai\""));
    assert!(bridge_config.contains("\"openclaw.agent\" = \"devy\""));
    assert!(bridge_config.contains("tmpfs_spec"));
    assert!(launcher.contains("gloves-docker-bridge"));
    assert!(launcher.contains("GLOVES_DOCKER_BRIDGE_CONFIG"));
    assert!(launcher.contains("GLOVES_DOCKER_REAL_BIN"));
    assert!(bridge_doc.contains("private, operator-controlled"));
    assert!(bridge_doc.contains("/run/secrets/..."));
    assert!(bridge_doc.contains("gloves://"));
}
