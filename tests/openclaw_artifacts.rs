use assert_cmd::Command;
use serde_json::Value;
use std::{fs, path::Path};

fn repo_path(relative: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

#[test]
fn openclaw_json5_bridge_contains_expected_server_and_plugin_fields() {
    let contents = fs::read_to_string(repo_path("integrations/openclaw/gloves.json5")).unwrap();

    assert!(contents.contains("command: \"gloves-mcp\""));
    assert!(contents.contains("GLOVES_SESSION_TOKEN_PATH"));
    assert!(contents.contains("package: \"@openclaw/gloves\""));
    assert!(contents.contains("GLOVES_SOCKET: \"/gloves.sock\""));
    assert!(contents.contains("GLOVES_TOKEN_PATH: \"/run/gloves/token\""));
}

#[test]
fn gloves_openclaw_skill_teaches_redacted_and_pipe_first_workflow() {
    let contents = fs::read_to_string(repo_path("skills/gloves-openclaw/SKILL.md")).unwrap();

    assert!(contents.contains("gloves show <path> --redacted"));
    assert!(contents.contains("gloves get <path> --format raw | <target-command>"));
    assert!(contents.contains("gloves set <path> --stdin"));
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
