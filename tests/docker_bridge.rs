#[cfg(unix)]
mod unix_tests {
    use assert_cmd::Command;
    use serde_json::Value;
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
    };

    fn write_executable(path: &Path, contents: &str) {
        fs::write(path, contents).unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }

    fn write_bridge_config(root: &Path, runtime_root: &Path, docker_bin: &Path) -> PathBuf {
        fs::create_dir_all(runtime_root).unwrap();
        let config_path = runtime_root.join("bridge.toml");
        fs::write(
            &config_path,
            format!(
                r#"
version = 1
gloves_root = "{root}"
runtime_root = "{runtime_root}"
docker_bin = "{docker_bin}"
audit_agent = "openclaw"
secret_mount_root = "/run/secrets"
tmpfs_spec = "/run/secrets:size=2M,mode=0700,noexec,nosuid,nodev"

[[targets]]
secret_ref = "gloves://agents/devy/api-keys/anthropic"
container_path = "/run/secrets/anthropic"

[targets.selector.labels]
"openclaw.agent" = "devy"
"#,
                root = root.display(),
                runtime_root = runtime_root.display(),
                docker_bin = docker_bin.display(),
            ),
        )
        .unwrap();
        config_path
    }

    fn install_fake_docker(fake_docker: &Path, fake_root: &Path) {
        write_executable(
            fake_docker,
            &format!(
                r#"#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
FAKE_ROOT="{fake_root}"
mkdir -p "${{FAKE_ROOT}}"
printf '%s\n' "$*" >> "${{FAKE_ROOT}}/docker.log"

extract_name() {{
  local previous=""
  for token in "$@"; do
    if [[ "${{previous}}" == "--name" ]]; then
      printf '%s' "${{token}}"
      return 0
    fi
    case "${{token}}" in
      --name=*)
        printf '%s' "${{token#--name=}}"
        return 0
        ;;
    esac
    previous="${{token}}"
  done
  printf 'container-unknown'
}}

subcommand="${{1:-}}"
shift || true
case "${{subcommand}}" in
  create|run)
    name="$(extract_name "$@")"
    mkdir -p "${{FAKE_ROOT}}/containerfs/${{name}}"
    printf 'container-123456\n'
    ;;
  start|stop|rm)
    exit 0
    ;;
  exec)
    if [[ "${{1:-}}" == "-i" ]]; then
      shift
    fi
    container="${{1:?missing container}}"
    shift
    path="${{@: -1}}"
    mkdir -p "${{FAKE_ROOT}}/containerfs/${{container}}$(dirname "${{path}}")"
    cat > "${{FAKE_ROOT}}/containerfs/${{container}}${{path}}"
    chmod 0400 "${{FAKE_ROOT}}/containerfs/${{container}}${{path}}"
    ;;
  *)
    exit 0
    ;;
esac
"#,
                fake_root = fake_root.display(),
            ),
        );
    }

    fn setup_secret_runtime(root: &Path) {
        let root_string = root.to_str().unwrap();
        let gloves_bin = assert_cmd::cargo::cargo_bin!("gloves");
        Command::new(gloves_bin)
            .args(["--root", root_string, "set-identity", "--agent", "devy"])
            .assert()
            .success();
        fs::create_dir_all(root.join("store")).unwrap();
        fs::write(
            root.join("store/.gloves.yaml"),
            "version: 1\ncreation_rules:\n  - path_regex: ^agents/devy/.*$\n    age: []\n",
        )
        .unwrap();
        Command::new(gloves_bin)
            .args([
                "--root",
                root_string,
                "--agent",
                "devy",
                "set",
                "agents/devy/api-keys/anthropic",
                "--value",
                "sk-ant-api03-bridge-test",
            ])
            .assert()
            .success();
    }

    fn bridge_state_path(runtime_root: &Path) -> PathBuf {
        runtime_root.join("docker-bridge/state.json")
    }

    #[test]
    fn docker_bridge_injects_tmpfs_files_on_start_without_leaking_plaintext() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let runtime_root = temp.path().join("runtime");
        let fake_root = temp.path().join("fake-docker");
        let fake_docker = temp.path().join("docker-real");
        setup_secret_runtime(&root);
        install_fake_docker(&fake_docker, &fake_root);
        let config_path = write_bridge_config(&root, &runtime_root, &fake_docker);

        Command::new(assert_cmd::cargo::cargo_bin!("gloves-docker-bridge"))
            .env("GLOVES_DOCKER_BRIDGE_CONFIG", &config_path)
            .args([
                "create",
                "--name",
                "openclaw-agent-devy",
                "--label",
                "openclaw.agent=devy",
                "ghcr.io/openclaw/agent:latest",
                "sleep",
                "60",
            ])
            .assert()
            .success()
            .stdout(predicates::str::contains("container-123456"));

        Command::new(assert_cmd::cargo::cargo_bin!("gloves-docker-bridge"))
            .env("GLOVES_DOCKER_BRIDGE_CONFIG", &config_path)
            .args(["start", "openclaw-agent-devy"])
            .assert()
            .success();

        let injected_path = fake_root.join("containerfs/openclaw-agent-devy/run/secrets/anthropic");
        let injected_value = fs::read_to_string(&injected_path).unwrap();
        let injected_mode = fs::metadata(&injected_path).unwrap().permissions().mode() & 0o777;
        let docker_log = fs::read_to_string(fake_root.join("docker.log")).unwrap();
        let audit_log = fs::read_to_string(root.join("audit.jsonl")).unwrap();

        assert_eq!(injected_value, "sk-ant-api03-bridge-test");
        assert_eq!(injected_mode, 0o400);
        assert!(docker_log.contains("--tmpfs"));
        assert!(docker_log.contains("/run/secrets:size=2M,mode=0700,noexec,nosuid,nodev"));
        assert!(audit_log.contains("inject_ref"));
        assert!(!audit_log.contains("sk-ant-api03-bridge-test"));
    }

    #[test]
    fn docker_bridge_supports_exec_rechecks_and_cleanup_state() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let runtime_root = temp.path().join("runtime");
        let fake_root = temp.path().join("fake-docker");
        let fake_docker = temp.path().join("docker-real");
        setup_secret_runtime(&root);
        install_fake_docker(&fake_docker, &fake_root);
        let config_path = write_bridge_config(&root, &runtime_root, &fake_docker);

        Command::new(assert_cmd::cargo::cargo_bin!("gloves-docker-bridge"))
            .env("GLOVES_DOCKER_BRIDGE_CONFIG", &config_path)
            .args([
                "create",
                "--name",
                "openclaw-agent-devy",
                "--label=openclaw.agent=devy",
                "ghcr.io/openclaw/agent:latest",
                "sleep",
                "60",
            ])
            .assert()
            .success();

        Command::new(assert_cmd::cargo::cargo_bin!("gloves-docker-bridge"))
            .env("GLOVES_DOCKER_BRIDGE_CONFIG", &config_path)
            .args([
                "exec",
                "-i",
                "openclaw-agent-devy",
                "/bin/sh",
                "-lc",
                "true",
            ])
            .assert()
            .success();

        let state_before_stop: Value =
            serde_json::from_slice(&fs::read(bridge_state_path(&runtime_root)).unwrap()).unwrap();
        assert_eq!(state_before_stop[0]["injected"], true);

        Command::new(assert_cmd::cargo::cargo_bin!("gloves-docker-bridge"))
            .env("GLOVES_DOCKER_BRIDGE_CONFIG", &config_path)
            .args(["stop", "openclaw-agent-devy"])
            .assert()
            .success();

        let state_after_stop: Value =
            serde_json::from_slice(&fs::read(bridge_state_path(&runtime_root)).unwrap()).unwrap();
        assert_eq!(state_after_stop[0]["injected"], false);

        Command::new(assert_cmd::cargo::cargo_bin!("gloves-docker-bridge"))
            .env("GLOVES_DOCKER_BRIDGE_CONFIG", &config_path)
            .args(["rm", "openclaw-agent-devy"])
            .assert()
            .success();

        let state_after_rm: Value =
            serde_json::from_slice(&fs::read(bridge_state_path(&runtime_root)).unwrap()).unwrap();
        assert_eq!(state_after_rm, Value::Array(vec![]));
    }
}
