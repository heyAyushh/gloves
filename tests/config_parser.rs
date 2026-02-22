use std::{fs, path::Path};

use gloves::{
    config::{
        discover_config, resolve_config_path, AgentAccessFile, ConfigPathsFile, ConfigSource,
        DaemonConfigFile, DefaultsConfigFile, GlovesConfig, GlovesConfigFile, SecretAclOperation,
        VaultConfigFile, VaultMode,
    },
    error::GlovesError,
    types::AgentId,
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn write_config(path: &Path, body: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, body).unwrap();
}

#[test]
fn config_roundtrip_v1() {
    let mut agents = std::collections::BTreeMap::new();
    agents.insert(
        "default-agent".to_owned(),
        AgentAccessFile {
            paths: vec!["runtime_root".to_owned()],
            operations: vec![gloves::config::PathOperation::Read],
        },
    );

    let mut private_paths = std::collections::BTreeMap::new();
    private_paths.insert("runtime_root".to_owned(), ".openclaw/secrets".to_owned());

    let source = GlovesConfigFile {
        version: 1,
        paths: ConfigPathsFile {
            root: Some(".openclaw/secrets".to_owned()),
        },
        private_paths,
        daemon: DaemonConfigFile {
            bind: Some("127.0.0.1:7788".to_owned()),
            io_timeout_seconds: Some(5),
            request_limit_bytes: Some(16 * 1024),
        },
        vault: VaultConfigFile {
            mode: Some(VaultMode::Auto),
        },
        defaults: DefaultsConfigFile {
            agent_id: Some("default-agent".to_owned()),
            secret_ttl_days: Some(1),
            vault_mount_ttl: Some("1h".to_owned()),
            vault_secret_ttl_days: Some(365),
            vault_secret_length_bytes: Some(64),
        },
        agents,
        secrets: gloves::config::SecretsConfigFile::default(),
    };

    let encoded = toml::to_string(&source).unwrap();
    let decoded: GlovesConfigFile = toml::from_str(&encoded).unwrap();
    assert_eq!(source, decoded);
}

#[test]
fn config_vault_mode_defaults_to_auto() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join(".gloves.toml");
    let config = GlovesConfig::parse_from_str("version = 1\n", &source).unwrap();
    assert_eq!(config.vault.mode, VaultMode::Auto);
}

#[test]
fn config_validate_rejects_invalid_vault_mode() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join(".gloves.toml");
    let raw = r#"
version = 1

[vault]
mode = "strict"
"#;

    let error = GlovesConfig::parse_from_str(raw, &source).unwrap_err();
    assert!(matches!(error, GlovesError::InvalidInput(_)));
}

#[test]
fn config_discovery_prefers_flag() {
    let temp = tempfile::tempdir().unwrap();
    let cwd = temp.path().join("workspace");
    let explicit = temp.path().join("explicit.toml");
    let env_path = temp.path().join("env.toml");
    let discovered = cwd.join(".gloves.toml");

    write_config(&explicit, "version = 1\n");
    write_config(&env_path, "version = 1\n");
    write_config(&discovered, "version = 1\n");

    let resolved = resolve_config_path(
        Some(&explicit),
        Some(env_path.to_str().unwrap()),
        false,
        &cwd,
    )
    .unwrap();

    assert_eq!(resolved.source, ConfigSource::Flag);
    assert_eq!(resolved.path.unwrap(), explicit);
}

#[test]
fn config_discovery_prefers_env_over_discovery() {
    let temp = tempfile::tempdir().unwrap();
    let cwd = temp.path().join("workspace");
    let env_path = temp.path().join("env.toml");
    let discovered = cwd.join(".gloves.toml");

    write_config(&env_path, "version = 1\n");
    write_config(&discovered, "version = 1\n");

    let resolved =
        resolve_config_path(None, Some(env_path.to_str().unwrap()), false, &cwd).unwrap();

    assert_eq!(resolved.source, ConfigSource::Env);
    assert_eq!(resolved.path.unwrap(), env_path);
}

#[test]
fn config_discovery_walks_parent_dirs() {
    let temp = tempfile::tempdir().unwrap();
    let top = temp.path().join("repo");
    let nested = top.join("a/b/c");
    let discovered = top.join(".gloves.toml");

    write_config(&discovered, "version = 1\n");
    fs::create_dir_all(&nested).unwrap();

    let found = discover_config(&nested).unwrap();
    assert_eq!(found, discovered);
}

#[test]
fn config_resolve_no_config_short_circuits() {
    let temp = tempfile::tempdir().unwrap();
    let cwd = temp.path();
    let explicit = cwd.join("missing.toml");
    let env_value = "also-missing.toml";

    let resolved = resolve_config_path(Some(&explicit), Some(env_value), true, cwd).unwrap();
    assert_eq!(resolved.source, ConfigSource::None);
    assert!(resolved.path.is_none());
}

#[test]
fn config_resolve_rejects_non_file_path() {
    let temp = tempfile::tempdir().unwrap();
    let cwd = temp.path();
    let directory = cwd.join("not-a-file");
    fs::create_dir_all(&directory).unwrap();

    let error = resolve_config_path(Some(&directory), None, false, cwd).unwrap_err();
    assert!(matches!(error, GlovesError::InvalidInput(_)));
}

#[test]
fn config_validate_rejects_unknown_agent_path_alias() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join(".gloves.toml");
    let raw = r#"
version = 1

[private_paths]
runtime_root = ".openclaw/secrets"

[agents.default-agent]
paths = ["missing_alias"]
operations = ["read"]
"#;

    let error = GlovesConfig::parse_from_str(raw, &source).unwrap_err();
    assert!(matches!(error, GlovesError::InvalidInput(_)));
}

#[test]
fn config_validate_rejects_invalid_operation() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join(".gloves.toml");
    let raw = r#"
version = 1

[private_paths]
runtime_root = ".openclaw/secrets"

[agents.default-agent]
paths = ["runtime_root"]
operations = ["delete"]
"#;

    let error = GlovesConfig::parse_from_str(raw, &source).unwrap_err();
    assert!(matches!(error, GlovesError::InvalidInput(_)));
}

#[test]
fn config_resolve_relative_paths_against_file_dir() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("configs/project/.gloves.toml");
    let raw = r#"
version = 1

[paths]
root = "./runtime"

[private_paths]
runtime_root = "./runtime"
"#;

    let config = GlovesConfig::parse_from_str(raw, &source).unwrap();
    let base = source.parent().unwrap();

    assert_eq!(config.root, base.join("runtime"));
    assert_eq!(config.private_paths["runtime_root"], base.join("runtime"));
}

#[test]
fn config_resolve_home_expansion() {
    let Some(home) = std::env::var_os("HOME") else {
        return;
    };

    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join(".gloves.toml");
    let raw = r#"
version = 1

[private_paths]
password_store = "~/.password-store"
"#;

    let config = GlovesConfig::parse_from_str(raw, &source).unwrap();
    assert!(config.private_paths["password_store"].starts_with(home));
}

#[cfg(unix)]
#[test]
fn config_validate_rejects_group_world_writable_file() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join(".gloves.toml");
    write_config(
        &source,
        r#"
version = 1

[private_paths]
runtime_root = ".openclaw/secrets"
"#,
    );

    let mut permissions = fs::metadata(&source).unwrap().permissions();
    permissions.set_mode(0o666);
    fs::set_permissions(&source, permissions).unwrap();

    let error = GlovesConfig::load_from_path(&source).unwrap_err();
    assert!(matches!(error, GlovesError::InvalidInput(_)));
}

#[cfg(unix)]
#[test]
fn config_validate_accepts_private_modes() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join(".gloves.toml");
    write_config(
        &source,
        r#"
version = 1

[private_paths]
runtime_root = ".openclaw/secrets"
"#,
    );

    let mut permissions = fs::metadata(&source).unwrap().permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(&source, permissions).unwrap();

    let config = GlovesConfig::load_from_path(&source).unwrap();
    assert!(config.private_paths.contains_key("runtime_root"));
}

#[test]
fn config_validate_rejects_duplicate_agent_aliases() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join(".gloves.toml");
    let raw = r#"
version = 1

[private_paths]
runtime_root = ".openclaw/secrets"

[agents.default-agent]
paths = ["runtime_root", "runtime_root"]
operations = ["read"]
"#;

    let error = GlovesConfig::parse_from_str(raw, &source).unwrap_err();
    assert!(matches!(error, GlovesError::InvalidInput(_)));
}

#[test]
fn config_validate_rejects_duplicate_operations() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join(".gloves.toml");
    let raw = r#"
version = 1

[private_paths]
runtime_root = ".openclaw/secrets"

[agents.default-agent]
paths = ["runtime_root"]
operations = ["read", "read"]
"#;

    let error = GlovesConfig::parse_from_str(raw, &source).unwrap_err();
    assert!(matches!(error, GlovesError::InvalidInput(_)));
}

#[test]
fn config_validate_rejects_non_loopback_daemon_bind() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join(".gloves.toml");
    let raw = r#"
version = 1

[daemon]
bind = "0.0.0.0:7788"
"#;

    let error = GlovesConfig::parse_from_str(raw, &source).unwrap_err();
    assert!(matches!(error, GlovesError::InvalidInput(_)));
}

#[test]
fn config_validate_rejects_zero_port_daemon_bind() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join(".gloves.toml");
    let raw = r#"
version = 1

[daemon]
bind = "127.0.0.1:0"
"#;

    let error = GlovesConfig::parse_from_str(raw, &source).unwrap_err();
    assert!(matches!(error, GlovesError::InvalidInput(_)));
}

#[test]
fn config_validate_rejects_non_positive_defaults() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join(".gloves.toml");
    let raw = r#"
version = 1

[defaults]
secret_ttl_days = 0
"#;

    let error = GlovesConfig::parse_from_str(raw, &source).unwrap_err();
    assert!(matches!(error, GlovesError::InvalidInput(_)));
}

#[test]
fn config_validate_rejects_unsupported_version() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join(".gloves.toml");
    let raw = "version = 2\n";

    let error = GlovesConfig::parse_from_str(raw, &source).unwrap_err();
    assert!(matches!(error, GlovesError::InvalidInput(_)));
}

#[test]
fn config_validate_rejects_unknown_fields() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join(".gloves.toml");
    let raw = r#"
version = 1
unknown_key = "value"
"#;

    let error = GlovesConfig::parse_from_str(raw, &source).unwrap_err();
    assert!(matches!(error, GlovesError::InvalidInput(_)));
}

#[test]
fn config_validate_rejects_invalid_mount_ttl() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join(".gloves.toml");
    let raw = r#"
version = 1

[defaults]
vault_mount_ttl = "1w"
"#;

    let error = GlovesConfig::parse_from_str(raw, &source).unwrap_err();
    assert!(matches!(error, GlovesError::InvalidInput(_)));
}

#[test]
fn config_validate_rejects_unsupported_home_expansion() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join(".gloves.toml");
    let raw = r#"
version = 1

[private_paths]
password_store = "~user/private"
"#;

    let error = GlovesConfig::parse_from_str(raw, &source).unwrap_err();
    assert!(matches!(error, GlovesError::InvalidInput(_)));
}

#[test]
fn config_validate_rejects_non_positive_daemon_limits() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join(".gloves.toml");
    let raw = r#"
version = 1

[daemon]
request_limit_bytes = 0
"#;

    let error = GlovesConfig::parse_from_str(raw, &source).unwrap_err();
    assert!(matches!(error, GlovesError::InvalidInput(_)));
}

#[test]
fn config_agent_paths_returns_not_found_for_unknown_agent() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join(".gloves.toml");
    let raw = r#"
version = 1

[private_paths]
runtime_root = ".openclaw/secrets"

[agents.default-agent]
paths = ["runtime_root"]
operations = ["read"]
"#;

    let config = GlovesConfig::parse_from_str(raw, &source).unwrap();
    let missing_agent = AgentId::new("agent-b").unwrap();

    let error = config.agent_paths(&missing_agent).unwrap_err();
    assert!(matches!(error, GlovesError::NotFound));
}

#[test]
fn config_secret_acl_parses_and_matches_patterns() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join(".gloves.toml");
    let raw = r#"
version = 1

[secrets.acl.default-agent]
paths = ["github/*", "shared/token", "*"]
operations = ["read", "list"]
"#;

    let config = GlovesConfig::parse_from_str(raw, &source).unwrap();
    let agent = AgentId::new("default-agent").unwrap();
    let policy = config.secret_access_policy(&agent).unwrap();

    assert!(config.has_secret_acl());
    assert!(policy.allows_operation(SecretAclOperation::Read));
    assert!(policy.allows_operation(SecretAclOperation::List));
    assert!(policy.allows_secret("github/token"));
    assert!(policy.allows_secret("shared/token"));
    assert!(policy.allows_secret("other/secret"));
}

#[test]
fn config_secret_acl_parses_all_operations() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join(".gloves.toml");
    let raw = r#"
version = 1

[secrets.acl.default-agent]
paths = ["github/*"]
operations = ["read", "write", "list", "revoke", "request", "status", "approve", "deny"]
"#;

    let config = GlovesConfig::parse_from_str(raw, &source).unwrap();
    let agent = AgentId::new("default-agent").unwrap();
    let policy = config.secret_access_policy(&agent).unwrap();

    assert!(policy.allows_operation(SecretAclOperation::Read));
    assert!(policy.allows_operation(SecretAclOperation::Write));
    assert!(policy.allows_operation(SecretAclOperation::List));
    assert!(policy.allows_operation(SecretAclOperation::Revoke));
    assert!(policy.allows_operation(SecretAclOperation::Request));
    assert!(policy.allows_operation(SecretAclOperation::Status));
    assert!(policy.allows_operation(SecretAclOperation::Approve));
    assert!(policy.allows_operation(SecretAclOperation::Deny));
}

#[test]
fn config_secret_acl_rejects_invalid_pattern() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join(".gloves.toml");
    let raw = r#"
version = 1

[secrets.acl.default-agent]
paths = ["github*"]
operations = ["read"]
"#;

    let error = GlovesConfig::parse_from_str(raw, &source).unwrap_err();
    assert!(matches!(error, GlovesError::InvalidInput(_)));
}

#[test]
fn config_secret_acl_rejects_duplicate_pattern() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join(".gloves.toml");
    let raw = r#"
version = 1

[secrets.acl.default-agent]
paths = ["github/*", "github/*"]
operations = ["read"]
"#;

    let error = GlovesConfig::parse_from_str(raw, &source).unwrap_err();
    assert!(matches!(error, GlovesError::InvalidInput(_)));
}

#[test]
fn config_secret_acl_rejects_duplicate_operations() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join(".gloves.toml");
    let raw = r#"
version = 1

[secrets.acl.default-agent]
paths = ["github/*"]
operations = ["read", "read"]
"#;

    let error = GlovesConfig::parse_from_str(raw, &source).unwrap_err();
    assert!(matches!(error, GlovesError::InvalidInput(_)));
}

#[test]
fn config_secret_pipe_command_policy_parses() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join(".gloves.toml");
    let raw = r#"
version = 1

[secrets.pipe.commands.curl]
require_url = true
url_prefixes = ["https://api.example.com/v1/", "http://127.0.0.1:4001/carddav/"]
"#;

    let config = GlovesConfig::parse_from_str(raw, &source).unwrap();
    let policy = config.secret_pipe_command_policy("curl").unwrap();
    assert!(policy.require_url);
    assert_eq!(
        policy.url_prefixes,
        vec![
            "https://api.example.com/v1/".to_owned(),
            "http://127.0.0.1:4001/carddav/".to_owned(),
        ]
    );
}

#[test]
fn config_secret_pipe_command_policy_rejects_missing_prefixes_with_require_url() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join(".gloves.toml");
    let raw = r#"
version = 1

[secrets.pipe.commands.curl]
require_url = true
"#;

    let error = GlovesConfig::parse_from_str(raw, &source).unwrap_err();
    assert!(matches!(error, GlovesError::InvalidInput(_)));
}

#[test]
fn config_secret_pipe_command_policy_rejects_invalid_command_name() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join(".gloves.toml");
    let raw = r#"
version = 1

[secrets.pipe.commands."curl/bin"]
require_url = true
url_prefixes = ["https://api.example.com/v1/"]
"#;

    let error = GlovesConfig::parse_from_str(raw, &source).unwrap_err();
    assert!(matches!(error, GlovesError::InvalidInput(_)));
}

#[test]
fn config_secret_pipe_command_policy_rejects_invalid_url_prefix() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join(".gloves.toml");
    let raw = r#"
version = 1

[secrets.pipe.commands.curl]
require_url = true
url_prefixes = ["ftp://api.example.com/v1/"]
"#;

    let error = GlovesConfig::parse_from_str(raw, &source).unwrap_err();
    assert!(matches!(error, GlovesError::InvalidInput(_)));
}

#[test]
fn config_secret_pipe_command_policy_rejects_query_or_fragment_prefix() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join(".gloves.toml");
    let raw = r#"
version = 1

[secrets.pipe.commands.curl]
require_url = true
url_prefixes = ["https://api.example.com/v1/?token=abc"]
"#;

    let error = GlovesConfig::parse_from_str(raw, &source).unwrap_err();
    assert!(matches!(error, GlovesError::InvalidInput(_)));
}

#[cfg(unix)]
#[test]
fn config_load_rejects_symlink() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target.toml");
    let link = temp.path().join(".gloves.toml");
    write_config(&target, "version = 1\n");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let error = GlovesConfig::load_from_path(&link).unwrap_err();
    assert!(matches!(error, GlovesError::InvalidInput(_)));
}
