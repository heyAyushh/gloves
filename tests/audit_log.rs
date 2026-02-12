use std::os::unix::fs::PermissionsExt;

use gloves::{
    audit::{AuditEvent, AuditLog},
    types::{AgentId, SecretId},
};

#[test]
fn log_writes_jsonl() {
    let temp_dir = tempfile::tempdir().unwrap();
    let log = AuditLog::new(temp_dir.path().join("audit.jsonl")).unwrap();

    log.log(AuditEvent::SecretExpired {
        secret_id: SecretId::new("a").unwrap(),
    })
    .unwrap();

    let text = std::fs::read_to_string(log.path()).unwrap();
    let line = text.lines().next().unwrap();
    let value: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(value["event"], "secret_expired");
}

#[test]
fn log_appends() {
    let temp_dir = tempfile::tempdir().unwrap();
    let log = AuditLog::new(temp_dir.path().join("audit.jsonl")).unwrap();

    log.log(AuditEvent::SecretExpired {
        secret_id: SecretId::new("a").unwrap(),
    })
    .unwrap();
    log.log(AuditEvent::SecretRevoked {
        secret_id: SecretId::new("b").unwrap(),
        by: AgentId::new("agent-a").unwrap(),
    })
    .unwrap();

    let text = std::fs::read_to_string(log.path()).unwrap();
    assert_eq!(text.lines().count(), 2);
}

#[test]
fn all_events_serialize() {
    let events = vec![
        AuditEvent::SecretAccessed {
            secret_id: SecretId::new("a").unwrap(),
            by: AgentId::new("agent-a").unwrap(),
        },
        AuditEvent::SecretExpired {
            secret_id: SecretId::new("b").unwrap(),
        },
        AuditEvent::SecretCreated {
            secret_id: SecretId::new("c").unwrap(),
            by: AgentId::new("agent-b").unwrap(),
        },
        AuditEvent::SecretRevoked {
            secret_id: SecretId::new("d").unwrap(),
            by: AgentId::new("agent-c").unwrap(),
        },
    ];

    for event in events {
        let json = serde_json::to_string(&event).unwrap();
        assert!(serde_json::from_str::<serde_json::Value>(&json).is_ok());
    }
}

#[test]
fn log_file_permissions() {
    let temp_dir = tempfile::tempdir().unwrap();
    let log = AuditLog::new(temp_dir.path().join("audit.jsonl")).unwrap();

    let mode = std::fs::metadata(log.path()).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn log_includes_timestamp() {
    let temp_dir = tempfile::tempdir().unwrap();
    let log = AuditLog::new(temp_dir.path().join("audit.jsonl")).unwrap();

    log.log(AuditEvent::SecretExpired {
        secret_id: SecretId::new("a").unwrap(),
    })
    .unwrap();

    let text = std::fs::read_to_string(log.path()).unwrap();
    let line = text.lines().next().unwrap();
    let value: serde_json::Value = serde_json::from_str(line).unwrap();
    assert!(value["timestamp"].as_str().unwrap().contains('T'));
}
