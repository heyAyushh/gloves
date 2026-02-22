use std::collections::HashSet;

use chrono::{Duration, Utc};
use gloves::error::ValidationError;
use gloves::types::{
    AgentId, Owner, PendingRequest, RequestStatus, SecretId, SecretMeta, SecretValue,
};

#[test]
fn secret_id_valid() {
    assert!(SecretId::new("db_pass").is_ok());
    assert!(SecretId::new("pg/myapp").is_ok());
    assert!(SecretId::new("a.b-c").is_ok());
}

#[test]
fn secret_id_empty() {
    assert_eq!(SecretId::new(""), Err(ValidationError::InvalidName));
}

#[test]
fn secret_id_too_long() {
    let value = "a".repeat(129);
    assert_eq!(SecretId::new(&value), Err(ValidationError::InvalidName));
}

#[test]
fn secret_id_traversal() {
    assert_eq!(
        SecretId::new("../etc/passwd"),
        Err(ValidationError::PathTraversal)
    );
}

#[test]
fn secret_id_leading_slash() {
    assert_eq!(SecretId::new("/root"), Err(ValidationError::PathTraversal));
}

#[test]
fn secret_id_special_chars() {
    assert_eq!(
        SecretId::new("db pass!"),
        Err(ValidationError::InvalidCharacter)
    );
}

#[test]
fn secret_id_display() {
    let id = SecretId::new("abc/def").unwrap();
    assert_eq!(id.to_string(), "abc/def");
}

#[test]
fn agent_id_validation_and_display() {
    assert!(AgentId::new("agent_01").is_ok());
    assert!(matches!(
        AgentId::new("bad id"),
        Err(ValidationError::InvalidCharacter)
    ));
    assert_eq!(AgentId::new("agent_a").unwrap().to_string(), "agent_a");
}

#[test]
fn owner_serde() {
    let human = serde_json::to_string(&Owner::Human).unwrap();
    let agent = serde_json::to_string(&Owner::Agent).unwrap();
    assert_eq!(human, "\"human\"");
    assert_eq!(agent, "\"agent\"");
    assert_eq!(serde_json::from_str::<Owner>(&human).unwrap(), Owner::Human);
    assert_eq!(serde_json::from_str::<Owner>(&agent).unwrap(), Owner::Agent);
}

#[test]
fn request_status_serde_all_variants() {
    let values = [
        RequestStatus::Pending,
        RequestStatus::Fulfilled,
        RequestStatus::Denied,
        RequestStatus::Expired,
    ];
    for value in values {
        let json = serde_json::to_string(&value).unwrap();
        let roundtrip: RequestStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip, value);
    }
}

#[test]
fn secret_value_expose() {
    let value = SecretValue::new(b"abc".to_vec());
    let output = value.expose(|bytes| bytes.to_vec());
    assert_eq!(output, b"abc".to_vec());
}

#[test]
fn secret_value_no_debug() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/trybuild/secret_value_traits.rs");
}

#[test]
fn secret_meta_roundtrip() {
    let secret_id = SecretId::new("meta_roundtrip").unwrap();
    let creator = AgentId::new("creator").unwrap();
    let recipient = AgentId::new("recipient").unwrap();
    let mut recipients = HashSet::new();
    recipients.insert(recipient);
    let meta = SecretMeta {
        id: secret_id,
        owner: Owner::Agent,
        created_at: Utc::now(),
        expires_at: Utc::now() + Duration::days(1),
        recipients,
        created_by: creator,
        last_accessed: None,
        access_count: 0,
        checksum: "abc".to_owned(),
    };

    let bytes = serde_json::to_vec(&meta).unwrap();
    let decoded: SecretMeta = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded.id.as_str(), meta.id.as_str());
    assert_eq!(decoded.owner, meta.owner);
    assert_eq!(decoded.recipients, meta.recipients);
}

#[test]
fn pending_request_roundtrip() {
    let request = PendingRequest {
        id: uuid::Uuid::new_v4(),
        secret_name: SecretId::new("human/api").unwrap(),
        requested_by: AgentId::new("agent_a").unwrap(),
        reason: "Need access".to_owned(),
        requested_at: Utc::now(),
        expires_at: Utc::now() + Duration::hours(1),
        signature: vec![1, 2, 3],
        verifying_key: vec![4; 32],
        status: RequestStatus::Pending,
        pending: true,
        approved_at: None,
        approved_by: None,
        denied_at: None,
        denied_by: None,
    };

    let bytes = serde_json::to_vec(&request).unwrap();
    let decoded: PendingRequest = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded.secret_name.as_str(), request.secret_name.as_str());
    assert_eq!(decoded.requested_by, request.requested_by);
    assert_eq!(decoded.status, RequestStatus::Pending);
    assert!(decoded.pending);
    assert!(decoded.approved_at.is_none());
    assert!(decoded.denied_at.is_none());
}
