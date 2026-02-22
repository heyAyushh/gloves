use std::sync::{Arc, Mutex};

use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use gloves::{
    error::GlovesError,
    human::{
        backend::{HumanBackend, PassExecutor, PassOutput, SystemPassExecutor},
        pending::PendingRequestStore,
    },
    types::{AgentId, RequestStatus, SecretId},
};
use rand::RngExt;

struct MockPass {
    responses: Arc<Mutex<Vec<PassOutput>>>,
}

impl MockPass {
    fn new(responses: Vec<PassOutput>) -> Self {
        Self {
            responses: Arc::new(Mutex::new(responses)),
        }
    }
}

impl PassExecutor for MockPass {
    fn exec(&self, _args: &[&str]) -> gloves::error::Result<PassOutput> {
        Ok(self.responses.lock().unwrap().remove(0))
    }
}

fn signing_key() -> SigningKey {
    let mut key_bytes = [0_u8; 32];
    rand::rng().fill(&mut key_bytes);
    SigningKey::from_bytes(&key_bytes)
}

#[test]
fn get_parses_stdout() {
    let backend = HumanBackend::with_executor(Box::new(MockPass::new(vec![PassOutput {
        status_code: 0,
        stdout: "mypassword\n".to_owned(),
        stderr: String::new(),
    }])));

    let value = backend.get("service/key").unwrap();
    assert_eq!(value.expose(|bytes| bytes.to_vec()), b"mypassword");
}

#[test]
fn get_not_found() {
    let backend = HumanBackend::with_executor(Box::new(MockPass::new(vec![PassOutput {
        status_code: 1,
        stdout: String::new(),
        stderr: "is not in the password store".to_owned(),
    }])));

    assert!(matches!(backend.get("missing"), Err(GlovesError::NotFound)));
}

#[test]
fn get_gpg_denied() {
    let backend = HumanBackend::with_executor(Box::new(MockPass::new(vec![PassOutput {
        status_code: 1,
        stdout: String::new(),
        stderr: "decryption failed".to_owned(),
    }])));

    assert!(matches!(backend.get("secure"), Err(GlovesError::GpgDenied)));
}

#[test]
fn exists_true() {
    let backend = HumanBackend::with_executor(Box::new(MockPass::new(vec![PassOutput {
        status_code: 0,
        stdout: String::new(),
        stderr: String::new(),
    }])));

    assert!(backend.exists("exists").unwrap());
}

#[test]
fn exists_false() {
    let backend = HumanBackend::with_executor(Box::new(MockPass::new(vec![PassOutput {
        status_code: 1,
        stdout: String::new(),
        stderr: String::new(),
    }])));

    assert!(!backend.exists("missing").unwrap());
}

#[test]
fn get_unknown_error_maps_crypto() {
    let backend = HumanBackend::with_executor(Box::new(MockPass::new(vec![PassOutput {
        status_code: 9,
        stdout: String::new(),
        stderr: "unexpected failure".to_owned(),
    }])));
    assert!(matches!(
        backend.get("missing"),
        Err(GlovesError::Crypto(_))
    ));
}

#[test]
fn system_pass_executor_runs_custom_binary() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = tempfile::tempdir().unwrap();
    let script = temp_dir.path().join("fake-pass.sh");
    std::fs::write(
        &script,
        "#!/bin/sh\nif [ \"$1\" = \"show\" ]; then printf 'ok\\n'; exit 0; fi\nexit 9\n",
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    let executor = SystemPassExecutor::with_binary(script.to_string_lossy().into_owned());
    let output = executor.exec(&["show", "secret"]).unwrap();
    assert_eq!(output.status_code, 0);
    assert_eq!(output.stdout, "ok\n");
}

#[test]
fn system_pass_executor_utf8_error() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = tempfile::tempdir().unwrap();
    let script = temp_dir.path().join("bad-utf8-pass.sh");
    std::fs::write(&script, "#!/bin/sh\nprintf '\\377'\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    let executor = SystemPassExecutor::with_binary(script.to_string_lossy().into_owned());
    assert!(matches!(
        executor.exec(&["show", "secret"]),
        Err(GlovesError::Utf8(_))
    ));
}

#[test]
fn system_pass_executor_default_constructs() {
    let _ = SystemPassExecutor::default();
}

#[test]
fn human_backend_default_constructs() {
    let _ = HumanBackend::default();
}

#[test]
fn pending_create_persist() {
    let temp_dir = tempfile::tempdir().unwrap();
    let store = PendingRequestStore::new(temp_dir.path().join("pending.json")).unwrap();
    let signing_key = signing_key();

    store
        .create(
            SecretId::new("human/password").unwrap(),
            AgentId::new("agent-a").unwrap(),
            "need for deploy".to_owned(),
            Duration::minutes(10),
            &signing_key,
        )
        .unwrap();

    let loaded = store.load_all().unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].status, RequestStatus::Pending);
    assert!(loaded[0].pending);
}

#[test]
fn pending_auto_expire() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("pending.json");
    let store = PendingRequestStore::new(&path).unwrap();
    let signing_key = signing_key();

    store
        .create(
            SecretId::new("human/password").unwrap(),
            AgentId::new("agent-a").unwrap(),
            "need for deploy".to_owned(),
            Duration::seconds(-1),
            &signing_key,
        )
        .unwrap();

    let loaded = store.load_all().unwrap();
    assert_eq!(loaded[0].status, RequestStatus::Expired);
    assert!(!loaded[0].pending);
}

#[test]
fn pending_deny() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("pending.json");
    let store = PendingRequestStore::new(&path).unwrap();
    let signing_key = signing_key();

    let request = store
        .create(
            SecretId::new("human/password").unwrap(),
            AgentId::new("agent-a").unwrap(),
            "need for deploy".to_owned(),
            Duration::minutes(1),
            &signing_key,
        )
        .unwrap();

    let reviewer = AgentId::new("reviewer-a").unwrap();
    let denied = store.deny(request.id, reviewer.clone()).unwrap();
    assert_eq!(denied.status, RequestStatus::Denied);
    assert!(!denied.pending);
    assert_eq!(denied.denied_by, Some(reviewer.clone()));
    assert!(denied.denied_at.is_some());
    assert!(denied.approved_by.is_none());
    assert!(denied.approved_at.is_none());

    let loaded = store.load_all().unwrap();
    assert_eq!(loaded[0].status, RequestStatus::Denied);
    assert!(!loaded[0].pending);
    assert_eq!(loaded[0].denied_by, Some(reviewer));
    assert!(loaded[0].denied_at.is_some());
    assert!(loaded[0].expires_at > Utc::now() - Duration::hours(1));
}

#[test]
fn pending_approve() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("pending.json");
    let store = PendingRequestStore::new(&path).unwrap();
    let signing_key = signing_key();

    let request = store
        .create(
            SecretId::new("human/password").unwrap(),
            AgentId::new("agent-a").unwrap(),
            "need for deploy".to_owned(),
            Duration::minutes(1),
            &signing_key,
        )
        .unwrap();
    let reviewer = AgentId::new("reviewer-a").unwrap();
    let approved = store.approve(request.id, reviewer.clone()).unwrap();
    assert_eq!(approved.status, RequestStatus::Fulfilled);
    assert!(!approved.pending);
    assert_eq!(approved.approved_by, Some(reviewer.clone()));
    assert!(approved.approved_at.is_some());
    assert!(approved.denied_by.is_none());
    assert!(approved.denied_at.is_none());

    let loaded = store.load_all().unwrap();
    assert_eq!(loaded[0].status, RequestStatus::Fulfilled);
    assert!(!loaded[0].pending);
    assert_eq!(loaded[0].approved_by, Some(reviewer));
    assert!(loaded[0].approved_at.is_some());

    assert!(store
        .is_fulfilled(
            &SecretId::new("human/password").unwrap(),
            &AgentId::new("agent-a").unwrap()
        )
        .unwrap());
}

#[test]
fn pending_signature_tamper_fails_load() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("pending.json");
    let store = PendingRequestStore::new(&path).unwrap();
    let signing_key = signing_key();

    store
        .create(
            SecretId::new("human/password").unwrap(),
            AgentId::new("agent-a").unwrap(),
            "need for deploy".to_owned(),
            Duration::minutes(1),
            &signing_key,
        )
        .unwrap();

    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    value[0]["signature"][0] = serde_json::Value::from(255_u64);
    std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();

    assert!(matches!(
        store.load_all(),
        Err(GlovesError::IntegrityViolation)
    ));
}

#[test]
fn pending_approve_not_found() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("pending.json");
    let store = PendingRequestStore::new(&path).unwrap();
    assert!(matches!(
        store.approve(uuid::Uuid::new_v4(), AgentId::new("reviewer-a").unwrap()),
        Err(GlovesError::NotFound)
    ));
}

#[test]
fn pending_deny_not_found() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("pending.json");
    let store = PendingRequestStore::new(&path).unwrap();
    assert!(matches!(
        store.deny(uuid::Uuid::new_v4(), AgentId::new("reviewer-a").unwrap()),
        Err(GlovesError::NotFound)
    ));
}

#[test]
fn pending_request_cannot_be_resolved_twice() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("pending.json");
    let store = PendingRequestStore::new(&path).unwrap();
    let signing_key = signing_key();

    let request = store
        .create(
            SecretId::new("human/password").unwrap(),
            AgentId::new("agent-a").unwrap(),
            "need for deploy".to_owned(),
            Duration::minutes(1),
            &signing_key,
        )
        .unwrap();

    store
        .approve(request.id, AgentId::new("reviewer-a").unwrap())
        .unwrap();
    assert!(matches!(
        store.deny(request.id, AgentId::new("reviewer-b").unwrap()),
        Err(GlovesError::InvalidInput(_))
    ));
}

#[test]
fn pending_load_repairs_legacy_pending_flag() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("pending.json");
    let store = PendingRequestStore::new(&path).unwrap();
    let signing_key = signing_key();

    let request = store
        .create(
            SecretId::new("human/password").unwrap(),
            AgentId::new("agent-a").unwrap(),
            "need for deploy".to_owned(),
            Duration::minutes(1),
            &signing_key,
        )
        .unwrap();

    let mut raw_requests: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    raw_requests[0]["pending"] = serde_json::Value::Bool(false);
    std::fs::write(&path, serde_json::to_vec_pretty(&raw_requests).unwrap()).unwrap();

    let loaded = store.load_all().unwrap();
    let restored = loaded
        .into_iter()
        .find(|entry| entry.id == request.id)
        .unwrap();
    assert_eq!(restored.status, RequestStatus::Pending);
    assert!(restored.pending);
}

#[test]
fn pending_is_fulfilled_false_without_match() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("pending.json");
    let store = PendingRequestStore::new(&path).unwrap();
    assert!(!store
        .is_fulfilled(
            &SecretId::new("human/password").unwrap(),
            &AgentId::new("agent-a").unwrap()
        )
        .unwrap());
}
