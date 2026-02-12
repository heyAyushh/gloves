use std::sync::{Arc, Mutex};

use chrono::{Duration, Utc};
use gloves::{
    error::GlovesError,
    human::{
        backend::{HumanBackend, PassExecutor, PassOutput},
        pending::PendingRequestStore,
    },
    types::{AgentId, RequestStatus, SecretId},
};

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
fn pending_create_persist() {
    let temp_dir = tempfile::tempdir().unwrap();
    let store = PendingRequestStore::new(temp_dir.path().join("pending.json")).unwrap();

    store
        .create(
            SecretId::new("human/password").unwrap(),
            AgentId::new("agent-a").unwrap(),
            "need for deploy".to_owned(),
            Duration::minutes(10),
        )
        .unwrap();

    let loaded = store.load_all().unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].status, RequestStatus::Pending);
}

#[test]
fn pending_auto_expire() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("pending.json");
    let store = PendingRequestStore::new(&path).unwrap();

    store
        .create(
            SecretId::new("human/password").unwrap(),
            AgentId::new("agent-a").unwrap(),
            "need for deploy".to_owned(),
            Duration::seconds(-1),
        )
        .unwrap();

    let loaded = store.load_all().unwrap();
    assert_eq!(loaded[0].status, RequestStatus::Expired);
}

#[test]
fn pending_deny() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("pending.json");
    let store = PendingRequestStore::new(&path).unwrap();

    let request = store
        .create(
            SecretId::new("human/password").unwrap(),
            AgentId::new("agent-a").unwrap(),
            "need for deploy".to_owned(),
            Duration::minutes(1),
        )
        .unwrap();

    store.deny(request.id).unwrap();
    let loaded = store.load_all().unwrap();
    assert_eq!(loaded[0].status, RequestStatus::Denied);
    assert!(loaded[0].expires_at > Utc::now() - Duration::hours(1));
}
