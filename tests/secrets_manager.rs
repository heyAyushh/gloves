use std::collections::HashSet;

use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use gloves::{
    agent::{backend::AgentBackend, meta::MetadataStore},
    audit::AuditLog,
    error::GlovesError,
    human::{
        backend::{HumanBackend, PassExecutor, PassOutput},
        pending::PendingRequestStore,
    },
    manager::{SecretsManager, SetSecretOptions},
    types::{AgentId, Owner, RequestStatus, SecretId, SecretMeta, SecretValue},
};
use rand::RngExt;

struct MockPass {
    output: PassOutput,
}

impl PassExecutor for MockPass {
    fn exec(&self, _args: &[&str]) -> gloves::error::Result<PassOutput> {
        Ok(self.output.clone())
    }
}

fn build_manager(human_backend: HumanBackend) -> (SecretsManager, tempfile::TempDir) {
    let temp_dir = tempfile::tempdir().unwrap();
    let manager = SecretsManager::new(
        AgentBackend::new(temp_dir.path().join("store")).unwrap(),
        human_backend,
        MetadataStore::new(temp_dir.path().join("meta")).unwrap(),
        PendingRequestStore::new(temp_dir.path().join("pending.json")).unwrap(),
        AuditLog::new(temp_dir.path().join("audit.jsonl")).unwrap(),
    );
    (manager, temp_dir)
}

fn signing_key() -> SigningKey {
    let mut key_bytes = [0_u8; 32];
    rand::rng().fill(&mut key_bytes);
    SigningKey::from_bytes(&key_bytes)
}

#[test]
fn set_agent_secret() {
    let (manager, _temp) = build_manager(HumanBackend::new());

    let id = SecretId::new("service/token").unwrap();
    let creator = AgentId::new("agent-a").unwrap();
    let mut recipients = HashSet::new();
    recipients.insert(creator.clone());
    let identity = age::x25519::Identity::generate();

    let created = manager
        .set(
            id.clone(),
            SecretValue::new(b"shh".to_vec()),
            SetSecretOptions {
                owner: Owner::Agent,
                ttl: Duration::hours(1),
                created_by: creator,
                recipients,
                recipient_keys: vec![identity.to_public().to_string()],
            },
        )
        .unwrap();

    assert_eq!(created, id);
}

#[test]
fn set_human_forbidden() {
    let (manager, _temp) = build_manager(HumanBackend::new());

    let id = SecretId::new("service/token").unwrap();
    let creator = AgentId::new("agent-a").unwrap();
    let recipients = HashSet::new();

    let result = manager.set(
        id,
        SecretValue::new(b"shh".to_vec()),
        SetSecretOptions {
            owner: Owner::Human,
            ttl: Duration::hours(1),
            created_by: creator,
            recipients,
            recipient_keys: vec![],
        },
    );

    assert!(matches!(result, Err(GlovesError::Forbidden)));
}

#[test]
fn set_rolls_back_ciphertext_when_metadata_save_fails() {
    let (manager, temp_dir) = build_manager(HumanBackend::new());
    std::fs::write(temp_dir.path().join("meta").join("service"), b"blocked").unwrap();

    let secret_id = SecretId::new("service/token").unwrap();
    let creator = AgentId::new("agent-a").unwrap();
    let mut recipients = HashSet::new();
    recipients.insert(creator.clone());
    let identity = age::x25519::Identity::generate();

    let result = manager.set(
        secret_id.clone(),
        SecretValue::new(b"value".to_vec()),
        SetSecretOptions {
            owner: Owner::Agent,
            ttl: Duration::hours(1),
            created_by: creator,
            recipients,
            recipient_keys: vec![identity.to_public().to_string()],
        },
    );

    assert!(matches!(result, Err(GlovesError::Io(_))));
    assert!(!manager.agent_backend.ciphertext_path(&secret_id).exists());
}

#[test]
fn set_rolls_back_metadata_and_ciphertext_when_audit_fails() {
    let (manager, temp_dir) = build_manager(HumanBackend::new());
    let audit_path = temp_dir.path().join("audit.jsonl");
    std::fs::remove_file(&audit_path).unwrap();
    std::fs::create_dir(&audit_path).unwrap();

    let secret_id = SecretId::new("service/token").unwrap();
    let creator = AgentId::new("agent-a").unwrap();
    let mut recipients = HashSet::new();
    recipients.insert(creator.clone());
    let identity = age::x25519::Identity::generate();

    let result = manager.set(
        secret_id.clone(),
        SecretValue::new(b"value".to_vec()),
        SetSecretOptions {
            owner: Owner::Agent,
            ttl: Duration::hours(1),
            created_by: creator,
            recipients,
            recipient_keys: vec![identity.to_public().to_string()],
        },
    );

    assert!(matches!(result, Err(GlovesError::Io(_))));
    assert!(!manager.agent_backend.ciphertext_path(&secret_id).exists());
    assert!(manager.metadata_store.load(&secret_id).is_err());
}

#[test]
fn get_routes_agent() {
    let (manager, _temp) = build_manager(HumanBackend::new());

    let id = SecretId::new("service/token").unwrap();
    let creator = AgentId::new("agent-a").unwrap();
    let mut recipients = HashSet::new();
    recipients.insert(creator.clone());
    let identity = age::x25519::Identity::generate();

    manager
        .set(
            id.clone(),
            SecretValue::new(b"agent-secret".to_vec()),
            SetSecretOptions {
                owner: Owner::Agent,
                ttl: Duration::hours(1),
                created_by: creator.clone(),
                recipients,
                recipient_keys: vec![identity.to_public().to_string()],
            },
        )
        .unwrap();

    let secret = manager.get(&id, &creator, Some(identity)).unwrap();
    assert_eq!(secret.expose(|bytes| bytes.to_vec()), b"agent-secret");
}

#[test]
fn get_routes_human() {
    let human_backend = HumanBackend::with_executor(Box::new(MockPass {
        output: PassOutput {
            status_code: 0,
            stdout: "from-pass\n".to_owned(),
            stderr: String::new(),
        },
    }));
    let (manager, _temp) = build_manager(human_backend);

    let id = SecretId::new("human/token").unwrap();
    let creator = AgentId::new("agent-a").unwrap();

    manager
        .metadata_store
        .save(&SecretMeta {
            id: id.clone(),
            owner: Owner::Human,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
            recipients: HashSet::new(),
            created_by: creator.clone(),
            last_accessed: None,
            access_count: 0,
            checksum: String::new(),
        })
        .unwrap();
    let signing_key = signing_key();
    let request = manager
        .request(
            id.clone(),
            creator.clone(),
            "approved access".to_owned(),
            Duration::minutes(10),
            &signing_key,
        )
        .unwrap();
    manager.approve_request(request.id).unwrap();

    let secret = manager.get(&id, &creator, None).unwrap();
    assert_eq!(secret.expose(|bytes| bytes.to_vec()), b"from-pass");
}

#[test]
fn get_human_without_approval_forbidden() {
    let human_backend = HumanBackend::with_executor(Box::new(MockPass {
        output: PassOutput {
            status_code: 0,
            stdout: "from-pass\n".to_owned(),
            stderr: String::new(),
        },
    }));
    let (manager, _temp) = build_manager(human_backend);

    let id = SecretId::new("human/token").unwrap();
    let creator = AgentId::new("agent-a").unwrap();
    manager
        .metadata_store
        .save(&SecretMeta {
            id: id.clone(),
            owner: Owner::Human,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
            recipients: HashSet::new(),
            created_by: creator.clone(),
            last_accessed: None,
            access_count: 0,
            checksum: String::new(),
        })
        .unwrap();

    assert!(matches!(
        manager.get(&id, &creator, None),
        Err(GlovesError::Forbidden)
    ));
}

#[test]
fn get_expired() {
    let (manager, _temp) = build_manager(HumanBackend::new());

    let id = SecretId::new("service/token").unwrap();
    let creator = AgentId::new("agent-a").unwrap();
    let mut recipients = HashSet::new();
    recipients.insert(creator.clone());
    let identity = age::x25519::Identity::generate();

    manager
        .set(
            id.clone(),
            SecretValue::new(b"agent-secret".to_vec()),
            SetSecretOptions {
                owner: Owner::Agent,
                ttl: Duration::seconds(-1),
                created_by: creator.clone(),
                recipients,
                recipient_keys: vec![identity.to_public().to_string()],
            },
        )
        .unwrap();

    assert!(matches!(
        manager.get(&id, &creator, Some(identity)),
        Err(GlovesError::Expired)
    ));
}

#[test]
fn get_unauthorized() {
    let (manager, _temp) = build_manager(HumanBackend::new());

    let id = SecretId::new("service/token").unwrap();
    let creator = AgentId::new("agent-a").unwrap();
    let mut recipients = HashSet::new();
    recipients.insert(creator.clone());
    let identity = age::x25519::Identity::generate();

    manager
        .set(
            id.clone(),
            SecretValue::new(b"agent-secret".to_vec()),
            SetSecretOptions {
                owner: Owner::Agent,
                ttl: Duration::hours(1),
                created_by: creator,
                recipients,
                recipient_keys: vec![identity.to_public().to_string()],
            },
        )
        .unwrap();

    let outsider = AgentId::new("agent-b").unwrap();
    assert!(matches!(
        manager.get(&id, &outsider, Some(age::x25519::Identity::generate())),
        Err(GlovesError::Unauthorized)
    ));
}

#[test]
fn get_agent_without_identity_is_unauthorized() {
    let (manager, _temp) = build_manager(HumanBackend::new());

    let id = SecretId::new("service/token").unwrap();
    let creator = AgentId::new("agent-a").unwrap();
    let mut recipients = HashSet::new();
    recipients.insert(creator.clone());
    let identity = age::x25519::Identity::generate();

    manager
        .set(
            id.clone(),
            SecretValue::new(b"agent-secret".to_vec()),
            SetSecretOptions {
                owner: Owner::Agent,
                ttl: Duration::hours(1),
                created_by: creator.clone(),
                recipients,
                recipient_keys: vec![identity.to_public().to_string()],
            },
        )
        .unwrap();

    assert!(matches!(
        manager.get(&id, &creator, None),
        Err(GlovesError::Unauthorized)
    ));
}

#[test]
fn get_increments_access() {
    let (manager, _temp) = build_manager(HumanBackend::new());

    let id = SecretId::new("service/token").unwrap();
    let creator = AgentId::new("agent-a").unwrap();
    let mut recipients = HashSet::new();
    recipients.insert(creator.clone());
    let identity = age::x25519::Identity::generate();

    manager
        .set(
            id.clone(),
            SecretValue::new(b"agent-secret".to_vec()),
            SetSecretOptions {
                owner: Owner::Agent,
                ttl: Duration::hours(1),
                created_by: creator.clone(),
                recipients,
                recipient_keys: vec![identity.to_public().to_string()],
            },
        )
        .unwrap();

    manager.get(&id, &creator, Some(identity)).unwrap();
    let meta = manager.metadata_store.load(&id).unwrap();
    assert_eq!(meta.access_count, 1);
}

#[test]
fn get_tampered_ciphertext_fails_integrity() {
    let (manager, _temp) = build_manager(HumanBackend::new());

    let id = SecretId::new("service/token").unwrap();
    let creator = AgentId::new("agent-a").unwrap();
    let mut recipients = HashSet::new();
    recipients.insert(creator.clone());
    let identity = age::x25519::Identity::generate();

    manager
        .set(
            id.clone(),
            SecretValue::new(b"agent-secret".to_vec()),
            SetSecretOptions {
                owner: Owner::Agent,
                ttl: Duration::hours(1),
                created_by: creator.clone(),
                recipients,
                recipient_keys: vec![identity.to_public().to_string()],
            },
        )
        .unwrap();

    let ciphertext_path = manager.agent_backend.ciphertext_path(&id);
    let mut bytes = std::fs::read(&ciphertext_path).unwrap();
    bytes[0] ^= 0xFF;
    std::fs::write(ciphertext_path, bytes).unwrap();

    assert!(matches!(
        manager.get(&id, &creator, Some(identity)),
        Err(GlovesError::IntegrityViolation)
    ));
}

#[test]
fn get_with_empty_checksum_allows_legacy_metadata() {
    let (manager, _temp) = build_manager(HumanBackend::new());

    let id = SecretId::new("service/token").unwrap();
    let creator = AgentId::new("agent-a").unwrap();
    let mut recipients = HashSet::new();
    recipients.insert(creator.clone());
    let identity = age::x25519::Identity::generate();

    manager
        .set(
            id.clone(),
            SecretValue::new(b"agent-secret".to_vec()),
            SetSecretOptions {
                owner: Owner::Agent,
                ttl: Duration::hours(1),
                created_by: creator.clone(),
                recipients,
                recipient_keys: vec![identity.to_public().to_string()],
            },
        )
        .unwrap();

    let mut meta = manager.metadata_store.load(&id).unwrap();
    meta.checksum.clear();
    manager.metadata_store.save(&meta).unwrap();

    let value = manager.get(&id, &creator, Some(identity)).unwrap();
    assert_eq!(value.expose(|bytes| bytes.to_vec()), b"agent-secret");
}

#[test]
fn request_creates_pending() {
    let (manager, _temp) = build_manager(HumanBackend::new());
    let signing_key = signing_key();

    manager
        .request(
            SecretId::new("human/token").unwrap(),
            AgentId::new("agent-a").unwrap(),
            "need deploy".to_owned(),
            Duration::minutes(10),
            &signing_key,
        )
        .unwrap();

    assert_eq!(manager.pending_store.load_all().unwrap().len(), 1);
}

#[test]
fn grant_agent_ok() {
    let (manager, _temp) = build_manager(HumanBackend::new());

    let id = SecretId::new("service/token").unwrap();
    let creator = AgentId::new("agent-a").unwrap();
    let new_agent = AgentId::new("agent-b").unwrap();
    let mut recipients = HashSet::new();
    recipients.insert(creator.clone());

    let creator_identity = age::x25519::Identity::generate();
    let new_identity = age::x25519::Identity::generate();

    manager
        .set(
            id.clone(),
            SecretValue::new(b"agent-secret".to_vec()),
            SetSecretOptions {
                owner: Owner::Agent,
                ttl: Duration::hours(1),
                created_by: creator.clone(),
                recipients,
                recipient_keys: vec![creator_identity.to_public().to_string()],
            },
        )
        .unwrap();

    manager
        .grant(
            &id,
            &creator,
            creator_identity,
            new_agent.clone(),
            &[
                new_identity.to_public().to_string(),
                age::x25519::Identity::generate().to_public().to_string(),
            ],
        )
        .unwrap();

    let value = manager.get(&id, &new_agent, Some(new_identity)).unwrap();
    assert_eq!(value.expose(|bytes| bytes.to_vec()), b"agent-secret");
}

#[test]
fn grant_human_forbidden() {
    let (manager, _temp) = build_manager(HumanBackend::new());

    let id = SecretId::new("human/token").unwrap();
    let creator = AgentId::new("agent-a").unwrap();
    manager
        .metadata_store
        .save(&SecretMeta {
            id: id.clone(),
            owner: Owner::Human,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
            recipients: HashSet::new(),
            created_by: creator.clone(),
            last_accessed: None,
            access_count: 0,
            checksum: String::new(),
        })
        .unwrap();

    let result = manager.grant(
        &id,
        &creator,
        age::x25519::Identity::generate(),
        AgentId::new("agent-b").unwrap(),
        &[age::x25519::Identity::generate().to_public().to_string()],
    );

    assert!(matches!(result, Err(GlovesError::Forbidden)));
}

#[test]
fn grant_by_non_creator_forbidden() {
    let (manager, _temp) = build_manager(HumanBackend::new());

    let id = SecretId::new("service/token").unwrap();
    let creator = AgentId::new("agent-a").unwrap();
    let outsider = AgentId::new("agent-b").unwrap();
    let mut recipients = HashSet::new();
    recipients.insert(creator.clone());
    let creator_identity = age::x25519::Identity::generate();

    manager
        .set(
            id.clone(),
            SecretValue::new(b"agent-secret".to_vec()),
            SetSecretOptions {
                owner: Owner::Agent,
                ttl: Duration::hours(1),
                created_by: creator,
                recipients,
                recipient_keys: vec![creator_identity.to_public().to_string()],
            },
        )
        .unwrap();

    let result = manager.grant(
        &id,
        &outsider,
        age::x25519::Identity::generate(),
        AgentId::new("agent-c").unwrap(),
        &[age::x25519::Identity::generate().to_public().to_string()],
    );
    assert!(matches!(result, Err(GlovesError::Forbidden)));
}

#[test]
fn revoke_by_creator() {
    let (manager, _temp) = build_manager(HumanBackend::new());

    let id = SecretId::new("service/token").unwrap();
    let creator = AgentId::new("agent-a").unwrap();
    let mut recipients = HashSet::new();
    recipients.insert(creator.clone());
    let identity = age::x25519::Identity::generate();

    manager
        .set(
            id.clone(),
            SecretValue::new(b"agent-secret".to_vec()),
            SetSecretOptions {
                owner: Owner::Agent,
                ttl: Duration::hours(1),
                created_by: creator.clone(),
                recipients,
                recipient_keys: vec![identity.to_public().to_string()],
            },
        )
        .unwrap();

    manager.revoke(&id, &creator).unwrap();
    assert!(manager.metadata_store.load(&id).is_err());
    assert!(!manager.agent_backend.ciphertext_path(&id).exists());
}

#[test]
fn revoke_by_noncreator() {
    let (manager, _temp) = build_manager(HumanBackend::new());

    let id = SecretId::new("service/token").unwrap();
    let creator = AgentId::new("agent-a").unwrap();
    let mut recipients = HashSet::new();
    recipients.insert(creator.clone());
    let identity = age::x25519::Identity::generate();

    manager
        .set(
            id.clone(),
            SecretValue::new(b"agent-secret".to_vec()),
            SetSecretOptions {
                owner: Owner::Agent,
                ttl: Duration::hours(1),
                created_by: creator,
                recipients,
                recipient_keys: vec![identity.to_public().to_string()],
            },
        )
        .unwrap();

    let outsider = AgentId::new("agent-b").unwrap();
    assert!(matches!(
        manager.revoke(&id, &outsider),
        Err(GlovesError::Forbidden)
    ));
}

#[test]
fn list_all() {
    let (manager, _temp) = build_manager(HumanBackend::new());
    let signing_key = signing_key();

    let id = SecretId::new("service/token").unwrap();
    let creator = AgentId::new("agent-a").unwrap();
    let mut recipients = HashSet::new();
    recipients.insert(creator.clone());
    let identity = age::x25519::Identity::generate();

    manager
        .set(
            id,
            SecretValue::new(b"agent-secret".to_vec()),
            SetSecretOptions {
                owner: Owner::Agent,
                ttl: Duration::hours(1),
                created_by: creator.clone(),
                recipients,
                recipient_keys: vec![identity.to_public().to_string()],
            },
        )
        .unwrap();
    manager
        .request(
            SecretId::new("human/token").unwrap(),
            creator,
            "need deploy".to_owned(),
            Duration::minutes(10),
            &signing_key,
        )
        .unwrap();

    let list = manager.list_all().unwrap();
    assert_eq!(list.len(), 2);
    assert!(serde_json::to_string(&list).unwrap().contains("pending"));
    assert!(serde_json::to_string(&list).unwrap().contains("secret"));
}

#[test]
fn approve_and_deny_request_wrappers() {
    let (manager, _temp) = build_manager(HumanBackend::new());
    let signing_key = signing_key();
    let request = manager
        .request(
            SecretId::new("human/token").unwrap(),
            AgentId::new("agent-a").unwrap(),
            "need deploy".to_owned(),
            Duration::minutes(10),
            &signing_key,
        )
        .unwrap();

    manager.approve_request(request.id).unwrap();
    let status = manager
        .pending_store
        .load_all()
        .unwrap()
        .into_iter()
        .find(|entry| entry.id == request.id)
        .unwrap()
        .status;
    assert_eq!(status, RequestStatus::Fulfilled);

    manager.deny_request(request.id).unwrap();
    let status = manager
        .pending_store
        .load_all()
        .unwrap()
        .into_iter()
        .find(|entry| entry.id == request.id)
        .unwrap()
        .status;
    assert_eq!(status, RequestStatus::Denied);
}

#[test]
fn status_value_is_valid() {
    assert_eq!(
        serde_json::to_string(&RequestStatus::Pending).unwrap(),
        "\"pending\""
    );
}
