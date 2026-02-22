use std::{
    fs,
    path::{Path, PathBuf},
};

use chrono::{Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use uuid::Uuid;

use crate::{
    error::{GlovesError, Result},
    fs_secure::{create_private_file_if_missing, write_private_file_atomic},
    types::{AgentId, PendingRequest, RequestStatus, SecretId},
};

/// Persistent store for pending human requests.
pub struct PendingRequestStore {
    path: PathBuf,
}

impl PendingRequestStore {
    /// Creates a pending request store at a JSON file path.
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let file_path = path.as_ref().to_path_buf();
        create_private_file_if_missing(&file_path, b"[]")?;
        Ok(Self { path: file_path })
    }

    /// Creates and persists a pending request.
    pub fn create(
        &self,
        secret_name: SecretId,
        requested_by: AgentId,
        reason: String,
        ttl: Duration,
        signing_key: &SigningKey,
    ) -> Result<PendingRequest> {
        let now = Utc::now();
        let mut request = PendingRequest {
            id: Uuid::new_v4(),
            secret_name,
            requested_by,
            reason,
            requested_at: now,
            expires_at: now + ttl,
            signature: Vec::new(),
            verifying_key: signing_key.verifying_key().to_bytes().to_vec(),
            status: RequestStatus::Pending,
            pending: true,
            approved_at: None,
            approved_by: None,
            denied_at: None,
            denied_by: None,
        };
        request.signature = sign_request_payload(&request, signing_key)?;

        let mut requests = self.load_all()?;
        requests.push(request.clone());
        self.save_all(&requests)?;

        Ok(request)
    }

    /// Loads all requests, auto-marking expired pending entries.
    pub fn load_all(&self) -> Result<Vec<PendingRequest>> {
        let bytes = fs::read(&self.path)?;
        let mut requests: Vec<PendingRequest> = serde_json::from_slice(&bytes)?;
        let now = Utc::now();
        let mut changed = false;
        for request in &mut requests {
            verify_request_signature(request)?;
            if request.status == RequestStatus::Pending && request.expires_at < now {
                request.status = RequestStatus::Expired;
                request.pending = false;
                changed = true;
            } else {
                let expected_pending = request.status == RequestStatus::Pending;
                if request.pending != expected_pending {
                    request.pending = expected_pending;
                    changed = true;
                }
            }
        }
        if changed {
            self.save_all(&requests)?;
        }
        Ok(requests)
    }

    /// Marks request denied and records reviewer details.
    pub fn deny(&self, request_id: Uuid, reviewed_by: AgentId) -> Result<PendingRequest> {
        self.resolve_request(request_id, RequestStatus::Denied, reviewed_by)
    }

    /// Marks request approved and records reviewer details.
    pub fn approve(&self, request_id: Uuid, reviewed_by: AgentId) -> Result<PendingRequest> {
        self.resolve_request(request_id, RequestStatus::Fulfilled, reviewed_by)
    }

    /// Returns true when a matching request is approved and valid.
    pub fn is_fulfilled(&self, secret_name: &SecretId, requested_by: &AgentId) -> Result<bool> {
        let requests = self.load_all()?;
        Ok(requests.into_iter().any(|request| {
            request.secret_name == *secret_name
                && request.requested_by == *requested_by
                && request.status == RequestStatus::Fulfilled
        }))
    }

    fn save_all(&self, requests: &[PendingRequest]) -> Result<()> {
        write_private_file_atomic(&self.path, &serde_json::to_vec_pretty(requests)?)?;
        Ok(())
    }

    fn resolve_request(
        &self,
        request_id: Uuid,
        next_status: RequestStatus,
        reviewed_by: AgentId,
    ) -> Result<PendingRequest> {
        let mut requests = self.load_all()?;
        let now = Utc::now();
        let mut resolved = None;
        for request in &mut requests {
            if request.id != request_id {
                continue;
            }
            if request.status != RequestStatus::Pending {
                return Err(GlovesError::InvalidInput(
                    "request is not pending".to_owned(),
                ));
            }
            request.status = next_status.clone();
            request.pending = false;
            match next_status {
                RequestStatus::Fulfilled => {
                    request.approved_at = Some(now);
                    request.approved_by = Some(reviewed_by.clone());
                }
                RequestStatus::Denied => {
                    request.denied_at = Some(now);
                    request.denied_by = Some(reviewed_by.clone());
                }
                RequestStatus::Pending | RequestStatus::Expired => {}
            }
            resolved = Some(request.clone());
            break;
        }

        let resolved = resolved.ok_or(GlovesError::NotFound)?;
        self.save_all(&requests)?;
        Ok(resolved)
    }
}

#[derive(serde::Serialize)]
struct SignedRequestPayload<'a> {
    id: Uuid,
    secret_name: &'a SecretId,
    requested_by: &'a AgentId,
    reason: &'a str,
    requested_at: chrono::DateTime<Utc>,
    expires_at: chrono::DateTime<Utc>,
}

fn signing_payload(request: &PendingRequest) -> Result<Vec<u8>> {
    serde_json::to_vec(&SignedRequestPayload {
        id: request.id,
        secret_name: &request.secret_name,
        requested_by: &request.requested_by,
        reason: &request.reason,
        requested_at: request.requested_at,
        expires_at: request.expires_at,
    })
    .map_err(Into::into)
}

fn sign_request_payload(request: &PendingRequest, signing_key: &SigningKey) -> Result<Vec<u8>> {
    let payload = signing_payload(request)?;
    Ok(signing_key.sign(&payload).to_bytes().to_vec())
}

fn verify_request_signature(request: &PendingRequest) -> Result<()> {
    let key_bytes: [u8; 32] = request
        .verifying_key
        .as_slice()
        .try_into()
        .map_err(|_| GlovesError::IntegrityViolation)?;
    let signature =
        Signature::from_slice(&request.signature).map_err(|_| GlovesError::IntegrityViolation)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| GlovesError::IntegrityViolation)?;
    verifying_key
        .verify(&signing_payload(request)?, &signature)
        .map_err(|_| GlovesError::IntegrityViolation)
}
