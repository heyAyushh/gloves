use std::{fs, path::{Path, PathBuf}};

use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::{
    error::Result,
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
        if !file_path.exists() {
            fs::write(&file_path, "[]")?;
        }
        Ok(Self { path: file_path })
    }

    /// Creates and persists a pending request.
    pub fn create(
        &self,
        secret_name: SecretId,
        requested_by: AgentId,
        reason: String,
        ttl: Duration,
    ) -> Result<PendingRequest> {
        let now = Utc::now();
        let request = PendingRequest {
            id: Uuid::new_v4(),
            secret_name,
            requested_by,
            reason,
            requested_at: now,
            expires_at: now + ttl,
            signature: Vec::new(),
            status: RequestStatus::Pending,
        };

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
            if request.status == RequestStatus::Pending && request.expires_at < now {
                request.status = RequestStatus::Expired;
                changed = true;
            }
        }
        if changed {
            self.save_all(&requests)?;
        }
        Ok(requests)
    }

    /// Marks request denied.
    pub fn deny(&self, request_id: Uuid) -> Result<()> {
        let mut requests = self.load_all()?;
        for request in &mut requests {
            if request.id == request_id {
                request.status = RequestStatus::Denied;
            }
        }
        self.save_all(&requests)
    }

    fn save_all(&self, requests: &[PendingRequest]) -> Result<()> {
        fs::write(&self.path, serde_json::to_vec_pretty(requests)?)?;
        Ok(())
    }
}
