use std::collections::HashSet;

use chrono::{Duration, Utc};

use crate::{
    agent::{backend::{parse_recipient, AgentBackend}, meta::MetadataStore},
    audit::{AuditEvent, AuditLog},
    error::{GlovesError, Result},
    human::{backend::HumanBackend, pending::PendingRequestStore},
    types::{AgentId, Owner, PendingRequest, SecretId, SecretMeta, SecretValue},
};

/// Aggregated item returned from listing API.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ListItem {
    /// One secret metadata entry.
    Secret(SecretMeta),
    /// One pending human request.
    Pending(PendingRequest),
}

/// Unified router over agent and human backends.
pub struct SecretsManager {
    /// Agent backend.
    pub agent_backend: AgentBackend,
    /// Human backend.
    pub human_backend: HumanBackend,
    /// Secret metadata store.
    pub metadata_store: MetadataStore,
    /// Pending request store.
    pub pending_store: PendingRequestStore,
    /// Audit writer.
    pub audit_log: AuditLog,
}

impl SecretsManager {
    /// Creates a new manager.
    pub fn new(
        agent_backend: AgentBackend,
        human_backend: HumanBackend,
        metadata_store: MetadataStore,
        pending_store: PendingRequestStore,
        audit_log: AuditLog,
    ) -> Self {
        Self {
            agent_backend,
            human_backend,
            metadata_store,
            pending_store,
            audit_log,
        }
    }

    /// Stores an agent secret and metadata.
    pub fn set(
        &self,
        secret_id: SecretId,
        owner: Owner,
        secret_value: SecretValue,
        ttl: Duration,
        created_by: AgentId,
        recipients: HashSet<AgentId>,
        recipient_keys: &[String],
    ) -> Result<SecretId> {
        if owner != Owner::Agent {
            return Err(GlovesError::Forbidden);
        }

        let parsed_recipients = recipient_keys
            .iter()
            .map(|value| parse_recipient(value))
            .collect::<Result<Vec<_>>>()?;

        self.agent_backend
            .encrypt(&secret_id, &secret_value, parsed_recipients)?;

        let now = Utc::now();
        let meta = SecretMeta {
            id: secret_id.clone(),
            owner,
            created_at: now,
            expires_at: now + ttl,
            recipients,
            created_by: created_by.clone(),
            last_accessed: None,
            access_count: 0,
            checksum: String::new(),
        };
        self.metadata_store.save(&meta)?;
        self.audit_log.log(AuditEvent::SecretCreated {
            secret_id: secret_id.clone(),
            by: created_by,
        })?;
        Ok(secret_id)
    }

    /// Gets a secret by id and caller identity.
    pub fn get(
        &self,
        secret_id: &SecretId,
        caller: &AgentId,
        caller_identity: Option<age::x25519::Identity>,
    ) -> Result<SecretValue> {
        let mut meta = self.metadata_store.load(secret_id)?;

        if meta.expires_at <= Utc::now() {
            return Err(GlovesError::Expired);
        }

        let secret = match meta.owner {
            Owner::Agent => {
                if !meta.recipients.contains(caller) {
                    return Err(GlovesError::Unauthorized);
                }

                let identity = caller_identity.ok_or(GlovesError::Unauthorized)?;
                self.agent_backend.decrypt(secret_id, vec![identity])?
            }
            Owner::Human => self.human_backend.get(secret_id.as_str())?,
        };

        meta.last_accessed = Some(Utc::now());
        meta.access_count += 1;
        self.metadata_store.save(&meta)?;
        self.audit_log.log(AuditEvent::SecretAccessed {
            secret_id: secret_id.clone(),
            by: caller.clone(),
        })?;
        Ok(secret)
    }

    /// Creates a pending human request.
    pub fn request(
        &self,
        secret_id: SecretId,
        requested_by: AgentId,
        reason: String,
        ttl: Duration,
    ) -> Result<PendingRequest> {
        self.pending_store.create(secret_id, requested_by, reason, ttl)
    }

    /// Grants access to an agent secret by adding a recipient.
    pub fn grant(
        &self,
        secret_id: &SecretId,
        granter: &AgentId,
        granter_identity: age::x25519::Identity,
        new_recipient: AgentId,
        all_recipient_keys: &[String],
    ) -> Result<()> {
        let mut meta = self.metadata_store.load(secret_id)?;
        if meta.owner != Owner::Agent {
            return Err(GlovesError::Forbidden);
        }
        if meta.created_by != *granter {
            return Err(GlovesError::Forbidden);
        }

        meta.recipients.insert(new_recipient);
        let parsed_recipients = all_recipient_keys
            .iter()
            .map(|value| parse_recipient(value))
            .collect::<Result<Vec<_>>>()?;
        self.agent_backend
            .grant(secret_id, granter_identity, parsed_recipients)?;
        self.metadata_store.save(&meta)
    }

    /// Revokes a secret owned by caller.
    pub fn revoke(&self, secret_id: &SecretId, caller: &AgentId) -> Result<()> {
        let meta = self.metadata_store.load(secret_id)?;
        if meta.created_by != *caller {
            return Err(GlovesError::Forbidden);
        }
        self.agent_backend.delete(secret_id)?;
        self.metadata_store.delete(secret_id)?;
        self.audit_log.log(AuditEvent::SecretRevoked {
            secret_id: secret_id.clone(),
            by: caller.clone(),
        })?;
        Ok(())
    }

    /// Lists secrets and pending requests.
    pub fn list_all(&self) -> Result<Vec<ListItem>> {
        let mut entries = self
            .metadata_store
            .list()?
            .into_iter()
            .map(ListItem::Secret)
            .collect::<Vec<_>>();
        entries.extend(
            self.pending_store
                .load_all()?
                .into_iter()
                .map(ListItem::Pending),
        );
        Ok(entries)
    }
}
