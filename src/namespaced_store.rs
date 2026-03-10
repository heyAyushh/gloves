use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path, PathBuf},
};

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{
    agent::age_crypto,
    error::{GlovesError, Result},
    fs_secure::{ensure_private_dir, write_private_file_atomic},
    types::{AgentId, SecretId},
};

const RULES_FILE_NAME: &str = ".gloves.yaml";
const RECIPIENTS_FILE_NAME: &str = ".age-recipients";
const IDENTITIES_DIR_NAME: &str = "identities";
const STORE_DIR_NAME: &str = "store";
const AUDIT_DIR_NAME: &str = "audit";
const METADATA_DIR_NAME: &str = ".gloves-meta";
const AGE_EXTENSION: &str = "age";
const TIMESTAMP_STAMP_FORMAT: &str = "%Y%m%d%H%M%S";
const REVOKED_IDENTITY_PREFIX: &str = "revoked";
const PREVIOUS_IDENTITY_PREFIX: &str = "previous";
const STAGED_IDENTITY_PREFIX: &str = "next";

#[derive(Debug, Clone)]
pub(crate) struct NamespacedStore {
    root: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SecretReadResult {
    pub(crate) name: String,
    pub(crate) value: String,
    pub(crate) length: usize,
    pub(crate) created: DateTime<Utc>,
    pub(crate) last_accessed: DateTime<Utc>,
    pub(crate) agent: String,
    pub(crate) encrypted_to: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RedactedSecretResult {
    pub(crate) name: String,
    pub(crate) exists: bool,
    pub(crate) length: usize,
    pub(crate) agent: String,
    pub(crate) encrypted_to: Vec<String>,
    pub(crate) created: DateTime<Utc>,
    pub(crate) modified: DateTime<Utc>,
    pub(crate) last_rotated: DateTime<Utc>,
    pub(crate) last_accessed: Option<DateTime<Utc>>,
    pub(crate) file_size: u64,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct IdentityCreationResult {
    pub(crate) agent: String,
    pub(crate) identity_path: PathBuf,
    pub(crate) public_key: String,
    pub(crate) recipients_file: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct UpdateKeysResult {
    pub(crate) updated: usize,
    pub(crate) unchanged: usize,
    pub(crate) skipped: usize,
    pub(crate) dry_run: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RotateIdentityResult {
    pub(crate) agent: String,
    pub(crate) identity_path: PathBuf,
    pub(crate) archived_identity_path: PathBuf,
    pub(crate) old_public_key: String,
    pub(crate) new_public_key: String,
    pub(crate) updated: usize,
    pub(crate) unchanged: usize,
    pub(crate) skipped: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecretMetadata {
    name: String,
    length: usize,
    created: DateTime<Utc>,
    modified: DateTime<Utc>,
    last_rotated: DateTime<Utc>,
    last_accessed: Option<DateTime<Utc>>,
    agent: String,
    encrypted_to: Vec<String>,
}

#[derive(Debug, Clone)]
struct FileRewrite {
    path: PathBuf,
    original_contents: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize)]
struct CreationRulesFile {
    #[serde(default, rename = "version")]
    _version: Option<u32>,
    #[serde(default)]
    creation_rules: Vec<CreationRule>,
}

#[derive(Debug, Clone, Deserialize)]
struct CreationRule {
    path_regex: String,
    #[serde(default)]
    age: Option<RecipientList>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum RecipientList {
    Csv(String),
    List(Vec<String>),
}

impl RecipientList {
    fn values(&self) -> Vec<String> {
        match self {
            Self::Csv(value) => value
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(str::to_owned)
                .collect(),
            Self::List(values) => values
                .iter()
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect(),
        }
    }
}

impl NamespacedStore {
    pub(crate) fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    pub(crate) fn init_layout(&self) -> Result<()> {
        ensure_private_dir(&self.root)?;
        ensure_private_dir(&self.identities_dir())?;
        ensure_private_dir(&self.store_dir())?;
        ensure_private_dir(&self.metadata_dir())?;
        ensure_private_dir(&self.audit_dir())?;
        Ok(())
    }

    pub(crate) fn create_identity(
        &self,
        agent: &AgentId,
        force: bool,
    ) -> Result<IdentityCreationResult> {
        self.init_layout()?;
        let identity_path = self.identity_path(agent);
        if identity_path.exists() {
            if !force {
                return Err(GlovesError::AlreadyExists);
            }
            let revoked_path = identity_path.with_extension(format!(
                "{AGE_EXTENSION}.{}-{}",
                REVOKED_IDENTITY_PREFIX,
                Utc::now().format(TIMESTAMP_STAMP_FORMAT)
            ));
            fs::rename(&identity_path, revoked_path)?;
        }

        age_crypto::generate_identity_file(&identity_path)?;
        let public_key = age_crypto::recipient_from_identity_file(&identity_path)?;
        let namespace = PathBuf::from("agents").join(agent.as_str());
        let recipients_file = self.namespace_recipients_file(&namespace);
        self.write_namespace_recipients(&namespace, std::slice::from_ref(&public_key), true)?;

        Ok(IdentityCreationResult {
            agent: agent.as_str().to_owned(),
            identity_path,
            public_key,
            recipients_file,
        })
    }

    pub(crate) fn set_secret(
        &self,
        secret_path: &SecretId,
        _agent: &AgentId,
        value: &[u8],
    ) -> Result<RedactedSecretResult> {
        self.init_layout()?;
        let namespace = namespace_for_secret_path(secret_path.as_str())?;
        let recipients = self.resolve_recipients(secret_path.as_str(), &namespace)?;
        if recipients.is_empty() {
            return Err(GlovesError::InvalidInput(format!(
                "no recipients resolved for {}",
                secret_path.as_str()
            )));
        }
        self.write_namespace_recipients(&namespace, &recipients, false)?;

        let ciphertext_path = self.secret_ciphertext_path(secret_path.as_str());
        let metadata_path = self.secret_metadata_path(secret_path.as_str());
        let ciphertext = age_crypto::encrypt_for_recipients(value, &recipients)?;
        write_private_file_atomic(&ciphertext_path, &ciphertext)?;
        let now = Utc::now();
        let metadata = SecretMetadata {
            name: secret_path.as_str().to_owned(),
            length: value.len(),
            created: metadata_path
                .exists()
                .then(|| {
                    self.read_metadata(secret_path.as_str())
                        .ok()
                        .map(|entry| entry.created)
                })
                .flatten()
                .unwrap_or(now),
            modified: now,
            last_rotated: now,
            last_accessed: None,
            agent: scope_agent(secret_path.as_str()),
            encrypted_to: recipients,
        };
        self.write_metadata(secret_path.as_str(), &metadata)?;
        self.show_secret(secret_path)
    }

    pub(crate) fn get_secret(
        &self,
        secret_path: &SecretId,
        agent: &AgentId,
    ) -> Result<SecretReadResult> {
        self.init_layout()?;
        let mut metadata = self.read_metadata(secret_path.as_str())?;
        let identity_path = self.identity_path(agent);
        if !identity_path.exists() {
            return Err(GlovesError::InvalidInput(format!(
                "identity file not found: {}",
                identity_path.display()
            )));
        }
        let recipient = age_crypto::recipient_from_identity_file(&identity_path)?;
        if !metadata
            .encrypted_to
            .iter()
            .any(|entry| entry == &recipient)
        {
            return Err(GlovesError::Unauthorized);
        }

        let plaintext = age_crypto::decrypt_file(
            &self.secret_ciphertext_path(secret_path.as_str()),
            &identity_path,
        )?;
        let last_accessed = Utc::now();
        metadata.last_accessed = Some(last_accessed);
        self.write_metadata(secret_path.as_str(), &metadata)?;
        let value = String::from_utf8(plaintext)?;

        Ok(SecretReadResult {
            name: metadata.name,
            length: metadata.length,
            value,
            created: metadata.created,
            last_accessed,
            agent: metadata.agent,
            encrypted_to: metadata.encrypted_to,
        })
    }

    pub(crate) fn show_secret(&self, secret_path: &SecretId) -> Result<RedactedSecretResult> {
        let metadata = self.read_metadata(secret_path.as_str())?;
        let ciphertext_path = self.secret_ciphertext_path(secret_path.as_str());
        let file_size = fs::metadata(ciphertext_path)?.len();
        Ok(RedactedSecretResult {
            name: metadata.name,
            exists: true,
            length: metadata.length,
            agent: metadata.agent,
            encrypted_to: metadata.encrypted_to,
            created: metadata.created,
            modified: metadata.modified,
            last_rotated: metadata.last_rotated,
            last_accessed: metadata.last_accessed,
            file_size,
        })
    }

    pub(crate) fn update_keys(
        &self,
        prefix: Option<&str>,
        identity_override: Option<&Path>,
        dry_run: bool,
    ) -> Result<UpdateKeysResult> {
        self.init_layout()?;
        let secret_paths = self.list_secret_paths(prefix)?;
        let mut updated = 0;
        let mut unchanged = 0;
        let mut skipped = 0;

        for secret_path in secret_paths {
            let secret_id = SecretId::new(&secret_path)?;
            let namespace = namespace_for_secret_path(secret_id.as_str())?;
            let next_recipients = match self.resolve_recipients(secret_id.as_str(), &namespace) {
                Ok(recipients) if !recipients.is_empty() => recipients,
                Ok(_) | Err(GlovesError::NotFound) => {
                    skipped += 1;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let mut metadata = self.read_metadata(secret_id.as_str())?;
            if metadata.encrypted_to == next_recipients {
                unchanged += 1;
                continue;
            }
            if dry_run {
                updated += 1;
                continue;
            }

            let identity_path = self.resolve_identity_for_update(
                identity_override,
                &metadata.encrypted_to,
                secret_id.as_str(),
            )?;
            let plaintext = age_crypto::decrypt_file(
                &self.secret_ciphertext_path(secret_id.as_str()),
                &identity_path,
            )?;
            let ciphertext = age_crypto::encrypt_for_recipients(&plaintext, &next_recipients)?;
            write_private_file_atomic(
                &self.secret_ciphertext_path(secret_id.as_str()),
                &ciphertext,
            )?;
            self.write_namespace_recipients(&namespace, &next_recipients, true)?;
            let now = Utc::now();
            metadata.modified = now;
            metadata.last_rotated = now;
            metadata.encrypted_to = next_recipients;
            self.write_metadata(secret_id.as_str(), &metadata)?;
            updated += 1;
        }

        Ok(UpdateKeysResult {
            updated,
            unchanged,
            skipped,
            dry_run,
        })
    }

    pub(crate) fn rotate_identity(
        &self,
        agent: &AgentId,
        keep_old: bool,
    ) -> Result<RotateIdentityResult> {
        self.init_layout()?;
        let identity_path = self.identity_path(agent);
        if !identity_path.exists() {
            return Err(GlovesError::InvalidInput(format!(
                "identity file not found: {}",
                identity_path.display()
            )));
        }

        let old_public_key = age_crypto::recipient_from_identity_file(&identity_path)?;
        let staged_identity_path = self.staged_identity_path(agent);
        age_crypto::generate_identity_file(&staged_identity_path)?;
        let new_public_key = age_crypto::recipient_from_identity_file(&staged_identity_path)?;
        let rewrites = self.rewrite_recipient_references(&old_public_key, &new_public_key)?;

        let update_result = match self.update_keys(None, Some(identity_path.as_path()), false) {
            Ok(result) => result,
            Err(error) => {
                let _ = self.restore_file_rewrites(&rewrites);
                let _ = fs::remove_file(&staged_identity_path);
                return Err(error);
            }
        };

        let archived_identity_path = self.archived_identity_path(agent, keep_old);
        fs::rename(&identity_path, &archived_identity_path)?;
        fs::rename(&staged_identity_path, &identity_path)?;

        Ok(RotateIdentityResult {
            agent: agent.as_str().to_owned(),
            identity_path,
            archived_identity_path,
            old_public_key,
            new_public_key,
            updated: update_result.updated,
            unchanged: update_result.unchanged,
            skipped: update_result.skipped,
        })
    }

    fn resolve_identity_for_update(
        &self,
        identity_override: Option<&Path>,
        current_recipients: &[String],
        secret_path: &str,
    ) -> Result<PathBuf> {
        if let Some(path) = identity_override {
            let recipient = age_crypto::recipient_from_identity_file(path)?;
            if current_recipients.iter().any(|entry| entry == &recipient) {
                return Ok(path.to_path_buf());
            }
            return Err(GlovesError::Unauthorized);
        }

        let identities_dir = self.identities_dir();
        if !identities_dir.exists() {
            return Err(GlovesError::InvalidInput(format!(
                "no identity can decrypt {secret_path}"
            )));
        }

        for entry in fs::read_dir(identities_dir)? {
            let path = entry?.path();
            if path.extension().and_then(|value| value.to_str()) != Some(AGE_EXTENSION) {
                continue;
            }
            let recipient = age_crypto::recipient_from_identity_file(&path)?;
            if current_recipients.iter().any(|entry| entry == &recipient) {
                return Ok(path);
            }
        }

        Err(GlovesError::InvalidInput(format!(
            "no identity can decrypt {secret_path}"
        )))
    }

    fn resolve_recipients(&self, secret_path: &str, namespace: &Path) -> Result<Vec<String>> {
        let rules = self.load_creation_rules()?;
        let explicit_recipients = rules
            .creation_rules
            .into_iter()
            .find_map(|rule| {
                let regex = Regex::new(&rule.path_regex).ok()?;
                regex
                    .is_match(secret_path)
                    .then(|| rule.age.map(|value| value.values()).unwrap_or_default())
            })
            .ok_or_else(|| {
                GlovesError::InvalidInput(format!(
                    "no matching creation rule for path {}",
                    secret_path
                ))
            })?;
        let namespace_recipients = self.read_namespace_recipients(namespace)?;
        let recipients = explicit_recipients
            .into_iter()
            .chain(namespace_recipients)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        Ok(recipients)
    }

    fn load_creation_rules(&self) -> Result<CreationRulesFile> {
        let rules_path = self.store_dir().join(RULES_FILE_NAME);
        let raw = fs::read_to_string(&rules_path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                GlovesError::InvalidInput(format!(
                    "creation rules not found: {}",
                    rules_path.display()
                ))
            } else {
                GlovesError::Io(error)
            }
        })?;
        serde_yaml::from_str(&raw)
            .map_err(|error| GlovesError::InvalidInput(format!("invalid creation rules: {error}")))
    }

    fn write_namespace_recipients(
        &self,
        namespace: &Path,
        recipients: &[String],
        replace: bool,
    ) -> Result<()> {
        let file_path = self.namespace_recipients_file(namespace);
        let existing = if replace {
            Vec::new()
        } else {
            self.read_namespace_recipients(namespace)
                .unwrap_or_default()
        };
        let merged = existing
            .into_iter()
            .chain(recipients.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let contents = if merged.is_empty() {
            String::new()
        } else {
            format!("{}\n", merged.join("\n"))
        };
        write_private_file_atomic(&file_path, contents.as_bytes())
    }

    fn read_namespace_recipients(&self, namespace: &Path) -> Result<Vec<String>> {
        let file_path = self.namespace_recipients_file(namespace);
        let raw = fs::read_to_string(file_path).unwrap_or_default();
        Ok(raw
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(str::to_owned)
            .collect())
    }

    fn read_metadata(&self, secret_path: &str) -> Result<SecretMetadata> {
        let path = self.secret_metadata_path(secret_path);
        let bytes = fs::read(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                GlovesError::NotFound
            } else {
                GlovesError::Io(error)
            }
        })?;
        serde_json::from_slice(&bytes).map_err(GlovesError::from)
    }

    fn write_metadata(&self, secret_path: &str, metadata: &SecretMetadata) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(metadata)?;
        write_private_file_atomic(&self.secret_metadata_path(secret_path), &bytes)
    }

    fn list_secret_paths(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        let mut pending = vec![self.store_dir()];
        let metadata_root = self.metadata_dir();
        let normalized_prefix = prefix.map(|value| value.trim_matches('/').to_owned());
        let mut secrets = Vec::new();

        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(&directory)? {
                let path = entry?.path();
                if path == metadata_root {
                    continue;
                }
                if path.is_dir() {
                    pending.push(path);
                    continue;
                }
                if path.extension().and_then(|value| value.to_str()) != Some(AGE_EXTENSION) {
                    continue;
                }
                let relative = path
                    .strip_prefix(self.store_dir())
                    .map_err(|error| GlovesError::InvalidInput(error.to_string()))?;
                let mut secret_path = relative.to_path_buf();
                secret_path.set_extension("");
                let secret_name = secret_path.to_string_lossy().replace('\\', "/");
                if normalized_prefix
                    .as_ref()
                    .is_some_and(|prefix| !secret_name.starts_with(prefix))
                {
                    continue;
                }
                secrets.push(secret_name);
            }
        }

        secrets.sort();
        Ok(secrets)
    }

    fn rewrite_recipient_references(
        &self,
        current_recipient: &str,
        next_recipient: &str,
    ) -> Result<Vec<FileRewrite>> {
        let mut rewrites = Vec::new();

        for file_path in self.recipient_reference_files()? {
            let original_contents = fs::read(&file_path)?;
            let original_text = String::from_utf8(original_contents.clone())?;
            let updated_text = if file_path.file_name().and_then(|value| value.to_str())
                == Some(RECIPIENTS_FILE_NAME)
            {
                replace_recipient_lines(&original_text, current_recipient, next_recipient)
            } else {
                original_text.replace(current_recipient, next_recipient)
            };

            if updated_text == original_text {
                continue;
            }

            write_private_file_atomic(&file_path, updated_text.as_bytes())?;
            rewrites.push(FileRewrite {
                path: file_path,
                original_contents,
            });
        }

        Ok(rewrites)
    }

    fn restore_file_rewrites(&self, rewrites: &[FileRewrite]) -> Result<()> {
        for rewrite in rewrites {
            write_private_file_atomic(&rewrite.path, &rewrite.original_contents)?;
        }
        Ok(())
    }

    fn recipient_reference_files(&self) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        let rules_path = self.store_dir().join(RULES_FILE_NAME);
        if rules_path.exists() {
            files.push(rules_path);
        }

        let mut pending = vec![self.store_dir()];
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(&directory)? {
                let path = entry?.path();
                if path == self.metadata_dir() {
                    continue;
                }
                if path.is_dir() {
                    pending.push(path);
                    continue;
                }
                if path.file_name().and_then(|value| value.to_str()) == Some(RECIPIENTS_FILE_NAME) {
                    files.push(path);
                }
            }
        }

        files.sort();
        Ok(files)
    }

    fn identity_path(&self, agent: &AgentId) -> PathBuf {
        self.identities_dir()
            .join(format!("{}.{}", agent.as_str(), AGE_EXTENSION))
    }

    fn archived_identity_path(&self, agent: &AgentId, keep_old: bool) -> PathBuf {
        let archive_prefix = if keep_old {
            PREVIOUS_IDENTITY_PREFIX
        } else {
            REVOKED_IDENTITY_PREFIX
        };
        self.identities_dir().join(format!(
            "{}.{}.{}-{}",
            agent.as_str(),
            AGE_EXTENSION,
            archive_prefix,
            Utc::now().format(TIMESTAMP_STAMP_FORMAT)
        ))
    }

    fn staged_identity_path(&self, agent: &AgentId) -> PathBuf {
        self.identities_dir().join(format!(
            "{}.{}.{}-{}",
            agent.as_str(),
            AGE_EXTENSION,
            STAGED_IDENTITY_PREFIX,
            Utc::now().format(TIMESTAMP_STAMP_FORMAT)
        ))
    }

    fn secret_ciphertext_path(&self, secret_path: &str) -> PathBuf {
        self.store_dir()
            .join(format!("{secret_path}.{}", AGE_EXTENSION))
    }

    fn secret_metadata_path(&self, secret_path: &str) -> PathBuf {
        self.metadata_dir().join(format!("{secret_path}.json"))
    }

    fn namespace_recipients_file(&self, namespace: &Path) -> PathBuf {
        self.store_dir().join(namespace).join(RECIPIENTS_FILE_NAME)
    }

    fn identities_dir(&self) -> PathBuf {
        self.root.join(IDENTITIES_DIR_NAME)
    }

    fn store_dir(&self) -> PathBuf {
        self.root.join(STORE_DIR_NAME)
    }

    fn metadata_dir(&self) -> PathBuf {
        self.store_dir().join(METADATA_DIR_NAME)
    }

    fn audit_dir(&self) -> PathBuf {
        self.root.join(AUDIT_DIR_NAME)
    }
}

fn namespace_for_secret_path(secret_path: &str) -> Result<PathBuf> {
    let relative_path = validated_relative_path(secret_path)?;
    let mut components = relative_path.components();
    let first = match components.next() {
        Some(Component::Normal(value)) => value.to_string_lossy().to_string(),
        _ => {
            return Err(GlovesError::Validation(
                crate::error::ValidationError::InvalidName,
            ))
        }
    };
    if first == "agents" {
        let second = match components.next() {
            Some(Component::Normal(value)) => value.to_string_lossy().to_string(),
            _ => {
                return Err(GlovesError::InvalidInput(format!(
                    "agent namespace is missing in {secret_path}"
                )))
            }
        };
        return Ok(PathBuf::from(first).join(second));
    }
    Ok(PathBuf::from(first))
}

fn scope_agent(secret_path: &str) -> String {
    let relative_path = Path::new(secret_path);
    let parts = relative_path
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().to_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    if parts.first().map(|entry| entry.as_str()) == Some("agents") && parts.len() >= 2 {
        return parts[1].clone();
    }
    parts
        .first()
        .cloned()
        .unwrap_or_else(|| "unknown".to_owned())
}

fn validated_relative_path(path: &str) -> Result<PathBuf> {
    let secret_id = SecretId::new(path)?;
    let relative_path = PathBuf::from(secret_id.as_str());
    if relative_path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(GlovesError::Validation(
            crate::error::ValidationError::PathTraversal,
        ));
    }
    Ok(relative_path)
}

fn replace_recipient_lines(
    contents: &str,
    current_recipient: &str,
    next_recipient: &str,
) -> String {
    let replaced_lines = contents
        .lines()
        .map(|line| {
            if line.trim() == current_recipient {
                next_recipient.to_owned()
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>();
    if contents.ends_with('\n') {
        format!("{}\n", replaced_lines.join("\n"))
    } else {
        replaced_lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        namespace_for_secret_path, replace_recipient_lines, scope_agent, validated_relative_path,
        CreationRule, CreationRulesFile, NamespacedStore, RecipientList, RULES_FILE_NAME,
    };
    use crate::{agent::age_crypto, error::GlovesError, types::AgentId};
    use std::{fs, path::Path, path::PathBuf};

    #[test]
    fn recipient_list_accepts_csv_and_array_values() {
        let csv = RecipientList::Csv("age1a,age1b".to_owned());
        assert_eq!(csv.values(), vec!["age1a".to_owned(), "age1b".to_owned()]);

        let list = RecipientList::List(vec!["age1a".to_owned(), "age1b".to_owned()]);
        assert_eq!(list.values(), vec!["age1a".to_owned(), "age1b".to_owned()]);
    }

    #[test]
    fn scope_agent_uses_agent_namespace() {
        assert_eq!(scope_agent("agents/devy/api-keys/anthropic"), "devy");
        assert_eq!(scope_agent("shared/database-url"), "shared");
    }

    #[test]
    fn creation_rules_deserialize_without_explicit_age_values() {
        let rules: CreationRulesFile =
            serde_yaml::from_str("version: 1\ncreation_rules:\n  - path_regex: ^agents/devy/.*$\n")
                .unwrap();
        assert_eq!(rules._version, Some(1));
        assert_eq!(rules.creation_rules.len(), 1);
        assert!(matches!(
            rules.creation_rules[0],
            CreationRule {
                age: None,
                path_regex: _
            }
        ));
    }

    #[test]
    fn replace_recipient_lines_updates_only_matching_keys() {
        let contents = "# main\nage1main\nage1devy\n";
        let updated = replace_recipient_lines(contents, "age1devy", "age1next");
        assert_eq!(updated, "# main\nage1main\nage1next\n");
    }

    #[test]
    fn namespace_helpers_cover_agents_shared_and_invalid_paths() {
        assert_eq!(
            namespace_for_secret_path("agents/devy/api-keys/anthropic").unwrap(),
            PathBuf::from("agents").join("devy")
        );
        assert_eq!(
            namespace_for_secret_path("shared/database-url").unwrap(),
            PathBuf::from("shared")
        );
        assert_eq!(
            validated_relative_path("shared/database-url").unwrap(),
            PathBuf::from("shared/database-url")
        );

        let missing_agent = namespace_for_secret_path("agents").unwrap_err();
        assert!(missing_agent
            .to_string()
            .contains("agent namespace is missing"));

        let traversal = validated_relative_path("../escape").unwrap_err();
        assert!(matches!(traversal, GlovesError::Validation(_)));
    }

    #[test]
    fn init_layout_and_create_identity_cover_force_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let store = NamespacedStore::new(temp.path());
        store.init_layout().unwrap();
        assert!(temp.path().join("identities").is_dir());
        assert!(temp.path().join("store").is_dir());
        assert!(temp.path().join("store/.gloves-meta").is_dir());
        assert!(temp.path().join("audit").is_dir());

        let agent = AgentId::new("devy").unwrap();
        let first = store.create_identity(&agent, false).unwrap();
        let duplicate = store.create_identity(&agent, false).unwrap_err();
        assert!(matches!(duplicate, GlovesError::AlreadyExists));

        let second = store.create_identity(&agent, true).unwrap();
        assert_ne!(first.public_key, second.public_key);
        let recipients = fs::read_to_string(second.recipients_file).unwrap();
        assert_eq!(recipients.trim(), second.public_key);
        assert!(fs::read_dir(temp.path().join("identities"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
            .any(|name| name.starts_with("devy.age.revoked-")));
    }

    #[test]
    fn resolve_recipients_merges_rules_with_namespace_entries_and_reports_missing_rules() {
        let temp = tempfile::tempdir().unwrap();
        let store = NamespacedStore::new(temp.path());
        store.init_layout().unwrap();

        let missing_rules = store
            .resolve_recipients("shared/database-url", Path::new("shared"))
            .unwrap_err();
        assert!(missing_rules
            .to_string()
            .contains("creation rules not found"));

        fs::write(
            temp.path().join("store").join(RULES_FILE_NAME),
            "version: 1\ncreation_rules:\n  - path_regex: ^shared/.*$\n    age:\n      - age1rule\n      - age1shared\n",
        )
        .unwrap();
        fs::create_dir_all(temp.path().join("store/shared")).unwrap();
        fs::write(
            temp.path().join("store/shared/.age-recipients"),
            "# comment\nage1namespace\nage1shared\n",
        )
        .unwrap();

        let recipients = store
            .resolve_recipients("shared/database-url", Path::new("shared"))
            .unwrap();
        assert_eq!(
            recipients,
            vec![
                "age1namespace".to_owned(),
                "age1rule".to_owned(),
                "age1shared".to_owned(),
            ]
        );

        let no_match = store
            .resolve_recipients("agents/devy/api-keys/anthropic", Path::new("agents/devy"))
            .unwrap_err();
        assert!(no_match.to_string().contains("no matching creation rule"));
    }

    #[test]
    fn list_secret_paths_skips_metadata_and_filters_prefix() {
        let temp = tempfile::tempdir().unwrap();
        let store = NamespacedStore::new(temp.path());
        store.init_layout().unwrap();
        fs::create_dir_all(temp.path().join("store/shared")).unwrap();
        fs::create_dir_all(temp.path().join("store/agents/devy")).unwrap();
        fs::create_dir_all(temp.path().join("store/.gloves-meta/shared")).unwrap();
        fs::write(
            temp.path().join("store/shared/database-url.age"),
            b"ciphertext",
        )
        .unwrap();
        fs::write(
            temp.path().join("store/agents/devy/openai.age"),
            b"ciphertext",
        )
        .unwrap();
        fs::write(
            temp.path()
                .join("store/.gloves-meta/shared/database-url.json"),
            b"{}",
        )
        .unwrap();

        let all = store.list_secret_paths(None).unwrap();
        assert_eq!(
            all,
            vec![
                "agents/devy/openai".to_owned(),
                "shared/database-url".to_owned()
            ]
        );
        let filtered = store.list_secret_paths(Some("agents/devy")).unwrap();
        assert_eq!(filtered, vec!["agents/devy/openai".to_owned()]);
    }

    #[test]
    fn rewrite_and_restore_recipient_references_round_trip() {
        let temp = tempfile::tempdir().unwrap();
        let store = NamespacedStore::new(temp.path());
        store.init_layout().unwrap();
        let rules_path = temp.path().join("store").join(RULES_FILE_NAME);
        let recipients_path = temp.path().join("store/shared/.age-recipients");
        fs::create_dir_all(recipients_path.parent().unwrap()).unwrap();
        fs::write(
            &rules_path,
            "version: 1\ncreation_rules:\n  - path_regex: ^shared/.*$\n    age:\n      - age1old\n",
        )
        .unwrap();
        fs::write(&recipients_path, "age1old\nage1keep\n").unwrap();

        let rewrites = store
            .rewrite_recipient_references("age1old", "age1new")
            .unwrap();
        assert_eq!(rewrites.len(), 2);
        assert!(fs::read_to_string(&rules_path).unwrap().contains("age1new"));
        assert!(fs::read_to_string(&recipients_path)
            .unwrap()
            .contains("age1new"));

        store.restore_file_rewrites(&rewrites).unwrap();
        assert!(fs::read_to_string(&rules_path).unwrap().contains("age1old"));
        assert!(fs::read_to_string(&recipients_path)
            .unwrap()
            .contains("age1old"));
    }

    #[test]
    fn resolve_identity_for_update_uses_override_and_existing_identity_search() {
        let temp = tempfile::tempdir().unwrap();
        let store = NamespacedStore::new(temp.path());
        store.init_layout().unwrap();
        let agent = AgentId::new("devy").unwrap();
        let identity = store.create_identity(&agent, false).unwrap();
        let current_recipients = vec![identity.public_key.clone()];

        let override_path = store
            .resolve_identity_for_update(
                Some(identity.identity_path.as_path()),
                &current_recipients,
                "agents/devy/api-keys/anthropic",
            )
            .unwrap();
        assert_eq!(override_path, identity.identity_path);

        let auto_resolved = store
            .resolve_identity_for_update(
                None,
                &current_recipients,
                "agents/devy/api-keys/anthropic",
            )
            .unwrap();
        assert!(auto_resolved.ends_with("devy.age"));

        let other_identity = temp.path().join("identities/other.age");
        age_crypto::generate_identity_file(&other_identity).unwrap();
        let unauthorized = store
            .resolve_identity_for_update(
                Some(other_identity.as_path()),
                &current_recipients,
                "agents/devy/api-keys/anthropic",
            )
            .unwrap_err();
        assert!(matches!(unauthorized, GlovesError::Unauthorized));
    }
}
