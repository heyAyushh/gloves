use std::path::{Component, Path};

use chrono::Duration;

use crate::{
    error::{GlovesError, Result},
    types::SecretId,
};

pub(super) fn validate_vault_name(vault_name: &str) -> Result<()> {
    SecretId::new(vault_name)?;
    if vault_name.contains('/') {
        return Err(GlovesError::InvalidInput(
            "vault name cannot contain '/'".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_ttl_minutes(ttl: Duration, max_ttl_minutes: u64) -> Result<u64> {
    let ttl_minutes = ttl.num_minutes();
    if ttl_minutes <= 0 {
        return Err(GlovesError::InvalidInput(
            "vault ttl must be positive".to_owned(),
        ));
    }
    let ttl_minutes_u64 = ttl_minutes as u64;
    if ttl_minutes_u64 > max_ttl_minutes {
        return Err(GlovesError::InvalidInput(format!(
            "vault ttl exceeds max of {max_ttl_minutes} minutes"
        )));
    }
    Ok(ttl_minutes_u64)
}

pub(super) fn validate_requested_file_path(requested_file: &str) -> Result<()> {
    if requested_file.is_empty() {
        return Err(GlovesError::InvalidInput(
            "requested file cannot be empty".to_owned(),
        ));
    }
    let path = Path::new(requested_file);
    if path.is_absolute() {
        return Err(GlovesError::InvalidInput(
            "requested file must be relative to vault root".to_owned(),
        ));
    }
    for component in path.components() {
        if matches!(component, Component::ParentDir) {
            return Err(GlovesError::InvalidInput(
                "requested file cannot use parent traversal".to_owned(),
            ));
        }
    }
    Ok(())
}
