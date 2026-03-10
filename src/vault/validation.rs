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

#[cfg(test)]
mod tests {
    use super::{validate_requested_file_path, validate_ttl_minutes, validate_vault_name};
    use chrono::Duration;

    #[test]
    fn validate_vault_name_rejects_path_segments() {
        validate_vault_name("agent-data").unwrap();

        let error = validate_vault_name("agent/data").unwrap_err();
        assert!(error.to_string().contains("cannot contain '/'"));
    }

    #[test]
    fn validate_ttl_minutes_enforces_positive_and_max_bounds() {
        assert_eq!(validate_ttl_minutes(Duration::minutes(30), 60).unwrap(), 30);

        let non_positive = validate_ttl_minutes(Duration::zero(), 60).unwrap_err();
        assert!(non_positive.to_string().contains("must be positive"));

        let too_large = validate_ttl_minutes(Duration::minutes(61), 60).unwrap_err();
        assert!(too_large.to_string().contains("exceeds max of 60 minutes"));
    }

    #[test]
    fn validate_requested_file_path_rejects_absolute_and_parent_paths() {
        validate_requested_file_path("logs/build.txt").unwrap();

        let empty = validate_requested_file_path("").unwrap_err();
        assert!(empty.to_string().contains("cannot be empty"));

        let absolute = validate_requested_file_path("/tmp/secret.txt").unwrap_err();
        assert!(absolute
            .to_string()
            .contains("must be relative to vault root"));

        let traversal = validate_requested_file_path("../secret.txt").unwrap_err();
        assert!(traversal
            .to_string()
            .contains("cannot use parent traversal"));
    }
}
