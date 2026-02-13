use chrono::Utc;

use crate::{
    audit::{AuditEvent, AuditLog},
    error::Result,
    fs_secure::{create_private_file_if_missing, ensure_private_dir},
    paths::SecretsPaths,
};

use super::{
    gocryptfs::FsEncryptionDriver,
    session::{load_sessions, save_sessions},
};

pub(crate) fn reap_expired_sessions<D>(
    driver: &D,
    paths: &SecretsPaths,
    audit_log: &AuditLog,
) -> Result<()>
where
    D: FsEncryptionDriver,
{
    ensure_private_dir(paths.root())?;
    ensure_private_dir(&paths.vaults_dir())?;
    create_private_file_if_missing(&paths.vault_sessions_file(), b"[]")?;

    let now = Utc::now();
    let mut retained = Vec::new();
    for session in load_sessions(&paths.vault_sessions_file())? {
        if session.is_expired(now) {
            if driver.is_mounted(&session.mountpoint)? {
                driver.unmount(&session.mountpoint)?;
                audit_log.log(AuditEvent::VaultUnmounted {
                    vault: session.vault_name.clone(),
                    reason: "session_expired".to_owned(),
                    agent: session.mounted_by.clone(),
                })?;
            }
            audit_log.log(AuditEvent::VaultSessionExpired {
                vault: session.vault_name,
            })?;
            continue;
        }
        retained.push(session);
    }
    save_sessions(&paths.vault_sessions_file(), &retained)?;
    Ok(())
}
