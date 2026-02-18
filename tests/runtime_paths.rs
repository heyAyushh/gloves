use gloves::paths::SecretsPaths;

#[test]
fn secrets_paths_layout() {
    let root = tempfile::tempdir().unwrap();
    let paths = SecretsPaths::new(root.path());

    assert!(paths.store_dir().ends_with("store"));
    assert!(paths.metadata_dir().ends_with("meta"));
    assert!(paths.pending_file().ends_with("pending.json"));
    assert!(paths.audit_file().ends_with("audit.jsonl"));
    assert!(paths.vaults_dir().ends_with("vaults"));
    assert!(paths.gpg_homes_dir().ends_with("gpg"));
    assert!(paths.gpg_home("agent-main").ends_with("gpg/agent-main"));
    assert!(paths
        .vault_sessions_file()
        .ends_with("vaults/sessions.json"));
    assert!(paths.encrypted_dir().ends_with("encrypted"));
    assert!(paths.mounts_dir().ends_with("mnt"));
    assert!(paths
        .vault_config_file("agent_data")
        .ends_with("vaults/agent_data.toml"));
    assert!(paths
        .vault_cipher_dir("agent_data")
        .ends_with("encrypted/agent_data"));
    assert!(paths
        .vault_mountpoint("agent_data")
        .ends_with("mnt/agent_data"));
    assert!(paths
        .default_identity_file()
        .ends_with("default-agent.agekey"));
    assert!(paths
        .default_signing_key_file()
        .ends_with("default-agent.signing.key"));
}
