use gloves::paths::SecretsPaths;

#[test]
fn secrets_paths_layout() {
    let root = tempfile::tempdir().unwrap();
    let paths = SecretsPaths::new(root.path());

    assert!(paths.store_dir().ends_with("store"));
    assert!(paths.metadata_dir().ends_with("meta"));
    assert!(paths.pending_file().ends_with("pending.json"));
    assert!(paths.audit_file().ends_with("audit.jsonl"));
    assert!(paths
        .default_identity_file()
        .ends_with("default-agent.agekey"));
    assert!(paths
        .default_signing_key_file()
        .ends_with("default-agent.signing.key"));
}
