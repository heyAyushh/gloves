use gloves::SecretRef;

#[test]
fn secret_ref_roundtrips_public_api() {
    let secret_ref: SecretRef = "gloves://agents/devy/api-keys/openai".parse().unwrap();

    assert_eq!(
        secret_ref.secret_id().as_str(),
        "agents/devy/api-keys/openai"
    );
    assert_eq!(
        secret_ref.to_string(),
        "gloves://agents/devy/api-keys/openai"
    );
}

#[test]
fn secret_ref_serializes_as_string_contract() {
    let secret_ref: SecretRef = "gloves://shared/database-url".parse().unwrap();
    let encoded = serde_json::to_string(&secret_ref).unwrap();
    let decoded: SecretRef = serde_json::from_str(&encoded).unwrap();

    assert_eq!(encoded, "\"gloves://shared/database-url\"");
    assert_eq!(decoded, secret_ref);
}

#[test]
fn secret_ref_validation_rejects_invalid_inputs() {
    assert!("gloves://agents/devy/../api-key"
        .parse::<SecretRef>()
        .is_err());
    assert!("gloves:///agents/devy/api-key"
        .parse::<SecretRef>()
        .is_err());
    assert!("agents/devy/api-key".parse::<SecretRef>().is_err());
}
