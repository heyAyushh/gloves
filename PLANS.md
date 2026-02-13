# Gloves Implementation and Test Plan

This plan is organized by Rust module boundaries and production-quality practices, not by implementation phases.

## Engineering Principles

- Module-first design: keep related types and behavior together.
- Test-first behavior changes: add failing tests before logic changes.
- Strong error contracts: use explicit `Result<T, GlovesError>` mapping.
- Security defaults: private file permissions, atomic writes, integrity checks.
- Deterministic CI gates: formatting, linting, tests, docs, publish dry-run.

## Domain: Types and Validation (`src/types.rs`, `src/error.rs`)

### Required behavior tests

- `secret_id_valid`
- `secret_id_empty`
- `secret_id_too_long`
- `secret_id_traversal`
- `secret_id_leading_slash`
- `secret_id_special_chars`
- `owner_serde`
- `secret_id_display`
- `agent_id_validation_and_display`
- `request_status_serde_all_variants`
- `secret_value_expose`
- `secret_value_no_debug` (`trybuild`)
- `secret_meta_roundtrip`
- `pending_request_roundtrip`

## Domain: Key Derivation (`src/agent/keys.rs`)

### Required behavior tests

- `derive_deterministic`
- `derive_different_salt`
- `derive_different_agent`
- `derive_different_vm`
- `salt_init_creates_file`
- `salt_init_idempotent`
- `salt_invalid_length_fails`
- `salt_permissions_0600`

## Domain: Agent Cryptography Backend (`src/agent/backend.rs`)

### Required behavior tests

- `encrypt_decrypt_roundtrip`
- `decrypt_wrong_key_fails`
- `decrypt_unsupported_header_fails`
- `multi_recipient_both_decrypt`
- `multi_recipient_outsider_fails`
- `encrypt_creates_age_file`
- `encrypt_no_overwrite`
- `encrypt_without_recipients_fails`
- `grant_adds_recipient`
- `ciphertext_checksum_changes_after_grant`
- `file_permissions_0600`
- `delete_missing_is_ok`
- `parse_identity_roundtrip`
- `parse_identity_invalid`

## Domain: Metadata and Registry (`src/agent/meta.rs`, `src/registry.rs`)

### Required behavior tests

- `meta_save_load_roundtrip`
- `meta_delete_missing_is_ok`
- `meta_list_ignores_non_json_files`
- `registry_register_lookup`
- `registry_reject_duplicate`
- `registry_first_agent_bootstrap`
- `registry_second_agent_with_valid_voucher_succeeds`
- `registry_voucher_required`
- `registry_rejects_unknown_voucher`
- `registry_hmac_valid`
- `registry_hmac_tampered`
- `registry_file_permissions_0600`

## Domain: Human Backend and Pending Access (`src/human/backend.rs`, `src/human/pending.rs`)

### Required behavior tests

- `get_parses_stdout`
- `get_not_found`
- `get_gpg_denied`
- `get_unknown_error_maps_crypto`
- `exists_true`
- `exists_false`
- `system_pass_executor_runs_custom_binary`
- `system_pass_executor_utf8_error`
- `system_pass_executor_default_constructs`
- `human_backend_default_constructs`
- `pending_create_persist`
- `pending_auto_expire`
- `pending_approve`
- `pending_deny`
- `pending_approve_not_found`
- `pending_deny_not_found`
- `pending_is_fulfilled_false_without_match`
- `pending_signature_tamper_fails_load`

## Domain: Secrets Router (`src/manager.rs`)

### Required behavior tests

- `set_agent_secret`
- `set_human_forbidden`
- `set_rolls_back_ciphertext_when_metadata_save_fails`
- `set_rolls_back_metadata_and_ciphertext_when_audit_fails`
- `get_routes_agent`
- `get_agent_without_identity_is_unauthorized`
- `get_routes_human`
- `get_human_without_approval_forbidden`
- `get_expired`
- `get_unauthorized`
- `get_tampered_ciphertext_fails_integrity`
- `get_with_empty_checksum_allows_legacy_metadata`
- `get_increments_access`
- `request_creates_pending`
- `grant_agent_ok`
- `grant_human_forbidden`
- `grant_by_non_creator_forbidden`
- `revoke_by_creator`
- `revoke_by_noncreator`
- `list_all`
- `approve_and_deny_request_wrappers`

## Domain: Audit and Retention (`src/audit.rs`, `src/reaper.rs`)

### Required behavior tests

- `log_writes_jsonl`
- `log_appends`
- `all_events_serialize`
- `log_file_permissions`
- `log_includes_timestamp`
- `reaps_expired`
- `keeps_valid`
- `logs_expiry_event`
- `handles_empty_dir`
- `secure_delete_zeroes`
- `secure_delete_missing_file_is_ok`

## Domain: CLI and Runtime Paths (`src/cli/mod.rs`, `src/main.rs`, `src/paths.rs`, `src/fs_secure.rs`)

### Required behavior tests

- `cli_init`
- `cli_set_generate`
- `cli_set_duplicate_secret_fails`
- `cli_set_then_get_roundtrip`
- `cli_set_from_stdin`
- `cli_set_empty_stdin_rejected`
- `cli_set_requires_input_source`
- `cli_set_rejects_generate_and_value`
- `cli_set_rejects_empty_value`
- `cli_get_redacted`
- `cli_get_raw_tty_warning`
- `cli_request`
- `cli_request_twice_uses_existing_signing_key`
- `cli_request_fails_when_pending_json_is_unreadable`
- `cli_approve_request`
- `cli_approve_invalid_uuid_fails`
- `cli_deny_request`
- `cli_list`
- `cli_revoke`
- `cli_status`
- `cli_status_defaults_to_fulfilled`
- `cli_verify`
- `cli_verify_fails_on_invalid_metadata_file`
- `secrets_paths_layout`
- `create_private_file_if_missing_does_not_overwrite`
- `write_private_file_atomic_overwrites`
- `ensure_private_dir_creates_directory`
- `private_permissions_are_restricted`

## Domain: Vaults and Encrypted Volumes (`src/vault/**`, `src/reaper.rs`, `src/cli/mod.rs`)

### Required behavior tests

- `vault_config_roundtrip`
- `vault_session_roundtrip`
- `vault_session_expired`
- `vault_session_active`
- `init_creates_cipher_dir`
- `mount_passes_extpass_and_idle`
- `unmount_calls_fusermount`
- `is_mounted_false`
- `vault_init_agent`
- `vault_init_human`
- `vault_mount_creates_session`
- `vault_mount_idempotent`
- `vault_unmount_removes_session`
- `vault_status_shows_remaining`
- `vault_list_shows_all`
- `vault_ask_file_prompt_requires_trusted_agent_access`
- `vault_ask_file_prompt_fails_without_access`
- `vault_ask_file_prompt_rejects_traversal`
- `reaper_unmounts_expired_session`
- `reaper_ignores_active_session`
- `reaper_logs_vault_expired`
- `reaper_handles_already_unmounted`
- `cli_vault_init`
- `cli_vault_mount`
- `cli_vault_unmount`
- `cli_vault_status`
- `cli_vault_list`
- `cli_vault_ask_file`
- `cli_vault_ask_file_requires_access`

## Domain: Bootstrap Config (`.gloves.toml`, CLI config resolution)

### Required behavior tests

- `config_roundtrip_v1`
- `config_discovery_prefers_flag`
- `config_discovery_prefers_env_over_discovery`
- `config_discovery_walks_parent_dirs`
- `config_validate_rejects_unknown_agent_path_alias`
- `config_validate_rejects_duplicate_private_alias`
- `config_validate_rejects_invalid_operation`
- `config_resolve_relative_paths_against_file_dir`
- `config_resolve_home_expansion`
- `config_validate_rejects_group_world_writable_file`
- `config_validate_accepts_private_modes`
- `cli_bootstrap_uses_discovered_gloves_toml`
- `cli_bootstrap_uses_explicit_config_path`
- `cli_bootstrap_no_config_keeps_existing_defaults`
- `cli_config_validate_success`
- `cli_config_validate_failure_invalid_alias`
- `cli_access_paths_json`
- `cli_access_paths_unknown_agent_fails`

## Release Gates

Run all gates before merging or publishing:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo llvm-cov --all-features --workspace --summary-only
cargo doc --no-deps
cargo publish --dry-run --locked
```

## Coverage Target

- Region coverage target: `>= 90%`
- Function coverage target: `>= 95%`
- Line coverage target: `>= 99%`
