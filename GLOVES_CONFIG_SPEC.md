# Gloves CLI Bootstrap Config Spec (`.gloves.toml`)

Status: Implemented (`v0.2.x`)
Target release: `v0.2.x`
Owner: `gloves` CLI/runtime

## Implementation Status

Implemented now:

- `src/config.rs` parser and validator for `.gloves.toml`
- Config precedence and discovery resolver (`flag` / `env` / `discovered` / `none`)
- Strict validation for schema, agent policies, daemon/default values, and path literals
- Unix permission checks for config files, including symlink rejection
- Agent path visibility resolver API (`GlovesConfig::agent_paths`)
- Integration test suite: `tests/config_parser.rs`
- CLI flags: `--config`, `--no-config`, `--vault-mode`
- CLI commands: `gloves config validate`, `gloves access paths`, `gloves audit`
- Runtime wiring for effective root/defaults (`set`, `request`, `daemon`, `vault`)
- Vault mode enforcement (`auto` / `required` / `disabled`) with dependency checks
- Config-driven secret pipe URL policies under `[secrets.pipe.commands.<command>]`
- CLI integration coverage for bootstrap/config/access/vault mode paths

Pending from this spec:

- none

## 1. Problem

`gloves` currently requires repeated CLI flags (for example `--root`) and has no first-class bootstrap config file.

We need a repository-local config model like `openclaw.json`:

- predictable bootstrap from a checked-in config file
- explicit secure/private path definitions
- explicit agent access visibility for private paths
- strict permissions for config and sensitive directories

## 2. Goals

- Add `.gloves.toml` as the default bootstrap config file.
- Allow explicit config file path via CLI.
- Add explicit vault runtime mode (`auto` / `required` / `disabled`) for better operator control.
- Keep secure permissions as a hard invariant.
- Provide an operator-visible command to show agent access to private paths.
- Keep current behavior backward compatible when no config file exists.

## 3. Non-goals

- No secret values in config.
- No replacement of `pass` or vault crypto internals.
- No dynamic policy engine.
- No implicit trust handoff beyond explicit config + existing audit trail.

## 4. CLI Surface

### 4.1 Global options

Add global options to `gloves`:

- `--config <PATH>`: absolute or relative path to config TOML
- `--no-config`: disable config discovery and use current defaults only
- `--vault-mode <auto|required|disabled>`: one-shot override for vault runtime behavior

### 4.2 Environment variable

- `GLOVES_CONFIG=<PATH>` provides config path when `--config` is not set.

### 4.3 New subcommands

Add:

- `gloves config validate`
  - Validates schema, permissions, and resolved paths.
  - Exit `0` on success, non-zero on failure.
- `gloves access paths --agent <AGENT_ID> [--json]`
  - Shows path-level access visibility for one agent.
  - Intended for operators to audit private path reachability.

## 5. Config Discovery and Precedence

Config selection order (first match wins):

1. `--no-config` set: skip config load entirely.
2. `--config <PATH>`.
3. `GLOVES_CONFIG` env value.
4. Auto-discovery: `.gloves.toml` in current directory, then parent directories up to filesystem root.
5. No config found: use existing defaults.

Notes:

- If an explicit path is provided (`--config` or `GLOVES_CONFIG`) and file is missing, fail fast.
- If auto-discovery finds no file, continue with defaults.

## 6. `.gloves.toml` Schema (v1)

```toml
version = 1

[paths]
# Equivalent to current --root default if omitted.
root = ".openclaw/secrets"

# Named private path aliases. Values may be absolute or config-relative.
[private_paths]
password_store = "~/.password-store"
workspace_private = "./.private"
runtime_root = ".openclaw/secrets"

[daemon]
bind = "127.0.0.1:7788"
io_timeout_seconds = 5
request_limit_bytes = 16384

[vault]
# Recommended default: "auto"
# - auto: vault commands work when binaries exist; otherwise return actionable errors.
# - required: config validation/runtime fails when vault binaries are missing.
# - disabled: vault commands are blocked intentionally.
mode = "auto"

[defaults]
agent_id = "default-agent"
secret_ttl_days = 1
vault_mount_ttl = "1h"
vault_secret_ttl_days = 365
vault_secret_length_bytes = 64

# Agent path visibility and allowed operations.
# Agent IDs must satisfy existing AgentId validation rules.
[agents.default-agent]
paths = ["runtime_root", "workspace_private"]
operations = ["read", "write", "list", "mount"]

[agents.agent-b]
paths = ["runtime_root"]
operations = ["read", "list"]

# Optional per-agent secret ACLs.
# Pattern forms:
# - "*" (all secrets)
# - "namespace/*" (all descendants)
# - "exact/secret-id" (one secret)
[secrets.acl.default-agent]
paths = ["github/*", "shared/*"]
operations = ["read", "write", "list", "revoke", "request", "status", "approve", "deny"]

[secrets.acl.agent-relationships]
paths = ["contacts/*", "shared/contacts/*"]
operations = ["read", "write", "list", "request", "status"]

[secrets.acl.agent-workflows]
paths = ["workflows/*", "shared/webhooks/*"]
operations = ["read", "write", "list", "request", "status", "approve", "deny"]

# Optional per-command URL policy for `get --pipe-to-args`.
# - require_url=true enforces that the template contains at least one URL argument.
# - url_prefixes restrict URL args to approved prefixes.
[secrets.pipe.commands.curl]
require_url = true
url_prefixes = [
  "https://api.example.com/v1/",
  "http://127.0.0.1:4001/carddav/"
]
```

Secret ACL operation mapping:

- `read`: `gloves get`
- `write`: `gloves set`
- `list`: `gloves list`
- `revoke`: `gloves revoke`
- `request`: `gloves request`
- `status`: `gloves status`
- `approve`: `gloves approve`
- `deny`: `gloves deny`

Secret pipe URL policy mapping:

- `[secrets.pipe.commands.<command>]`: policy entry keyed by executable name
- `require_url`: when `true`, `--pipe-to-args` templates must include at least one `http://` or `https://` URL argument
- `url_prefixes`: allowed URL prefixes for URL arguments in that template
- Behavior applies to `get --pipe-to-args` only

## 7. Validation Rules

### 7.1 File and ownership permissions

On Unix:

- config file MUST exist as a regular file.
- config file mode MUST NOT allow group/world write (`mode & 0o022 == 0`).
- if config defines any `private_paths`, file mode SHOULD be `0600` or `0640`.
- referenced runtime directories/files created by gloves continue to enforce existing private modes (`0700` dirs, `0600` files).

On non-Unix:

- enforce existing secure write helpers and skip Unix mode checks.

### 7.2 Path safety

- Resolve `~` to home directory.
- Resolve relative paths against the config file directory.
- Canonicalize for display and access checks where possible.
- Reject empty path values.
- Reject duplicate `private_paths` aliases.
- Reject unknown alias references under `[agents.<id>.paths]`.

### 7.3 Agent access model

- Unknown agent in `gloves access paths --agent` returns `NotFound`.
- Operations are constrained to enum: `read`, `write`, `list`, `mount`.
- Access output is visibility metadata only; it does not bypass existing secret/vault authorization.
- Secret ACL policy is optional under `[secrets.acl.<agent>]`.
- When secret ACL policy is configured, only matching path patterns + operations are permitted.

### 7.4 Vault mode and dependency checks

- `vault.mode` must be one of `auto`, `required`, `disabled`.
- Runtime dependencies for vault mode checks: `gocryptfs`, `fusermount`, `mountpoint`.
- `auto`:
  - non-vault commands run normally regardless of vault dependencies.
  - vault commands attempt execution and fail with actionable missing-binary errors when deps are absent.
- `required`:
  - `gloves config validate` fails if required vault binaries are missing.
  - runtime bootstrap for vault-enabled flows must fail fast when binaries are missing.
- `disabled`:
  - vault commands are blocked with explicit error.
  - non-vault commands remain available.

### 7.5 Secret pipe URL policy checks

- Command keys under `[secrets.pipe.commands]` must be bare executable names (`[a-zA-Z0-9._+-]`).
- Each command policy must either:
  - set `require_url = true`, or
  - define at least one `url_prefixes` entry.
- `url_prefixes` entries:
  - must be non-empty
  - must not contain whitespace
  - must start with `http://` or `https://`
  - must not contain duplicates
- At runtime, if config defines a policy for a command, that policy is applied before env URL policy fallback.

## 8. Effective Config and Overrides

- CLI flags continue to override config values for that invocation.
- `--root` overrides `[paths].root`.
- `--vault-mode` overrides `[vault].mode`.
- Command-specific options (for example daemon bind, vault ttl, agent id) override config defaults.
- Effective value resolution should be deterministic and auditable.

## 9. Output Contract for `gloves access paths`

### 9.1 JSON mode

`gloves access paths --agent agent-b --json` returns:

```json
{
  "agent": "agent-b",
  "paths": [
    {
      "alias": "runtime_root",
      "path": "/abs/path/.openclaw/secrets",
      "operations": ["read", "list"]
    }
  ]
}
```

### 9.2 Text mode

Human-readable table:

- `alias`
- `resolved path`
- `operations`

## 10. Backward Compatibility

- No `.gloves.toml`: current behavior remains unchanged.
- Existing scripts that pass `--root` continue working.
- Current default constants remain fallback values.
- `vault.mode = "auto"` preserves existing operational behavior.

## 11. Security Considerations

- Config can contain private path metadata; enforce strict file permissions.
- Never persist secret material in `.gloves.toml`.
- Always treat config contents as untrusted input and validate fully.
- Audit events SHOULD include config path source (`flag`, `env`, `discovered`, `none`) for sensitive operations.

## 12. Implementation Outline

1. Done: add config types and parser module (`src/config.rs`).
2. Done: add bootstrap resolver for discovery + precedence.
3. Done: integrate effective config into CLI runtime initialization.
4. Done: add `config validate` and `access paths` commands.
5. Done: enforce `vault.mode` semantics and dependency checks in CLI runtime.
6. Done: add permission/path validation and error mapping.
7. Done: update README and command reference.

## 13. TDD Plan

Add tests before implementation.

### Unit tests

- `config_roundtrip_v1`
- `config_discovery_prefers_flag`
- `config_discovery_prefers_env_over_discovery`
- `config_discovery_walks_parent_dirs`
- `config_validate_rejects_unknown_agent_path_alias`
- `config_validate_rejects_duplicate_private_alias`
- `config_validate_rejects_invalid_operation`
- `config_resolve_relative_paths_against_file_dir`
- `config_resolve_home_expansion`
- `config_vault_mode_defaults_to_auto`
- `config_validate_rejects_invalid_vault_mode`

### Unix permission tests

- `config_validate_rejects_group_world_writable_file`
- `config_validate_accepts_private_modes`

### CLI integration tests

- `cli_bootstrap_uses_discovered_gloves_toml`
- `cli_bootstrap_uses_explicit_config_path`
- `cli_bootstrap_no_config_keeps_existing_defaults`
- `cli_config_validate_success`
- `cli_config_validate_failure_invalid_alias`
- `cli_access_paths_json`
- `cli_access_paths_unknown_agent_fails`
- `cli_vault_mode_disabled_blocks_vault_commands`
- `cli_vault_mode_required_fails_without_binaries`
- `cli_vault_mode_auto_keeps_non_vault_commands_available`

## 14. Open Questions

- Should `gloves access paths` include inherited/default policy blocks, or only explicit per-agent entries?
- Should config source (`flag/env/discovered`) be emitted in `gloves verify` output?
- Should we allow a strict mode that requires config presence (`--require-config`)?
