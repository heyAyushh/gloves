# gloves

## Unreleased

### Minor Changes

- No unreleased changes yet.

## 0.5.4

### Patch Changes

- Hardened vault driver regression tests to wait for expected command-log content (not just file creation), removing a CI timing race in `mount_passes_extpass_and_idle`.
- Expanded security/operator docs with clearer policy-selection guidance between executable allowlists, URL-prefix policies, and exact template policies.
- Added release runbook guidance for failed tagged publishes (patch bump + new tag flow).

## 0.5.3

### Patch Changes

- Added focused URL-policy matcher unit tests in `cli/commands.rs` to cover host-boundary, path-boundary, and query/fragment validation branches.
- Added integration coverage for exact-authority and exact-path URL-prefix allow cases.
- Restored coverage gate compliance for release publishing.

## 0.5.2

### Minor Changes

- Added config-managed URL policy for `gloves get --pipe-to-args` under `[secrets.pipe.commands.<command>]`, including `require_url` enforcement and per-command URL prefixes.
- Added `gloves audit` command (`--limit`, `--json`) for direct audit log inspection.
- Added `command_executed` audit events for both CLI and daemon actions, including interface and optional target metadata.

### Patch Changes

- Added strict validation for `[secrets.pipe.commands.*]` config entries (bare command names, valid URL prefixes, duplicate checks, and non-empty policy requirements).
- Hardened URL-prefix matching to enforce scheme + authority + path-segment boundaries, preventing host/path prefix bypasses.
- Rejected URL policy prefixes that include query (`?`) or fragment (`#`) components.
- Kept `GLOVES_GET_PIPE_URL_POLICY` as compatibility fallback when config does not define a command URL policy.
- Expanded regression coverage for config URL policy behavior across arbitrary commands, URL mismatch rejection, and require-URL enforcement.
- Added regression coverage for host-boundary and path-segment boundary bypass attempts.
- Expanded audit regression coverage for command event serialization and CLI/daemon logging paths.
- Updated operator docs (`README`, security hardening guide, VM multi-agent guide, config spec) with the new URL policy model and audit usage.

## 0.5.0

### Minor Changes

- Split OpenClaw skill packaging into `gloves-cli-usage` and `gloves-setup-migrate` with a hard break from `gloves-cli`.
- Added a dedicated setup and migration skill covering bootstrap, ACL migration, optional separate roots, GPG fingerprinting, audit verification, and rollback checklists.
- Updated `setup-openclaw.sh` to install both skills by default, added `--skills-dest`, and kept `--skill-dest` as a deprecated alias.
- Added installer regression coverage for two-skill installation, summary output, and explicit-missing-skill failures.
- Updated README and release docs to reflect the two-skill installation and usage paths.

## 0.4.1

### Patch Changes

- Added extensive ACL regression coverage for all ACL-gated secret operations, including request/approve/deny path matching and deny-by-default cases.
- Added daemon coverage for request parsing, error responses, and runtime handling branches to keep CI coverage thresholds stable.
- Expanded operator docs with a complete secret ACL operation map and multi-agent ACL config examples.
- Added `pass`-to-agent handoff guidance to the `gloves-cli` skill and command reference, including ACL requirements and `gpg denied` troubleshooting.

## 0.4.0

### Minor Changes

- Added native per-agent secret ACL policy under `[secrets.acl.<agent>]` with path pattern validation and operation-level enforcement.
- Enforced ACLs across `set/get/list/revoke/request/status/approve/deny`, including list filtering and hardening against `--no-config` bypass for the same root.
- Added secure `get --pipe-to <command>` support with command allowlisting via `GLOVES_GET_PIPE_ALLOWLIST` and non-TTY raw-output blocking by default.
- Added per-agent GPG key management commands (`gpg create`, `gpg fingerprint`) with `gpg_key_created` audit events.
- Hardened GPG key generation for deep or relative runtime roots by routing through a short stable homedir alias and added regression coverage.

## 0.3.3

### Patch Changes

- Fixed vault mount config resolution by extending discovery to walk from `--root` when cwd-based discovery does not find `.gloves.toml`.
- Fixed failed mount cleanup to terminate the spawned foreground `gocryptfs` process first and avoid unconditional `fusermount -u` noise on non-mounted paths.
- Increased vault mount readiness timeout from 3s to 10s to reduce false-negative readiness failures on slower environments.
- Updated unmount execution to capture `fusermount` stderr and return structured errors instead of leaking raw cleanup noise to CLI output.
- Added regression tests for root-based config discovery on mount and for suppressing misleading cleanup stderr in missing-binary mount failures.
- Documented that `set --stdin` trims trailing CR/LF bytes.

## 0.3.2

### Patch Changes

- Fixed vault extpass wiring by introducing an internal `extpass-get` helper with explicit environment propagation, removing shell-quote dependent command construction.
- Fixed CLI output handling to gracefully tolerate broken pipes and preserve exact raw bytes for `gloves get` (no lossy UTF-8 conversion, no forced newline).
- Fixed vault bootstrap defaults to honor configured `agent_id`, `vault_secret_ttl_days`, and `vault_secret_length_bytes` values.
- Fixed vault mount error handling to clean up failed mount sessions and propagate actionable missing-binary diagnostics.
- Added regression coverage for extpass env requirements, raw-byte secret output, broken-pipe behavior, vault defaults wiring, mount cleanup, and driver error propagation.

## 0.3.1

### Patch Changes

- Fixed GitHub publish workflow macOS matrix to use supported runners for Intel macOS artifacts.
- Added GitHub Release binary assets and SHA-256 checksum publishing in CI.
- Updated OpenClaw setup script to install prebuilt release binaries by default, with source fallback.

## 0.3.0

### Minor Changes

- Replaced runtime `rage`/`rage-keygen` subprocess crypto with in-process `age` library encryption/decryption (rage project format).
- Removed runtime dependency on external rage binaries for `set`/`get`/daemon secret operations.
- Updated setup/docs/tests/CI to reflect the in-process crypto backend.

## 0.2.0

### Minor Changes

- Added encrypted vault lifecycle support with init, mount/unmount, status/list, session TTLs, and trusted file handoff prompts.
- Added `.gloves.toml` bootstrap config parsing and validation with discovery precedence (`--config`, `GLOVES_CONFIG`, parent discovery, `--no-config`).
- Added CLI runtime wiring for config-driven defaults, plus new `config validate` and `access paths` commands.
- Added vault runtime mode enforcement (`auto`, `required`, `disabled`) with dependency checks for `gocryptfs`, `fusermount`, and `mountpoint`.
- Updated direct dependencies to latest stable releases and applied compatibility updates for crypto and security crates.

## 0.1.1

### Minor Changes

- Added TCP sidecar daemon mode for OpenClaw-compatible supervisor deployments.
- Enforced daemon bind safety checks (loopback-only and non-zero port) with startup preflight support.
- Added integration coverage for daemon request/response behavior and invalid input handling.
- Added hardened `systemd` user unit templates for daemon runtime and periodic verify tasks.
- Updated README and skill command references for sidecar operation and endpoint matching.

## 0.1.0

### Minor Changes

- Initial release of `gloves`, a dual-backend secrets manager for OpenClaw-style and other multi-agent runtimes.
- Added agent-owned secret storage with age-format encryption and checksum integrity validation.
- Added human-owned secret access flow via `pass` with request/approve/deny/status lifecycle.
- Added runtime security controls: restricted file permissions, append-only audit logging, and TTL-based expiry reaping.
- Added CLI command suite: `init`, `set`, `get`, `env`, `request`, `approve`, `deny`, `list`, `revoke`, and `verify`.
