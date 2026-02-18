# gloves

## Unreleased

### Minor Changes

- No unreleased changes yet.

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
