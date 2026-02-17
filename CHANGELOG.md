# gloves

## Unreleased

### Minor Changes

- No unreleased changes yet.

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
