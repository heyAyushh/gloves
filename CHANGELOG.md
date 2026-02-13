# gloves

## Unreleased

### Minor Changes

- Added `.gloves.toml` bootstrap config parser and validator module in `src/config.rs`.
- Added config discovery/precedence resolution for explicit path, env path, and parent-directory discovery.
- Added strict config security checks, including Unix permission validation and symlink rejection.
- Added agent private-path visibility resolution API for config-defined access policies.
- Added comprehensive parser coverage in `tests/config_parser.rs` for schema, path, daemon, defaults, and security edge cases.
- Updated README, plan, and spec documents to reflect implemented parser scope and pending CLI wiring.

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
- Added agent-owned secret storage with `age` encryption and checksum integrity validation.
- Added human-owned secret access flow via `pass` with request/approve/deny/status lifecycle.
- Added runtime security controls: restricted file permissions, append-only audit logging, and TTL-based expiry reaping.
- Added CLI command suite: `init`, `set`, `get`, `env`, `request`, `approve`, `deny`, `list`, `revoke`, and `verify`.
