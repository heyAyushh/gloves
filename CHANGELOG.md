# gloves

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
