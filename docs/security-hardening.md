# Gloves Security Hardening Notes

This document describes the security controls around the new workflow-reduction features:

- `gloves get --pipe-to-args`
- `gloves vault exec`
- `gloves vault mount --agent`

The goal is to keep behavior ergonomic while reducing accidental data exposure.

## 1) Secret forwarding controls (`get`)

`gloves get` has two non-interactive output modes:

- `--pipe-to <command>`: streams raw secret bytes to command stdin
- `--pipe-to-args "<command> {secret}"`: interpolates secret text into command arguments

Security controls:

- The executable must be a bare command name (no path separators).
- The executable must be allowlisted in `GLOVES_GET_PIPE_ALLOWLIST`.
- `--pipe-to` and `--pipe-to-args` are mutually exclusive.
- `--pipe-to-args` template must include `{secret}` and cannot place `{secret}` as the executable.
- `--pipe-to-args` only accepts UTF-8 secrets.
- `--pipe-to-args` rejects control characters in secrets. Use `--pipe-to` for raw byte-safe forwarding.
- Secret bytes and interpolated argument buffers are zeroized in-process after use.

Operational guidance:

- Prefer `--pipe-to` for highest safety.
- Use `--pipe-to-args` only when downstream tools cannot read from stdin.
- Keep `GLOVES_GET_PIPE_ALLOWLIST` minimal and explicit.

## 2) Vault execution controls (`vault exec`)

`gloves vault exec <name> -- <command...>` mounts a vault, runs a command, then unmounts.

Security controls:

- Unmount is attempted on both command success and command failure paths.
- The wrapped command inherits stdio for compatibility, and returns its exit code.
- Sensitive extpass wiring env vars are removed from wrapped command environment:
  - `GLOVES_EXTPASS_ROOT`
  - `GLOVES_EXTPASS_AGENT`
- `--agent` on `vault mount` / `vault exec` controls mount attribution and extpass identity.

Operational guidance:

- Use short TTL values for mount windows.
- Prefer `vault exec` over ad hoc mount/unmount scripts when possible.
- Keep wrapped commands deterministic and non-interactive in automation.

## 3) Request policy controls

Request review can be constrained by secret patterns:

- `GLOVES_REQUEST_ALLOWLIST`
- `GLOVES_REQUEST_BLOCKLIST`
- CLI equivalents on `request`: `--allowlist`, `--blocklist`

Pattern forms:

- `*`
- `namespace/*`
- exact secret id (`namespace/name`)

Policy behavior:

- Blocklist always denies matching secrets.
- If allowlist is set, only allowlisted secrets are accepted.
- Invalid or empty pattern entries are rejected.

## 4) Sidecar and environment hygiene

- Keep daemon on loopback only (`127.0.0.1`).
- Do not log raw secret values or persist them in memory summaries.
- Keep secrets root permissions private to the service account.
- Run `gloves verify` on a schedule.

## 5) Validation gates

Before publishing changes that touch secret flow, run:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --locked
cargo doc --no-deps
```
