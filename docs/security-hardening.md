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
- Optional sub-policy `GLOVES_GET_PIPE_ARG_POLICY` can enforce exact approved `--pipe-to-args` templates per executable.
- Optional config policy `[secrets.pipe.commands.<command>]` can enforce approved URL prefixes per executable.
- Optional env fallback `GLOVES_GET_PIPE_URL_POLICY` can enforce approved URL prefixes when config has no command entry.
- `--pipe-to` and `--pipe-to-args` are mutually exclusive.
- `--pipe-to-args` template must include `{secret}` and cannot place `{secret}` as the executable.
- `--pipe-to-args` only accepts UTF-8 secrets.
- `--pipe-to-args` rejects control characters in secrets. Use `--pipe-to` for raw byte-safe forwarding.
- Secret bytes and interpolated argument buffers are zeroized in-process after use.

`GLOVES_GET_PIPE_ARG_POLICY` format:

```json
{
  "curl": [
    "curl -u ayush:{secret} http://127.0.0.1:4001/carddav/principal/ayush/"
  ],
  "print-arg": [
    "print-arg prefix:{secret}:suffix"
  ]
}
```

Policy behavior:

- Applies to `--pipe-to-args` only.
- Requires an exact template match after shell-style parsing/normalization.
- If policy is set and a command has no entry, execution is denied.

Config URL policy format (`.gloves.toml`):

```toml
[secrets.pipe.commands.curl]
require_url = true
url_prefixes = ["https://api.example.com/v1/"]

[secrets.pipe.commands.applecli]
require_url = true
url_prefixes = ["https://internal.example.local/"]
```

Config URL policy behavior:

- Applies to `--pipe-to-args` only.
- Works for any configured executable name.
- Enforces URL arguments (http/https) to start with an approved prefix.
- `require_url = true` denies templates that do not include any URL argument.
- For commands with config entries, config policy takes precedence over env URL policy.

`GLOVES_GET_PIPE_URL_POLICY` format (env fallback):

```json
{
  "curl": [
    "https://api.example.com/v1/",
    "http://127.0.0.1:4001/carddav/"
  ]
}
```

URL policy behavior:

- Applies to `--pipe-to-args` only.
- Enforces URL arguments (http/https) to start with an approved prefix.
- Allows payload/flag variation while keeping URL scope restricted.
- If a command has URL policy entries, templates without URL arguments are denied.

Operational guidance:

- Prefer `--pipe-to` for highest safety.
- Use `--pipe-to-args` only when downstream tools cannot read from stdin.
- Keep `GLOVES_GET_PIPE_ALLOWLIST` minimal and explicit.
- For networked binaries (for example `curl`), set `GLOVES_GET_PIPE_ARG_POLICY` or config URL policy under `[secrets.pipe.commands.<command>]` instead of relying on executable-only allowlists.
- Prefer `GLOVES_GET_PIPE_ARG_POLICY` for maximal control; use URL-prefix policy when exact-template policy is too strict for dynamic payloads.

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
- CLI and daemon actions emit `command_executed` audit events (actor, interface, action, optional target).
- Use `gloves audit --limit <n>` for readable output and `gloves audit --json` for automation/reporting.
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
