---
name: gloves-cli
description: Operate and troubleshoot the gloves secrets CLI for OpenClaw-style and other multi-agent runtimes. Use when asked to initialize secret storage, set/get/list/revoke agent secrets, create or resolve human access requests (request/approve/deny/status), run expiry verification (verify), inspect runtime files, or explain command behavior from implementation/tests.
---

# Gloves CLI

## Overview

Use this skill to run `gloves` commands safely and predictably, with behavior grounded in the real CLI implementation and tests.

Primary implementation and behavior sources:
- `src/cli/mod.rs`
- `src/manager.rs`
- `src/paths.rs`
- `tests/cli_integration.rs`

Command details and examples:
- `references/commands.md`

## Workflow

1. Identify the user goal.
2. Choose a secrets root (`--root`) and initialize layout if needed (`init`).
3. Run the minimal command sequence for that goal.
4. Validate the result using `list`, `status`, or command output.
5. Report results with exact command(s) executed and key output.

## Task Playbooks

### Agent Secret Lifecycle

1. Initialize:
   ```bash
   gloves --root <root> init
   ```
2. Store:
   ```bash
   gloves --root <root> set <secret-name> --generate --ttl <days>
   # or: --stdin / --value
   ```
3. Read (only when user explicitly wants secret output):
   ```bash
   gloves --root <root> get <secret-name>
   ```
4. Inspect:
   ```bash
   gloves --root <root> list
   ```
5. Revoke if requested:
   ```bash
   gloves --root <root> revoke <secret-name>
   ```

### Human Access Request Lifecycle

1. Create request:
   ```bash
   gloves --root <root> request <secret-name> --reason "<why>"
   ```
2. Check request status by secret:
   ```bash
   gloves --root <root> status <secret-name>
   ```
3. Resolve request:
   ```bash
   gloves --root <root> approve <request-uuid>
   # or:
   gloves --root <root> deny <request-uuid>
   ```
4. Verify status transition:
   ```bash
   gloves --root <root> status <secret-name>
   ```

### Expiry and Maintenance

1. Run expiry reaper and integrity checks:
   ```bash
   gloves --root <root> verify
   ```
2. Inspect combined state:
   ```bash
   gloves --root <root> list
   ```

## Guardrails

- Prefer `--stdin` or `--generate` over `--value` when possible.
- Avoid printing raw secrets unless the user explicitly requests it.
- Keep commands scoped to the selected `--root`; avoid touching unrelated paths.
- Use valid secret identifiers only (no traversal patterns like `..` or leading `/`).
- Expect `set` to fail on duplicates (`already exists`); do not assume overwrite behavior.
- Ensure agent memory/index excludes cover secret paths:
  - `~/.password-store/**` (or `$PASSWORD_STORE_DIR/**`)
  - `.openclaw/secrets/**` and any custom `--root` directory
- Never save raw secret values from CLI output into agent memory or notes.

## Troubleshooting

- `not found`: Secret or request does not exist.
- `already exists`: Secret name is already present.
- `unauthorized` / `forbidden`: Caller lacks required permissions or approval state.
- `expired`: Secret/request TTL elapsed.
- `integrity check failed`: Ciphertext checksum mismatch.
- `invalid input: ...`: Most often malformed UUID or invalid argument value.
- `gpg denied`: `pass`/GPG access denied for human backend reads.

## Verification

When changing CLI behavior or docs tied to CLI behavior, run:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo doc --no-deps
```
