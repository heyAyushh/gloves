---
name: gloves-cli-usage
description: Operate and troubleshoot the gloves secrets CLI for OpenClaw-style and other multi-agent runtimes. Use when asked to run or explain CLI operations (`set/get/list/revoke/request/requests/approve/deny/status/verify/daemon/vault/config/access/gpg/version/explain/tui`) and command behavior from implementation/tests. Use `gloves-setup-migrate` for bootstrap or migration playbooks.
---

# Gloves CLI Usage

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
2. Confirm available CLI surface quickly when needed (`gloves --help`, `gloves help <command>`, `gloves --version`, `gloves version --json`, `gloves requests --help`, `gloves tui`).
3. Choose a secrets root (`--root`) and initialize layout if needed (`init`).
4. Run the minimal command sequence for that goal.
5. Validate the result using `list`, `status`, `audit`, or command output.
6. Report results with exact command(s) executed and key output.

## Task Playbooks

### Agent Secret Lifecycle

1. Initialize:
   ```bash
   gloves --root <root> init
   ```
2. Store:
   ```bash
   gloves --root <root> set <secret-name> --generate --ttl <days>
   # or: --stdin / --value (ttl days must be > 0)
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
   # grouped navigation:
   gloves --root <root> requests approve <request-uuid>
   gloves --root <root> requests deny <request-uuid>
   ```
4. Verify status transition:
   ```bash
   gloves --root <root> status <secret-name>
   ```

### Human `pass` Handoff To Agent

1. Human stores secret in `pass` under the same secret name used by gloves:
   ```bash
   pass insert <secret-name>
   ```
2. Agent creates access request:
   ```bash
   gloves --root <root> --agent <requester-agent> request <secret-name> --reason "<why>"
   ```
3. Human approves or denies:
   ```bash
   gloves --root <root> --agent <operator-agent> approve <request-uuid>
   # or:
   gloves --root <root> --agent <operator-agent> deny <request-uuid>
   ```
4. Approved agent reads via gloves (prefer piping over raw tty output):
   ```bash
   GLOVES_GET_PIPE_ALLOWLIST=cat \
   gloves --root <root> --agent <requester-agent> get <secret-name> --pipe-to cat
   ```
5. If access fails with `gpg denied`, unlock/check the same secret once with `pass` in the human session:
   ```bash
   pass show <secret-name>
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

### Sidecar Daemon (TCP)

1. Verify strict startup checks:
   ```bash
   gloves --root <root> daemon --check --bind 127.0.0.1:7788
   # validates root permissions, loopback policy, and bind availability
   ```
2. Start daemon:
   ```bash
   gloves --root <root> daemon --bind 127.0.0.1:7788
   ```

### Access and Config Visibility

1. Validate effective config:
   ```bash
   gloves --root <root> config validate
   ```
2. Show one agent's private-path visibility:
   ```bash
   gloves --root <root> access paths --agent <agent-id> --json
   ```

### Agent GPG Operations

1. Create one agent key if missing:
   ```bash
   gloves --root <root> --agent <agent-id> gpg create
   ```
2. Print fingerprint:
   ```bash
   gloves --root <root> --agent <agent-id> gpg fingerprint
   ```

## Guardrails

- Prefer `--stdin` or `--generate` over `--value` when possible.
- Agent crypto runs in-process; no external `rage` binary install is required.
- Avoid printing raw secrets unless the user explicitly requests it.
- Keep commands scoped to the selected `--root`; avoid touching unrelated paths.
- Use valid secret identifiers only (no traversal patterns like `..` or leading `/`).
- Expect `set` to fail on duplicates (`already exists`); do not assume overwrite behavior.
- For daemon mode, bind only to loopback addresses (`127.0.0.1` or `::1`).
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
- `error[E...]`: Use `gloves explain <code>` for a detailed fix path.
- `--error-format json`: use structured diagnostics for automation/agents.
- Typo auto-run is off by default; use `GLOVES_SUGGEST_AUTORUN=1` for safe commands, and require `GLOVES_SUGGEST_AUTORUN_RISKY=1` for mutating commands.

## Verification

When changing CLI behavior or docs tied to CLI behavior, run:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo doc --no-deps
```
