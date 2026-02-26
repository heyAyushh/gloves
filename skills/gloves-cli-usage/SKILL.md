---
name: gloves-cli-usage
description: Operate and troubleshoot the gloves CLI for OpenClaw-style and other multi-agent runtimes. Use when asked to run or explain grouped CLI operations (`secrets`, `request`, `requests`, `vault`, `config`, `access`, `gpg`, `daemon`, `audit`, `verify`, `version`, `explain`, `tui`) and command behavior from implementation/tests. Use `gloves-setup-migrate` for bootstrap or migration playbooks.
---

# Gloves CLI Usage

## Overview

Use this skill to run `gloves` commands safely and predictably, with behavior grounded in the real CLI implementation and tests.

Primary behavior sources:

- `src/cli/mod.rs`
- `src/manager.rs`
- `src/paths.rs`
- `tests/cli_integration.rs`

Command reference:

- `references/commands.md`

## Workflow

1. Identify user goal and actor (`--agent <id>` when relevant).
2. Confirm command path with recursive help when needed (`gloves help [topic...]`, `gloves requests help approve`, `gloves secrets help set`).
3. Pick the target root (`--root`) and initialize once if needed (`init`).
4. Run the smallest command sequence that solves the task.
5. Validate with `list`, `secrets status`, `audit`, or direct command output.
6. Report exact commands run and key result lines.

## Task Playbooks

### Agent Secret Lifecycle

1. Initialize:
   ```bash
   gloves --root <root> init
   ```
2. Store:
   ```bash
   gloves --root <root> secrets set <secret-name> --generate --ttl <days>
   # or: --stdin / --value (ttl days must be > 0)
   ```
3. Read (only when user explicitly wants secret output):
   ```bash
   gloves --root <root> secrets get <secret-name>
   ```
4. Inspect:
   ```bash
   gloves --root <root> list
   ```
5. Revoke if requested:
   ```bash
   gloves --root <root> secrets revoke <secret-name>
   ```

### Human Access Request Lifecycle

1. Create request:
   ```bash
   gloves --root <root> request <secret-name> --reason "<why>"
   ```
2. Check status by secret:
   ```bash
   gloves --root <root> secrets status <secret-name>
   ```
3. Resolve request:
   ```bash
   gloves --root <root> requests list
   gloves --root <root> requests approve <request-uuid>
   # or:
   gloves --root <root> requests deny <request-uuid>
   ```
4. Verify status transition:
   ```bash
   gloves --root <root> secrets status <secret-name>
   ```

### Human `pass` Handoff to Agent

1. Human stores secret in `pass` under the same secret name:
   ```bash
   pass insert <secret-name>
   ```
2. Agent creates access request:
   ```bash
   gloves --root <root> --agent <requester-agent> request <secret-name> --reason "<why>"
   ```
3. Human resolves request:
   ```bash
   gloves --root <root> --agent <operator-agent> requests list
   gloves --root <root> --agent <operator-agent> requests approve <request-uuid>
   # or deny
   ```
4. Approved agent reads value (prefer piping over raw tty output):
   ```bash
   GLOVES_GET_PIPE_ALLOWLIST=cat \
   gloves --root <root> --agent <requester-agent> secrets get <secret-name> --pipe-to cat
   ```
5. If access fails with `gpg denied`, unlock/check once in the human session:
   ```bash
   pass show <secret-name>
   ```

### Expiry and Maintenance

1. Run expiry reaper and state checks:
   ```bash
   gloves --root <root> verify
   ```
2. Inspect state:
   ```bash
   gloves --root <root> list
   ```
3. Review audit stream:
   ```bash
   gloves --root <root> audit --limit 50
   gloves --root <root> audit --json --limit 200
   ```

### Sidecar Daemon (TCP)

1. Verify strict startup checks:
   ```bash
   gloves --root <root> daemon --check --bind 127.0.0.1:7788
   ```
2. Start daemon:
   ```bash
   gloves --root <root> daemon --bind 127.0.0.1:7788
   ```

### Config and Access Visibility

1. Validate effective config:
   ```bash
   gloves --root <root> config validate
   ```
2. Show one agent's configured private-path visibility:
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

### TUI Operations

1. Open command navigator:
   ```bash
   gloves --root <root> tui
   ```
2. Key navigation:
   - `Enter`: command -> global flags -> command fields -> run -> command tree
   - `e`: edit selected text field
   - `f`: toggle focused pane fullscreen
   - `Ctrl+C`: cancel active run

## Guardrails

- Prefer `--stdin` or `--generate` over `--value` when possible.
- Avoid printing raw secrets unless explicitly requested.
- Keep commands scoped to selected `--root`.
- Use valid secret ids only (no traversal patterns like `..` or leading `/`).
- Expect `secrets set` duplicate errors (`already exists`); do not assume overwrite.
- Keep daemon bind loopback-only (`127.0.0.1` or `::1`).
- Keep memory/index exclusions for secret sources:
  - `~/.password-store/**` (or `$PASSWORD_STORE_DIR/**`)
  - `.openclaw/secrets/**` and any custom `--root` path
- Never store raw secret values in notes or memory summaries.

## Troubleshooting

- `error[E102]` with label input (for example `approve requests`): run `gloves requests list` and then `gloves requests approve <request-id>`.
- `not found`: target secret/request does not exist.
- `already exists`: secret name already present.
- `forbidden` / `unauthorized`: caller lacks ACL/request approval.
- `expired`: TTL elapsed.
- `integrity check failed`: ciphertext checksum mismatch.
- `gpg denied`: `pass`/GPG access denied for human backend.
- Use `gloves explain <code>` for stable error remediation.
- Use `--error-format json` for automation-friendly diagnostics.

## Verification

When changing CLI behavior or docs tied to CLI behavior, run:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --locked
cargo doc --no-deps
```
