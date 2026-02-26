# Gloves CLI Usage Command Reference

## Top-Level

```bash
gloves --root <root> <command> [args...]
```

- Default root: `.openclaw/secrets`
- Primary command router: `src/cli/mod.rs`
- Crypto backend: in-process age-format library (no external rage binary required)

Quick inspection commands:

```bash
gloves --help
gloves help <command>
gloves --version
gloves version
gloves version --json
gloves explain E102
gloves requests --help
gloves tui
```

## Commands

| Command | Purpose | Key Flags/Args |
|---|---|---|
| `init` | Create runtime directory/file layout | none |
| `version` | Print CLI version and defaults | optional `--json` |
| `explain <code>` | Print detailed recovery guidance for a stable error code | example: `gloves explain E102` |
| `tui` | Open interactive command navigator (ratatui) | Enter prints selected command example; q/Esc exits |
| `set <name>` | Create an agent-owned secret | `--generate`, `--stdin`, `--value`, `--ttl <days>` (`days > 0`) |
| `get <name>` | Fetch secret value | `--pipe-to <command>`, `--pipe-to-args "<command> {secret}"` |
| `env <name> <var>` | Print redacted export text | none |
| `request <name> --reason <text>` | Open human-access request | `--reason` required, optional `--allowlist`, `--blocklist` |
| `requests list` | List only pending requests | alias: `gloves req list` |
| `requests approve <request_id>` | Approve request UUID via grouped workflow | alias: `gloves req approve <request_id>` |
| `requests deny <request_id>` | Deny request UUID via grouped workflow | alias: `gloves req deny <request_id>` |
| `approve <request_id>` | Approve request UUID | request UUID |
| `deny <request_id>` | Deny request UUID | request UUID |
| `list` | Print combined secret metadata and pending requests | optional `--pending` |
| `audit` | View audit events | `--limit <n>`, optional `--json` |
| `revoke <name>` | Remove caller-owned secret and metadata | none |
| `status <name>` | Print request status for secret | none |
| `verify` | Reap expired items and verify state | none |
| `daemon` | Run local sidecar daemon | `--check`, `--bind` |
| `vault <subcommand>` | Manage encrypted vault workflows | `init`, `mount`, `exec`, `unmount`, `status`, `list`, `ask-file` |
| `config validate` | Validate effective config | honors `--config`, `--no-config`, `GLOVES_CONFIG` |
| `access paths` | Show one agent's private-path visibility | `--agent`, optional `--json` |
| `gpg create` | Create selected agent GPG key | idempotent |
| `gpg fingerprint` | Show selected agent GPG fingerprint | returns `not found` when key is absent |

Global diagnostics flag:

- `--error-format <text|json>` controls parse/runtime error output shape.

## Command Patterns

### Initialize Once Per Root

```bash
gloves --root .openclaw/secrets init
```

### Confirm Installed Version

```bash
gloves --version
gloves version
gloves version --json
```

### Create and Read Agent Secret

```bash
gloves --root .openclaw/secrets set service/token --generate --ttl 1
gloves --root .openclaw/secrets get service/token
```

### Create Human Access Request and Resolve

```bash
gloves --root .openclaw/secrets request prod/db --reason "deploy migration"
gloves --root .openclaw/secrets list
gloves --root .openclaw/secrets approve <request-uuid>
gloves --root .openclaw/secrets requests list
gloves --root .openclaw/secrets requests approve <request-uuid>
gloves --root .openclaw/secrets status prod/db
```

### Human `pass` Secret Handoff To Agent

```bash
# human stores secret in pass
pass insert prod/db

# agent requests access
gloves --root .openclaw/secrets --agent agent-a request prod/db --reason "run migration"

# operator resolves request
gloves --root .openclaw/secrets --agent agent-main approve <request-uuid>

# approved agent reads through gloves
GLOVES_GET_PIPE_ALLOWLIST=cat \
gloves --root .openclaw/secrets --agent agent-a get prod/db --pipe-to cat
```

Notes:
- Secret name must match between `pass` and `gloves`.
- If ACL is enabled, requester needs `request/read/status` and operator needs `approve/deny`.
- If `gpg denied` occurs, verify `pass show prod/db` works in the human session.
- `approve` and `deny` require a UUID request id. If you accidentally pass a label such as `requests`, run `gloves list --pending` first.
- `requests list` provides noun-first navigation and is equivalent to `gloves list --pending`.
- For argument issues, check command-specific examples: `gloves help approve`, `gloves help set`, `gloves help get`, `gloves help revoke`, `gloves help request`, or `gloves help gpg`.
- CLI stderr includes stable error codes (`error[E...]`). Use `gloves explain <code>` for direct remediation.
- Parse errors can be emitted as JSON for automation (`gloves --error-format json ...`).

Typo suggestion auto-run (disabled by default):

- `GLOVES_SUGGEST_AUTORUN=1`: allow typo auto-run for safe read/navigation commands.
- `GLOVES_SUGGEST_AUTORUN_RISKY=1`: also allow typo auto-run for mutating commands.
- `GLOVES_SUGGEST_AUTORUN_DELAY_MS=<n>`: countdown before auto-run (default `1200`, max `10000`).

### Verify and Reap Expired State

```bash
gloves --root .openclaw/secrets verify
```

### Audit Trail

```bash
gloves --root .openclaw/secrets audit --limit 25
gloves --root .openclaw/secrets audit --json --limit 200
```

### Start Daemon Sidecar (OpenClaw/systemd)

```bash
# strict startup checks only (includes bind-availability check)
gloves --root .openclaw/secrets daemon --check --bind 127.0.0.1:7788

# start daemon on loopback TCP
gloves --root .openclaw/secrets daemon --bind 127.0.0.1:7788
```

### Config and Agent Visibility

```bash
gloves --root .openclaw/secrets config validate
gloves --root .openclaw/secrets access paths --agent agent-main --json
```

### GPG Agent Keys

```bash
gloves --root .openclaw/secrets --agent agent-main gpg create
gloves --root .openclaw/secrets --agent agent-main gpg fingerprint
```

## Runtime Paths

Built by `SecretsPaths` in `src/paths.rs`:
- `<root>/store/` encrypted `*.age` ciphertext
- `<root>/meta/` per-secret metadata JSON
- `<root>/pending.json` request records
- `<root>/audit.jsonl` append-only audit events
- `<root>/default-agent.agekey` generated default age identity
- `<root>/default-agent.signing.key` generated signing key
