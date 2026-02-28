# Gloves CLI Usage Command Reference

## Top-Level Shape

```bash
gloves --root <root> <command> [args...]
```

- Default root: `.openclaw/secrets`
- Primary parser/router: `src/cli/mod.rs`

Quick inspection:

```bash
gloves --help
gloves help
gloves help secrets set
gloves requests help approve
gloves --version
gloves --json --version
gloves explain E102
gloves tui
```

## Commands

| Command | Purpose | Key Flags/Args |
|---|---|---|
| `init` | Create runtime directory/file layout | none |
| `--version` | Print CLI version and runtime defaults | use with `--json` or `--error-format json` for JSON |
| `explain <code>` | Print recovery guidance for stable error code | example: `gloves explain E102` |
| `tui` | Open interactive command navigator | live run cards, cancel support |
| `help [topic...]` | Recursive help for command paths | examples: `help secrets set`, `help requests approve` |
| `secrets set <name>` | Create agent-owned secret | `--generate`, `--stdin`, `--value`, `--ttl <days>` |
| `secrets get <name>` | Read secret value | `--pipe-to`, `--pipe-to-args` |
| `secrets grant <name> --to <agent>` | Grant secret access to another agent | caller must be creator |
| `secrets revoke <name>` | Revoke caller-owned secret | none |
| `secrets status <name>` | Request status by secret id | pending/fulfilled/denied/expired |
| `env <name> <var>` | Print redacted export text | none |
| `request <name> --reason <text>` | Create human-access request | optional `--allowlist`, `--blocklist` |
| `requests list` | List pending requests | noun-first review queue |
| `requests approve <request_id>` | Approve request UUID | request UUID |
| `requests deny <request_id>` | Deny request UUID | request UUID |
| `list` | List secret entries | use `requests list` for pending queue |
| `audit` | View audit events | `--limit <n>` |
| `verify` | Reap expired items and verify state | none |
| `daemon` | Run local sidecar daemon | `--check`, `--bind` |
| `vault <subcommand>` | Manage encrypted vault workflows | `init`, `mount`, `exec`, `unmount`, `status`, `list`, `ask-file` |
| `config validate` | Validate effective config | honors `--config`, `--no-config`, `GLOVES_CONFIG` |
| `access paths` | Show one agent's private-path visibility | `--agent` |
| `gpg create` | Create selected agent GPG key | idempotent |
| `gpg fingerprint` | Print selected agent GPG fingerprint | `not found` when key absent |

Global machine output flags:

- `--json` enables JSON output for command results and diagnostics.
- `--error-format <text|json>` remains supported; `--error-format json` is equivalent to `--json`.

## Command Patterns

### Initialize Once Per Root

```bash
gloves --root .openclaw/secrets init
```

### Create and Read Agent Secret

```bash
gloves --root .openclaw/secrets secrets set service/token --generate --ttl 1
gloves --root .openclaw/secrets secrets get service/token
```

### Create Human Access Request and Resolve

```bash
gloves --root .openclaw/secrets request prod/db --reason "deploy migration"
gloves --root .openclaw/secrets requests list
gloves --root .openclaw/secrets requests approve <request-uuid>
gloves --root .openclaw/secrets secrets status prod/db
```

### Human `pass` Secret Handoff to Agent

```bash
# human stores secret in pass
pass insert prod/db

# agent requests access
gloves --root .openclaw/secrets --agent agent-a request prod/db --reason "run migration"

# human resolves request
gloves --root .openclaw/secrets --agent agent-main requests list
gloves --root .openclaw/secrets --agent agent-main requests approve <request-uuid>

# approved agent reads through gloves
GLOVES_GET_PIPE_ALLOWLIST=cat \
gloves --root .openclaw/secrets --agent agent-a secrets get prod/db --pipe-to cat
```

Notes:

- Secret name must match between `pass` and `gloves` request/get.
- If ACL is enabled, requester needs `request/read/status`; reviewer needs `approve/deny`.
- If `gpg denied` occurs, verify `pass show <secret-name>` in reviewer session.
- `requests approve` and `requests deny` require UUID request ids from `requests list`.
- For targeted help, use `gloves help requests approve`, `gloves help secrets set`, `gloves help secrets get`.
- CLI stderr includes stable error codes (`error[E...]`); use `gloves explain <code>`.
- For machine workflows, use `gloves --json ...` or `gloves --error-format json ...`.

Typo suggestion auto-run (disabled by default):

- `GLOVES_SUGGEST_AUTORUN=1`: allow typo auto-run for safe commands.
- `GLOVES_SUGGEST_AUTORUN_RISKY=1`: also allow typo auto-run for mutating commands.
- `GLOVES_SUGGEST_AUTORUN_DELAY_MS=<n>`: countdown before auto-run (default `1200`, max `10000`).

### Verify and Reap Expired State

```bash
gloves --root .openclaw/secrets verify
```

### Audit Trail

```bash
gloves --root .openclaw/secrets audit --limit 25
gloves --root .openclaw/secrets --json audit --limit 200
```

### Start Daemon Sidecar

```bash
# strict startup checks only
gloves --root .openclaw/secrets daemon --check --bind 127.0.0.1:7788

# start daemon
gloves --root .openclaw/secrets daemon --bind 127.0.0.1:7788
```

### Config and Agent Visibility

```bash
gloves --root .openclaw/secrets config validate
gloves --root .openclaw/secrets --json access paths --agent agent-main
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

### Vault Exec with Environment Secrets

Run a command with secrets injected as environment variables:

```bash
# Basic usage - inject secret as env var
gloves --root .openclaw/secrets vault exec myvault --env-secrets API_KEY=github/token -- npx mcp-server

# Shorthand - if env var name matches secret name
gloves --root .openclaw/secrets vault exec myvault --env-secrets github/token -- ./server.sh

# Multiple secrets
gloves --root .openclaw/secrets vault exec myvault --env-secrets API_KEY=github/token,LINEAR_KEY=linear/api-key -- ./server

# Custom TTL
gloves --root .openclaw/secrets vault exec myvault --ttl 30m --env-secrets DB_PASS=shared/db-pass -- ./app
```

Syntax: `--env-secrets KEY=secret-name` or `--env-secrets secret-name` (shorthand)

The command mounts the vault, injects secrets as env vars, runs the command, then automatically unmounts.

See also: `docs/vault-exec.md`
