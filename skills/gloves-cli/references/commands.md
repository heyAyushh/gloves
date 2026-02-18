# Gloves CLI Command Reference

## Top-Level

```bash
gloves --root <root> <command> [args...]
```

- Default root: `.openclaw/secrets`
- Primary command router: `src/cli/mod.rs`
- Crypto backend: in-process age-format library (no external rage binary required)

## Commands

| Command | Purpose | Key Flags/Args |
|---|---|---|
| `init` | Create runtime directory/file layout | none |
| `set <name>` | Create an agent-owned secret | `--generate`, `--stdin`, `--value`, `--ttl <days>` (`days > 0`) |
| `get <name>` | Fetch secret value | none |
| `env <name> <var>` | Print redacted export text | none |
| `request <name> --reason <text>` | Open human-access request | `--reason` required |
| `approve <request_id>` | Approve request UUID | request UUID |
| `deny <request_id>` | Deny request UUID | request UUID |
| `list` | Print combined secret metadata and pending requests | none |
| `revoke <name>` | Remove caller-owned secret and metadata | none |
| `status <name>` | Print request status for secret | none |
| `verify` | Reap expired items and verify state | none |
| `daemon` | Run local sidecar daemon | `--check`, `--bind` |

## Command Patterns

### Initialize Once Per Root

```bash
gloves --root .openclaw/secrets init
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

### Verify and Reap Expired State

```bash
gloves --root .openclaw/secrets verify
```

### Start Daemon Sidecar (OpenClaw/systemd)

```bash
# strict startup checks only (includes bind-availability check)
gloves --root .openclaw/secrets daemon --check --bind 127.0.0.1:7788

# start daemon on loopback TCP
gloves --root .openclaw/secrets daemon --bind 127.0.0.1:7788
```

## Runtime Paths

Built by `SecretsPaths` in `src/paths.rs`:
- `<root>/store/` encrypted `*.age` ciphertext
- `<root>/meta/` per-secret metadata JSON
- `<root>/pending.json` request records
- `<root>/audit.jsonl` append-only audit events
- `<root>/default-agent.agekey` generated default age identity
- `<root>/default-agent.signing.key` generated signing key
