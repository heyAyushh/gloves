# Multi-Agent and Human Operations Guide (VM)

This guide is for operators running `gloves` inside a virtual machine where multiple agents and humans share a secrets control plane.

Use this as the day-0/day-1 reference for setup, workflows, and security operations.

## Who This Is For

- Platform operators bootstrapping a shared VM runtime
- Agent developers consuming secrets safely in automation
- Human reviewers approving or denying access requests
- Security reviewers validating ACL and audit behavior

## What `gloves` Supports Today

Supported:

- Agent-owned secret lifecycle (`set`, `get`, `revoke`)
- Human approval flow (`request`, `approve`, `deny`, `status`)
- Encrypted vault lifecycle (`vault init`, `mount`, `exec`, `unmount`, `status`, `list`, `ask-file`)
- Safe non-interactive secret forwarding (`get --pipe-to`, `get --pipe-to-args`)
- Loopback-only sidecar daemon (`daemon`)
- Config-driven defaults and ACL (`.gloves.toml`)

## Architecture for One VM

Recommended baseline:

1. One dedicated Linux user owns the secrets root and runs `gloves`.
2. All agent and human actions identify themselves with `--agent <id>`.
3. ACL and defaults are managed centrally in `.gloves.toml`.
4. Human-owned secrets live in `pass`; agent-owned secrets live in `gloves` encrypted store.
5. `gloves verify` runs on a schedule (for TTL cleanup and runtime integrity checks).

If you need strict OS-level tenant isolation, prefer separate VM instances or separate `--root` directories per tenant/environment.

## Day 0: VM Bootstrap

### 1) Install prerequisites

Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y pass gnupg gocryptfs fuse3
```

macOS (for local test VMs):

```bash
brew install pass gnupg gocryptfs
```

Install `gloves`:

```bash
cargo install gloves
```

### 2) Create config

Create `/etc/gloves/prod.gloves.toml`:

```toml
version = 1

[paths]
root = "/srv/gloves/prod"

[private_paths]
runtime_root = "/srv/gloves/prod"
workspace_private = "/srv/agents/workspace/.private"
password_store = "/home/gloves/.password-store"

[daemon]
bind = "127.0.0.1:7788"
io_timeout_seconds = 5
request_limit_bytes = 16384

[vault]
mode = "required"

[defaults]
agent_id = "agent-main"
secret_ttl_days = 7
vault_mount_ttl = "1h"
vault_secret_ttl_days = 365
vault_secret_length_bytes = 64

[agents.agent-main]
paths = ["runtime_root", "workspace_private"]
operations = ["read", "write", "list", "mount"]

[agents.agent-workflows]
paths = ["runtime_root", "workspace_private"]
operations = ["read", "write", "list", "mount"]

[agents.human-ops]
paths = ["runtime_root", "password_store"]
operations = ["read", "list", "mount"]

[agents.human-security]
paths = ["runtime_root", "password_store"]
operations = ["read", "list", "mount"]

[secrets.acl.agent-main]
paths = ["shared/*", "svc/*"]
operations = ["read", "write", "list", "request", "status"]

[secrets.acl.agent-workflows]
paths = ["shared/*", "svc/workflows/*", "vault/*"]
operations = ["read", "write", "list", "request", "status"]

[secrets.acl.human-ops]
paths = ["*"]
operations = ["read", "write", "list", "revoke", "request", "status", "approve", "deny"]

[secrets.acl.human-security]
paths = ["*"]
operations = ["read", "write", "list", "revoke", "request", "status", "approve", "deny"]

[secrets.pipe.commands.curl]
require_url = true
url_prefixes = [
  "https://api.example.com/v1/",
  "http://internal.example.local/health"
]
```

Validate:

```bash
gloves --config /etc/gloves/prod.gloves.toml config validate
```

### 3) Initialize runtime

```bash
gloves --config /etc/gloves/prod.gloves.toml init
```

### 4) Initialize GPG identities for human operators

```bash
gloves --config /etc/gloves/prod.gloves.toml --agent human-ops gpg create
gloves --config /etc/gloves/prod.gloves.toml --agent human-security gpg create
```

### 5) Validate path visibility per agent

```bash
gloves --config /etc/gloves/prod.gloves.toml access paths --agent agent-main --json
gloves --config /etc/gloves/prod.gloves.toml access paths --agent agent-workflows --json
gloves --config /etc/gloves/prod.gloves.toml access paths --agent human-ops --json
```

## Identity and Role Model

Use stable agent IDs and never rely on implicit defaults in automation.

Good pattern:

- `agent-main`
- `agent-workflows`
- `agent-relationships`
- `human-ops`
- `human-security`

Always pass `--agent` in jobs, scripts, and supervisors so audit events map cleanly to caller identity.

## Core Use Cases

### Use case 1: Agent-owned service secret

Create:

```bash
gloves --config /etc/gloves/prod.gloves.toml \
  --agent agent-main \
  set svc/github/token --generate --ttl 7
```

Read in interactive shell (TTY):

```bash
gloves --config /etc/gloves/prod.gloves.toml \
  --agent agent-main \
  get svc/github/token
```

Revoke:

```bash
gloves --config /etc/gloves/prod.gloves.toml \
  --agent agent-main \
  revoke svc/github/token
```

### Use case 2: Human approval flow for sensitive secret

Human operator stores the secret in `pass` first:

```bash
pass insert prod/db/root-password
```

Agent requests:

```bash
gloves --config /etc/gloves/prod.gloves.toml \
  --agent agent-workflows \
  request prod/db/root-password --reason "Run migration 2026-02"
```

Human reviews pending:

```bash
gloves --config /etc/gloves/prod.gloves.toml \
  --agent human-ops \
  list --pending
```

Human approves or denies:

```bash
gloves --config /etc/gloves/prod.gloves.toml \
  --agent human-ops \
  approve <request-uuid>

gloves --config /etc/gloves/prod.gloves.toml \
  --agent human-security \
  deny <request-uuid>
```

Requester checks status:

```bash
gloves --config /etc/gloves/prod.gloves.toml \
  --agent agent-workflows \
  status prod/db/root-password
```

### Use case 3: Vault operations for shared encrypted workspace

Initialize vaults:

```bash
gloves --config /etc/gloves/prod.gloves.toml \
  --agent agent-main \
  vault init agent_data --owner agent

gloves --config /etc/gloves/prod.gloves.toml \
  --agent human-ops \
  vault init personal --owner human
```

Mount, work, unmount:

```bash
gloves --config /etc/gloves/prod.gloves.toml \
  --agent agent-main \
  vault mount agent_data --ttl 45m

# ... read/write files in mountpoint ...

gloves --config /etc/gloves/prod.gloves.toml \
  --agent agent-main \
  vault unmount agent_data
```

Trusted agent handoff prompt:

```bash
gloves --config /etc/gloves/prod.gloves.toml \
  --agent agent-main \
  vault ask-file agent_data \
  --file docs/report.pdf \
  --requester agent-main \
  --trusted-agent agent-workflows \
  --reason "Need report section from mounted vault"
```

Important identity note:

- Global `--agent` controls the default caller identity used by vault internals.
- `vault mount --agent <id>` sets mount session attribution (`mounted_by`), audit identity, and extpass decryption identity.
- `vault exec --agent <id>` uses the same identity behavior, then unmounts automatically after command completion.

In most environments, set global `--agent` explicitly and use `vault mount --agent` only when you intentionally want a different session attribution.

### Use case 4: Secret use in automation with controlled interpolation

Preferred pattern is still `--pipe-to` (stdin stream, byte-safe):

Example wrapper `/usr/local/bin/curl-with-secret`:

```bash
#!/usr/bin/env bash
set -euo pipefail
secret="$(cat)"
exec curl -u "ayush:${secret}" "http://internal.example.local/health"
```

Allowlist and execute:

```bash
export GLOVES_GET_PIPE_ALLOWLIST=curl-with-secret

gloves --config /etc/gloves/prod.gloves.toml \
  --agent agent-main \
  get svc/http/basic-auth-password --pipe-to curl-with-secret
```

Notes:

- `--pipe-to` accepts only bare executable names from `PATH`.
- Keep `GLOVES_GET_PIPE_ALLOWLIST` minimal (one or few trusted commands).

When the downstream command requires argument interpolation, use `--pipe-to-args`:

```bash
export GLOVES_GET_PIPE_ALLOWLIST=curl

gloves --config /etc/gloves/prod.gloves.toml \
  --agent agent-main \
  get svc/http/basic-auth-password \
  --pipe-to-args "curl -u ayush:{secret} http://internal.example.local/health"
```

Security guards for `--pipe-to-args`:

- Command executable must be allowlisted in `GLOVES_GET_PIPE_ALLOWLIST`.
- Optional `GLOVES_GET_PIPE_ARG_POLICY` can lock commands to exact approved templates.
- Optional config URL policy under `[secrets.pipe.commands.<command>]` can lock commands to approved URL prefixes while allowing payload variation.
- Optional `GLOVES_GET_PIPE_URL_POLICY` remains available as env fallback when config has no command policy.
- Template must include `{secret}` placeholder and may not place it in the executable position.
- Secret must be UTF-8 and must not contain control characters (use `--pipe-to` for raw byte-safe flows).
- Interpolated argument buffers are zeroized in-process after command execution.

Example sub-allowlist policy for `curl`:

```bash
export GLOVES_GET_PIPE_ARG_POLICY='{
  "curl": [
    "curl -u ayush:{secret} http://internal.example.local/health"
  ]
}'
```

With this set, a `curl` invocation using different flags/URL is blocked even if `curl` is in `GLOVES_GET_PIPE_ALLOWLIST`.

Example URL-prefix policy for dynamic payloads in config (recommended):

```toml
[secrets.pipe.commands.curl]
require_url = true
url_prefixes = [
  "https://api.example.com/v1/",
  "http://internal.example.local/health"
]
```

Env fallback (same behavior) is still available:

```bash
export GLOVES_GET_PIPE_URL_POLICY='{
  "curl": [
    "https://api.example.com/v1/",
    "http://internal.example.local/health"
  ]
}'
```

With this set, same-URL requests with different payload arguments are allowed, but off-policy URLs are denied.

### Use case 5: Sidecar daemon for orchestrated runtimes

Preflight:

```bash
gloves --config /etc/gloves/prod.gloves.toml daemon --check --bind 127.0.0.1:7788
```

Run:

```bash
gloves --config /etc/gloves/prod.gloves.toml daemon --bind 127.0.0.1:7788
```

Best practice:

- Keep daemon bound to loopback only.
- Pair with process supervision (`systemd` user service or equivalent).

## Best Practices Checklist

### Access and identity

- Always pass explicit `--agent` in automation and human runbooks.
- Use least-privilege ACL per role under `[secrets.acl.<agent>]`.
- Keep wildcard ACL (`"*"`) only for tightly controlled human operator roles.

### Secret handling

- Prefer `set --stdin` or `set --generate`; avoid secrets in shell history.
- Prefer `get --pipe-to` with vetted wrappers for non-TTY automation.
- Use `get --pipe-to-args` only when target tools cannot read stdin and keep allowlists narrow.
- For tools like `curl`, use `GLOVES_GET_PIPE_ARG_POLICY` for exact templates or `[secrets.pipe.commands.<command>]` for URL scoping with flexible payloads.
- Do not persist raw `gloves get` output in logs, tickets, or agent memory summaries.

### Vault handling

- Use short mount TTL values (`15m` to `1h`) unless there is a strong reason for longer.
- Explicitly unmount when work completes; do not depend only on TTL.
- Use `vault mode = "required"` for production so missing dependencies fail fast.

### Runtime hardening

- Use one VM (or root directory) per environment (`dev`, `staging`, `prod`).
- Restrict secrets root ownership and permissions to the service account.
- Store config under controlled path and strict file permissions.
- Run periodic `verify` via timer/service.

### Audit and ops

- Review `audit.jsonl` during incident response and change windows.
- Use `gloves audit --limit 100` for a readable event stream, or `gloves audit --json` for automation.
- Treat `approve`/`deny` as change-controlled operations for high-impact secrets.
- Require reason strings in request workflows with ticket/change IDs.

## Suggested VM Operating Cadence

Per deploy:

```bash
gloves --config /etc/gloves/prod.gloves.toml config validate
gloves --config /etc/gloves/prod.gloves.toml verify
```

Every hour (or similar):

```bash
gloves --config /etc/gloves/prod.gloves.toml verify
```

After permission or ACL changes:

```bash
gloves --config /etc/gloves/prod.gloves.toml access paths --agent agent-main --json
gloves --config /etc/gloves/prod.gloves.toml access paths --agent human-ops --json
```

## Troubleshooting

`vault mode 'required' is set but missing required binaries`:

- Install `gocryptfs`, `fusermount`, and `mountpoint` in the VM image.

`refusing to write secret bytes to non-tty stdout`:

- Use `--pipe-to <allowlisted-command>` for non-interactive contexts.

`pipe command 'X' is not allowlisted`:

- Set `GLOVES_GET_PIPE_ALLOWLIST` to include that command name.

`secret contains control characters` with `--pipe-to-args`:

- Use `--pipe-to` instead so secret bytes are streamed on stdin without argument interpolation.

`missing required environment variable: GLOVES_EXTPASS_ROOT`:

- This is expected if `extpass-get` is run directly. It is an internal helper used by vault extpass wiring.

`forbidden` errors:

- Check `[secrets.acl.<agent>]` path patterns and operation coverage for the calling agent.

## Human and Agent Runbook Template

Use this lightweight template in your ops docs:

1. Caller identity: `--agent <id>`
2. Config path: `--config /etc/gloves/prod.gloves.toml`
3. Action: `request|approve|deny|set|get|vault mount|vault exec|vault unmount`
4. Change reason: include ticket or incident ID
5. Post-check: `list`, `status`, `vault status`, `verify`

This keeps workflows auditable and consistent across both humans and agents.
