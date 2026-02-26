# VM Multi-Agent and Human Guide

Back to docs map: [Documentation Index](INDEX.md)

This guide is for operators running `gloves` on a shared VM for both agents and humans.

## 1) Architecture Baseline

- one service account owns the secrets root
- all callers use explicit `--agent <id>`
- config is centralized in one `.gloves.toml`
- agent-owned secrets live in `gloves` encrypted store
- human-owned secrets live in `pass`

## 2) Day-0 Bootstrap

Install prerequisites:

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y pass gnupg gocryptfs fuse3
```

Install `gloves`:

```bash
cargo install gloves
```

Create config (example `/etc/gloves/prod.gloves.toml`):

```toml
version = 1

[paths]
root = "/srv/gloves/prod"

[private_paths]
runtime_root = "/srv/gloves/prod"
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

[agents.agent-main]
paths = ["runtime_root"]
operations = ["read", "write", "list", "mount"]

[agents.agent-workflows]
paths = ["runtime_root"]
operations = ["read", "write", "list", "mount"]

[agents.human-ops]
paths = ["runtime_root", "password_store"]
operations = ["read", "list", "mount"]

[secrets.acl.agent-main]
paths = ["shared/*", "svc/*"]
operations = ["read", "write", "list", "request", "status"]

[secrets.acl.human-ops]
paths = ["*"]
operations = ["read", "write", "list", "revoke", "request", "status", "approve", "deny"]
```

Validate and initialize:

```bash
gloves --config /etc/gloves/prod.gloves.toml config validate
gloves --config /etc/gloves/prod.gloves.toml init
```

Create reviewer GPG identity:

```bash
gloves --config /etc/gloves/prod.gloves.toml --agent human-ops gpg create
```

## 3) Daily Workflows

Agent-owned secret:

```bash
gloves --config /etc/gloves/prod.gloves.toml --agent agent-main \
  secrets set svc/github/token --generate --ttl 7

gloves --config /etc/gloves/prod.gloves.toml --agent agent-main \
  secrets get svc/github/token
```

Human approval flow:

```bash
# human stores canonical value
pass insert prod/db/root-password

# agent requests
gloves --config /etc/gloves/prod.gloves.toml --agent agent-workflows \
  request prod/db/root-password --reason "migration"

# human reviews and resolves
gloves --config /etc/gloves/prod.gloves.toml --agent human-ops requests list
gloves --config /etc/gloves/prod.gloves.toml --agent human-ops requests approve <request-id>

# requester checks
gloves --config /etc/gloves/prod.gloves.toml --agent agent-workflows \
  secrets status prod/db/root-password
```

Vault lifecycle:

```bash
gloves --config /etc/gloves/prod.gloves.toml --agent agent-main \
  vault init agent_data --owner agent

gloves --config /etc/gloves/prod.gloves.toml --agent agent-main \
  vault mount agent_data --ttl 45m

gloves --config /etc/gloves/prod.gloves.toml --agent agent-main \
  vault unmount agent_data
```

## 4) Sidecar Daemon

Preflight:

```bash
gloves --config /etc/gloves/prod.gloves.toml daemon --check --bind 127.0.0.1:7788
```

Run:

```bash
gloves --config /etc/gloves/prod.gloves.toml daemon --bind 127.0.0.1:7788
```

## 5) Operational Cadence

Per deploy:

```bash
gloves --config /etc/gloves/prod.gloves.toml config validate
gloves --config /etc/gloves/prod.gloves.toml verify
```

Hourly or periodic:

```bash
gloves --config /etc/gloves/prod.gloves.toml verify
gloves --config /etc/gloves/prod.gloves.toml audit --limit 100
```

After policy changes:

```bash
gloves --config /etc/gloves/prod.gloves.toml access paths --agent agent-main --json
gloves --config /etc/gloves/prod.gloves.toml access paths --agent human-ops --json
```

## 6) Checklist

- explicit `--agent` everywhere
- least-privilege ACL per role
- short TTL for temporary secrets
- loopback daemon bind only
- periodic verify and audit review

## Related Docs

- [Configuration Guide](configuration.md)
- [Secrets and Requests](secrets-and-requests.md)
- [Humans, Agents, and GPG](humans-agents-and-gpg.md)
- [Security Hardening](security-hardening.md)
