# Bootstrap Checklist

## 1. Prerequisites

- `gloves` binary installed.
- `pass` and `gpg` installed for human-secret workflows.
- `gocryptfs`, `fusermount`, and `mountpoint` available when vault workflows are needed.
- Writable secrets root (default: `.openclaw/secrets` or `~/.openclaw/secrets`).

## 2. Install Flows

Release-based setup:

```bash
curl -fsSL https://raw.githubusercontent.com/openclaw/gloves/main/scripts/setup-openclaw.sh | bash
```

Source-based setup from local repository:

```bash
./scripts/setup-openclaw.sh --install-mode source --repo-root "$(pwd)"
```

Install script behavior:

- Installs `gloves` CLI (unless `--skip-cli-install`).
- Installs skills into the destination root:
  - `gloves-cli-usage`
  - `gloves-setup-migrate`
- Initializes secrets root (unless `--skip-init`).

## 3. Fresh Root Initialization

```bash
gloves --version
gloves --json --version
gloves --error-format json --version
gloves --root ~/.openclaw/secrets init
gloves --root ~/.openclaw/secrets config validate
```

## 4. Baseline Config Template

Use a `.gloves.toml` as a checked-in baseline for reproducible setup:

```toml
version = 1

[paths]
root = ".openclaw/secrets"

[defaults]
agent_id = "agent-main"
secret_ttl_days = 1

[secrets.acl.agent-main]
paths = ["*"]
operations = ["read", "write", "list", "revoke", "request", "status", "approve", "deny"]
```

Validate after edits:

```bash
gloves --config .gloves.toml config validate
```
