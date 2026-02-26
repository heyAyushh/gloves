# Configuration Guide

`gloves` supports bootstrap configuration through `.gloves.toml`.

Full schema: [GLOVES_CONFIG_SPEC.md](../GLOVES_CONFIG_SPEC.md)

## Resolution Order

Config source precedence:

1. `--no-config` (skip all config loading)
2. `--config <path>`
3. `GLOVES_CONFIG`
4. parent-directory discovery of `.gloves.toml`
5. built-in defaults

## Minimal Example

```toml
version = 1

[paths]
root = ".openclaw/secrets"

[defaults]
agent_id = "default-agent"
secret_ttl_days = 1

[vault]
mode = "auto"
```

## Agent Path Visibility and Operations

```toml
[private_paths]
runtime_root = ".openclaw/secrets"
workspace_private = "./.private"

[agents.agent-main]
paths = ["runtime_root", "workspace_private"]
operations = ["read", "write", "list", "mount"]
```

Inspect one agent's view:

```bash
gloves access paths --agent agent-main --json
```

## Secret ACL Policy

```toml
[secrets.acl.agent-main]
paths = ["shared/*", "svc/*"]
operations = ["read", "write", "list", "request", "status"]

[secrets.acl.human-ops]
paths = ["*"]
operations = ["read", "write", "list", "revoke", "request", "status", "approve", "deny"]
```

## URL Policy for `secrets get --pipe-to-args`

```toml
[secrets.pipe.commands.curl]
require_url = true
url_prefixes = ["https://api.example.com/v1/"]
```

This restricts URL arguments to approved prefixes.

## Validation

```bash
gloves config validate
```

Use this in CI and before deploy.

## Related Docs

- [Concepts and Parts](concepts-and-parts.md)
- [Secrets and Requests](secrets-and-requests.md)
- [Security Hardening](security-hardening.md)
- [VM Multi-Agent Operations](vm-multi-agent-human-guide.md)
