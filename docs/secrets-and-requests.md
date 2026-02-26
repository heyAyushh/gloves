# Secrets and Requests

This guide covers daily command usage for secret lifecycle and human approval workflows.

## Command Map

| Area | Command |
|---|---|
| Create/update secret | `gloves secrets set <name>` |
| Read secret | `gloves secrets get <name>` |
| Share secret with agent | `gloves secrets grant <name> --to <agent>` |
| Remove secret | `gloves secrets revoke <name>` |
| Create request for human-owned secret | `gloves request <name> --reason <text>` |
| List pending requests | `gloves requests list` |
| Approve pending request | `gloves requests approve <request-id>` |
| Deny pending request | `gloves requests deny <request-id>` |
| Request status by secret | `gloves secrets status <name>` |

## Secret Lifecycle

Create from generated value:

```bash
gloves secrets set svc/github/token --generate --ttl 7
```

Create from stdin:

```bash
printf 'token-value' | gloves secrets set svc/github/token --stdin --ttl 7
```

Read:

```bash
gloves secrets get svc/github/token
```

Grant to another agent:

```bash
gloves --agent agent-main secrets grant svc/github/token --to agent-workflows
```

Revoke:

```bash
gloves secrets revoke svc/github/token
```

## Human Request Lifecycle

Create request:

```bash
gloves --agent agent-workflows request prod/db/root-password --reason "migration"
```

Review queue:

```bash
gloves --agent human-ops requests list
```

Resolve:

```bash
gloves --agent human-ops requests approve <request-id>
# or
gloves --agent human-ops requests deny <request-id>
```

Check by secret id:

```bash
gloves --agent agent-workflows secrets status prod/db/root-password
```

## List Behavior

- `gloves list` lists secret entries.
- `gloves requests list` lists pending request queue.

Use `requests list` when you want approval workflow navigation.

## Actor x Action Matrix

| Action | Agent caller | Human caller |
|---|---|---|
| `secrets set/get` on agent-owned secret | Yes (policy-dependent) | Yes (if acting as configured agent id) |
| `request` for human-owned secret | Yes | Yes |
| `requests approve/deny` | Yes if policy permits | Yes (recommended for reviewers) |
| `secrets grant` | Only secret creator agent | Only if acting as secret creator identity |
| `gpg create/fingerprint` | Yes | Yes |

## Non-interactive Secret Use

Safer automation (stdin stream):

```bash
export GLOVES_GET_PIPE_ALLOWLIST=curl-with-secret
gloves secrets get svc/http/password --pipe-to curl-with-secret
```

Argument interpolation mode:

```bash
export GLOVES_GET_PIPE_ALLOWLIST=curl
gloves secrets get svc/http/password --pipe-to-args "curl -u user:{secret} https://api.example.com/v1/health"
```

For strict policy, define URL prefixes in `.gloves.toml`:

```toml
[secrets.pipe.commands.curl]
require_url = true
url_prefixes = ["https://api.example.com/v1/"]
```

## Related Docs

- [Humans, Agents, and GPG](humans-agents-and-gpg.md)
- [Configuration Guide](configuration.md)
- [Security Hardening](security-hardening.md)
- [Troubleshooting](troubleshooting.md)
