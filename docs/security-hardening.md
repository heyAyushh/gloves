# Security Hardening

Back to docs map: [Documentation Index](INDEX.md)

This guide captures security controls and hardening guidance for `gloves`.

## 1) Secret forwarding controls

`gloves secrets get` supports two non-interactive modes:

- `--pipe-to <command>`: stream raw secret bytes to stdin
- `--pipe-to-args "<command> {secret}"`: interpolate UTF-8 secret text into args

Guardrails:

- Executable must be a bare command name.
- Executable must be allowlisted by `GLOVES_GET_PIPE_ALLOWLIST`.
- `--pipe-to` and `--pipe-to-args` are mutually exclusive.
- `--pipe-to-args` must include `{secret}` and cannot use `{secret}` as executable.
- `--pipe-to-args` rejects control characters in secret input.

Extra policy options:

- `GLOVES_GET_PIPE_ARG_POLICY`: exact template allowlist
- `.gloves.toml [secrets.pipe.commands.<command>]`: URL-prefix policy
- `GLOVES_GET_PIPE_URL_POLICY`: env fallback URL-prefix policy

Example config URL policy:

```toml
[secrets.pipe.commands.curl]
require_url = true
url_prefixes = ["https://api.example.com/v1/"]
```

## 2) Request policy controls

Controls:

- `GLOVES_REQUEST_ALLOWLIST`
- `GLOVES_REQUEST_BLOCKLIST`
- `gloves request --allowlist ... --blocklist ...`

Pattern formats:

- `*`
- `namespace/*`
- exact secret id (`namespace/name`)

## 3) Vault execution controls

`gloves vault exec <name> -- <command...>` mounts, executes, and unmounts.

Safety properties:

- unmount attempted on success and failure paths
- wrapped command exit code is preserved
- extpass env vars are removed from wrapped command env

## 4) Runtime hygiene

- Keep daemon loopback-only (`127.0.0.1`).
- Use `GLOVES_DAEMON_TOKEN` for daemon API request authentication.
- Keep config + runtime root permissions private.
- Never persist raw secret values in logs or memory summaries.

## 5) Verification cadence

Run routinely:

```bash
gloves config validate
gloves verify
gloves audit --json --limit 200
```

## 6) Recommended defaults

- Prefer stdin-based flows (`secrets set --stdin`, `secrets get --pipe-to`).
- Use least-privilege ACL per agent.
- Use short TTL values for temporary secrets and vault mounts.
- Require explicit `--agent` in automation.

## Related Docs

- [Configuration Guide](configuration.md)
- [Secrets and Requests](secrets-and-requests.md)
- [Troubleshooting](troubleshooting.md)
- [VM Multi-Agent Operations](vm-multi-agent-human-guide.md)
