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

## 3) Process execution controls

`gloves run --env NAME=gloves://namespace/secret-path -- <command...>` injects explicitly selected secrets as environment variables into one child process.

Safety properties:

- secret values stay out of wrapper JSON/text output
- the wrapped command exit code is preserved
- command execution is audited without logging plaintext values
- secret ACL read policy applies before injection

Use `gloves run` for the generic top-level UX, similar to `op run` or `doppler run`.

`gloves exec env --env NAME=gloves://namespace/secret-path -- <command...>` is the lower-level explicit env-delivery primitive behind `gloves run`.

`gloves vault exec <name> -- <command...>` remains the vault-specific path that mounts, executes, and unmounts.

Current guidance:

- use `run` for the default user-facing flow
- use `exec env` when you need to select env delivery explicitly
- prefer explicit refs over broad scope injection
- treat env delivery as the baseline convenience path, not the final security ceiling

Stronger future delivery strategies are planned around file-based and brokered execution paths so high-risk secrets do not need to ride through process environments.

Additional vault safety properties:

- unmount attempted on success and failure paths
- extpass env vars are removed from wrapped command env

## 4) Runtime hygiene

- Keep daemon loopback-only (`127.0.0.1`).
- Use `GLOVES_DAEMON_TOKEN` for daemon API request authentication.
- For OpenClaw, prefer the packaged Gateway plugin and host-side `gloves-mcp` stdio sessions instead of sandbox bind mounts for binaries, sockets, or token files.
- Treat `socketPath` as a compatibility option for other runtimes, not the default OpenClaw guidance.
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
