# Troubleshooting

This page focuses on common CLI and workflow confusion points.

## `approve requests` fails with invalid id

Symptom:

```text
error[E102]: invalid input: `requests` is a label, not a request id
```

Cause:

- `approve` expects one request UUID, not the literal word `requests`.

Fix:

```bash
gloves requests list
gloves requests approve <request-id>
# or
gloves requests deny <request-id>
```

## I cannot find command docs for subcommands

Use recursive help:

```bash
gloves help
gloves help secrets
gloves help secrets set
gloves requests help approve
```

## `forbidden` errors

Cause:

- caller identity and ACL policy do not allow requested operation/path.

Checks:

```bash
gloves access paths --agent <id> --json
gloves config validate
```

Then review `[secrets.acl.<agent>]` in config.

## `gpg fingerprint` says key not found

Create key first:

```bash
gloves --agent <id> gpg create
gloves --agent <id> gpg fingerprint
```

## Vault command fails due missing binaries

Install required binaries:

- `gocryptfs`
- `fusermount`
- `mountpoint`

If your policy is strict, set `vault.mode = "required"` and run `gloves config validate`.

## TUI output pane seems stuck or empty

- Ensure you triggered run with `Enter` cycle or `r`.
- Check status bar for run state.
- Use `End` or `G` to re-enable follow-tail.
- Use `c` only when you want to clear run history cards.
- Cancel active run with `Ctrl+C`.

## Diagnostics Toolkit

```bash
gloves --json --version
gloves --error-format json --version
gloves config validate
gloves verify
gloves audit --limit 50
gloves audit --json --limit 200
```

## Related Docs

- [Quickstart](quickstart.md)
- [TUI Guide](tui-guide.md)
- [Configuration Guide](configuration.md)
- [Security Hardening](security-hardening.md)
