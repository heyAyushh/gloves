# Quickstart

This quickstart covers local setup plus the basic agent and human workflows.

## Prerequisites

- `gloves` installed (`cargo install gloves` or release script)
- `pass` + GPG installed for human-owned secret workflows
- writable root directory (default `.openclaw/secrets`)

## 1) Confirm installation

```bash
gloves --version
gloves --json --version
```

## 2) Initialize runtime layout

```bash
gloves --root .openclaw/secrets init
```

## 3) Create and read an agent-owned secret

```bash
gloves --root .openclaw/secrets secrets set service/token --generate
gloves --root .openclaw/secrets secrets get service/token
gloves --root .openclaw/secrets list
```

If you omit `--ttl`, `gloves` uses `defaults.secret_ttl_days`; the built-in default is 30 days. Use `--ttl never` for a non-expiring secret. The create command prints the expiry timestamp for expiring secrets and says `never expires` for long-lived ones.

## 4) Run one command with an explicit secret ref

```bash
gloves --root .openclaw/secrets run --env API_KEY=gloves://service/token -- env
gloves --root .openclaw/secrets exec env --env API_KEY=gloves://service/token -- env
```

Use `gloves run` as the default top-level UX.

Use `gloves exec env` when you want to choose the env-delivery mechanic directly.

## 5) Create a human-owned secret and request access

Store secret in `pass` (human side):

```bash
pass insert prod/db/root-password
```

Request access (agent side):

```bash
gloves --root .openclaw/secrets request prod/db/root-password --reason "run migration"
```

List pending requests (review side):

```bash
gloves --root .openclaw/secrets requests list
```

Approve or deny (human reviewer):

```bash
gloves --root .openclaw/secrets requests approve <request-id>
# or
gloves --root .openclaw/secrets requests deny <request-id>
```

Check status:

```bash
gloves --root .openclaw/secrets secrets status prod/db/root-password
```

## 6) Initialize per-agent GPG identity (human workflows)

```bash
gloves --root .openclaw/secrets --agent human-ops gpg create
gloves --root .openclaw/secrets --agent human-ops gpg fingerprint
```

## 7) Verify runtime health

```bash
gloves --root .openclaw/secrets verify
gloves --root .openclaw/secrets audit --limit 25
```

## 8) Use recursive help for command discovery

```bash
gloves help
gloves help secrets
gloves help secrets set
gloves requests help approve
```

## Next Reading

- [Secrets and Requests](secrets-and-requests.md)
- [Humans, Agents, and GPG](humans-agents-and-gpg.md)
- [TUI Guide](tui-guide.md)
- [Troubleshooting](troubleshooting.md)
