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
gloves --root .openclaw/secrets secrets set service/token --generate --ttl 1
gloves --root .openclaw/secrets secrets get service/token
gloves --root .openclaw/secrets list
```

## 4) Create a human-owned secret and request access

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

## 5) Initialize per-agent GPG identity (human workflows)

```bash
gloves --root .openclaw/secrets --agent human-ops gpg create
gloves --root .openclaw/secrets --agent human-ops gpg fingerprint
```

## 6) Verify runtime health

```bash
gloves --root .openclaw/secrets verify
gloves --root .openclaw/secrets audit --limit 25
```

## 7) Use recursive help for command discovery

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
