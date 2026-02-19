# Migration Playbooks

## 1. Shared Root + Secret ACL (Primary Path)

Use one root and constrain access with `[secrets.acl.<agent>]`.

### Steps

1. Back up current runtime tree.
2. Create or update `.gloves.toml` with ACL entries.
3. Validate config.
4. Test each agent operation under `--agent`.
5. Cut over automation and supervisors.

Example ACL model:

```toml
version = 1

[paths]
root = "~/.openclaw/secrets"

[defaults]
agent_id = "agent-main"

[secrets.acl.agent-main]
paths = ["github/*", "openclaw/*", "shared/*"]
operations = ["read", "write", "list", "revoke", "request", "status", "approve", "deny"]

[secrets.acl.agent-relationships]
paths = ["contacts/*", "shared/contacts/*"]
operations = ["read", "write", "list", "request", "status"]

[secrets.acl.agent-workflows]
paths = ["workflows/*", "shared/webhooks/*"]
operations = ["read", "write", "list", "request", "status", "approve", "deny"]
```

Validation commands:

```bash
gloves --config .gloves.toml config validate
gloves --root ~/.openclaw/secrets --agent agent-main list
gloves --root ~/.openclaw/secrets --agent agent-relationships list
gloves --root ~/.openclaw/secrets --agent agent-workflows list
```

## 2. Optional Separate Roots For OpenClaw Agents

Use this when you want filesystem-level isolation in addition to ACL.

Suggested layout:

```text
~/.openclaw/secrets/
  agent-main/
  agent-relationships/
  agent-workflows/
  shared/
```

Initialize each root:

```bash
gloves --root ~/.openclaw/secrets/agent-main init
gloves --root ~/.openclaw/secrets/agent-relationships init
gloves --root ~/.openclaw/secrets/agent-workflows init
gloves --root ~/.openclaw/secrets/shared init
```

Migration approach:

1. Export inventory from old root with `list` and metadata backups.
2. Re-create secrets into target roots with `set` and controlled requester approvals.
3. Update agent process configs to use the intended root.
4. Keep shared cross-agent secrets in `shared/` and gate access through approvals/ACL.

## 3. Agent Fingerprint And Audit Verification

Create/read per-agent GPG key fingerprint and record it with deployment notes.

```bash
gloves --root ~/.openclaw/secrets --agent agent-main gpg create
gloves --root ~/.openclaw/secrets --agent agent-main gpg fingerprint
```

Audit checks:

```bash
gloves --root ~/.openclaw/secrets verify
gloves --root ~/.openclaw/secrets list
```

Runtime audit file:

- `<root>/audit.jsonl`

Review for events including secret create/access/revoke, request lifecycle, and fingerprint reads.

## 4. Per-Agent GPG Key Provisioning With Real CLI

For each operational agent identity:

```bash
gloves --root <root> --agent <agent-id> gpg create
gloves --root <root> --agent <agent-id> gpg fingerprint
```

Expectations:

- First `gpg create` prints `created: true`.
- Re-run prints `created: false` and same fingerprint.
- `gpg fingerprint` returns a stable fingerprint.

## 5. Rollback And Post-Migration Verification

Rollback triggers:

- Missing ACL needed for production command.
- Approval path regressions.
- GPG/pass access failures for human-owned secrets.

Rollback procedure:

1. Stop automation that writes to new topology.
2. Re-enable prior config/root mapping.
3. Re-run baseline verification on old topology.

Post-migration verification checklist:

- `gloves --config <config> config validate` passes.
- `gloves --root <root> verify` passes.
- Every agent can perform only intended ACL operations.
- Audit log contains expected events for migration validation commands.
