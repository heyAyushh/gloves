# Security

`gloves` protects agent and human secrets by combining encrypted-at-rest storage, recipient-scoped identities, approval policy, and redacted tool results.

## Core Invariants

- Secret values never appear in the LLM context when accessed through the OpenClaw plugin flow.
- Secret values are stored only as age-encrypted `.age` files under the gloves store.
- Agent identities stay on the host and are written with `0600` permissions.
- Cross-agent access is denied unless the caller's recipient is present in the secret recipient set.
- Destructive operations are denied by default in the current MCP server policy.

## Threat Model

The current design assumes:

- the host machine is trusted to hold identities and the encrypted store
- sandboxed agents are less trusted than the host
- OpenClaw tool results may be visible to the model and must therefore stay redacted
- approval operators may need to review secret access before decryption proceeds

The main threats addressed today are:

- accidental secret disclosure into conversation history
- unauthorized decrypt attempts from the wrong agent identity
- stale keys retaining access after rotation or re-encryption
- secret leakage through ordinary tool text output

## Current Controls

### Encrypted Store

- Each secret is encrypted to one or more age recipients.
- `.gloves.yaml` creation rules and namespace `.age-recipients` files define who can decrypt a path.
- `gloves updatekeys` and `gloves rotate` re-encrypt secrets when recipients change.

### Identity Handling

- `gloves set-identity` creates age identities per agent.
- Identity files live under `identities/` and are restricted to `0600`.
- `gloves rotate` archives the old identity and re-encrypts secrets to the new recipient.

### Redacted Tool Results

- `gloves show` returns metadata only.
- `gloves-mcp` returns redacted metadata for `gloves_get`; it does not place the plaintext in the MCP result body.
- The Bun plugin injects the plaintext into sandbox environment variables or tmpfs files and returns only a redacted confirmation.

### Session Authentication and Approval

- `gloves-mcp` writes a per-process session token and rejects unauthenticated MCP initialization.
- Read/write tools go through approval-tier checks.
- The current server supports auto approval and operator-mediated approval through pending requests plus `gloves_approve`.

### Auditability

- `gloves-mcp` appends JSONL audit records for startup, auth failures, reads, writes, approvals, and rotation.

## Operational Guidance

- For OpenClaw, prefer the packaged Gateway plugin (`@openclaw/gloves`) over direct MCP server wiring in agent config.
- Let the plugin launch `gloves-mcp` on the host over stdio; omit `socketPath` unless you are keeping a legacy unix-socket deployment.
- Prefer `injectMode: "env"` or `injectMode: "both"` only when the sandbox lifecycle is tightly controlled.
- Use tmpfs injection for file-based secrets, never the writable project tree.
- Keep the store root, identities, session token path, and `gloves-mcp` binary on the host side instead of bind-mounting them into the sandbox.
- Rotate identities after operator turnover or suspected exposure.
- Use the Docker harness as a regression check for redaction, cross-agent denial, and rotation safety in the stdio plugin flow.

## Current Gaps

The following protections are not complete yet:

- The production Docker end-to-end suite described in the implementation plan.

Those gaps mean the project already enforces the brokered model at the tool-result boundary, but it is not yet at the final production architecture described in the long-form spec.
