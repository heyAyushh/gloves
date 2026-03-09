---
name: gloves
version: 0.1.0
description: Secrets manager workflow for OpenClaw agents. Use when an agent needs to verify a secret exists, read redacted metadata, pipe a secret into a command without exposing it in conversation, or store/update a namespaced secret through the gloves CLI.
author: heyAyushh
tags:
  - security
  - secrets
  - encryption
metadata:
  openclaw:
    requires:
      bins:
        - gloves
    capabilities:
      - secrets_read
      - secrets_write
---

# Gloves OpenClaw Skill

Use this skill to access OpenClaw-oriented secrets safely through `gloves`.

## Workflow

1. Check whether the secret exists with redacted metadata first:
   ```bash
   gloves show <path> --redacted
   ```
2. If a tool or process needs the value, pipe it directly:
   ```bash
   gloves get <path> --format raw | <target-command>
   ```
3. Store or rotate values by sending bytes through stdin or an existing environment variable:
   ```bash
   gloves set <path> --stdin
   gloves set <path> --stdin < secret.txt
   ```
   Or, through the OpenClaw plugin tool surface, use `gloves_set` with `from_env` so the secret comes from an existing environment variable instead of the conversation.
4. Re-encrypt namespaces after recipient changes:
   ```bash
   gloves updatekeys --path <prefix>
   ```
5. Resolve pending human approvals through the tool surface when needed:
   ```bash
   gloves_approve request_id=<uuid> decision=approve
   ```

## Rules

- Never print, echo, or restate a secret value in the conversation.
- Never capture a secret value in a shell variable unless the caller explicitly requires a transient env export and there is no safe pipe alternative.
- Prefer `gloves show --redacted` when asked to “check”, “confirm”, or “display” a secret.
- If a user asks to reveal a secret, refuse and return redacted metadata instead.
- When using OpenClaw tools, prefer `gloves_set` with `from_env` so the value stays in environment plumbing instead of prompt text.
- Use namespaced paths such as `agents/<agent>/api-keys/<provider>` or `shared/<name>`.

## Bundled References

- Read [references/openclaw.json5](references/openclaw.json5) when wiring the MCP/plugin include into OpenClaw config.
