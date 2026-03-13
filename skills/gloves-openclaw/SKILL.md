---
name: gloves
version: 0.1.0
description: Secrets manager workflow for OpenClaw operators and agents. Use when you need the safe OpenClaw plugin tools, redacted metadata checks, request review flows, or the private Docker shim examples for `/run/secrets/...` delivery.
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

For OpenClaw runtime setup:

- use the packaged Gateway plugin `@gloves/openclaw` for safe metadata and approval tools
- treat `gloves-mcp` stdio as the preferred future runtime transport
- treat the Docker shim as a private operator bridge, not official OpenClaw support

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
4. Re-encrypt namespaces after recipient changes:
   ```bash
   gloves updatekeys --path <prefix>
   ```
5. Resolve pending human approvals through the official OpenClaw plugin surface when needed:
   ```bash
   gloves_requests_list
   gloves_request_approve request_id=<uuid>
   gloves_request_deny request_id=<uuid>
   ```

## Rules

- Never print, echo, or restate a secret value in the conversation.
- Never capture a secret value in a shell variable unless the caller explicitly requires a transient env export and there is no safe pipe alternative.
- Prefer `gloves show --redacted` when asked to “check”, “confirm”, or “display” a secret.
- If a user asks to reveal a secret, refuse and return redacted metadata instead.
- When using the official OpenClaw plugin, stay inside the safe tool subset:
  - `gloves_list`
  - `gloves_status`
  - `gloves_requests_list`
  - `gloves_request_approve`
  - `gloves_request_deny`
- Do not bind `~/.cargo/bin`, daemon sockets, token files, or host secret directories into the sandbox.
- For private Docker injection, use `gloves://...` refs and the host-side bridge examples instead of printing plaintext into tool results.
- Use namespaced paths such as `agents/<agent>/api-keys/<provider>` or `shared/<name>`.

## Bundled References

- Read [references/openclaw.json5](references/openclaw.json5) when wiring the packaged plugin entry into OpenClaw config.
