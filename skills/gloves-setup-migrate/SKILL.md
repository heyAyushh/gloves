---
name: gloves-setup-migrate
description: Bootstrap and migrate gloves for OpenClaw multi-agent environments. Use when asked to install/setup gloves, initialize roots, migrate from flat secret layouts, adopt per-agent secret ACLs, introduce optional separate roots, verify agent fingerprints/audit logs, or create per-agent GPG keys.
---

# Gloves Setup And Migration

## Overview

Use this skill when the task is installation, bootstrap, migration, or operational cutover.

Use `gloves-cli-usage` for day-to-day command execution and troubleshooting.

## Workflow

1. Identify whether the environment is fresh setup or migration.
2. Select topology:
   - shared root with secret ACLs (default)
   - optional separate roots per OpenClaw agent
3. Apply setup or migration checklist from references.
4. Validate with real CLI checks (`config validate`, `list`, `verify`, `gpg fingerprint`).
5. Record audit/fingerprint evidence and rollback path before cutover.

## References

- Bootstrap checklist and install flows: `references/bootstrap.md`
- Migration playbooks and verification: `references/migration.md`

## Guardrails

- Never copy raw secret values into docs, notes, or memory.
- Keep all paths under explicit `--root` or configured root values.
- Prefer dry-run style command previews before destructive or broad migration moves.
- Validate before/after state with `gloves verify` and audit log checks.
