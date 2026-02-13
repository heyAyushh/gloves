---
name: fix-pr
description: Read all suggested PR changes and apply them directly to the codebase. Use when you have PR review comments to address, suggested changes to implement, or feedback to incorporate into your code.
---

# Fix PR

Apply suggested PR changes to the codebase.

## Workflow

1. Identify the relevant local branch and remote for the PR using `gh` CLI
2. Read all files changed in the PR or current diff
3. Read all suggested changes, review comments, or instructions
4. Understand the intent behind each suggestion
5. Apply suggested changes to relevant files
6. Fix bugs, unsafe patterns, or incorrect logic discovered
7. Refactor minimally to keep code correct and maintainable
8. Preserve existing behavior unless change is explicitly requested
9. Avoid breaking public APIs unless explicitly instructed

## Rules

- Make the smallest possible changes that fully satisfy suggestions
- Do not introduce new dependencies unless required
- Prefer clarity and correctness over cleverness
- If a suggestion is ambiguous, choose the safest reasonable implementation

## After Completing

- Summarize all modifications made
- List assumptions, trade-offs, or remaining risks
- Call out anything that could not be safely fixed
