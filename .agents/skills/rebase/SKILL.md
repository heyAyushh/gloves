---
name: rebase
description: Rebase the current branch with flexible target options. Use when you need to rebase on main, a specific branch, or a remote branch, with intelligent conflict handling.
---

# Rebase

Rebase the current branch.

## Arguments

- No arguments: rebase on local main
- `origin`: fetch origin, rebase on origin/main
- `origin/branch`: fetch origin, rebase on origin/branch
- `branch`: rebase on local branch

## Steps

1. **Parse arguments**
   - No args → target is "main", no fetch
   - Contains "/" (e.g., "origin/develop") → split into remote and branch, fetch remote, target is remote/branch
   - Just "origin" → fetch origin, target is "origin/main"
   - Anything else → target is that branch name, no fetch

2. **Fetch if needed**
   ```bash
   git fetch <remote>
   ```

3. **Rebase**
   ```bash
   git rebase <target>
   ```

4. **Handle conflicts** (if any)

5. **Continue until complete**

## Handling Conflicts

- BEFORE resolving any conflict, understand changes made to each conflicting file in the target branch
- For each conflicting file:
  ```bash
  git log -p -n 3 <target> -- <file>
  ```
- Goal: preserve BOTH target branch changes AND our branch's changes
- After resolving each conflict:
  ```bash
  git add <file>
  git rebase --continue
  ```
- If a conflict is too complex or unclear, ask for guidance before proceeding
