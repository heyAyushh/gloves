---
name: clean-gone
description: Clean up git branches marked as [gone] (deleted on remote but still exist locally). Use when you want to prune stale local branches, remove worktrees for deleted branches, or clean up after PR merges.
---

# Clean Gone Branches

Execute the following to clean up stale local branches deleted from the remote.

## Steps

1. **List branches to identify [gone] status**
   ```bash
   git branch -v
   ```
   Note: Branches with '+' prefix have worktrees that must be removed first.

2. **Identify worktrees for [gone] branches**
   ```bash
   git worktree list
   ```

3. **Remove worktrees and delete [gone] branches**
   ```bash
   git branch -v | grep '\[gone\]' | sed 's/^[+* ]//' | awk '{print $1}' | while read branch; do
     echo "Processing branch: $branch"
     worktree=$(git worktree list | grep "\\[$branch\\]" | awk '{print $1}')
     if [ ! -z "$worktree" ] && [ "$worktree" != "$(git rev-parse --show-toplevel)" ]; then
       echo "  Removing worktree: $worktree"
       git worktree remove --force "$worktree"
     fi
     echo "  Deleting branch: $branch"
     git branch -D "$branch"
   done
   ```

## Expected Outcome

- List all local branches with status
- Remove worktrees for [gone] branches
- Delete branches marked as [gone]
- Report which worktrees and branches were removed

If no branches are marked as [gone], report that no cleanup was needed.
