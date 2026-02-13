---
name: commit-push
description: Commit changes and push to the current branch remote. Use when you want to commit local changes and push them upstream in one workflow, with branch protection against main/master.
---

# Commit and Push

Commit changes on the current branch and push to the remote.

## Steps

1. **Check branch (prevent direct pushes to main/master)**
   ```bash
   BRANCH=$(git branch --show-current)
   if [ "$BRANCH" = "main" ] || [ "$BRANCH" = "master" ]; then
     echo "Direct pushes to main/master are not allowed"
     exit 1
   fi
   ```

2. **Stage changes**
   ```bash
   git add -A
   ```

3. **Commit**
   ```bash
   git commit -m "<prefix>: <summary (imperative, concise)>"
   ```

4. **Push**
   ```bash
   git push -u origin "$BRANCH"
   ```

## One-liner

```bash
MSG="fix: remove unnecessary debug log output" \
BRANCH=$(git branch --show-current) && \
if [ "$BRANCH" = "main" ] || [ "$BRANCH" = "master" ]; then \
  echo "Direct pushes to main/master not allowed"; exit 1; \
fi && \
git add -A && git commit -m "$MSG" && git push -u origin "$BRANCH"
```

## Notes

- Always review diffs with `git status` or `git diff` before executing
- Use conventional commit prefixes: feat, fix, refactor, perf, test, docs, build, ci, chore, style, revert
