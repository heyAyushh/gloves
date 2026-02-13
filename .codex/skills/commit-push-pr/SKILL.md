---
name: commit-push-pr
description: Complete workflow to commit changes, push to remote, and create a pull request. Use when you want to ship changes end-to-end in one operation, from local changes to an open PR.
---

# Commit, Push, and Create PR

One-shot workflow for committing, pushing, and creating a pull request.

## Preconditions

- Modified files exist
- Remote `origin` is configured
- GitHub CLI (`gh`) is installed
- On a working branch (not main/master)

## Steps

1. **Check branch**
   ```bash
   BRANCH=$(git branch --show-current)
   if [ "$BRANCH" = "main" ] || [ "$BRANCH" = "master" ]; then
     echo "Direct pushes to main/master not allowed"
     exit 1
   fi
   ```

2. **Stage and commit**
   ```bash
   git add -A
   git commit -m "<prefix>: <summary>"
   ```

3. **Push**
   ```bash
   git push -u origin "$BRANCH"
   ```

4. **Create PR**
   ```bash
   gh pr create --title "<prefix>: <summary>" --body "$(cat <<'EOF'
   ## Summary
   - Change description

   ## Test plan
   - How to verify
   EOF
   )"
   ```

## PR Auto-generation Info

When generating PR content, use:
```bash
git branch --show-current              # Branch name for intent
git merge-base origin/main HEAD        # Merge base
git diff --name-status $(git merge-base origin/main HEAD)...HEAD  # Changed files
git log origin/main..HEAD --oneline    # Commit history
```

## Branch Prefix to Commit Prefix

| Branch prefix | Commit prefix |
|---------------|---------------|
| feature/      | feat          |
| fix/          | fix           |
| refactor/     | refactor      |
| perf/         | perf          |
| test/         | test          |
| docs/         | docs          |
| build/        | build         |
| ci/           | ci            |
| chore/        | chore         |

## Troubleshooting

If push succeeded but PR creation failed:
```bash
gh pr create --title "Title" --body "Message" --base main
```
