---
name: commit
description: Commit local changes on the current branch following conventional commit message format. Use when you need to create a git commit without pushing, or when you want to stage and commit changes with a properly formatted message.
---

# Commit Changes

Commit local changes following conventional commit message format.

## Steps

1. **Review uncommitted changes**
   ```bash
   git status
   git diff
   ```

2. **Stage changes**
   ```bash
   git add -A
   ```

3. **Commit with conventional format**
   ```bash
   git commit -m "<prefix>: <summary (imperative, concise)>"
   ```

## Commit Message Format

Use conventional commit prefixes:
- `feat`: New feature
- `fix`: Bug fix
- `refactor`: Code refactoring
- `perf`: Performance improvement
- `test`: Tests
- `docs`: Documentation
- `build`: Build system
- `ci`: CI configuration
- `chore`: Maintenance
- `style`: Code style
- `revert`: Revert changes

Example:
```bash
git add -A && git commit -m "fix: remove unnecessary debug log output"
```

## Notes

- This command only commits; it does not push to remote
- Branch protection policies are out of scope
- Always review diffs before committing
