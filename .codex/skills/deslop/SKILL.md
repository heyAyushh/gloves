---
name: deslop
description: Remove AI-generated code slop and improve code quality. Use when you need to clean up AI-written code, remove unnecessary defensive patterns, eliminate inconsistent comments, or align code style with the rest of the codebase.
---

# Remove AI Code Slop

Check the diff against main and remove AI-generated slop from this branch.

If the diff is empty and on main/master, scan the entire codebase for AI slop.

## What to Remove

- Extra comments that a human wouldn't add or inconsistent with the file
- Unnecessary defensive checks or try/catch blocks abnormal for that codebase area (especially if called by trusted/validated codepaths)
- Casts to `any` to work around type issues
- Any style inconsistent with the file

## Output

Report with only a 1-3 sentence summary of what was changed.
