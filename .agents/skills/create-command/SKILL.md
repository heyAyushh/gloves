---
name: create-command
description: Create a new command file following repo conventions. Use when you need to add a new slash command, create automation workflows, or extend the command library with new functionality.
---

# Create Command

Create a new command file matching repo style and structure.

## Steps

1. Choose a concise kebab-case name (e.g., `create-command`)
2. Create file at `configs/commands/<name>.md`
3. Use clear title and short, actionable sections
4. Keep instructions minimal and consistent with existing commands
5. Use backticks for paths and tool names
6. If input is provided, state how to process the target

## Template

```md
# <Command name>

## Overview

<One or two sentences describing intent and scope.>

## Steps

1. <Step one, imperative>
2. <Step two, imperative>
3. <Step three, imperative>

## Notes (optional)

- <Constraints, assumptions, or out-of-scope items>
```

## Install Locally

Copy the new command to your project or global tool folder:

```bash
# Cursor (project)
cp configs/commands/<name>.md .cursor/commands/

# Claude Code (project)
cp configs/commands/<name>.md .claude/commands/
```
