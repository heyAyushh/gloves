---
name: init
description: Initialize AGENTS.md documentation for a codebase. Use when setting up a new repository for AI coding assistants, creating project documentation for Claude Code or Cursor, or improving existing AGENTS.md files.
---

# Initialize AGENTS.md

Analyze the codebase and create AGENTS.md documentation for AI assistants.

## What to Include

1. **Commands**: Build, lint, test commands. Include commands to run a single test.
2. **Architecture**: High-level code structure and "big picture" architecture that requires reading multiple files to understand.

## Examples

- https://github.com/openai/codex/blob/main/AGENTS.md
- https://agents.md#examples

## Guidelines

- If AGENTS.md exists, suggest improvements
- Do not repeat yourself or include obvious instructions
- Avoid listing every component or file structure easily discovered
- Don't include generic development practices
- Include important parts from existing `.cursor/rules/`, `.cursorrules`, `.github/copilot-instructions.md`, or `README.md`
- Do not make up information unless expressly included in files read

## File Header

```
# AGENTS.md

This file provides guidance to Claude Code (claude.ai/code) and Cursor IDE (https://cursor.com) when working with code in this repository.
```

## Also Create CLAUDE.md

Create a file called `CLAUDE.md` with:
```
@AGENTS.md
```
