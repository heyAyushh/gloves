---
name: iterate-browser
description: Iterate on tasks using debug instrumentation and browser tools. Use when you need to debug web applications, verify frontend behavior, or fix issues without asking the user to manually test.
---

# Iterate with Browser

Debug and iterate using browser tools. Never ask the user to test manually.

## Workflow

1. Add `debug.log` traces to key code locations
2. Use browser tools (`browser_navigate`, `browser_click`, `browser_snapshot`, etc.) to reproduce the issue and collect trace output
3. Analyze traces, identify the problem, and implement a fix
4. Repeat until the issue is resolved

## Key Principle

Never ask the user to "try it out" or "let me know if it works" - verify everything yourself using browser tools and debug.log traces.
