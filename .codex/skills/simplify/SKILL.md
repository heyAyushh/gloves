---
name: simplify
description: Streamline code by removing redundancy and aligning with repo style. Use when you need to consolidate logic, reduce indirection, clean up repeated patterns, or make code more concise following Karpathy's "Simplicity First" principle.
---

# Simplify

Streamline code by removing redundancy and aligning with repo style.

## Philosophy: Simplicity First (Karpathy Guidelines)

Apply principles from [Karpathy Guidelines](../karpathy-guidelines/SKILL.md):

1. **Minimum code that solves the problem** - Nothing speculative
2. **No abstractions for single-use code** - Keep it inline unless reused
3. **No "flexibility" that wasn't requested** - Don't generalize prematurely
4. **No error handling for impossible scenarios** - Handle real cases only

Ask: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## Workflow

1. **Understand** - Read the code and identify its core purpose
   - State what the code does in plain language
   - Identify redundant logic, unnecessary indirection, or repeated patterns
   - Ask if unclear before simplifying

2. **Simplify** - Make the smallest change that improves clarity
   - Consolidate to smaller, clearer units with meaningful names
   - Remove speculative abstractions and unused flexibility
   - Align structure and formatting with existing repo conventions

3. **Verify** - Ensure behavior is preserved
   - Tests pass before and after
   - Edge cases still handled correctly
   - No accidental removal of important functionality

## Constraints

- Prefer minimal, behavior-preserving changes
- Apply changes only within the specified target
- Don't "improve" adjacent code as a side effect
- Match existing style, even if different from preference
