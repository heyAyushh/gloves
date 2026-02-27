---
name: refactor
description: Refactor code to improve quality while maintaining functionality. Use when you need to improve code structure, eliminate duplication, optimize performance, or enhance maintainability without changing behavior.
---

# Refactor Code

Improve code quality while maintaining the same functionality.

## Code Quality Improvements

- Extract reusable functions or components
- Eliminate code duplication
- Improve variable and function naming
- Simplify complex logic and reduce nesting

## Performance Optimizations

- Identify and fix performance bottlenecks
- Optimize algorithms and data structures
- Reduce unnecessary computations
- Improve memory usage

## Maintainability

- Make code more readable and self-documenting
- Add appropriate comments where needed
- Follow SOLID principles and design patterns
- Improve error handling and edge case coverage

## Workflow (Karpathy-Inspired)

1. **Think Before Refactoring** - Understand the code's intent and dependencies
   - State assumptions about what the code does
   - Identify why the current structure exists
   - Ask if unclear before changing

2. **Simplicity First** - Make the smallest change that improves quality
   - Extract only when duplication is real, not incidental
   - Prefer clarity over cleverness
   - Don't add flexibility that isn't needed

3. **Surgical Changes** - Touch only what needs improvement
   - Don't "clean up" adjacent code as a side effect
   - Match existing style, even if different from preference
   - Keep refactoring focused on one concern at a time

4. **Goal-Driven Execution** - Define success before starting
   - "Make code more readable" → specific metrics (cyclomatic complexity, naming clarity)
   - "Eliminate duplication" → identify specific duplicated blocks
   - Verify tests pass before and after

## Checklist

- [ ] Understood the code's intent and dependencies
- [ ] Made surgical changes (only touched what needed improvement)
- [ ] Extracted reusable functions or components (where truly duplicated)
- [ ] Eliminated code duplication
- [ ] Improved variable and function naming
- [ ] Simplified complex logic and reduced nesting
- [ ] Identified and fixed performance bottlenecks (with evidence)
- [ ] Made code more readable and self-documenting
- [ ] Followed existing style patterns
- [ ] Tests pass before and after refactoring
