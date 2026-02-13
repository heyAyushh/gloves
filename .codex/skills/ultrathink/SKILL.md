---
name: ultrathink
description: Deep reasoning mode for complex problems requiring maximum cognitive depth. Use when facing difficult architectural decisions, complex debugging, multi-step problem solving, or situations requiring careful analysis before implementation.
---

# Ultrathink - Deep Reasoning Mode

Engage maximum cognitive depth for complex problems.

## Protocol

### 1. Clarify First

Before implementation, use the AskUserQuestion subagent to:
- Confirm understanding of the core problem
- Surface hidden assumptions
- Identify edge cases and constraints
- Validate success criteria

### 2. Think Deeply

- Break the problem into atomic components
- Consider multiple approaches with trade-offs
- Reason through edge cases and failure modes
- Think about security, performance, and maintainability
- Document your reasoning chain explicitly

### 3. Implement Carefully

- Write code incrementally with clear intent
- Use meaningful names that reveal purpose
- Handle errors explicitly at boundaries
- Keep solutions minimal - no speculative features

### 4. Verify Rigorously

After implementation, invoke the verifier subagent to:
- Confirm the solution addresses the original problem
- Test critical paths and edge cases
- Validate no regressions were introduced
- Ensure code quality standards are met

## Subagent Usage

```
Task(subagent_type="AskUserQuestion", prompt="Clarify X before proceeding...")
Task(subagent_type="verifier", prompt="Verify implementation of X...")
```

## Mindset

- Prefer correctness over speed
- Question assumptions ruthlessly
- Make implicit requirements explicit
- Leave code better than you found it
