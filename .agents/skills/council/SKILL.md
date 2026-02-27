---
name: council
description: Multi-agent exploration and task delegation for complex areas of interest. Use when you need to deeply explore a codebase area, gather information from multiple perspectives, or delegate parallel research tasks for comprehensive analysis.
---

# Council

Multi-agent exploration workflow for complex codebase analysis.

## Workflow

1. **Initial exploration**: Dig around the codebase for the given area of interest. Gather keywords, architecture overview, and general context.

2. **Spawn task agents**: Launch n=10 parallel task agents (unless specified otherwise) to explore deeper. Some agents should take unconventional approaches for variance.

3. **Synthesize results**: Once agents complete, use gathered information to fulfill the user's request.

## Usage

If the user is in plan mode, use the collected information to create the plan.

Example invocation:
```
Based on [area of interest], spawn 10 agents to explore:
- Core implementation patterns
- Edge cases and error handling
- Integration points
- Test coverage
- Documentation gaps
- Performance characteristics
- Security considerations
- Alternative approaches
- Historical context (git history)
- Related systems
```
