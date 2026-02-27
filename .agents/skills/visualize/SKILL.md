---
name: visualize
description: Generate Mermaid diagrams from code, architecture, or concepts. Use when you need to visualize code flow, system architecture, data relationships, state machines, sequences, class structures, or any other diagrammable concept.
---

# Visualize - Generate Mermaid Diagram

Analyze input and generate clear, well-structured Mermaid diagrams.

## Workflow

1. **Analyze input** - Understand what to visualize (code flow, architecture, data relationships, state machines, sequences, etc.)

2. **Choose diagram type**:
   - `flowchart` - Process flows, decision trees, algorithms
   - `sequenceDiagram` - API calls, message passing, request/response
   - `classDiagram` - Class structures, inheritance, interfaces
   - `erDiagram` - Database schemas, entity relationships
   - `stateDiagram-v2` - State machines, lifecycle flows
   - `graph TD/LR` - Dependency graphs, module relationships
   - `gitgraph` - Git branching strategies
   - `journey` - User journeys
   - `gantt` - Timelines and schedules

3. **Generate diagram** with:
   - Clear, descriptive node labels
   - Logical grouping with subgraphs where appropriate
   - Consistent styling and direction
   - Meaningful relationship labels on edges
   - Manageable complexity (split if needed)

4. **Output** in mermaid code block:
   ````
   ```mermaid
   [diagram code]
   ```
   ````

## Style Guidelines

- Use descriptive IDs: `userService` not `a1`
- Add labels to relationships when they add clarity
- Use subgraphs to group related components
- Keep readable: max ~15-20 nodes per diagram
- Arrow styles:
  - `-->` solid (main flow)
  - `-.->` dotted (optional/async)
  - `==>` thick (important path)
  - `o-->` circle end (aggregation)
  - `*-->` diamond end (composition)

## After Generating

- Explain what the diagram shows
- Offer to refine or expand specific sections
- Suggest alternative diagram types if applicable
