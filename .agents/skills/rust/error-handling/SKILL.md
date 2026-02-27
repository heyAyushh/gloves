---
name: rust-error-handling
description: Guides Rust error handling strategy. Use when choosing between Result/Option/panic, using anyhow vs thiserror, propagating errors with ?, or designing custom error types.
---

# Error Handling

> **Layer 1: Language Mechanics**

## Core Question

**Is this failure expected or a bug?**

Before choosing error handling strategy:
- Can this fail in normal operation?
- Who should handle this failure?
- What context does the caller need?

---

## Thinking Prompt

Before handling an error:

1. **What kind of failure is this?**
   - Expected → `Result<T, E>`
   - Absence normal → `Option<T>`
   - Bug/invariant → `panic!`
   - Unrecoverable → `panic!`

2. **Who handles this?**
   - Caller → propagate with `?`
   - Current function → `match`/`if-let`
   - User → friendly error message
   - Programmer → panic with message

3. **What context is needed?**
   - Type of error → thiserror variants
   - Call chain → `anyhow::Context`
   - Debug info → anyhow or tracing

---

## Decision Flowchart

```
Is failure expected?
├─ Yes → Is absence the only "failure"?
│        ├─ Yes → Option<T>
│        └─ No → Result<T, E>
│                 ├─ Library → thiserror
│                 └─ Application → anyhow
└─ No → Is it a bug?
        ├─ Yes → panic!, assert!
        └─ No → Consider if really unrecoverable

Use ? → Need context?
├─ Yes → .context("message")
└─ No → Plain ?
```

---

## Quick Reference

| Pattern | When | Example |
|---------|------|---------|
| `Result<T, E>` | Recoverable error | `fn read() -> Result<String, io::Error>` |
| `Option<T>` | Absence is normal | `fn find() -> Option<&Item>` |
| `?` | Propagate error | `let data = file.read()?;` |
| `unwrap()` | Dev/test only | `config.get("key").unwrap()` |
| `expect()` | Invariant holds | `env.get("HOME").expect("HOME set")` |
| `panic!` | Unrecoverable | `panic!("critical failure")` |

## Library vs Application

| Context | Error Crate | Why |
|---------|-------------|-----|
| Library | `thiserror` | Typed errors for consumers |
| Application | `anyhow` | Ergonomic error handling |
| Mixed | Both | thiserror at boundaries, anyhow internally |

---

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| `.unwrap()` in production | Use `?` or `match` |
| Type mismatch on `?` | Use `anyhow` or `impl From<E>` |
| Lost error context | Add `.context("what was happening")` |
| `Box<dyn Error>` everywhere | Use `thiserror` for typed errors |

---

## Anti-Patterns

| Anti-Pattern | Why Bad | Better |
|--------------|---------|--------|
| `.unwrap()` everywhere | Panics in production | `.expect("reason")` or `?` |
| Ignore errors silently | Bugs hidden | Handle or propagate |
| `panic!` for expected errors | Bad UX, no recovery | Result |
| `Box<dyn Error>` everywhere | Lost type info | thiserror |

---

## Related Skills

- `ownership` — error propagation and ownership
- `type-driven-design` — custom error types with thiserror
- `anti-patterns` — common error handling mistakes
