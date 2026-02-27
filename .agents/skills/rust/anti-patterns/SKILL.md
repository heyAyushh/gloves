---
name: rust-anti-patterns
description: Identifies and fixes common Rust anti-patterns. Use during code review, when seeing excessive clones/unwraps/index loops, or when code fights the borrow checker instead of working with it.
---

# Anti-Patterns

> **Layer 2: Design Choices**

## Core Question

**Is this pattern hiding a design problem?**

When reviewing code:
- Is this solving the symptom or the cause?
- Is there a more idiomatic approach?
- Does this fight or flow with Rust?

---

## Top 5 Beginner Mistakes

| Rank | Mistake | Fix |
|------|---------|-----|
| 1 | Clone to escape borrow checker | Use references |
| 2 | Unwrap in production | Propagate with `?` |
| 3 | String for everything | Use `&str` |
| 4 | Index loops | Use iterators |
| 5 | Fighting lifetimes | Restructure to own data |

---

## Anti-Pattern Reference

| Anti-Pattern | Why Bad | Better |
|--------------|---------|--------|
| `.clone()` everywhere | Hides ownership issues | Proper references or ownership |
| `.unwrap()` in production | Runtime panics | `?`, `expect`, or matching |
| `Rc` when single owner | Unnecessary overhead | Simple ownership |
| `unsafe` for convenience | UB risk | Find safe pattern |
| OOP via `Deref` | Misleading API | Composition, traits |
| Giant match arms | Unmaintainable | Extract to methods |
| `String` everywhere | Allocation waste | `&str`, `Cow<str>` |
| Ignoring `#[must_use]` | Lost errors | Handle or `let _ =` |

---

## Code Smell → Refactoring

| Smell | Indicates | Refactoring |
|-------|-----------|-------------|
| Many `.clone()` | Ownership unclear | Clarify data flow |
| Many `.unwrap()` | Error handling missing | Add proper handling |
| Many `pub` fields | Encapsulation broken | Private + accessors |
| Deep nesting | Complex logic | Extract methods |
| Long functions | Multiple responsibilities | Split |
| Giant enums | Missing abstraction | Trait + types |

---

## Quick Review Checklist

- [ ] No `.clone()` without justification
- [ ] No `.unwrap()` in library code
- [ ] No `pub` fields with invariants
- [ ] No index loops when iterator works
- [ ] No `String` where `&str` suffices
- [ ] No ignored `#[must_use]` warnings
- [ ] No `unsafe` without `// SAFETY:` comment
- [ ] No giant functions (>50 lines)

---

## Deprecated → Better

| Deprecated | Better |
|------------|--------|
| Index-based loops | `.iter()`, `.enumerate()` |
| `collect::<Vec<_>>()` then iterate | Chain iterators |
| Manual unsafe cell | `Cell`, `RefCell` |
| `mem::transmute` for casts | `as` or `TryFrom` |
| Custom linked list | `Vec`, `VecDeque` |
| `lazy_static!` | `std::sync::OnceLock` |
| `once_cell::Lazy` | `std::sync::LazyLock` |

---

## Related Skills

- `ownership` — fixing ownership anti-patterns
- `error-handling` — replacing unwrap chains
- `performance` — fixing allocation anti-patterns
- `type-driven-design` — fixing primitive obsession
