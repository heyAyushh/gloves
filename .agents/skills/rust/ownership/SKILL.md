---
name: rust-ownership
description: Guides ownership, borrowing, and lifetime decisions in Rust. Use when encountering E0382, E0597, E0506, E0507, move errors, or when designing data ownership.
---

# Ownership & Lifetimes

> **Layer 1: Language Mechanics**

## Core Question

**Who should own this data, and for how long?**

Before fixing ownership errors, understand the data's role:
- Is it shared or exclusive?
- Is it short-lived or long-lived?
- Is it transformed or just read?

---

## Error → Design Question

| Error | Don't Just Say | Ask Instead |
|-------|----------------|-------------|
| E0382 | "Clone it" | Who should own this data? |
| E0597 | "Extend lifetime" | Is the scope boundary correct? |
| E0506 | "End borrow first" | Should mutation happen elsewhere? |
| E0507 | "Clone before move" | Why are we moving from a reference? |
| E0515 | "Return owned" | Should caller own the data? |
| E0716 | "Bind to variable" | Why is this temporary? |
| E0106 | "Add 'a" | What is the actual lifetime relationship? |

---

## Thinking Prompt

Before fixing an ownership error, ask:

1. **What is this data's domain role?**
   - Entity (unique identity) → owned
   - Value Object (interchangeable) → clone/copy OK
   - Temporary (computation result) → maybe restructure

2. **Is the ownership design intentional?**
   - By design → work within constraints
   - Accidental → consider redesign

3. **Fix symptom or redesign?**
   - If Strike 3 (3rd attempt) → escalate to design layer

---

## Quick Reference

| Pattern | Ownership | Cost | Use When |
|---------|-----------|------|----------|
| Move | Transfer | Zero | Caller doesn't need data |
| `&T` | Borrow | Zero | Read-only access |
| `&mut T` | Exclusive borrow | Zero | Need to modify |
| `clone()` | Duplicate | Alloc + copy | Actually need a copy |
| `Rc<T>` | Shared (single) | Ref count | Single-thread sharing |
| `Arc<T>` | Shared (multi) | Atomic ref count | Multi-thread sharing |
| `Cow<T>` | Clone-on-write | Alloc if mutated | Might modify |

## Error Code Reference

| Error | Cause | Fix |
|-------|-------|-----|
| E0382 | Value moved | Clone, reference, or redesign ownership |
| E0597 | Reference outlives owner | Extend owner scope or restructure |
| E0506 | Assign while borrowed | End borrow before mutation |
| E0507 | Move out of borrowed | Clone or use reference |
| E0515 | Return local reference | Return owned value |
| E0716 | Temporary dropped | Bind to variable |
| E0106 | Missing lifetime | Add `'a` annotation |

---

## Anti-Patterns

| Anti-Pattern | Why Bad | Better |
|--------------|---------|--------|
| `.clone()` everywhere | Hides design issues | Design ownership properly |
| Fight borrow checker | Increases complexity | Work with the compiler |
| `'static` for everything | Restricts flexibility | Use appropriate lifetimes |
| Leak with `Box::leak` | Memory leak | Proper lifetime design |

---

## Related Skills

- `zero-cost-abstractions` — static vs dynamic dispatch
- `type-driven-design` — newtype and type state patterns
- `concurrency` — Send/Sync and shared state
- `anti-patterns` — common ownership mistakes
