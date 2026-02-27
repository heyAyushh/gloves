---
name: rust-zero-cost-abstractions
description: Guides generic vs trait object decisions in Rust. Use when choosing between static and dynamic dispatch, designing traits, handling E0277/E0038, or deciding between enum and dyn Trait.
---

# Zero-Cost Abstractions

> **Layer 1: Language Mechanics**

## Core Question

**Do we need compile-time or runtime polymorphism?**

Before choosing between generics and trait objects:
- Is the type known at compile time?
- Is a heterogeneous collection needed?
- What's the performance priority?

---

## Thinking Prompt

Before adding trait bounds:

1. **What abstraction is needed?**
   - Same behavior, different types → trait
   - Different behavior, same type → enum
   - No abstraction needed → concrete type

2. **When is type known?**
   - Compile time → generics (static dispatch)
   - Runtime → trait objects (dynamic dispatch)

3. **What's the trade-off priority?**
   - Performance → generics
   - Compile time → trait objects
   - Flexibility → depends

---

## Syntax Comparison

```rust
// Static dispatch — type known at compile time
fn process(x: impl Display) { }      // argument position
fn process<T: Display>(x: T) { }     // explicit generic
fn get() -> impl Display { }         // return position

// Dynamic dispatch — type determined at runtime
fn process(x: &dyn Display) { }      // reference
fn process(x: Box<dyn Display>) { }  // owned
```

## Decision Guide

| Scenario | Choose | Why |
|----------|--------|-----|
| Performance critical | Generics | Zero runtime cost |
| Heterogeneous collection | `dyn Trait` | Different types at runtime |
| Plugin architecture | `dyn Trait` | Unknown types at compile time |
| Reduce compile time | `dyn Trait` | Less monomorphization |
| Small, known type set | `enum` | No indirection |

## Cost Comparison

| Pattern | Dispatch | Code Size | Runtime Cost |
|---------|----------|-----------|--------------|
| `fn foo<T: Trait>()` | Static | +bloat | Zero |
| `fn foo(x: &dyn Trait)` | Dynamic | Minimal | vtable lookup |
| `impl Trait` return | Static | +bloat | Zero |
| `Box<dyn Trait>` | Dynamic | Minimal | Allocation + vtable |

---

## Object Safety

A trait is object-safe if it:
- Doesn't have `Self: Sized` bound
- Doesn't return `Self`
- Doesn't have generic methods
- Uses `where Self: Sized` for non-object-safe methods

## Error Code Reference

| Error | Cause | Fix |
|-------|-------|-----|
| E0277 | Type doesn't impl trait | Add impl or change bound |
| E0308 | Type mismatch | Check generic params |
| E0599 | No method found | Import trait with `use` |
| E0038 | Trait not object-safe | Use generics or redesign |

---

## Anti-Patterns

| Anti-Pattern | Why Bad | Better |
|--------------|---------|--------|
| Over-generic everything | Compile time, complexity | Concrete types when possible |
| `dyn` for known types | Unnecessary indirection | Generics |
| Complex trait hierarchies | Hard to understand | Simpler design |
| Ignore object safety | Limits flexibility | Plan for dyn if needed |

---

## Related Skills

- `type-driven-design` — newtypes and type state
- `performance` — when dispatch cost matters
- `concurrency` — Send/Sync bounds on generics
