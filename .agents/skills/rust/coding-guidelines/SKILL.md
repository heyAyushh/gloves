---
name: rust-coding-guidelines
description: 50 core Rust coding conventions covering naming, data types, strings, error handling, memory, concurrency, async, and modern crate recommendations. Use when reviewing code style or setting up project conventions.
---

# Rust Coding Guidelines

## Naming (Rust-Specific)

| Rule | Guideline |
|------|-----------|
| No `get_` prefix | `fn name()` not `fn get_name()` |
| Iterator convention | `iter()` / `iter_mut()` / `into_iter()` |
| Conversion naming | `as_` (cheap ref), `to_` (expensive), `into_` (ownership) |
| Constants | `SCREAMING_SNAKE_CASE` for `const`/`static` |

## Data Types

| Rule | Guideline |
|------|-----------|
| Use newtypes | `struct Email(String)` for domain semantics |
| Prefer slice patterns | `if let [first, .., last] = slice` |
| Pre-allocate | `Vec::with_capacity()`, `String::with_capacity()` |
| Avoid Vec abuse | Use arrays for fixed sizes |

## Strings

| Rule | Guideline |
|------|-----------|
| Prefer bytes | `s.bytes()` over `s.chars()` when ASCII |
| Use `Cow<str>` | When might modify borrowed data |
| Use `write!` | Over string concatenation with `+` |
| Avoid nested iteration | `contains()` on string is O(n·m) |

## Error Handling

| Rule | Guideline |
|------|-----------|
| Use `?` propagation | Not `try!()` macro |
| `expect()` over `unwrap()` | When value is guaranteed |
| Assertions for invariants | `assert!` at function entry |

## Memory

| Rule | Guideline |
|------|-----------|
| Meaningful lifetimes | `'src`, `'ctx` not just `'a` |
| `try_borrow()` for RefCell | Avoid panic |
| Shadowing for transformation | `let x = x.parse()?` |

## Concurrency

| Rule | Guideline |
|------|-----------|
| Identify lock ordering | Prevent deadlocks |
| Atomics for primitives | Not `Mutex` for `bool`/`usize` |
| Choose memory order carefully | `Relaxed`/`Acquire`/`Release`/`SeqCst` |

## Async

| Rule | Guideline |
|------|-----------|
| Sync threads for CPU-bound | Async is for I/O |
| Don't hold locks across await | Use scoped guards |

## Macros

| Rule | Guideline |
|------|-----------|
| Avoid unless necessary | Prefer functions/generics |
| Follow Rust syntax | Macro input should look like Rust |

---

## Deprecated → Better

| Deprecated | Better | Since |
|------------|--------|-------|
| `lazy_static!` | `std::sync::OnceLock` | Rust 1.70 |
| `once_cell::Lazy` | `std::sync::LazyLock` | Rust 1.80 |
| `std::sync::mpsc` | `crossbeam::channel` | — |
| `std::sync::Mutex` | `parking_lot::Mutex` | — |
| `failure`/`error-chain` | `thiserror`/`anyhow` | — |
| `try!()` | `?` operator | 2018 edition |

---

## Quick Reference

```
Naming:  snake_case (fn/var), CamelCase (type), SCREAMING_CASE (const)
Format:  rustfmt (just use it)
Docs:    /// for public items, //! for module docs
Lint:    #![warn(clippy::all)]
```

---

## Related Skills

- `anti-patterns` — common style mistakes
- `error-handling` — error crate selection
- `concurrency` — lock ordering and atomics
