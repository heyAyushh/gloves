---
name: rust-concurrency
description: Guides concurrency and async decisions in Rust. Use when encountering Send/Sync errors (E0277), choosing between threads vs async, designing shared state, or debugging deadlocks.
---

# Concurrency

> **Layer 1: Language Mechanics**

## Core Question

**Is this CPU-bound or I/O-bound, and what's the sharing model?**

Before choosing concurrency primitives:
- What's the workload type?
- What data needs to be shared?
- What's the thread safety requirement?

---

## Thinking Prompt

Before adding concurrency:

1. **What's the workload?**
   - CPU-bound → threads (`std::thread`, rayon)
   - I/O-bound → async (tokio, async-std)
   - Mixed → hybrid approach

2. **What's the sharing model?**
   - No sharing → message passing (channels)
   - Immutable sharing → `Arc<T>`
   - Mutable sharing → `Arc<Mutex<T>>` or `Arc<RwLock<T>>`

3. **What are the Send/Sync requirements?**
   - Cross-thread ownership → `Send`
   - Cross-thread references → `Sync`
   - Single-thread async → `spawn_local`

---

## Decision Flowchart

```
What type of work?
├─ CPU-bound → std::thread or rayon
├─ I/O-bound → async/await
└─ Mixed → hybrid (spawn_blocking)

Need to share data?
├─ No → message passing (channels)
├─ Immutable → Arc<T>
└─ Mutable →
   ├─ Read-heavy → Arc<RwLock<T>>
   └─ Write-heavy → Arc<Mutex<T>>
   └─ Simple counter → AtomicUsize

Async context?
├─ Type is Send → tokio::spawn
├─ Type is !Send → spawn_local
└─ Blocking code → spawn_blocking
```

---

## Send/Sync Markers

| Marker | Meaning | Example |
|--------|---------|---------|
| `Send` | Can transfer ownership between threads | Most types |
| `Sync` | Can share references between threads | `Arc<T>` |
| `!Send` | Must stay on one thread | `Rc<T>` |
| `!Sync` | No shared refs across threads | `RefCell<T>` |

## Quick Reference

| Pattern | Thread-Safe | Blocking | Use When |
|---------|-------------|----------|----------|
| `std::thread` | Yes | Yes | CPU-bound parallelism |
| `async/await` | Yes | No | I/O-bound concurrency |
| `Mutex<T>` | Yes | Yes | Shared mutable state |
| `RwLock<T>` | Yes | Yes | Read-heavy shared state |
| `mpsc::channel` | Yes | Optional | Message passing |
| `Arc<Mutex<T>>` | Yes | Yes | Shared mutable across threads |

---

## Async-Specific Patterns

### Avoid MutexGuard Across Await

```rust
// Bad: guard held across await
let guard = mutex.lock().await;
do_async().await;  // guard still held!

// Good: scope the lock
{
    let guard = mutex.lock().await;
    // use guard
}  // guard dropped
do_async().await;
```

### Non-Send Types in Async

```rust
// Rc is !Send, can't cross await in spawned task
// Option 1: use Arc instead
// Option 2: use spawn_local (single-thread runtime)
// Option 3: ensure Rc is dropped before .await
```

---

## Error → Design Question

| Error | Don't Just Say | Ask Instead |
|-------|----------------|-------------|
| E0277 Send | "Add Send bound" | Should this type cross threads? |
| E0277 Sync | "Wrap in Mutex" | Is shared access really needed? |
| Future not Send | "Use spawn_local" | Is async the right choice? |
| Deadlock | "Reorder locks" | Is the locking design correct? |

---

## Anti-Patterns

| Anti-Pattern | Why Bad | Better |
|--------------|---------|--------|
| `Arc<Mutex<T>>` everywhere | Contention, complexity | Message passing |
| `thread::sleep` in async | Blocks executor | `tokio::time::sleep` |
| Holding locks across await | Blocks other tasks | Scope locks tightly |
| Ignoring deadlock risk | Hard to debug | Lock ordering, `try_lock` |

---

## Related Skills

- `ownership` — data ownership and borrowing
- `performance` — choosing between rayon, threads, and async for throughput
- `anti-patterns` — common concurrency mistakes
