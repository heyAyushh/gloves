---
name: rust-performance
description: Guides Rust performance optimization. Use when profiling, benchmarking, reducing allocations, improving cache locality, choosing between rayon/async/threads, or applying SIMD/parallelism.
---

# Performance Optimization

> **Layer 2: Design Choices**

## Core Question

**What's the bottleneck, and is optimization worth it?**

Before optimizing:
- Have you measured? (Don't guess)
- What's the acceptable performance target?
- Will optimization add significant complexity?

---

## Thinking Prompt

1. **Have you measured?**
   - Profile first → flamegraph, perf
   - Benchmark → criterion, `cargo bench`
   - Identify actual hotspots

2. **What's the priority?**
   - Algorithm (10x–1000x improvement)
   - Data structure (2x–10x)
   - Allocation reduction (2x–5x)
   - Cache optimization (1.5x–3x)

3. **What's the trade-off?**
   - Complexity vs speed
   - Memory vs CPU
   - Latency vs throughput

---

## Optimization Priority

```
1. Algorithm choice     (10x - 1000x)
2. Data structure       (2x - 10x)
3. Allocation reduction (2x - 5x)
4. Cache optimization   (1.5x - 3x)
5. SIMD/Parallelism     (2x - 8x)
```

---

## Common Techniques

| Technique | When | How |
|-----------|------|-----|
| Pre-allocation | Known size | `Vec::with_capacity(n)` |
| Avoid cloning | Hot paths | Use references or `Cow<T>` |
| Batch operations | Many small ops | Collect then process |
| SmallVec | Usually small | `smallvec::SmallVec<[T; N]>` |
| Inline buffers | Fixed-size data | Arrays over Vec |

## Tooling

| Tool | Purpose |
|------|---------|
| `cargo bench` | Micro-benchmarks |
| `criterion` | Statistical benchmarks |
| `perf` / `flamegraph` | CPU profiling |
| `heaptrack` | Allocation tracking |
| `valgrind` / `cachegrind` | Cache analysis |

---

## Common Mistakes

| Mistake | Why Wrong | Better |
|---------|-----------|--------|
| Optimize without profiling | Wrong target | Profile first |
| Benchmark in debug mode | Meaningless results | Always `--release` |
| Use `LinkedList` | Cache unfriendly | `Vec` or `VecDeque` |
| Hidden `.clone()` in loop | Unnecessary allocs | Use references |
| Premature optimization | Wasted effort | Make it correct first |

---

## Anti-Patterns

| Anti-Pattern | Why Bad | Better |
|--------------|---------|--------|
| Clone to avoid lifetimes | Performance cost | Proper ownership |
| Box everything | Indirection cost | Stack allocation when possible |
| HashMap for small sets | Overhead | Vec with linear search |
| String concat in loop | O(n²) | `String::with_capacity` or write! |

---

## Related Skills

- `ownership` — avoid clones, use references in hot paths
- `concurrency` — rayon for data parallelism, tokio for I/O
- `anti-patterns` — performance anti-patterns
