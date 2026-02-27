---
name: rust-type-driven-design
description: Guides type-driven design in Rust. Use when encoding invariants in types, applying newtype pattern, implementing type state machines, using PhantomData, or making invalid states unrepresentable.
---

# Type-Driven Design

> **Layer 1: Language Mechanics**

## Core Question

**How can the type system prevent invalid states?**

Before reaching for runtime checks:
- Can the compiler catch this error?
- Can invalid states be unrepresentable?
- Can the type encode the invariant?

---

## Thinking Prompt

Before adding runtime validation:

1. **Can the type encode the constraint?**
   - Numeric range → bounded types or newtypes
   - Valid states → type state pattern
   - Semantic meaning → newtype

2. **When is validation possible?**
   - At construction → validated newtype
   - At state transition → type state
   - Only at runtime → `Result` with clear error

3. **Who needs to know the invariant?**
   - Compiler → type-level encoding
   - API users → clear type signatures
   - Runtime only → documentation

---

## Pattern Quick Reference

| Pattern | Purpose | Example |
|---------|---------|---------|
| Newtype | Type safety | `struct UserId(u64);` |
| Type State | State machine | `Connection<Connected>` |
| PhantomData | Variance/lifetime | `PhantomData<&'a T>` |
| Marker Trait | Capability flag | `trait Validated {}` |
| Builder | Gradual construction | `Builder::new().name("x").build()` |
| Sealed Trait | Prevent external impl | `mod private { pub trait Sealed {} }` |

---

## Pattern Examples

### Newtype — validated domain value

```rust
struct Email(String);  // Not just any string

impl Email {
    pub fn new(s: &str) -> Result<Self, ValidationError> {
        // Validate once, trust forever
        validate_email(s)?;
        Ok(Self(s.to_string()))
    }
}
```

### Type State — compile-time state machine

```rust
struct Connection<State>(TcpStream, PhantomData<State>);

struct Disconnected;
struct Connected;
struct Authenticated;

impl Connection<Disconnected> {
    fn connect(self) -> Connection<Connected> { todo!() }
}

impl Connection<Connected> {
    fn authenticate(self) -> Connection<Authenticated> { todo!() }
}
// compile error if you call authenticate() on Disconnected
```

---

## Decision Guide

| Need | Pattern |
|------|---------|
| Type safety for primitives | Newtype |
| Compile-time state validation | Type State |
| Lifetime/variance markers | PhantomData |
| Capability flags | Marker Trait |
| Gradual construction | Builder |
| Closed set of impls | Sealed Trait |

---

## Anti-Patterns

| Anti-Pattern | Why Bad | Better |
|--------------|---------|--------|
| Boolean flags for states | Runtime errors | Type state |
| String for semantic types | No type safety | Newtype |
| `Option` for uninitialized | Unclear invariant | Builder |
| Public fields with invariants | Invariant violation | Private + validated `new()` |

---

## Related Skills

- `zero-cost-abstractions` — trait design for newtypes
- `error-handling` — validation errors in constructors
- `anti-patterns` — primitive obsession and boolean blindness
