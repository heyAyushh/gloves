# gloves
[![CI](https://github.com/heyAyushh/gloves/actions/workflows/ci.yml/badge.svg)](https://github.com/heyAyushh/gloves/actions/workflows/ci.yml)
[![Tests](https://github.com/heyAyushh/gloves/actions/workflows/test.yml/badge.svg)](https://github.com/heyAyushh/gloves/actions/workflows/test.yml)
[![Coverage](https://github.com/heyAyushh/gloves/actions/workflows/coverage.yml/badge.svg)](https://github.com/heyAyushh/gloves/actions/workflows/coverage.yml)

`gloves` is a dual-backend secrets manager for OpenClaw-style multi-agent environments.

- Human backend: reads human-owned secrets through `pass`
- Agent backend: encrypts agent-owned secrets using `age` recipients
- Unified API: one router for `set`, `get`, `grant`, `revoke`, `request`, and `list`

## Security Model

- Secret values use a non-`Debug` wrapper (`SecretValue`) to avoid accidental logging
- Agent secrets are encrypted on disk (`.age`) with per-recipient access
- Metadata, pending requests, and audit events are persisted as JSON/JSONL
- TTL reaper removes expired encrypted files and metadata

## Install

```bash
cargo install --path .
```

## CLI Usage

Initialize storage:

```bash
gloves --root .openclaw/secrets init
```

Set a generated agent secret with 1-day TTL:

```bash
gloves --root .openclaw/secrets set service/token --generate --ttl 1
```

List entries:

```bash
gloves --root .openclaw/secrets list
```

Create a human-access request:

```bash
gloves --root .openclaw/secrets request prod/db --reason "deploy migration"
```

Verify and reap expired items:

```bash
gloves --root .openclaw/secrets verify
```

## Development

```bash
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo doc --no-deps
cargo publish --dry-run
```

## CI/CD

- Workflows:
  - `.github/workflows/ci.yml`
  - `.github/workflows/test.yml`
  - `.github/workflows/coverage.yml`
  - `.github/workflows/publish.yml`
- CI (lint/docs) runs on pull requests targeting `main` and direct pushes to `main`.
- Test and coverage gates run on pull requests targeting `main` and direct pushes to `main`.
- Coverage is computed locally in GitHub Actions via `cargo-llvm-cov` with threshold gates.
- Publish runs only on pushes to `main`.
- Set repository secret `CARGO_REGISTRY_TOKEN` for crates.io publish access.
