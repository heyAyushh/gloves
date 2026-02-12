# gloves
[![CI](https://github.com/heyAyushh/gloves/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/heyAyushh/gloves/actions/workflows/ci-cd.yml)
[![Coverage](https://codecov.io/gh/heyAyushh/gloves/graph/badge.svg?branch=main)](https://codecov.io/gh/heyAyushh/gloves)

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

- Workflow: `.github/workflows/ci-cd.yml`
- CI runs on:
  - pull requests targeting `main`
  - pushes to `main`
- Coverage upload runs only for pull requests targeting `main`.
- Coverage badge source: Codecov (`main` branch).
- Publish runs only on pushes to `main` after CI succeeds.
- Set repository secret `CARGO_REGISTRY_TOKEN` for crates.io publish access.
- Set repository secret `CODECOV_TOKEN` if your Codecov setup requires a token.
