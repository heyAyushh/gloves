# gloves

[![CI](https://github.com/heyAyushh/gloves/actions/workflows/ci.yml/badge.svg)](https://github.com/heyAyushh/gloves/actions/workflows/ci.yml)
[![Tests](https://github.com/heyAyushh/gloves/actions/workflows/test.yml/badge.svg)](https://github.com/heyAyushh/gloves/actions/workflows/test.yml)
[![Coverage](https://github.com/heyAyushh/gloves/actions/workflows/coverage.yml/badge.svg)](https://github.com/heyAyushh/gloves/actions/workflows/coverage.yml)
[![crates.io](https://img.shields.io/crates/v/gloves.svg)](https://crates.io/crates/gloves)

`gloves` is a secure secrets control plane for multi-agent runtimes and human operators.

It provides:

- agent-owned encrypted secrets
- human approval workflows
- access/audit controls
- vault and daemon operations
- an interactive TUI navigator

## Documentation

Start here: [Documentation Index](docs/INDEX.md)

Fast links:

- [Quickstart](docs/quickstart.md)
- [Concepts and Parts](docs/concepts-and-parts.md)
- [Secrets and Requests](docs/secrets-and-requests.md)
- [Humans, Agents, and GPG](docs/humans-agents-and-gpg.md)
- [TUI Guide](docs/tui-guide.md)
- [Configuration Guide](docs/configuration.md)
- [Troubleshooting](docs/troubleshooting.md)
- [VM Multi-Agent Operations](docs/vm-multi-agent-human-guide.md)
- [Security Hardening](docs/security-hardening.md)
- [Release Binaries](docs/release-binaries.md)

## Command Model

Primary command groups:

- `gloves secrets ...`: set/get/grant/revoke/status
- `gloves request ...`: create one pending human request
- `gloves requests ...`: list/approve/deny pending requests
- `gloves vault ...`: encrypted vault operations
- `gloves gpg ...`: per-agent GPG key workflows
- `gloves tui`: interactive command center

Recursive help is supported:

```bash
gloves help
gloves help secrets
gloves help secrets set
gloves secrets help set
gloves requests help approve
```

## Quick Example

```bash
# initialize runtime layout
gloves --root .openclaw/secrets init

# create one secret
gloves --root .openclaw/secrets secrets set service/token --generate --ttl 1

# read secret
gloves --root .openclaw/secrets secrets get service/token

# list entries
gloves --root .openclaw/secrets list
```

For complete setup and human/agent workflows, use [Quickstart](docs/quickstart.md).

## Install

### From release binaries (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/openclaw/gloves/main/scripts/setup-openclaw.sh | bash
```

### From crates.io

```bash
cargo install gloves
```

### From source

```bash
git clone https://github.com/openclaw/gloves
cd gloves
cargo install --path .
```

## Security and Policy

- Use least-privilege agent access in `.gloves.toml`
- Prefer `gloves secrets get --pipe-to <command>` over raw stdout in automation
- Keep secrets root and config permissions private
- Use `gloves audit --json --limit 100` for machine-readable audit export

Details:

- [Configuration Guide](docs/configuration.md)
- [Security Hardening](docs/security-hardening.md)
- [GLOVES Config Spec](GLOVES_CONFIG_SPEC.md)

## Development

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --locked
cargo doc --no-deps
```

## License and Changelog

- [LICENSE](LICENSE)
- [CHANGELOG](CHANGELOG.md)
