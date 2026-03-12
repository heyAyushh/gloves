# gloves

[![CI](https://github.com/heyAyushh/gloves/actions/workflows/ci.yml/badge.svg)](https://github.com/heyAyushh/gloves/actions/workflows/ci.yml)
[![Tests](https://github.com/heyAyushh/gloves/actions/workflows/test.yml/badge.svg)](https://github.com/heyAyushh/gloves/actions/workflows/test.yml)
[![Coverage](https://github.com/heyAyushh/gloves/actions/workflows/coverage.yml/badge.svg)](https://github.com/heyAyushh/gloves/actions/workflows/coverage.yml)
[![crates.io](https://img.shields.io/crates/v/gloves.svg)](https://crates.io/crates/gloves)
[![docs.rs](https://img.shields.io/docsrs/gloves)](https://docs.rs/gloves)

`gloves` is a secure secrets control plane for multi-agent runtimes and human operators.

It provides:

- agent-owned encrypted secrets
- human approval workflows
- access/audit controls
- vault and daemon operations
- an interactive TUI navigator
- a Bun OpenClaw client/plugin bridge for brokered secret injection

## Documentation

Start here: [Documentation Index](docs/INDEX.md)

API and crate docs: [docs.rs/gloves](https://docs.rs/gloves)

<details>
<summary>Browse guides</summary>

- [Quickstart](docs/quickstart.md)
- [Architecture](ARCHITECTURE.md)
- [Security](SECURITY.md)
- [Concepts and Parts](docs/concepts-and-parts.md)
- [Secrets and Requests](docs/secrets-and-requests.md)
- [Humans, Agents, and GPG](docs/humans-agents-and-gpg.md)
- [TUI Guide](docs/tui-guide.md)
- [Configuration Guide](docs/configuration.md)
- [Troubleshooting](docs/troubleshooting.md)
- [VM Multi-Agent Operations](docs/vm-multi-agent-human-guide.md)
- [Security Hardening](docs/security-hardening.md)
- [Release Binaries](docs/release-binaries.md)

</details>

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
gloves --root .openclaw/secrets secrets set service/token --generate

# read secret
gloves --root .openclaw/secrets secrets get service/token

# list entries
gloves --root .openclaw/secrets list
```

If you omit `--ttl`, `gloves` uses `defaults.secret_ttl_days` from config; the built-in default is 30 days. Use `--ttl never` for a non-expiring secret. `gloves secrets set` prints the expiry timestamp for expiring secrets and says `never expires` otherwise.

For complete setup and human/agent workflows, use [Quickstart](docs/quickstart.md).

## OpenClaw Integration

The repository now includes:

- `gloves-mcp` for redacted MCP tool access
- `@gloves/mcp-client` as the Bun/TypeScript bridge to `gloves-mcp`
- `@gloves/openclaw` as the OpenClaw Gateway plugin, including the secret-delivery logic
- `integrations/openclaw/gloves.json5` as the reference config snippet

If you are setting up OpenClaw, the only package you should install is `@gloves/openclaw`.
The only remaining internal JS package is `@gloves/mcp-client`.

Recommended runtime path:

- install `@gloves/openclaw` on the Gateway host
- let the plugin launch host-local `gloves-mcp` sessions over stdio
- allow the plugin tool group per agent with `group:plugins:gloves`

Current plugin reads keep secret values out of the MCP result body and inject them into the sandbox environment or tmpfs instead. No sandbox bind mount to `~/.cargo/bin`, a daemon socket, or the token path is required for the standard OpenClaw setup.

Compatibility transports:

- `socketPath` remains available for non-OpenClaw or legacy runtime integrations
- `gloves daemon` remains available for direct host-side automation
- neither transport is the preferred OpenClaw deployment path

## Install

### From release binaries (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/openclaw/gloves/main/scripts/setup-openclaw.sh | bash
```

<details>
<summary>Other install options</summary>

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

</details>

## Security and Policy

- Use least-privilege agent access in `.gloves.toml`
- Prefer `gloves secrets get --pipe-to <command>` over raw stdout in automation
- Keep secrets root and config permissions private
- Use `gloves audit --json --limit 100` for machine-readable audit export

Details:

- [Architecture](ARCHITECTURE.md)
- [Security](SECURITY.md)
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

When Docker is available, the OpenClaw sandbox harness can be exercised with:

```bash
bun run docker:e2e
```

That harness now models the recommended OpenClaw flow: a plugin running in the sandbox image launches bundled `gloves-mcp` over stdio and keeps tool responses redacted.

## License and Changelog

- [LICENSE](LICENSE)
- [CHANGELOG](CHANGELOG.md)
