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
- OpenClaw-safe plugin tooling plus a private Docker bridge for sandbox file delivery

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

- `gloves run ...`: run a process with explicit secret-ref bindings
- `gloves exec ...`: run a process with an explicit delivery mechanic
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
# fresh OpenClaw setup
gloves bootstrap --profile openclaw \
  --root .openclaw/secrets \
  --config .openclaw/.gloves.toml \
  --agents main,relationships,coder

# create one namespaced secret
gloves --root .openclaw/secrets set shared/github-token --value ghp_example_token

# run one command with an explicit secret ref
gloves --root .openclaw/secrets run --env API_KEY=gloves://shared/github-token -- env

# read secret
gloves --root .openclaw/secrets get shared/github-token

# list entries
gloves --root .openclaw/secrets list
```

`gloves bootstrap` is intentionally a thin fresh-setup command. It initializes the runtime layout, creates agent identities, writes `.gloves.toml`, writes `store/.gloves.yaml`, and validates the result. It does not migrate existing secrets, patch OpenClaw config files, mutate Docker, or bootstrap GPG by default.

If you omit `--ttl`, `gloves` uses `defaults.secret_ttl_days` from config; the built-in default is 30 days. Use `--ttl never` for a non-expiring secret. `gloves secrets set` prints the expiry timestamp for expiring secrets and says `never expires` otherwise.

## Process Execution

`gloves run` is the top-level process execution UX. It is the closest `gloves` equivalent to `op run`, `doppler run`, and `aws-vault exec`.

Examples:

```bash
gloves run --env API_KEY=gloves://shared/github-token -- curl -H "Authorization: Bearer $API_KEY" https://api.example.com
gloves run --env DB_URL=gloves://shared/db-url -- ./migrate.sh
gloves run --env API_KEY=gloves://shared/github-token --env DB_URL=gloves://shared/db-url -- env
gloves exec env --env API_KEY=gloves://shared/github-token -- env
```

`gloves run` accepts only explicit `NAME=gloves://namespace/secret-path` bindings in v1. It does not accept bare secret paths, comma-separated lists, or implicit "load this whole scope" behavior.

Use `gloves run` when you want the generic "run this command with secrets" flow.

Use `gloves exec env` when you want the lower-level env-delivery primitive directly.

Use `gloves vault exec` when you specifically need the lower-level vault workflow that mounts a vault, executes a command, and unmounts it afterward.

Current delivery model:

- `run` is the high-level UX
- `exec env` is the shipped explicit delivery mechanic
- explicit secret refs are the stable contract between CLI intent and runtime delivery

Planned follow-on strategies:

- `exec file` for tmpfs-style file delivery
- `run --profile ...` for reviewed bundles of refs and delivery policy
- brokered or session-based delivery for backends that can avoid raw env injection entirely

For complete setup and human/agent workflows, use [Quickstart](docs/quickstart.md).

## OpenClaw Integration

The repository now includes:

- `@gloves/openclaw` as the real OpenClaw-native plugin package for safe metadata and approval tools
- `gloves-mcp` as the preferred future stdio transport for first-class runtime integrations
- `gloves-docker-bridge` as a private operator-controlled Docker wrapper for `/run/secrets/...` delivery
- `integrations/openclaw/gloves.json5` as the official safe plugin config snippet
- `integrations/openclaw/docker-bridge.toml` and `integrations/openclaw/launch-openclaw-with-gloves.sh` as the private bridge examples

If you are setting up OpenClaw today, install `@gloves/openclaw` for safe list/status/request tools. Treat the Docker bridge as a private last-mile hack that you operate at process start.

Guaranteed-safe official support:

- install `@gloves/openclaw` on the Gateway host
- point the plugin at a host-local `gloves` binary and runtime root
- allow plugin id `gloves` per agent
- use only:
  - `gloves_list`
  - `gloves_status`
  - `gloves_requests_list`
  - `gloves_request_approve`
  - `gloves_request_deny`

Preferred future transport:

- `gloves-mcp` over stdio for OpenClaw-facing integrations that can safely consume a runtime secret side-channel

Private operator bridge:

- `gloves-docker-bridge` resolves `gloves://...` refs on the host
- it injects tmpfs files under `/run/secrets/...`
- it does not require bind mounts of host secret dirs, `~/.cargo/bin`, token files, or daemon sockets
- it is not an official OpenClaw API integration

Compatibility transports:

- Unix sockets remain available for non-OpenClaw or legacy runtime integrations
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

The bridge regression coverage in `cargo test` covers the private Docker wrapper flow with `/run/secrets/...` injection and cleanup. The example Docker harness remains an operator-oriented validation path rather than an official OpenClaw support contract.

## License and Changelog

- [LICENSE](LICENSE)
- [CHANGELOG](CHANGELOG.md)
