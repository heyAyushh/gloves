# Architecture

This document describes the current `gloves` architecture in the repository.

## Components

- `gloves` CLI
  - manages the encrypted store
  - creates and rotates age identities
  - reads, writes, shows, and re-encrypts namespaced secrets
- `gloves-mcp`
  - authenticates MCP sessions with a session token
  - enforces approval tiers
  - exposes redacted MCP tools such as `gloves_get`, `gloves_set`, and `gloves_rotate`
- `@gloves/client`
  - Bun/TypeScript client that speaks to `gloves-mcp`
  - launches host-local `gloves-mcp` sessions over stdio by default and consumes the secret side-channel
- `@gloves/adapter-core`
  - shared runtime-agnostic adapter helpers for env/tmpfs injection and secret-source resolution
- `@gloves/openclaw`
  - OpenClaw-facing adapter that registers `gloves_get`, `gloves_list`, `gloves_show`, and `gloves_rotate`
  - injects plaintext into environment variables or tmpfs instead of returning it in tool output
- `@openclaw/gloves`
  - packaged OpenClaw plugin that re-exports the adapter and carries plugin manifest metadata

## Adapter Boundary

`gloves-mcp` is the canonical machine-facing interface for runtime integrations.
OpenClaw support lives in `@gloves/openclaw` as an adapter over that interface rather than a
core product boundary. OpenClaw operators should install `@openclaw/gloves` on the Gateway host,
then configure the plugin to launch `gloves-mcp` over stdio. The optional unix socket path exists
only as a compatibility transport for legacy deployments.
Additional runtimes should follow the same pattern with sibling adapters over
`@gloves/adapter-core`.

## Store Layout

The current OpenClaw-oriented store layout is:

```text
<root>/
├── identities/
│   └── <agent>.age
├── store/
│   ├── .gloves.yaml
│   ├── .gloves-meta/
│   ├── agents/
│   └── shared/
└── audit/
```

- `identities/` holds agent age private keys.
- `store/` holds encrypted `.age` files plus namespace `.age-recipients` files.
- `.gloves-meta/` stores redacted metadata used by `show`, `list`, and access bookkeeping.
- `audit/` stores JSONL audit trails.

## Secret Read Flow

Current OpenClaw plugin reads work like this:

1. `@openclaw/gloves` registers plugin tools in the OpenClaw Gateway process.
2. `@gloves/openclaw` receives a `gloves_get` tool call.
3. `@gloves/client` launches a host-local `gloves-mcp` session over stdio by default.
4. `gloves-mcp` validates the session token and agent id.
5. `gloves-mcp` applies approval policy, returns redacted metadata, and delivers plaintext over the MCP secret side-channel.
6. The plugin injects the plaintext into `api.sandbox.env` or tmpfs.
7. The tool return value sent back to the model stays redacted.

This keeps the brokered tool-response model without requiring sandbox bind mounts for host binaries or unix sockets.

## Transport Choices

- OpenClaw default: plugin tools plus stdio child-process sessions to `gloves-mcp`
- Compatibility transport: optional unix socket mode when another runtime needs a long-lived local broker
- Direct host automation: loopback TCP `gloves daemon`

The transports serve different runtimes. OpenClaw should prefer stdio because it avoids exposing a reusable endpoint into the sandbox.

## Docker Verification

The repository Docker harness exercises the OpenClaw-style stdio flow:

1. the sandbox image includes `gloves` and `gloves-mcp`
2. the plugin starts `gloves-mcp` over stdio inside the container
3. decrypted values are injected into env/tmpfs and kept out of tool result bodies
4. cross-agent access and post-rotation access rules are verified end to end

## Rotation Flow

`gloves rotate --agent <id>` currently:

1. validates the current identity
2. generates a staged replacement identity
3. rewrites recipient references in `.age-recipients` files and `.gloves.yaml`
4. runs `updatekeys` with the old identity so existing ciphertext can still be decrypted
5. archives the old identity
6. promotes the staged identity into place

`gloves-mcp` exposes the same operation as `gloves_rotate` for the authenticated agent.

## Approval Model

The current MCP policy tiers are:

- auto: `gloves_list`, `gloves_show`, `gloves_approve`
- human/approval-gated: `gloves_get`, `gloves_set`, `gloves_rotate`
- deny: `gloves_delete`

When approval is required, the server creates a pending request and blocks until another authenticated MCP session resolves it or the request times out.

## Planned Next Steps

The long-form implementation spec still calls for:

- broader production-style end-to-end coverage for Gateway installs
- additional runtime adapters beyond OpenClaw

Those items are not yet the architecture on disk today, so they are tracked as future work rather than described here as completed behavior.
