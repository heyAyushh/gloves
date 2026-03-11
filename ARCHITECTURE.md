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
  - currently uses MCP for authorization and metadata, then falls back to local CLI reads for plaintext retrieval
- `@gloves/adapter-core`
  - shared runtime-agnostic adapter helpers for env/tmpfs injection and secret-source resolution
- `@gloves/openclaw`
  - OpenClaw-facing adapter that registers `gloves_get`, `gloves_list`, `gloves_show`, and `gloves_rotate`
  - injects plaintext into environment variables or tmpfs instead of returning it in tool output

## Adapter Boundary

`gloves-mcp` is the canonical machine-facing interface for runtime integrations.
OpenClaw support lives in `@gloves/openclaw` as an adapter over that interface rather than a
core product boundary. `@openclaw/gloves` remains available as a deprecated compatibility shim.
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

1. `@gloves/openclaw` receives a `gloves_get` tool call.
2. `@gloves/client` opens an MCP session to `gloves-mcp`.
3. `gloves-mcp` validates the session token and agent id.
4. `gloves-mcp` applies approval policy and returns only redacted metadata.
5. `@gloves/client` reads the plaintext locally through `gloves get --format raw`.
6. The plugin injects the plaintext into `api.sandbox.env` or tmpfs.
7. The tool return value sent back to the model stays redacted.

This preserves the brokered tool-response model even though the client still uses a local CLI fallback for plaintext bytes.

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

- a native client transport instead of the CLI plaintext fallback
- the production Docker end-to-end integration suite

Those items are not yet the architecture on disk today, so they are tracked as future work rather than described here as completed behavior.
