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
- `@gloves/openclaw`
  - packaged OpenClaw-native plugin that registers only safe `gloves_*` tools
  - shells out to host-local `gloves` commands for metadata and approval flows
- `gloves-docker-bridge`
  - private operator-controlled Docker wrapper
  - resolves `gloves://...` refs on the host and injects tmpfs files under `/run/secrets/...`

## Adapter Boundary

`gloves` now separates three layers:

1. official OpenClaw support: `@gloves/openclaw` safe tools only
2. preferred future runtime transport: `gloves-mcp` over stdio
3. private last-mile delivery: `gloves-docker-bridge`

The Docker bridge is intentionally outside the official plugin contract. It exists for operators who control OpenClaw process start and need Docker sandbox file delivery today without patching the OpenClaw binary.

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

## Safe OpenClaw Flow

Current official OpenClaw plugin work looks like this:

1. `@gloves/openclaw` registers plugin tools in the OpenClaw Gateway process.
2. OpenClaw calls one of the safe metadata or request-review tools.
3. The plugin runs a host-local `gloves --json ...` command.
4. The CLI returns redacted metadata or request state.
5. The tool result stays plaintext-free.

This path does not depend on undocumented sandbox APIs or plaintext delivery.

## Private Docker Bridge Flow

The private bridge path works like this:

1. the operator starts OpenClaw through a launcher that prepends a `docker` shim to `PATH`
2. OpenClaw issues normal Docker CLI commands without being modified
3. `gloves-docker-bridge` matches target containers by labels, env, image, or name prefix
4. the bridge resolves configured `gloves://...` refs on the host
5. the bridge writes secret bytes into `/run/secrets/...` inside the sandbox tmpfs
6. the bridge records audit events and bridge state on the host

This keeps the last-mile injection private and operator-controlled. It is version-sensitive to Docker/OpenClaw runtime behavior and is not described as official OpenClaw support.

## Transport Choices

- OpenClaw official support today: `@gloves/openclaw` safe tools
- Preferred future OpenClaw transport: stdio child-process sessions to `gloves-mcp`
- Compatibility transport: optional unix socket mode when another runtime needs a long-lived local broker
- Direct host automation: loopback TCP `gloves daemon`

The transports serve different runtimes. OpenClaw should prefer stdio once a first-class runtime contract exists because it avoids exposing a reusable endpoint into the sandbox.

## Generic Process Execution

`gloves` now separates generic process execution into two public layers:

- `gloves run`: high-level user-facing intent surface
- `gloves exec`: lower-level delivery-mechanic surface

In the current release:

- `gloves run --env NAME=gloves://... -- <command...>` is the recommended generic UX
- `gloves exec env --env NAME=gloves://... -- <command...>` is the explicit env-delivery primitive
- `gloves vault exec` remains a separate vault-specific mount / execute / unmount workflow

Both generic command paths compile into the same execution request shape:

- command argv
- secret-ref bindings
- delivery strategy
- runtime hygiene rules

That shared execution layer is what leaves room for future file, profile, and broker/session delivery without another top-level command rewrite.

## Secret Ref Contract

Portable secret refs use the form `gloves://<secret-path>`.

Examples:

- `gloves://agents/devy/api-keys/openai`
- `gloves://shared/database-url`

The ref format is runtime-neutral and is used between:

- `gloves`
- runtime/plugin layers
- host-side last-mile injectors

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
