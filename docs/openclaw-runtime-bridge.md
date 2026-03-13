# OpenClaw Runtime Bridge

This document describes the private, operator-controlled Docker bridge used to inject resolved `gloves://...` secret refs into OpenClaw sandbox containers.

## Support Boundary

- Official support: `@gloves/openclaw` safe metadata and approval tools only.
- Preferred future transport: `gloves-mcp` over stdio for first-class runtime integrations.
- Private integration layer: `gloves-docker-bridge`, a host-side Docker wrapper for `/run/secrets/...` delivery.

Do not treat the Docker bridge as an official OpenClaw API contract. It depends on operator-controlled process start, Docker CLI behavior, and the container metadata you choose to match.

## Secret Refs

The bridge consumes runtime-neutral secret refs:

```text
gloves://agents/devy/api-keys/openai
gloves://shared/database-url
```

The ref is the contract between:

- `gloves`
- the runtime/plugin layer
- the last-mile injector

The bridge resolves refs on the host and writes only the resulting bytes into container tmpfs files under `/run/secrets/...`.

## Bridge Config

Example: [integrations/openclaw/docker-bridge.toml](../integrations/openclaw/docker-bridge.toml)

Key fields:

- `gloves_root`: host runtime root using an absolute host path
- `runtime_root`: host state directory for bridge metadata using an absolute host path
- `docker_bin`: optional real Docker binary path when the launcher cannot provide `GLOVES_DOCKER_REAL_BIN`
- `secret_mount_root`: container tmpfs root
- `tmpfs_spec`: Docker `--tmpfs` spec added to matched containers
- `targets[*].secret_ref`: secret ref to resolve
- `targets[*].container_path`: sandbox file path under `/run/secrets/...`
- `targets[*].agent_id`: optional decrypting agent override
- `targets[*].selector`: labels/env/name matchers for target containers

## Launcher Flow

Example: [integrations/openclaw/launch-openclaw-with-gloves.sh](../integrations/openclaw/launch-openclaw-with-gloves.sh)

The launcher:

1. resolves the real Docker binary before changing `PATH`
2. creates a private shim directory
3. symlinks `docker` to `gloves-docker-bridge`
4. exports `GLOVES_DOCKER_BRIDGE_CONFIG`
5. exports `GLOVES_DOCKER_REAL_BIN` so the bridge uses the same Docker binary the launcher discovered
6. starts OpenClaw with the shimmed `PATH`

This keeps:

- bridge state on the host
- secret resolution on the host
- plaintext out of model-visible tool results
- plaintext out of the workspace mount

## Delivery Model

For matched containers, the bridge:

1. records the container at `docker create` or `docker run`
2. adds a `--tmpfs` mount when `/run/secrets` is missing
3. resolves the configured secret refs on the host
4. writes the bytes via `docker exec -i ...` into `/run/secrets/...`
5. sets restrictive file permissions
6. marks state so later `docker exec` calls do not re-inject unnecessarily
7. resets or removes state on `docker stop` and `docker rm`

Matched foreground `docker run` invocations are rejected up front. Use detached containers or a `create` then `start` flow so the bridge can inject before later `exec` calls.

## When To Use What

- Use `@gloves/openclaw` for safe list/status/request tooling inside OpenClaw.
- Use `gloves-mcp` stdio when you are building a first-class runtime integration that can safely consume a secret side-channel.
- Use the Docker bridge only when you need private last-mile file delivery into sandboxed Docker agents and you control process start and runtime `PATH`.
- Use unix sockets only for compatibility with other local runtimes that already expect a long-lived broker.
- Use loopback TCP `gloves daemon` only for direct host automation.
