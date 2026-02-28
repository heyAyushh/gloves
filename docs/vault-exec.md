# Vault Exec with Environment Secrets

The `gloves vault exec` command provides a secure way to run commands with secrets injected as environment variables. It mounts a vault, injects specified secrets into the command's environment, executes the command, and automatically unmounts the vault when done.

## Use Cases

- Running MCP servers that require API keys
- Executing scripts that expect secrets in environment variables
- Any command that needs secrets without writing them to disk

## Basic Usage

```bash
# Mount vault, inject secrets as env vars, run command, unmount
gloves --root .openclaw/secrets vault exec myvault --env-secrets API_KEY=github/token -- npx mcp-server

# Shorthand: if KEY matches secret name, just use the secret name
gloves --root .openclaw/secrets vault exec myvault --env-secrets github/token -- ./server.sh

# With custom TTL
gloves --root .openclaw/secrets vault exec myvault --ttl 30m --env-secrets DB_PASSWORD=shared/db-pass -- ./app
```

## Syntax

### Environment Secret Format

```
--env-secrets KEY=secret-name
```

- `KEY`: The environment variable name to set
- `secret-name`: The gloves secret to retrieve and inject

**Shorthand:** If the environment variable name matches the secret name exactly, you can omit the `=secret-name` part:

```bash
# These are equivalent:
--env-secrets github/token
--env-secrets github/token=github/token
```

### Multiple Secrets

Separate multiple secrets with commas:

```bash
gloves vault exec myvault --env-secrets API_KEY=github/token,LINEAR_KEY=linear/api-key,DB_PASS=shared/db-pass -- ./server
```

## Command Structure

```
gloves vault exec <vault-name> [options] -- <command> [args...]

Options:
  --ttl <duration>      Mount session TTL (default: 1h)
  --mountpoint <path>   Custom mountpoint override
  --agent <id>          Agent identity for this exec session
  --env-secrets <spec>  Secret to inject as env var (repeatable)
```

## Examples

### Running an MCP Server

```bash
# Inject Linear API key into MCP server environment
gloves vault exec mcp-servers --env-secrets LINEAR_API_KEY=linear/api-key -- npx @modelcontextprotocol/server-linear

# Or with shorthand if env var matches secret name
gloves vault exec mcp-servers --env-secrets linear/api-key -- npx @modelcontextprotocol/server-linear
```

### Running a Script

```bash
# Script expects DATABASE_URL and API_KEY in environment
gloves vault exec production --env-secrets DATABASE_URL=shared/db-url,API_KEY=shared/api-key -- ./deploy.sh

# Using shorthand
gloves vault exec production --env-secrets shared/db-url -- ./backup.sh
```

### With Custom TTL

```bash
# Longer TTL for long-running processes
gloves vault exec long-running --ttl 4h --env-secrets TOKEN=github/token -- ./worker.sh
```

## How It Works

1. **Mount**: Vault is mounted with the specified TTL
2. **Resolve**: Secrets are retrieved from the gloves store
3. **Inject**: Secrets are injected as environment variables into the command process
4. **Execute**: The specified command runs with the enriched environment
5. **Unmount**: Vault is automatically unmounted (whether command succeeds or fails)

## Security Benefits

- **No disk exposure**: Secrets never touch disk - they're injected directly into process memory
- **Automatic cleanup**: Vault is unmounted immediately after command completes
- **Audit trail**: All secret accesses are logged in the audit log
- **TTL enforcement**: Mounts automatically expire if the command hangs

## Troubleshooting

### Secret not found

Ensure the secret exists in your gloves store:
```bash
gloves --root .openclaw/secrets list
```

### Permission denied

Check your agent ACL allows reading the secret:
```bash
gloves --root .openclaw/secrets access paths --agent your-agent
```

### Command exits but vault stays mounted

This shouldn't happen - the unmount runs in a defer block. If it does, manually unmount:
```bash
gloves --root .openclaw/secrets vault unmount <vault-name>
```

## Integration with MCP

The `--env-secrets` feature is particularly useful for MCP (Model Context Protocol) servers that require API keys:

```bash
# Linear MCP server
gloves vault exec mcp-linear --env-secrets LINEAR_API_KEY=linear/api-key -- npx @modelcontextprotocol/server-linear

# GitHub MCP server  
gloves vault exec mcp-github --env-secrets GITHUB_TOKEN=github/token -- npx @modelcontextprotocol/server-github

# Custom MCP server with multiple secrets
gloves vault exec mcp-custom --env-secrets API_KEY=linear/api-key,DATABASE_URL=shared/db-url -- ./mcp-server
```
