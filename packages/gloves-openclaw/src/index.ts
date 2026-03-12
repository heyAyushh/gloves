import {
  defaultSecretEnvName,
  injectSecretValue,
  resolveSecretValueFromSources,
  validateSecretInjectionConfig,
  type SecretEnvironment,
  type SecretInjectMode,
} from "@gloves/adapter-core";
import { GlovesClient, type GlovesClientConfig } from "@gloves/client";

export interface GlovesPluginConfig extends Omit<GlovesClientConfig, "agentId"> {
  injectMode: SecretInjectMode;
  tmpfsPath?: string;
}

export interface PluginToolDefinition {
  description: string;
  parameters: Record<string, unknown>;
  handler: (argumentsValue: Record<string, unknown>) => Promise<Record<string, unknown>>;
}

export interface PluginAPI {
  agent: { id: string };
  sandbox: {
    env: SecretEnvironment;
    writeFile?: (path: string, contents: string, options?: { mode?: number }) => Promise<void> | void;
  };
  registerTool: (name: string, definition: PluginToolDefinition) => void;
  onShutdown: (callback: () => void | Promise<void>) => void;
}

export interface OpenClawPlugin {
  name: string;
  version: string;
  init: (api: PluginAPI) => Promise<void>;
}

export default function glovesPlugin(config: GlovesPluginConfig): OpenClawPlugin {
  return {
    name: "gloves",
    version: "0.1.1",
    async init(api: PluginAPI) {
      validatePluginConfig(config, api);
      const client = await GlovesClient.connect({
        ...config,
        agentId: api.agent.id,
      });

      api.registerTool("gloves_get", {
        description: "Retrieve a secret for the current agent and inject it without exposing the value.",
        parameters: {
          path: { type: "string", required: true },
          inject_as: { type: "string", required: false },
        },
        handler: async ({ path, inject_as }) => {
          const secretPath = expectString(path, "path");
          const result = await client.get(secretPath);
          const injection = await injectSecretValue(
            secretPath,
            result.value,
            typeof inject_as === "string" ? inject_as : undefined,
            config,
            api.sandbox,
          );

          return {
            success: true,
            injected: true,
            inject_target: injection.injectTarget,
            inject_method: injection.injectMethod,
            message: `Secret '${secretPath}' (${result.metadata.length} chars) injected as ${injection.injectTarget}`,
          };
        },
      });

      api.registerTool("gloves_list", {
        description: "List available secret names for the current agent.",
        parameters: {
          prefix: { type: "string", required: false },
        },
        handler: async ({ prefix }) => {
          const names = await client.list(typeof prefix === "string" ? prefix : undefined);
          return { secrets: names, count: names.length };
        },
      });

      api.registerTool("gloves_show", {
        description: "Show secret metadata without exposing the value.",
        parameters: {
          path: { type: "string", required: true },
        },
        handler: async ({ path }) => {
          return await client.show(expectString(path, "path"));
        },
      });

      api.registerTool("gloves_set", {
        description: "Store a secret from an existing environment variable without exposing the value.",
        parameters: {
          path: { type: "string", required: true },
          from_env: { type: "string", required: true },
        },
        handler: async ({ path, from_env }) => {
          const secretPath = expectString(path, "path");
          const envName = expectString(from_env, "from_env");
          const secretValue = resolveSecretValueFromSources(envName, {
            readEnvironment: api.sandbox.env.get,
            readProcessEnvironment: (name) => process.env[name],
          });
          await client.set(secretPath, secretValue);
          return {
            success: true,
            stored: true,
            path: secretPath,
            from_env: envName,
            length: secretValue.length,
            message: `Secret '${secretPath}' stored from ${envName}`,
          };
        },
      });

      api.registerTool("gloves_approve", {
        description: "Approve or deny a pending secret-access request.",
        parameters: {
          request_id: { type: "string", required: true },
          decision: { type: "string", required: true },
          reason: { type: "string", required: false },
        },
        handler: async ({ request_id, decision, reason }) => {
          const requestId = expectString(request_id, "request_id");
          const parsedDecision = expectDecision(decision);
          const parsedReason = typeof reason === "string" && reason.length > 0 ? reason : undefined;
          await client.approve(requestId, parsedDecision, parsedReason);
          return {
            success: true,
            request_id: requestId,
            decision: parsedDecision,
          };
        },
      });

      api.registerTool("gloves_delete", {
        description: "Attempt to delete a secret. The daemon denies destructive operations by policy.",
        parameters: {
          path: { type: "string", required: true },
        },
        handler: async ({ path }) => {
          const secretPath = expectString(path, "path");
          await client.delete(secretPath);
          return {
            success: true,
            deleted: true,
            path: secretPath,
          };
        },
      });

      api.registerTool("gloves_rotate", {
        description: "Rotate the current agent identity and re-encrypt affected secrets.",
        parameters: {
          agent_id: { type: "string", required: false },
        },
        handler: async ({ agent_id }) => {
          const requestedAgent = typeof agent_id === "string" && agent_id.length > 0
            ? agent_id
            : api.agent.id;
          if (requestedAgent !== api.agent.id) {
            throw new Error("gloves_rotate may only rotate the current agent");
          }

          await client.rotate(requestedAgent);
          return {
            success: true,
            agent: requestedAgent,
            rotated: true,
          };
        },
      });

      api.onShutdown(() => client.disconnect());
    },
  };
}

function expectString(value: unknown, fieldName: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`tool argument '${fieldName}' must be a non-empty string`);
  }
  return value;
}

function expectDecision(value: unknown): "approve" | "deny" {
  const decision = expectString(value, "decision");
  if (decision === "approve" || decision === "deny") {
    return decision;
  }
  throw new Error("tool argument 'decision' must be 'approve' or 'deny'");
}

function validatePluginConfig(config: GlovesPluginConfig, api: PluginAPI): void {
  try {
    validateSecretInjectionConfig(config, api.sandbox);
  } catch (error) {
    if (error instanceof Error) {
      if (error.message.includes("tmpfsPath")) {
        throw new Error("tmpfs injection requires tmpfsPath at plugin startup");
      }
      if (error.message.includes("file writer")) {
        throw new Error("tmpfs injection requires api.sandbox.writeFile at plugin startup");
      }
    }
    throw error;
  }
}
