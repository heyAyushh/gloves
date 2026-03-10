#!/usr/bin/env bun

import { mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";

import glovesPlugin, {
  type PluginAPI,
  type PluginToolDefinition,
} from "../packages/openclaw-gloves/src/index";

type ConversationRecord =
  | { tool: string; response: Record<string, unknown> }
  | { tool: string; error: string };

const TMPFS_PATH = "/run/secrets";
const DEFAULT_INJECT_ENV = "ANTHROPIC_API_KEY";

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`missing required environment variable ${name}`);
  }
  return value;
}

async function main() {
  const agentId = requiredEnv("GLOVES_AGENT_ID");
  const ownSecretPath = requiredEnv("GLOVES_OWN_SECRET");
  const otherSecretPath = requiredEnv("GLOVES_OTHER_SECRET");
  const root = requiredEnv("GLOVES_ROOT");
  const mcpConfigPath = requiredEnv("GLOVES_MCP_CONFIG");
  const tokenPath = requiredEnv("GLOVES_TOKEN_PATH");
  const socketPath = requiredEnv("GLOVES_SOCKET");
  const artifactsDir = requiredEnv("GLOVES_ARTIFACTS_DIR");
  const injectAs = process.env.GLOVES_INJECT_AS || DEFAULT_INJECT_ENV;

  mkdirSync(TMPFS_PATH, { recursive: true });
  mkdirSync(artifactsDir, { recursive: true });

  const tools = new Map<string, PluginToolDefinition>();
  const shutdownCallbacks: Array<() => void | Promise<void>> = [];
  const injectedEnv = new Map<string, string>();
  const conversation: ConversationRecord[] = [];

  const plugin = glovesPlugin({
    root,
    mcpConfigPath,
    tokenPath,
    socketPath,
    injectMode: "both",
    tmpfsPath: TMPFS_PATH,
  });

  const api: PluginAPI = {
    agent: { id: agentId },
    sandbox: {
      env: {
        set(name, value) {
          injectedEnv.set(name, value);
        },
        get(name) {
          return injectedEnv.get(name);
        },
      },
      writeFile(path, contents, options) {
        writeFileSync(path, contents, { mode: options?.mode ?? 0o600 });
      },
    },
    registerTool(name, definition) {
      tools.set(name, definition);
    },
    onShutdown(callback) {
      shutdownCallbacks.push(callback);
    },
  };

  try {
    await plugin.init(api);

    const getResult = await tools.get("gloves_get")!.handler({
      path: ownSecretPath,
      inject_as: injectAs,
    });
    conversation.push({ tool: "gloves_get", response: getResult });

    const firstValue = injectedEnv.get(injectAs);
    if (!firstValue) {
      throw new Error(`gloves_get did not inject ${injectAs}`);
    }
    if (JSON.stringify(getResult).includes(firstValue)) {
      throw new Error("gloves_get leaked the secret value in the tool response");
    }
    const tmpfsValue = readFileSync(join(TMPFS_PATH, injectAs), "utf8");
    if (tmpfsValue !== firstValue) {
      throw new Error("tmpfs secret injection did not match the environment injection");
    }

    let crossAgentDenied = false;
    let crossAgentError = "";
    try {
      await tools.get("gloves_get")!.handler({
        path: otherSecretPath,
        inject_as: "WEBHOOK_TOKEN",
      });
      throw new Error("cross-agent secret access unexpectedly succeeded");
    } catch (error) {
      crossAgentError = error instanceof Error ? error.message : String(error);
      crossAgentDenied =
        crossAgentError.includes("Permission denied")
        || crossAgentError.includes("Operation denied");
      conversation.push({ tool: "gloves_get_cross_agent", error: crossAgentError });
      if (!crossAgentDenied) {
        throw error;
      }
    }

    const rotateResult = await tools.get("gloves_rotate")!.handler({
      agent_id: agentId,
    });
    conversation.push({ tool: "gloves_rotate", response: rotateResult });

    const postRotateResult = await tools.get("gloves_get")!.handler({
      path: ownSecretPath,
      inject_as: injectAs,
    });
    conversation.push({ tool: "gloves_get_after_rotate", response: postRotateResult });

    const secondValue = injectedEnv.get(injectAs);
    if (!secondValue) {
      throw new Error(`post-rotate gloves_get did not inject ${injectAs}`);
    }
    if (secondValue !== firstValue) {
      throw new Error("rotated secret injection returned a different plaintext value");
    }
    if (JSON.stringify(postRotateResult).includes(secondValue)) {
      throw new Error("post-rotate gloves_get leaked the secret value in the tool response");
    }

    const summary = {
      success: true,
      agent: agentId,
      ownSecretPath,
      otherSecretPath,
      crossAgentDenied,
      crossAgentError,
      injectedTargets: [injectAs],
      conversationEntries: conversation.length,
      tmpfsPath: join(TMPFS_PATH, injectAs),
    };
    writeFileSync(
      join(artifactsDir, "conversation.json"),
      `${JSON.stringify(conversation, null, 2)}\n`,
    );
    writeFileSync(
      join(artifactsDir, "result.json"),
      `${JSON.stringify(summary, null, 2)}\n`,
    );
    process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  } finally {
    for (const callback of shutdownCallbacks) {
      await callback();
    }
  }
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
});
