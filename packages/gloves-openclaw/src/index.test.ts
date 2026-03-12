import { readFileSync } from "node:fs";

import { afterEach, describe, expect, mock, test } from "bun:test";

import glovesPlugin, { type PluginAPI, type PluginToolDefinition } from "./index";
import {
  createGlovesFixture,
  ensureGlovesBinaries,
  type GlovesFixture,
} from "../../gloves-client/src/testing";

let fixture: GlovesFixture | null = null;

ensureGlovesBinaries();

afterEach(() => {
  fixture?.cleanup();
  fixture = null;
});

describe("@gloves/openclaw", () => {
  test("registers tools and injects secrets without returning raw values", async () => {
    fixture = createGlovesFixture();
    const tools = new Map<string, PluginToolDefinition>();
    const envSet = mock(() => {});
    const envGet = mock((name: string) => {
      if (name === "OPENAI_API_KEY") {
        return "sk-proj-written-from-plugin";
      }
      return undefined;
    });
    const writeFile = mock(async () => {});
    const shutdownCallbacks: Array<() => void | Promise<void>> = [];

    const plugin = glovesPlugin({
      root: fixture.root,
      mcpConfigPath: fixture.mcpConfigPath,
      tokenPath: fixture.tokenPath,
      socketPath: fixture.socketPath,
      glovesBin: "/definitely-unused-gloves-binary",
      glovesMcpBin: fixture.glovesMcpBin,
      injectMode: "both",
      tmpfsPath: "/run/secrets",
    });

    const api: PluginAPI = {
      agent: { id: "devy" },
      sandbox: {
        env: { set: envSet, get: envGet },
        writeFile,
      },
      registerTool(name, definition) {
        tools.set(name, definition);
      },
      onShutdown(callback) {
        shutdownCallbacks.push(callback);
      },
    };

    await plugin.init(api);
    expect(tools.has("gloves_get")).toBe(true);
    expect(tools.has("gloves_list")).toBe(true);
    expect(tools.has("gloves_show")).toBe(true);
    expect(tools.has("gloves_set")).toBe(true);
    expect(tools.has("gloves_approve")).toBe(true);
    expect(tools.has("gloves_delete")).toBe(true);
    expect(tools.has("gloves_rotate")).toBe(true);

    const getResult = await tools.get("gloves_get")!.handler({
      path: fixture.secretPath,
      inject_as: "ANTHROPIC_API_KEY",
    });

    expect(envSet).toHaveBeenCalledWith("ANTHROPIC_API_KEY", fixture.secretValue);
    expect(writeFile).toHaveBeenCalledWith("/run/secrets/ANTHROPIC_API_KEY", fixture.secretValue, {
      mode: 0o600,
    });
    expect(JSON.stringify(getResult)).not.toContain(fixture.secretValue);
    expect(getResult.injected).toBe(true);

    const listResult = await tools.get("gloves_list")!.handler({ prefix: "agents/devy" });
    expect(listResult.count).toBeGreaterThanOrEqual(1);

    const showResult = await tools.get("gloves_show")!.handler({ path: fixture.secretPath });
    expect(showResult.name).toBe(fixture.secretPath);

    const setResult = await tools.get("gloves_set")!.handler({
      path: "agents/devy/api-keys/openai",
      from_env: "OPENAI_API_KEY",
    });
    expect(envGet).toHaveBeenCalledWith("OPENAI_API_KEY");
    expect(JSON.stringify(setResult)).not.toContain("sk-proj-written-from-plugin");
    expect(setResult.stored).toBe(true);

    const showStoredResult = await tools.get("gloves_show")!.handler({
      path: "agents/devy/api-keys/openai",
    });
    expect(showStoredResult.length).toBe("sk-proj-written-from-plugin".length);

    await expect(
      tools.get("gloves_delete")!.handler({ path: fixture.secretPath }),
    ).rejects.toThrow("Operation denied");

    const rotateResult = await tools.get("gloves_rotate")!.handler({});
    expect(rotateResult.agent).toBe("devy");
    expect(rotateResult.rotated).toBe(true);

    for (const callback of shutdownCallbacks) {
      await callback();
    }
  });

  test("fails fast when tmpfs injection has no tmpfsPath", async () => {
    const plugin = glovesPlugin({
      root: "/tmp/gloves",
      mcpConfigPath: "/tmp/gloves.toml",
      tokenPath: "/tmp/session-token",
      injectMode: "tmpfs",
    });

    const api: PluginAPI = {
      agent: { id: "devy" },
      sandbox: {
        env: { set() {} },
        writeFile: async () => {},
      },
      registerTool() {},
      onShutdown() {},
    };

    await expect(plugin.init(api)).rejects.toThrow("tmpfsPath");
  });

  test("fails fast when tmpfs injection has no sandbox writer", async () => {
    const plugin = glovesPlugin({
      root: "/tmp/gloves",
      mcpConfigPath: "/tmp/gloves.toml",
      tokenPath: "/tmp/session-token",
      injectMode: "both",
      tmpfsPath: "/run/secrets",
    });

    const api: PluginAPI = {
      agent: { id: "devy" },
      sandbox: {
        env: { set() {} },
      },
      registerTool() {},
      onShutdown() {},
    };

    await expect(plugin.init(api)).rejects.toThrow("sandbox.writeFile");
  });

  test("fails clearly when gloves_set cannot resolve its source environment variable", async () => {
    fixture = createGlovesFixture();
    const tools = new Map<string, PluginToolDefinition>();

    const plugin = glovesPlugin({
      root: fixture.root,
      mcpConfigPath: fixture.mcpConfigPath,
      tokenPath: fixture.tokenPath,
      socketPath: fixture.socketPath,
      glovesBin: fixture.glovesBin,
      glovesMcpBin: fixture.glovesMcpBin,
      injectMode: "env",
    });

    const api: PluginAPI = {
      agent: { id: "devy" },
      sandbox: {
        env: { set() {}, get() { return undefined; } },
      },
      registerTool(name, definition) {
        tools.set(name, definition);
      },
      onShutdown() {},
    };

    await plugin.init(api);
    await expect(
      tools.get("gloves_set")!.handler({
        path: "agents/devy/api-keys/openai",
        from_env: "MISSING_SECRET",
      }),
    ).rejects.toThrow("MISSING_SECRET");
  });

  test("uses stdio MCP sessions when socketPath is omitted from plugin config", async () => {
    fixture = createGlovesFixture({ transport: "stdio" });
    const tools = new Map<string, PluginToolDefinition>();
    const envSet = mock(() => {});

    const plugin = glovesPlugin({
      root: fixture.root,
      mcpConfigPath: fixture.mcpConfigPath,
      tokenPath: fixture.tokenPath,
      glovesMcpBin: fixture.glovesMcpBin,
      injectMode: "env",
    });

    const api: PluginAPI = {
      agent: { id: "devy" },
      sandbox: {
        env: { set: envSet, get() { return undefined; } },
      },
      registerTool(name, definition) {
        tools.set(name, definition);
      },
      onShutdown() {},
    };

    await plugin.init(api);

    const getResult = await tools.get("gloves_get")!.handler({
      path: fixture.secretPath,
      inject_as: "ANTHROPIC_API_KEY",
    });

    expect(envSet).toHaveBeenCalledWith("ANTHROPIC_API_KEY", fixture.secretValue);
    expect(getResult.injected).toBe(true);
  });

  test("approves a pending gloves_get request through the plugin tool surface", async () => {
    fixture = createGlovesFixture({ approvalChannel: "tty" });
    const tools = new Map<string, PluginToolDefinition>();
    const envSet = mock(() => {});

    const plugin = glovesPlugin({
      root: fixture.root,
      mcpConfigPath: fixture.mcpConfigPath,
      tokenPath: fixture.tokenPath,
      socketPath: fixture.socketPath,
      glovesBin: "/definitely-unused-gloves-binary",
      glovesMcpBin: fixture.glovesMcpBin,
      injectMode: "env",
    });

    const api: PluginAPI = {
      agent: { id: "devy" },
      sandbox: {
        env: { set: envSet, get() { return undefined; } },
      },
      registerTool(name, definition) {
        tools.set(name, definition);
      },
      onShutdown() {},
    };

    await plugin.init(api);

    const getPromise = tools.get("gloves_get")!.handler({
      path: fixture.secretPath,
      inject_as: "ANTHROPIC_API_KEY",
    });
    const requestId = await waitForPendingRequestId(fixture.root);
    const approvalResult = await tools.get("gloves_approve")!.handler({
      request_id: requestId,
      decision: "approve",
    });
    const getResult = await getPromise;

    expect(approvalResult.success).toBe(true);
    expect(approvalResult.decision).toBe("approve");
    expect(envSet).toHaveBeenCalledWith("ANTHROPIC_API_KEY", fixture.secretValue);
    expect(getResult.injected).toBe(true);
  });
});

const PENDING_REQUEST_WAIT_TIMEOUT_MS = 5_000;
const PENDING_REQUEST_WAIT_INTERVAL_MS = 25;

async function waitForPendingRequestId(root: string): Promise<string> {
  const pendingPath = `${root}/store/.gloves-pending.json`;
  const deadline = Date.now() + PENDING_REQUEST_WAIT_TIMEOUT_MS;
  while (Date.now() < deadline) {
    try {
      const raw = readFileSync(pendingPath, "utf8");
      const payload = JSON.parse(raw) as Array<{ id?: string }>;
      const requestId = payload.at(0)?.id;
      if (typeof requestId === "string" && requestId.length > 0) {
        return requestId;
      }
    } catch {
      // Wait for the daemon to persist the approval request.
    }
    await Bun.sleep(PENDING_REQUEST_WAIT_INTERVAL_MS);
  }

  throw new Error(`timed out waiting for pending request at ${pendingPath}`);
}
