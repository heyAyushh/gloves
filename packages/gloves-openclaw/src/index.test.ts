import { existsSync, renameSync } from "node:fs";
import { resolve } from "node:path";

import { afterAll, afterEach, describe, expect, mock, test } from "bun:test";

import glovesPlugin, {
  defaultSecretTargetName,
  deliverSecretValue,
  resolveSecretValueFromSources,
  type PluginAPI,
  type PluginToolDefinition,
} from "./index";
import {
  createGlovesFixture,
  ensureGlovesBinaries,
  type GlovesFixture,
} from "../../gloves-client/src/testing";

let fixture: GlovesFixture | null = null;
const CLIENT_NATIVE_ADDON_PATH = resolve(import.meta.dir, "../../gloves-client/native/gloves_client_native.node");
const CLIENT_NATIVE_ADDON_BACKUP_PATH = `${CLIENT_NATIVE_ADDON_PATH}.disabled`;

ensureGlovesBinaries();
disableNativeAddonForPluginTests();

afterEach(() => {
  fixture?.cleanup();
  fixture = null;
});

afterAll(() => {
  restoreNativeAddonAfterPluginTests();
});

describe("@gloves/openclaw", () => {
  test("defaults secret target names to portable environment variable names", () => {
    expect(defaultSecretTargetName("agents/devy/api-keys/openai")).toBe("OPENAI");
    expect(defaultSecretTargetName("shared/database-url")).toBe("DATABASE_URL");
  });

  test("resolves secret source values from sandbox and process environments", () => {
    expect(
      resolveSecretValueFromSources("API_KEY", {
        readEnvironment: (name) => name === "API_KEY" ? "sandbox-secret" : undefined,
        readProcessEnvironment: () => "process-secret",
      }),
    ).toBe("sandbox-secret");

    expect(
      resolveSecretValueFromSources("API_KEY", {
        readEnvironment: () => undefined,
        readProcessEnvironment: (name) => name === "API_KEY" ? "process-secret" : undefined,
      }),
    ).toBe("process-secret");
  });

  test("fails when no delivery source can provide a secret", () => {
    expect(() =>
      resolveSecretValueFromSources("MISSING_SECRET", {
        readEnvironment: () => undefined,
        readProcessEnvironment: () => undefined,
      })
    ).toThrow("MISSING_SECRET");
  });

  test("delivers secrets through environment and tmpfs sinks", async () => {
    const setEnv = mock(() => {});
    const writeFile = mock(async () => {});

    const result = await deliverSecretValue(
      "agents/devy/api-keys/anthropic",
      "sk-test",
      undefined,
      { injectMode: "both", tmpfsPath: "/run/secrets" },
      {
        env: { set: setEnv },
        writeFile,
      },
    );

    expect(result).toEqual({
      injectTarget: "ANTHROPIC",
      injectMethod: "both",
    });
    expect(setEnv).toHaveBeenCalledWith("ANTHROPIC", "sk-test");
    expect(writeFile).toHaveBeenCalledWith("/run/secrets/ANTHROPIC", "sk-test", {
      mode: 0o600,
    });
  });

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

  test("fails fast when tmpfs delivery has no tmpfsPath", async () => {
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

  test("fails fast when tmpfs delivery has no sandbox writer", async () => {
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
        from_env: "OPENAI_API_KEY",
      }),
    ).rejects.toThrow("OPENAI_API_KEY");
  });

  test("uses stdio MCP sessions when socketPath is omitted from plugin config", async () => {
    fixture = createGlovesFixture({ transport: "stdio" });
    const tools = new Map<string, PluginToolDefinition>();
    const envSet = mock(() => {});

    const plugin = glovesPlugin({
      root: fixture.root,
      mcpConfigPath: fixture.mcpConfigPath,
      tokenPath: fixture.tokenPath,
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

    const listResult = await tools.get("gloves_list")!.handler({ prefix: "agents/devy" });
    expect(listResult.secrets).toContain(fixture.secretPath);

    const getResult = await tools.get("gloves_get")!.handler({ path: fixture.secretPath });
    expect(envSet).toHaveBeenCalledWith("ANTHROPIC", fixture.secretValue);
    expect(JSON.stringify(getResult)).not.toContain(fixture.secretValue);
  });

});

function disableNativeAddonForPluginTests(): void {
  if (existsSync(CLIENT_NATIVE_ADDON_PATH) && !existsSync(CLIENT_NATIVE_ADDON_BACKUP_PATH)) {
    renameSync(CLIENT_NATIVE_ADDON_PATH, CLIENT_NATIVE_ADDON_BACKUP_PATH);
  }
}

function restoreNativeAddonAfterPluginTests(): void {
  if (existsSync(CLIENT_NATIVE_ADDON_BACKUP_PATH) && !existsSync(CLIENT_NATIVE_ADDON_PATH)) {
    renameSync(CLIENT_NATIVE_ADDON_BACKUP_PATH, CLIENT_NATIVE_ADDON_PATH);
  }
}
