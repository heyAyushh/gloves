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

describe("@openclaw/gloves", () => {
  test("registers tools and injects secrets without returning raw values", async () => {
    fixture = createGlovesFixture();
    const tools = new Map<string, PluginToolDefinition>();
    const envSet = mock(() => {});
    const writeFile = mock(async () => {});
    const shutdownCallbacks: Array<() => void | Promise<void>> = [];

    const plugin = glovesPlugin({
      root: fixture.root,
      mcpConfigPath: fixture.mcpConfigPath,
      tokenPath: fixture.tokenPath,
      glovesBin: fixture.glovesBin,
      glovesMcpBin: fixture.glovesMcpBin,
      injectMode: "both",
      tmpfsPath: "/run/secrets",
    });

    const api: PluginAPI = {
      agent: { id: "devy" },
      sandbox: {
        env: { set: envSet },
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

    const rotateResult = await tools.get("gloves_rotate")!.handler({});
    expect(rotateResult.agent).toBe("devy");
    expect(rotateResult.rotated).toBe(true);

    for (const callback of shutdownCallbacks) {
      await callback();
    }
  });
});
