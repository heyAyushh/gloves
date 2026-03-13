import { afterEach, describe, expect, test } from "bun:test";

import { GlovesClient } from "./index";
import {
  createGlovesFixture,
  ensureGlovesBinaries,
  ensureNativeAddon,
  type GlovesFixture,
} from "./testing";

let fixture: GlovesFixture | null = null;

ensureGlovesBinaries();
ensureNativeAddon();

afterEach(() => {
  fixture?.cleanup();
  fixture = null;
});

describe("@gloves/mcp-client", () => {
  test("loads the native addon when it is available", { timeout: 15_000 }, async () => {
    fixture = createGlovesFixture();
    const client = await GlovesClient.connect({
      root: fixture.root,
      agentId: "devy",
      mcpConfigPath: fixture.mcpConfigPath,
      tokenPath: fixture.tokenPath,
      socketPath: fixture.socketPath,
      glovesMcpBin: fixture.glovesMcpBin,
    });

    expect((client as unknown as { nativeClient: unknown }).nativeClient).not.toBeNull();

    const secret = await client.get(fixture.secretPath);
    expect(secret.value).toBe(fixture.secretValue);
  });

  test("lists, shows, and gets secrets through the MCP bridge", async () => {
    fixture = createGlovesFixture();
    const client = await GlovesClient.connect({
      root: fixture.root,
      agentId: "devy",
      mcpConfigPath: fixture.mcpConfigPath,
      tokenPath: fixture.tokenPath,
      socketPath: fixture.socketPath,
      glovesBin: "/definitely-unused-gloves-binary",
      glovesMcpBin: fixture.glovesMcpBin,
    });

    const listed = await client.list("agents/devy");
    expect(listed).toContain(fixture.secretPath);

    const shown = await client.show(fixture.secretPath);
    expect(shown.name).toBe(fixture.secretPath);
    expect(shown.length).toBe(fixture.secretValue.length);

    const secret = await client.get(fixture.secretPath);
    expect(secret.value).toBe(fixture.secretValue);
    expect(secret.metadata.name).toBe(fixture.secretPath);
    expect(secret.approvalStatus).toBe("auto");
  });

  test("uses stdio MCP sessions when socketPath is omitted", async () => {
    fixture = createGlovesFixture({ transport: "stdio" });
    const client = await GlovesClient.connect({
      root: fixture.root,
      agentId: "devy",
      mcpConfigPath: fixture.mcpConfigPath,
      tokenPath: fixture.tokenPath,
      glovesBin: "/definitely-unused-gloves-binary",
      glovesMcpBin: fixture.glovesMcpBin,
    });

    const listed = await client.list("agents/devy");
    expect(listed).toContain(fixture.secretPath);

    const secret = await client.get(fixture.secretPath);
    expect(secret.value).toBe(fixture.secretValue);
    expect(secret.metadata.name).toBe(fixture.secretPath);
  });

  test("stores secrets via env-backed MCP writes", async () => {
    fixture = createGlovesFixture();
    const client = await GlovesClient.connect({
      root: fixture.root,
      agentId: "devy",
      mcpConfigPath: fixture.mcpConfigPath,
      tokenPath: fixture.tokenPath,
      socketPath: fixture.socketPath,
      glovesBin: fixture.glovesBin,
      glovesMcpBin: fixture.glovesMcpBin,
    });

    await client.set("agents/devy/api-keys/openai", "sk-proj-written-from-client");
    const written = await client.get("agents/devy/api-keys/openai");
    expect(written.value).toBe("sk-proj-written-from-client");
    expect(written.metadata.agent).toBe("devy");
  });

  test("rotates the current agent identity without losing access", async () => {
    fixture = createGlovesFixture();
    const client = await GlovesClient.connect({
      root: fixture.root,
      agentId: "devy",
      mcpConfigPath: fixture.mcpConfigPath,
      tokenPath: fixture.tokenPath,
      socketPath: fixture.socketPath,
      glovesBin: "/definitely-unused-gloves-binary",
      glovesMcpBin: fixture.glovesMcpBin,
    });

    await client.rotate();
    const secret = await client.get(fixture.secretPath);
    expect(secret.value).toBe(fixture.secretValue);
    expect(secret.metadata.agent).toBe("devy");
  });

  test("surfaces daemon policy errors for destructive delete requests", async () => {
    fixture = createGlovesFixture();
    const client = await GlovesClient.connect({
      root: fixture.root,
      agentId: "devy",
      mcpConfigPath: fixture.mcpConfigPath,
      tokenPath: fixture.tokenPath,
      socketPath: fixture.socketPath,
      glovesBin: "/definitely-unused-gloves-binary",
      glovesMcpBin: fixture.glovesMcpBin,
    });

    await expect(client.delete(fixture.secretPath)).rejects.toThrow("Operation denied");
  });
});
