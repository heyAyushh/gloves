import { afterEach, describe, expect, test } from "bun:test";

import { GlovesClient } from "./index";
import {
  createGlovesFixture,
  ensureGlovesBinaries,
  type GlovesFixture,
} from "./testing";

let fixture: GlovesFixture | null = null;

ensureGlovesBinaries();

afterEach(() => {
  fixture?.cleanup();
  fixture = null;
});

describe("@gloves/client", () => {
  test("lists, shows, and gets secrets through the MCP bridge", async () => {
    fixture = createGlovesFixture();
    const client = await GlovesClient.connect({
      root: fixture.root,
      agentId: "devy",
      mcpConfigPath: fixture.mcpConfigPath,
      tokenPath: fixture.tokenPath,
      glovesBin: fixture.glovesBin,
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

  test("stores secrets via env-backed MCP writes", async () => {
    fixture = createGlovesFixture();
    const client = await GlovesClient.connect({
      root: fixture.root,
      agentId: "devy",
      mcpConfigPath: fixture.mcpConfigPath,
      tokenPath: fixture.tokenPath,
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
      glovesBin: fixture.glovesBin,
      glovesMcpBin: fixture.glovesMcpBin,
    });

    await client.rotate();
    const secret = await client.get(fixture.secretPath);
    expect(secret.value).toBe(fixture.secretValue);
    expect(secret.metadata.agent).toBe("devy");
  });
});
