import { spawnSync } from "node:child_process";

import { afterEach, describe, expect, test } from "bun:test";

import glovesPlugin, {
  createTools,
  filterSecretNames,
  normalizeConfig,
  SAFE_TOOL_NAMES,
  type GlovesOpenClawConfig,
  type OpenClawPluginApi,
  type OpenClawToolDefinition,
} from "./index";
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
  test("normalizes plugin config for the native register(api) entry", () => {
    const config = normalizeConfig({ root: "/tmp/gloves" });

    expect(config.glovesBin).toBe("gloves");
    expect(config.operatorAgentId).toBe("openclaw");
    expect(config.timeoutMs).toBeGreaterThan(0);
  });

  test(
    "registers only the guaranteed-safe OpenClaw tool subset as optional tools",
    { timeout: 15_000 },
    async () => {
    fixture = createGlovesFixture();
    const tools: OpenClawToolDefinition[] = [];
    const options: Array<{ optional?: boolean } | undefined> = [];

    const api: OpenClawPluginApi = {
      config: {
        root: fixture.root,
        glovesBin: fixture.glovesBin,
        operatorAgentId: "openclaw",
      },
      registerTool(tool, registrationOptions) {
        tools.push(tool);
        options.push(registrationOptions);
      },
    };

    await glovesPlugin.register(api);

    expect(tools.map((tool) => tool.name)).toEqual([...SAFE_TOOL_NAMES]);
    expect(options.every((entry) => entry?.optional === true)).toBe(true);
    },
  );

  test("lists status and request review flows without leaking plaintext", async () => {
    fixture = createGlovesFixture();
    createPendingRequest(fixture, fixture.secretPath);
    const toolMap = new Map<string, OpenClawToolDefinition>();
    const config = normalizeConfig({
      root: fixture.root,
      glovesBin: fixture.glovesBin,
      operatorAgentId: "openclaw",
    });

    for (const tool of createTools(config)) {
      toolMap.set(tool.name, tool);
    }

    const listed = await toolMap.get("gloves_list")!.execute("call-1", { prefix: "agents/devy" });
    expect(listed.secrets).toEqual([fixture.secretPath]);

    const status = await toolMap.get("gloves_status")!.execute("call-2", { path: fixture.secretPath });
    expect(status.secret).toBe(fixture.secretPath);
    expect(status.status).toBe("pending");

    const requests = await toolMap.get("gloves_requests_list")!.execute("call-3", {});
    expect(requests.count).toBe(1);
    const requestId = String((requests.requests as Array<Record<string, unknown>>)[0].id);

    const approved = await toolMap.get("gloves_request_approve")!.execute("call-4", {
      request_id: requestId,
    });
    expect(approved.action).toBe("approved");
    expect(approved.status).toBe("fulfilled");

    createPendingRequest(fixture, "agents/devy/api-keys/openai");
    const denyRequests = await toolMap.get("gloves_requests_list")!.execute("call-5", {});
    const denyRequestId = String((denyRequests.requests as Array<Record<string, unknown>>)[0].id);
    const denied = await toolMap.get("gloves_request_deny")!.execute("call-6", {
      request_id: denyRequestId,
    });
    expect(denied.action).toBe("denied");
    expect(denied.status).toBe("denied");

    const rendered = JSON.stringify({ listed, status, requests, approved, denied });
    expect(rendered).not.toContain(fixture.secretValue);
  });

  test("fails clearly when required plugin config is missing", async () => {
    const api: OpenClawPluginApi = {
      config: {} as GlovesOpenClawConfig,
      registerTool() {},
    };

    await expect(glovesPlugin.register(api)).rejects.toThrow("config.root");
  });

  test("filters secret list payloads down to secret ids only", () => {
    const secrets = filterSecretNames({
      status: "ok",
      result: [
        { kind: "secret", id: "agents/devy/api-keys/openai" },
        { kind: "pending", id: "ignored" },
        { kind: "secret", id: "shared/database-url" },
      ],
    }, "agents/devy");

    expect(secrets).toEqual(["agents/devy/api-keys/openai"]);
  });
});

function createPendingRequest(fixtureValue: GlovesFixture, secretPath: string): void {
  const result = spawnSync(
    fixtureValue.glovesBin,
    ["--json", "--root", fixtureValue.root, "request", secretPath, "--reason", "plugin test"],
    {
      encoding: "utf8",
    },
  );
  if (result.status !== 0) {
    throw new Error(result.stderr || result.stdout || "failed to create pending request");
  }
}
