import { spawn } from "node:child_process";
import { readdir, readFile } from "node:fs/promises";
import { join, relative } from "node:path";

export const id = "gloves";
export const name = "Gloves";
export const SAFE_TOOL_NAMES = [
  "gloves_list",
  "gloves_status",
  "gloves_requests_list",
  "gloves_request_approve",
  "gloves_request_deny",
] as const;

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_OPERATOR_AGENT_ID = "openclaw";

type SafeToolName = typeof SAFE_TOOL_NAMES[number];

export interface GlovesOpenClawConfig {
  root: string;
  glovesBin?: string;
  operatorAgentId?: string;
  cwd?: string;
  timeoutMs?: number;
}

export interface OpenClawToolDefinition {
  name: SafeToolName;
  description: string;
  parameters: {
    type: "object";
    properties: Record<string, unknown>;
    required?: string[];
  };
  execute: (_toolCallId: string, parameters: Record<string, unknown>) => Promise<Record<string, unknown>>;
}

export interface OpenClawPluginApi {
  config: GlovesOpenClawConfig;
  registerTool: (tool: OpenClawToolDefinition, options?: { optional?: boolean }) => void;
}

export interface OpenClawPlugin {
  id: string;
  name: string;
  register: (api: OpenClawPluginApi) => Promise<void>;
}

export default {
  id,
  name,
  async register(api: OpenClawPluginApi) {
    const config = normalizeConfig(api.config);
    for (const tool of createTools(config)) {
      api.registerTool(tool, { optional: true });
    }
  },
} satisfies OpenClawPlugin;

export function normalizeConfig(config: GlovesOpenClawConfig): Required<GlovesOpenClawConfig> {
  if (!config.root || config.root.trim().length === 0) {
    throw new Error("plugins.entries.gloves.config.root is required");
  }
  return {
    root: config.root,
    glovesBin: config.glovesBin ?? "gloves",
    operatorAgentId: config.operatorAgentId ?? DEFAULT_OPERATOR_AGENT_ID,
    cwd: config.cwd ?? process.cwd(),
    timeoutMs: config.timeoutMs ?? DEFAULT_TIMEOUT_MS,
  };
}

export function createTools(config: Required<GlovesOpenClawConfig>): OpenClawToolDefinition[] {
  return [
    {
      name: "gloves_list",
      description: "List secret names without decrypting or returning plaintext values.",
      parameters: {
        type: "object",
        properties: {
          prefix: {
            type: "string",
            description: "Optional prefix used to filter secret names.",
          },
        },
      },
      execute: async (_toolCallId, parameters) => {
        const prefix = optionalString(parameters.prefix, "prefix");
        const secrets = await listSecretNamesFromMetadata(config.root, prefix);
        return {
          secrets,
          count: secrets.length,
        };
      },
    },
    {
      name: "gloves_status",
      description: "Show request status metadata for one secret path.",
      parameters: {
        type: "object",
        properties: {
          path: {
            type: "string",
            description: "Secret path to inspect.",
          },
        },
        required: ["path"],
      },
      execute: async (_toolCallId, parameters) => {
        const path = requiredString(parameters.path, "path");
        const payload = await runGlovesJsonCommand(config, ["secrets", "status", path]);
        return objectResult(payload);
      },
    },
    {
      name: "gloves_requests_list",
      description: "List pending secret-access requests without returning secret plaintext.",
      parameters: {
        type: "object",
        properties: {},
      },
      execute: async () => {
        const payload = await runGlovesJsonCommand(config, ["requests", "list"]);
        const requests = Array.isArray(unwrapPayloadResult(payload))
          ? (unwrapPayloadResult(payload) as Array<Record<string, unknown>>)
          : [];
        return {
          requests,
          count: requests.length,
        };
      },
    },
    {
      name: "gloves_request_approve",
      description: "Approve a pending secret-access request by id.",
      parameters: {
        type: "object",
        properties: {
          request_id: {
            type: "string",
            description: "Pending request id to approve.",
          },
        },
        required: ["request_id"],
      },
      execute: async (_toolCallId, parameters) => {
        const requestId = requiredString(parameters.request_id, "request_id");
        const payload = await runGlovesJsonCommand(config, ["requests", "approve", requestId]);
        return objectResult(payload);
      },
    },
    {
      name: "gloves_request_deny",
      description: "Deny a pending secret-access request by id.",
      parameters: {
        type: "object",
        properties: {
          request_id: {
            type: "string",
            description: "Pending request id to deny.",
          },
        },
        required: ["request_id"],
      },
      execute: async (_toolCallId, parameters) => {
        const requestId = requiredString(parameters.request_id, "request_id");
        const payload = await runGlovesJsonCommand(config, ["requests", "deny", requestId]);
        return objectResult(payload);
      },
    },
  ];
}

export async function runGlovesJsonCommand(
  config: Required<GlovesOpenClawConfig>,
  commandArguments: string[],
): Promise<unknown> {
  const child = spawn(
    config.glovesBin,
    ["--json", "--root", config.root, "--agent", config.operatorAgentId, ...commandArguments],
    {
      cwd: config.cwd,
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );

  const stdoutChunks: Buffer[] = [];
  const stderrChunks: Buffer[] = [];
  child.stdout.on("data", (chunk) => stdoutChunks.push(Buffer.from(chunk)));
  child.stderr.on("data", (chunk) => stderrChunks.push(Buffer.from(chunk)));

  const exitCode = await waitForExitCode(child, config.timeoutMs);
  const stdout = Buffer.concat(stdoutChunks).toString("utf8").trim();
  const stderr = Buffer.concat(stderrChunks).toString("utf8").trim();

  if (exitCode !== 0) {
    throw new Error(stderr || stdout || `gloves exited with code ${exitCode}`);
  }
  if (stdout.length === 0) {
    throw new Error("gloves returned no JSON payload");
  }

  const payload = JSON.parse(stdout) as unknown;
  if (isEnvelope(payload) && payload.status !== "ok") {
    throw new Error(`unexpected gloves response status: ${String(payload.status)}`);
  }
  return payload;
}

export function filterSecretNames(payload: unknown, prefix?: string): string[] {
  const result = unwrapPayloadResult(payload);
  const entries = Array.isArray(result) ? result : [];
  const secretPrefix = prefix?.trim();
  return entries
    .filter((entry): entry is { kind?: unknown; id?: unknown } =>
      typeof entry === "object" && entry !== null,
    )
    .filter((entry) => entry.kind === "secret" && typeof entry.id === "string")
    .map((entry) => entry.id as string)
    .filter((entry) => !secretPrefix || entry.startsWith(secretPrefix));
}

function objectResult(payload: unknown): Record<string, unknown> {
  const result = unwrapPayloadResult(payload);
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    throw new Error("gloves command did not return an object result");
  }
  return result as Record<string, unknown>;
}

function unwrapPayloadResult(payload: unknown): unknown {
  if (typeof payload === "object" && payload !== null && "result" in payload) {
    return (payload as { result?: unknown }).result;
  }
  return payload;
}

function isEnvelope(payload: unknown): payload is { status?: unknown; result?: unknown } {
  return (
    typeof payload === "object"
    && payload !== null
    && "status" in payload
    && "command" in payload
    && "result" in payload
  );
}

async function listSecretNamesFromMetadata(root: string, prefix?: string): Promise<string[]> {
  const metadataRoot = join(root, "store", ".gloves-meta");
  const entries = await collectMetadataEntries(metadataRoot);
  const normalizedPrefix = prefix?.trim();
  return entries.filter((entry) => !normalizedPrefix || entry.startsWith(normalizedPrefix)).sort();
}

async function collectMetadataEntries(directory: string): Promise<string[]> {
  let names: string[] = [];
  let directoryEntries: Awaited<ReturnType<typeof readdir>>;
  try {
    directoryEntries = await readdir(directory, { withFileTypes: true });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes("no such file or directory")) {
      return [];
    }
    throw error;
  }

  for (const entry of directoryEntries) {
    const entryPath = join(directory, entry.name);
    if (entry.isDirectory()) {
      names = names.concat(await collectMetadataEntries(entryPath));
      continue;
    }
    if (!entry.isFile() || !entry.name.endsWith(".json")) {
      continue;
    }
    const parsed = JSON.parse(await readFile(entryPath, "utf8")) as { name?: unknown };
    if (typeof parsed.name === "string") {
      names.push(parsed.name);
      continue;
    }
    names.push(relative(directory, entryPath).replace(/\.json$/u, ""));
  }
  return names;
}

function requiredString(value: unknown, fieldName: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`tool argument '${fieldName}' must be a non-empty string`);
  }
  return value;
}

function optionalString(value: unknown, fieldName: string): string | undefined {
  if (typeof value === "undefined") {
    return undefined;
  }
  return requiredString(value, fieldName);
}

function waitForExitCode(
  child: ReturnType<typeof spawn>,
  timeoutMs: number,
): Promise<number> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`gloves command timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    child.on("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    child.on("close", (code) => {
      clearTimeout(timeout);
      resolve(code ?? 1);
    });
  });
}
