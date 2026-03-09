import { readFileSync } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import { createInterface } from "node:readline";
import { basename } from "node:path";

export interface GlovesClientConfig {
  root: string;
  agentId: string;
  mcpConfigPath: string;
  tokenPath: string;
  glovesBin?: string;
  glovesMcpBin?: string;
  cwd?: string;
  timeoutMs?: number;
}

export interface SecretMetadata {
  name: string;
  exists: boolean;
  length: number;
  agent: string;
  encryptedTo: string[];
  created: string;
  modified: string;
  lastRotated: string;
  lastAccessed?: string;
  fileSize: number;
}

export interface GetSecretResult {
  value: string;
  metadata: SecretMetadata;
  approvalStatus: "auto" | "approved";
  approvalLatencyMs: number;
}

type ToolResponse = {
  content?: Array<{ type: string; text: string }>;
  isError?: boolean;
  structuredContent?: Record<string, unknown>;
};

type JsonRpcResponse = {
  result?: ToolResponse | Record<string, unknown>;
  error?: { code: number; message: string; data?: unknown };
};

type SessionConfig = GlovesClientConfig & {
  env?: Record<string, string>;
};

const DEFAULT_TIMEOUT_MS = 10_000;
const INITIALIZE_METHOD = "initialize";
const INITIALIZED_NOTIFICATION = "notifications/initialized";
const TOOLS_LIST_METHOD = "tools/list";
const TOOLS_CALL_METHOD = "tools/call";

export class GlovesClient {
  private readonly config: Required<Omit<GlovesClientConfig, "cwd" | "glovesBin" | "glovesMcpBin" | "timeoutMs">> &
    Pick<GlovesClientConfig, "cwd"> & {
      glovesBin: string;
      glovesMcpBin: string;
      timeoutMs: number;
    };

  private constructor(config: GlovesClient["config"]) {
    this.config = config;
  }

  static async connect(config: GlovesClientConfig): Promise<GlovesClient> {
    if (!config.root || !config.agentId || !config.mcpConfigPath || !config.tokenPath) {
      throw new Error("GlovesClient.connect requires root, agentId, mcpConfigPath, and tokenPath");
    }

    return new GlovesClient({
      root: config.root,
      agentId: config.agentId,
      mcpConfigPath: config.mcpConfigPath,
      tokenPath: config.tokenPath,
      glovesBin: config.glovesBin ?? "gloves",
      glovesMcpBin: config.glovesMcpBin ?? "gloves-mcp",
      cwd: config.cwd,
      timeoutMs: config.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    });
  }

  async list(prefix?: string): Promise<string[]> {
    const response = await this.callTool("gloves_list", prefix ? { prefix } : {});
    const secrets = response.structuredContent?.secrets;
    if (!Array.isArray(secrets)) {
      throw new Error("gloves_list did not return a secret list");
    }
    return secrets.map((entry) => String(entry));
  }

  async show(path: string): Promise<SecretMetadata> {
    const response = await this.callTool("gloves_show", { path });
    return normalizeMetadata(response.structuredContent);
  }

  async get(path: string): Promise<GetSecretResult> {
    const startedAt = performance.now();
    const mcpResponse = await this.callTool("gloves_get", { path });
    const value = this.runGlovesRaw(["--agent", this.config.agentId, "get", path, "--format", "raw"]);
    const metadata = await this.show(path);
    const approvalStatus = normalizeApprovalStatus(mcpResponse.structuredContent?.approval_status);
    return {
      value,
      metadata,
      approvalStatus,
      approvalLatencyMs: Number((performance.now() - startedAt).toFixed(3)),
    };
  }

  async set(path: string, value: string): Promise<void> {
    const envName = createSetEnvName(path);
    await this.callTool("gloves_set", { path, from_env: envName }, { [envName]: value });
  }

  async rotate(agentId = this.config.agentId): Promise<void> {
    await this.callTool("gloves_rotate", { agent_id: agentId });
  }

  async approve(requestId: string, decision: "approve" | "deny", reason?: string): Promise<void> {
    await this.callTool("gloves_approve", {
      request_id: requestId,
      decision,
      ...(reason ? { reason } : {}),
    });
  }

  disconnect(): void {}

  private async callTool(
    name: string,
    argumentsValue: Record<string, unknown>,
    envOverrides?: Record<string, string>,
  ): Promise<ToolResponse> {
    const session = await McpSession.start({
      ...this.config,
      env: envOverrides,
    });
    try {
      const response = await session.request({
        jsonrpc: "2.0",
        id: 2,
        method: TOOLS_CALL_METHOD,
        params: {
          name,
          arguments: argumentsValue,
        },
      });
      if (response.error) {
        throw new Error(`${response.error.message} (${response.error.code})`);
      }
      return response.result as ToolResponse;
    } finally {
      await session.close();
    }
  }

  private runGlovesRaw(args: string[]): string {
    const command = spawnSync(
      this.config.glovesBin,
      ["--root", this.config.root, ...args],
      {
        cwd: this.config.cwd,
        encoding: "utf8",
      },
    );
    if (command.status !== 0) {
      throw new Error(command.stderr || `gloves ${args.join(" ")} failed`);
    }
    return command.stdout;
  }
}

class McpSession {
  private readonly child: ReturnType<typeof spawn>;
  private readonly lineReader: ReturnType<typeof createInterface>;
  private readonly stderrChunks: string[] = [];
  private readonly config: SessionConfig;

  private constructor(child: ReturnType<typeof spawn>, config: SessionConfig) {
    if (!child.stdout || !child.stdin || !child.stderr) {
      throw new Error("gloves-mcp did not expose stdio streams");
    }
    this.child = child;
    this.config = config;
    this.lineReader = createInterface({ input: child.stdout });
    child.stderr.on("data", (chunk) => {
      this.stderrChunks.push(Buffer.from(chunk).toString("utf8"));
    });
  }

  static async start(config: SessionConfig): Promise<McpSession> {
    const previousToken = readTokenFile(config.tokenPath);
    const child = spawn(config.glovesMcpBin, ["--config", config.mcpConfigPath, "--agent", config.agentId], {
      cwd: config.cwd,
      env: { ...process.env, ...(config.env ?? {}) },
      stdio: ["pipe", "pipe", "pipe"],
    });
    const session = new McpSession(child, config);
    const token = await waitForFreshToken(config.tokenPath, previousToken, config.timeoutMs);
    const initializeResponse = await session.request({
      jsonrpc: "2.0",
      id: 1,
      method: INITIALIZE_METHOD,
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {
          tools: {
            listChanged: true,
          },
        },
        clientInfo: {
          name: "@gloves/client",
          version: "0.1.0",
        },
        _meta: {
          sessionToken: token,
          agentId: config.agentId,
        },
      },
    });
    if (initializeResponse.error) {
      await session.close();
      throw new Error(`${initializeResponse.error.message} (${initializeResponse.error.code})`);
    }
    session.write({
      jsonrpc: "2.0",
      method: INITIALIZED_NOTIFICATION,
      params: {},
    });
    return session;
  }

  async request(payload: Record<string, unknown>): Promise<JsonRpcResponse> {
    this.write(payload);
    return this.readResponse();
  }

  async close(): Promise<void> {
    this.lineReader.close();
    this.child.kill("SIGKILL");
    await new Promise<void>((resolve) => {
      this.child.once("exit", () => resolve());
      setTimeout(resolve, 50);
    });
  }

  private write(payload: Record<string, unknown>): void {
    this.child.stdin?.write(`${JSON.stringify(payload)}\n`);
  }

  private async readResponse(): Promise<JsonRpcResponse> {
    const line = await readLine(this.lineReader, this.config.timeoutMs);
    try {
      return JSON.parse(line) as JsonRpcResponse;
    } catch (error) {
      throw new Error(formatSessionError(this.stderrChunks.join(""), error));
    }
  }
}

function readTokenFile(tokenPath: string): string | null {
  try {
    const token = readFileSync(tokenPath, "utf8").trim();
    return token.length > 0 ? token : null;
  } catch {
    return null;
  }
}

async function waitForFreshToken(
  tokenPath: string,
  previousToken: string | null,
  timeoutMs: number,
): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const token = readTokenFile(tokenPath);
    if (token && token !== previousToken) {
      return token;
    }
    await Bun.sleep(25);
  }
  throw new Error(`timed out waiting for session token at ${tokenPath}`);
}

async function readLine(
  lineReader: ReturnType<typeof createInterface>,
  timeoutMs: number,
): Promise<string> {
  return await Promise.race([
    new Promise<string>((resolve, reject) => {
      lineReader.once("line", resolve);
      lineReader.once("close", () => reject(new Error("gloves-mcp closed before sending a response")));
    }),
    new Promise<string>((_, reject) => {
      setTimeout(() => reject(new Error("timed out waiting for gloves-mcp response")), timeoutMs);
    }),
  ]);
}

function normalizeMetadata(value: unknown): SecretMetadata {
  const record = (value ?? {}) as Record<string, unknown>;
  return {
    name: String(record.name),
    exists: Boolean(record.exists),
    length: Number(record.length ?? 0),
    agent: String(record.agent),
    encryptedTo: Array.isArray(record.encrypted_to) ? record.encrypted_to.map(String) : [],
    created: String(record.created),
    modified: String(record.modified),
    lastRotated: String(record.last_rotated),
    lastAccessed: record.last_accessed ? String(record.last_accessed) : undefined,
    fileSize: Number(record.file_size ?? 0),
  };
}

function normalizeApprovalStatus(value: unknown): "auto" | "approved" {
  return value === "approved" ? "approved" : "auto";
}

function createSetEnvName(path: string): string {
  const suffix = basename(path).replace(/[^A-Za-z0-9]/g, "_").toUpperCase();
  return `GLOVES_SET_${suffix}_${Date.now()}`;
}

function formatSessionError(stderr: string, error: unknown): string {
  const reason = error instanceof Error ? error.message : String(error);
  const details = stderr.trim();
  return details ? `${reason}: ${details}` : reason;
}
