import { readFileSync, rmSync } from "node:fs";
import { spawn } from "node:child_process";
import { Socket, createConnection } from "node:net";
import { basename } from "node:path";

export interface GlovesClientConfig {
  root: string;
  agentId: string;
  mcpConfigPath: string;
  tokenPath: string;
  socketPath?: string;
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
  id?: unknown;
  method?: string;
  params?: Record<string, unknown>;
  result?: ToolResponse | Record<string, unknown>;
  error?: { code: number; message: string; data?: unknown };
};

type SessionResponse = {
  response: JsonRpcResponse;
  secretValue?: string;
};

type SessionConfig = GlovesClientConfig & {
  env?: Record<string, string>;
};

const DEFAULT_TIMEOUT_MS = 10_000;
const INITIALIZE_METHOD = "initialize";
const INITIALIZED_NOTIFICATION = "notifications/initialized";
const TOOLS_LIST_METHOD = "tools/list";
const TOOLS_CALL_METHOD = "tools/call";
const SECRET_NOTIFICATION_METHOD = "gloves/secret";

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
      socketPath: config.socketPath,
      glovesBin: config.glovesBin ?? "gloves",
      glovesMcpBin: config.glovesMcpBin ?? "gloves-mcp",
      cwd: config.cwd,
      timeoutMs: config.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    });
  }

  async list(prefix?: string): Promise<string[]> {
    const { response } = await this.callTool("gloves_list", prefix ? { prefix } : {});
    const secrets = response.structuredContent?.secrets;
    if (!Array.isArray(secrets)) {
      throw new Error("gloves_list did not return a secret list");
    }
    return secrets.map((entry) => String(entry));
  }

  async show(path: string): Promise<SecretMetadata> {
    const { response } = await this.callTool("gloves_show", { path });
    return normalizeMetadata(response.structuredContent);
  }

  async get(path: string): Promise<GetSecretResult> {
    const startedAt = performance.now();
    const mcpResponse = await this.callTool("gloves_get", { path });
    if (typeof mcpResponse.secretValue !== "string") {
      throw new Error("gloves_get did not deliver a secret side-channel payload");
    }
    const metadata = await this.show(path);
    const approvalStatus = normalizeApprovalStatus(mcpResponse.response.structuredContent?.approval_status);
    return {
      value: mcpResponse.secretValue,
      metadata,
      approvalStatus,
      approvalLatencyMs: Number((performance.now() - startedAt).toFixed(3)),
    };
  }

  async set(path: string, value: string): Promise<void> {
    const envName = createSetEnvName(path);
    await this.callTool("gloves_set", { path, from_env: envName }, { [envName]: value });
  }

  async delete(path: string): Promise<void> {
    await this.callTool("gloves_delete", { path });
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
  ): Promise<{ response: ToolResponse; secretValue?: string }> {
    const session = await McpSession.start({
      ...this.config,
      env: envOverrides,
      socketPath: envOverrides ? undefined : this.config.socketPath,
    });
    try {
      const sessionResponse = await session.request({
        jsonrpc: "2.0",
        id: 2,
        method: TOOLS_CALL_METHOD,
        params: {
          name,
          arguments: argumentsValue,
        },
      });
      if (sessionResponse.response.error) {
        throw new Error(`${sessionResponse.response.error.message} (${sessionResponse.response.error.code})`);
      }
      return {
        response: sessionResponse.response.result as ToolResponse,
        secretValue: sessionResponse.secretValue,
      };
    } finally {
      await session.close();
    }
  }
}

class McpSession {
  private readonly child: ReturnType<typeof spawn> | null;
  private readonly socket: Socket | null;
  private readonly output: NodeJS.WritableStream;
  private readonly lineReader: BufferedLineReader;
  private readonly stderrChunks: string[] = [];
  private readonly config: SessionConfig;
  private readonly sessionTokenOverridePath?: string;

  private constructor(options: {
    child?: ReturnType<typeof spawn>;
    socket?: Socket;
    input: NodeJS.ReadableStream;
    output: NodeJS.WritableStream;
    stderr?: NodeJS.ReadableStream | null;
    config: SessionConfig;
    sessionTokenOverridePath?: string;
  }) {
    this.child = options.child ?? null;
    this.socket = options.socket ?? null;
    this.output = options.output;
    this.config = options.config;
    this.sessionTokenOverridePath = options.sessionTokenOverridePath;
    this.lineReader = new BufferedLineReader(options.input);
    options.stderr?.on("data", (chunk) => {
      this.stderrChunks.push(Buffer.from(chunk).toString("utf8"));
    });
  }

  static async start(config: SessionConfig): Promise<McpSession> {
    if (config.socketPath) {
      return await McpSession.startSocket(config);
    }
    return await McpSession.startStdio(config);
  }

  private static async startSocket(config: SessionConfig): Promise<McpSession> {
    const socket = createConnection(config.socketPath);
    await waitForSocketConnection(socket, config.timeoutMs);
    const session = new McpSession({
      socket,
      input: socket,
      output: socket,
      config,
    });
    const token = await waitForToken(config.tokenPath, config.timeoutMs);
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
    if (initializeResponse.response.error) {
      await session.close();
      throw new Error(`${initializeResponse.response.error.message} (${initializeResponse.response.error.code})`);
    }
    session.write({
      jsonrpc: "2.0",
      method: INITIALIZED_NOTIFICATION,
      params: {},
    });
    return session;
  }

  private static async startStdio(config: SessionConfig): Promise<McpSession> {
    const sessionTokenOverridePath = createStdioTokenPath(config.tokenPath);
    const previousToken = readTokenFile(sessionTokenOverridePath);
    const childArguments = ["--config", config.mcpConfigPath, "--agent", config.agentId, "--stdio"];
    const child = spawn(config.glovesMcpBin, childArguments, {
      cwd: config.cwd,
      env: {
        ...process.env,
        ...(config.env ?? {}),
        GLOVES_SESSION_TOKEN_PATH: sessionTokenOverridePath,
      },
      stdio: ["pipe", "pipe", "pipe"],
    });
    if (!child.stdout || !child.stdin || !child.stderr) {
      throw new Error("gloves-mcp did not expose stdio streams");
    }
    const session = new McpSession({
      child,
      input: child.stdout,
      output: child.stdin,
      stderr: child.stderr,
      config,
      sessionTokenOverridePath,
    });
    const token = await waitForFreshToken(sessionTokenOverridePath, previousToken, config.timeoutMs);
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
    if (initializeResponse.response.error) {
      await session.close();
      throw new Error(`${initializeResponse.response.error.message} (${initializeResponse.response.error.code})`);
    }
    session.write({
      jsonrpc: "2.0",
      method: INITIALIZED_NOTIFICATION,
      params: {},
    });
    return session;
  }

  async request(payload: Record<string, unknown>): Promise<SessionResponse> {
    this.write(payload);
    return this.readResponse(payload.id);
  }

  async close(): Promise<void> {
    this.lineReader.dispose();
    if (this.child) {
      this.child.kill("SIGKILL");
      await new Promise<void>((resolve) => {
        this.child?.once("exit", () => resolve());
        setTimeout(resolve, 50);
      });
      if (this.sessionTokenOverridePath) {
        rmSync(this.sessionTokenOverridePath, { force: true });
      }
      return;
    }
    if (this.socket) {
      this.socket.end();
      this.socket.destroy();
    }
  }

  private write(payload: Record<string, unknown>): void {
    this.output.write(`${JSON.stringify(payload)}\n`);
  }

  private async readResponse(requestId: unknown): Promise<SessionResponse> {
    let secretValue: string | undefined;
    while (true) {
      const line = await readLine(this.lineReader, this.config.timeoutMs);
      let message: JsonRpcResponse;
      try {
        message = JSON.parse(line) as JsonRpcResponse;
      } catch (error) {
        throw new Error(formatSessionError(this.stderrChunks.join(""), error));
      }
      if (message.method === SECRET_NOTIFICATION_METHOD) {
        const params = message.params ?? {};
        if (sameRequestId(params.requestId, requestId) && typeof params.value === "string") {
          secretValue = params.value;
        }
        continue;
      }
      if (sameRequestId(message.id, requestId)) {
        return {
          response: message,
          secretValue,
        };
      }
    }
  }
}

function sameRequestId(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
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

async function waitForToken(tokenPath: string, timeoutMs: number): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const token = readTokenFile(tokenPath);
    if (token) {
      return token;
    }
    await Bun.sleep(25);
  }
  throw new Error(`timed out waiting for session token at ${tokenPath}`);
}

async function waitForSocketConnection(socket: Socket, timeoutMs: number): Promise<void> {
  await Promise.race([
    new Promise<void>((resolve, reject) => {
      socket.once("connect", resolve);
      socket.once("error", reject);
    }),
    new Promise<void>((_, reject) => {
      setTimeout(() => reject(new Error("timed out connecting to gloves socket")), timeoutMs);
    }),
  ]);
}

async function readLine(
  lineReader: BufferedLineReader,
  timeoutMs: number,
): Promise<string> {
  return await lineReader.readLine(timeoutMs);
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

function createStdioTokenPath(tokenPath: string): string {
  return `${tokenPath}.stdio-${process.pid}-${Date.now()}`;
}

function formatSessionError(stderr: string, error: unknown): string {
  const reason = error instanceof Error ? error.message : String(error);
  const details = stderr.trim();
  return details ? `${reason}: ${details}` : reason;
}

class BufferedLineReader {
  private readonly input: NodeJS.ReadableStream;
  private readonly lines: string[] = [];
  private readonly waiters: Array<{
    resolve: (line: string) => void;
    reject: (error: Error) => void;
  }> = [];
  private buffer = "";
  private closedError: Error | null = null;

  constructor(input: NodeJS.ReadableStream) {
    this.input = input;
    input.on("data", this.handleData);
    input.on("end", this.handleClose);
    input.on("close", this.handleClose);
    input.on("error", this.handleError);
  }

  async readLine(timeoutMs: number): Promise<string> {
    if (this.lines.length > 0) {
      return this.lines.shift()!;
    }
    if (this.closedError) {
      throw this.closedError;
    }

    return await Promise.race([
      new Promise<string>((resolve, reject) => {
        this.waiters.push({ resolve, reject });
      }),
      new Promise<string>((_, reject) => {
        setTimeout(() => reject(new Error("timed out waiting for gloves-mcp response")), timeoutMs);
      }),
    ]);
  }

  dispose(): void {
    this.input.off("data", this.handleData);
    this.input.off("end", this.handleClose);
    this.input.off("close", this.handleClose);
    this.input.off("error", this.handleError);
  }

  private readonly handleData = (chunk: string | Buffer): void => {
    this.buffer += Buffer.from(chunk).toString("utf8");
    while (this.buffer.includes("\n")) {
      const newlineIndex = this.buffer.indexOf("\n");
      const line = this.buffer.slice(0, newlineIndex).replace(/\r$/, "");
      this.buffer = this.buffer.slice(newlineIndex + 1);
      this.pushLine(line);
    }
  };

  private readonly handleClose = (): void => {
    this.closeWithError(new Error("gloves-mcp closed before sending a response"));
  };

  private readonly handleError = (error: Error): void => {
    this.closeWithError(error);
  };

  private pushLine(line: string): void {
    const waiter = this.waiters.shift();
    if (waiter) {
      waiter.resolve(line);
      return;
    }
    this.lines.push(line);
  }

  private closeWithError(error: Error): void {
    if (this.closedError) {
      return;
    }
    this.closedError = error;
    while (this.waiters.length > 0) {
      this.waiters.shift()!.reject(error);
    }
  }
}
