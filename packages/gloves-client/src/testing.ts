import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";

export type GlovesFixture = {
  root: string;
  mcpConfigPath: string;
  tokenPath: string;
  glovesBin: string;
  glovesMcpBin: string;
  secretPath: string;
  secretValue: string;
  cleanup: () => void;
};

type BinaryPaths = {
  glovesBin: string;
  glovesMcpBin: string;
};

const SECRET_PATH = "agents/devy/api-keys/anthropic";
const SECRET_VALUE = "sk-ant-api03-plugin-test";
const DEFAULT_APPROVAL_CHANNEL = "auto";
const GLOVES_CONFIG_NAME = "gloves.toml";
const REPO_ROOT = resolve(import.meta.dir, "../../..");

let cachedBinaries: BinaryPaths | null = null;

export function ensureGlovesBinaries(): BinaryPaths {
  if (cachedBinaries) {
    return cachedBinaries;
  }

  const build = spawnSync("cargo", ["build", "--bin", "gloves", "--bin", "gloves-mcp"], {
    cwd: REPO_ROOT,
    encoding: "utf8",
  });
  if (build.status !== 0) {
    throw new Error(build.stderr || "cargo build failed");
  }

  cachedBinaries = {
    glovesBin: join(REPO_ROOT, "target", "debug", process.platform === "win32" ? "gloves.exe" : "gloves"),
    glovesMcpBin: join(REPO_ROOT, "target", "debug", process.platform === "win32" ? "gloves-mcp.exe" : "gloves-mcp"),
  };
  return cachedBinaries;
}

export function createGlovesFixture(options?: { approvalChannel?: string }): GlovesFixture {
  const binaries = ensureGlovesBinaries();
  const tempRoot = mkdtempSync(join(tmpdir(), "gloves-bun-"));
  const root = join(tempRoot, "root");
  const mcpConfigPath = join(tempRoot, GLOVES_CONFIG_NAME);
  const tokenPath = join(tempRoot, "session-token");
  mkdirSync(root, { recursive: true });

  runGlovesCommand(binaries.glovesBin, root, ["set-identity", "--agent", "devy"]);
  runGlovesCommand(binaries.glovesBin, root, ["set-identity", "--agent", "main"]);
  writeCreationRules(root);
  runGlovesCommand(binaries.glovesBin, root, [
    "--agent",
    "devy",
    "set",
    SECRET_PATH,
    "--value",
    SECRET_VALUE,
  ]);
  writeMcpConfig(root, mcpConfigPath, tokenPath, options?.approvalChannel ?? DEFAULT_APPROVAL_CHANNEL);

  return {
    root,
    mcpConfigPath,
    tokenPath,
    glovesBin: binaries.glovesBin,
    glovesMcpBin: binaries.glovesMcpBin,
    secretPath: SECRET_PATH,
    secretValue: SECRET_VALUE,
    cleanup() {
      rmSync(tempRoot, { recursive: true, force: true });
    },
  };
}

function writeCreationRules(root: string): void {
  const storeDir = join(root, "store");
  mkdirSync(storeDir, { recursive: true });
  writeFileSync(
    join(storeDir, ".gloves.yaml"),
    "version: 1\ncreation_rules:\n  - path_regex: ^agents/devy/.*$\n    age: []\n  - path_regex: ^agents/main/.*$\n    age: []\n",
  );
}

function writeMcpConfig(
  root: string,
  configPath: string,
  tokenPath: string,
  approvalChannel: string,
): void {
  const contents = `[daemon]
session_token_path = ${JSON.stringify(tokenPath)}
[daemon.approval]
default_channel = ${JSON.stringify(approvalChannel)}
timeout_seconds = 5
[store]
path = ${JSON.stringify(join(root, "store"))}
[identities]
path = ${JSON.stringify(join(root, "identities"))}
[audit]
path = ${JSON.stringify(join(root, "audit"))}
`;
  writeFileSync(configPath, contents);
}

function runGlovesCommand(glovesBin: string, root: string, args: string[]): void {
  const command = spawnSync(glovesBin, ["--root", root, ...args], {
    cwd: REPO_ROOT,
    encoding: "utf8",
  });
  if (command.status !== 0) {
    throw new Error(command.stderr || `gloves command failed: ${args.join(" ")}`);
  }
}
