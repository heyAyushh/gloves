#!/usr/bin/env bun

import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { join, resolve } from "node:path";

import { ensureGlovesBinaries } from "../packages/gloves-client/src/testing";

type DockerFixture = {
  tempDir: string;
  root: string;
  runtimeDir: string;
  artifactsDir: string;
  mcpConfigPath: string;
  agentStdoutPath: string;
  agentStderrPath: string;
  ownSecretPath: string;
  ownSecretValue: string;
  otherSecretPath: string;
  otherSecretValue: string;
};

type ScriptOptions = {
  imageTag: string;
  keepTemp: boolean;
};

const REPO_ROOT = resolve(import.meta.dir, "..");
const TEMP_ROOT = join(REPO_ROOT, ".tmp");
const IMAGE_TAG_DEFAULT = "gloves-agent-sandbox:e2e";
const DOCKER_TIMEOUT_MS = 180_000;
const OWN_SECRET_PATH = "agents/devy/api-keys/anthropic";
const OWN_SECRET_VALUE = "sk-ant-api03-docker-e2e";
const OTHER_SECRET_PATH = "agents/webhook/tokens/github-pat";
const OTHER_SECRET_VALUE = "github_pat_docker_e2e";

function parseArgs(argv: string[]): ScriptOptions {
  let imageTag = IMAGE_TAG_DEFAULT;
  let keepTemp = false;

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--keep-temp") {
      keepTemp = true;
      continue;
    }
    if (token === "--image-tag") {
      const next = argv[index + 1];
      if (!next) {
        throw new Error("missing value for --image-tag");
      }
      imageTag = next;
      index += 1;
      continue;
    }
    throw new Error(`unexpected argument: ${token}`);
  }

  return { imageTag, keepTemp };
}

function runChecked(
  command: string,
  args: string[],
  options?: {
    cwd?: string;
    env?: Record<string, string>;
    timeoutMs?: number;
    allowFailure?: boolean;
  },
) {
  const result = spawnSync(command, args, {
    cwd: options?.cwd ?? REPO_ROOT,
    env: { ...process.env, ...(options?.env ?? {}) },
    encoding: "utf8",
    timeout: options?.timeoutMs,
  });
  if (!options?.allowFailure && result.status !== 0) {
    const stderr = result.stderr?.trim();
    const stdout = result.stdout?.trim();
    throw new Error(
      stderr || stdout || `${command} ${args.join(" ")} failed with exit code ${result.status}`,
    );
  }
  return result;
}

function assertDockerDaemonAvailable() {
  const result = runChecked("docker", ["version"], { allowFailure: true });
  if (result.status === 0) {
    return;
  }

  const stderr = result.stderr?.trim() || result.stdout?.trim() || "unknown docker error";
  throw new Error(
    `docker daemon is unavailable. Start Docker Desktop or the local docker service and retry.\n${stderr}`,
  );
}

function buildDockerImage(dockerfilePath: string, imageTag: string) {
  runChecked("docker", [
    "build",
    "--file",
    dockerfilePath,
    "--tag",
    imageTag,
    ".",
  ]);
}

function createFixture(glovesBin: string): DockerFixture {
  mkdirSync(TEMP_ROOT, { recursive: true });
  const tempDir = mkdtempSync(join(TEMP_ROOT, "docker-e2e-"));
  const root = join(tempDir, "root");
  const runtimeDir = join(tempDir, "runtime");
  const artifactsDir = join(tempDir, "artifacts");
  const mcpConfigPath = join(runtimeDir, "gloves.toml");
  const agentStdoutPath = join(tempDir, "agent.stdout.log");
  const agentStderrPath = join(tempDir, "agent.stderr.log");

  mkdirSync(root, { recursive: true });
  mkdirSync(runtimeDir, { recursive: true });
  mkdirSync(artifactsDir, { recursive: true });
  mkdirSync(join(root, "store"), { recursive: true });

  runGloves(glovesBin, root, ["set-identity", "--agent", "devy"]);
  runGloves(glovesBin, root, ["set-identity", "--agent", "webhook"]);
  writeFileSync(
    join(root, "store", ".gloves.yaml"),
    [
      "version: 1",
      "creation_rules:",
      "  - path_regex: ^agents/devy/.*$",
      "    age: []",
      "  - path_regex: ^agents/webhook/.*$",
      "    age: []",
      "",
    ].join("\n"),
  );
  runGloves(glovesBin, root, [
    "--agent",
    "devy",
    "set",
    OWN_SECRET_PATH,
    "--value",
    OWN_SECRET_VALUE,
  ]);
  runGloves(glovesBin, root, [
    "--agent",
    "webhook",
    "set",
    OTHER_SECRET_PATH,
    "--value",
    OTHER_SECRET_VALUE,
  ]);
  writeFileSync(
    mcpConfigPath,
    [
      "[daemon]",
      'session_token_path = "/run/gloves/session-token"',
      "[daemon.approval]",
      'default_channel = "auto"',
      "timeout_seconds = 5",
      "[store]",
      'path = "/data/root/store"',
      "[identities]",
      'path = "/data/root/identities"',
      "[audit]",
      'path = "/data/root/audit"',
      "",
    ].join("\n"),
  );

  return {
    tempDir,
    root,
    runtimeDir,
    artifactsDir,
    mcpConfigPath,
    agentStdoutPath,
    agentStderrPath,
    ownSecretPath: OWN_SECRET_PATH,
    ownSecretValue: OWN_SECRET_VALUE,
    otherSecretPath: OTHER_SECRET_PATH,
    otherSecretValue: OTHER_SECRET_VALUE,
  };
}

function runGloves(glovesBin: string, root: string, args: string[]) {
  runChecked(glovesBin, ["--root", root, ...args]);
}

function dockerUser(): string {
  return typeof process.getuid === "function" && typeof process.getgid === "function"
    ? `${process.getuid()}:${process.getgid()}`
    : "1000:1000";
}

function dockerUid(): number {
  return typeof process.getuid === "function" ? process.getuid() : 1000;
}

function dockerGid(): number {
  return typeof process.getgid === "function" ? process.getgid() : 1000;
}

function runSandboxContainer(imageTag: string, fixture: DockerFixture) {
  const baseArgs = [
    "run",
    "--rm",
    "--network=none",
    "--read-only",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges:true",
    "--tmpfs",
    "/tmp:size=64M,noexec,nosuid,nodev",
    "--tmpfs",
    `/run/secrets:size=10M,mode=0700,uid=${dockerUid()},gid=${dockerGid()},noexec,nosuid,nodev`,
    "--user",
    dockerUser(),
    "--env",
    "HOME=/tmp",
    "--env",
    "TMPDIR=/tmp",
    "--env",
    "GLOVES_ROOT=/data/root",
    "--env",
    "GLOVES_MCP_CONFIG=/run/gloves/gloves.toml",
    "--env",
    "GLOVES_TOKEN_PATH=/run/gloves/session-token",
    "--env",
    "GLOVES_MCP_BIN=/usr/local/bin/gloves-mcp",
    "--env",
    "GLOVES_AGENT_ID=devy",
    "--env",
    `GLOVES_OWN_SECRET=${fixture.ownSecretPath}`,
    "--env",
    `GLOVES_OTHER_SECRET=${fixture.otherSecretPath}`,
    "--env",
    "GLOVES_INJECT_AS=ANTHROPIC_API_KEY",
    "--env",
    "GLOVES_ARTIFACTS_DIR=/artifacts",
    "--volume",
    `${fixture.root}:/data/root`,
    "--volume",
    `${fixture.runtimeDir}:/run/gloves`,
    "--volume",
    `${fixture.artifactsDir}:/artifacts`,
    imageTag,
  ];
  const hardenedArgs = [...baseArgs];
  hardenedArgs.splice(6, 0, "--security-opt=seccomp=default");

  let result = runChecked("docker", hardenedArgs, {
    timeoutMs: DOCKER_TIMEOUT_MS,
    allowFailure: true,
  });
  if (
    result.status !== 0
    && (result.stderr ?? "").includes("opening seccomp profile (default) failed")
  ) {
    result = runChecked("docker", baseArgs, {
      timeoutMs: DOCKER_TIMEOUT_MS,
      allowFailure: true,
    });
  }
  if (result.status !== 0) {
    const stderr = result.stderr?.trim();
    const stdout = result.stdout?.trim();
    throw new Error(stderr || stdout || "docker sandbox run failed");
  }

  writeFileSync(fixture.agentStdoutPath, result.stdout ?? "");
  writeFileSync(fixture.agentStderrPath, result.stderr ?? "");
}

function assertNoSecretLeaks(fixture: DockerFixture) {
  const filesToScan = [
    fixture.agentStdoutPath,
    fixture.agentStderrPath,
    join(fixture.artifactsDir, "conversation.json"),
    join(fixture.artifactsDir, "result.json"),
    join(fixture.root, "audit"),
  ];
  const secrets = [fixture.ownSecretValue, fixture.otherSecretValue];

  for (const path of filesToScan) {
    if (!existsSync(path)) {
      continue;
    }
    if (path.endsWith("/audit")) {
      for (const entry of readdirSync(path)) {
        assertFileDoesNotContainSecrets(join(path, entry), secrets);
      }
      continue;
    }
    assertFileDoesNotContainSecrets(path, secrets);
  }
}

function assertFileDoesNotContainSecrets(path: string, secrets: string[]) {
  const payload = readFileSync(path);
  for (const secret of secrets) {
    if (payload.includes(Buffer.from(secret))) {
      throw new Error(`secret plaintext leaked into ${path}`);
    }
  }
}

function assertContainerArtifacts(fixture: DockerFixture) {
  const result = JSON.parse(
    readFileSync(join(fixture.artifactsDir, "result.json"), "utf8"),
  ) as Record<string, unknown>;
  const conversation = JSON.parse(
    readFileSync(join(fixture.artifactsDir, "conversation.json"), "utf8"),
  ) as Array<Record<string, unknown>>;

  if (result.success !== true) {
    throw new Error("sandbox result.json did not report success");
  }
  if (result.crossAgentDenied !== true) {
    throw new Error("sandbox did not deny cross-agent access");
  }
  if (!Array.isArray(conversation) || conversation.length < 3) {
    throw new Error("sandbox conversation log is incomplete");
  }
}

function assertRevokedIdentityCannotDecrypt(glovesBin: string, fixture: DockerFixture) {
  runGloves(glovesBin, fixture.root, [
    "--agent",
    "devy",
    "get",
    fixture.ownSecretPath,
    "--format",
    "raw",
  ]);

  const revokedIdentityName = readdirSync(join(fixture.root, "identities")).find((entry) =>
    entry.startsWith("devy.age.revoked-")
  );
  if (!revokedIdentityName) {
    throw new Error("rotate did not archive the old devy identity");
  }

  const currentIdentityPath = join(fixture.root, "identities", "devy.age");
  const backupIdentityPath = join(fixture.root, "identities", "devy.age.current");
  const revokedIdentityPath = join(fixture.root, "identities", revokedIdentityName);
  renameSync(currentIdentityPath, backupIdentityPath);
  copyFileSync(revokedIdentityPath, currentIdentityPath);
  try {
    const result = runChecked(
      glovesBin,
      [
        "--root",
        fixture.root,
        "--agent",
        "devy",
        "get",
        fixture.ownSecretPath,
        "--format",
        "raw",
      ],
      { allowFailure: true },
    );
    if (result.status === 0) {
      throw new Error("revoked identity unexpectedly decrypted the rotated secret");
    }
  } finally {
    rmSync(currentIdentityPath, { force: true });
    renameSync(backupIdentityPath, currentIdentityPath);
  }
}

function printSummary(fixture: DockerFixture) {
  const summary = {
    command: "bun run docker:e2e",
    fixture: fixture.tempDir,
    artifacts: fixture.artifactsDir,
    checks: [
      "plugin stdio read succeeded",
      "cross-agent access denied",
      "tool responses remained redacted",
      "rotation preserved access",
      "revoked identity lost decrypt access",
    ],
  };
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
}

function cleanup(fixture: DockerFixture, keepTemp: boolean) {
  if (!keepTemp) {
    rmSync(fixture.tempDir, { recursive: true, force: true });
  }
}

try {
  const options = parseArgs(Bun.argv.slice(2));
  const { glovesBin } = ensureGlovesBinaries();
  assertDockerDaemonAvailable();
  buildDockerImage("docker/agent-sandbox.Dockerfile", options.imageTag);

  const fixture = createFixture(glovesBin);
  try {
    runSandboxContainer(options.imageTag, fixture);
    assertContainerArtifacts(fixture);
    assertNoSecretLeaks(fixture);
    assertRevokedIdentityCannotDecrypt(glovesBin, fixture);
    printSummary(fixture);
  } finally {
    cleanup(fixture, options.keepTemp);
  }
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
