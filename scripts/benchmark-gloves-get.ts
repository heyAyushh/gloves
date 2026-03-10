#!/usr/bin/env bun

type Options = {
  root: string;
  agent: string;
  path: string;
  iterations: number;
  warmups: number;
};

const DEFAULT_ITERATIONS = 10;
const DEFAULT_WARMUPS = 2;
const TARGET_MS = 50;
const GLOVES_BIN = process.env.GLOVES_BIN || "gloves";

function parseArgs(argv: string[]): Options {
  const values = new Map<string, string>();
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) {
      throw new Error(`unexpected argument: ${token}`);
    }
    const next = argv[index + 1];
    if (!next || next.startsWith("--")) {
      throw new Error(`missing value for ${token}`);
    }
    values.set(token.slice(2), next);
    index += 1;
  }

  const root = values.get("root");
  const agent = values.get("agent");
  const path = values.get("path");
  if (!root || !agent || !path) {
    throw new Error("usage: bun run scripts/benchmark-gloves-get.ts --root <path> --agent <id> --path <secret> [--iterations <n>] [--warmups <n>]");
  }

  const iterations = Number(values.get("iterations") ?? DEFAULT_ITERATIONS);
  const warmups = Number(values.get("warmups") ?? DEFAULT_WARMUPS);
  if (!Number.isInteger(iterations) || iterations <= 0) {
    throw new Error("--iterations must be a positive integer");
  }
  if (!Number.isInteger(warmups) || warmups < 0) {
    throw new Error("--warmups must be a non-negative integer");
  }

  return { root, agent, path, iterations, warmups };
}

function runGet(options: Options): number {
  const startedAt = performance.now();
  const result = Bun.spawnSync({
    cmd: [
      GLOVES_BIN,
      "--root",
      options.root,
      "--agent",
      options.agent,
      "get",
      options.path,
      "--format",
      "raw",
    ],
    stdout: "ignore",
    stderr: "pipe",
  });
  const elapsedMs = performance.now() - startedAt;
  if (result.exitCode !== 0) {
    const stderr = Buffer.from(result.stderr).toString("utf8").trim();
    throw new Error(stderr || `gloves get failed with exit code ${result.exitCode}`);
  }
  return Number(elapsedMs.toFixed(3));
}

function percentile(samples: number[], ratio: number): number {
  const sorted = [...samples].sort((left, right) => left - right);
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * ratio) - 1));
  return sorted[index];
}

function average(samples: number[]): number {
  const total = samples.reduce((sum, value) => sum + value, 0);
  return total / samples.length;
}

function main() {
  const options = parseArgs(Bun.argv.slice(2));
  for (let count = 0; count < options.warmups; count += 1) {
    runGet(options);
  }

  const samples: number[] = [];
  for (let count = 0; count < options.iterations; count += 1) {
    samples.push(runGet(options));
  }

  const summary = {
    command: "gloves get",
    root: options.root,
    agent: options.agent,
    path: options.path,
    iterations: options.iterations,
    warmups: options.warmups,
    target_ms: TARGET_MS,
    min_ms: Math.min(...samples),
    max_ms: Math.max(...samples),
    avg_ms: Number(average(samples).toFixed(3)),
    p50_ms: Number(percentile(samples, 0.5).toFixed(3)),
    p95_ms: Number(percentile(samples, 0.95).toFixed(3)),
    meets_target: average(samples) < TARGET_MS,
    samples_ms: samples,
  };

  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
}

try {
  main();
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
