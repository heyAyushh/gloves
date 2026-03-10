import { cpSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const REPO_ROOT = resolve(import.meta.dir, "../../..");
const OUTPUT_PATH = resolve(import.meta.dir, "../native/gloves_client_native.node");

const build = spawnSync("cargo", ["build", "-p", "gloves-client-native"], {
  cwd: REPO_ROOT,
  stdio: "inherit",
});
if (build.status !== 0) {
  process.exit(build.status ?? 1);
}

const sourcePath = resolve(REPO_ROOT, nativeArtifactRelativePath());
if (!existsSync(sourcePath)) {
  throw new Error(`native addon artifact not found at ${sourcePath}`);
}

mkdirSync(dirname(OUTPUT_PATH), { recursive: true });
cpSync(sourcePath, OUTPUT_PATH);

function nativeArtifactRelativePath(): string {
  if (process.platform === "darwin") {
    return join("target", "debug", "libgloves_client_native.dylib");
  }
  if (process.platform === "linux") {
    return join("target", "debug", "libgloves_client_native.so");
  }
  if (process.platform === "win32") {
    return join("target", "debug", "gloves_client_native.dll");
  }
  throw new Error(`unsupported platform for native addon build: ${process.platform}`);
}
