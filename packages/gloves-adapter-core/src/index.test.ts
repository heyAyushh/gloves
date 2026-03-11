import { describe, expect, mock, test } from "bun:test";

import {
  defaultSecretEnvName,
  injectSecretValue,
  resolveSecretValueFromSources,
  validateSecretInjectionConfig,
} from "./index";

describe("@gloves/adapter-core", () => {
  test("defaultSecretEnvName derives a portable environment variable name", () => {
    expect(defaultSecretEnvName("agents/devy/api-keys/openai")).toBe("OPENAI");
    expect(defaultSecretEnvName("shared/database-url")).toBe("DATABASE_URL");
  });

  test("resolveSecretValueFromSources prefers environment values and falls back to process values", () => {
    expect(
      resolveSecretValueFromSources("API_KEY", {
        readEnvironment: (name) => name === "API_KEY" ? "sandbox-secret" : undefined,
        readProcessEnvironment: () => "process-secret",
      }),
    ).toBe("sandbox-secret");

    expect(
      resolveSecretValueFromSources("API_KEY", {
        readEnvironment: () => undefined,
        readProcessEnvironment: (name) => name === "API_KEY" ? "process-secret" : undefined,
      }),
    ).toBe("process-secret");
  });

  test("resolveSecretValueFromSources fails when no source can provide the secret", () => {
    expect(() =>
      resolveSecretValueFromSources("MISSING_SECRET", {
        readEnvironment: () => undefined,
        readProcessEnvironment: () => undefined,
      })
    ).toThrow("MISSING_SECRET");
  });

  test("validateSecretInjectionConfig rejects tmpfs mode without required options", () => {
    expect(() =>
      validateSecretInjectionConfig(
        { injectMode: "tmpfs" },
        {},
      )
    ).toThrow("tmpfsPath");

    expect(() =>
      validateSecretInjectionConfig(
        { injectMode: "both", tmpfsPath: "/run/secrets" },
        {},
      )
    ).toThrow("file writer");
  });

  test("injectSecretValue writes through environment and tmpfs sinks", async () => {
    const setEnv = mock(() => {});
    const writeFile = mock(async () => {});

    const result = await injectSecretValue(
      "agents/devy/api-keys/anthropic",
      "sk-test",
      undefined,
      { injectMode: "both", tmpfsPath: "/run/secrets" },
      {
        env: { set: setEnv },
        writeFile,
      },
    );

    expect(result).toEqual({
      injectTarget: "ANTHROPIC",
      injectMethod: "both",
    });
    expect(setEnv).toHaveBeenCalledWith("ANTHROPIC", "sk-test");
    expect(writeFile).toHaveBeenCalledWith("/run/secrets/ANTHROPIC", "sk-test", {
      mode: 0o600,
    });
  });
});
