export type SecretInjectMode = "env" | "tmpfs" | "both";

export interface SecretInjectionConfig {
  injectMode: SecretInjectMode;
  tmpfsPath?: string;
}

export interface SecretEnvironment {
  set: (name: string, value: string) => void;
  get?: (name: string) => string | undefined;
}

export interface SecretInjectionSink {
  env: SecretEnvironment;
  writeFile?: (path: string, contents: string, options?: { mode?: number }) => Promise<void> | void;
}

export interface SecretReadSources {
  readEnvironment?: (name: string) => string | undefined;
  readProcessEnvironment?: (name: string) => string | undefined;
}

export interface SecretInjectionResult {
  injectTarget: string;
  injectMethod: SecretInjectMode;
}

export function defaultSecretEnvName(path: string): string {
  return path
    .split("/")
    .at(-1)!
    .replace(/[^A-Za-z0-9]/g, "_")
    .toUpperCase();
}

export function resolveSecretValueFromSources(
  envName: string,
  sources: SecretReadSources,
): string {
  const environmentValue = sources.readEnvironment?.(envName);
  if (typeof environmentValue === "string") {
    return environmentValue;
  }

  const processValue = sources.readProcessEnvironment?.(envName);
  if (typeof processValue === "string") {
    return processValue;
  }

  throw new Error(
    `secret source '${envName}' is not available via environment or process sources`,
  );
}

export function validateSecretInjectionConfig(
  config: SecretInjectionConfig,
  sink: Pick<SecretInjectionSink, "writeFile">,
): void {
  if (config.injectMode === "tmpfs" || config.injectMode === "both") {
    if (!config.tmpfsPath) {
      throw new Error("tmpfs injection requires tmpfsPath at adapter startup");
    }
    if (!sink.writeFile) {
      throw new Error("tmpfs injection requires a file writer at adapter startup");
    }
  }
}

export async function injectSecretValue(
  secretPath: string,
  secretValue: string,
  requestedEnvName: string | undefined,
  config: SecretInjectionConfig,
  sink: SecretInjectionSink,
): Promise<SecretInjectionResult> {
  validateSecretInjectionConfig(config, sink);

  const envName = requestedEnvName && requestedEnvName.length > 0
    ? requestedEnvName
    : defaultSecretEnvName(secretPath);

  if (config.injectMode === "env" || config.injectMode === "both") {
    sink.env.set(envName, secretValue);
  }

  if (config.injectMode === "tmpfs" || config.injectMode === "both") {
    await sink.writeFile!(
      `${config.tmpfsPath}/${envName}`,
      secretValue,
      { mode: 0o600 },
    );
  }

  return {
    injectTarget: envName,
    injectMethod: config.injectMode,
  };
}
