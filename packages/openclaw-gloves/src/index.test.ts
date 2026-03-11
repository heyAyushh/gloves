import { describe, expect, test } from "bun:test";

import canonicalPlugin from "@gloves/openclaw";
import legacyPlugin from "./index";

describe("@openclaw/gloves", () => {
  test("re-exports the canonical OpenClaw adapter", () => {
    expect(legacyPlugin).toBe(canonicalPlugin);
  });
});
