import { describe, test, expect } from "bun:test";
import { mkdtempSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ApiKeyManager, FileStore, generateKey, fingerprint, MemorySink, parseBearer } from "../src/index.ts";

function tempStore(): { file: string; store: FileStore; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "akm-"));
  const file = join(dir, "keys.jsonl");
  const store = new FileStore({ file });
  return { file, store, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

describe("crypto", () => {
  test("generateKey produces unique, prefixed keys", () => {
    const a = generateKey();
    const b = generateKey("openai");
    expect(a).toMatch(/^akm_/);
    expect(a).not.toBe(b);
  });

  test("fingerprint is deterministic and pepper-aware", () => {
    const key = generateKey();
    expect(fingerprint(key)).toBe(fingerprint(key));
    expect(fingerprint(key, "pepper")).not.toBe(fingerprint(key));
  });
});

describe("ApiKeyManager — create & validate", () => {
  test("create returns raw once, key is retrievable by id", () => {
    const { store, cleanup } = tempStore();
    const m = new ApiKeyManager({ store });
    const { raw, key } = m.createKey({ provider: "openai", name: "prod" });
    expect(raw).toMatch(/^akm_openai_/);
    expect(m.listKeys().some((k) => k.id === key.id)).toBe(true);
    cleanup();
  });

  test("validate accepts a correct key and rejects an unknown one", () => {
    const m = new ApiKeyManager();
    const { raw } = m.createKey();
    expect(m.validate(raw).ok).toBe(true);
    expect(m.validate("akm_bogus").ok).toBe(false);
    expect(m.validate("akm_bogus").reason).toBe("invalid");
  });

  test("validate(consume) enforces quota", () => {
    const m = new ApiKeyManager();
    const { raw } = m.createKey({ quota: 2 });
    expect(m.validate(raw, { consume: true }).remaining).toBe(1);
    expect(m.validate(raw, { consume: true }).remaining).toBe(0);
    const r = m.validate(raw, { consume: true });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("quota_exceeded");
  });

  test("revoked keys are denied", () => {
    const m = new ApiKeyManager();
    const { raw, key } = m.createKey();
    expect(m.revoke(key.id)).toBe(true);
    expect(m.validate(raw).ok).toBe(false);
    expect(m.validate(raw).reason).toBe("revoked");
  });

  test("expired keys are denied with 'expired' reason", () => {
    const m = new ApiKeyManager();
    const { raw } = m.createKey({ ttlMs: -1000 });
    expect(m.validate(raw).ok).toBe(false);
    expect(m.validate(raw).reason).toBe("expired");
  });

  test("alert fires once near threshold, then auto-revokes at quota", () => {
    const m = new ApiKeyManager({ sinks: [new MemorySink()] });
    const sink = m.sinks[0] as MemorySink;
    const { key, raw } = m.createKey({ quota: 100, alertThreshold: 0.9 });
    for (let i = 0; i < 90; i++) m.validate(raw, { consume: true });
    expect(sink.alerts).toContain(key.id);
    for (let i = 0; i < 10; i++) m.validate(raw, { consume: true });
    expect(m.validate(raw).reason).toBe("quota_exceeded");
    expect(sink.uses.length).toBe(100);
  });
});

describe("ApiKeyManager — rotation", () => {
  test("rotate revokes old key and mints a working replacement", () => {
    const m = new ApiKeyManager();
    const { raw, key } = m.createKey({ provider: "openai", quota: 50 });
    const { old, replacement, replacementId } = m.rotate(key.id);
    expect(old.revoked).toBe(true);
    expect(m.validate(raw).reason).toBe("revoked");
    expect(m.validate(replacement).ok).toBe(true);
    expect(m.validate(replacement).remaining).toBe(50);
    expect(replacementId).not.toBe(key.id);
  });

  test("rotate(keepOld) leaves old key valid (grace window)", () => {
    const m = new ApiKeyManager();
    const { raw, key } = m.createKey();
    const { replacement } = m.rotate(key.id, { revokeOld: false });
    expect(m.validate(raw).ok).toBe(true);
    expect(m.validate(replacement).ok).toBe(true);
  });
});

describe("ApiKeyManager — persistence & multi-provider", () => {
  test("FileStore round-trip preserves records", () => {
    const { file, store, cleanup } = tempStore();
    const m = new ApiKeyManager({ store });
    const { raw, key } = m.createKey({ provider: "anthropic", metadata: { env: "prod" } });
    expect(existsSync(file)).toBe(true);
    const m2 = new ApiKeyManager({ store: new FileStore({ file }) });
    expect(m2.validate(raw).ok).toBe(true);
    expect(m2.listKeys().some((k) => k.id === key.id)).toBe(true);
    cleanup();
  });

  test("listByProvider isolates providers", () => {
    const m = new ApiKeyManager();
    m.createKey({ provider: "openai" });
    m.createKey({ provider: "anthropic" });
    m.createKey({ provider: "openai" });
    expect(m.listByProvider("openai").length).toBe(2);
    expect(m.listByProvider("anthropic").length).toBe(1);
  });

  test("secret pepper keeps fingerprints distinct from plain SHA-256", () => {
    const m = new ApiKeyManager({ secret: "topsecret" });
    const { raw } = m.createKey();
    expect(m.validate(raw).ok).toBe(true);
  });
});

describe("middleware helper", () => {
  test("parseBearer extracts the token; missing scheme yields null", () => {
    expect(parseBearer("Bearer abc123")).toBe("abc123");
    expect(parseBearer("Basic abc")).toBeUndefined();
    expect(parseBearer("")).toBeUndefined();
  });
});
