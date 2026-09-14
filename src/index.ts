/**
 * index.ts — public entry point for api-key-manager.
 *
 *   import { ApiKeyManager, FileStore, createManager } from "api-key-manager";
 *
 *   const manager = createManager({ file: "keys.jsonl" });
 *   const { raw } = await manager.createKey({ provider: "openai", quota: 1000 });
 */

import { ApiKeyManager, parseBearer } from "./manager.ts";
import type { ManagerOptions } from "./manager.ts";
import { FileStore, MemoryStore, makeRecord } from "./storage.ts";
import { deriveFingerprint } from "./storage.ts";
import { fingerprint, generateKey, newKeyId, shortPrefix, GLOBAL_PROVIDER } from "./crypto.ts";
import { ConsoleSink, HttpSink, MemorySink } from "./provider/base.ts";
import { run as cli } from "./cli.ts";
import type {
  ApiKeyRecord,
  CreateKeyOptions,
  KeyStore,
  RotateOptions,
  Rotation,
  UsageSink,
  Validation,
  ValidOptions,
} from "./types.ts";

export {
  ApiKeyManager,
  parseBearer,
  FileStore,
  MemoryStore,
  makeRecord,
  deriveFingerprint,
  fingerprint,
  generateKey,
  newKeyId,
  shortPrefix,
  GLOBAL_PROVIDER,
  ConsoleSink,
  HttpSink,
  MemorySink,
  cli,
};

export type {
  ApiKeyRecord,
  CreateKeyOptions,
  KeyStore,
  ManagerOptions,
  RotateOptions,
  Rotation,
  UsageSink as UsageProvider,
  Validation,
  ValidOptions,
};

/**
 * Convenience factory: a manager backed by a persisted JSONL file, with an
 * optional pepper secret (read from `secret` or `API_KEY_MANAGER_SECRET`).
 */
export function createManager(
  options: ManagerOptions & { file?: string } = {},
): ApiKeyManager {
  const { file, ...rest } = options;
  const store =
    rest.store ?? (file ? new FileStore({ file }) : new MemoryStore());
  const secret =
    rest.secret ??
    (typeof process !== "undefined" ? process.env.API_KEY_MANAGER_SECRET : undefined);
  return new ApiKeyManager({ ...rest, store, secret });
}

export { ApiKeyManager as default };
