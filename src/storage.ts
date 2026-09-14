/**
 * storage.ts — durable persistence for API key records.
 *
 * Two stores back the manager:
 *  - MemoryStore — ephemeral, useful for tests and single-process services.
 *  - FileStore    — JSONL document that persists across restarts, written
 *                   atomically (temp file + rename) so a crash never
 *                   corrupts the store.
 */

import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";

import { fingerprint, KEY_PREFIX, newKeyId, shortPrefix } from "./crypto.ts";
import { GLOBAL_PROVIDER } from "./crypto.ts";
import type { ApiKeyRecord, CreateKeyOptions, KeyStore } from "./types.ts";

/**
 * Build a persisted record from a freshly-issued secret. Only the one-way
 * fingerprint of the secret is stored — never the secret itself.
 */
export function makeRecord(
  secret: string,
  opts: CreateKeyOptions,
  pepper?: string,
): ApiKeyRecord {
  const now = Date.now();
  const provider = opts.provider ?? GLOBAL_PROVIDER;
  const quota = opts.quota && opts.quota > 0 ? Math.floor(opts.quota) : undefined;
  const threshold =
    opts.alertThreshold === undefined
      ? 0.8
      : Math.min(0.999, Math.max(0.001, opts.alertThreshold));
  return {
    id: newKeyId(),
    provider,
    name: opts.name ?? "",
    prefix: shortPrefix(secret),
    fingerprint: fingerprint(secret, pepper),
    createdAt: now,
    expiresAt: opts.ttlMs != null ? now + opts.ttlMs : undefined,
    idleTtlMs: opts.idleTtlMs && opts.idleTtlMs > 0 ? opts.idleTtlMs : undefined,
    quota,
    usage: 0,
    useCount: 0,
    rotations: 0,
    revocations: 0,
    alertThreshold: threshold,
    alerted: false,
    revoked: false,
    metadata: opts.metadata ?? {},
  };
}

/** Fingerprint a presented secret for comparison against stored records. */
export function deriveFingerprint(secret: string, pepper?: string): string {
  return fingerprint(secret, pepper);
}

/** Simple in-memory store used by tests and ephemeral single-process setups. */
export class MemoryStore implements KeyStore {
  private data: ApiKeyRecord[] = [];
  load(): ApiKeyRecord[] {
    return this.data;
  }
  save(records: ApiKeyRecord[]): void {
    this.data = records;
  }
}

export interface FileStoreOptions {
  /** Path to the JSONL file (default "keys.jsonl"). */
  file?: string;
}

function parseLine(line: string): ApiKeyRecord | null {
  const trimmed = line.trim();
  if (!trimmed) return null;
  try {
    return JSON.parse(trimmed) as ApiKeyRecord;
  } catch {
    return null; // skip a malformed line rather than losing the whole store
  }
}

/**
 * File-backed store persisting one JSON record per line (JSONL). Writes are
 * atomic (temp file + rename) so a crash never corrupts the store.
 */
export class FileStore implements KeyStore {
  private file: string;

  constructor(opts: FileStoreOptions = {}) {
    this.file = opts.file ?? "keys.jsonl";
  }

  load(): ApiKeyRecord[] {
    if (!existsSync(this.file)) return [];
    const records: ApiKeyRecord[] = [];
    for (const line of readFileSync(this.file, "utf8").split("\n")) {
      const rec = parseLine(line);
      if (rec) records.push(rec);
    }
    return records;
  }

  save(records: ApiKeyRecord[]): void {
    const body = records.map((r) => JSON.stringify(r)).join("\n");
    const out = records.length ? body + "\n" : "";
    const tmp = this.file + ".tmp";
    writeFileSync(tmp, out, "utf8");
    renameSync(tmp, this.file);
  }
}

export { KEY_PREFIX };
