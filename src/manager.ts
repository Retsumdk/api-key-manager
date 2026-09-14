/**
 * manager.ts — the ApiKeyManager: create, validate, use, revoke, rotate.
 *
 * The manager talks only to a {@link KeyStore} and never holds plaintext
 * keys in memory beyond the moment they are generated. Rotation mints a
 * fresh secret, records the lineage, and (by default) revokes the old key.
 */

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
import { generateKey, GLOBAL_PROVIDER, newKeyId, shortPrefix } from "./crypto.ts";
import { deriveFingerprint, makeRecord, MemoryStore } from "./storage.ts";

export interface ManagerOptions {
  /** Backing store (defaults to in-memory). */
  store?: KeyStore;
  /** Optional pepper — HMACs fingerprints so rainbow tables are useless. */
  secret?: string;
  /** Default alert threshold (fraction of quota) for new keys. */
  defaultAlertThreshold?: number;
  /** Usage-tracking sinks notified on successful uses / threshold alerts. */
  sinks?: UsageSink[];
}

export class ApiKeyManager {
  readonly store: KeyStore;
  readonly sinks: UsageSink[];
  private secret: string | undefined;
  private defaultAlertThreshold: number;

  constructor(options: ManagerOptions = {}) {
    this.store = options.store ?? new MemoryStore();
    this.secret = options.secret;
    this.defaultAlertThreshold = options.defaultAlertThreshold ?? 0.8;
    this.sinks = options.sinks ?? [];
  }

  /** All current records, with auto-expired records filtered out. */
  listKeys(): ApiKeyRecord[] {
    const now = Date.now();
    return this.store
      .load()
      .filter((r) => !this.isExpired(r, now))
      .map((r) => ({ ...r }));
  }

  /** All current records filtered to a single provider. */
  listByProvider(provider: string): ApiKeyRecord[] {
    return this.listKeys().filter((r) => r.provider === provider);
  }

  /**
   * Create a new key. Returns the raw secret exactly once — it cannot be
   * recovered later, only validated (fingerprint lookup).
   */
  createKey(options: CreateKeyOptions = {}): { raw: string; key: ApiKeyRecord } {
    const raw = generateKey(options.provider);
    const record: ApiKeyRecord = makeRecord(raw, options, this.secret);
    this.persist([...this.rawRecords(), record]);
    return { raw, key: { ...record } };
  }

  /**
   * Validate a raw key. If `opts.consume` is set, `amount` usage units are
   * recorded and quota/alert thresholds are enforced.
   */
  validate(
    raw: string,
    opts: ValidOptions = {},
    amount = 1,
  ): Validation {
    const now = Date.now();
    const fp = deriveFingerprint(raw, this.secret);
    const records = this.rawRecords();
    const idx = records.findIndex((r) => r.fingerprint === fp);
    if (idx < 0) {
      return { ok: false, reason: "invalid" };
    }
    const rec = records[idx]!;
    if (rec.revoked) return { ok: false, reason: "revoked", key: { ...rec } };
    if (this.isExpired(rec, now)) {
      return { ok: false, reason: rec.expiresAt ? "expired" : "idle_expired", key: { ...rec } };
    }
    if (rec.quota != null && rec.usage >= rec.quota) {
      return { ok: false, reason: "quota_exceeded", key: { ...rec }, remaining: 0 };
    }
    if (opts.consume) {
      this.applyUsage(records, idx, amount, now);
      return { ok: true, key: { ...records[idx]! }, remaining: remainingFor(records[idx]!) };
    }
    return { ok: true, key: { ...rec }, remaining: remainingFor(rec) };
  }

  /** Record usage without validating; throws if the key doesn't exist. */
  useById(
    id: string,
    amount = 1,
  ): { key: ApiKeyRecord; remaining: number | undefined; alertFired: boolean } {
    const records = this.rawRecords();
    const idx = records.findIndex((r) => r.id === id);
    if (idx < 0) throw new Error(`no key with id '${id}'`);
    const { alertFired } = this.applyUsage(records, idx, amount, Date.now());
    const rec = records[idx]!;
    return {
      key: { ...rec },
      remaining: remainingFor(rec),
      alertFired,
    };
  }

  /** Revoke a key by id (soft-revoke; record is retained). */
  revoke(id: string): boolean {
    const records = this.rawRecords();
    const rec = records.find((r) => r.id === id);
    if (!rec || rec.revoked) return false;
    rec.revoked = true;
    rec.revocations += 1;
    this.persist(records);
    return true;
  }

  /**
   * Rotate a key: (by default) revoke the existing secret and mint a fresh
   * one that inherits provider/name/quota/metadata. The new raw secret is
   * returned exactly once.
   */
  rotate(id: string, opts: RotateOptions = {}): Rotation {
    const records = this.rawRecords();
    const idx = records.findIndex((r) => r.id === id);
    if (idx < 0) throw new Error(`no key with id '${id}'`);
    const old = records[idx]!;
    const now = Date.now();
    const raw = generateKey(old.provider);
    const created: ApiKeyRecord = makeRecord(
      raw,
      {
        provider: old.provider,
        name: old.name,
        quota: opts.quota ?? old.quota,
        idleTtlMs: old.idleTtlMs,
        alertThreshold: old.alertThreshold,
        metadata: { ...old.metadata },
      },
      this.secret,
    );
    old.rotatedInto = created.id;
    old.rotations += 1;
    if (opts.revokeOld !== false) {
      old.revoked = true;
      old.revocations += 1;
    }
    const next = [...records, created];
    this.persist(next);
    return { old: { ...old }, replacement: raw, replacementId: created.id };
  }

  /** Delete a key record permanently (irreversible). */
  delete(id: string): boolean {
    const records = this.rawRecords();
    const next = records.filter((r) => r.id !== id);
    if (next.length === records.length) return false;
    this.persist(next);
    return true;
  }

  /** Reset all records (dangerous — used by maintenance/CLI --reset). */
  reset(): void {
    this.persist([]);
  }

  /** True if the record is revoked or auto-expired at `now`. */
  isExpired(rec: ApiKeyRecord, now = Date.now()): boolean {
    if (rec.revoked) return true;
    if (rec.expiresAt != null && now >= rec.expiresAt) return true;
    if (
      rec.idleTtlMs != null &&
      rec.lastUsedAt != null &&
      now - rec.lastUsedAt >= rec.idleTtlMs
    ) {
      return true;
    }
    return false;
  }

  /** Remaining allowed usage for a record, or undefined if unlimited. */
  remaining(rec: ApiKeyRecord): number | undefined {
    return remainingFor(rec);
  }

  /**
   * Extract a bearer token and validate it without consuming usage. Returns
   * the token and the validation so a server can 401 on failure.
   */
  checkHeader(authorization: string | undefined): { token: string } & Validation {
    const token = parseBearer(authorization);
    if (!token) return { token: "", ok: false, reason: "invalid" };
    const v = this.validate(token);
    return { token, ...v };
  }

  /**
   * Build an Express-style middleware that validates the Authorization header
   * and, when `consume` is true, charges one usage unit per request.
   */
  middleware(options: { consume?: boolean; header?: string } = {}) {
    const { consume = true, header = "authorization" } = options;
    const self = this;
    return function apiKeyMiddleware(req: Record<string, unknown>, res: any, next: () => void) {
      const r = (req as { header?: (n: string) => string | undefined });
      const auth = typeof r.header === "function" ? r.header(header) : undefined;
      const parsed = parseBearer(typeof auth === "string" ? auth : undefined);
      if (!parsed) {
        res.statusCode = 401;
        res.setHeader("WWW-Authenticate", 'Bearer realm="api-key-manager"');
        return res.json({ error: "missing bearer token" });
      }
      const v = self.validate(parsed, { consume }, 1);
      if (!v.ok) {
        res.statusCode = 401;
        res.setHeader("WWW-Authenticate", 'Bearer error="invalid_token"');
        return res.json({ error: `invalid token (${v.reason})` });
      }
      (req as Record<string, unknown>).apiKey = v.key;
      next();
    };
  }

  // --- internals ---

  private rawRecords(): ApiKeyRecord[] {
    return this.store.load();
  }

  private persist(records: ApiKeyRecord[]): void {
    this.store.save(records);
  }

  /** Record usage units and fire a one-shot threshold alert when due. */
  private applyUsage(
    records: ApiKeyRecord[],
    idx: number,
    amount: number,
    now: number,
  ): { alertFired: boolean } {
    const rec = records[idx]!;
    rec.usage += amount;
    rec.useCount += 1;
    rec.lastUsedAt = now;
    let alertFired = false;
    // Reaching the quota simply denies further use with a clear reason; the
    // key is left non-revoked so an operator can raise the quota or rotate.
    if (rec.quota != null && !rec.alerted && rec.quota * rec.alertThreshold <= rec.usage) {
      rec.alerted = true;
      alertFired = true;
    }
    this.persist(records);
    for (const sink of this.sinks) {
      sink.onUse?.(rec, amount);
      if (alertFired) sink.onAlert?.(rec);
    }
    return { alertFired };
  }
}

/** Extract a bearer token from an Authorization header, if well-formed. */
export function parseBearer(authorization: string | undefined): string | undefined {
  if (!authorization) return undefined;
  const match = /^Bearer\s+(.+)$/i.exec(authorization.trim());
  return match ? match[1] : undefined;
}

/** Remaining usage, or undefined for an unlimited key. */
function remainingFor(rec: ApiKeyRecord): number | undefined {
  if (rec.quota == null) return undefined;
  return Math.max(0, rec.quota - rec.usage);
}

export { GLOBAL_PROVIDER };
