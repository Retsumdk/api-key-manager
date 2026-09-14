/**
 * types.ts — shared types for api-key-manager.
 */

/** A persistent key record. Plaintext secrets are never stored. */
export interface ApiKeyRecord {
  /** Stable, opaque identifier (uuid-v4). */
  id: string;
  /** Provider/namespace the key belongs to (multi-provider support). */
  provider: string;
  /** Optional human label. */
  name: string;
  /** Short displayable prefix of the secret (never the full key). */
  prefix: string;
  /** Fingerprint (SHA-256 or HMAC-SHA-256 when a pepper is set). */
  fingerprint: string;
  createdAt: number;
  /** Absolute expiry, if set. */
  expiresAt?: number;
  /** Auto-revoke after this many ms of inactivity, if set. */
  idleTtlMs?: number;
  /** Maximum total usage, or undefined for unlimited. */
  quota?: number;
  /** Current total usage (increments on each consumed validation). */
  usage: number;
  /** Number of individual call events recorded (usage ÷ batch size). */
  useCount: number;
  /** Fraction of quota at which a one-shot alert fires. */
  alertThreshold: number;
  /** Whether the pre-quota alert has fired. */
  alerted: boolean;
  /** Whether the key is revoked. */
  revoked: boolean;
  lastUsedAt?: number;
  /** How many times a key has rotated into this record. */
  rotations: number;
  /** How many times this record has been soft-revoked. */
  revocations: number;
  /** Id of the key this one rotated into, if any. */
  rotatedInto?: string;
  /** Free-form metadata. */
  metadata: Record<string, string>;
}

/** Persistence contract implemented by MemoryStore and FileStore. */
export interface KeyStore {
  load(): ApiKeyRecord[];
  save(records: ApiKeyRecord[]): void;
}

export interface CreateKeyOptions {
  provider?: string;
  name?: string;
  quota?: number;
  ttlMs?: number;
  idleTtlMs?: number;
  alertThreshold?: number;
  metadata?: Record<string, string>;
}

export interface ValidOptions {
  /** When true, usage is recorded and quota enforced. */
  consume?: boolean;
}

export type DenyReason =
  | "invalid"
  | "revoked"
  | "expired"
  | "idle_expired"
  | "quota_exceeded";

export interface Validation {
  ok: boolean;
  reason?: DenyReason;
  key?: ApiKeyRecord;
  /** Remaining capacity (undefined when the key is unlimited). */
  remaining?: number;
}

export interface RotateOptions {
  /** When false, the old key stays valid for a grace window. */
  revokeOld?: boolean;
  /** Override the quota inherited from the old key. */
  quota?: number;
}

export interface Rotation {
  old: ApiKeyRecord;
  /** The new raw secret — returned exactly once. */
  replacement: string;
  /** Stable id of the replacement record. */
  replacementId: string;
}

/** A hook that receives usage and threshold-alert events. */
export interface UsageSink {
  onUse?(key: ApiKeyRecord, amount: number): void;
  onAlert?(key: ApiKeyRecord): void;
}
