/**
 * crypto.ts — key generation and fingerprinting primitives.
 *
 * The core security guarantee of this library: full key material is never
 * persisted. Only a deterministic fingerprint (and a short display prefix)
 * are stored, so a leaked store file does not expose usable keys, and API
 * keys cannot be recovered from the store by anyone who grabs it.
 */

import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";

/** Namespace used when no provider is supplied. */
export const GLOBAL_PROVIDER = "default";

/** Raw-key prefix that makes keys self-identifying. */
export const KEY_PREFIX = "akm_";

/**
 * Generate a cryptographically random secret (32 bytes, base64url).
 * Optionally namespaced by provider so the key announces its provider on sight.
 */
export function generateKey(provider?: string): string {
  const nonce = randomBytes(32).toString("base64url");
  const p = provider && provider !== GLOBAL_PROVIDER ? `${provider}_` : "";
  return `${KEY_PREFIX}${p}${nonce}`;
}

/** Fresh opaque identifier for a key record. */
export function newKeyId(): string {
  return randomUUID();
}

/** First ~8 chars of the secret for human display; never sufficient to reconstruct it. */
export function shortPrefix(secret: string): string {
  return secret.slice(0, Math.min(secret.length, 8));
}

/**
 * Compute the stored marker for a secret. When a `pepper` (an
 * operator-managed secret) is provided, the marker becomes a keyed HMAC so
 * precomputed rainbow tables are useless; otherwise a plain SHA-256 is used.
 */
export function fingerprint(secret: string, pepper?: string): string {
  const data = Buffer.from(`v1:${secret}`, "utf8");
  return pepper
    ? createHmac("sha256", pepper).update(data).digest("hex")
    : createHash("sha256").update(data).digest("hex");
}
