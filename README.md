# API Key Manager

[![CI](https://github.com/Retsumdk/api-key-manager/workflows/CI/badge.svg)](https://github.com/Retsumdk/api-key-manager/actions)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-blue.svg)](https://www.typescriptlang.org/)
[![Bun](https://img.shields.io/badge/Bun-1.2-black.svg)](https://bun.sh)
[![Zero Deps](https://img.shields.io/badge/runtime_deps-0-brightgreen.svg)](package.json)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Rotating API key management with usage tracking: secure generation, quotas,
revocation, rotation, and durable persistence — with the guarantee that **no
plaintext key is ever stored**.

Built for production services that need to issue and rotate credentials for
multiple providers (OpenAI, Anthropic, internal APIs, …) without building
another key table.

## Problem

API keys are the load-bearing credential of most backends, yet they are
usually stored as plaintext in a database or config file. A single leaked
store file exposes every customer's live key. Rotation and per-key quota
enforcement are almost always bolted on after the fact, and "rotating" usually
means manually generating a new key and hoping callers pick it up.

## Solution

`api-key-manager` stores **only a one-way fingerprint** of each key — never
the key itself. A leaked store is useless to an attacker because the secret
can't be recovered from the fingerprint.

It provides:

- **Secure generation** — cryptographically random secrets (32 bytes, base64url)
  with an optional provider namespace.
- **Fingerprint-at-rest security** — SHA-256, or HMAC-SHA-256 when a pepper
  (`secret`) is provided, so precomputed rainbow tables are useless.
- **Quotas & usage tracking** — per-key usage counters with a one-shot alert
  when a configurable threshold is crossed, and hard denial past the quota.
- **Revocation & rotation** — soft-revoke a key, or rotate it to mint a fresh
  secret that inherits provider / quota / metadata. The old key can be left
  active for a grace window (`revokeOld: false`) so callers can migrate.
- **Durable persistence** — append-safe JSONL `FileStore` with atomic writes,
  or an in-memory `MemoryStore` for ephemeral/services/tests.
- **Pluggable usage sinks** — `ConsoleSink`, `HttpSink`, or `MemorySink` to
  stream usage / alert events to any backend.
- **Middleware & CLI** — an Express-style middleware to gate requests by
  `Authorization: Bearer`, and a full command-line interface.

## How it works

```
                    ┌────────────────────────────────────────────┐
   issue/validate   │              ApiKeyManager                 │
 ─────────────────► │  create / validate / use / revoke / rotate │
                    │                    │                        │
                    │                    ▼                        │
                    │        fingerprint(secret[, pepper])       │
                    │      (HMAC-SHA-256 or SHA-256, one-way)    │
                    │                    │                        │
                    │                    ▼                        │
                    │              KeyStore (JSONL / memory)     │
                    │        stores: id, prefix, fingerprint,    │
                    │        quotas, usage, revocation, lineage  │
                    └────────────────────────────────────────────┘
                                         │
                                         ▼
                              UsageSink (console / http / memory)
                                   usage & threshold-alert events
```

A key is created by generating a random secret and storing its fingerprint.
To validate, the presented secret is fingerprinted and matched against the
store — the secret itself is never required to be persisted. Rotation mints a
new secret, records the lineage on the old record, and (by default) revokes it.

## Getting started

Requires [Bun](https://bun.sh) (or Node ≥ 18 for the library API).

```bash
git clone https://github.com/Retsumdk/api-key-manager.git
cd api-key-manager
bun install
bun run build
```

### Library usage

```ts
import { ApiKeyManager, FileStore } from "api-key-manager";

const manager = new ApiKeyManager({
  store: new FileStore({ file: "keys.jsonl" }),
  secret: process.env.KEY_MANAGER_PEPPER, // optional: HMAC fingerprints
});

// Issue a key (shown exactly once, never recoverable):
const { raw, key } = manager.createKey({ provider: "openai", quota: 1000 });

// Validate + charge one unit:
const result = manager.validate(raw, { consume: true });
if (result.ok) console.log("remaining:", result.remaining);
else console.log("denied:", result.reason);

// Rotate when the key leaks:
const { replacement } = manager.rotate(key.id);
```

### Middleware (Express-style)

```ts
import { ApiKeyManager } from "api-key-manager";

const manager = new ApiKeyManager();
app.use("/api", manager.middleware({ consume: true }));

app.get("/api/me", (req, res) => res.json({ keyId: req.apiKey.id }));
```

Every request that passes validation is charged one usage unit; missing or
invalid bearer tokens get a `401` with a `WWW-Authenticate` header.

## CLI

The CLI talks to a local JSONL store and is ideal for ops tooling and scripts.

```bash
# Issue a key for the "openai" provider with a 1000-call quota, 90-day TTL
api-key-manager create --provider openai --name prod --quota 1000 --ttl 90d --store keys.jsonl
# {
#   "id": "1f0e2c6c-…", "provider": "openai", "prefix": "akm_open",
#   "key": "akm_openai_…", "remaining": 1000,
#   "message": "Store this key now — it is shown once and never recoverable." }
```

```bash
# Validate and consume one unit
api-key-manager validate akm_openai_… --consume --store keys.jsonl
# OK — valid key (openai/prod), remaining: 999
```

```bash
api-key-manager list --store keys.jsonl                 # table of keys
api-key-manager list --provider openai --store keys.jsonl
api-key-manager rotate <id> --store keys.jsonl          # revoke old, print new
api-key-manager rotate <id> --keep-old                  # grace-window rotation
api-key-manager revoke <id> --store keys.jsonl
api-key-manager status --store keys.jsonl
```

Set `API_KEY_MANAGER_SECRET` to pepper fingerprints from the environment
instead of passing `--secret`.

### Duration syntax

`--ttl` / `--idle` accept `90d`, `24h`, `45m`, `30s`, `2w`, `500ms`.

## Configuration

| Option              | Default   | Description                                            |
| ------------------- | --------- | ------------------------------------------------------ |
| `store`             | `MemoryStore` | Backing `KeyStore` (`FileStore` for persistence).    |
| `secret`            | —         | Pepper for HMAC fingerprints (or `API_KEY_MANAGER_SECRET`). |
| `defaultAlertThreshold` | `0.8`  | Fraction of quota at which a one-shot alert fires.    |
| `sinks`             | `[]`      | `UsageSink[]` notified on use / alert events.          |
| `file` (`FileStore`) | `keys.jsonl` | Path to the JSONL store file.                        |

Per-key options on `createKey` / `rotate`: `provider`, `name`, `quota`,
`ttlMs`, `idleTtlMs`, `alertThreshold`, `metadata`.

## API reference

| Method | Description |
| ------ | ----------- |
| `createKey(opts)` | Issue a key; returns `{ raw, key }` (`raw` shown once). |
| `validate(raw, { consume }, amount=1)` | Validate (and optionally charge) a key. |
| `useById(id, amount=1)` | Record usage directly; enforces quota. |
| `revoke(id)` | Soft-revoke by id. |
| `rotate(id, { revokeOld, quota })` | Mint a replacement key. |
| `delete(id)` / `reset()` | Remove / clear all records. |
| `listKeys()` / `listByProvider(p)` | List active records. |
| `remaining(key)` | Remaining capacity (`undefined` = unlimited). |
| `checkHeader(auth)` | Parse + validate a bearer header. |
| `middleware({ consume, header })` | Express-style gate. |

Also exported: `FileStore`, `MemoryStore`, `ConsoleSink`, `HttpSink`,
`MemorySink` (usage sinks), and the `createManager({ file })` convenience
factory.

## Related Repos

- [json-schema-validator](https://github.com/Retsumdk/json-schema-validator) — JSON Schema validation middleware
- [audit-logger](https://github.com/Retsumdk/audit-logger) — Immutable audit trail for compliance
- [rate-limiter-middleware](https://github.com/Retsumdk/rate-limiter-middleware) — API rate limiting

## License

MIT License — see [LICENSE](LICENSE).
