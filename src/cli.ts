#!/usr/bin/env bun
/**
 * cli.ts — command-line interface for api-key-manager.
 *
 *   api-key-manager create --provider openai --name "prod" --quota 1000
 *   api-key-manager validate akm_xxxx --consume
 *   api-key-manager list
 *   api-key-manager rotate <id>
 */

import { parseArgs } from "node:util";
import { ApiKeyManager } from "./manager.ts";
import { FileStore } from "./storage.ts";

const HELP = `api-key-manager — rotating API key management with usage tracking

Usage:
  api-key-manager <command> [options]

Commands:
  create     Issue a new key        (--provider, --name, --quota, --ttl, --idle, --alert)
  validate   Check a key            (<key>; --consume records one use)
  list       List keys              (--provider)
  revoke     Soft-revoke a key      (<id>)
  rotate     Rotate a key           (<id>; --keep-old, --quota)
  use        Record usage on a key  (<id>; --amount)
  status     Show store summary
  help       Show this help

Global options:
  --store FILE    JSONL store path (default: keys.jsonl)
  --secret SECRET Pepper to HMAC fingerprints (or $API_KEY_MANAGER_SECRET)

Examples:
  api-key-manager create --provider openai --quota 1000 --ttl 90d
  api-key-manager validate akm_<key> --consume
  api-key-manager rotate <id> --keep-old
`;

const UNITS: Record<string, number> = {
  ms: 1,
  s: 1000,
  m: 60_000,
  h: 3_600_000,
  d: 86_400_000,
  w: 604_800_000,
};

function parseDuration(s: string): number {
  const m = /^(\d+(?:\.\d+)?)(ms|s|m|h|d|w)$/.exec(s);
  if (!m || m[1] === undefined || m[2] === undefined) {
    throw new Error(`invalid duration '${s}' (use e.g. 90d, 24h, 45m)`);
  }
  return Math.round(parseFloat(m[1]) * UNITS[m[2]]!);
}

function buildManager(args: Record<string, unknown>): ApiKeyManager {
  const file = typeof args.store === "string" ? args.store : "keys.jsonl";
  const store = new FileStore({ file });
  const secret =
    typeof args.secret === "string"
      ? args.secret
      : process.env.API_KEY_MANAGER_SECRET;
  return new ApiKeyManager({ store, secret });
}

export function run(argv: string[]): number {
  let args: Record<string, unknown>;
  try {
    const parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        store: { type: "string" },
        secret: { type: "string" },
        json: { type: "boolean", default: false },
        provider: { type: "string" },
        name: { type: "string" },
        quota: { type: "string" },
        ttl: { type: "string" },
        idle: { type: "string" },
        alert: { type: "string" },
        consume: { type: "boolean", default: false },
        amount: { type: "string" },
        "keep-old": { type: "boolean", default: false },
      },
    });
    args = { ...parsed.values, positionals: parsed.positionals };
  } catch (err) {
    console.error(String(err));
    return 2;
  }

  const positionals = (args.positionals as string[]) ?? [];
  const [cmd, ...rest] = positionals;
  if (!cmd || cmd === "help" || cmd === "--help" || cmd === "-h") {
    console.log(HELP);
    return 0;
  }

  const manager = buildManager(args);
  const json = args.json === true;

  const emit = (obj: unknown): void => {
    if (json) console.log(JSON.stringify(obj, null, 2));
    else console.log(typeof obj === "string" ? obj : JSON.stringify(obj, null, 2));
  };
  const flag = (name: string): boolean => args[name] === true;
  const str = (name: string): string | undefined =>
    typeof args[name] === "string" ? (args[name] as string) : undefined;

  switch (cmd) {
    case "create": {
      const quotaStr = str("quota");
      const quota = quotaStr ? Number(quotaStr) : undefined;
      if (quota != null && (Number.isNaN(quota) || quota <= 0)) {
        console.error("--quota must be a positive number");
        return 2;
      }
      const ttl = str("ttl");
      const idle = str("idle");
      let ttlMs: number | undefined;
      let idleMs: number | undefined;
      try {
        ttlMs = ttl ? parseDuration(ttl) : undefined;
        idleMs = idle ? parseDuration(idle) : undefined;
      } catch (e) {
        console.error(String(e));
        return 2;
      }
      const { raw, key } = manager.createKey({
        provider: str("provider"),
        name: str("name"),
        quota,
        ttlMs,
        idleTtlMs: idleMs,
        alertThreshold: str("alert") ? Number(str("alert")) : undefined,
      });
      emit({
        id: key.id,
        provider: key.provider,
        prefix: key.prefix,
        key: raw,
        remaining: manager.remaining(key) ?? null,
        message: "Store this key now — it is shown once and never recoverable.",
      });
      return 0;
    }
    case "validate": {
      const raw = rest[0];
      if (!raw) {
        console.error("validate requires a <key> argument");
        return 2;
      }
      const res = manager.validate(raw, { consume: flag("consume") });
      if (json) {
        emit({
          ok: res.ok,
          reason: res.reason ?? null,
          provider: res.key?.provider ?? null,
          name: res.key?.name ?? null,
          remaining: res.remaining ?? null,
          keyId: res.key?.id ?? null,
        });
        return res.ok ? 0 : 1;
      }
      if (res.ok) {
        console.log(
          `OK — valid key (${res.key?.provider}/${res.key?.name || "unnamed"}), remaining: ${res.remaining ?? "unlimited"}`,
        );
        return 0;
      }
      console.log(`DENIED — ${res.reason ?? "invalid"}`);
      return 1;
    }
    case "list": {
      const provider = str("provider");
      const filtered = manager
        .listKeys()
        .filter((k) => !provider || k.provider === provider);
      if (json) {
        emit(filtered);
        return 0;
      }
      for (const k of filtered) {
        const quota = k.quota == null ? "∞" : String(k.quota);
        console.log(
          `${k.id.padEnd(36)} ${k.provider.padEnd(10)} quota:${quota.padStart(6)} used:${String(k.usage).padStart(6)} ${k.revoked ? "REVOKED " : "active   "}${k.name || ""}`,
        );
      }
      return 0;
    }
    case "revoke": {
      const id = rest[0];
      if (!id) {
        console.error("revoke requires an <id>");
        return 2;
      }
      const ok = manager.revoke(id);
      emit(ok ? `revoked ${id}` : `no active key with id '${id}'`);
      return ok ? 0 : 1;
    }
    case "rotate": {
      const id = rest[0];
      if (!id) {
        console.error("rotate requires an <id>");
        return 2;
      }
      const quotaStr = str("quota");
      const res = manager.rotate(id, {
        revokeOld: !flag("keep-old"),
        quota: quotaStr ? Number(quotaStr) : undefined,
      });
      const rotated = {
        replacementId: res.replacementId,
        replacement: res.replacement,
        oldRevoked: res.old.revoked,
        message: "Store the new key now — it is shown once and never recoverable.",
      };
      if (json) emit(rotated);
      else {
        console.log(`replacementId: ${rotated.replacementId}`);
        console.log(`oldRevoked:    ${rotated.oldRevoked}`);
        console.log(`key:           ${rotated.replacement}`);
        console.log(rotated.message);
      }
      return 0;
    }
    case "use": {
      const id = rest[0];
      if (!id) {
        console.error("use requires an <id>");
        return 2;
      }
      const amount = Number(str("amount") ?? 1);
      const { key, remaining } = manager.useById(id, amount);
      emit({ ok: true, keyId: key.id, used: amount, remaining: remaining ?? null });
      return 0;
    }
    case "status": {
      const keys = manager.listKeys();
      emit({
        store: typeof args.store === "string" ? args.store : "keys.jsonl",
        total: keys.length,
        active: keys.filter((k) => !k.revoked).length,
        secretConfigured: Boolean(
          typeof args.secret === "string"
            ? args.secret
            : process.env.API_KEY_MANAGER_SECRET,
        ),
      });
      return 0;
    }
    default: {
      console.error(`unknown command '${cmd}'\n\n${HELP}`);
      return 2;
    }
  }
}

// Support direct execution: bun cli.ts ...
if (import.meta.main) {
  process.exitCode = run(process.argv.slice(2));
}
