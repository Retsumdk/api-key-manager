/**
 * provider/base.ts — pluggable usage-tracking sinks.
 *
 * The manager stays synchronous at the point of use so request paths are
 * deterministic, but it fans usage and threshold-alert events out to optional
 * sinks. Plug a sink in front of an analytics store, a metrics backend, or an
 * external usage API to enable "usage tracking" without coupling the manager.
 *
 * - MemorySink   — in-process recorder (tests, auditing).
 * - ConsoleSink  — structured JSONL log of every usage event (audit trail).
 * - HttpSink     — forwards events to a REST endpoint (fire-and-forget).
 */

import type { ApiKeyRecord, UsageSink } from "../types.ts";

/** In-memory event recorder; ideal for tests and single-process auditing. */
export class MemorySink implements UsageSink {
  readonly uses: { keyId: string; amount: number; at: number }[] = [];
  readonly alerts: string[] = [];

  onUse(key: ApiKeyRecord, amount: number): void {
    this.uses.push({ keyId: key.id, amount, at: Date.now() });
  }
  onAlert(key: ApiKeyRecord): void {
    this.alerts.push(key.id);
  }
}

/** Structured JSONL logger — a durable audit trail on disk. */
export class ConsoleSink implements UsageSink {
  onUse(key: ApiKeyRecord, amount: number): void {
    console.log(
      JSON.stringify({
        event: "key.used",
        id: key.id,
        provider: key.provider,
        prefix: key.prefix,
        amount,
        usage: key.usage,
      }),
    );
  }
  onAlert(key: ApiKeyRecord): void {
    console.log(
      JSON.stringify({
        event: "key.quota_alert",
        id: key.id,
        provider: key.provider,
        usage: key.usage,
        quota: key.quota,
      }),
    );
  }
}

export interface HttpSinkOptions {
  /** Endpoint that receives usage events. */
  url: string;
  /** Optional bearer token sent to the endpoint. */
  token?: string;
}

/**
 * Fire-and-forget forwarder. Events are POSTed as JSON; failures are swall
 * and logged to stderr so a slow metrics endpoint never breaks request paths.
 */
export class HttpSink implements UsageSink {
  private url: string;
  private token?: string;

  constructor(opts: HttpSinkOptions) {
    this.url = opts.url;
    this.token = opts.token;
  }

  onUse(key: ApiKeyRecord, amount: number): void {
    this.post({ event: "key.used", id: key.id, amount, quota: key.quota, usage: key.usage });
  }
  onAlert(key: ApiKeyRecord): void {
    this.post({ event: "key.quota_alert", id: key.id, quota: key.quota, usage: key.usage });
  }

  private post(body: Record<string, unknown>): void {
    void fetch(this.url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(this.token ? { authorization: `Bearer ${this.token}` } : {}),
      },
      body: JSON.stringify(body),
    }).catch((err) => console.error(`[api-key-manager:HttpSink] ${String(err)}`));
  }
}
