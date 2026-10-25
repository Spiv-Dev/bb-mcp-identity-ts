/**
 * The broker's public keys: pinned from config and/or fetched from the JWKS
 * URL, cached for a TTL, refetched once per lookup of an unknown `kid`
 * (concurrent lookups share one request). Pinned keys are permanent; the
 * fetched set is replaced on every successful fetch, so a key the broker
 * stops publishing stops verifying.
 */
import { importJWK, type JWK, type KeyLike } from 'jose';

import type { PinnedJwks } from './config.js';

export const ALG = 'ES256';

export interface KeySetOptions {
  jwksUrl: string;
  pinned: PinnedJwks | null;
  ttlS: number;
  timeoutMs: number;
  fetchImpl?: typeof fetch;
}

export interface KeySetHealth {
  kids: string[];
  fetched_at: number | null;
  last_error: string | null;
}

function isCandidate(k: unknown): k is JWK & { kid: string } {
  if (typeof k !== 'object' || k === null) return false;
  const j = k as JWK;
  if (j.kty !== 'EC' || j.crv !== 'P-256') return false;
  if (j.alg !== undefined && j.alg !== ALG) return false;
  if (j.use !== undefined && j.use !== 'sig') return false;
  if (j.key_ops !== undefined && !(Array.isArray(j.key_ops) && j.key_ops.includes('verify'))) return false;
  if ('d' in j) return false; // never accept a private key as a verification key
  return typeof j.kid === 'string' && j.kid.length > 0;
}

async function importAll(jwks: PinnedJwks): Promise<Map<string, KeyLike>> {
  const out = new Map<string, KeyLike>();
  for (const k of jwks.keys) {
    if (!isCandidate(k)) continue;
    try {
      const key = await importJWK(k, ALG);
      if (key instanceof Uint8Array) continue;
      out.set(k.kid, key);
    } catch {
      // an unparsable member is skipped, never fatal
    }
  }
  return out;
}

export class KeySet {
  private readonly url: string;
  private readonly ttlMs: number;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private pinnedKeys = new Map<string, KeyLike>();
  private fetchedKeys = new Map<string, KeyLike>();
  private fetchedAt = 0;
  private lastError: string | null = null;
  private readonly ready: Promise<void>;
  private inflight: Promise<boolean> | null = null;

  constructor(options: KeySetOptions) {
    this.url = options.jwksUrl;
    this.ttlMs = options.ttlS * 1000;
    this.timeoutMs = options.timeoutMs;
    this.fetchImpl = options.fetchImpl ?? fetch;
    if (options.pinned) {
      this.ready = importAll(options.pinned).then((keys) => {
        this.pinnedKeys = keys;
      });
      this.fetchedAt = Date.now();
    } else {
      this.ready = Promise.resolve();
    }
  }

  private lookup(kid: string): KeyLike | undefined {
    return this.pinnedKeys.get(kid) ?? this.fetchedKeys.get(kid);
  }

  /** Refresh from the JWKS URL. Resolves true on success; never rejects. */
  fetch(): Promise<boolean> {
    if (!this.url) return Promise.resolve(false);
    if (this.inflight) return this.inflight;
    this.inflight = this.doFetch().finally(() => {
      this.inflight = null;
    });
    return this.inflight;
  }

  private async doFetch(): Promise<boolean> {
    try {
      const res = await this.fetchImpl(this.url, {
        headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = (await res.json()) as unknown;
      if (typeof body !== 'object' || body === null || !Array.isArray((body as { keys?: unknown }).keys)) {
        throw new Error('JWKS body has no keys array');
      }
      this.fetchedKeys = await importAll({ keys: (body as { keys: unknown[] }).keys });
      this.fetchedAt = Date.now();
      this.lastError = null;
      return true;
    } catch (err) {
      this.lastError = String((err as Error).message ?? err).slice(0, 200);
      return false;
    }
  }

  async keyFor(kid: string): Promise<KeyLike | null> {
    await this.ready;
    const key = this.lookup(kid);
    const stale = Date.now() - this.fetchedAt > this.ttlMs;
    if (key && !stale) return key;
    // Unknown kid, or the cache aged out: one refetch, then whatever we have.
    await this.fetch();
    return this.lookup(kid) ?? null;
  }

  health(): KeySetHealth {
    return {
      kids: [...new Set([...this.pinnedKeys.keys(), ...this.fetchedKeys.keys()])].sort(),
      fetched_at: this.fetchedAt ? Math.floor(this.fetchedAt / 1000) : null,
      last_error: this.lastError,
    };
  }
}
