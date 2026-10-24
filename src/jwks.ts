/**
 * The broker's public keys: pinned from config and/or fetched from the JWKS
 * URL, cached for a TTL, refetched at most once per unknown `kid`.
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
  if ('d' in j) return false; // never accept a private key as a verification key
  return typeof j.kid === 'string' && j.kid.length > 0;
}

export class KeySet {
  private readonly url: string;
  private readonly ttlMs: number;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly keys = new Map<string, KeyLike>();
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
      this.ready = this.absorb(options.pinned);
      this.fetchedAt = Date.now();
    } else {
      this.ready = Promise.resolve();
    }
  }

  private async absorb(jwks: PinnedJwks): Promise<void> {
    for (const k of jwks.keys) {
      if (!isCandidate(k)) continue;
      try {
        const key = await importJWK(k, ALG);
        if (key instanceof Uint8Array) continue;
        this.keys.set(k.kid, key);
      } catch {
        // an unparsable member is skipped, never fatal
      }
    }
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
      await this.absorb({ keys: (body as { keys: unknown[] }).keys });
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
    const key = this.keys.get(kid);
    const stale = Date.now() - this.fetchedAt > this.ttlMs;
    if (key && !stale) return key;
    // Unknown kid, or the cache aged out: one refetch, then whatever we have.
    await this.fetch();
    return this.keys.get(kid) ?? null;
  }

  health(): KeySetHealth {
    return {
      kids: [...this.keys.keys()].sort(),
      fetched_at: this.fetchedAt ? Math.floor(this.fetchedAt / 1000) : null,
      last_error: this.lastError,
    };
  }
}
