/**
 * The broker's entitlement snapshot for this app: polled, cached on disk,
 * and consulted on every request. See docs/VERIFIER_PROTOCOL.md section 4
 * in the bb-identity repo for the contract.
 */
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

export interface SubjectEntry {
  status: string;
  active: boolean;
  not_before: number;
  tier: string | null;
  scope: string | null;
}

export function scopesOf(entry: SubjectEntry): string[] {
  return (entry.scope ?? '').split(/\s+/).filter(Boolean);
}

export interface SnapshotDocument {
  version: number;
  generated_at: number;
  source?: string;
  stale_after_s?: number;
  app: string;
  resource?: string;
  subjects: Record<string, unknown>;
}

export interface SnapshotStoreOptions {
  url: string;
  verifierToken: string | null;
  app: string;
  cachePath: string | null;
  pollIntervalS: number;
  timeoutMs: number;
  fetchImpl?: typeof fetch;
  /** Called with a short, secret-free message on a failed poll or cache write. */
  warn?: (message: string) => void;
}

export interface SnapshotHealth {
  version: number | null;
  generated_at: number | null;
  age_s: number | null;
  fresh: boolean;
  stale_after_s: number;
  last_error: string | null;
  subjects: number | null;
}

const DEFAULT_STALE_AFTER_S = 1200;

function isDocumentFor(app: string, body: unknown): body is SnapshotDocument {
  if (typeof body !== 'object' || body === null) return false;
  const b = body as Partial<SnapshotDocument>;
  return b.app === app && typeof b.subjects === 'object' && b.subjects !== null && !Array.isArray(b.subjects);
}

export class SnapshotStore {
  private readonly url: string;
  private readonly token: string | null;
  private readonly app: string;
  private readonly cachePath: string | null;
  private readonly intervalMs: number;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly warn: (message: string) => void;
  private snapshot: SnapshotDocument | null = null;
  private etag: string | null = null;
  private lastError: string | null = null;
  private timer: NodeJS.Timeout | null = null;
  private inflight: Promise<boolean> | null = null;

  constructor(options: SnapshotStoreOptions) {
    this.url = options.url;
    this.token = options.verifierToken;
    this.app = options.app;
    this.cachePath = options.cachePath;
    this.intervalMs = options.pollIntervalS * 1000;
    this.timeoutMs = options.timeoutMs;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.warn = options.warn ?? (() => undefined);
    if (this.cachePath && existsSync(this.cachePath)) {
      try {
        this.accept(JSON.parse(readFileSync(this.cachePath, 'utf8')) as unknown, null, false);
      } catch (err) {
        this.warn(`identity snapshot cache unreadable: ${(err as Error).message}`);
      }
    }
  }

  // ── state ───────────────────────────────────────────────────────────

  private accept(body: unknown, etag: string | null, persist: boolean): void {
    if (!isDocumentFor(this.app, body)) throw new Error('snapshot is not for this app');
    this.snapshot = body;
    this.etag = etag ?? `"${body.version}"`;
    this.lastError = null;
    if (persist && this.cachePath) {
      const tmp = `${this.cachePath}.tmp`;
      try {
        mkdirSync(dirname(this.cachePath), { recursive: true });
        writeFileSync(tmp, JSON.stringify(body), { mode: 0o600 });
        renameSync(tmp, this.cachePath);
        try {
          chmodSync(this.cachePath, 0o600);
        } catch {
          // best effort (Windows)
        }
      } catch (err) {
        this.warn(`could not persist identity snapshot: ${(err as Error).message}`);
      }
    }
  }

  get version(): number | null {
    return this.snapshot === null ? null : Math.trunc(Number(this.snapshot.version) || 0);
  }

  generatedAtMs(): number | null {
    return this.snapshot === null ? null : Math.trunc(Number(this.snapshot.generated_at) || 0);
  }

  staleAfterS(): number {
    const v = this.snapshot?.stale_after_s;
    return typeof v === 'number' && Number.isFinite(v) ? Math.trunc(v) : DEFAULT_STALE_AFTER_S;
  }

  /** `nowS` is unix seconds (defaults to the clock). */
  isFresh(nowS?: number): boolean {
    const gen = this.generatedAtMs();
    if (gen === null) return false;
    const nowMs = (nowS ?? Date.now() / 1000) * 1000;
    return nowMs - gen <= this.staleAfterS() * 1000;
  }

  entry(sub: string): SubjectEntry | null {
    if (this.snapshot === null) return null;
    const raw = Object.prototype.hasOwnProperty.call(this.snapshot.subjects, sub) ? this.snapshot.subjects[sub] : undefined;
    if (typeof raw !== 'object' || raw === null) return null;
    const r = raw as Partial<SubjectEntry>;
    return {
      status: typeof r.status === 'string' ? r.status : 'unknown',
      active: r.active === true,
      not_before: Math.trunc(Number(r.not_before) || 0),
      tier: typeof r.tier === 'string' && r.tier ? r.tier : null,
      scope: typeof r.scope === 'string' ? r.scope : null,
    };
  }

  // ── fetching ────────────────────────────────────────────────────────

  /** One poll. Resolves true when a usable snapshot is loaded afterwards; never rejects. */
  fetch(): Promise<boolean> {
    if (this.inflight) return this.inflight;
    this.inflight = this.doFetch().finally(() => {
      this.inflight = null;
    });
    return this.inflight;
  }

  private async doFetch(): Promise<boolean> {
    if (!this.url || !this.token) {
      this.lastError = 'snapshot url or verifier token not configured';
      return this.snapshot !== null;
    }
    const headers: Record<string, string> = { Authorization: `Bearer ${this.token}`, Accept: 'application/json' };
    if (this.snapshot !== null && this.etag) headers['If-None-Match'] = this.etag;
    try {
      const res = await this.fetchImpl(this.url, { headers, signal: AbortSignal.timeout(this.timeoutMs) });
      if (res.status === 304) {
        this.lastError = null;
        return true;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      this.accept((await res.json()) as unknown, res.headers.get('etag'), true);
      return true;
    } catch (err) {
      this.lastError = String((err as Error).message ?? err).slice(0, 200);
      this.warn(`identity snapshot poll failed: ${this.lastError}`);
      return this.snapshot !== null;
    }
  }

  /** Poll once now (awaitable), then keep polling in the background. */
  async start(): Promise<boolean> {
    if (this.timer) return this.snapshot !== null;
    const first = await this.fetch();
    this.timer = setInterval(() => {
      void this.fetch();
    }, this.intervalMs);
    this.timer.unref();
    return first;
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  health(): SnapshotHealth {
    const gen = this.generatedAtMs();
    return {
      version: this.version,
      generated_at: gen === null ? null : Math.floor(gen / 1000),
      age_s: gen === null ? null : Math.max(0, Math.floor((Date.now() - gen) / 1000)),
      fresh: this.isFresh(),
      stale_after_s: this.staleAfterS(),
      last_error: this.lastError,
      subjects: this.snapshot === null ? null : Object.keys(this.snapshot.subjects).length,
    };
  }
}
