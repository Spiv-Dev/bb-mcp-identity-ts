/**
 * Break-glass: one sealed, time-boxed, alerting operator bearer per server
 * (the Python library `bb_mcp_identity.break_glass` behaves identically).
 *
 * It exists so a lockout (broker down, Salesforce down, an entitlement
 * mistake) is never fixed by switching the identity mode off. It does not
 * consult the broker or the snapshot.
 *
 *   sealed      the server holds only the SHA-256 of the bearer; the plaintext
 *               is minted once (`mintBreakGlass(app)`) and kept offline.
 *   time-boxed  it works only while `<PFX>_IDENTITY_BREAK_GLASS_UNTIL` is in the
 *               future, and that value may be at most 24 hours ahead when the
 *               server starts. Unset or past = disarmed.
 *   alerting    every accepted use is logged and counted in `health()`; the
 *               server's `onBreakGlass` hook (sync or async) gets an event at
 *               most once a minute.
 *
 * UNTIL has one strict format in both verifier libraries:
 * `YYYY-MM-DDTHH:MM[:SS[.fff]]` then `Z` or `+HH:MM` / `-HH:MM`.
 *
 * The principal acts as the operator named in `BREAK_GLASS_OWNER` (an 18-char
 * Salesforce Id) at `BREAK_GLASS_TIER`, with `kind: 'break_glass'`.
 */
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

export const BREAK_GLASS_PREFIX = 'bbg_';
export const BREAK_GLASS_MAX_WINDOW_S = 24 * 3600;
const ALERT_INTERVAL_S = 60;

/** The one UNTIL format both libraries accept (the Python verifier uses the same pattern). */
export const UNTIL_PATTERN = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,3}))?)?(Z|([+-])(\d{2}):(\d{2}))$/;
export const OWNER_PATTERN = /^[A-Za-z0-9]{18}$/;

/**
 * Unix seconds for an UNTIL value, or null when it does not match the format or
 * names an impossible instant (31 November, 24:00, a 25-hour offset). No
 * rollover: Date.parse would turn 2026-11-31 into 1 December.
 */
export function parseUntil(raw: string): number | null {
  const m = UNTIL_PATTERN.exec(raw);
  if (!m) return null;
  const [, y, mo, d, h, mi, s, frac, , sign, oh, om] = m;
  const year = Number(y);
  const month = Number(mo);
  const day = Number(d);
  const hour = Number(h);
  const minute = Number(mi);
  const second = Number(s ?? 0);
  const daysInMonth = new Date(Date.UTC(year, month, 0)).getUTCDate();
  if (month < 1 || month > 12 || day < 1 || day > daysInMonth || hour > 23 || minute > 59 || second > 59) return null;
  let offsetMin = 0;
  if (sign) {
    const offH = Number(oh);
    const offM = Number(om);
    if (offH > 23 || offM > 59) return null;
    offsetMin = (sign === '-' ? -1 : 1) * (offH * 60 + offM);
  }
  const ms = Date.UTC(year, month - 1, day, hour, minute, second, Number((frac ?? '0').padEnd(3, '0')));
  return ms / 1000 - offsetMin * 60;
}

export interface BreakGlassConfig {
  /** Lower-case SHA-256 hex of the bearer. */
  readonly sha256: string;
  /** Unix seconds; null = configured but disarmed. */
  readonly until: number | null;
  readonly tier: string | null;
  readonly ownerSub: string | null;
}

export interface BreakGlassEvent {
  event: 'identity.break_glass_used';
  app: string;
  owner_sub: string | null;
  tier: string | null;
  until: string | null;
  uses: number;
  at: string;
}

export type BreakGlassHook = (event: BreakGlassEvent) => void | Promise<void>;

export interface BreakGlassHealth {
  configured: boolean;
  armed: boolean;
  until: string | null;
  uses: number;
  last_used: string | null;
}

export function isArmed(config: BreakGlassConfig, nowS: number): boolean {
  return config.until !== null && nowS < config.until;
}

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

/** A new break-glass bearer and its SHA-256 hex. Keep the bearer offline. */
export function mintBreakGlass(app: string): { bearer: string; sha256: string } {
  const bearer = `${BREAK_GLASS_PREFIX}${app}_${randomBytes(32).toString('base64url')}`;
  return { bearer, sha256: sha256Hex(bearer) };
}

function iso(seconds: number | null): string | null {
  return seconds === null ? null : new Date(seconds * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

export interface BreakGlassLogger {
  info: (message: string) => void;
  warn: (message: string) => void;
  error: (message: string) => void;
}

export class BreakGlass {
  readonly config: BreakGlassConfig | null;
  readonly app: string;
  uses = 0;
  lastUsed: number | null = null;
  private lastAlert = Number.NEGATIVE_INFINITY;

  constructor(
    config: BreakGlassConfig | null,
    app: string,
    private readonly hook: BreakGlassHook | undefined,
    private readonly log: BreakGlassLogger,
  ) {
    this.config = config;
    this.app = app;
  }

  static isCandidate(bearer: string): boolean {
    return bearer.startsWith(BREAK_GLASS_PREFIX);
  }

  /** Log the armed state once at start, so an armed server is never quiet about it. */
  announce(nowS: number = Date.now() / 1000): void {
    const cfg = this.config;
    if (cfg === null) return;
    if (isArmed(cfg, nowS)) {
      this.log.error(
        `identity break-glass ARMED for app ${this.app} until ${iso(cfg.until)} (tier ${cfg.tier}, owner ${cfg.ownerSub})`,
      );
    } else {
      this.log.info(`identity break-glass configured for app ${this.app}, not armed`);
    }
  }

  /** `'ok'` or a stable deny reason. */
  check(bearer: string, nowS: number): 'ok' | 'break_glass_not_configured' | 'break_glass_mismatch' | 'break_glass_not_armed' {
    const cfg = this.config;
    if (cfg === null) {
      this.log.warn(`identity break-glass bearer presented but none is configured (app ${this.app})`);
      return 'break_glass_not_configured';
    }
    const presented = Buffer.from(sha256Hex(bearer), 'utf8');
    const expected = Buffer.from(cfg.sha256, 'utf8');
    if (presented.length !== expected.length || !timingSafeEqual(presented, expected)) {
      this.log.error(`identity break-glass bearer REJECTED: no match (app ${this.app})`);
      return 'break_glass_mismatch';
    }
    if (!isArmed(cfg, nowS)) {
      this.log.error(`identity break-glass bearer REJECTED: not armed (app ${this.app})`);
      return 'break_glass_not_armed';
    }
    this.uses += 1;
    this.lastUsed = nowS;
    const event: BreakGlassEvent = {
      event: 'identity.break_glass_used',
      app: this.app,
      owner_sub: cfg.ownerSub,
      tier: cfg.tier,
      until: iso(cfg.until),
      uses: this.uses,
      at: iso(nowS) ?? '',
    };
    // Every use is logged; only the alert hook is throttled.
    this.log.error(`identity BREAK-GLASS bearer used: ${JSON.stringify(event)}`);
    if (this.hook && nowS - this.lastAlert >= ALERT_INTERVAL_S) {
      this.lastAlert = nowS;
      this.fire(this.hook, event);
    }
    return 'ok';
  }

  /** An alert hook, sync or async, must never break the request or crash the process. */
  private fire(hook: BreakGlassHook, event: BreakGlassEvent): void {
    const failed = (err: unknown): void => {
      this.log.error(`identity break-glass alert hook failed: ${err instanceof Error ? err.message : String(err)}`);
    };
    try {
      const result = hook(event);
      if (result && typeof (result as Promise<void>).then === 'function') (result as Promise<void>).then(undefined, failed);
    } catch (err) {
      failed(err);
    }
  }

  health(nowS: number = Date.now() / 1000): BreakGlassHealth {
    const cfg = this.config;
    return {
      configured: cfg !== null,
      armed: cfg !== null && isArmed(cfg, nowS),
      until: cfg === null ? null : iso(cfg.until),
      uses: this.uses,
      last_used: iso(this.lastUsed),
    };
  }
}
