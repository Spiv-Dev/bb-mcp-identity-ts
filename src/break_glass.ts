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
 *   alerting    every accepted use is logged and passed to the server's
 *               `onBreakGlass` hook (at most once a minute; every use is
 *               counted in `health()`).
 *
 * The principal acts as the operator named in `BREAK_GLASS_OWNER` (an 18-char
 * Salesforce Id) at `BREAK_GLASS_TIER`, with `kind: 'break_glass'`.
 */
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

export const BREAK_GLASS_PREFIX = 'bbg_';
export const BREAK_GLASS_MAX_WINDOW_S = 24 * 3600;
const ALERT_INTERVAL_S = 60;

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

export type BreakGlassHook = (event: BreakGlassEvent) => void;

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
    if (nowS - this.lastAlert >= ALERT_INTERVAL_S) {
      this.lastAlert = nowS;
      const event: BreakGlassEvent = {
        event: 'identity.break_glass_used',
        app: this.app,
        owner_sub: cfg.ownerSub,
        tier: cfg.tier,
        until: iso(cfg.until),
        uses: this.uses,
        at: iso(nowS) ?? '',
      };
      this.log.error(`identity BREAK-GLASS bearer used: ${JSON.stringify(event)}`);
      if (this.hook) {
        try {
          this.hook(event);
        } catch (err) {
          // An alert hook must never break the request.
          this.log.error(`identity break-glass alert hook failed: ${(err as Error).message}`);
        }
      }
    }
    return 'ok';
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
