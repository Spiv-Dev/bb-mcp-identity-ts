/**
 * Verify a bearer against the broker: signature (ES256, pinned or fetched
 * keys), issuer, audience, expiry, then the snapshot (active, entitled,
 * not_before, fresh). Every failure is a `Deny` with a stable reason.
 */
import { decodeProtectedHeader, errors as joseErrors, jwtVerify, type JWTPayload } from 'jose';

import { BreakGlass, type BreakGlassHealth, type BreakGlassHook } from './break_glass.js';
import { isEnabled, type IdentityConfig } from './config.js';
import { ALG, KeySet } from './jwks.js';
import { ServicePrincipals, type ServicePrincipal } from './service_principals.js';
import { scopesOf, SnapshotStore } from './snapshot.js';

export type PrincipalKind = 'user' | 'service' | 'break_glass';

/** A verified caller. `sub` is the 18-char Salesforce User Id. */
export interface Principal {
  readonly sub: string;
  readonly username: string;
  readonly app: string;
  readonly tier: string;
  readonly scopes: readonly string[];
  readonly clientId: string;
  readonly authTime: number;
  readonly jti: string;
  readonly exp: number;
  readonly kind: PrincipalKind;
}

export function scopeString(principal: Principal): string {
  return principal.scopes.join(' ');
}

/**
 * The bearer must be refused. `reason` is stable and safe to log; `ours` says
 * whether the token was issued by our broker at all (an enabled-mode server
 * lets a non-broker token fall through to its legacy validator).
 */
export class Deny extends Error {
  override readonly name = 'Deny';
  readonly reason: string;
  readonly ours: boolean;

  constructor(reason: string, options: { ours?: boolean } = {}) {
    super(reason);
    this.reason = reason;
    this.ours = options.ours ?? true;
  }
}

export interface VerifierOptions {
  fetchImpl?: typeof fetch;
  warn?: (message: string) => void;
  /** Called whenever the break-glass bearer is accepted (at most once a minute): wire it to alerting. */
  onBreakGlass?: BreakGlassHook;
}

export interface VerifierHealth {
  mode: IdentityConfig['mode'];
  issuer: string;
  resource: string;
  keys: ReturnType<KeySet['health']>;
  snapshot: ReturnType<SnapshotStore['health']>;
  service_principals: number;
  break_glass: BreakGlassHealth;
}

const REQUIRED_CLAIMS = ['exp', 'iat', 'sub', 'iss', 'aud'];

function denyFor(err: unknown): Deny {
  if (err instanceof joseErrors.JWTExpired) return new Deny('expired');
  if (err instanceof joseErrors.JWTClaimValidationFailed) {
    if (err.claim === 'aud') return new Deny('wrong_audience');
    if (err.claim === 'iss') return new Deny('wrong_issuer');
    return new Deny(`invalid_token:${err.code}`);
  }
  if (err instanceof joseErrors.JOSEError) return new Deny(`invalid_token:${err.code}`);
  return new Deny(`invalid_token:${(err as Error).name ?? 'Error'}`);
}

export class Verifier {
  readonly config: IdentityConfig;
  readonly keys: KeySet;
  readonly snapshot: SnapshotStore;
  readonly servicePrincipals: ServicePrincipals;
  readonly breakGlass: BreakGlass;

  constructor(config: IdentityConfig, options: VerifierOptions = {}) {
    this.config = config;
    this.keys = new KeySet({
      jwksUrl: config.jwksUrl,
      pinned: config.pinnedJwks,
      ttlS: config.jwksTtlS,
      timeoutMs: config.httpTimeoutMs,
      fetchImpl: options.fetchImpl,
    });
    this.snapshot = new SnapshotStore({
      url: config.snapshotUrl,
      verifierToken: config.verifierToken,
      app: config.app,
      cachePath: config.snapshotCachePath,
      pollIntervalS: config.pollIntervalS,
      timeoutMs: config.httpTimeoutMs,
      fetchImpl: options.fetchImpl,
      warn: options.warn,
    });
    this.servicePrincipals = ServicePrincipals.fromFile(config.servicePrincipalsPath);
    // Break-glass is never silent: without a `warn` sink it logs to the console.
    const out = options.warn;
    this.breakGlass = new BreakGlass(config.breakGlass, config.app, options.onBreakGlass, {
      info: out ?? ((m) => console.info(m)),
      warn: out ?? ((m) => console.warn(m)),
      error: out ?? ((m) => console.error(m)),
    });
    if (config.servicePrincipalsPath && this.servicePrincipals.size === 0) {
      (options.warn ?? (() => undefined))('identity: service principals file is missing or empty');
    }
  }

  private lastMissRefreshS = 0;
  private missFetch: Promise<boolean> | null = null;

  /**
   * Fetch the snapshot now, at most once per `missRefreshS` (0 = never);
   * concurrent misses share one fetch. Only reached after the signature checked
   * out, so a forged token cannot drive fetches. Returns whether a fetch ran.
   */
  private async refreshOnMiss(now: number): Promise<boolean> {
    const interval = this.config.missRefreshS;
    if (interval <= 0) return false;
    if (this.missFetch !== null) {
      await this.missFetch;
      return true;
    }
    if (now - this.lastMissRefreshS < interval) return false;
    this.lastMissRefreshS = now;
    this.missFetch = this.snapshot.fetch().finally(() => {
      this.missFetch = null;
    });
    await this.missFetch;
    return true;
  }

  /** Fetch keys and the snapshot once, then keep polling in the background. */
  async start(): Promise<void> {
    if (!isEnabled(this.config)) return;
    this.breakGlass.announce();
    await this.keys.fetch();
    await this.snapshot.start();
  }

  stop(): void {
    this.snapshot.stop();
  }

  // ── tokens ──────────────────────────────────────────────────────────

  /** `nowS` is unix seconds (defaults to the clock). Rejects with `Deny`. */
  async verify(bearer: string, nowS?: number): Promise<Principal> {
    if (!isEnabled(this.config)) throw new Deny('identity_off', { ours: false });
    const now = nowS ?? Date.now() / 1000;

    // Break-glass first: it must work with the broker and the snapshot down. A `bbg_`
    // bearer is always ours, so a refusal never falls through to a legacy validator.
    if (BreakGlass.isCandidate(bearer)) {
      const outcome = this.breakGlass.check(bearer, now);
      if (outcome !== 'ok') throw new Deny(outcome);
      return this.breakGlassPrincipal();
    }

    const svc = bearer.startsWith('bbs_') || this.servicePrincipals.size > 0 ? this.servicePrincipals.match(bearer) : null;
    if (svc !== null) return this.service(svc);

    let header: ReturnType<typeof decodeProtectedHeader>;
    try {
      header = decodeProtectedHeader(bearer);
    } catch {
      throw new Deny('not_a_jwt', { ours: false });
    }
    // Not ours (or an algorithm-confusion attempt). Never verify anything but ES256.
    if (header.alg !== ALG) throw new Deny('wrong_alg', { ours: false });
    const kid = header.kid;
    if (typeof kid !== 'string' || !kid) throw new Deny('no_kid', { ours: false });
    const key = await this.keys.keyFor(kid);
    if (key === null) throw new Deny('unknown_kid');

    let claims: JWTPayload;
    try {
      ({ payload: claims } = await jwtVerify(bearer, key, {
        algorithms: [ALG],
        issuer: this.config.issuer,
        audience: this.config.resource,
        clockTolerance: this.config.leewayS,
        currentDate: new Date(now * 1000),
        requiredClaims: REQUIRED_CLAIMS,
      }));
    } catch (err) {
      throw denyFor(err);
    }

    const sub = typeof claims.sub === 'string' ? claims.sub : '';
    const authTime = Math.trunc(Number(claims['auth_time']) || 0);
    if (sub.length !== 18 || !authTime) throw new Deny('malformed_claims');
    const app = claims['app'];
    if (app !== undefined && app !== null && app !== this.config.app) throw new Deny('wrong_app');

    // The snapshot decides. It is newer than the token.
    if (!this.snapshot.isFresh(now)) throw new Deny(this.snapshot.version !== null ? 'snapshot_stale' : 'no_snapshot');
    let entry = this.snapshot.entry(sub);
    // A validly signed token is never older than the snapshot that should know
    // its subject: a first sign-in (or a new entitlement) can beat the next
    // poll by up to a minute. Refetch once, rate-limited, and re-check.
    if ((entry === null || !entry.tier) && (await this.refreshOnMiss(now))) entry = this.snapshot.entry(sub);
    if (entry === null) throw new Deny('unknown_subject');
    if (!entry.active) throw new Deny(`subject_${entry.status}`);
    // A revocation at second N ends every session signed in at or before N (the broker applies the same rule).
    if (authTime <= entry.not_before) throw new Deny('not_before');
    if (!entry.tier) throw new Deny('not_entitled');

    return {
      sub,
      username: typeof claims['preferred_username'] === 'string' ? claims['preferred_username'] : '',
      app: this.config.app,
      tier: entry.tier,
      scopes: scopesOf(entry),
      clientId: typeof claims['client_id'] === 'string' ? claims['client_id'] : '',
      authTime,
      jti: typeof claims.jti === 'string' ? claims.jti : '',
      exp: Math.trunc(Number(claims.exp) || 0),
      kind: 'user',
    };
  }

  private service(svc: ServicePrincipal): Principal {
    const { ok, reason } = ServicePrincipals.usable(svc, this.snapshot);
    if (!ok) throw new Deny(`service_${reason}`);
    return {
      sub: svc.ownerSub,
      username: svc.name,
      app: this.config.app,
      tier: svc.tier,
      scopes: [],
      clientId: svc.name,
      authTime: 0,
      jti: '',
      exp: 0,
      kind: 'service',
    };
  }

  private breakGlassPrincipal(): Principal {
    const bg = this.config.breakGlass;
    // check() returned 'ok', so break-glass is configured and armed, with a tier and an owner.
    if (bg === null || bg.tier === null || bg.ownerSub === null) throw new Deny('break_glass_not_configured');
    return {
      sub: bg.ownerSub,
      username: 'break-glass',
      app: this.config.app,
      tier: bg.tier,
      scopes: [],
      clientId: 'break-glass',
      authTime: 0,
      jti: '',
      exp: Math.trunc(bg.until ?? 0),
      kind: 'break_glass',
    };
  }

  // ── health ──────────────────────────────────────────────────────────

  health(): VerifierHealth {
    return {
      mode: this.config.mode,
      issuer: this.config.issuer,
      resource: this.config.resource,
      keys: this.keys.health(),
      snapshot: this.snapshot.health(),
      service_principals: this.servicePrincipals.size,
      break_glass: this.breakGlass.health(),
    };
  }
}
