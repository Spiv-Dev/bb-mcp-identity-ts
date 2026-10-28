/**
 * Settings for a verifier, read from `<PREFIX>_IDENTITY_*` environment
 * variables so every MCP server configures it the same way (the Python
 * library `bb_mcp_identity` reads the identical names).
 *
 *   SF_IDENTITY_MODE=enabled            off | enabled | required
 *   SF_IDENTITY_ISSUER=https://id.bakerbaynes.com/r/salesforce
 *   SF_IDENTITY_RESOURCE=https://salesforce-mcp.bakerbaynes.com/mcp
 *   SF_IDENTITY_VERIFIER_TOKEN=bbv_salesforce_...      (snapshot reads; required unless off)
 *   SF_IDENTITY_SNAPSHOT_URL=http://127.0.0.1:8775/r/salesforce/snapshot   (optional)
 *   SF_IDENTITY_JWKS_URL=http://127.0.0.1:8775/.well-known/jwks.json       (optional)
 *   SF_IDENTITY_SNAPSHOT_CACHE=/var/lib/bb-salesforce-mcp/identity-snapshot.json
 *   SF_IDENTITY_PINNED_JWKS={"keys":[...]}              (optional, offline verification)
 *   SF_IDENTITY_SERVICE_PRINCIPALS=/etc/.../service-principals   (optional)
 *   SF_IDENTITY_BREAK_GLASS_SHA256=<64 hex>             (optional; the sealed operator bearer)
 *   SF_IDENTITY_BREAK_GLASS_UNTIL=2026-10-28T18:00:00+02:00   (arms it; at most 24 h ahead)
 *   SF_IDENTITY_BREAK_GLASS_TIER=Admin                  (required while armed)
 *   SF_IDENTITY_BREAK_GLASS_OWNER=<18-char Salesforce Id>   (required while armed)
 *
 * An empty value counts as unset. The broker URLs must be https, except
 * loopback (the broker on the same VM) which may be plain http.
 */

import { BREAK_GLASS_MAX_WINDOW_S, type BreakGlassConfig } from './break_glass.js';

export type Mode = 'off' | 'enabled' | 'required';

export class ConfigError extends Error {
  override readonly name = 'ConfigError';
}

export interface PinnedJwks {
  keys: unknown[];
}

export interface IdentityConfig {
  readonly mode: Mode;
  /** `https://id.bakerbaynes.com/r/<app>`, no trailing slash. */
  readonly issuer: string;
  /** This server's MCP URL: the token audience. */
  readonly resource: string;
  /** The app key, taken from the issuer. */
  readonly app: string;
  readonly jwksUrl: string;
  readonly snapshotUrl: string;
  readonly verifierToken: string | null;
  readonly snapshotCachePath: string | null;
  readonly servicePrincipalsPath: string | null;
  readonly pinnedJwks: PinnedJwks | null;
  /** The sealed operator bearer; null = no break-glass on this server. */
  readonly breakGlass: BreakGlassConfig | null;
  readonly pollIntervalS: number;
  readonly jwksTtlS: number;
  readonly leewayS: number;
  readonly httpTimeoutMs: number;
  readonly realm: string;
}

export function isEnabled(config: IdentityConfig): boolean {
  return config.mode !== 'off';
}

export function isRequired(config: IdentityConfig): boolean {
  return config.mode === 'required';
}

/** Split `https://host/r/<app>` into its base URL and app key. */
export function issuerParts(issuer: string): { base: string; app: string } {
  const marker = '/r/';
  const idx = issuer.lastIndexOf(marker);
  if (idx < 0) throw new ConfigError(`issuer must look like https://host/r/<app>: ${JSON.stringify(issuer)}`);
  const base = issuer.slice(0, idx);
  const app = issuer.slice(idx + marker.length).replace(/^\/+|\/+$/g, '');
  if (!app || app.includes('/')) throw new ConfigError(`issuer must end with /r/<app>: ${JSON.stringify(issuer)}`);
  return { base, app };
}

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]']);

/** The broker is reached over https, or over plain http on loopback only. */
export function assertBrokerUrl(name: string, url: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new ConfigError(`${name} is not a valid URL: ${JSON.stringify(url)}`);
  }
  if (parsed.protocol === 'https:') return;
  if (parsed.protocol === 'http:' && LOOPBACK_HOSTS.has(parsed.hostname)) return;
  throw new ConfigError(`${name} must use https (plain http is allowed for loopback only): ${JSON.stringify(url)}`);
}

export interface FromEnvOptions {
  realm?: string;
  env?: Record<string, string | undefined>;
  /** Unix seconds, for tests; defaults to the clock. Bounds the break-glass window. */
  nowS?: number;
}

type Env = Record<string, string | undefined>;

/** A trimmed value; empty counts as unset. */
function readStr(env: Env, name: string): string {
  return (env[name] ?? '').trim();
}

function readInt(env: Env, name: string, fallback: number, min: number): number {
  const raw = readStr(env, name);
  if (!raw) return fallback;
  if (!/^\d+$/.test(raw)) throw new ConfigError(`${name} must be an integer (got ${JSON.stringify(raw)})`);
  const n = Number.parseInt(raw, 10);
  if (n < min) throw new ConfigError(`${name} must be at least ${min} (got ${raw})`);
  return n;
}

function readFloat(env: Env, name: string, fallback: number): number {
  const raw = readStr(env, name);
  if (!raw) return fallback;
  if (!/^\d+(\.\d+)?$/.test(raw) || Number.parseFloat(raw) <= 0) {
    throw new ConfigError(`${name} must be a positive number (got ${JSON.stringify(raw)})`);
  }
  return Number.parseFloat(raw);
}

export function configFromEnv(prefix: string, options: FromEnvOptions = {}): IdentityConfig {
  const env = options.env ?? process.env;
  const p = `${prefix}_IDENTITY_`;
  const mode = (readStr(env, p + 'MODE') || 'off').toLowerCase();
  if (mode !== 'off' && mode !== 'enabled' && mode !== 'required') {
    throw new ConfigError(`${p}MODE must be off, enabled or required (got ${JSON.stringify(mode)})`);
  }
  const issuer = readStr(env, p + 'ISSUER').replace(/\/+$/, '');
  let resource = readStr(env, p + 'RESOURCE');
  const verifierToken = readStr(env, p + 'VERIFIER_TOKEN') || null;
  if (mode !== 'off') {
    if (!issuer) throw new ConfigError(`${p}ISSUER is required when ${p}MODE=${mode}`);
    if (!resource) throw new ConfigError(`${p}RESOURCE is required when ${p}MODE=${mode}`);
    if (!verifierToken) throw new ConfigError(`${p}VERIFIER_TOKEN is required when ${p}MODE=${mode}`);
  }
  // Drop one trailing slash from a resource that has a path (never from a bare origin).
  if (resource.endsWith('/') && resource.split('/').length - 1 > 3) resource = resource.replace(/\/+$/, '');
  const parts = issuer ? issuerParts(issuer) : { base: '', app: '' };

  const pinnedRaw = readStr(env, p + 'PINNED_JWKS');
  let pinned: PinnedJwks | null = null;
  if (pinnedRaw) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(pinnedRaw);
    } catch (err) {
      throw new ConfigError(`${p}PINNED_JWKS is not JSON: ${(err as Error).message}`);
    }
    if (typeof parsed !== 'object' || parsed === null || !Array.isArray((parsed as { keys?: unknown }).keys)) {
      throw new ConfigError(`${p}PINNED_JWKS must be a JWKS object with a keys array`);
    }
    pinned = { keys: (parsed as { keys: unknown[] }).keys };
  }

  const jwksUrl = readStr(env, p + 'JWKS_URL') || (parts.base ? `${parts.base}/.well-known/jwks.json` : '');
  const snapshotUrl = readStr(env, p + 'SNAPSHOT_URL') || (issuer ? `${issuer}/snapshot` : '');
  if (mode !== 'off') {
    assertBrokerUrl(`${p}ISSUER`, issuer);
    assertBrokerUrl(`${p}JWKS_URL`, jwksUrl);
    assertBrokerUrl(`${p}SNAPSHOT_URL`, snapshotUrl);
  }

  return {
    mode,
    issuer,
    resource,
    app: parts.app,
    jwksUrl,
    snapshotUrl,
    verifierToken,
    snapshotCachePath: readStr(env, p + 'SNAPSHOT_CACHE') || null,
    servicePrincipalsPath: readStr(env, p + 'SERVICE_PRINCIPALS') || null,
    pinnedJwks: pinned,
    breakGlass: breakGlassFromEnv(env, p, options.nowS ?? Date.now() / 1000),
    pollIntervalS: readInt(env, p + 'POLL_INTERVAL_S', 60, 1),
    jwksTtlS: readInt(env, p + 'JWKS_TTL_S', 300, 1),
    leewayS: readInt(env, p + 'LEEWAY_S', 30, 0),
    httpTimeoutMs: Math.round(readFloat(env, p + 'HTTP_TIMEOUT_S', 5) * 1000),
    realm: options.realm ?? `${prefix.toLowerCase()}-mcp`,
  };
}

const HEX64 = /^[0-9a-f]{64}$/;
const ISO_WITH_OFFSET = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})$/i;

/**
 * Parse the break-glass settings. Unset = no break-glass. A malformed or
 * over-long window is a ConfigError, never a silently wider one.
 */
function breakGlassFromEnv(env: Env, p: string, nowS: number): BreakGlassConfig | null {
  const sha = readStr(env, p + 'BREAK_GLASS_SHA256').toLowerCase();
  const untilRaw = readStr(env, p + 'BREAK_GLASS_UNTIL');
  const tier = readStr(env, p + 'BREAK_GLASS_TIER') || null;
  const ownerSub = readStr(env, p + 'BREAK_GLASS_OWNER') || null;
  if (!sha) {
    if (untilRaw) throw new ConfigError(`${p}BREAK_GLASS_UNTIL is set but ${p}BREAK_GLASS_SHA256 is not`);
    return null;
  }
  if (!HEX64.test(sha)) throw new ConfigError(`${p}BREAK_GLASS_SHA256 must be 64 hex characters (the SHA-256 of the bearer)`);
  if (!untilRaw) return { sha256: sha, until: null, tier, ownerSub };
  if (!ISO_WITH_OFFSET.test(untilRaw)) {
    throw new ConfigError(
      `${p}BREAK_GLASS_UNTIL must be an ISO-8601 datetime with a timezone offset, e.g. +02:00: ${JSON.stringify(untilRaw)}`,
    );
  }
  const ms = Date.parse(untilRaw);
  if (Number.isNaN(ms)) throw new ConfigError(`${p}BREAK_GLASS_UNTIL is not a valid datetime: ${JSON.stringify(untilRaw)}`);
  const until = ms / 1000;
  if (until > nowS + BREAK_GLASS_MAX_WINDOW_S) {
    throw new ConfigError(`${p}BREAK_GLASS_UNTIL may be at most 24 hours ahead (got ${JSON.stringify(untilRaw)})`);
  }
  if (!tier) throw new ConfigError(`${p}BREAK_GLASS_TIER is required while ${p}BREAK_GLASS_UNTIL is set`);
  if (!ownerSub || ownerSub.length !== 18) {
    throw new ConfigError(`${p}BREAK_GLASS_OWNER must be the operator's 18-char Salesforce Id while ${p}BREAK_GLASS_UNTIL is set`);
  }
  return { sha256: sha, until, tier, ownerSub };
}
