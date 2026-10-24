/**
 * Settings for a verifier, read from `<PREFIX>_IDENTITY_*` environment
 * variables so every MCP server configures it the same way (the Python
 * library `bb_mcp_identity` reads the identical names).
 *
 *   SF_IDENTITY_MODE=enabled            off | enabled | required
 *   SF_IDENTITY_ISSUER=https://id.bakerbaynes.com/r/salesforce
 *   SF_IDENTITY_RESOURCE=https://salesforce-mcp.bakerbaynes.com/mcp
 *   SF_IDENTITY_VERIFIER_TOKEN=bbv_salesforce_...      (snapshot reads)
 *   SF_IDENTITY_SNAPSHOT_URL=http://127.0.0.1:8775/r/salesforce/snapshot   (optional)
 *   SF_IDENTITY_JWKS_URL=http://127.0.0.1:8775/.well-known/jwks.json       (optional)
 *   SF_IDENTITY_SNAPSHOT_CACHE=/var/lib/bb-salesforce-mcp/identity-snapshot.json
 *   SF_IDENTITY_PINNED_JWKS={"keys":[...]}              (optional, offline verification)
 *   SF_IDENTITY_SERVICE_PRINCIPALS=/etc/.../service-principals   (optional)
 */

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

export interface FromEnvOptions {
  realm?: string;
  env?: Record<string, string | undefined>;
}

function readInt(env: Record<string, string | undefined>, name: string, fallback: number): number {
  const raw = (env[name] ?? '').trim();
  if (!raw) return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n <= 0) throw new ConfigError(`${name} must be a positive integer (got ${JSON.stringify(raw)})`);
  return n;
}

function readFloat(env: Record<string, string | undefined>, name: string, fallback: number): number {
  const raw = (env[name] ?? '').trim();
  if (!raw) return fallback;
  const n = Number.parseFloat(raw);
  if (!Number.isFinite(n) || n <= 0) throw new ConfigError(`${name} must be a positive number (got ${JSON.stringify(raw)})`);
  return n;
}

export function configFromEnv(prefix: string, options: FromEnvOptions = {}): IdentityConfig {
  const env = options.env ?? process.env;
  const p = `${prefix}_IDENTITY_`;
  const mode = (env[p + 'MODE'] ?? 'off').trim().toLowerCase();
  if (mode !== 'off' && mode !== 'enabled' && mode !== 'required') {
    throw new ConfigError(`${p}MODE must be off, enabled or required (got ${JSON.stringify(mode)})`);
  }
  const issuer = (env[p + 'ISSUER'] ?? '').trim().replace(/\/+$/, '');
  let resource = (env[p + 'RESOURCE'] ?? '').trim();
  if (mode !== 'off') {
    if (!issuer) throw new ConfigError(`${p}ISSUER is required when ${p}MODE=${mode}`);
    if (!resource) throw new ConfigError(`${p}RESOURCE is required when ${p}MODE=${mode}`);
  }
  // Drop one trailing slash from a resource that has a path (never from a bare origin).
  if (resource.endsWith('/') && resource.split('/').length - 1 > 3) resource = resource.replace(/\/+$/, '');
  const parts = issuer ? issuerParts(issuer) : { base: '', app: '' };

  const pinnedRaw = env[p + 'PINNED_JWKS'];
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

  return {
    mode,
    issuer,
    resource,
    app: parts.app,
    jwksUrl: (env[p + 'JWKS_URL'] ?? (parts.base ? `${parts.base}/.well-known/jwks.json` : '')).trim(),
    snapshotUrl: (env[p + 'SNAPSHOT_URL'] ?? (issuer ? `${issuer}/snapshot` : '')).trim(),
    verifierToken: (env[p + 'VERIFIER_TOKEN'] ?? '').trim() || null,
    snapshotCachePath: (env[p + 'SNAPSHOT_CACHE'] ?? '').trim() || null,
    servicePrincipalsPath: (env[p + 'SERVICE_PRINCIPALS'] ?? '').trim() || null,
    pinnedJwks: pinned,
    pollIntervalS: readInt(env, p + 'POLL_INTERVAL_S', 60),
    jwksTtlS: readInt(env, p + 'JWKS_TTL_S', 300),
    leewayS: readInt(env, p + 'LEEWAY_S', 30),
    httpTimeoutMs: Math.round(readFloat(env, p + 'HTTP_TIMEOUT_S', 5) * 1000),
    realm: options.realm ?? `${prefix.toLowerCase()}-mcp`,
  };
}
