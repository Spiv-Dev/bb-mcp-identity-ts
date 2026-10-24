/**
 * node:http integration that puts a server behind the broker.
 *
 *   const gate = new IdentityGate(verifier, {
 *     mcpPath: '/mcp',
 *     legacyBearerOk: (bearer) => tokens.has(bearer),   // enabled mode only; omit in required mode
 *     mintInternalToken: (p) => signInternalJwt(p),      // optional: keep the inner validator unchanged
 *     scopesSupported: ['sf:read', 'sf:write'],
 *   });
 *
 *   createServer(async (req, res) => {
 *     const outcome = await gate.handle(req, res);
 *     if (outcome.kind === 'handled') return;           // metadata document or 401 already written
 *     ...the server's existing request handling...
 *   });
 *
 * Behaviour on `mcpPath`:
 *   no bearer                    -> 401 + WWW-Authenticate (resource_metadata=...)   { kind: 'handled' }
 *   broker token, verified       -> { kind: 'principal' }; `gate.principalOf(req)` returns it; with
 *                                   `mintInternalToken` the Authorization header is replaced by the
 *                                   server's own internal token for that principal
 *   broker token, denied         -> 401 (the reason is logged, never sent)            { kind: 'handled' }
 *   not a broker token, enabled  -> `legacyBearerOk(bearer)` true: { kind: 'legacy' }, request untouched;
 *                                   false: 401                                        { kind: 'handled' }
 *   not a broker token, required -> 401                                               { kind: 'handled' }
 *
 * Also serves `/.well-known/oauth-protected-resource` and the same document
 * with the MCP path appended. Every other path, and every request while the
 * mode is `off`, is { kind: 'pass' }.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';

import { isEnabled, isRequired } from './config.js';
import { protectedResourceMetadata, wwwAuthenticate } from './metadata.js';
import { Deny, type Principal, type Verifier } from './verifier.js';

export type LegacyCheck = (bearer: string) => boolean | Promise<boolean>;
export type Minter = (principal: Principal) => string | Promise<string>;

export interface GateOptions {
  mcpPath?: string;
  legacyBearerOk?: LegacyCheck;
  mintInternalToken?: Minter;
  scopesSupported?: readonly string[];
  /** Receives one line per refusal with the stable reason; never the token. */
  log?: (message: string, fields: Record<string, unknown>) => void;
}

export type GateOutcome =
  | { kind: 'pass' }
  | { kind: 'handled' }
  | { kind: 'legacy'; bearer: string }
  | { kind: 'principal'; principal: Principal };

export const PRM_PATH = '/.well-known/oauth-protected-resource';

/** The request path without its query string. */
export function pathOnly(url: string | undefined): string {
  if (!url) return '';
  const q = url.indexOf('?');
  return q >= 0 ? url.slice(0, q) : url;
}

/** The token from an `Authorization: Bearer <token>` header, or null. */
export function extractBearer(header: string | string[] | undefined): string | null {
  const h = Array.isArray(header) ? header[0] : header;
  if (typeof h !== 'string') return null;
  const m = /^\s*bearer\s+(.+?)\s*$/i.exec(h);
  return m?.[1] ? m[1] : null;
}

function writeJson(res: ServerResponse, status: number, body: unknown): void {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

export class IdentityGate {
  readonly verifier: Verifier;
  readonly mcpPath: string;
  private readonly legacyBearerOk: LegacyCheck | null;
  private readonly mintInternalToken: Minter | null;
  private readonly scopesSupported: readonly string[];
  private readonly log: (message: string, fields: Record<string, unknown>) => void;
  private readonly principals = new WeakMap<IncomingMessage, Principal>();
  verified = 0;
  denied = 0;

  constructor(verifier: Verifier, options: GateOptions = {}) {
    this.verifier = verifier;
    this.mcpPath = (options.mcpPath ?? '/mcp').replace(/\/+$/, '') || '/';
    this.legacyBearerOk = options.legacyBearerOk ?? null;
    this.mintInternalToken = options.mintInternalToken ?? null;
    this.scopesSupported = options.scopesSupported ?? [];
    this.log = options.log ?? (() => undefined);
  }

  /** The principal verified for this request, if the gate verified one. */
  principalOf(req: IncomingMessage): Principal | undefined {
    return this.principals.get(req);
  }

  async handle(req: IncomingMessage, res: ServerResponse): Promise<GateOutcome> {
    const config = this.verifier.config;
    if (!isEnabled(config)) return { kind: 'pass' };
    const path = pathOnly(req.url);
    if (path === PRM_PATH || path === `${PRM_PATH}${this.mcpPath}`) {
      writeJson(res, 200, protectedResourceMetadata(config, this.scopesSupported));
      return { kind: 'handled' };
    }
    if (!(path === this.mcpPath || path.startsWith(`${this.mcpPath}/`))) return { kind: 'pass' };

    const bearer = extractBearer(req.headers.authorization);
    if (bearer === null) {
      this.challenge(res, 'missing_bearer');
      return { kind: 'handled' };
    }
    let principal: Principal;
    try {
      principal = await this.verifier.verify(bearer);
    } catch (err) {
      if (!(err instanceof Deny)) throw err;
      if (!err.ours && !isRequired(config) && this.legacyBearerOk !== null && (await this.legacyBearerOk(bearer))) {
        return { kind: 'legacy', bearer };
      }
      this.denied += 1;
      this.log('identity: bearer refused', { reason: err.reason, ours: err.ours, method: req.method, path });
      this.challenge(res, err.reason);
      return { kind: 'handled' };
    }

    this.verified += 1;
    this.principals.set(req, principal);
    if (this.mintInternalToken !== null) {
      req.headers.authorization = `Bearer ${await this.mintInternalToken(principal)}`;
    }
    return { kind: 'principal', principal };
  }

  /** Compose: run `inner` for every request the gate does not answer itself. */
  wrap(inner: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
    return async (req, res) => {
      const outcome = await this.handle(req, res);
      if (outcome.kind === 'handled') return;
      await inner(req, res);
    };
  }

  private challenge(res: ServerResponse, reason: string): void {
    const error = reason === 'missing_bearer' ? null : 'invalid_token';
    res.statusCode = 401;
    res.setHeader('WWW-Authenticate', wwwAuthenticate(this.verifier.config, { error }));
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.end(JSON.stringify({ error: error ?? 'unauthorized', error_description: 'authorization required' }));
  }
}
