/**
 * A stub broker for tests: an ephemeral ES256 key pair, a JWKS endpoint, a
 * snapshot endpoint with verifier-token auth and ETag, and a minter for test
 * tokens. Everything here is synthetic and lives only for one test run.
 */
import { randomBytes } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { exportJWK, generateKeyPair, SignJWT, type JWK, type KeyLike } from 'jose';

import { configFromEnv, type IdentityConfig, type SnapshotDocument } from '../../src/index.js';

export const APP = 'testapp';
export const RESOURCE = 'https://testapp-mcp.example.test/mcp';
export const VERIFIER_TOKEN = 'bbv_testapp_verifier_token_value_0000000000';
export const SUB = '005000000000001AAA';
export const OTHER_SUB = '005000000000002AAA';

/** Claim overrides; `_kid` and `_alg` steer the header instead. */
export type MintOverrides = Record<string, unknown> & { _kid?: string; _alg?: 'ES256' | 'HS256' };

export interface MutableSnapshot extends SnapshotDocument {
  subjects: Record<string, { status: string; active: boolean; not_before: number; tier: string | null; scope: string | null }>;
}

/** A throwaway symmetric key, new on every run, used only to mint tokens the verifier must refuse (wrong_alg). */
const HS_KEY = new Uint8Array(randomBytes(32));

export class StubBroker {
  readonly kid = 'bbid-test-1';
  jwksHits = 0;
  snapshotHits = 0;
  baseUrl = '';
  snapshot: MutableSnapshot;
  publicJwk: JWK = { kty: 'EC' };
  private privateKey: KeyLike | null = null;
  private server: Server | null = null;

  constructor() {
    this.snapshot = {
      version: 1,
      generated_at: Date.now(),
      source: 'salesforce',
      stale_after_s: 1200,
      app: APP,
      resource: RESOURCE,
      subjects: { [SUB]: { status: 'active', active: true, not_before: 0, tier: 'Admin', scope: 't:read t:write' } },
    };
  }

  get issuer(): string {
    return `${this.baseUrl}/r/${APP}`;
  }

  async start(): Promise<void> {
    const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
    this.privateKey = privateKey;
    this.publicJwk = { ...(await exportJWK(publicKey)), kid: this.kid, alg: 'ES256', use: 'sig' };
    this.server = createServer((req, res) => this.route(req, res));
    await new Promise<void>((resolve) => this.server!.listen(0, '127.0.0.1', resolve));
    const addr = this.server.address();
    if (!addr || typeof addr === 'string') throw new Error('stub broker did not bind a port');
    this.baseUrl = `http://127.0.0.1:${addr.port}`;
  }

  async stop(): Promise<void> {
    const s = this.server;
    this.server = null;
    if (s) await new Promise<void>((resolve) => s.close(() => resolve()));
  }

  /** Apply a change and bump the version so a poller sees it (generated_at is left to the test). */
  publish(mutate: (snap: MutableSnapshot) => void): void {
    mutate(this.snapshot);
    this.snapshot.version += 1;
  }

  async mint(overrides: MintOverrides = {}): Promise<string> {
    const { _kid, _alg, ...claimOverrides } = overrides;
    const now = Math.floor(Date.now() / 1000);
    const claims: Record<string, unknown> = {
      iss: this.issuer,
      aud: RESOURCE,
      sub: SUB,
      preferred_username: 'alice@example.invalid',
      app: APP,
      tier: 'Admin',
      scope: 't:read t:write',
      client_id: 'client-1',
      auth_time: now,
      iat: now,
      exp: now + 600,
      jti: 'jti-1',
      ...claimOverrides,
    };
    for (const k of Object.keys(claims)) if (claims[k] === undefined) delete claims[k];
    const alg = _alg ?? 'ES256';
    const jwt = new SignJWT(claims).setProtectedHeader({ alg, kid: _kid ?? this.kid, typ: 'at+jwt' });
    if (alg === 'HS256') return jwt.sign(HS_KEY);
    if (!this.privateKey) throw new Error('stub broker not started');
    return jwt.sign(this.privateKey);
  }

  private route(req: IncomingMessage, res: ServerResponse): void {
    const json = (status: number, body: unknown, extra: Record<string, string> = {}): void => {
      res.statusCode = status;
      res.setHeader('Content-Type', 'application/json');
      for (const [k, v] of Object.entries(extra)) res.setHeader(k, v);
      res.end(JSON.stringify(body));
    };
    if (req.method === 'GET' && req.url === '/.well-known/jwks.json') {
      this.jwksHits += 1;
      json(200, { keys: [this.publicJwk] });
      return;
    }
    if (req.method === 'GET' && req.url === `/r/${APP}/snapshot`) {
      this.snapshotHits += 1;
      if (req.headers.authorization !== `Bearer ${VERIFIER_TOKEN}`) {
        json(401, { error: 'unauthorized' });
        return;
      }
      const etag = `"${this.snapshot.version}"`;
      if (req.headers['if-none-match'] === etag) {
        res.statusCode = 304;
        res.end();
        return;
      }
      json(200, this.snapshot, { ETag: etag });
      return;
    }
    res.statusCode = 404;
    res.end();
  }
}

export function makeConfig(broker: StubBroker, mode = 'required', extra: Record<string, string> = {}): IdentityConfig {
  return configFromEnv('T', {
    env: {
      T_IDENTITY_MODE: mode,
      T_IDENTITY_ISSUER: broker.issuer,
      T_IDENTITY_RESOURCE: RESOURCE,
      T_IDENTITY_VERIFIER_TOKEN: VERIFIER_TOKEN,
      T_IDENTITY_POLL_INTERVAL_S: '3600',
      ...extra,
    },
  });
}
