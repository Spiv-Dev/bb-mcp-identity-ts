/**
 * Cases adopted from the first review pass: configuration rails, header
 * hygiene, malformed snapshot entries, key rotation, path matching, and the
 * gate's fail-closed behaviour when a callback throws.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  ConfigError,
  configFromEnv,
  Deny,
  IdentityGate,
  isCalendarDate,
  parseLines,
  ServicePrincipals,
  SnapshotStore,
  Verifier,
  VERSION,
  wwwAuthenticate,
} from '../src/index.js';
import { APP, makeConfig, RESOURCE, StubBroker, SUB } from './helpers/stub_broker.js';

let broker: StubBroker;
const servers: Server[] = [];

beforeEach(async () => {
  broker = new StubBroker();
  await broker.start();
});

afterEach(async () => {
  await broker.stop();
  await Promise.all(servers.splice(0).map((s) => new Promise<void>((resolve) => s.close(() => resolve()))));
});

async function started(mode = 'required', extra: Record<string, string> = {}): Promise<Verifier> {
  const v = new Verifier(makeConfig(broker, mode, extra));
  await v.keys.fetch();
  await v.snapshot.fetch();
  return v;
}

async function denial(v: Verifier, bearer: string): Promise<Deny> {
  try {
    await v.verify(bearer);
  } catch (err) {
    if (err instanceof Deny) return err;
    throw err;
  }
  throw new Error('expected a Deny');
}

async function serve(handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>): Promise<string> {
  const server = createServer(handler);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  if (!addr || typeof addr === 'string') throw new Error('no port');
  return `http://127.0.0.1:${addr.port}`;
}

function post(base: string, path: string, bearer?: string): Promise<Response> {
  return fetch(`${base}${path}`, { method: 'POST', headers: bearer ? { Authorization: `Bearer ${bearer}` } : {}, body: '{}' });
}

const BASE_ENV = {
  X_IDENTITY_MODE: 'required',
  X_IDENTITY_ISSUER: 'https://id.example.test/r/app',
  X_IDENTITY_RESOURCE: 'https://app.example.test/mcp',
  X_IDENTITY_VERIFIER_TOKEN: 'bbv_x',
};

describe('package', () => {
  it('keeps VERSION in step with package.json', () => {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string };
    expect(VERSION).toBe(pkg.version);
  });
});

describe('configuration rails', () => {
  it('treats an empty value as unset', () => {
    expect(() => configFromEnv('X', { env: { ...BASE_ENV, X_IDENTITY_VERIFIER_TOKEN: '  ' } })).toThrow(/VERIFIER_TOKEN is required/);
    const c = configFromEnv('X', { env: { ...BASE_ENV, X_IDENTITY_SNAPSHOT_URL: '', X_IDENTITY_JWKS_URL: '', X_IDENTITY_LEEWAY_S: '' } });
    expect(c.snapshotUrl).toBe('https://id.example.test/r/app/snapshot');
    expect(c.jwksUrl).toBe('https://id.example.test/.well-known/jwks.json');
    expect(c.leewayS).toBe(30);
  });

  it('requires the verifier token unless the mode is off', () => {
    const { X_IDENTITY_VERIFIER_TOKEN: _drop, ...noToken } = BASE_ENV;
    expect(() => configFromEnv('X', { env: noToken })).toThrow(ConfigError);
    expect(configFromEnv('X', { env: { ...noToken, X_IDENTITY_MODE: 'off' } }).mode).toBe('off');
  });

  it('parses integers strictly and allows a zero leeway only', () => {
    expect(() => configFromEnv('X', { env: { ...BASE_ENV, X_IDENTITY_LEEWAY_S: '30abc' } })).toThrow(ConfigError);
    expect(() => configFromEnv('X', { env: { ...BASE_ENV, X_IDENTITY_LEEWAY_S: '1.9' } })).toThrow(ConfigError);
    expect(configFromEnv('X', { env: { ...BASE_ENV, X_IDENTITY_LEEWAY_S: '0' } }).leewayS).toBe(0);
    expect(() => configFromEnv('X', { env: { ...BASE_ENV, X_IDENTITY_POLL_INTERVAL_S: '0' } })).toThrow(ConfigError);
    expect(() => configFromEnv('X', { env: { ...BASE_ENV, X_IDENTITY_HTTP_TIMEOUT_S: '-1' } })).toThrow(ConfigError);
  });

  it('allows plain http for loopback broker URLs only', () => {
    for (const host of ['127.0.0.1', 'localhost', '[::1]']) {
      const c = configFromEnv('X', { env: { ...BASE_ENV, X_IDENTITY_SNAPSHOT_URL: `http://${host}:8775/r/app/snapshot`, X_IDENTITY_JWKS_URL: `http://${host}:8775/.well-known/jwks.json` } });
      expect(c.snapshotUrl).toContain(host);
    }
    expect(() => configFromEnv('X', { env: { ...BASE_ENV, X_IDENTITY_SNAPSHOT_URL: 'http://10.0.0.5:8775/r/app/snapshot' } })).toThrow(/https/);
    expect(() => configFromEnv('X', { env: { ...BASE_ENV, X_IDENTITY_JWKS_URL: 'http://id.example.test/.well-known/jwks.json' } })).toThrow(/https/);
    expect(() => configFromEnv('X', { env: { ...BASE_ENV, X_IDENTITY_ISSUER: 'http://id.example.test/r/app' } })).toThrow(/https/);
    expect(() => configFromEnv('X', { env: { ...BASE_ENV, X_IDENTITY_SNAPSHOT_URL: 'not a url' } })).toThrow(ConfigError);
  });
});

describe('header hygiene', () => {
  it('never lets quotes or line breaks from the realm into WWW-Authenticate', () => {
    const c = configFromEnv('X', { env: BASE_ENV, realm: 'evil" x\r\nSet-Cookie: a=b' });
    const header = wwwAuthenticate(c, { error: 'invalid_token"\n' });
    expect(header).not.toMatch(/[\r\n]/);
    expect(header).toContain('realm="evil xSet-Cookie: a=b"');
    expect(header).toContain('error="invalid_token"');
    expect(header.split('"').length - 1).toBe(6);
  });
});

describe('service principal lines', () => {
  const token = `bbs_${'x'.repeat(40)}`;

  it('rejects impossible calendar dates', () => {
    expect(isCalendarDate('2099-02-28')).toBe(true);
    expect(isCalendarDate('2099-02-31')).toBe(false);
    expect(isCalendarDate('2024-02-29')).toBe(true);
    expect(isCalendarDate('2023-02-29')).toBe(false);
    expect(isCalendarDate('2099-13-01')).toBe(false);
    expect(() => parseLines(`svc-a:Read:${SUB}:2099-02-31:${token}`)).toThrow(/expiry/);
  });

  it('rejects duplicate names and reused tokens', () => {
    expect(() => parseLines(`svc-a:Read:${SUB}:2099-01-01:${token}\nsvc-a:Write:${SUB}:2099-01-01:${token}2`)).toThrow(/duplicate/);
    expect(() => parseLines(`svc-a:Read:${SUB}:2099-01-01:${token}\nsvc-b:Write:${SUB}:2099-01-01:${token}`)).toThrow(/reuses/);
  });

  it('keeps the expiry day itself valid', () => {
    const [p] = parseLines(`svc-a:Read:${SUB}:2030-06-30:${token}`);
    const dir = mkdtempSync(join(tmpdir(), 'bb-mcp-identity-'));
    const cache = join(dir, 'snap.json');
    writeFileSync(cache, JSON.stringify(broker.snapshot));
    const store = new SnapshotStore({ url: '', verifierToken: null, app: APP, cachePath: cache, pollIntervalS: 3600, timeoutMs: 1000 });
    expect(ServicePrincipals.usable(p!, store, '2030-06-30')).toEqual({ ok: true, reason: 'ok' });
    expect(ServicePrincipals.usable(p!, store, '2030-07-01')).toEqual({ ok: false, reason: 'expired' });
  });

  it('warns when a configured principals file is missing', async () => {
    const warnings: string[] = [];
    const v = new Verifier(makeConfig(broker, 'required', { T_IDENTITY_SERVICE_PRINCIPALS: join(tmpdir(), 'definitely-missing-principals') }), {
      warn: (m) => {
        warnings.push(m);
      },
    });
    expect(v.servicePrincipals.size).toBe(0);
    expect(warnings).toEqual(['identity: service principals file is missing or empty']);
  });
});

describe('snapshot entries', () => {
  it('treats a malformed subject entry as absent', async () => {
    const v = await started();
    broker.publish((s) => Object.assign(s.subjects[SUB]!, { not_before: 'soon' as unknown as number }));
    await v.snapshot.fetch();
    expect((await denial(v, await broker.mint())).reason).toBe('unknown_subject');
    broker.publish((s) => Object.assign(s.subjects[SUB]!, { not_before: 0, active: 'yes' as unknown as boolean }));
    await v.snapshot.fetch();
    expect((await denial(v, await broker.mint())).reason).toBe('unknown_subject');
    broker.publish((s) => Object.assign(s.subjects[SUB]!, { active: true, tier: 7 as unknown as string }));
    await v.snapshot.fetch();
    expect((await denial(v, await broker.mint())).reason).toBe('unknown_subject');
  });

  it('never resolves prototype keys as subjects', async () => {
    const v = await started();
    expect(v.snapshot.entry('__proto__')).toBeNull();
    expect(v.snapshot.entry('constructor')).toBeNull();
    expect(v.snapshot.entry('toString')).toBeNull();
    expect(v.snapshot.entry(SUB)?.tier).toBe('Admin');
  });

  it('keeps one poller across repeated start() calls and stops cleanly', async () => {
    const v = new Verifier(makeConfig(broker, 'required', { T_IDENTITY_POLL_INTERVAL_S: '1' }));
    const [a, b] = await Promise.all([v.snapshot.start(), v.snapshot.start()]);
    expect(a).toBe(true);
    expect(b).toBe(true);
    const seen = v.snapshot.version;
    broker.publish(() => undefined);
    await new Promise((r) => setTimeout(r, 1400));
    expect(v.snapshot.version).toBe(seen! + 1);
    v.stop();
    broker.publish(() => undefined);
    await new Promise((r) => setTimeout(r, 1400));
    expect(v.snapshot.version).toBe(seen! + 1);
  });
});

describe('keys and tokens', () => {
  it('drops a key the broker stopped publishing on the next refetch', async () => {
    const v = await started();
    const oldKidToken = await broker.mint();
    const rotated = new StubBroker();
    await rotated.start();
    try {
      broker.publicJwk = { ...rotated.publicJwk, kid: 'bbid-test-2' };
      // Still cached: the old key verifies until the next refetch.
      expect((await v.verify(oldKidToken)).sub).toBe(SUB);
      expect((await denial(v, await broker.mint({ _kid: 'bbid-never' }))).reason).toBe('unknown_kid');
      // The refetch replaced the fetched set; the old kid is gone, the new one works.
      expect((await denial(v, oldKidToken)).reason).toBe('unknown_kid');
      expect(v.health().keys.kids).toEqual(['bbid-test-2']);
      expect((await v.verify(await rotated.mint({ _kid: 'bbid-test-2', iss: broker.issuer }))).sub).toBe(SUB);
    } finally {
      await rotated.stop();
    }
  });

  it('applies the clock leeway at the boundary', async () => {
    const v = await started();
    const now = Math.floor(Date.now() / 1000);
    expect((await v.verify(await broker.mint({ exp: now - 20 }))).sub).toBe(SUB);
    expect((await denial(v, await broker.mint({ exp: now - 40 }))).reason).toBe('expired');
  });

  it('treats an unsigned token as not ours', async () => {
    const v = await started();
    const b64 = (s: string): string => Buffer.from(s).toString('base64url');
    const unsigned = `${b64(JSON.stringify({ alg: 'none', kid: 'bbid-test-1' }))}.${b64(JSON.stringify({ sub: SUB, iss: broker.issuer, aud: RESOURCE }))}.`;
    const d = await denial(v, unsigned);
    expect(d.reason).toBe('wrong_alg');
    expect(d.ours).toBe(false);
  });
});

describe('gate paths and failures', () => {
  it('gates the MCP path and everything under it, nothing beside it', async () => {
    const gate = new IdentityGate(await started());
    const base = await serve(
      gate.wrap((_req, res) => {
        res.end('inner');
      }),
    );
    for (const open of ['/mcpX', '/mcp-other', '/mcpp/x', '/healthz']) {
      expect((await post(base, open)).status, open).toBe(200);
    }
    for (const gated of ['/mcp', '/mcp/', '/mcp/sub', '/mcp?x=1']) {
      expect((await post(base, gated)).status, gated).toBe(401);
    }
    const root = new IdentityGate(await started(), { mcpPath: '/' });
    const rootBase = await serve(
      root.wrap((_req, res) => {
        res.end('inner');
      }),
    );
    expect((await post(rootBase, '/')).status).toBe(401);
    expect((await post(rootBase, '/anything')).status).toBe(401);
    expect((await fetch(`${rootBase}/.well-known/oauth-protected-resource`)).status).toBe(200);
  });

  it('fails closed with a 500 when a callback throws, without reaching the server', async () => {
    let innerCalls = 0;
    const logged: Record<string, unknown>[] = [];
    const gate = new IdentityGate(await started('enabled'), {
      mintInternalToken: () => {
        throw new Error('kms down');
      },
      legacyBearerOk: () => {
        throw new TypeError('token store offline');
      },
      log: (_m, f) => {
        logged.push(f);
      },
    });
    const base = await serve(
      gate.wrap((_req, res) => {
        innerCalls += 1;
        res.end('inner');
      }),
    );
    const r1 = await post(base, '/mcp', await broker.mint());
    expect(r1.status).toBe(500);
    expect(await r1.json()).toEqual({ error: 'server_error', error_description: 'identity check failed' });
    const r2 = await post(base, '/mcp', 'tok_legacy');
    expect(r2.status).toBe(500);
    expect(innerCalls).toBe(0);
    expect(gate.errors).toBe(2);
    expect(gate.verified).toBe(0);
    expect(logged.map((f) => f['error'])).toEqual(['Error', 'TypeError']);
    expect(JSON.stringify(logged)).not.toContain('kms down');
  });

  it('admits a service principal through the gate as its owner', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'bb-mcp-identity-'));
    const spPath = join(dir, 'service-principals');
    const token = `bbs_${'q'.repeat(40)}`;
    writeFileSync(spPath, `svc-nightly:Read:${SUB}:2099-01-01:${token}\n`);
    const gate = new IdentityGate(await started('required', { T_IDENTITY_SERVICE_PRINCIPALS: spPath }));
    const base = await serve(
      gate.wrap((req, res) => {
        const p = gate.principalOf(req);
        res.end(JSON.stringify({ sub: p?.sub, tier: p?.tier, kind: p?.kind }));
      }),
    );
    const r = await post(base, '/mcp', token);
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ sub: SUB, tier: 'Read', kind: 'service' });
  });
});
