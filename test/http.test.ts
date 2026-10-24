import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { extractBearer, IdentityGate, type Principal, Verifier } from '../src/index.js';
import { makeConfig, RESOURCE, StubBroker, SUB } from './helpers/stub_broker.js';

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

async function verifier(mode: string): Promise<Verifier> {
  const v = new Verifier(makeConfig(broker, mode));
  await v.keys.fetch();
  await v.snapshot.fetch();
  return v;
}

/** A server whose inner handler echoes the Authorization header and the gate's principal. */
async function serve(gate: IdentityGate): Promise<string> {
  const inner = (req: IncomingMessage, res: ServerResponse): void => {
    const p = gate.principalOf(req);
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ authorization: req.headers.authorization ?? '', principal: p?.sub ?? null, tier: p?.tier ?? null, path: req.url }));
  };
  const server = createServer(gate.wrap(inner));
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  if (!addr || typeof addr === 'string') throw new Error('no port');
  return `http://127.0.0.1:${addr.port}`;
}

function post(base: string, path: string, bearer?: string): Promise<Response> {
  return fetch(`${base}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}) },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
  });
}

describe('IdentityGate', () => {
  it('challenges without a bearer and serves the metadata document on both paths', async () => {
    const gate = new IdentityGate(await verifier('required'), { mcpPath: '/mcp', scopesSupported: ['t:read', 't:write', 'mcp'] });
    const base = await serve(gate);
    const r = await post(base, '/mcp');
    expect(r.status).toBe(401);
    const www = r.headers.get('www-authenticate') ?? '';
    expect(www).toContain('resource_metadata="https://testapp-mcp.example.test/.well-known/oauth-protected-resource"');
    expect(www).toContain('realm="t-mcp"');
    expect(www).not.toContain('error=');
    expect(r.headers.get('cache-control')).toBe('no-store');
    expect(await r.json()).toEqual({ error: 'unauthorized', error_description: 'authorization required' });

    const meta = await (await fetch(`${base}/.well-known/oauth-protected-resource`)).json();
    const meta2 = await (await fetch(`${base}/.well-known/oauth-protected-resource/mcp`)).json();
    expect(meta).toEqual(meta2);
    expect(meta).toEqual({
      resource: RESOURCE,
      authorization_servers: [broker.issuer],
      scopes_supported: ['mcp', 't:read', 't:write'],
      bearer_methods_supported: ['header'],
    });
  });

  it('sets the principal and rewrites the Authorization header for the inner layer', async () => {
    const minted: Principal[] = [];
    const gate = new IdentityGate(await verifier('required'), {
      mintInternalToken: (p) => {
        minted.push(p);
        return `internal-for-${p.sub}-${p.tier}`;
      },
    });
    const base = await serve(gate);
    const r = await post(base, '/mcp', await broker.mint());
    expect(r.status).toBe(200);
    const body = (await r.json()) as { authorization: string; principal: string; tier: string };
    expect(body.principal).toBe(SUB);
    expect(body.tier).toBe('Admin');
    expect(body.authorization).toBe(`Bearer internal-for-${SUB}-Admin`);
    expect(minted).toHaveLength(1);
    expect(gate.verified).toBe(1);
    expect(gate.denied).toBe(0);
    // A sub-path of the MCP endpoint is gated too; the header is left alone without a minter.
    const plain = new IdentityGate(await verifier('required'));
    const base2 = await serve(plain);
    const token = await broker.mint();
    const r2 = await post(base2, '/mcp/extra?x=1', token);
    expect(r2.status).toBe(200);
    expect(((await r2.json()) as { authorization: string }).authorization).toBe(`Bearer ${token}`);
  });

  it('refuses legacy tokens in required mode even when a legacy check is wired', async () => {
    const gate = new IdentityGate(await verifier('required'), { legacyBearerOk: () => true });
    const base = await serve(gate);
    const r = await post(base, '/mcp', 'tok_legacy_personal_token_xxxxxxxxxxxxxxxx');
    expect(r.status).toBe(401);
    expect(r.headers.get('www-authenticate')).toContain('error="invalid_token"');
    expect(gate.denied).toBe(1);
  });

  it('lets legacy tokens through to the server in enabled mode, never a denied broker token', async () => {
    const refusals: Record<string, unknown>[] = [];
    const gate = new IdentityGate(await verifier('enabled'), {
      legacyBearerOk: async (b) => b.startsWith('tok_'),
      log: (_m, fields) => {
        refusals.push(fields);
      },
    });
    const base = await serve(gate);
    const ok = await post(base, '/mcp', 'tok_legacy_personal_token_xxxxxxxxxxxxxxxx');
    expect(ok.status).toBe(200);
    expect(((await ok.json()) as { principal: string | null }).principal).toBeNull();
    const bad = await post(base, '/mcp', 'zzz_not_a_known_token');
    expect(bad.status).toBe(401);
    const denied = await post(base, '/mcp', await broker.mint({ aud: 'https://other.example.test/mcp' }));
    expect(denied.status).toBe(401);
    expect(refusals.map((f) => f['reason'])).toEqual(['not_a_jwt', 'wrong_audience']);
    expect(JSON.stringify(refusals)).not.toContain('zzz_not_a_known_token');
  });

  it('leaves other paths and off mode untouched', async () => {
    const base = await serve(new IdentityGate(await verifier('required')));
    const r = await post(base, '/healthz');
    expect(r.status).toBe(200);
    const off = await serve(new IdentityGate(new Verifier(makeConfig(broker, 'off'))));
    expect((await post(off, '/mcp')).status).toBe(200);
    expect((await fetch(`${off}/.well-known/oauth-protected-resource`)).status).toBe(200);
    expect(((await (await fetch(`${off}/.well-known/oauth-protected-resource`)).json()) as { path: string }).path).toBe(
      '/.well-known/oauth-protected-resource',
    );
  });

  it('exposes the outcome to servers that route by hand', async () => {
    const gate = new IdentityGate(await verifier('enabled'), { legacyBearerOk: (b) => b === 'tok_ok' });
    const outcomes: string[] = [];
    const server = createServer(async (req, res) => {
      const outcome = await gate.handle(req, res);
      outcomes.push(outcome.kind);
      if (outcome.kind === 'handled') return;
      res.statusCode = 204;
      res.end();
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const addr = server.address();
    const base = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`;
    await post(base, '/other');
    await post(base, '/mcp');
    await post(base, '/mcp', 'tok_ok');
    await post(base, '/mcp', await broker.mint());
    await fetch(`${base}/.well-known/oauth-protected-resource`);
    expect(outcomes).toEqual(['pass', 'handled', 'legacy', 'principal', 'handled']);
  });
});

describe('extractBearer', () => {
  it.each([
    ['Bearer abc', 'abc'],
    ['bearer   abc  ', 'abc'],
    ['BEARER x.y.z', 'x.y.z'],
    ['Basic abc', null],
    ['Bearer', null],
    ['Bearer ', null],
    [undefined, null],
  ])('parses %j', (header, expected) => {
    expect(extractBearer(header)).toBe(expected);
  });
  it('takes the first of repeated headers', () => {
    expect(extractBearer(['Bearer one', 'Bearer two'])).toBe('one');
  });
});
