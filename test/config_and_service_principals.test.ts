import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

import { ConfigError, configFromEnv, parseLines, ServicePrincipals, SnapshotStore } from '../src/index.js';
import { APP, SUB } from './helpers/stub_broker.js';

describe('configFromEnv', () => {
  it('derives the app, JWKS and snapshot URLs and applies the defaults', () => {
    const c = configFromEnv('DEV', {
      env: {
        DEV_IDENTITY_MODE: 'enabled',
        DEV_IDENTITY_ISSUER: 'https://id.example.test/r/development/',
        DEV_IDENTITY_RESOURCE: 'https://dev.example.test/mcp/',
        DEV_IDENTITY_VERIFIER_TOKEN: 'bbv_x',
      },
    });
    expect(c.mode).toBe('enabled');
    expect(c.issuer).toBe('https://id.example.test/r/development');
    expect(c.resource).toBe('https://dev.example.test/mcp');
    expect(c.app).toBe('development');
    expect(c.jwksUrl).toBe('https://id.example.test/.well-known/jwks.json');
    expect(c.snapshotUrl).toBe('https://id.example.test/r/development/snapshot');
    expect(c.verifierToken).toBe('bbv_x');
    expect(c.pinnedJwks).toBeNull();
    expect(c.pollIntervalS).toBe(60);
    expect(c.jwksTtlS).toBe(300);
    expect(c.leewayS).toBe(30);
    expect(c.httpTimeoutMs).toBe(5000);
    expect(c.realm).toBe('dev-mcp');
  });

  it('keeps a bare-origin resource intact and honours explicit overrides', () => {
    const c = configFromEnv('DEV', {
      realm: 'custom',
      env: {
        DEV_IDENTITY_MODE: 'required',
        DEV_IDENTITY_ISSUER: 'https://id.example.test/r/development',
        DEV_IDENTITY_RESOURCE: 'https://dev.example.test/',
        DEV_IDENTITY_VERIFIER_TOKEN: 'bbv_x',
        DEV_IDENTITY_JWKS_URL: 'http://127.0.0.1:8775/.well-known/jwks.json',
        DEV_IDENTITY_SNAPSHOT_URL: 'http://127.0.0.1:8775/r/development/snapshot',
        DEV_IDENTITY_HTTP_TIMEOUT_S: '2.5',
        DEV_IDENTITY_PINNED_JWKS: '{"keys":[]}',
      },
    });
    expect(c.resource).toBe('https://dev.example.test/');
    expect(c.jwksUrl).toBe('http://127.0.0.1:8775/.well-known/jwks.json');
    expect(c.snapshotUrl).toBe('http://127.0.0.1:8775/r/development/snapshot');
    expect(c.httpTimeoutMs).toBe(2500);
    expect(c.realm).toBe('custom');
    expect(c.pinnedJwks).toEqual({ keys: [] });
  });

  it('needs nothing in off mode', () => {
    const c = configFromEnv('X', { env: {} });
    expect(c.mode).toBe('off');
    expect(c.issuer).toBe('');
    expect(c.app).toBe('');
    expect(c.jwksUrl).toBe('');
  });

  it.each([
    [{ X_IDENTITY_MODE: 'maybe' }],
    [{ X_IDENTITY_MODE: 'enabled' }],
    [{ X_IDENTITY_MODE: 'enabled', X_IDENTITY_ISSUER: 'https://id.example.test/r/app' }],
    [{ X_IDENTITY_MODE: 'enabled', X_IDENTITY_ISSUER: 'https://id.example.test/app', X_IDENTITY_RESOURCE: 'https://x/mcp' }],
    [{ X_IDENTITY_MODE: 'required', X_IDENTITY_ISSUER: 'https://id.example.test/r/app', X_IDENTITY_RESOURCE: 'https://x/mcp', X_IDENTITY_PINNED_JWKS: '{nope' }],
    [{ X_IDENTITY_MODE: 'required', X_IDENTITY_ISSUER: 'https://id.example.test/r/app', X_IDENTITY_RESOURCE: 'https://x/mcp', X_IDENTITY_PINNED_JWKS: '{"k":1}' }],
    [{ X_IDENTITY_MODE: 'required', X_IDENTITY_ISSUER: 'https://id.example.test/r/app', X_IDENTITY_RESOURCE: 'https://x/mcp', X_IDENTITY_POLL_INTERVAL_S: 'abc' }],
  ])('rejects bad settings %j', (env) => {
    expect(() => configFromEnv('X', { env })).toThrow(ConfigError);
  });
});

describe('service principals', () => {
  const token = `bbs_${'x'.repeat(40)}`;

  it('parses lines, skipping comments and blanks', () => {
    const lines = parseLines(`# comment\n\nsvc-nightly:Read:${SUB}:2099-01-01:${token}\n  svc-sync : Write : ${SUB} : 2030-06-30 : ${token}2 \n`);
    expect(lines).toHaveLength(2);
    expect(lines[0]).toEqual({ name: 'svc-nightly', tier: 'Read', ownerSub: SUB, expires: '2099-01-01', token });
    expect(lines[1]?.name).toBe('svc-sync');
    expect(lines[1]?.token).toBe(`${token}2`);
  });

  it.each([
    [`svc-a:Read:${SUB}:2099-01-01`],
    [`nightly:Read:${SUB}:2099-01-01:${token}`],
    [`svc-a:Read:005short:2099-01-01:${token}`],
    [`svc-a:Read:${SUB}:2099-01-01:tooshort`],
    [`svc-a:Read:${SUB}:tomorrow:${token}`],
    [`svc-a:Read:${SUB}:2099-13-45:${token}`],
  ])('rejects a malformed line %s', (line) => {
    expect(() => parseLines(line)).toThrow();
  });

  it('matches a bearer exactly and follows the owner and the expiry', () => {
    const dir = mkdtempSync(join(tmpdir(), 'bb-mcp-identity-'));
    const spPath = join(dir, 'service-principals');
    writeFileSync(spPath, `svc-nightly:Read:${SUB}:2099-01-01:${token}\nsvc-old:Read:${SUB}:2000-01-01:${token}old\n`);
    const sp = ServicePrincipals.fromFile(spPath);
    expect(sp.size).toBe(2);
    expect(sp.match(token)?.name).toBe('svc-nightly');
    expect(sp.match(`${token}x`)).toBeNull();
    expect(sp.match('short')).toBeNull();
    expect(ServicePrincipals.fromFile(join(dir, 'missing')).size).toBe(0);

    const cache = join(dir, 'snap.json');
    const snap = {
      version: 7,
      generated_at: Date.now(),
      stale_after_s: 1200,
      app: APP,
      subjects: { [SUB]: { status: 'active', active: true, not_before: 0, tier: 'Admin', scope: 't:read' } },
    };
    writeFileSync(cache, JSON.stringify(snap));
    const store = new SnapshotStore({ url: '', verifierToken: null, app: APP, cachePath: cache, pollIntervalS: 3600, timeoutMs: 1000 });
    expect(store.version).toBe(7);

    const nightly = sp.match(token)!;
    expect(ServicePrincipals.usable(nightly, store)).toEqual({ ok: true, reason: 'ok' });
    expect(ServicePrincipals.usable(sp.match(`${token}old`)!, store)).toEqual({ ok: false, reason: 'expired' });
    expect(ServicePrincipals.usable(nightly, store, '2099-01-02')).toEqual({ ok: false, reason: 'expired' });

    snap.subjects[SUB]!.active = false;
    snap.subjects[SUB]!.status = 'inactive';
    writeFileSync(cache, JSON.stringify(snap));
    const inactive = new SnapshotStore({ url: '', verifierToken: null, app: APP, cachePath: cache, pollIntervalS: 3600, timeoutMs: 1000 });
    expect(ServicePrincipals.usable(nightly, inactive)).toEqual({ ok: false, reason: 'owner_inactive' });

    writeFileSync(cache, JSON.stringify({ ...snap, subjects: {} }));
    const unknown = new SnapshotStore({ url: '', verifierToken: null, app: APP, cachePath: cache, pollIntervalS: 3600, timeoutMs: 1000 });
    expect(ServicePrincipals.usable(nightly, unknown)).toEqual({ ok: false, reason: 'owner_unknown' });

    writeFileSync(cache, JSON.stringify({ ...snap, generated_at: Date.now() - 2_000_000 }));
    const stale = new SnapshotStore({ url: '', verifierToken: null, app: APP, cachePath: cache, pollIntervalS: 3600, timeoutMs: 1000 });
    expect(ServicePrincipals.usable(nightly, stale)).toEqual({ ok: false, reason: 'snapshot_stale' });
  });
});
