import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { Deny, Verifier } from '../src/index.js';
import { makeConfig, OTHER_SUB, RESOURCE, StubBroker, SUB } from './helpers/stub_broker.js';

let broker: StubBroker;

beforeEach(async () => {
  broker = new StubBroker();
  await broker.start();
});

afterEach(async () => {
  await broker.stop();
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

describe('Verifier', () => {
  it('yields a principal whose tier and scopes come from the snapshot', async () => {
    const v = await started();
    const p = await v.verify(await broker.mint());
    expect(p.sub).toBe(SUB);
    expect(p.tier).toBe('Admin');
    expect(p.scopes).toEqual(['t:read', 't:write']);
    expect(p.username).toBe('alice@example.invalid');
    expect(p.clientId).toBe('client-1');
    expect(p.kind).toBe('user');
    expect(p.authTime).toBeGreaterThan(0);
  });

  it('lets the snapshot scope win over the token scope', async () => {
    const v = await started();
    broker.publish((s) => Object.assign(s.subjects[SUB]!, { tier: 'Read', scope: 't:read' }));
    await v.snapshot.fetch();
    const p = await v.verify(await broker.mint({ tier: 'Admin', scope: 't:read t:write' }));
    expect(p.tier).toBe('Read');
    expect(p.scopes).toEqual(['t:read']);
  });

  it.each([
    [{ aud: 'https://other.example.test/mcp' }, 'wrong_audience', true],
    [{ iss: 'https://evil.example.test/r/testapp' }, 'wrong_issuer', true],
    [{ exp: Math.floor(Date.now() / 1000) - 120 }, 'expired', true],
    [{ _kid: 'bbid-unknown' }, 'unknown_kid', true],
    [{ _alg: 'HS256' }, 'wrong_alg', false],
    [{ sub: 'short' }, 'malformed_claims', true],
    [{ auth_time: undefined }, 'malformed_claims', true],
    [{ app: 'otherapp' }, 'wrong_app', true],
    [{ sub: OTHER_SUB }, 'unknown_subject', true],
  ])('denies %j with %s', async (overrides, reason, ours) => {
    const v = await started();
    const d = await denial(v, await broker.mint(overrides as Record<string, unknown>));
    expect(d.reason).toBe(reason);
    expect(d.ours).toBe(ours);
  });

  it('treats anything that is not a JWT as not ours', async () => {
    const v = await started();
    const d = await denial(v, 'tok_legacy_personal_token_xxxxxxxxxxxxxxxx');
    expect(d.reason).toBe('not_a_jwt');
    expect(d.ours).toBe(false);
    const forged = await broker.mint();
    const tampered = `${forged.slice(0, -4)}AAAA`;
    expect((await denial(v, tampered)).reason).toMatch(/^invalid_token:/);
  });

  it('refetches the JWKS exactly once for an unknown kid', async () => {
    const v = await started();
    const before = broker.jwksHits;
    expect((await denial(v, await broker.mint({ _kid: 'bbid-unknown' }))).reason).toBe('unknown_kid');
    expect(broker.jwksHits).toBe(before + 1);
    // A key the broker starts publishing later is picked up on that single refetch.
    const rotated = new StubBroker();
    await rotated.start();
    try {
      broker.publicJwk = { ...rotated.publicJwk, kid: 'bbid-test-2' };
      const later = await rotated.mint({ _kid: 'bbid-test-2', iss: broker.issuer });
      expect((await v.verify(later)).sub).toBe(SUB);
    } finally {
      await rotated.stop();
    }
  });

  it('applies the snapshot rules: inactive, not entitled, not_before', async () => {
    const v = await started();
    broker.publish((s) => Object.assign(s.subjects[SUB]!, { active: false, status: 'inactive', tier: null, scope: null }));
    await v.snapshot.fetch();
    expect((await denial(v, await broker.mint())).reason).toBe('subject_inactive');

    broker.publish((s) => Object.assign(s.subjects[SUB]!, { active: true, status: 'active', tier: null, scope: null }));
    await v.snapshot.fetch();
    expect((await denial(v, await broker.mint())).reason).toBe('not_entitled');

    const nowS = Math.floor(Date.now() / 1000);
    broker.publish((s) => Object.assign(s.subjects[SUB]!, { tier: 'Admin', scope: 't:read', not_before: nowS + 5 }));
    await v.snapshot.fetch();
    expect((await denial(v, await broker.mint())).reason).toBe('not_before');
    // Signed in at the very second of the revocation: still ended.
    expect((await denial(v, await broker.mint({ auth_time: nowS + 5 }))).reason).toBe('not_before');
    // Signed in one second later: a new session.
    expect((await v.verify(await broker.mint({ auth_time: nowS + 6 }))).sub).toBe(SUB);
  });

  it('denies on a stale snapshot and when none was ever loaded', async () => {
    const v = await started();
    broker.publish((s) => {
      s.generated_at = Date.now() - 2_000_000;
    });
    await v.snapshot.fetch();
    expect((await denial(v, await broker.mint())).reason).toBe('snapshot_stale');

    const v2 = new Verifier(makeConfig(broker, 'required', { T_IDENTITY_VERIFIER_TOKEN: 'wrong' }));
    await v2.keys.fetch();
    expect(await v2.snapshot.fetch()).toBe(false);
    expect((await denial(v2, await broker.mint())).reason).toBe('no_snapshot');
  });

  it('never verifies in off mode', async () => {
    const v = new Verifier(makeConfig(broker, 'off'));
    const d = await denial(v, await broker.mint());
    expect(d.reason).toBe('identity_off');
    expect(d.ours).toBe(false);
  });

  it('verifies with pinned keys and no JWKS endpoint', async () => {
    const v = new Verifier(
      makeConfig(broker, 'required', { T_IDENTITY_PINNED_JWKS: JSON.stringify({ keys: [broker.publicJwk] }), T_IDENTITY_JWKS_URL: 'http://127.0.0.1:9/nope' }),
    );
    await v.snapshot.fetch();
    expect((await v.verify(await broker.mint())).sub).toBe(SUB);
    expect(broker.jwksHits).toBe(0);
    expect(v.health().keys.kids).toEqual(['bbid-test-1']);
  });

  it('ignores private or foreign JWKS members', async () => {
    const pinned = {
      keys: [
        { ...broker.publicJwk, d: 'bm90LWEtcmVhbC1wcml2YXRlLXBhcnQ' },
        { kty: 'RSA', kid: 'rsa-1', n: 'AQAB', e: 'AQAB' },
        { ...broker.publicJwk, kid: '' },
        { ...broker.publicJwk, alg: 'ES384' },
      ],
    };
    const v = new Verifier(makeConfig(broker, 'required', { T_IDENTITY_PINNED_JWKS: JSON.stringify(pinned), T_IDENTITY_JWKS_URL: '' }));
    await v.snapshot.fetch();
    expect(v.health().keys.kids).toEqual([]);
    expect((await denial(v, await broker.mint())).reason).toBe('unknown_kid');
  });

  it('uses the ETag on polls and restores from the disk cache', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'bb-mcp-identity-'));
    const cache = join(dir, 'snap.json');
    const v = new Verifier(makeConfig(broker, 'required', { T_IDENTITY_SNAPSHOT_CACHE: cache }));
    expect(await v.snapshot.fetch()).toBe(true);
    const hits = broker.snapshotHits;
    expect(await v.snapshot.fetch()).toBe(true); // 304
    expect(broker.snapshotHits).toBe(hits + 1);
    expect(existsSync(cache)).toBe(true);
    // A fresh verifier restores from disk before its first poll, even when the broker is unreachable.
    const v2 = new Verifier(makeConfig(broker, 'required', { T_IDENTITY_SNAPSHOT_CACHE: cache, T_IDENTITY_VERIFIER_TOKEN: 'wrong' }));
    expect(v2.snapshot.version).toBe(broker.snapshot.version);
    expect(v2.snapshot.health().fresh).toBe(true);
    await v2.keys.fetch();
    expect((await v2.verify(await broker.mint())).sub).toBe(SUB);
    // A cache written for another app is ignored.
    writeFileSync(cache, JSON.stringify({ ...broker.snapshot, app: 'someone-else' }));
    const v3 = new Verifier(makeConfig(broker, 'required', { T_IDENTITY_SNAPSHOT_CACHE: cache }));
    expect(v3.snapshot.version).toBeNull();
  });

  it('honours service principals only while the owner is active', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'bb-mcp-identity-'));
    const spPath = join(dir, 'service-principals');
    const token = `bbs_${'y'.repeat(40)}`;
    writeFileSync(spPath, `svc-nightly:Read:${SUB}:2099-01-01:${token}\n`);
    const v = await started('required', { T_IDENTITY_SERVICE_PRINCIPALS: spPath });
    const p = await v.verify(token);
    expect(p.kind).toBe('service');
    expect(p.sub).toBe(SUB);
    expect(p.tier).toBe('Read');
    expect(p.clientId).toBe('svc-nightly');
    expect(v.health().service_principals).toBe(1);

    broker.publish((s) => Object.assign(s.subjects[SUB]!, { active: false, status: 'inactive' }));
    await v.snapshot.fetch();
    expect((await denial(v, token)).reason).toBe('service_owner_inactive');
    expect((await denial(v, `bbs_${'z'.repeat(40)}`)).reason).toBe('not_a_jwt');
  });

  it('reports health', async () => {
    const v = await started();
    const h = v.health();
    expect(h.mode).toBe('required');
    expect(h.resource).toBe(RESOURCE);
    expect(h.snapshot.fresh).toBe(true);
    expect(h.snapshot.version).toBe(broker.snapshot.version);
    expect(h.snapshot.subjects).toBe(1);
    expect(h.keys.kids).toEqual(['bbid-test-1']);
    expect(h.keys.last_error).toBeNull();
  });
});
