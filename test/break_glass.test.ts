import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { afterEach, describe, expect, it } from 'vitest';

import {
  ConfigError,
  configFromEnv,
  Deny,
  IdentityGate,
  isArmed,
  mintBreakGlass,
  Verifier,
  type BreakGlassEvent,
} from '../src/index.js';
import { RESOURCE } from './helpers/stub_broker.js';

const OWNER = '005000000000009AAA';
const { bearer: BEARER, sha256: SHA } = mintBreakGlass('testapp');

function isoIn(deltaS: number): string {
  return new Date(Date.now() + deltaS * 1000).toISOString();
}

function baseEnv(mode = 'required'): Record<string, string> {
  return {
    T_IDENTITY_MODE: mode,
    T_IDENTITY_ISSUER: 'https://id.example.test/r/testapp',
    T_IDENTITY_RESOURCE: RESOURCE,
    T_IDENTITY_VERIFIER_TOKEN: 'bbv_x',
  };
}

function armedEnv(untilDeltaS = 3600, extra: Record<string, string> = {}): Record<string, string> {
  return {
    T_IDENTITY_BREAK_GLASS_SHA256: SHA,
    T_IDENTITY_BREAK_GLASS_UNTIL: isoIn(untilDeltaS),
    T_IDENTITY_BREAK_GLASS_TIER: 'Admin',
    T_IDENTITY_BREAK_GLASS_OWNER: OWNER,
    ...extra,
  };
}

const quiet = { warn: () => undefined };

function verifierFor(env: Record<string, string>, onBreakGlass?: (e: BreakGlassEvent) => void): Verifier {
  return new Verifier(configFromEnv('T', { env }), { ...quiet, onBreakGlass });
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

describe('break-glass settings', () => {
  it('mints a bbg_ bearer with its sha256', () => {
    const a = mintBreakGlass('development');
    expect(a.bearer.startsWith('bbg_development_')).toBe(true);
    expect(a.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(mintBreakGlass('development').bearer).not.toBe(a.bearer);
  });

  it('is absent when unset, and configured-but-disarmed with a hash and no window', () => {
    expect(configFromEnv('T', { env: baseEnv() }).breakGlass).toBeNull();
    const cfg = configFromEnv('T', { env: { ...baseEnv(), T_IDENTITY_BREAK_GLASS_SHA256: SHA.toUpperCase() } }).breakGlass;
    expect(cfg?.sha256).toBe(SHA);
    expect(cfg && isArmed(cfg, Date.now() / 1000)).toBe(false);
  });

  it.each([
    [{ T_IDENTITY_BREAK_GLASS_UNTIL: '2026-10-28T10:00:00+02:00' }, /SHA256 is not/],
    [{ T_IDENTITY_BREAK_GLASS_SHA256: 'nothex' }, /64 hex/],
    [armedEnv(3600, { T_IDENTITY_BREAK_GLASS_UNTIL: 'tomorrow' }), /timezone offset/],
    [armedEnv(3600, { T_IDENTITY_BREAK_GLASS_UNTIL: '2030-01-01T10:00:00' }), /timezone offset/],
    [armedEnv(25 * 3600), /at most 24 hours/],
    [armedEnv(3600, { T_IDENTITY_BREAK_GLASS_TIER: '' }), /TIER is required/],
    [armedEnv(3600, { T_IDENTITY_BREAK_GLASS_OWNER: 'short' }), /18-char/],
    [armedEnv(3600, { T_IDENTITY_BREAK_GLASS_OWNER: '../../../etc/passw' }), /18-char/],
    [armedEnv(3600, { T_IDENTITY_BREAK_GLASS_OWNER: '0050000000000ééAAA' }), /18-char/],
  ])('fails loudly on a bad setting (%#)', (extra, message) => {
    expect(() => configFromEnv('T', { env: { ...baseEnv(), ...extra } })).toThrow(ConfigError);
    expect(() => configFromEnv('T', { env: { ...baseEnv(), ...extra } })).toThrow(message);
  });

  it('treats a past window as simply disarmed', () => {
    const cfg = configFromEnv('T', { env: { ...baseEnv(), ...armedEnv(-60) } }).breakGlass;
    expect(cfg).not.toBeNull();
    expect(cfg && isArmed(cfg, Date.now() / 1000)).toBe(false);
  });
});

describe('break-glass verification', () => {
  it('works with no broker and no snapshot, as the owner at the configured tier', async () => {
    const p = await verifierFor({ ...baseEnv(), ...armedEnv() }).verify(BEARER);
    expect(p).toMatchObject({ kind: 'break_glass', sub: OWNER, tier: 'Admin', username: 'break-glass', app: 'testapp' });
  });

  const refusals: [Record<string, string>, string, string][] = [
    [{}, BEARER, 'break_glass_not_configured'],
    [{ T_IDENTITY_BREAK_GLASS_SHA256: SHA }, BEARER, 'break_glass_not_armed'],
    [armedEnv(-1), BEARER, 'break_glass_not_armed'],
    [armedEnv(), `${BEARER}x`, 'break_glass_mismatch'],
    [armedEnv(), 'bbg_testapp_guess', 'break_glass_mismatch'],
  ];
  for (const mode of ['enabled', 'required']) {
    it.each(refusals)(`refuses as ours in ${mode} mode (%#)`, async (extra, bearer, reason) => {
      const d = await denial(verifierFor({ ...baseEnv(mode), ...extra }), bearer);
      expect(d.reason).toBe(reason);
      expect(d.ours).toBe(true); // never handed to a legacy validator
    });
  }

  it('is never honoured in off mode', async () => {
    const d = await denial(verifierFor({ ...baseEnv('off'), ...armedEnv() }), BEARER);
    expect(d.reason).toBe('identity_off');
  });

  it('logs and counts every use and throttles alerts to one a minute', async () => {
    const events: BreakGlassEvent[] = [];
    const lines: string[] = [];
    const v = new Verifier(configFromEnv('T', { env: { ...baseEnv(), ...armedEnv() } }), {
      warn: (m) => lines.push(m),
      onBreakGlass: (e) => {
        events.push(e);
      },
    });
    const now = Date.now() / 1000;
    await v.verify(BEARER, now);
    await v.verify(BEARER, now + 10);
    await v.verify(BEARER, now + 61);
    expect(events).toHaveLength(2);
    expect(events[0]).toMatchObject({ event: 'identity.break_glass_used', owner_sub: OWNER, tier: 'Admin', uses: 1 });
    expect(events[1]?.uses).toBe(3);
    expect(lines.filter((l) => l.includes('BREAK-GLASS bearer used'))).toHaveLength(3);
    const h = v.health().break_glass;
    expect(h).toMatchObject({ configured: true, armed: true, uses: 3 });
    expect(h.last_used).not.toBeNull();
  });

  it('never lets a failing alert hook break the request', async () => {
    const v = verifierFor({ ...baseEnv(), ...armedEnv() }, () => {
      throw new Error('pager down');
    });
    expect((await v.verify(BEARER)).kind).toBe('break_glass');
  });

  it('announces an armed break-glass at start', async () => {
    const lines: string[] = [];
    // Points at a broker nobody runs: start() logs the announcement before it fetches keys.
    const v = new Verifier(configFromEnv('T', { env: { ...baseEnv(), ...armedEnv(600) } }), { warn: (m) => lines.push(m) });
    await v.start().catch(() => undefined);
    v.stop();
    expect(lines.some((l) => l.includes('break-glass ARMED'))).toBe(true);
  });
});

describe('break-glass through the gate', () => {
  const servers: Server[] = [];
  afterEach(async () => {
    await Promise.all(servers.splice(0).map((s) => new Promise<void>((resolve) => s.close(() => resolve()))));
  });

  it('lets the armed bearer through and refuses a wrong one', async () => {
    const gate = new IdentityGate(verifierFor({ ...baseEnv(), ...armedEnv(600) }));
    const server = createServer(
      gate.wrap((req: IncomingMessage, res: ServerResponse) => {
        const p = gate.principalOf(req);
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ principal: p?.sub ?? null, tier: p?.tier ?? null, kind: p?.kind ?? null }));
      }),
    );
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const addr = server.address();
    if (!addr || typeof addr === 'string') throw new Error('no port');
    const call = (bearer: string): Promise<Response> =>
      fetch(`http://127.0.0.1:${addr.port}/mcp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${bearer}` },
        body: '{}',
      });
    const ok = await call(BEARER);
    expect(ok.status).toBe(200);
    expect(await ok.json()).toEqual({ principal: OWNER, tier: 'Admin', kind: 'break_glass' });
    expect((await call('bbg_testapp_wrong')).status).toBe(401);
  });
});

describe('break-glass: one strict UNTIL format, the same as the Python verifier', () => {
  const now = Date.UTC(2026, 9, 28, 12, 0) / 1000;
  const env = (until: string): Record<string, string> => ({ ...baseEnv(), ...armedEnv(), T_IDENTITY_BREAK_GLASS_UNTIL: until });

  it.each([
    '2026-11-31T06:00:00Z', // no 31 November (Date.parse would roll it to 1 December)
    '2026-02-30T00:00:00Z',
    '2026-10-28T24:00:00Z',
    '2026-10-28t18:00:00z', // lowercase separators
    '2026-10-28 18:00:00+02:00', // space separator
    '20261028T180000+0200', // basic format
    '2026-10-28T18:00:00+0200',
    '2026-10-28T18:00:00+02',
    '2026-10-28T18Z',
    '2026-10-28T18:00:00.000001Z', // more than millisecond precision
    '2026-10-28T18:00:00+24:00',
  ])('rejects %s', (until) => {
    expect(() => configFromEnv('T', { env: env(until), nowS: now })).toThrow(ConfigError);
  });

  it.each([
    ['2026-10-28T18:00Z', Date.UTC(2026, 9, 28, 18, 0) / 1000],
    ['2026-10-28T18:00:00Z', Date.UTC(2026, 9, 28, 18, 0) / 1000],
    ['2026-10-28T20:00:00.123+02:00', Date.UTC(2026, 9, 28, 18, 0, 0, 123) / 1000],
    ['2026-10-28T09:00:00-04:00', Date.UTC(2026, 9, 28, 13, 0) / 1000],
  ])('accepts %s', (until, expected) => {
    const cfg = configFromEnv('T', { env: env(until), nowS: now }).breakGlass;
    expect(cfg?.until).toBeCloseTo(expected, 6);
    expect(cfg && isArmed(cfg, now)).toBe(true);
  });
});

describe('break-glass: async alert hooks', () => {
  it('a rejecting async hook is logged and never becomes an unhandled rejection', async () => {
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown): void => {
      unhandled.push(reason);
    };
    process.on('unhandledRejection', onUnhandled);
    try {
      const lines: string[] = [];
      const v = new Verifier(configFromEnv('T', { env: { ...baseEnv(), ...armedEnv() } }), {
        warn: (m) => lines.push(m),
        onBreakGlass: async () => {
          throw new Error('n8n down');
        },
      });
      expect((await v.verify(BEARER)).kind).toBe('break_glass');
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(unhandled).toEqual([]);
      expect(lines.some((l) => l.includes('alert hook failed: n8n down'))).toBe(true);
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }
  });

  it('an async hook is delivered', async () => {
    const sent: BreakGlassEvent[] = [];
    const v = verifierFor({ ...baseEnv(), ...armedEnv() }, async (e) => {
      await Promise.resolve();
      sent.push(e);
    });
    await v.verify(BEARER);
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(sent).toHaveLength(1);
  });
});

