/** The usage ledger: event shape, redaction, never-throw, rotation and prune. All synthetic. */
import { createHash } from 'node:crypto';
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';

import { FIELD_ORDER, QUESTION_LIMIT, redactQuestion, UsageLedger, userSlug } from '../src/index.js';

const SPEC = join(dirname(fileURLToPath(import.meta.url)), '..', 'spec');
const SCHEMA = JSON.parse(readFileSync(join(SPEC, 'usage_event_v1.json'), 'utf8')) as {
  required: string[];
  properties: Record<string, Record<string, unknown>>;
};
const FIXTURES = JSON.parse(readFileSync(join(SPEC, 'redaction_fixtures_v1.json'), 'utf8')) as {
  cases: Array<{ in: string; out: string | null }>;
};

// Shared with bb-mcp-identity-py, which pins the same hashes. Change both repos together.
const SCHEMA_SHA256 = '6494bd8175dbf76f0e46b081e0039d0a058e593e89a3f6647cb8ddcbdef2a7a4';
const FIXTURES_SHA256 = '26a04dfee7c4cc83be4954bdbc116758a29bbd081d90af34f239a3df91511ef6';

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'usage-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function sha(p: string): string {
  return createHash('sha256').update(readFileSync(p)).digest('hex');
}

function readLines(dir: string): Array<Record<string, unknown>> {
  return readdirSync(dir)
    .filter((n) => n.startsWith('usage-'))
    .sort()
    .flatMap((n) =>
      readFileSync(join(dir, n), 'utf8')
        .split('\n')
        .filter(Boolean)
        .map((l) => JSON.parse(l) as Record<string, unknown>),
    );
}

/** A small JSON-schema check covering the keywords the v1 schema uses. */
function checkSchema(ev: Record<string, unknown>): void {
  expect(Object.keys(ev).sort()).toEqual([...SCHEMA.required].sort());
  for (const [key, rule] of Object.entries(SCHEMA.properties)) {
    const val = ev[key];
    if ('const' in rule) expect(val, key).toBe(rule['const']);
    if ('enum' in rule) expect(rule['enum'] as unknown[], key).toContain(val);
    const types = rule['type'] as string | string[] | undefined;
    if (types !== undefined) {
      const allowed = Array.isArray(types) ? types : [types];
      const actual = val === null ? 'null' : Array.isArray(val) ? 'array' : Number.isInteger(val) ? 'integer' : typeof val;
      expect(allowed, key).toContain(actual);
    }
    if (typeof val === 'string') {
      if (typeof rule['maxLength'] === 'number') expect(Array.from(val).length, key).toBeLessThanOrEqual(rule['maxLength']);
      if (typeof rule['pattern'] === 'string') expect(val, key).toMatch(new RegExp(rule['pattern']));
    }
    if (typeof val === 'number' && typeof rule['minimum'] === 'number') expect(val).toBeGreaterThanOrEqual(rule['minimum']);
    if (Array.isArray(val)) {
      expect(val.length).toBeLessThanOrEqual(rule['maxItems'] as number);
      const pat = new RegExp((rule['items'] as { pattern: string }).pattern);
      for (const item of val) expect(item).toMatch(pat);
    }
  }
}

describe('spec files', () => {
  it('are the shared versions', () => {
    expect(sha(join(SPEC, 'usage_event_v1.json'))).toBe(SCHEMA_SHA256);
    expect(sha(join(SPEC, 'redaction_fixtures_v1.json'))).toBe(FIXTURES_SHA256);
  });

  it('field order matches the schema', () => {
    expect([...FIELD_ORDER]).toEqual(SCHEMA.required);
  });
});

describe('UsageLedger', () => {
  it('is off without the env setting', () => {
    const led = UsageLedger.fromEnv('TESTAPP', { server: 'testapp' }, {});
    expect(led.enabled).toBe(false);
    expect(led.record({ tool: 't', outcome: 'ok', duration_ms: 1 })).toBe(false);
    expect(led.writeCatalog([{ name: 't' }])).toBe(false);
  });

  it('reads <PREFIX>_USAGE_DIR', () => {
    const d = tmp();
    const led = UsageLedger.fromEnv('TESTAPP', { server: 'testapp' }, { TESTAPP_USAGE_DIR: d });
    expect(led.enabled).toBe(true);
    expect(led.dir).toBe(d);
  });

  it('writes a full event that matches the schema', () => {
    const d = tmp();
    const led = new UsageLedger(d, { server: 'testapp', version: '1.2.3' });
    expect(
      led.record({
        tool: 'sf_ping',
        kind: 'write',
        user: 'Mitchell@BakerBaynes.com',
        user_kind: 'user',
        tier: 'admin',
        client: 'claude-ai',
        outcome: 'ok',
        duration_ms: 12.6,
        response_bytes: 2048,
        arg_keys: ['repo', 'dry_run', '_user_question', '_user_id'],
        write_mode: 'preview',
        via_tool: 'sf_batch_call',
        correlation_id: 'c-1',
        parent_correlation_id: 'p-1',
        question: 'Email jane.doe@acme.co.za about the R 12 500 renewal',
      }),
    ).toBe(true);
    const [ev] = readLines(d);
    expect(ev).toBeDefined();
    checkSchema(ev!);
    expect(ev!['server']).toBe('testapp');
    expect(ev!['server_version']).toBe('1.2.3');
    expect(ev!['user']).toBe('mitchell');
    expect(ev!['duration_ms']).toBe(13);
    expect(ev!['arg_keys']).toEqual(['dry_run', 'repo']);
    expect(ev!['question']).toBe('Email [email] about the [amount] renewal');
    expect(Object.keys(ev!)).toEqual([...FIELD_ORDER]);
  });

  it('writes a minimal event that matches the schema', () => {
    const d = tmp();
    const led = new UsageLedger(d, { server: 'testapp' });
    led.record({ tool: 't', outcome: 'denied', duration_ms: 0 });
    const [ev] = readLines(d);
    checkSchema(ev!);
    expect(ev).toMatchObject({ user: null, user_kind: 'unknown', kind: 'read', write_mode: 'n/a', question: null, arg_keys: [] });
  });

  it('never writes argument values', () => {
    const d = tmp();
    const led = new UsageLedger(d, { server: 'testapp' });
    const secret = 'VALUE-THAT-MUST-NOT-APPEAR';
    led.record({
      tool: 't',
      outcome: 'ok',
      duration_ms: 1,
      arg_keys: { account: secret, amount: 5 },
      ...({ args: { x: secret }, result: { y: secret } } as object),
    });
    const text = readdirSync(d)
      .map((n) => readFileSync(join(d, n), 'utf8'))
      .join('');
    expect(text).not.toContain(secret);
    const [ev] = readLines(d);
    expect(ev!['arg_keys']).toEqual(['account', 'amount']);
    expect(led.droppedFields).toBe(2);
  });

  it.each([
    ['kind', 'delete', 'read'],
    ['outcome', 'maybe', 'error'],
    ['user_kind', 'robot', 'unknown'],
    ['write_mode', 'yes', 'n/a'],
    ['duration_ms', -5, 0],
    ['duration_ms', Number.POSITIVE_INFINITY, 0],
    ['duration_ms', '12', 0],
    ['response_bytes', true, null],
  ])('a bad %s (%s) falls back to %s', (field, value, expected) => {
    const d = tmp();
    const led = new UsageLedger(d, { server: 'testapp' });
    expect(led.record({ tool: 't', outcome: 'ok', duration_ms: 1, [field]: value })).toBe(true);
    const [ev] = readLines(d);
    checkSchema(ev!);
    expect(ev![field]).toBe(expected);
  });

  it('bounds and cleans strings', () => {
    const d = tmp();
    const led = new UsageLedger(d, { server: 'testapp' });
    led.record({ tool: 'x'.repeat(500), outcome: 'ok', duration_ms: 1, client: 'bad\u0000client \ud83d', error_code: 'E'.repeat(99) });
    const [ev] = readLines(d);
    checkSchema(ev!);
    expect((ev!['tool'] as string).length).toBe(128);
    expect((ev!['error_code'] as string).length).toBe(64);
    expect(ev!['client']).toBe('badclient �');
  });

  it('rejects odd argument names', () => {
    const d = tmp();
    const led = new UsageLedger(d, { server: 'testapp' });
    led.record({ tool: 't', outcome: 'ok', duration_ms: 1, arg_keys: ['ok', '-dash', 'has space', 'x'.repeat(65), 7, ''] });
    expect(readLines(d)[0]!['arg_keys']).toEqual(['ok']);
  });

  it('never throws when the directory cannot be written', () => {
    const d = tmp();
    const blocker = join(d, 'file');
    writeFileSync(blocker, 'not a directory');
    const led = new UsageLedger(join(blocker, 'usage'), { server: 'testapp' });
    expect(led.record({ tool: 't', outcome: 'ok', duration_ms: 1 })).toBe(false);
    expect(led.writeCatalog([{ name: 't' }])).toBe(false);
    expect(led.writeErrors).toBe(2);
    expect(led.stats().last_error).not.toBeNull();
  });

  it('writes one line per event into UTC day files', () => {
    const d = tmp();
    const led = new UsageLedger(d, { server: 'testapp' });
    const day1 = new Date('2026-11-05T23:59:59.999Z');
    led.record({ tool: 'a', outcome: 'ok', duration_ms: 1, ts: day1 });
    led.record({ tool: 'b', outcome: 'ok', duration_ms: 1, ts: new Date(day1.getTime() + 1) });
    const names = readdirSync(d).filter((n) => n.startsWith('usage-')).sort();
    expect(names).toEqual(['usage-2026-11-05.jsonl', 'usage-2026-11-06.jsonl']);
    for (const n of names) {
      const raw = readFileSync(join(d, n), 'utf8');
      expect(raw.endsWith('\n')).toBe(true);
      expect(raw.split('\n').length).toBe(2);
    }
    expect(readLines(d).map((e) => e['ts'])).toEqual(['2026-11-05T23:59:59.999Z', '2026-11-06T00:00:00.000Z']);
  });

  it('prunes files older than 14 days', () => {
    const d = tmp();
    for (const day of ['2026-10-20', '2026-10-22', '2026-10-23', '2026-11-04']) writeFileSync(join(d, `usage-${day}.jsonl`), '{}\n');
    writeFileSync(join(d, 'keep-me.txt'), 'x');
    const led = new UsageLedger(d, { server: 'testapp' });
    led.record({ tool: 't', outcome: 'ok', duration_ms: 1, ts: new Date('2026-11-06T08:00:00Z') });
    expect(readdirSync(d).sort()).toEqual(['keep-me.txt', 'usage-2026-10-23.jsonl', 'usage-2026-11-04.jsonl', 'usage-2026-11-06.jsonl']);
  });

  it.skipIf(process.platform === 'win32')('creates files with mode 0600', () => {
    const d = tmp();
    const led = new UsageLedger(d, { server: 'testapp' });
    led.record({ tool: 't', outcome: 'ok', duration_ms: 1 });
    led.writeCatalog([{ name: 't' }]);
    for (const n of readdirSync(d)) expect(statSync(join(d, n)).mode & 0o777).toBe(0o600);
  });

  it('writes the catalog', () => {
    const d = tmp();
    const led = new UsageLedger(d, { server: 'testapp' });
    expect(led.writeCatalog([{ name: 'b_tool', kind: 'write', domain: 'x' }, { name: 'a_tool' }, { name: null }, { name: undefined }])).toBe(true);
    const doc = JSON.parse(readFileSync(join(d, 'tools.json'), 'utf8')) as { server: string; v: number; tools: unknown[] };
    expect(doc.server).toBe('testapp');
    expect(doc.v).toBe(1);
    expect(doc.tools).toEqual([
      { name: 'a_tool', kind: 'read', domain: null },
      { name: 'b_tool', kind: 'write', domain: 'x' },
    ]);
    expect(readdirSync(d).filter((n) => n.startsWith('.tools.json.'))).toEqual([]);
  });

  it('reports stats', () => {
    const d = tmp();
    const led = new UsageLedger(d, { server: 'testapp' });
    led.record({ tool: 't', outcome: 'ok', duration_ms: 1 });
    expect(led.stats()).toMatchObject({ enabled: true, written: 1, write_errors: 0 });
  });
});

describe('userSlug', () => {
  it.each([
    ['Mitchell@BakerBaynes.com', 'mitchell'],
    ['jeandre.vr@bakerbaynes.com.sandbox', 'jeandre.vr'],
    ['break-glass', 'break-glass'],
    ['svc-routines', 'svc-routines'],
    ['  ', null],
    ['@nolocal', null],
    [null, null],
  ])('%s -> %s', (username, slug) => {
    expect(userSlug(username)).toBe(slug);
  });
});

describe('redactQuestion', () => {
  it.each(FIXTURES.cases.map((c) => [JSON.stringify(c.in).slice(0, 40), c] as const))('fixture %s', (_label, c) => {
    expect(redactQuestion(c.in)).toBe(c.out);
  });

  it('returns null for blanks and non-strings', () => {
    expect(redactQuestion(null)).toBeNull();
    expect(redactQuestion(42)).toBeNull();
    expect(redactQuestion('   ')).toBeNull();
  });

  it('lets no synthetic PII through randomised questions', () => {
    let seed = 20261106;
    const rand = (): number => {
      seed = (seed * 1103515245 + 12345) % 2 ** 31;
      return seed / 2 ** 31;
    };
    const pick = <T,>(xs: readonly T[]): T => xs[Math.floor(rand() * xs.length)]!;
    const words = ['pipeline', 'renewal', 'Implementations', 'west', 'team', 'Q3', 'for', 'the', 'deal', '2026'];
    const makers = [
      () => `${'abcxyz'.charAt(Math.floor(rand() * 6))}x.y@acme.co.za`,
      () => pick(['082 555 0123', '+27 71 555 0123', '011-555-0123', '0215550123']),
      () => Array.from({ length: pick([9, 13, 16]) }, () => String(Math.floor(rand() * 10))).join(''),
      () => pick(['R 12 500', 'R2,5m', '$1,200', '500k', 'ZAR 3 940.17', '1 500 rand']),
    ];
    for (let i = 0; i < 400; i++) {
      const parts: string[] = [];
      const planted: string[] = [];
      const n = 5 + Math.floor(rand() * 136);
      for (let j = 0; j < n; j++) {
        if (rand() < 0.15) {
          const tok = pick(makers)();
          planted.push(tok);
          parts.push(tok);
        } else parts.push(pick(words));
      }
      if (rand() < 0.3) parts.push('\u{1F600}'.repeat(1 + Math.floor(rand() * 600)));
      const out = redactQuestion(parts.join(' '));
      if (out === null) continue;
      expect(Array.from(out).length).toBeLessThanOrEqual(QUESTION_LIMIT);
      expect(out).not.toMatch(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/);
      expect(out).not.toContain('@');
      expect(out).not.toMatch(/[0-9]{9,}/);
      for (const tok of planted) expect(out).not.toContain(tok);
    }
  });
});
