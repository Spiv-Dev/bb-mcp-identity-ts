/**
 * Usage ledger: one JSON line per MCP tool call, for the fleet usage feed.
 *
 *   import { UsageLedger } from 'bb-mcp-identity';
 *
 *   const usage = UsageLedger.fromEnv('SF', { server: 'salesforce', version });
 *   usage.writeCatalog(tools.map((t) => ({ name: t.name, kind: t.isWrite ? 'write' : 'read' })));
 *   usage.record({ tool, outcome: 'ok', duration_ms: 12, user: 'mitchell', user_kind: 'user' });
 *
 * Each server appends events to `<dir>/usage-YYYY-MM-DD.jsonl` (UTC day, mode 0600). A shipper
 * on the VM reads the files and loads them into the fleet usage store; nothing here talks to
 * the network. `<PREFIX>_USAGE_DIR` unset means the ledger does nothing.
 *
 * What an event holds is fixed by `spec/usage_event_v1.json` (shared byte for byte with
 * bb-mcp-identity-py): call metadata and, optionally, the person's question after
 * `redactQuestion`. Argument values and results are never accepted. `record` never throws.
 *
 * This module imports nothing from the auth code.
 */
import { randomUUID } from 'node:crypto';
import { closeSync, mkdirSync, openSync, readdirSync, renameSync, unlinkSync, writeSync } from 'node:fs';
import { join } from 'node:path';

export const USAGE_SCHEMA_VERSION = 1;
export const USAGE_RETENTION_DAYS = 14;
export const QUESTION_LIMIT = 500;

export const KINDS = ['read', 'write', 'admin'] as const;
export const USER_KINDS = ['user', 'service', 'break_glass', 'legacy', 'system', 'unknown'] as const;
export const OUTCOMES = ['ok', 'error', 'denied'] as const;
export const WRITE_MODES = ['preview', 'apply', 'n/a'] as const;

export type UsageKind = (typeof KINDS)[number];
export type UsageUserKind = (typeof USER_KINDS)[number];
export type UsageOutcome = (typeof OUTCOMES)[number];
export type UsageWriteMode = (typeof WRITE_MODES)[number];

export const FIELD_ORDER = [
  'v',
  'id',
  'ts',
  'server',
  'server_version',
  'tool',
  'kind',
  'user',
  'user_kind',
  'tier',
  'client',
  'outcome',
  'error_code',
  'duration_ms',
  'response_bytes',
  'arg_keys',
  'write_mode',
  'via_tool',
  'correlation_id',
  'parent_correlation_id',
  'question',
] as const;

export interface UsageEvent {
  v: number;
  id: string;
  ts: string;
  server: string;
  server_version: string;
  tool: string;
  kind: UsageKind;
  user: string | null;
  user_kind: UsageUserKind;
  tier: string | null;
  client: string | null;
  outcome: UsageOutcome;
  error_code: string | null;
  duration_ms: number;
  response_bytes: number | null;
  arg_keys: string[];
  write_mode: UsageWriteMode;
  via_tool: string | null;
  correlation_id: string | null;
  parent_correlation_id: string | null;
  question: string | null;
}

/** What a server passes to `record`. Loosely typed on purpose: bad values are dropped, not thrown. */
export interface UsageFields {
  tool: unknown;
  outcome: unknown;
  duration_ms?: unknown;
  kind?: unknown;
  user?: unknown;
  user_kind?: unknown;
  tier?: unknown;
  client?: unknown;
  error_code?: unknown;
  response_bytes?: unknown;
  /** Argument names (or the arguments object: only its keys are kept). */
  arg_keys?: unknown;
  write_mode?: unknown;
  via_tool?: unknown;
  correlation_id?: unknown;
  parent_correlation_id?: unknown;
  question?: unknown;
  ts?: Date;
}

export interface UsageStats {
  enabled: boolean;
  dir: string | null;
  written: number;
  dropped_fields: number;
  write_errors: number;
  last_error: string | null;
}

export interface CatalogTool {
  name: unknown;
  kind?: unknown;
  domain?: unknown;
}

const MAX: Record<string, number> = {
  server: 64,
  server_version: 64,
  tool: 128,
  user: 64,
  tier: 32,
  client: 200,
  error_code: 64,
  via_tool: 128,
  correlation_id: 128,
  parent_correlation_id: 128,
};
const MAX_ARG_KEYS = 64;

// Argument names are identifiers; a key with 5+ digits is more likely a value than a name.
const ARG_RE = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;
const NAME_STRIP_RE = /[^A-Za-z0-9_.:-]/g;
const CODE_RE = /^[A-Za-z0-9_.:-]{1,64}$/;
const ID_RE = /^[A-Za-z0-9_.:-]{1,128}$/;
const TIER_RE = /^[a-z0-9_-]{1,32}$/;
const VERSION_STRIP_RE = /[^A-Za-z0-9_.+-]/g;
/** The largest integer JavaScript keeps exactly. */
export const MAX_COUNT = Number.MAX_SAFE_INTEGER;
/** The store's integer column. */
export const MAX_DURATION_MS = 2 ** 31 - 1;
const SLUG_STRIP_RE = /[^a-z0-9._-]/g;
const LONE_SURROGATE_RE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g;
const FILE_RE = /^usage-(\d{4}-\d{2}-\d{2})\.jsonl$/;

// --- redaction -------------------------------------------------------------------------------
//
// The same steps and patterns, in the same order, as bb-mcp-identity-py (bb_mcp_identity/usage.py);
// both are held to spec/redaction_fixtures_v1.json. Classes are spelt out ([0-9], [ \t]) so the two
// engines match exactly the same text, and every pattern starts only at a token boundary so a long
// input cannot make it quadratic.
//
// Steps: drop invisible characters, turn every kind of space into ' ', cut the input to PRE_LIMIT
// characters at a space (so no token is split), redact, then cut to the limit.

export const PRE_LIMIT = 1200;

const WS = '[ \\t\\r\\n\\f\\v\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]';
const WS_RE = new RegExp(`${WS}+`, 'g');
const INVISIBLE_RE = /[\u00ad\u200b-\u200d\u2060\ufeff]/g;
const SP = '[ \\t]';
const NUM = `[0-9](?:[0-9]|[,.][0-9]|${SP}(?=[0-9]))*`;
const SCALE = '(?:k|mn|mm|m|bn|million|billion|thousand|mil|miljoen)';
const BARE_SCALE = '(?:k|mn|mm|bn|million|billion|miljoen)';
const CUR = '(?:ZAR|USD|EUR|GBP|rand|dollars?|euros?)';
const NOT_IN_NUMBER = '(?<![0-9A-Za-z,.])';
const EMAIL_CH = '[^ @<>()\\[\\],;:"]';

const REDACTIONS: ReadonlyArray<readonly [RegExp, string]> = [
  [/\b[A-Za-z][A-Za-z0-9+.-]{1,15}:\/\/[^ ]+|\bwww\.[^ ]+/gi, '[url]'],
  [new RegExp(`(?<![^ <>()\\[\\],;:"'])${EMAIL_CH}+@${EMAIL_CH}+\\.[^ @<>()\\[\\],;:".]{2,}`, 'g'), '[email]'],
  [/(?<![^ (<["'])[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\.[A-Za-z]{2,}\/[^ ]*/g, '[url]'],
  // Long opaque tokens (API keys, session tokens): 24+ letters/digits/-/_ with both a digit and a letter.
  [/(?<![A-Za-z0-9_-])(?=[A-Za-z0-9_-]*[0-9])(?=[A-Za-z0-9_-]*[A-Za-z])[A-Za-z0-9_-]{24,}(?![A-Za-z0-9_-])/g, '[secret]'],
  // Amounts: a currency marker before or after the figure, a scaled figure, or grouped thousands.
  [new RegExp(`(?:\\b(?:R|ZAR|USD|EUR|GBP)|[$\\u20ac\\u00a3])${SP}?${NUM}(?:${SP}?${SCALE})?(?![0-9A-Za-z])`, 'gi'), '[amount]'],
  [new RegExp(`${NOT_IN_NUMBER}${NUM}${SP}?(?:${SCALE}${SP}?)?${CUR}\\b`, 'gi'), '[amount]'],
  [new RegExp(`${NOT_IN_NUMBER}[0-9]+(?:[.,][0-9]+)?${SP}?${BARE_SCALE}\\b`, 'gi'), '[amount]'],
  [new RegExp(`${NOT_IN_NUMBER}[0-9]{1,3}(?:,[0-9]{3})+(?:\\.[0-9]+)?(?![0-9])`, 'g'), '[amount]'],
];

// Phones, ID and account numbers, cards: a run of 9+ digits with up to three separators
// (space . - ( )) between them. Dates and a list of years do not count.
const DIGIT_RUN_RE = /(?<![0-9A-Za-z])\+?\(?[0-9](?:[ .()-]{0,3}[0-9]){8,}/g;
const ISO_DATE_RE = /(?:19|20)[0-9]{2}-[0-9]{2}-[0-9]{2}/g;
const YEAR_RE = /^(?:19|20)[0-9]{2}$/;
// Letter-prefixed document numbers (passports, permits): 1-2 letters then 6-9 digits.
const DOCNUM_RE = /\b[A-Za-z]{1,2}[0-9]{6,9}\b/g;
// Salesforce Ids: 15 or 18 letters/digits with at least three digits and a letter.
const SFID_RE = /\b[A-Za-z0-9]{15}(?:[A-Za-z0-9]{3})?\b/g;

function digitCount(s: string): number {
  return (s.match(/[0-9]/g) ?? []).length;
}

function digitRun(tok: string): string {
  const groups = tok.split(/[^0-9]+/).filter(Boolean);
  if (groups.length > 0 && groups.every((g) => YEAR_RE.test(g))) return tok; // a list of years
  if (digitCount(tok.replace(ISO_DATE_RE, '')) < 9) return tok; // dates and a time, not a number
  return '+0('.includes(tok.charAt(0)) ? '[phone]' : '[number]';
}

function clean(s: string): string {
  return s.replace(LONE_SURROGATE_RE, '\ufffd').replace(CONTROL_RE, '');
}

/** Collapse every kind of space to one ' ' and trim (the same in Python and JavaScript). */
function trimWs(s: string): string {
  return s.replace(INVISIBLE_RE, '').replace(WS_RE, ' ').replace(/^ +| +$/g, '');
}

function cutPoints(s: string, n: number): string {
  const points = Array.from(s);
  return points.length > n ? points.slice(0, n).join('') : s;
}

/**
 * Strip contact details, numbers, Ids, links, tokens and amounts from a question, then cut it to
 * `limit` characters (code points). Names are NOT removed; the store keeps questions separately
 * and for 90 days for that reason. Returns null for a blank or non-string question.
 */
export function redactQuestion(text: unknown, limit: number = QUESTION_LIMIT): string | null {
  if (typeof text !== 'string') return null;
  let s = trimWs(clean(text));
  if (Array.from(s).length > PRE_LIMIT) {
    const cut = cutPoints(s, PRE_LIMIT);
    const space = cut.lastIndexOf(' ');
    s = space > 0 && Array.from(cut.slice(0, space)).length > PRE_LIMIT / 2 ? cut.slice(0, space) : cut;
  }
  for (const [pattern, placeholder] of REDACTIONS) s = s.replace(pattern, placeholder);
  s = s.replace(DIGIT_RUN_RE, digitRun);
  s = s.replace(DOCNUM_RE, '[id]');
  s = s.replace(SFID_RE, (tok) => (digitCount(tok) >= 3 && /[A-Za-z]/.test(tok) ? '[id]' : tok));
  s = trimWs(s);
  if (!s) return null;
  return Array.from(s).length > limit ? cutPoints(s, limit).replace(/ +$/, '') : s;
}

/** The fleet's person key: the lowercase local part of a username or email. */
export function userSlug(username: unknown): string | null {
  if (typeof username !== 'string') return null;
  const local = username.trim().toLowerCase().split('@', 1)[0] ?? '';
  const slug = local.replace(SLUG_STRIP_RE, '').slice(0, MAX['user']);
  return slug || null;
}

/** A tool / server / domain name: only [A-Za-z0-9_.:-] survive, so no free text gets in. */
function name(value: unknown, field: string): string | null {
  if (typeof value !== 'string') return null;
  return value.replace(NAME_STRIP_RE, '').slice(0, MAX[field]) || null;
}

function utcDay(ts: string): string {
  return ts.slice(0, 10);
}

function errName(err: unknown): string {
  return err instanceof Error ? err.name : 'Error';
}

export interface UsageLedgerOptions {
  server: string;
  version?: string;
  retentionDays?: number;
}

/** Append-only JSONL writer. `record` never throws. */
export class UsageLedger {
  readonly dir: string | null;
  readonly server: string;
  readonly version: string;
  readonly retentionDays: number;
  written = 0;
  droppedFields = 0;
  writeErrors = 0;
  lastError: string | null = null;
  private prunedDay: string | null = null;

  constructor(dir: string | null | undefined, opts: UsageLedgerOptions) {
    this.dir = dir ? dir : null;
    this.server = name(opts.server, 'server') ?? 'unknown';
    this.version = (typeof opts.version === 'string' ? opts.version.replace(VERSION_STRIP_RE, '') : '').slice(0, MAX['server_version']);
    this.retentionDays = Math.max(1, Math.floor(opts.retentionDays ?? USAGE_RETENTION_DAYS));
  }

  static fromEnv(prefix: string, opts: UsageLedgerOptions, env: NodeJS.ProcessEnv = process.env): UsageLedger {
    return new UsageLedger(env[`${prefix}_USAGE_DIR`] || null, opts);
  }

  get enabled(): boolean {
    return this.dir !== null;
  }

  stats(): UsageStats {
    return {
      enabled: this.enabled,
      dir: this.dir,
      written: this.written,
      dropped_fields: this.droppedFields,
      write_errors: this.writeErrors,
      last_error: this.lastError,
    };
  }

  /** The event `record` would write (validated, unknown fields dropped). Never throws. */
  buildEvent(fields: UsageFields): UsageEvent {
    const known = new Set<string>([...FIELD_ORDER, 'ts']);
    for (const k of Object.keys(fields)) if (!known.has(k)) this.droppedFields += 1;
    const ts = fields.ts instanceof Date && !Number.isNaN(fields.ts.getTime()) ? fields.ts : new Date();
    const ev: UsageEvent = {
      v: USAGE_SCHEMA_VERSION,
      id: randomUUID().replace(/-/g, ''),
      ts: ts.toISOString(),
      server: this.server,
      server_version: this.version,
      tool: name(fields.tool, 'tool') ?? 'unknown',
      kind: this.oneOf(fields.kind ?? 'read', KINDS, 'read'),
      user: userSlug(fields.user),
      user_kind: this.oneOf(fields.user_kind ?? 'unknown', USER_KINDS, 'unknown'),
      tier: typeof fields.tier === 'string' && TIER_RE.test(fields.tier.toLowerCase()) ? fields.tier.toLowerCase() : null,
      client: redactQuestion(fields.client, MAX['client']),
      outcome: this.oneOf(fields.outcome, OUTCOMES, 'error'),
      error_code: this.code(fields.error_code),
      duration_ms: Math.min(this.count(fields.duration_ms, 0) ?? 0, MAX_DURATION_MS),
      response_bytes: this.count(fields.response_bytes, null),
      arg_keys: this.argKeys(fields.arg_keys),
      write_mode: this.oneOf(fields.write_mode ?? 'n/a', WRITE_MODES, 'n/a'),
      via_tool: name(fields.via_tool, 'via_tool'),
      correlation_id: this.id(fields.correlation_id),
      parent_correlation_id: this.id(fields.parent_correlation_id),
      question: redactQuestion(fields.question),
    };
    return ev;
  }

  /** Append one event. Returns true if it was written; never throws. */
  record(fields: UsageFields): boolean {
    if (this.dir === null) return false;
    try {
      const ev = this.buildEvent(fields);
      const ordered: Record<string, unknown> = {};
      for (const k of FIELD_ORDER) ordered[k] = ev[k];
      const line = Buffer.from(`${JSON.stringify(ordered)}\n`, 'utf8');
      const day = utcDay(ev.ts);
      mkdirSync(this.dir, { recursive: true, mode: 0o700 });
      const fd = openSync(join(this.dir, `usage-${day}.jsonl`), 'a', 0o600);
      try {
        writeSync(fd, line); // one write per line: a reader never sees half of one
      } finally {
        closeSync(fd);
      }
      this.written += 1;
      if (this.prunedDay !== day) {
        this.prunedDay = day;
        this.prune(day);
      }
      return true;
    } catch (err) {
      this.writeErrors += 1;
      this.lastError = errName(err);
      return false;
    }
  }

  /** Write `tools.json` (the server's registered tools) atomically. Never throws. */
  writeCatalog(tools: Iterable<CatalogTool>): boolean {
    if (this.dir === null) return false;
    try {
      const rows: Array<{ name: string; kind: UsageKind; domain: string | null }> = [];
      for (const t of tools) {
        const toolName = name(t.name, 'tool');
        if (!toolName) continue;
        rows.push({ name: toolName, kind: this.oneOf(t.kind ?? 'read', KINDS, 'read'), domain: name(t.domain, 'tool') });
      }
      rows.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
      const doc = {
        v: USAGE_SCHEMA_VERSION,
        server: this.server,
        server_version: this.version,
        generated_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
        tools: rows,
      };
      mkdirSync(this.dir, { recursive: true, mode: 0o700 });
      const tmp = join(this.dir, `.tools.json.${process.pid}.tmp`);
      const fd = openSync(tmp, 'w', 0o600);
      try {
        writeSync(fd, Buffer.from(JSON.stringify(doc, null, 1), 'utf8'));
      } finally {
        closeSync(fd);
      }
      renameSync(tmp, join(this.dir, 'tools.json'));
      return true;
    } catch (err) {
      this.writeErrors += 1;
      this.lastError = errName(err);
      return false;
    }
  }

  private prune(today: string): void {
    if (this.dir === null) return;
    try {
      const cutoff = new Date(Date.parse(`${today}T00:00:00Z`) - this.retentionDays * 86_400_000).toISOString().slice(0, 10);
      for (const name of readdirSync(this.dir)) {
        const m = FILE_RE.exec(name);
        if (m?.[1] !== undefined && m[1] < cutoff) {
          try {
            unlinkSync(join(this.dir, name));
          } catch {
            /* already gone */
          }
        }
      }
    } catch (err) {
      this.lastError = errName(err);
    }
  }

  private oneOf<T extends string>(value: unknown, allowed: readonly T[], fallback: T): T {
    if (typeof value === 'string' && (allowed as readonly string[]).includes(value)) return value as T;
    if (value !== null && value !== undefined) this.droppedFields += 1;
    return fallback;
  }

  private count(value: unknown, fallback: number | null): number | null {
    if (value === null || value === undefined || typeof value === 'boolean') return fallback;
    if (typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= MAX_COUNT) return Math.round(value);
    if (typeof value === 'bigint' && value >= 0n && value <= BigInt(MAX_COUNT)) return Number(value);
    this.droppedFields += 1;
    return fallback;
  }

  private code(value: unknown): string | null {
    if (value === null || value === undefined) return null;
    if (typeof value === 'string') {
      const v = value.slice(0, MAX['error_code']);
      if (CODE_RE.test(v)) return v;
    }
    this.droppedFields += 1;
    return 'unclassified'; // free text (a message) never goes in as a code
  }

  private id(value: unknown): string | null {
    if (value === null || value === undefined) return null;
    if (typeof value === 'string' && ID_RE.test(value)) return value;
    this.droppedFields += 1;
    return null;
  }

  private argKeys(value: unknown): string[] {
    if (value === null || value === undefined) return [];
    let names: unknown[];
    if (Array.isArray(value)) names = value;
    else if (value instanceof Set) names = [...(value as Set<unknown>)];
    else if (value instanceof Map) names = [...(value as Map<unknown, unknown>).keys()];
    else if (typeof value === 'object' && [Object.prototype, null].includes(Object.getPrototypeOf(value))) {
      names = Object.keys(value as object); // an args object: keep the names only
    } else {
      this.droppedFields += 1;
      return [];
    }
    const keys = new Set<string>();
    for (const k of names) {
      if (typeof k === 'string' && ARG_RE.test(k) && digitCount(k) < 5) keys.add(k);
    }
    return [...keys].sort().slice(0, MAX_ARG_KEYS);
  }
}
