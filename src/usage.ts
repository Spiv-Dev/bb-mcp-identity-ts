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
const MAX_ARG_KEY_LEN = 64;

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.:-]*$/;
const SLUG_STRIP_RE = /[^a-z0-9._-]/g;
const LONE_SURROGATE_RE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g;
const FILE_RE = /^usage-(\d{4}-\d{2}-\d{2})\.jsonl$/;

// --- redaction -------------------------------------------------------------------------------
//
// The same patterns, in the same order, as bb-mcp-identity-py (bb_mcp_identity/usage.py); both
// are held to spec/redaction_fixtures_v1.json. Classes are spelt out ([0-9], [ \t]) so the two
// engines match exactly the same text.

const WS = '[ \\t\\r\\n\\f\\v\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff]';
const SP = '[ \\t\\u00a0]';
const NUM = `[0-9](?:[0-9,.]|${SP}(?=[0-9]))*`;
const SCALE = '(?:k|m|bn|million|thousand|mil)';

const REDACTIONS: ReadonlyArray<readonly [RegExp, string]> = [
  [/\b(?:https?:\/\/|www\.)[^ \t\r\n]+/gi, '[url]'],
  [/[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g, '[email]'],
  [/(?:\+27|\b0)[ -]?\(?[0-9]{2}\)?[ -]?[0-9]{3}[ -]?[0-9]{4}\b/g, '[phone]'],
  [/\+[0-9]{1,3}(?:[ -]?[0-9]){7,12}\b/g, '[phone]'],
  [/\b[0-9](?:[ -]?[0-9]){12,18}\b/g, '[number]'],
  [/\b[0-9]{9,}\b/g, '[number]'],
  [new RegExp(`(?:\\b(?:R|ZAR|USD|EUR|GBP)${SP}?|[$\\u20ac\\u00a3]${SP}?)${NUM}(?:${SP}?${SCALE}\\b)?`, 'gi'), '[amount]'],
  [new RegExp(`\\b${NUM}${SP}?(?:ZAR|USD|EUR|GBP|rand)\\b`, 'gi'), '[amount]'],
  [new RegExp(`\\b[0-9]+(?:[.,][0-9]+)?${SP}?(?:k|m|bn)\\b`, 'gi'), '[amount]'],
];

const SFID_RE = /\b[A-Za-z0-9]{15}(?:[A-Za-z0-9]{3})?\b/g;
const WS_RE = new RegExp(`${WS}+`, 'g');

function clean(s: string): string {
  return s.replace(LONE_SURROGATE_RE, '�').replace(CONTROL_RE, '');
}

/**
 * Strip contact details, numbers, Ids and amounts from a question, then cut it to `limit`
 * characters (code points). Redaction runs first, so a cut never leaves half an address. Names
 * are NOT removed; the store keeps questions separately and for 90 days for that reason.
 */
export function redactQuestion(text: unknown, limit: number = QUESTION_LIMIT): string | null {
  if (typeof text !== 'string') return null;
  let s = clean(text);
  for (const [pattern, placeholder] of REDACTIONS) s = s.replace(pattern, placeholder);
  s = s.replace(SFID_RE, (tok) => (/[0-9]/.test(tok) && /[A-Za-z]/.test(tok) ? '[id]' : tok));
  s = s.replace(WS_RE, ' ').replace(/^ +| +$/g, '');
  if (!s) return null;
  const points = Array.from(s);
  return points.length > limit ? points.slice(0, limit).join('').replace(/ +$/, '') : s;
}

/** The fleet's person key: the lowercase local part of a username or email. */
export function userSlug(username: unknown): string | null {
  if (typeof username !== 'string') return null;
  const local = username.trim().toLowerCase().split('@', 1)[0] ?? '';
  const slug = local.replace(SLUG_STRIP_RE, '').slice(0, MAX['user']);
  return slug || null;
}

function short(value: unknown, field: string): string | null {
  if (typeof value !== 'string') return null;
  const s = clean(value).trim();
  return Array.from(s).slice(0, MAX[field]).join('') || null;
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
    this.server = short(opts.server, 'server') ?? 'unknown';
    this.version = short(opts.version ?? '', 'server_version') ?? '';
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
      tool: short(fields.tool, 'tool') ?? 'unknown',
      kind: this.oneOf(fields.kind ?? 'read', KINDS, 'read'),
      user: userSlug(fields.user),
      user_kind: this.oneOf(fields.user_kind ?? 'unknown', USER_KINDS, 'unknown'),
      tier: short(fields.tier, 'tier'),
      client: short(fields.client, 'client'),
      outcome: this.oneOf(fields.outcome, OUTCOMES, 'error'),
      error_code: short(fields.error_code, 'error_code'),
      duration_ms: this.count(fields.duration_ms, 0) ?? 0,
      response_bytes: this.count(fields.response_bytes, null),
      arg_keys: this.argKeys(fields.arg_keys),
      write_mode: this.oneOf(fields.write_mode ?? 'n/a', WRITE_MODES, 'n/a'),
      via_tool: short(fields.via_tool, 'via_tool'),
      correlation_id: short(fields.correlation_id, 'correlation_id'),
      parent_correlation_id: short(fields.parent_correlation_id, 'parent_correlation_id'),
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
        const name = short(t.name, 'tool');
        if (!name) continue;
        rows.push({ name, kind: this.oneOf(t.kind ?? 'read', KINDS, 'read'), domain: short(t.domain, 'tool') });
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
    if (typeof value === 'number' && Number.isFinite(value) && value >= 0) return Math.round(value);
    this.droppedFields += 1;
    return fallback;
  }

  private argKeys(value: unknown): string[] {
    if (value === null || value === undefined) return [];
    let names: unknown[];
    if (Array.isArray(value)) names = value;
    else if (value instanceof Set) names = [...(value as Set<unknown>)];
    else if (typeof value === 'object') names = Object.keys(value as object); // an args object: keep the names only
    else {
      this.droppedFields += 1;
      return [];
    }
    const keys = new Set<string>();
    for (const k of names) {
      if (typeof k === 'string' && k && !k.startsWith('_') && k.length <= MAX_ARG_KEY_LEN && NAME_RE.test(k)) keys.add(k);
    }
    return [...keys].sort().slice(0, MAX_ARG_KEYS);
  }
}
