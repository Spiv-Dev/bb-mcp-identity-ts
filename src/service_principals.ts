/**
 * Service principals: the non-human callers that keep a static bearer.
 *
 * File format, one per line (mode 600, never committed):
 *
 *   svc-<name>:<tier>:<owner 18-char Salesforce id>:<expires YYYY-MM-DD>:<token>
 *
 * A service principal is honoured only while its owner is present and active
 * in the broker snapshot and its expiry date has not passed (the expiry day
 * itself, in UTC, is still valid). Names and tokens are unique per file.
 */
import { createHash, timingSafeEqual } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';

import type { SnapshotStore } from './snapshot.js';

export interface ServicePrincipal {
  name: string;
  tier: string;
  ownerSub: string;
  /** ISO date, YYYY-MM-DD (UTC). */
  expires: string;
  token: string;
}

const DATE_RE = /^(\d{4})-(\d{2})-(\d{2})$/;

/** True for a real calendar date (V8's Date.parse would accept 2099-02-31). */
export function isCalendarDate(s: string): boolean {
  const m = DATE_RE.exec(s);
  if (!m) return false;
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const dt = new Date(Date.UTC(y, mo - 1, d));
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === mo - 1 && dt.getUTCDate() === d;
}

function splitFields(line: string, count: number): string[] {
  // Like Python's str.split(':', count - 1): the last field keeps any further colons.
  const out: string[] = [];
  let rest = line;
  for (let i = 0; i < count - 1; i++) {
    const idx = rest.indexOf(':');
    if (idx < 0) break;
    out.push(rest.slice(0, idx));
    rest = rest.slice(idx + 1);
  }
  out.push(rest);
  return out;
}

export function parseLines(text: string): ServicePrincipal[] {
  const out: ServicePrincipal[] = [];
  const names = new Set<string>();
  const tokens = new Set<string>();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const parts = splitFields(line, 5).map((p) => p.trim());
    if (parts.length !== 5) throw new Error('service principal line must have 5 colon-separated fields');
    const [name, tier, owner, expires, token] = parts as [string, string, string, string, string];
    if (!name.startsWith('svc-') || !tier || owner.length !== 18 || token.length < 32) {
      throw new Error(`malformed service principal line for ${JSON.stringify(name)}`);
    }
    if (!isCalendarDate(expires)) throw new Error(`service principal ${JSON.stringify(name)} has an invalid expiry date`);
    if (names.has(name)) throw new Error(`duplicate service principal name ${JSON.stringify(name)}`);
    if (tokens.has(token)) throw new Error(`service principal ${JSON.stringify(name)} reuses another principal's token`);
    names.add(name);
    tokens.add(token);
    out.push({ name, tier, ownerSub: owner, expires, token });
  }
  return out;
}

function digest(s: string): Buffer {
  return createHash('sha256').update(s, 'utf8').digest();
}

export function todayUtc(now: Date = new Date()): string {
  return now.toISOString().slice(0, 10);
}

export class ServicePrincipals {
  private readonly principals: readonly ServicePrincipal[];

  constructor(principals: ServicePrincipal[]) {
    this.principals = principals;
  }

  /** Reads the file; a missing path yields no principals (the caller decides whether to warn). */
  static fromFile(path: string | null): ServicePrincipals {
    if (!path || !existsSync(path)) return new ServicePrincipals([]);
    return new ServicePrincipals(parseLines(readFileSync(path, 'utf8')));
  }

  get size(): number {
    return this.principals.length;
  }

  match(bearer: string): ServicePrincipal | null {
    const presented = digest(bearer);
    for (const p of this.principals) {
      if (timingSafeEqual(digest(p.token), presented)) return p;
    }
    return null;
  }

  static usable(p: ServicePrincipal, snapshot: SnapshotStore, today: string = todayUtc()): { ok: boolean; reason: string } {
    if (p.expires < today) return { ok: false, reason: 'expired' };
    if (!snapshot.isFresh()) return { ok: false, reason: 'snapshot_stale' };
    const owner = snapshot.entry(p.ownerSub);
    if (owner === null) return { ok: false, reason: 'owner_unknown' };
    if (!owner.active) return { ok: false, reason: `owner_${owner.status}` };
    return { ok: true, reason: 'ok' };
  }
}
