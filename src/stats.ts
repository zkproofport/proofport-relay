import { createHash, timingSafeEqual } from 'crypto';
import type Redis from 'ioredis';
import { scrubError } from './mask';

/**
 * Per-circuit request statistics, one Redis hash per UTC day.
 *
 * Only dApp -> relay requests are counted: every request that reaches this
 * relay came from a dApp. Proofs the app generates for itself never touch the
 * relay and so are never counted.
 *
 * Stored per day under `relay:stats:YYYY-MM-DD`, fields:
 *   <circuit>|requested
 *   <circuit>|completed
 *   <circuit>|error|<errorCode or "none">
 *   <circuit>|cancelled
 *   <circuit>|expired
 *
 * Nothing else is stored: no IP, wallet, requestId, scope or nullifier. A
 * timeout (`expired`) is its own field so it can be told apart, and is grouped
 * with `cancelled` when the two are read together (see `abandoned` below).
 *
 * The day is the UTC day on which the EVENT happened. A request made at 23:59
 * that times out at 00:03 counts `requested` on the first day and `expired` on
 * the second; summed over any range that contains both, they reconcile.
 */

export const STATS_KEY_PREFIX = 'relay:stats:';
/** Kept a little longer than the longest range the endpoint will answer. */
export const STATS_TTL_SECONDS = 400 * 24 * 60 * 60;
/** Inclusive number of days one stats query may span. */
export const STATS_MAX_RANGE_DAYS = 400;

export type TerminalOutcome = 'completed' | 'error' | 'cancelled' | 'expired';
export type StatsOutcome = 'requested' | TerminalOutcome;

export const ERROR_CODE_RE = /^E\d{4}$/;
const NO_ERROR_CODE = 'none';

/** The UTC calendar day of an instant, `YYYY-MM-DD`. */
export function utcDay(at: Date): string {
  return at.toISOString().slice(0, 10);
}

export function statsKey(day: string): string {
  return `${STATS_KEY_PREFIX}${day}`;
}

export function statsField(circuit: string, outcome: StatsOutcome, errorCode?: string): string {
  if (outcome !== 'error') return `${circuit}|${outcome}`;
  if (errorCode !== undefined && !ERROR_CODE_RE.test(errorCode)) {
    throw new Error(`errorCode '${errorCode}' does not match ${ERROR_CODE_RE}`);
  }
  return `${circuit}|error|${errorCode ?? NO_ERROR_CODE}`;
}

export interface StatsRecorder {
  /**
   * Counts one event. Fire-and-forget: it never throws and never returns a
   * promise the caller could wait on, so a Redis failure while counting can
   * neither fail nor delay the proof path. Failures are logged and dropped.
   */
  record(circuit: string, outcome: StatsOutcome, errorCode?: string, at?: Date): void;
}

export function createStatsRecorder(redis: Redis, log: (line: string) => void = console.error): StatsRecorder {
  return {
    record(circuit, outcome, errorCode, at = new Date()) {
      let field: string;
      try {
        field = statsField(circuit, outcome, errorCode);
      } catch (err) {
        log(`[Relay Stats] Not counted: ${scrubError(err)}`);
        return;
      }
      const key = statsKey(utcDay(at));
      try {
        redis
          .multi()
          .hincrby(key, field, 1)
          .expire(key, STATS_TTL_SECONDS)
          .exec()
          .then((replies) => {
            const failed = replies?.find(([e]) => e);
            if (failed) log(`[Relay Stats] Count failed for field=${field}: ${scrubError(failed[0])}`);
          })
          .catch((err) => log(`[Relay Stats] Count failed for field=${field}: ${scrubError(err)}`));
      } catch (err) {
        log(`[Relay Stats] Count failed for field=${field}: ${scrubError(err)}`);
      }
    },
  };
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

export interface CircuitCounts {
  requested: number;
  completed: number;
  error: { total: number; byCode: Record<string, number> };
  cancelled: number;
  expired: number;
  /** cancelled + expired: the request ended without an answer from the user. */
  abandoned: number;
}

export interface DayStats {
  date: string;
  circuits: Record<string, CircuitCounts>;
}

export interface StatsReport {
  from: string;
  to: string;
  days: DayStats[];
  totals: { circuits: Record<string, CircuitCounts>; all: CircuitCounts };
  /** Hash fields this reader does not understand, so nothing is silently dropped. */
  unrecognized: Record<string, number>;
}

function emptyCounts(): CircuitCounts {
  return { requested: 0, completed: 0, error: { total: 0, byCode: {} }, cancelled: 0, expired: 0, abandoned: 0 };
}

function addInto(target: CircuitCounts, source: CircuitCounts): void {
  target.requested += source.requested;
  target.completed += source.completed;
  target.cancelled += source.cancelled;
  target.expired += source.expired;
  target.abandoned += source.abandoned;
  target.error.total += source.error.total;
  for (const [code, n] of Object.entries(source.error.byCode)) {
    target.error.byCode[code] = (target.error.byCode[code] ?? 0) + n;
  }
}

/** Applies one hash field to the counts. False when the field is not one this module writes. */
function applyField(circuits: Record<string, CircuitCounts>, field: string, n: number): boolean {
  const parts = field.split('|');
  const [circuit, outcome, code] = parts;
  if (!circuit) return false;
  const counts = (circuits[circuit] ??= emptyCounts());
  if (parts.length === 3 && outcome === 'error' && (code === NO_ERROR_CODE || ERROR_CODE_RE.test(code))) {
    counts.error.total += n;
    counts.error.byCode[code] = (counts.error.byCode[code] ?? 0) + n;
    return true;
  }
  if (parts.length !== 2) return false;
  switch (outcome) {
    case 'requested': counts.requested += n; return true;
    case 'completed': counts.completed += n; return true;
    case 'cancelled': counts.cancelled += n; counts.abandoned += n; return true;
    case 'expired': counts.expired += n; counts.abandoned += n; return true;
    default: return false;
  }
}

export type RangeCheck = { ok: true; days: string[] } | { ok: false; error: string };

const DATE_RE = /^(\d{4})-(\d{2})-(\d{2})$/;

function parseDay(value: unknown, name: string): { ok: true; ms: number } | { ok: false; error: string } {
  if (typeof value !== 'string' || value.length === 0) {
    return { ok: false, error: `${name} is required, as YYYY-MM-DD (UTC)` };
  }
  const m = DATE_RE.exec(value);
  if (!m) return { ok: false, error: `${name} must be YYYY-MM-DD (UTC)` };
  const ms = Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
  // Date.UTC rolls 2026-02-30 over to March; a real calendar date round-trips.
  if (Number.isNaN(ms) || utcDay(new Date(ms)) !== value) {
    return { ok: false, error: `${name} '${value}' is not a calendar date` };
  }
  return { ok: true, ms };
}

/** Validates a `from`..`to` query and lists the days in it, inclusive. */
export function checkRange(from: unknown, to: unknown): RangeCheck {
  const f = parseDay(from, 'from');
  if (!f.ok) return f;
  const t = parseDay(to, 'to');
  if (!t.ok) return t;
  if (f.ms > t.ms) return { ok: false, error: 'from must not be after to' };
  const span = Math.round((t.ms - f.ms) / 86_400_000) + 1;
  if (span > STATS_MAX_RANGE_DAYS) {
    return { ok: false, error: `range is ${span} days; at most ${STATS_MAX_RANGE_DAYS} days per query` };
  }
  const days: string[] = [];
  for (let i = 0; i < span; i++) days.push(utcDay(new Date(f.ms + i * 86_400_000)));
  return { ok: true, days };
}

export async function readStats(redis: Redis, days: string[]): Promise<StatsReport> {
  const pipeline = redis.pipeline();
  for (const day of days) pipeline.hgetall(statsKey(day));
  const replies = (await pipeline.exec()) ?? [];

  const report: StatsReport = {
    from: days[0],
    to: days[days.length - 1],
    days: [],
    totals: { circuits: {}, all: emptyCounts() },
    unrecognized: {},
  };

  days.forEach((date, i) => {
    const [err, hash] = replies[i] ?? [new Error('no reply'), null];
    if (err) throw err;
    const circuits: Record<string, CircuitCounts> = {};
    for (const [field, raw] of Object.entries((hash ?? {}) as Record<string, string>)) {
      const n = Number(raw);
      if (!Number.isFinite(n) || !applyField(circuits, field, n)) {
        report.unrecognized[`${date}:${field}`] = Number.isFinite(n) ? n : 0;
      }
    }
    for (const [circuit, counts] of Object.entries(circuits)) {
      addInto((report.totals.circuits[circuit] ??= emptyCounts()), counts);
      addInto(report.totals.all, counts);
    }
    report.days.push({ date, circuits });
  });

  return report;
}

/**
 * Constant-time bearer check. Both sides are hashed first so the comparison
 * takes the same time whatever the length of the presented token.
 */
export function bearerMatches(header: string | undefined, token: string): boolean {
  if (typeof header !== 'string') return false;
  const m = /^Bearer (.+)$/.exec(header);
  if (!m) return false;
  const presented = createHash('sha256').update(m[1]).digest();
  const expected = createHash('sha256').update(token).digest();
  return timingSafeEqual(presented, expected);
}
