import { describe, it, expect, vi } from 'vitest';
import type Redis from 'ioredis';
import {
  bearerMatches,
  checkRange,
  createStatsRecorder,
  readStats,
  statsField,
  statsKey,
  STATS_MAX_RANGE_DAYS,
  STATS_TTL_SECONDS,
  utcDay,
} from '../stats';

describe('statsField', () => {
  it('builds per-outcome fields', () => {
    expect(statsField('coinbase_attestation', 'requested')).toBe('coinbase_attestation|requested');
    expect(statsField('coinbase_attestation', 'completed')).toBe('coinbase_attestation|completed');
    expect(statsField('coinbase_attestation', 'cancelled')).toBe('coinbase_attestation|cancelled');
    expect(statsField('coinbase_attestation', 'expired')).toBe('coinbase_attestation|expired');
  });
  it('buckets an error by code, and an absent code as none', () => {
    expect(statsField('mdl_kr_age', 'error', 'E2007')).toBe('mdl_kr_age|error|E2007');
    expect(statsField('mdl_kr_age', 'error')).toBe('mdl_kr_age|error|none');
  });
  it('refuses a malformed code rather than writing it as a field', () => {
    expect(() => statsField('mdl_kr_age', 'error', 'E20')).toThrow(/errorCode/);
    expect(() => statsField('mdl_kr_age', 'error', 'x|y')).toThrow(/errorCode/);
  });
});

describe('utcDay', () => {
  it('splits at UTC midnight, not local midnight', () => {
    expect(utcDay(new Date('2026-10-14T23:59:59.999Z'))).toBe('2026-10-14');
    expect(utcDay(new Date('2026-10-15T00:00:00.000Z'))).toBe('2026-10-15');
    // 08:59 in Seoul on the 15th is still the 14th in UTC.
    expect(utcDay(new Date('2026-10-15T08:59:00+09:00'))).toBe('2026-10-14');
  });
});

describe('checkRange', () => {
  it('lists the days inclusively', () => {
    expect(checkRange('2026-02-27', '2026-03-01')).toEqual({ ok: true, days: ['2026-02-27', '2026-02-28', '2026-03-01'] });
    expect(checkRange('2026-10-14', '2026-10-14')).toEqual({ ok: true, days: ['2026-10-14'] });
  });
  it('requires both dates, separately for missing and empty', () => {
    expect(checkRange(undefined, '2026-10-14')).toMatchObject({ ok: false, error: expect.stringMatching(/from is required/) });
    expect(checkRange('', '2026-10-14')).toMatchObject({ ok: false, error: expect.stringMatching(/from is required/) });
    expect(checkRange('2026-10-14', undefined)).toMatchObject({ ok: false, error: expect.stringMatching(/to is required/) });
  });
  it('refuses malformed and non-calendar dates', () => {
    for (const bad of ['2026-1-1', '20261014', '2026-10-14T00:00:00Z', "2026-10-14' OR 1=1", '%', '2026-13-01', '2026-02-30', ['2026-10-14']]) {
      expect(checkRange(bad, '2026-12-31').ok).toBe(false);
    }
  });
  it('refuses from after to', () => {
    expect(checkRange('2026-10-15', '2026-10-14')).toMatchObject({ ok: false, error: 'from must not be after to' });
  });
  it('accepts exactly the maximum span and refuses one more day', () => {
    const from = '2025-01-01';
    const lastOk = utcDay(new Date(Date.UTC(2025, 0, 1) + (STATS_MAX_RANGE_DAYS - 1) * 86_400_000));
    const tooFar = utcDay(new Date(Date.UTC(2025, 0, 1) + STATS_MAX_RANGE_DAYS * 86_400_000));
    const ok = checkRange(from, lastOk);
    expect(ok.ok && ok.days.length).toBe(STATS_MAX_RANGE_DAYS);
    expect(checkRange(from, tooFar)).toMatchObject({ ok: false, error: expect.stringMatching(/at most 400 days/) });
  });
});

describe('bearerMatches', () => {
  const token = 'a'.repeat(64);
  it('accepts the exact token', () => {
    expect(bearerMatches(`Bearer ${token}`, token)).toBe(true);
  });
  it('refuses a missing header, a different scheme, a wrong or longer token', () => {
    expect(bearerMatches(undefined, token)).toBe(false);
    expect(bearerMatches('', token)).toBe(false);
    expect(bearerMatches(`Basic ${token}`, token)).toBe(false);
    expect(bearerMatches(`Bearer ${'b'.repeat(64)}`, token)).toBe(false);
    expect(bearerMatches(`Bearer ${token}x`, token)).toBe(false);
    expect(bearerMatches('Bearer ', token)).toBe(false);
  });
});

/** A fake that records the MULTI it was given. */
function fakeRedis(exec: () => Promise<unknown>) {
  const calls: unknown[][] = [];
  const multi = {
    hincrby: (...a: unknown[]) => { calls.push(['hincrby', ...a]); return multi; },
    expire: (...a: unknown[]) => { calls.push(['expire', ...a]); return multi; },
    exec,
  };
  return { client: { multi: () => multi } as unknown as Redis, calls };
}

describe('createStatsRecorder', () => {
  it('increments the day hash and refreshes its TTL in one MULTI', async () => {
    const { client, calls } = fakeRedis(() => Promise.resolve([[null, 1], [null, 1]]));
    createStatsRecorder(client).record('coinbase_attestation', 'error', 'E2007', new Date('2026-10-14T23:59:59.999Z'));
    expect(calls).toEqual([
      ['hincrby', 'relay:stats:2026-10-14', 'coinbase_attestation|error|E2007', 1],
      ['expire', 'relay:stats:2026-10-14', STATS_TTL_SECONDS],
    ]);
  });

  it('lands an event one millisecond later on the next day', () => {
    const { client, calls } = fakeRedis(() => Promise.resolve([]));
    createStatsRecorder(client).record('coinbase_attestation', 'expired', undefined, new Date('2026-10-15T00:00:00.000Z'));
    expect(calls[0]).toEqual(['hincrby', statsKey('2026-10-15'), 'coinbase_attestation|expired', 1]);
  });

  it('returns synchronously and swallows a rejected write, logging it', async () => {
    const log = vi.fn();
    const { client } = fakeRedis(() => Promise.reject(new Error('connect ECONNREFUSED 10.1.2.3:6379')));
    const ret = createStatsRecorder(client, log).record('coinbase_attestation', 'completed');
    expect(ret).toBeUndefined();
    await new Promise((r) => setTimeout(r, 0));
    expect(log).toHaveBeenCalledTimes(1);
    expect(log.mock.calls[0][0]).toContain('Count failed');
    expect(log.mock.calls[0][0]).toContain('10.1.x.x');
    expect(log.mock.calls[0][0]).not.toContain('10.1.2.3');
  });

  it('does not wait on a write that never finishes', () => {
    const { client } = fakeRedis(() => new Promise(() => {}));
    const started = Date.now();
    createStatsRecorder(client).record('coinbase_attestation', 'completed');
    expect(Date.now() - started).toBeLessThan(50);
  });

  it('swallows a client that throws synchronously', () => {
    const log = vi.fn();
    const client = { multi: () => { throw new Error('Connection is closed.'); } } as unknown as Redis;
    expect(() => createStatsRecorder(client, log).record('coinbase_attestation', 'requested')).not.toThrow();
    expect(log).toHaveBeenCalledWith(expect.stringContaining('Connection is closed.'));
  });

  it('logs and skips a per-command error inside the MULTI reply', async () => {
    const log = vi.fn();
    const { client } = fakeRedis(() => Promise.resolve([[new Error('WRONGTYPE'), null], [null, 1]]));
    createStatsRecorder(client, log).record('coinbase_attestation', 'completed');
    await new Promise((r) => setTimeout(r, 0));
    expect(log).toHaveBeenCalledWith(expect.stringContaining('WRONGTYPE'));
  });

  it('does not write a malformed error code', () => {
    const log = vi.fn();
    const { client, calls } = fakeRedis(() => Promise.resolve([]));
    createStatsRecorder(client, log).record('coinbase_attestation', 'error', 'nope');
    expect(calls).toEqual([]);
    expect(log).toHaveBeenCalledWith(expect.stringContaining('Not counted'));
  });
});

describe('readStats', () => {
  function pipelineOf(hashes: Record<string, Record<string, string>>) {
    const keys: string[] = [];
    const pipeline = {
      hgetall: (k: string) => { keys.push(k); return pipeline; },
      exec: async () => keys.map((k) => [null, hashes[k] ?? {}]),
    };
    return { pipeline: () => pipeline } as unknown as Redis;
  }

  it('sums per day, per circuit and overall, grouping cancelled with expired as abandoned', async () => {
    const redis = pipelineOf({
      'relay:stats:2026-10-14': {
        'coinbase_attestation|requested': '3',
        'coinbase_attestation|completed': '1',
        'coinbase_attestation|error|E2007': '1',
        'coinbase_attestation|cancelled': '1',
      },
      'relay:stats:2026-10-15': {
        'coinbase_attestation|expired': '1',
        'mdl_kr_age|requested': '1',
        'mdl_kr_age|error|none': '1',
      },
    });
    const report = await readStats(redis, ['2026-10-14', '2026-10-15']);
    expect(report.from).toBe('2026-10-14');
    expect(report.to).toBe('2026-10-15');
    expect(report.days[0].circuits.coinbase_attestation).toMatchObject({ requested: 3, completed: 1, cancelled: 1, expired: 0, abandoned: 1, error: { total: 1, byCode: { E2007: 1 } } });
    expect(report.totals.circuits.coinbase_attestation).toMatchObject({ requested: 3, abandoned: 2, expired: 1 });
    expect(report.totals.all).toMatchObject({ requested: 4, completed: 1, cancelled: 1, expired: 1, abandoned: 2, error: { total: 2, byCode: { E2007: 1, none: 1 } } });
    expect(report.unrecognized).toEqual({});
  });

  it('reports fields it does not understand instead of dropping them', async () => {
    const redis = pipelineOf({ 'relay:stats:2026-10-14': { 'coinbase_attestation|weird': '2', 'x|error|bad': '1' } });
    const report = await readStats(redis, ['2026-10-14']);
    expect(report.unrecognized).toEqual({ '2026-10-14:coinbase_attestation|weird': 2, '2026-10-14:x|error|bad': 1 });
  });

  it('answers zeros for a day with no data', async () => {
    const report = await readStats(pipelineOf({}), ['2026-10-14']);
    expect(report.days).toEqual([{ date: '2026-10-14', circuits: {} }]);
    expect(report.totals.all.requested).toBe(0);
  });
});
