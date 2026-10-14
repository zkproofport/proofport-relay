import { createHash } from 'crypto';
import type Redis from 'ioredis';

/**
 * Lockout for wrong stats tokens, per caller address.
 *
 * The stats token is 32+ random characters, so guessing it is hopeless anyway;
 * this exists so the admin page cannot be used as a free oracle, and so a
 * stream of wrong tokens is visible as 429s rather than an endless run of 401s.
 *
 * Counted in Redis, not in memory: Cloud Run runs up to 20 relay instances and
 * a caller's tries land on any of them. An in-memory count would allow
 * 20 x STATS_AUTH_MAX_FAILURES per window.
 *
 * The key holds a SHA-256 of the address, never the address itself; the relay
 * does not store caller IPs it has no use for.
 *
 * Once locked out, every stats call from that address is refused until the
 * window ends -- including one with the right token -- so a guesser cannot
 * learn which of their tries was right by its status code.
 */
export const STATS_AUTH_MAX_FAILURES = 10;
export const STATS_AUTH_WINDOW_SECONDS = 15 * 60;
export const STATS_AUTH_KEY_PREFIX = 'relay:stats-auth-fail:';

export function statsAuthKey(ip: string): string {
  return `${STATS_AUTH_KEY_PREFIX}${createHash('sha256').update(ip).digest('hex')}`;
}

export interface StatsAuthGuard {
  /** Seconds until this address may try again; 0 when it is not locked out. */
  lockedFor(ip: string): Promise<number>;
  /** Counts one wrong token. Resolves to the failure count in the current window. */
  recordFailure(ip: string): Promise<number>;
}

export function createStatsAuthGuard(redis: Redis): StatsAuthGuard {
  return {
    async lockedFor(ip) {
      const key = statsAuthKey(ip);
      const [[e1, raw], [e2, pttl]] = (await redis.multi().get(key).pttl(key).exec()) ?? [[new Error('no reply'), null], [null, null]];
      if (e1) throw e1;
      if (e2) throw e2;
      const count = Number(raw ?? 0);
      if (count < STATS_AUTH_MAX_FAILURES) return 0;
      const ms = Number(pttl);
      // -1 (no expiry) cannot be written by recordFailure; treat it as a full window
      // rather than a permanent lock or no lock.
      return ms > 0 ? Math.ceil(ms / 1000) : STATS_AUTH_WINDOW_SECONDS;
    },
    async recordFailure(ip) {
      const key = statsAuthKey(ip);
      // SET NX starts the window on the first failure only; INCR keeps the TTL.
      const replies = await redis.multi().set(key, '0', 'EX', STATS_AUTH_WINDOW_SECONDS, 'NX').incr(key).exec();
      const failed = replies?.find(([e]) => e);
      if (!replies || failed) throw failed?.[0] ?? new Error('no reply');
      return Number(replies[1][1]);
    },
  };
}
