/**
 * Integration: real relay (`createRelay`) in this process, real Redis, real
 * HTTP and Socket.IO clients. Covers which address a caller is counted under
 * (trust proxy = one hop) and the stats API's wrong-token lockout, which lives
 * in Redis so that every instance sees the same count.
 *
 * Run with `scripts/test-relay.sh integration`. REDIS_TEST_URL must name a
 * non-zero database; this suite flushes it.
 */
import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import type { AddressInfo } from 'net';
import Redis from 'ioredis';
import { io as connectSocket, Socket as ClientSocket } from 'socket.io-client';
import { createRelay, Relay } from '../app';
import { createStatsRecorder } from '../stats';
import { STATS_AUTH_KEY_PREFIX, STATS_AUTH_MAX_FAILURES, STATS_AUTH_WINDOW_SECONDS, statsAuthKey } from '../statsAuth';

const REDIS_TEST_URL = process.env.REDIS_TEST_URL;
if (!REDIS_TEST_URL) {
  throw new Error('REDIS_TEST_URL is required (e.g. redis://localhost:6379/15). Run scripts/test-relay.sh integration.');
}
const db = Number(new URL(REDIS_TEST_URL).pathname.replace('/', '') || '0');
if (!(db > 0)) {
  throw new Error(`REDIS_TEST_URL must name a non-zero database; this suite flushes it. Got '${REDIS_TEST_URL}'.`);
}

const TOKEN = 's'.repeat(64);
const LONG = 3_600_000;
const DAY = '2026-10-14';

let redis: Redis;
const relays: Relay[] = [];
const sockets: ClientSocket[] = [];

beforeAll(async () => {
  redis = new Redis(REDIS_TEST_URL);
  await redis.flushdb();
});

afterEach(async () => {
  for (const s of sockets.splice(0)) s.disconnect();
  for (const r of relays.splice(0)) await r.close();
});

afterAll(async () => {
  await redis.quit();
});

async function start(): Promise<string> {
  const relay = createRelay({
    redis,
    stats: createStatsRecorder(redis),
    statsToken: TOKEN,
    adapter: null,
    corsOrigin: '*',
    relayExternalUrl: '',
    port: 0,
    deadlineMs: LONG,
    sweepIntervalMs: LONG,
  });
  await new Promise<void>((resolve) => relay.httpServer.listen(0, '127.0.0.1', resolve));
  relays.push(relay);
  return `http://127.0.0.1:${(relay.httpServer.address() as AddressInfo).port}`;
}

/** POST /api/v1/proof/request with an empty body: 401 when admitted, 429 when limited. */
async function hitRequest(url: string, xff?: string): Promise<number> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (xff !== undefined) headers['X-Forwarded-For'] = xff;
  const res = await fetch(`${url}/api/v1/proof/request`, { method: 'POST', headers, body: '{}' });
  return res.status;
}

async function statsCall(url: string, opts: { token?: string; xff?: string } = {}) {
  const headers: Record<string, string> = {};
  if (opts.token !== undefined) headers.Authorization = `Bearer ${opts.token}`;
  if (opts.xff !== undefined) headers['X-Forwarded-For'] = opts.xff;
  const res = await fetch(`${url}/api/v1/stats?from=${DAY}&to=${DAY}`, { headers });
  return { status: res.status, retryAfter: res.headers.get('retry-after'), body: await res.json() as Record<string, unknown> };
}

describe('rate-limit key: the rightmost X-Forwarded-For entry (one trusted hop)', () => {
  it('a spoofed leftmost entry does not change the bucket: 10 admitted, the 11th limited whatever the client writes', async () => {
    const url = await start();
    const statuses: number[] = [];
    for (let i = 0; i < 11; i++) statuses.push(await hitRequest(url, `10.${i}.0.1, 198.51.100.10`));
    expect(statuses.slice(0, 10)).toEqual(Array(10).fill(401));
    expect(statuses[10]).toBe(429);
  });

  it('two different rightmost entries get separate buckets', async () => {
    const url = await start();
    for (let i = 0; i < 10; i++) expect(await hitRequest(url, '198.51.100.20')).toBe(401);
    expect(await hitRequest(url, '198.51.100.20')).toBe(429);
    expect(await hitRequest(url, '198.51.100.21')).toBe(401);
    expect(await hitRequest(url, '9.9.9.9, 198.51.100.21')).toBe(401);
  });

  it('no header: the socket address is the bucket, untouched by callers who sent one', async () => {
    const url = await start();
    for (let i = 0; i < 11; i++) await hitRequest(url, '198.51.100.30');
    expect(await hitRequest(url)).toBe(401);
  });

  it('the 429 says when to come back', async () => {
    const url = await start();
    for (let i = 0; i < 10; i++) await hitRequest(url, '198.51.100.31');
    const res = await fetch(`${url}/api/v1/proof/request`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': '198.51.100.31' }, body: '{}' });
    expect(res.status).toBe(429);
    const ra = Number(res.headers.get('retry-after'));
    expect(ra).toBeGreaterThan(0);
    expect(ra).toBeLessThanOrEqual(60);
  });

  it('Socket.IO reads the same address: socket proof:request and HTTP share one bucket, keyed by the handshake X-Forwarded-For', async () => {
    const url = await start();
    const ip = '198.51.100.40';
    for (let i = 0; i < 6; i++) expect(await hitRequest(url, `7.7.7.7, ${ip}`)).toBe(401);

    const socket = connectSocket(`${url}/proof`, {
      path: '/socket.io',
      transports: ['websocket'],
      forceNew: true,
      extraHeaders: { 'X-Forwarded-For': `8.8.8.8, ${ip}` },
    });
    sockets.push(socket);
    await new Promise<void>((resolve, reject) => {
      socket.once('connect', () => resolve());
      socket.once('connect_error', reject);
    });
    const errors: Array<{ code?: number }> = [];
    socket.on('proof:error', (e) => errors.push(e));
    for (let i = 0; i < 5; i++) socket.emit('proof:request', {});
    const deadline = Date.now() + 5000;
    while (errors.length < 5 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 20));
    // 6 over HTTP + 4 over the socket = 10 admitted (401: no session); the 5th socket event is the 11th hit.
    // Compared as a set of outcomes, not in arrival order: the 429 is answered
    // at once, while each 401 first waits on a Redis read, so the 429 can
    // arrive before the 401s it was counted after.
    expect(errors.map((e) => e.code).sort()).toEqual([401, 401, 401, 401, 429]);
    expect(await hitRequest(url, ip)).toBe(429);

    // A socket from a different caller is not affected.
    const other = connectSocket(`${url}/proof`, { path: '/socket.io', transports: ['websocket'], forceNew: true, extraHeaders: { 'X-Forwarded-For': '198.51.100.41' } });
    sockets.push(other);
    await new Promise<void>((resolve) => other.once('connect', () => resolve()));
    const otherError = new Promise<{ code?: number }>((resolve) => other.once('proof:error', resolve));
    other.emit('proof:request', {});
    expect((await otherError).code).toBe(401);
  });
});

describe('GET /api/v1/stats wrong-token lockout (Redis)', () => {
  it(`${STATS_AUTH_MAX_FAILURES} wrong tokens are 401s; the next try is 429 with Retry-After, even with the right token`, async () => {
    const url = await start();
    const xff = '203.0.113.50';
    for (let i = 0; i < STATS_AUTH_MAX_FAILURES; i++) {
      expect((await statsCall(url, { token: `wrong-${i}`, xff })).status).toBe(401);
    }
    const locked = await statsCall(url, { token: 'wrong-again', xff });
    expect(locked.status).toBe(429);
    const ra = Number(locked.retryAfter);
    expect(ra).toBeGreaterThan(0);
    expect(ra).toBeLessThanOrEqual(STATS_AUTH_WINDOW_SECONDS);
    expect(locked.body.retryAfterSeconds).toBe(ra);

    const right = await statsCall(url, { token: TOKEN, xff });
    expect(right.status).toBe(429);
  });

  it('the count is shared by every instance (two relays, one Redis)', async () => {
    const a = await start();
    const b = await start();
    const xff = '203.0.113.51';
    for (let i = 0; i < STATS_AUTH_MAX_FAILURES; i++) {
      expect((await statsCall(i % 2 === 0 ? a : b, { token: 'nope', xff })).status).toBe(401);
    }
    expect((await statsCall(a, { token: TOKEN, xff })).status).toBe(429);
    expect((await statsCall(b, { token: TOKEN, xff })).status).toBe(429);
  });

  it('9 failures still let the right token in (boundary), and another caller is never locked by someone else', async () => {
    const url = await start();
    for (let i = 0; i < STATS_AUTH_MAX_FAILURES - 1; i++) await statsCall(url, { token: 'nope', xff: '203.0.113.52' });
    expect((await statsCall(url, { token: TOKEN, xff: '203.0.113.52' })).status).toBe(200);

    for (let i = 0; i < STATS_AUTH_MAX_FAILURES + 3; i++) await statsCall(url, { token: 'nope', xff: '203.0.113.53' });
    expect((await statsCall(url, { token: TOKEN, xff: '203.0.113.54' })).status).toBe(200);
    // Spoofing the leftmost entry does not escape a lockout.
    expect((await statsCall(url, { token: TOKEN, xff: '1.2.3.4, 203.0.113.53' })).status).toBe(429);
  });

  it('a missing Authorization header counts as a failure too', async () => {
    const url = await start();
    for (let i = 0; i < STATS_AUTH_MAX_FAILURES; i++) expect((await statsCall(url, { xff: '203.0.113.55' })).status).toBe(401);
    expect((await statsCall(url, { xff: '203.0.113.55' })).status).toBe(429);
  });

  it('Redis holds a hash of the address with a TTL, never the address', async () => {
    const url = await start();
    const ip = '203.0.113.56';
    await statsCall(url, { token: 'nope', xff: ip });
    const keys = await redis.keys(`${STATS_AUTH_KEY_PREFIX}*`);
    expect(keys.length).toBeGreaterThan(0);
    for (const k of keys) {
      expect(k).toMatch(/^relay:stats-auth-fail:[0-9a-f]{64}$/);
      expect(k).not.toContain('203.0.113');
    }
    expect(await redis.get(statsAuthKey(ip))).toBe('1');
    const ttl = await redis.ttl(statsAuthKey(ip));
    expect(ttl).toBeGreaterThan(STATS_AUTH_WINDOW_SECONDS - 5);
    expect(ttl).toBeLessThanOrEqual(STATS_AUTH_WINDOW_SECONDS);
    // A later failure does not extend the window.
    await redis.expire(statsAuthKey(ip), 100);
    await statsCall(url, { token: 'nope', xff: ip });
    expect(await redis.ttl(statsAuthKey(ip))).toBeLessThanOrEqual(100);
    expect(await redis.get(statsAuthKey(ip))).toBe('2');
  });

  it('20 concurrent wrong tokens: every one counted, none admitted', async () => {
    const url = await start();
    const ip = '203.0.113.57';
    const results = await Promise.all(Array.from({ length: 20 }, () => statsCall(url, { token: 'nope', xff: ip })));
    expect(results.every((r) => r.status === 401 || r.status === 429)).toBe(true);
    expect(Number(await redis.get(statsAuthKey(ip)))).toBeGreaterThanOrEqual(STATS_AUTH_MAX_FAILURES);
    expect((await statsCall(url, { token: TOKEN, xff: ip })).status).toBe(429);
  });

  it('successful reads have their own limit: 60 per minute, then 429', async () => {
    const url = await start();
    const xff = '203.0.113.58';
    const statuses: number[] = [];
    for (let i = 0; i < 61; i++) statuses.push((await statsCall(url, { token: TOKEN, xff })).status);
    expect(statuses.slice(0, 60).every((s) => s === 200)).toBe(true);
    expect(statuses[60]).toBe(429);
    // Being read-limited is not a failed login: the lockout counter is untouched.
    expect(await redis.get(statsAuthKey(xff))).toBeNull();
  });
});
