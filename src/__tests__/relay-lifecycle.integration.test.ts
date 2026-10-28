/**
 * Integration: real relay instances (`createRelay`) in this process, a real
 * Redis, real HTTP and real Socket.IO clients. Nothing is mocked.
 *
 * Run with `scripts/test-relay.sh integration` (needs the dev stack's Redis).
 * REDIS_TEST_URL must name a non-zero database; this suite flushes it.
 */
import { describe, it, expect, beforeAll, afterAll, afterEach, vi } from 'vitest';
import type { AddressInfo } from 'net';
import Redis from 'ioredis';
import { ethers } from 'ethers';
import { io as connectSocket, Socket as ClientSocket } from 'socket.io-client';
import { createAdapter } from '@socket.io/redis-adapter';
import { createRelay, ERROR_MESSAGE_MAX_CHARS, EXPIRED_MESSAGE, Relay } from '../app';
import { EDGES } from '../edge';
import { createStatsRecorder, DIMENSION_MAX_VALUES_PER_DAY, readStats, StatsRecorder, utcDay } from '../stats';
import { DEADLINES_KEY, metaKey, TERMINAL_TTL_SECONDS } from '../lifecycle';

/** The relay's public origin in tests; every deep link's callbackUrl must be built from it. */
const TEST_EXTERNAL_URL = 'https://relay.example.test';

const REDIS_TEST_URL = process.env.REDIS_TEST_URL;
if (!REDIS_TEST_URL) {
  throw new Error('REDIS_TEST_URL is required (e.g. redis://localhost:6379/15). Run scripts/test-relay.sh integration.');
}
const db = Number(new URL(REDIS_TEST_URL).pathname.replace('/', '') || '0');
if (!(db > 0)) {
  throw new Error(`REDIS_TEST_URL must name a non-zero database; this suite flushes it. Got '${REDIS_TEST_URL}'.`);
}

const STATS_TOKEN = 't'.repeat(64);
/** What every `completed` answer must carry since 2026-10-27. */
const PROOF = { proof: '0xdead', publicInputs: ['0x01'] };
const LONG = 3_600_000;

let redis: Redis;
const opened: Array<{ relay: Relay; clients: Redis[] }> = [];
const sockets: ClientSocket[] = [];

beforeAll(async () => {
  redis = new Redis(REDIS_TEST_URL);
  await redis.flushdb();
});

afterEach(async () => {
  for (const s of sockets.splice(0)) s.disconnect();
  for (const { relay, clients } of opened.splice(0)) {
    await relay.close();
    for (const c of clients) c.disconnect();
  }
});

afterAll(async () => {
  await redis.quit();
});

interface Started { relay: Relay; url: string }

async function start(opts: {
  deadlineMs?: number;
  sweepIntervalMs?: number;
  adapterKey?: string;
  stats?: StatsRecorder;
  edge?: (typeof EDGES)[keyof typeof EDGES];
} = {}): Promise<Started> {
  const clients: Redis[] = [];
  let adapter = null;
  if (opts.adapterKey) {
    const pub = new Redis(REDIS_TEST_URL!);
    const sub = pub.duplicate();
    clients.push(pub, sub);
    adapter = createAdapter(pub, sub, { key: opts.adapterKey });
  }
  const relay = createRelay({
    redis,
    stats: opts.stats ?? createStatsRecorder(redis),
    statsToken: STATS_TOKEN,
    adapter,
    edge: opts.edge ?? EDGES.local,
    relayExternalUrl: TEST_EXTERNAL_URL,
    deadlineMs: opts.deadlineMs ?? LONG,
    sweepIntervalMs: opts.sweepIntervalMs ?? LONG,
    playIntegrity: { enabled: false, missing: ['PLAY_INTEGRITY_DECRYPTION_KEY', 'PLAY_INTEGRITY_VERIFICATION_KEY'] },
  });
  await new Promise<void>((resolve) => relay.httpServer.listen(0, '127.0.0.1', resolve));
  const { port } = relay.httpServer.address() as AddressInfo;
  opened.push({ relay, clients });
  // `localhost`, not 127.0.0.1: the Host header is then not the peer IP, so
  // the masking test can insist the peer IP never appears raw.
  return { relay, url: `http://localhost:${port}` };
}

const wallet = ethers.Wallet.createRandom();

async function createRequest(url: string, circuitId = 'coinbase_attestation', inputs: Record<string, unknown> = { scope: 'myapp.com' }) {
  const ch = await (await fetch(`${url}/api/v1/challenge`)).json() as { requestId: string; challenge: string };
  const signature = await wallet.signMessage(ch.challenge);
  const res = await fetch(`${url}/api/v1/proof/request`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ requestId: ch.requestId, challenge: ch.challenge, signature, circuitId, inputs }),
  });
  expect(res.status).toBe(201);
  return { requestId: ch.requestId, challenge: ch.challenge, signature };
}

async function callback(url: string, body: Record<string, unknown>) {
  const res = await fetch(`${url}/api/v1/proof/callback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() as Record<string, unknown> };
}

async function poll(url: string, requestId: string) {
  const res = await fetch(`${url}/api/v1/proof/${requestId}`);
  return { status: res.status, body: await res.json() as Record<string, unknown> };
}

/** A dApp socket subscribed to a request, collecting every proof:result. */
async function dappSocket(url: string, requestId: string) {
  const socket = connectSocket(`${url}/proof`, { path: '/socket.io', transports: ['websocket'], forceNew: true });
  sockets.push(socket);
  const results: Array<Record<string, unknown>> = [];
  const statuses: Array<Record<string, unknown>> = [];
  socket.on('proof:result', (r) => results.push(r));
  socket.on('proof:status', (s) => statuses.push(s));
  await new Promise<void>((resolve, reject) => {
    socket.once('connect_error', reject);
    socket.once('proof:status', () => resolve());
    socket.once('proof:result', () => resolve());
    socket.on('connect', () => socket.emit('proof:subscribe', { requestId }));
  });
  return { socket, results, statuses };
}

async function until(check: () => boolean | Promise<boolean>, ms = 5000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await check()) return;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error('condition not met in time');
}

const settle = () => new Promise((r) => setTimeout(r, 300));

async function todayCounts(circuit: string) {
  const day = utcDay(new Date());
  const report = await readStats(redis, [day]);
  return report.days[0].circuits[circuit] ?? { requested: 0, completed: 0, cancelled: 0, expired: 0, abandoned: 0, error: { total: 0, byCode: {} } };
}

/** Pushes a request's deadline into the past, as if 280 s had gone by. */
async function backdate(requestId: string) {
  const meta = JSON.parse((await redis.get(metaKey(requestId)))!);
  meta.deadlineAt = Date.now() - 1;
  await redis.set(metaKey(requestId), JSON.stringify(meta), 'KEEPTTL');
  await redis.zadd(DEADLINES_KEY, meta.deadlineAt, requestId);
}

// ---------------------------------------------------------------------------

describe('terminal outcomes', () => {
  it('completed: socket and poll both get it, carrying the REQUESTED circuit, counted once', async () => {
    const { url } = await start();
    const before = await todayCounts('coinbase_attestation');
    const { requestId } = await createRequest(url);
    const dapp = await dappSocket(url, requestId);

    const cb = await callback(url, { requestId, status: 'completed', circuit: 'coinbase_attestation', proof: '0xdead', publicInputs: ['0x01'], chainId: 8453 });
    expect(cb).toEqual({ status: 200, body: { received: true } });

    await until(() => dapp.results.length === 1);
    expect(dapp.results[0]).toMatchObject({ requestId, status: 'completed', proof: '0xdead', circuit: 'coinbase_attestation' });
    expect((await poll(url, requestId)).body).toMatchObject({ status: 'completed', proof: '0xdead', publicInputs: ['0x01'], circuit: 'coinbase_attestation' });

    const after = await todayCounts('coinbase_attestation');
    expect(after.requested - before.requested).toBe(1);
    expect(after.completed - before.completed).toBe(1);
  });

  it('an answer that omits the circuit is delivered under the circuit recorded at creation', async () => {
    const { url } = await start();
    const { requestId } = await createRequest(url);
    const dapp = await dappSocket(url, requestId);
    expect((await callback(url, { requestId, status: 'completed', ...PROOF })).status).toBe(200);
    await until(() => dapp.results.length === 1);
    expect(dapp.results[0].circuit).toBe('coinbase_attestation');
    expect((await poll(url, requestId)).body.circuit).toBe('coinbase_attestation');
  });

  it('an answer naming another circuit is refused for every status: not delivered, not counted, request stays open', async () => {
    const { url } = await start();
    const before = await todayCounts('coinbase_attestation');
    const beforeOther = await todayCounts('mdl_kr_age');
    const { requestId } = await createRequest(url);
    const dapp = await dappSocket(url, requestId);

    for (const body of [
      { status: 'completed', circuit: 'mdl_kr_age', ...PROOF },
      { status: 'error', circuit: 'mdl_kr_age', errorCode: 'E2007' },
      { status: 'cancelled', circuit: 'coinbase-kyc' },
      { status: 'generating', circuit: 'COINBASE_ATTESTATION' },
      { status: 'completed', circuit: 'coinbase_attestation ', ...PROOF },
      { status: 'completed', circuit: '', ...PROOF },
    ]) {
      const cb = await callback(url, { requestId, ...body });
      expect(cb.status).toBe(400);
      expect(String(cb.body.error)).toContain("does not match the request's circuit 'coinbase_attestation'");
    }
    await settle();
    expect(dapp.results).toHaveLength(0);
    expect((await poll(url, requestId)).body.status).toBe('pending');
    expect((await todayCounts('coinbase_attestation')).completed).toBe(before.completed);
    expect((await todayCounts('mdl_kr_age')).completed).toBe(beforeOther.completed);

    // The real answer still lands afterwards.
    expect((await callback(url, { requestId, status: 'completed', circuit: 'coinbase_attestation', ...PROOF })).status).toBe(200);
    await until(() => dapp.results.length === 1);
    expect((await todayCounts('coinbase_attestation')).completed - before.completed).toBe(1);
  });

  it('error with errorCode: delivered with the code, counted under that code', async () => {
    const { url } = await start();
    const before = await todayCounts('coinbase_attestation');
    const { requestId } = await createRequest(url);
    const dapp = await dappSocket(url, requestId);

    expect((await callback(url, { requestId, status: 'error', errorCode: 'E2007', error: 'Proof generation failed' })).status).toBe(200);
    await until(() => dapp.results.length === 1);
    expect(dapp.results[0]).toMatchObject({ status: 'error', errorCode: 'E2007', error: 'Proof generation failed' });
    expect((await poll(url, requestId)).body).toMatchObject({ status: 'error', errorCode: 'E2007' });

    const after = await todayCounts('coinbase_attestation');
    expect((after.error.byCode.E2007 ?? 0) - (before.error.byCode.E2007 ?? 0)).toBe(1);
  });

  it('error without errorCode and legacy failed both land in the none bucket', async () => {
    const { url } = await start();
    const before = await todayCounts('coinbase_attestation');
    const a = await createRequest(url);
    const b = await createRequest(url);
    expect((await callback(url, { requestId: a.requestId, status: 'error', error: 'x' })).status).toBe(200);
    expect((await callback(url, { requestId: b.requestId, status: 'failed', errorCode: 'E2001' })).status).toBe(200);
    expect((await poll(url, b.requestId)).body).toMatchObject({ status: 'failed', errorCode: 'E2001' });
    const after = await todayCounts('coinbase_attestation');
    expect((after.error.byCode.none ?? 0) - (before.error.byCode.none ?? 0)).toBe(1);
    expect((after.error.byCode.E2001 ?? 0) - (before.error.byCode.E2001 ?? 0)).toBe(1);
  });

  it('errorCode on a non-error outcome is not stored or counted', async () => {
    const { url } = await start();
    const { requestId } = await createRequest(url);
    expect((await callback(url, { requestId, status: 'cancelled', errorCode: 'E2007' })).status).toBe(200);
    expect((await poll(url, requestId)).body.errorCode).toBeUndefined();
  });

  it('cancelled reaches both a socket dApp and a polling dApp, and is counted', async () => {
    const { url } = await start();
    const before = await todayCounts('coinbase_attestation');
    const { requestId } = await createRequest(url);
    const dapp = await dappSocket(url, requestId);
    expect((await callback(url, { requestId, status: 'cancelled' })).status).toBe(200);
    await until(() => dapp.results.length === 1);
    expect(dapp.results[0]).toMatchObject({ requestId, status: 'cancelled' });
    expect((await poll(url, requestId)).body).toMatchObject({ status: 'cancelled' });
    const after = await todayCounts('coinbase_attestation');
    expect(after.cancelled - before.cancelled).toBe(1);
    expect(after.abandoned - before.abandoned).toBe(1);
  });

  it('a late subscriber gets the buffered terminal result replayed', async () => {
    const { url } = await start();
    const { requestId } = await createRequest(url);
    await callback(url, { requestId, status: 'cancelled' });
    const late = await dappSocket(url, requestId);
    expect(late.results).toEqual([expect.objectContaining({ status: 'cancelled' })]);
  });
});

describe('idempotency', () => {
  it('a second terminal callback answers 409 and changes nothing: no second emit, no second count', async () => {
    const { url } = await start();
    const before = await todayCounts('coinbase_attestation');
    const { requestId } = await createRequest(url);
    const dapp = await dappSocket(url, requestId);

    expect((await callback(url, { requestId, status: 'completed', proof: '0x01', publicInputs: ['0x01'] })).status).toBe(200);
    const dup = await callback(url, { requestId, status: 'error', errorCode: 'E2007' });
    expect(dup).toEqual({ status: 409, body: { error: 'This request has already been answered', reason: 'already_answered' } });
    const same = await callback(url, { requestId, status: 'completed', proof: '0x02', publicInputs: ['0x01'] });
    expect(same.status).toBe(409);

    await settle();
    expect(dapp.results).toHaveLength(1);
    expect((await poll(url, requestId)).body).toMatchObject({ status: 'completed', proof: '0x01', publicInputs: ['0x01'] });
    const after = await todayCounts('coinbase_attestation');
    expect(after.completed - before.completed).toBe(1);
    expect((after.error.byCode.E2007 ?? 0) - (before.error.byCode.E2007 ?? 0)).toBe(0);
  });

  it('a re-sent answer after the status has aged out still gets 409 with its reason, not 404', async () => {
    const { url, relay } = await start();
    const expired = await createRequest(url);
    await backdate(expired.requestId);
    await relay.sweep();
    const answered = await createRequest(url);
    await callback(url, { requestId: answered.requestId, status: 'completed', ...PROOF });

    // The app was killed and re-sends on a later launch, after the 10-minute
    // status and result are gone.
    for (const id of [expired.requestId, answered.requestId]) {
      await redis.del(`proof:status:${id}`, `proof:result:${id}`, `proof:meta:${id}`);
      expect(await redis.ttl(`proof:terminal:${id}`)).toBeGreaterThan(TERMINAL_TTL_SECONDS - 60);
    }
    expect(await callback(url, { requestId: expired.requestId, status: 'cancelled' })).toEqual({ status: 409, body: { error: 'The request timed out before the app answered', reason: 'expired' } });
    expect(await callback(url, { requestId: answered.requestId, status: 'error', errorCode: 'E2007' })).toEqual({ status: 409, body: { error: 'This request has already been answered', reason: 'already_answered' } });
    expect(await callback(url, { requestId: answered.requestId, status: 'generating' })).toMatchObject({ status: 409, body: { reason: 'already_answered' } });

    // Once the terminal record is gone too, the request is unknown.
    await redis.del(`proof:terminal:${answered.requestId}`);
    expect((await callback(url, { requestId: answered.requestId, status: 'completed', ...PROOF })).status).toBe(404);
  });

  it('concurrent terminal callbacks: exactly one wins', async () => {
    const { url } = await start();
    const { requestId } = await createRequest(url);
    const dapp = await dappSocket(url, requestId);
    const replies = await Promise.all(
      ['completed', 'error', 'cancelled', 'completed', 'error'].map((status) => callback(url, { requestId, status, ...(status === 'completed' && PROOF) })),
    );
    expect(replies.filter((r) => r.status === 200)).toHaveLength(1);
    expect(replies.filter((r) => r.status === 409)).toHaveLength(4);
    for (const r of replies.filter((x) => x.status === 409)) expect(r.body.reason).toBe('already_answered');
    await settle();
    expect(dapp.results).toHaveLength(1);
  });

  it('an intermediate status after a terminal one is refused and does not overwrite it', async () => {
    const { url } = await start();
    const { requestId } = await createRequest(url);
    expect((await callback(url, { requestId, status: 'generating' })).status).toBe(200);
    expect((await poll(url, requestId)).body.status).toBe('generating');
    await callback(url, { requestId, status: 'completed', ...PROOF });
    expect((await callback(url, { requestId, status: 'generating' })).status).toBe(409);
    expect((await poll(url, requestId)).body.status).toBe('completed');
  });
});

describe('callback validation', () => {
  it('refuses a malformed errorCode with 400 and leaves the request open', async () => {
    const { url } = await start();
    const { requestId } = await createRequest(url);
    for (const errorCode of ['E20', 'E20071', 'e2007', 'X2007', '2007', '', 2007, null, ['E2007'], 'E2007|x', 'E%07']) {
      const r = await callback(url, { requestId, status: 'error', errorCode });
      expect(r.status, `errorCode ${JSON.stringify(errorCode)}`).toBe(400);
    }
    expect((await poll(url, requestId)).body.status).toBe('pending');
    // Still answerable: nothing above consumed the one terminal answer.
    expect((await callback(url, { requestId, status: 'error', errorCode: 'E2007' })).status).toBe(200);
  });

  it('refuses a non-string error', async () => {
    const { url } = await start();
    const { requestId } = await createRequest(url);
    expect((await callback(url, { requestId, status: 'error', error: { msg: 'x' } })).status).toBe(400);
    expect((await callback(url, { requestId, status: 'error', error: 42 })).status).toBe(400);
  });

  it('caps a huge error message at the documented length, counting characters not bytes', async () => {
    const { url } = await start();
    const { requestId } = await createRequest(url);
    const huge = '실패🙁'.repeat(50_000);
    expect((await callback(url, { requestId, status: 'error', error: huge })).status).toBe(200);
    const stored = String((await poll(url, requestId)).body.error);
    expect(Array.from(stored)).toHaveLength(ERROR_MESSAGE_MAX_CHARS);
    expect(huge.startsWith(stored)).toBe(true);
  });

  it('keeps an error message of exactly the cap and of cap-1 intact', async () => {
    const { url } = await start();
    for (const n of [ERROR_MESSAGE_MAX_CHARS - 1, ERROR_MESSAGE_MAX_CHARS]) {
      const { requestId } = await createRequest(url);
      const msg = 'e'.repeat(n);
      await callback(url, { requestId, status: 'error', error: msg });
      expect((await poll(url, requestId)).body.error).toBe(msg);
    }
  });

  it('refuses missing fields, unknown statuses and an app claiming expired', async () => {
    const { url } = await start();
    const { requestId } = await createRequest(url);
    expect((await callback(url, { status: 'completed' })).status).toBe(400);
    expect((await callback(url, { requestId })).status).toBe(400);
    expect((await callback(url, { requestId: 42, status: 'completed' })).status).toBe(400);
    const unknown = await callback(url, { requestId, status: 'done' });
    expect(unknown.status).toBe(400);
    expect(String(unknown.body.error)).toContain('Known: completed, error, failed, cancelled, generating');
    expect((await callback(url, { requestId, status: 'expired' })).status).toBe(400);
    expect((await poll(url, requestId)).body.status).toBe('pending');
  });

  it('answers 404 for an unknown requestId', async () => {
    const { url } = await start();
    expect((await callback(url, { requestId: 'no-such-request', status: 'completed', ...PROOF })).status).toBe(404);
  });

  it('answers 400, not a stack trace, to a malformed JSON body', async () => {
    const { url } = await start();
    const res = await fetch(`${url}/api/v1/proof/callback`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"requestId": 0x5290' });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: 'Malformed request body' });
  });
});

describe('relay-side timeout', () => {
  it('the sweep expires an open request: socket and poll get expired, counted once, late callback 409', async () => {
    const { url, relay } = await start();
    const before = await todayCounts('coinbase_attestation');
    const { requestId } = await createRequest(url);
    const dapp = await dappSocket(url, requestId);
    await backdate(requestId);

    expect(await relay.sweep()).toBeGreaterThanOrEqual(1);
    await until(() => dapp.results.length === 1);
    expect(dapp.results[0]).toMatchObject({ requestId, status: 'expired', error: EXPIRED_MESSAGE, circuit: 'coinbase_attestation' });
    expect((await poll(url, requestId)).body).toMatchObject({ status: 'expired', error: EXPIRED_MESSAGE });

    const late = await callback(url, { requestId, status: 'completed', proof: '0x01', publicInputs: ['0x01'] });
    expect(late).toEqual({ status: 409, body: { error: 'The request timed out before the app answered', reason: 'expired' } });

    expect(await relay.sweep()).toBe(0);
    await settle();
    expect(dapp.results).toHaveLength(1);
    const after = await todayCounts('coinbase_attestation');
    expect(after.expired - before.expired).toBe(1);
    expect(after.completed - before.completed).toBe(0);
    expect(await redis.zscore(DEADLINES_KEY, requestId)).toBeNull();
  });

  it('the periodic timer is wired: a short deadline expires with no explicit sweep', async () => {
    const { url } = await start({ deadlineMs: 300, sweepIntervalMs: 100 });
    const { requestId } = await createRequest(url);
    const dapp = await dappSocket(url, requestId);
    await until(() => dapp.results.length === 1, 3000);
    expect(dapp.results[0].status).toBe('expired');
  });

  it('a request inside its deadline is not expired by the sweep', async () => {
    const { url, relay } = await start();
    const { requestId } = await createRequest(url);
    await relay.sweep();
    expect((await poll(url, requestId)).body.status).toBe('pending');
  });

  it('lazy expiry on poll, with no sweep at all', async () => {
    const { url } = await start();
    const { requestId } = await createRequest(url);
    await backdate(requestId);
    expect((await poll(url, requestId)).body).toMatchObject({ status: 'expired' });
  });

  it('lazy expiry on subscribe delivers expired to the subscribing socket', async () => {
    const { url } = await start();
    const { requestId } = await createRequest(url);
    await backdate(requestId);
    const dapp = await dappSocket(url, requestId);
    await until(() => dapp.results.length >= 1);
    expect(dapp.results[0]).toMatchObject({ status: 'expired' });
  });

  it('lazy expiry on callback: a callback past the deadline gets 409 and the dApp gets expired', async () => {
    const { url } = await start();
    const before = await todayCounts('coinbase_attestation');
    const { requestId } = await createRequest(url);
    const dapp = await dappSocket(url, requestId);
    await backdate(requestId);
    const late = await callback(url, { requestId, status: 'completed', proof: '0x01', publicInputs: ['0x01'] });
    expect(late).toEqual({ status: 409, body: { error: 'The request timed out before the app answered', reason: 'expired' } });
    await until(() => dapp.results.length === 1);
    expect(dapp.results[0].status).toBe('expired');
    const after = await todayCounts('coinbase_attestation');
    expect(after.expired - before.expired).toBe(1);
    expect(after.completed - before.completed).toBe(0);
  });

  it('two instances racing the same expiries: each request expires exactly once, counted once, delivered once', async () => {
    const key = `socket.io-it-${Date.now()}`;
    const a = await start({ adapterKey: key });
    const b = await start({ adapterKey: key });
    const before = await todayCounts('coinbase_attestation');
    const ids: string[] = [];
    for (let i = 0; i < 5; i++) ids.push((await createRequest(a.url)).requestId);
    const sockets = await Promise.all(ids.map((id, i) => dappSocket(i % 2 ? a.url : b.url, id)));
    // Drain anything an earlier failed test left due, so the sum below is ours.
    await a.relay.sweep();
    for (const id of ids) await backdate(id);

    const counts = await Promise.all([a.relay.sweep(), b.relay.sweep(), a.relay.sweep(), b.relay.sweep()]);
    expect(counts.reduce((x, y) => x + y, 0)).toBe(5);
    await until(() => sockets.every((s) => s.results.length >= 1));
    await settle();
    for (const s of sockets) expect(s.results).toHaveLength(1);
    const after = await todayCounts('coinbase_attestation');
    expect(after.expired - before.expired).toBe(5);
  });

  it('a completed callback racing the expiry: exactly one outcome', async () => {
    const { url, relay } = await start();
    const before = await todayCounts('coinbase_attestation');
    const { requestId } = await createRequest(url);
    const dapp = await dappSocket(url, requestId);
    await backdate(requestId);
    const [cb] = await Promise.all([callback(url, { requestId, status: 'completed', ...PROOF }), relay.sweep()]);
    expect(cb).toMatchObject({ status: 409, body: { reason: 'expired' } });
    await settle();
    expect(dapp.results).toHaveLength(1);
    const after = await todayCounts('coinbase_attestation');
    expect((after.expired - before.expired) + (after.completed - before.completed)).toBe(1);
  });
});

describe('cross-instance delivery (Redis adapter)', () => {
  it('a callback on instance B reaches a dApp socket on instance A', async () => {
    const key = `socket.io-it-${Date.now()}`;
    const a = await start({ adapterKey: key });
    const b = await start({ adapterKey: key });
    const { requestId } = await createRequest(a.url);
    const dapp = await dappSocket(a.url, requestId);
    expect((await callback(b.url, { requestId, status: 'completed', proof: '0xbeef', publicInputs: ['0x01'] })).status).toBe(200);
    await until(() => dapp.results.length === 1);
    expect(dapp.results[0]).toMatchObject({ status: 'completed', proof: '0xbeef', publicInputs: ['0x01'] });
  });

  it('control: without the adapter the same callback never reaches the other instance', async () => {
    const a = await start();
    const b = await start();
    const { requestId } = await createRequest(a.url);
    const dapp = await dappSocket(a.url, requestId);
    expect((await callback(b.url, { requestId, status: 'completed', ...PROOF })).status).toBe(200);
    await settle();
    expect(dapp.results).toHaveLength(0);
  });
});

describe('statistics never block the proof path', () => {
  it('Redis unreachable for stats: the callback still answers and the dApp still gets its result', async () => {
    const dead = new Redis('redis://127.0.0.1:1', { lazyConnect: true, enableOfflineQueue: false, maxRetriesPerRequest: 0, retryStrategy: () => null });
    dead.on('error', () => {});
    const errors: string[] = [];
    const { url } = await start({ stats: createStatsRecorder(dead, (l) => errors.push(l)) });
    const { requestId } = await createRequest(url);
    const dapp = await dappSocket(url, requestId);
    const started = Date.now();
    expect((await callback(url, { requestId, status: 'completed', ...PROOF })).status).toBe(200);
    expect(Date.now() - started).toBeLessThan(1000);
    await until(() => dapp.results.length === 1);
    await until(() => errors.length >= 2);
    expect(errors.every((l) => l.includes('[Relay Stats] Count failed'))).toBe(true);
    dead.disconnect();
  });

  it('a stats write that hangs forever does not delay the callback', async () => {
    const hanging = { record: vi.fn() } as StatsRecorder;
    const { url } = await start({ stats: hanging });
    const { requestId } = await createRequest(url);
    expect((await callback(url, { requestId, status: 'cancelled' })).status).toBe(200);
    // Server-side fetch sends no Origin and this request has no envelope scope.
    const labels = { origin: 'm:none', scope: 'm:none' };
    expect(hanging.record).toHaveBeenCalledWith('coinbase_attestation', 'requested', undefined, undefined, labels);
    // The answer carries the request's labels plus where it came from (no header -> none).
    expect(hanging.record).toHaveBeenCalledWith('coinbase_attestation', 'cancelled', undefined, undefined, { ...labels, country: 'm:none' });
  });
});

describe('GET /api/v1/stats', () => {
  it('401 without a token, with a wrong token, and with a wrong scheme -- before validating the query', async () => {
    const { url } = await start();
    const q = `${url}/api/v1/stats?from=bad&to=worse`;
    expect((await fetch(q)).status).toBe(401);
    expect((await fetch(q, { headers: { Authorization: `Bearer ${'x'.repeat(64)}` } })).status).toBe(401);
    expect((await fetch(q, { headers: { Authorization: `Basic ${STATS_TOKEN}` } })).status).toBe(401);
    const res = await fetch(q, { headers: { Authorization: `Bearer ${STATS_TOKEN}` } });
    expect(res.status).toBe(400);
  });

  it('400 for bad dates, from > to and a range over 400 days', async () => {
    const { url } = await start();
    const get = (qs: string) => fetch(`${url}/api/v1/stats?${qs}`, { headers: { Authorization: `Bearer ${STATS_TOKEN}` } });
    expect((await get('to=2026-10-14')).status).toBe(400);
    expect((await get('from=2026-02-30&to=2026-03-01')).status).toBe(400);
    expect((await get('from=2026-10-15&to=2026-10-14')).status).toBe(400);
    expect((await get('from=2024-01-01&to=2026-10-14')).status).toBe(400);
    expect((await get('from=2026-10-14&to=2026-10-14&from=2026-10-13')).status).toBe(400);
  });

  it('answers per-day, per-circuit counts and totals; an event at 23:59:59.999Z and one at 00:00Z land on different days', async () => {
    const { url } = await start();
    const recorder = createStatsRecorder(redis);
    recorder.record('giwa_attestation', 'requested', undefined, new Date('2031-01-01T23:59:59.999Z'));
    recorder.record('giwa_attestation', 'expired', undefined, new Date('2031-01-02T00:00:00.000Z'));
    recorder.record('giwa_attestation', 'error', 'E3001', new Date('2031-01-02T12:00:00.000Z'));
    await settle();
    const res = await fetch(`${url}/api/v1/stats?from=2031-01-01&to=2031-01-02`, { headers: { Authorization: `Bearer ${STATS_TOKEN}` } });
    expect(res.status).toBe(200);
    const body = await res.json() as { days: Array<Record<string, unknown>>; totals: { all: Record<string, unknown> } };
    expect(body.days[0]).toMatchObject({ date: '2031-01-01', circuits: { giwa_attestation: { requested: 1, expired: 0 } } });
    expect(body.days[1]).toMatchObject({ date: '2031-01-02', circuits: { giwa_attestation: { requested: 0, expired: 1, abandoned: 1, error: { total: 1, byCode: { E3001: 1 } } } } });
    expect(body.totals.all).toMatchObject({ requested: 1, expired: 1, abandoned: 1 });
    const ttl = await redis.ttl('relay:stats:2031-01-01');
    expect(ttl).toBeGreaterThan(399 * 86400);
  });

  it('stores nothing personal in the stats hash', async () => {
    const { url } = await start();
    const { requestId } = await createRequest(url, 'coinbase_attestation', { scope: 'secret.example', userAddress: wallet.address });
    await callback(url, { requestId, status: 'error', errorCode: 'E2007', error: `bad ${wallet.address}` });
    await settle();
    const hash = await redis.hgetall(`relay:stats:${utcDay(new Date())}`);
    const dump = JSON.stringify(hash);
    for (const forbidden of [requestId, wallet.address.toLowerCase(), wallet.address, 'secret.example', '127.0.0.1']) {
      expect(dump).not.toContain(forbidden);
    }
    for (const field of Object.keys(hash)) expect(field).toMatch(/^[a-z0-9_]+\|(requested|completed|cancelled|expired|error\|(E\d{4}|none))$/);
  });
});

describe('log masking across a full lifecycle', () => {
  it('no raw IP, address, nullifier, public input, signature or inputs hash in any log line; masked forms present', async () => {
    const lines: string[] = [];
    const capture = (...args: unknown[]) => { lines.push(args.map((a) => (typeof a === 'string' ? a : a instanceof Error ? `${a.stack}` : JSON.stringify(a))).join(' ')); };
    const spies = [
      vi.spyOn(console, 'log').mockImplementation(capture),
      vi.spyOn(console, 'error').mockImplementation(capture),
      vi.spyOn(console, 'warn').mockImplementation(capture),
      vi.spyOn(console, 'info').mockImplementation(capture),
    ];
    try {
      const { url } = await start();
      const actionTarget = ethers.Wallet.createRandom().address;
      const nullifier = ethers.hexlify(ethers.randomBytes(32));
      const publicInput = ethers.hexlify(ethers.randomBytes(32));
      const inputs = { scope: 'private-scope.example', action: { to: actionTarget, value: '1' } };

      const { requestId, challenge, signature } = await createRequest(url, 'coinbase_attestation', inputs);
      const dapp = await dappSocket(url, requestId);
      await callback(url, { requestId, status: 'generating' });
      await callback(url, {
        requestId,
        status: 'completed',
        circuit: 'coinbase_attestation',
        proof: ethers.hexlify(ethers.randomBytes(64)),
        publicInputs: [publicInput, nullifier],
        nullifier,
        verifierAddress: '0x1234567890abcdef1234567890abcdef12345678',
        chainId: 8453,
      });
      await until(() => dapp.results.length === 1);
      const polled = await poll(url, requestId);
      expect(polled.body.status).toBe('completed');
      // A free-text error naming personal values, on a second request.
      const second = await createRequest(url);
      await callback(url, { requestId: second.requestId, status: 'error', errorCode: 'E2007', error: `wallet ${actionTarget} from 203.0.113.45 and 2001:db8:85a3::8a2e:370:7334 nullifier ${nullifier}` });
      await poll(url, second.requestId);

      const all = lines.join('\n');
      const inputsHash = String(polled.body.inputsHash);
      const forbidden = [
        '127.0.0.1', '203.0.113.45', '2001:db8:85a3::8a2e:370:7334',
        actionTarget, actionTarget.toLowerCase(), wallet.address, wallet.address.toLowerCase(),
        nullifier, publicInput, signature, challenge, inputsHash, 'private-scope.example',
      ];
      for (const value of forbidden) {
        expect(all, `raw value leaked: ${value}`).not.toContain(value);
      }
      const masked = (hex: string) => `0x${hex.slice(2, 6)}…${hex.slice(-4)}`;
      expect(all).toContain('127.0.x.x');
      expect(all).toContain(masked(wallet.address));
      expect(all).toContain(masked(actionTarget));
      expect(all).toContain(masked(nullifier));
      expect(all).toContain('203.0.x.x');
      expect(all).toContain('2001:db8:85a3:x:x:x:x:x');
      expect(all).toContain(`${inputsHash.slice(0, 4)}…${inputsHash.slice(-4)}`);
      expect(all).toContain('zkproofport://proof-request?data=<');
      // Envelope fields stay readable.
      expect(all).toContain(`requestId=${requestId}`);
      expect(all).toContain('errorCode=E2007');
      expect(all).toContain('verifierAddress=0x1234567890abcdef1234567890abcdef12345678');
    } finally {
      for (const s of spies) s.mockRestore();
    }
  });
});


// ---------------------------------------------------------------------------
// Labels: which page asked, the envelope scope, where the app answered from
// ---------------------------------------------------------------------------
describe('stats by site, scope and country', () => {
  const today = () => utcDay(new Date());

  async function labelledRequest(url: string, opts: { origin?: string; scope?: unknown; xff: string }) {
    const ch = await (await fetch(`${url}/api/v1/challenge`, { headers: { 'X-Forwarded-For': opts.xff } })).json() as { requestId: string; challenge: string };
    const signature = await wallet.signMessage(ch.challenge);
    const headers: Record<string, string> = { 'Content-Type': 'application/json', 'X-Forwarded-For': opts.xff };
    if (opts.origin !== undefined) headers.Origin = opts.origin;
    const res = await fetch(`${url}/api/v1/proof/request`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        requestId: ch.requestId, challenge: ch.challenge, signature, circuitId: 'coinbase_attestation',
        inputs: { scope: 'inside-inputs-never-read' },
        ...(opts.scope !== undefined && { scope: opts.scope }),
      }),
    });
    expect(res.status).toBe(201);
    return ch.requestId;
  }

  async function answer(url: string, requestId: string, status: string, region?: string) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (region !== undefined) headers['X-Relay-Client-Region'] = region;
    const res = await fetch(`${url}/api/v1/proof/callback`, {
      method: 'POST', headers,
      body: JSON.stringify({ requestId, status, circuit: 'coinbase_attestation', ...(status === 'error' && { errorCode: 'E2005' }), ...(status === 'completed' && PROOF) }),
    });
    expect(res.status).toBe(200);
  }

  async function dims() {
    return (await readStats(redis, [today()])).dimensions;
  }

  it('a request and its answer land under the page that asked, the envelope scope and the answering country', async () => {
    await redis.flushdb();
    const { url } = await start();
    const id = await labelledRequest(url, { origin: 'https://DojangScan.com', scope: 'dojang-v1', xff: '198.51.100.1' });
    await answer(url, id, 'completed', 'KR');
    await until(async () => (await dims()).country['v:KR']?.all.completed === 1);
    const d = await dims();
    expect(d.origin['v:dojangscan.com'].circuits.coinbase_attestation).toMatchObject({ requested: 1, completed: 1 });
    expect(d.scope['v:dojang-v1'].all).toMatchObject({ requested: 1, completed: 1 });
    // The scope inside the proof inputs is never read.
    expect(Object.keys(d.scope)).toEqual(['v:dojang-v1']);
    expect(d.country['v:KR'].all).toMatchObject({ requested: 0, completed: 1 });
  });

  it('no Origin and no envelope scope are counted as "none"; an error answer as error, under its country', async () => {
    await redis.flushdb();
    const { url } = await start();
    const id = await labelledRequest(url, { xff: '198.51.100.2' });
    await answer(url, id, 'error', 'US');
    await until(async () => (await dims()).country['v:US']?.all.error === 1);
    const d = await dims();
    expect(d.origin['m:none'].all).toMatchObject({ requested: 1, error: 1 });
    expect(d.scope['m:none'].all).toMatchObject({ requested: 1, error: 1 });
  });

  it('a country the load balancer could not place, and a forged value, are not counted as a country', async () => {
    await redis.flushdb();
    const { url } = await start();
    const a = await labelledRequest(url, { origin: 'https://a.example', xff: '198.51.100.3' });
    const b = await labelledRequest(url, { origin: 'https://a.example', xff: '198.51.100.3' });
    await answer(url, a, 'cancelled', '');
    await answer(url, b, 'cancelled', 'KR,US');
    await until(async () => (await dims()).origin['v:a.example']?.all.cancelled === 2);
    const d = await dims();
    expect(d.country['m:unknown'].all.cancelled).toBe(1);
    expect(d.country['m:invalid'].all.cancelled).toBe(1);
  });

  it('behind a Cloud Run domain mapping the country header is not trusted at all', async () => {
    await redis.flushdb();
    const { url } = await start({ edge: EDGES['cloud-run-domain'] });
    const id = await labelledRequest(url, { origin: 'https://a.example', xff: '198.51.100.4' });
    await answer(url, id, 'completed', 'KR');
    await until(async () => (await dims()).origin['v:a.example']?.all.completed === 1);
    expect((await dims()).country).toEqual({});
  });

  it('an expiry keeps the site and scope of its request and has no country', async () => {
    await redis.flushdb();
    const { url, relay } = await start({ deadlineMs: 50 });
    await labelledRequest(url, { origin: 'https://slow.example', scope: 's', xff: '198.51.100.5' });
    await new Promise((r) => setTimeout(r, 120));
    await relay.sweep();
    await until(async () => (await dims()).origin['v:slow.example']?.all.expired === 1);
    const d = await dims();
    expect(d.scope['v:s'].all).toMatchObject({ requested: 1, expired: 1, abandoned: 1 });
    expect(d.country).toEqual({});
  });

  it('a request over Socket.IO is labelled by its handshake Origin', async () => {
    await redis.flushdb();
    const { url } = await start();
    const ch = await (await fetch(`${url}/api/v1/challenge`, { headers: { 'X-Forwarded-For': '198.51.100.6' } })).json() as { requestId: string; challenge: string };
    const socket = connectSocket(`${url}/proof`, {
      path: '/socket.io', transports: ['websocket'], forceNew: true, extraHeaders: { Origin: 'https://socket.example' },
    });
    sockets.push(socket);
    await new Promise<void>((resolve, reject) => {
      socket.once('connect_error', reject);
      socket.once('proof:status', () => resolve());
      socket.once('proof:error', (e) => reject(new Error(JSON.stringify(e))));
      socket.on('connect', async () => socket.emit('proof:request', {
        requestId: ch.requestId, challenge: ch.challenge, signature: await wallet.signMessage(ch.challenge),
        circuitId: 'coinbase_attestation', inputs: { scope: 'x' },
      }));
    });
    await until(async () => (await dims()).origin['v:socket.example']?.all.requested === 1);
  });

  it('the sites add up to the circuit totals, request for request', async () => {
    await redis.flushdb();
    const { url } = await start();
    const origins = ['https://a.example', 'https://b.example', undefined, 'null', 'chrome-extension://x'];
    for (const [i, origin] of origins.entries()) await labelledRequest(url, { origin, xff: `198.51.100.${10 + i}` });
    await until(async () => {
      const r = await readStats(redis, [today()]);
      return Object.values(r.dimensions.origin).reduce((n, row) => n + row.all.requested, 0) === origins.length;
    });
    const r = await readStats(redis, [today()]);
    const sum = Object.values(r.dimensions.origin).reduce((n, row) => n + row.all.requested, 0);
    expect(sum).toBe(r.totals.all.requested);
    expect(r.dimensions.origin['m:none'].all.requested).toBe(2);
    expect(r.dimensions.origin['m:invalid'].all.requested).toBe(1);
  });

  it(`at most ${DIMENSION_MAX_VALUES_PER_DAY} distinct values a day, even written at once from two relays; the rest is "other"`, async () => {
    await redis.flushdb();
    const second = new Redis(REDIS_TEST_URL!);
    const recorders = [createStatsRecorder(redis), createStatsRecorder(second)];
    const extra = 37;
    const total = DIMENSION_MAX_VALUES_PER_DAY + extra;
    for (let i = 0; i < total; i++) recorders[i % 2].record('coinbase_attestation', 'requested', undefined, undefined, { scope: `v:s${i}` });
    await until(async () => {
      const r = await readStats(redis, [today()]);
      return Object.values(r.dimensions.scope).reduce((n, row) => n + row.all.requested, 0) === total;
    }, 10_000);
    const r = await readStats(redis, [today()]);
    const values = Object.keys(r.dimensions.scope).filter((k) => k.startsWith('v:'));
    expect(values).toHaveLength(DIMENSION_MAX_VALUES_PER_DAY);
    expect(r.dimensions.scope['m:other'].all.requested).toBe(extra);
    // A value already seen that day keeps counting as itself after the cap.
    recorders[0].record('coinbase_attestation', 'completed', undefined, undefined, { scope: values[0] });
    await until(async () => (await readStats(redis, [today()])).dimensions.scope[values[0]].all.completed === 1);
    // The cap set expires with the day, like the counts.
    expect(await redis.ttl(`relay:stats:dim-seen:scope:${today()}`)).toBeGreaterThan(0);
    second.disconnect();
  });
});
