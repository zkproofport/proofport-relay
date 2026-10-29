/**
 * E2E: request lifecycle across TWO real relay containers on one Redis.
 *
 *   relay    http://localhost:4001  (the dev stack's relay)
 *   relay-b  http://localhost:4011  (test-only, docker-compose.relay-pair.yml)
 *
 * Real HTTP and real Socket.IO to running containers; nothing mocked. The only
 * shortcut is that the expiry tests move a request's deadline into the past in
 * Redis instead of waiting the real 540 s.
 *
 * Run: `scripts/test-relay.sh e2e` -- it starts relay-b, passes the env below
 * and removes relay-b afterwards.
 *
 * Every proof request here is created on relay-b, under this run's own
 * X-Forwarded-For address (CALLER): the request endpoint is capped at 10/min
 * per caller per instance. This file makes 7.
 */
import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import Redis from 'ioredis';
import { io as connectSocket, Socket as ClientSocket } from 'socket.io-client';

function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required. Run scripts/test-relay.sh e2e.`);
  return v;
}

const A = required('RELAY_URL');
const B = required('RELAY_B_URL');
const TOKEN = required('RELAY_STATS_TOKEN');
const REDIS_E2E_URL = required('REDIS_E2E_URL');
const CIRCUIT = 'mdl_kr_ownership';
/** What every `completed` answer must carry since 2026-10-27. */
const PROOF = { proof: '0xdead', publicInputs: ['0x01'] };

let redis: Redis;
const sockets: ClientSocket[] = [];

beforeAll(async () => {
  for (const url of [A, B]) {
    const res = await fetch(`${url}/health`);
    if (!res.ok) throw new Error(`${url} not healthy: ${res.status}`);
  }
  redis = new Redis(REDIS_E2E_URL);
});

afterEach(() => {
  for (const s of sockets.splice(0)) s.disconnect();
});

afterAll(async () => {
  await redis.quit();
});

/**
 * This run's caller address (the relay trusts one X-Forwarded-For hop,
 * src/clientIp.ts). Without it every run is counted under Docker's gateway
 * address, and two runs inside a minute exhaust the 10/min request budget.
 */
const CALLER = { 'X-Forwarded-For': `198.18.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 254) + 1}` };

async function createRequest(url: string): Promise<string> {
  const ch = await (await fetch(`${url}/api/v1/challenge`, { headers: CALLER })).json() as { requestId: string; challenge: string };
  const res = await fetch(`${url}/api/v1/proof/request`, {
    method: 'POST',
    headers: { ...CALLER, 'Content-Type': 'application/json' },
    body: JSON.stringify({ requestId: ch.requestId, challenge: ch.challenge, circuitId: CIRCUIT, inputs: { scope: 'e2e.example' } }),
  });
  if (res.status === 429) throw new Error(`${url} rate-limited proof requests (10/min per IP); wait a minute and re-run.`);
  expect(res.status).toBe(201);
  return ch.requestId;
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

async function dappSocket(url: string, requestId: string) {
  const socket = connectSocket(`${url}/proof`, { path: '/socket.io', transports: ['websocket'], forceNew: true });
  sockets.push(socket);
  const results: Array<Record<string, unknown>> = [];
  socket.on('proof:result', (r) => results.push(r));
  await new Promise<void>((resolve, reject) => {
    socket.once('connect_error', reject);
    socket.once('proof:status', () => resolve());
    socket.once('proof:result', () => resolve());
    socket.on('connect', () => socket.emit('proof:subscribe', { requestId }));
  });
  return results;
}

async function until(check: () => boolean | Promise<boolean>, ms: number) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await check()) return;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`condition not met within ${ms} ms`);
}

async function stats(url = A) {
  const day = new Date().toISOString().slice(0, 10);
  const res = await fetch(`${url}/api/v1/stats?from=${day}&to=${day}`, { headers: { Authorization: `Bearer ${TOKEN}` } });
  expect(res.status).toBe(200);
  const body = await res.json() as { days: Array<{ circuits: Record<string, { requested: number; completed: number; cancelled: number; expired: number; error: { byCode: Record<string, number> } }> }> };
  return body.days[0].circuits[CIRCUIT] ?? { requested: 0, completed: 0, cancelled: 0, expired: 0, error: { byCode: {} } };
}

/** Moves a request's deadline into the past, standing in for 540 s of waiting. */
async function backdate(requestId: string) {
  const raw = await redis.get(`proof:meta:${requestId}`);
  if (!raw) throw new Error(`no proof:meta for ${requestId} -- is the container running this relay version?`);
  const meta = JSON.parse(raw);
  meta.deadlineAt = Date.now() - 1;
  await redis.set(`proof:meta:${requestId}`, JSON.stringify(meta), 'KEEPTTL');
  await redis.zadd('proof:deadlines', meta.deadlineAt, requestId);
}

describe('cross-instance delivery', () => {
  it('dApp socket on relay, app callback on relay-b: delivered', async () => {
    const requestId = await createRequest(B);
    const results = await dappSocket(A, requestId);
    expect((await callback(B, { requestId, status: 'completed', proof: '0xbeef', publicInputs: ['0x01'], circuit: CIRCUIT })).status).toBe(200);
    await until(() => results.length === 1, 5000);
    expect(results[0]).toMatchObject({ requestId, status: 'completed', proof: '0xbeef' });
  });

  it('dApp socket on relay-b, app callback on relay: delivered', async () => {
    const requestId = await createRequest(B);
    const results = await dappSocket(B, requestId);
    expect((await callback(A, { requestId, status: 'cancelled' })).status).toBe(200);
    await until(() => results.length === 1, 5000);
    expect(results[0]).toMatchObject({ requestId, status: 'cancelled' });
  });
});

describe('terminal outcomes over real HTTP', () => {
  it('error with errorCode: malformed code refused, then delivered, duplicate 409, counted once', async () => {
    const before = await stats();
    const requestId = await createRequest(B);
    const results = await dappSocket(A, requestId);

    expect((await callback(A, { requestId, status: 'error', errorCode: 'E20' })).status).toBe(400);
    expect((await callback(A, { requestId, status: 'error', errorCode: 'E2007', error: 'Proof generation failed' })).status).toBe(200);
    const dup = await callback(B, { requestId, status: 'completed', ...PROOF });
    expect(dup).toEqual({ status: 409, body: { error: 'This request has already been answered', reason: 'already_answered' } });

    await until(() => results.length === 1, 5000);
    expect(results[0]).toMatchObject({ status: 'error', errorCode: 'E2007', error: 'Proof generation failed' });
    expect((await poll(B, requestId)).body).toMatchObject({ status: 'error', errorCode: 'E2007' });
    const after = await stats(B);
    expect(after.requested - before.requested).toBe(1);
    expect((after.error.byCode.E2007 ?? 0) - (before.error.byCode.E2007 ?? 0)).toBe(1);
    expect(after.completed - before.completed).toBe(0);
  });

  it('cancelled reaches a polling dApp', async () => {
    const requestId = await createRequest(B);
    expect((await poll(A, requestId)).body.status).toBe('pending');
    expect((await callback(B, { requestId, status: 'cancelled' })).status).toBe(200);
    expect((await poll(A, requestId)).body).toMatchObject({ status: 'cancelled' });
  });
});

describe('relay-side timeout in the containers', () => {
  it('a request past its deadline is expired by a container sweep: socket and poll get expired, late callback 409, counted once', async () => {
    const before = await stats();
    const requestId = await createRequest(B);
    const results = await dappSocket(A, requestId);
    await backdate(requestId);

    // Either container's 5 s sweep may win; both deliver through the adapter.
    await until(() => results.length === 1, 12_000);
    expect(results[0]).toMatchObject({ requestId, status: 'expired', circuit: CIRCUIT });
    expect((await poll(B, requestId)).body).toMatchObject({ status: 'expired' });
    const late = await callback(A, { requestId, status: 'completed', ...PROOF });
    expect(late).toEqual({ status: 409, body: { error: 'The request timed out before the app answered', reason: 'expired' } });

    await new Promise((r) => setTimeout(r, 6000));
    expect(results).toHaveLength(1);
    const after = await stats();
    expect(after.expired - before.expired).toBe(1);
  });

  it('a polling dApp sees expired as soon as it asks after the deadline', async () => {
    const requestId = await createRequest(B);
    await backdate(requestId);
    expect((await poll(A, requestId)).body).toMatchObject({ status: 'expired' });
  });
});

describe('GET /api/v1/stats on the container', () => {
  it('401 without or with a wrong token; 400 for bad dates, from > to, range too long', async () => {
    // Wrong tokens are counted per caller in Redis for 15 minutes (statsAuth.ts).
    // Sent from the host's own address they would add up across runs and lock
    // the other tests' stats reads out, so these two carry a fresh
    // X-Forwarded-For entry standing in for Google's front end (CALLER).
    expect((await fetch(`${A}/api/v1/stats?from=2026-10-14&to=2026-10-14`, { headers: CALLER })).status).toBe(401);
    expect((await fetch(`${A}/api/v1/stats?from=2026-10-14&to=2026-10-14`, { headers: { ...CALLER, Authorization: 'Bearer wrong' } })).status).toBe(401);
    const get = (qs: string) => fetch(`${A}/api/v1/stats?${qs}`, { headers: { Authorization: `Bearer ${TOKEN}` } });
    expect((await get('from=2026-02-30&to=2026-03-01')).status).toBe(400);
    expect((await get('from=2026-10-15&to=2026-10-14')).status).toBe(400);
    expect((await get('from=2024-01-01&to=2026-10-14')).status).toBe(400);
    expect((await get('from=2026-10-14&to=2026-10-14')).status).toBe(200);
  });

  it('callback for an unknown request is 404 on either container', async () => {
    expect((await callback(A, { requestId: 'no-such-request', status: 'completed', ...PROOF })).status).toBe(404);
    expect((await callback(B, { requestId: 'no-such-request', status: 'error', errorCode: 'E2007' })).status).toBe(404);
  });
});
