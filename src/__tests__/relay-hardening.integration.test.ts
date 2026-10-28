/**
 * Integration: the six relay defects fixed on 2026-10-27 (circuits-dev.md fix
 * list item 21), each against real in-process relays, real Redis (DB 15,
 * flushed) and real HTTP / Socket.IO clients. No mocks.
 *
 *   inputs hash        legacy + V2 published side by side (inputsHash.ts)
 *   session claim      one atomic Redis step for session and nonce (CLAIM_LUA)
 *   circuit mismatch   an answer naming another circuit is refused
 *   completed answer   must carry a proof; every field type-checked
 *   callback limit     60 per minute per caller per instance
 *   callback URL       always RELAY_EXTERNAL_URL, never the Host header
 *
 * Run with `scripts/test-relay.sh integration`.
 */
import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import type { AddressInfo } from 'net';
import { createHash } from 'crypto';
import Redis from 'ioredis';
import { ethers } from 'ethers';
import { io as connectSocket, Socket as ClientSocket } from 'socket.io-client';
import { createRelay, NONCE_MAX_CHARS, Relay } from '../app';
import { EDGES } from '../edge';
import { createStatsRecorder } from '../stats';
import { MAX_INPUTS_DEPTH } from '../inputsHash';

const TEST_EXTERNAL_URL = 'https://relay.example.test';
const CALLBACK_URL = `${TEST_EXTERNAL_URL}/api/v1/proof/callback`;

const REDIS_TEST_URL = process.env.REDIS_TEST_URL;
if (!REDIS_TEST_URL) {
  throw new Error('REDIS_TEST_URL is required (e.g. redis://localhost:6379/15). Run scripts/test-relay.sh integration.');
}
const db = Number(new URL(REDIS_TEST_URL).pathname.replace('/', '') || '0');
if (!(db > 0)) {
  throw new Error(`REDIS_TEST_URL must name a non-zero database; this suite flushes it. Got '${REDIS_TEST_URL}'.`);
}

const LONG = 3_600_000;
const PROOF = { proof: '0xdead', publicInputs: ['0x01'] };
const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');
/** The shipped app's computation (proofport-app src/utils/deeplink.ts). */
const appHash = (inputs: Record<string, unknown>) => sha256(JSON.stringify(inputs, Object.keys(inputs).sort()));

let redis: Redis;
const relays: Relay[] = [];
const sockets: ClientSocket[] = [];
let xffCounter = 0;
/** A fresh caller address per use, so no test shares another's rate-limit bucket. */
const freshIp = () => `198.51.100.${++xffCounter % 250}`;

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
    statsToken: 't'.repeat(64),
    adapter: null,
    edge: EDGES.local,
    relayExternalUrl: TEST_EXTERNAL_URL,
    deadlineMs: LONG,
    sweepIntervalMs: LONG,
    playIntegrity: { enabled: false, missing: ['PLAY_INTEGRITY_DECRYPTION_KEY', 'PLAY_INTEGRITY_VERIFICATION_KEY'] },
  });
  await new Promise<void>((resolve) => relay.httpServer.listen(0, '127.0.0.1', resolve));
  relays.push(relay);
  return `http://127.0.0.1:${(relay.httpServer.address() as AddressInfo).port}`;
}

const wallet = ethers.Wallet.createRandom();

async function challenge(url: string) {
  const res = await fetch(`${url}/api/v1/challenge`, { headers: { 'X-Forwarded-For': freshIp() } });
  expect(res.status).toBe(200);
  return await res.json() as { requestId: string; challenge: string };
}

async function postRequest(url: string, body: Record<string, unknown>, headers: Record<string, string> = {}) {
  const res = await fetch(`${url}/api/v1/proof/request`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': freshIp(), ...headers },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() as Record<string, unknown> };
}

/** A signed request body for a fresh session. */
async function signedBody(url: string, extra: Record<string, unknown> = {}) {
  const ch = await challenge(url);
  const signature = await wallet.signMessage(ch.challenge);
  return { requestId: ch.requestId, challenge: ch.challenge, signature, circuitId: 'coinbase_attestation', inputs: { scope: 'myapp.com' }, ...extra };
}

async function createRequest(url: string, extra: Record<string, unknown> = {}) {
  const body = await signedBody(url, extra);
  const res = await postRequest(url, body);
  expect(res.status).toBe(201);
  return { requestId: body.requestId, deepLink: res.body.deepLink as string };
}

async function callback(url: string, body: Record<string, unknown>, ip = freshIp()) {
  const res = await fetch(`${url}/api/v1/proof/callback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': ip },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() as Record<string, unknown>, retryAfter: res.headers.get('retry-after') };
}

async function poll(url: string, requestId: string) {
  const res = await fetch(`${url}/api/v1/proof/${requestId}`);
  return { status: res.status, body: await res.json() as Record<string, unknown> };
}

function decodeDeepLink(deepLink: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(new URL(deepLink).searchParams.get('data')!, 'base64url').toString('utf8'));
}

async function dappSocket(url: string, requestId: string) {
  const socket = connectSocket(`${url}/proof`, { path: '/socket.io', transports: ['websocket'], forceNew: true });
  sockets.push(socket);
  const results: Array<Record<string, unknown>> = [];
  socket.on('proof:result', (r) => results.push(r));
  await new Promise<void>((resolve, reject) => {
    socket.once('connect_error', reject);
    socket.once('proof:status', () => resolve());
    socket.on('connect', () => socket.emit('proof:subscribe', { requestId }));
  });
  return results;
}

const settle = () => new Promise((r) => setTimeout(r, 300));

// ---------------------------------------------------------------------------

describe('inputs hash: legacy for shipped apps, V2 canonical at every depth', () => {
  const giwa = (value: string) => ({ scope: 'dapp.example', action: { kind: 'transfer', to: '0x2222222222222222222222222222222222222222', value } });

  it('poll returns inputsHash equal to what a shipped app computes, and inputsHashV2 over every depth', async () => {
    const url = await start();
    const inputs = giwa('1');
    const { requestId, deepLink } = await createRequest(url, { inputs });
    const polled = (await poll(url, requestId)).body;
    // The app hashes the inputs it decoded from the deep link.
    const fromLink = decodeDeepLink(deepLink).inputs as Record<string, unknown>;
    expect(polled.inputsHash).toBe(appHash(fromLink));
    expect(polled.inputsHashV2).toBe(sha256('{"action":{"kind":"transfer","to":"0x2222222222222222222222222222222222222222","value":"1"},"scope":"dapp.example"}'));
  });

  it('two requests differing only inside the nested action: legacy hashes equal (kept), V2 hashes differ (fixed)', async () => {
    const url = await start();
    const a = await createRequest(url, { inputs: giwa('1') });
    const b = await createRequest(url, { inputs: giwa('1000000') });
    const pa = (await poll(url, a.requestId)).body;
    const pb = (await poll(url, b.requestId)).body;
    expect(pa.inputsHash).toBe(pb.inputsHash);
    expect(pa.inputsHashV2).not.toBe(pb.inputsHashV2);
  });

  it('flat inputs: the two hashes are identical', async () => {
    const url = await start();
    const { requestId } = await createRequest(url, { inputs: { scope: '홍길동 🪪', countryList: ['KR', 'US'], isIncluded: true } });
    const polled = (await poll(url, requestId)).body;
    expect(polled.inputsHashV2).toBe(polled.inputsHash);
  });

  it(`inputs nested deeper than ${MAX_INPUTS_DEPTH} levels: 400, and the session is still usable`, async () => {
    const url = await start();
    let deep: unknown = 1;
    for (let i = 0; i < MAX_INPUTS_DEPTH + 1; i++) deep = [deep];
    const body = await signedBody(url, { inputs: { deep } });
    const refused = await postRequest(url, body);
    expect(refused.status).toBe(400);
    expect(refused.body.error).toContain('nested more than');
    expect((await postRequest(url, { ...body, inputs: { scope: 'ok' } })).status).toBe(201);
  });

  it('a request opened before inputsHashV2 existed (rollout) polls with the legacy hash only', async () => {
    const url = await start();
    const { requestId } = await createRequest(url);
    await redis.del(`proof:inputsHashV2:${requestId}`);
    const polled = (await poll(url, requestId)).body;
    expect(polled.inputsHash).toMatch(/^[0-9a-f]{64}$/);
    expect(polled).not.toHaveProperty('inputsHashV2');
  });
});

describe('session and nonce claim: one atomic step', () => {
  it('20 simultaneous requests on one session across two instances: exactly one 201, the rest 409', async () => {
    const [a, b] = await Promise.all([start(), start()]);
    const body = await signedBody(a);
    const results = await Promise.all(Array.from({ length: 20 }, (_, i) => postRequest(i % 2 ? b : a, body)));
    const statuses = results.map((r) => r.status).sort();
    expect(statuses.filter((s) => s === 201)).toHaveLength(1);
    expect(statuses.filter((s) => s === 409)).toHaveLength(19);
    for (const r of results.filter((x) => x.status === 409)) expect(r.body.error).toBe('Session already used (replay detected)');
  });

  it('one nonce on 20 different sessions at once, across two instances: exactly one 201', async () => {
    const [a, b] = await Promise.all([start(), start()]);
    const nonce = `n-${Date.now()}-${Math.random()}`;
    const bodies = await Promise.all(Array.from({ length: 20 }, () => signedBody(a, { nonce })));
    const results = await Promise.all(bodies.map((body, i) => postRequest(i % 2 ? b : a, body)));
    expect(results.filter((r) => r.status === 201)).toHaveLength(1);
    expect(results.filter((r) => r.status === 409 && r.body.error === 'Duplicate nonce (replay detected)')).toHaveLength(19);
  });

  it('a duplicate nonce does not burn the session: the same session succeeds with a fresh nonce', async () => {
    const url = await start();
    const nonce = `dup-${Date.now()}`;
    await createRequest(url, { nonce });
    const body = await signedBody(url, { nonce });
    expect((await postRequest(url, body)).status).toBe(409);
    expect((await postRequest(url, { ...body, nonce: `${nonce}-fresh` })).status).toBe(201);
  });

  it('a used session does not burn the nonce: the nonce still works on a new session', async () => {
    const url = await start();
    const body = await signedBody(url);
    expect((await postRequest(url, body)).status).toBe(201);
    const nonce = `kept-${Date.now()}`;
    expect((await postRequest(url, { ...body, nonce })).status).toBe(409);
    expect((await postRequest(url, await signedBody(url, { nonce }))).status).toBe(201);
  });

  it('a session marked claimed by a relay from before this change (no claim key) is refused', async () => {
    const url = await start();
    const body = await signedBody(url);
    const key = `session:${body.requestId}`;
    const session = JSON.parse((await redis.get(key))!);
    await redis.set(key, JSON.stringify({ ...session, status: 'claimed' }), 'KEEPTTL');
    expect((await postRequest(url, body)).status).toBe(409);
  });

  it('an unknown session is 401', async () => {
    const url = await start();
    const body = await signedBody(url);
    await redis.del(`session:${body.requestId}`);
    expect((await postRequest(url, body)).status).toBe(401);
  });

  it('nonce absent, null and empty string all mean "no nonce", as before', async () => {
    const url = await start();
    for (const nonce of [undefined, null, '']) {
      expect((await postRequest(url, await signedBody(url, { nonce }))).status).toBe(201);
    }
  });

  it('a nonce that is not a string is 400 and leaves the session usable', async () => {
    const url = await start();
    const body = await signedBody(url);
    for (const nonce of [42, true, { a: 1 }, ['x'], 0.5]) {
      const r = await postRequest(url, { ...body, nonce });
      expect(r.status).toBe(400);
      expect(r.body.error).toBe('nonce must be a string');
    }
    expect((await postRequest(url, body)).status).toBe(201);
  });

  it(`nonce length: ${NONCE_MAX_CHARS} characters (emoji count once) accepted, one more refused`, async () => {
    const url = await start();
    const stamp = String(Date.now());
    const atMax = '🪪'.repeat(NONCE_MAX_CHARS - stamp.length) + stamp;
    expect(Array.from(atMax)).toHaveLength(NONCE_MAX_CHARS);
    expect((await postRequest(url, await signedBody(url, { nonce: atMax }))).status).toBe(201);
    const over = await postRequest(url, await signedBody(url, { nonce: `x${atMax}` }));
    expect(over.status).toBe(400);
    expect(over.body.error).toBe(`nonce must be at most ${NONCE_MAX_CHARS} characters`);
  });

  it('hostile nonces are opaque: wildcards, glob, Korean, control characters each claim only themselves', async () => {
    const url = await start();
    const stamp = Date.now();
    const nonces = [`%_${stamp}`, `*${stamp}`, `\\${stamp}`, `[a-z]?${stamp}`, `한국어-${stamp}`, `a\u0000b${stamp}`];
    for (const nonce of nonces) expect((await postRequest(url, await signedBody(url, { nonce }))).status).toBe(201);
    // A pattern-looking nonce did not claim anything else.
    expect((await postRequest(url, await signedBody(url, { nonce: `x${stamp}` }))).status).toBe(201);
  });
});

describe('callback fields', () => {
  it.each([
    ['completed without proof', { status: 'completed', publicInputs: ['0x01'] }, 'a completed answer must carry proof and publicInputs'],
    ['completed with an empty proof', { status: 'completed', proof: '', publicInputs: ['0x01'] }, 'a completed answer must carry proof and publicInputs'],
    ['completed without publicInputs', { status: 'completed', proof: '0x01' }, 'a completed answer must carry proof and publicInputs'],
    ['completed with nothing', { status: 'completed' }, 'a completed answer must carry proof and publicInputs'],
    ['proof as a number', { status: 'completed', proof: 1, publicInputs: [] }, 'proof must be a string'],
    ['proof null', { status: 'completed', proof: null, publicInputs: [] }, 'proof must be a string'],
    ['publicInputs as a string', { status: 'completed', proof: '0x01', publicInputs: '0x01' }, 'publicInputs must be an array of strings'],
    ['publicInputs with a number', { status: 'completed', proof: '0x01', publicInputs: ['0x01', 2] }, 'publicInputs must be an array of strings'],
    ['publicInputs null', { status: 'completed', proof: '0x01', publicInputs: null }, 'publicInputs must be an array of strings'],
    ['verifierAddress as a number', { status: 'completed', ...PROOF, verifierAddress: 1 }, 'verifierAddress must be a string'],
    ['verifierAddress null', { status: 'completed', ...PROOF, verifierAddress: null }, 'verifierAddress must be a string'],
    ['chainId as a string', { status: 'completed', ...PROOF, chainId: '8453' }, 'chainId must be a positive integer'],
    ['chainId 0', { status: 'completed', ...PROOF, chainId: 0 }, 'chainId must be a positive integer'],
    ['chainId negative', { status: 'completed', ...PROOF, chainId: -1 }, 'chainId must be a positive integer'],
    ['chainId fractional', { status: 'completed', ...PROOF, chainId: 1.5 }, 'chainId must be a positive integer'],
    ['chainId beyond 2^53', { status: 'completed', ...PROOF, chainId: 2 ** 53 }, 'chainId must be a positive integer'],
    ['chainId null', { status: 'completed', ...PROOF, chainId: null }, 'chainId must be a positive integer'],
    ['circuit as a number', { status: 'error', circuit: 1 }, 'circuit must be a string'],
    ['circuit null', { status: 'cancelled', circuit: null }, 'circuit must be a string'],
    ['proof on an error answer as an object', { status: 'error', proof: { x: 1 } }, 'proof must be a string'],
  ])('%s: 400, nothing delivered, request still open', async (_name, fields, message) => {
    const url = await start();
    const { requestId } = await createRequest(url);
    const results = await dappSocket(url, requestId);
    const r = await callback(url, { requestId, ...fields });
    expect(r.status).toBe(400);
    expect(r.body.error).toBe(message);
    await settle();
    expect(results).toHaveLength(0);
    expect((await poll(url, requestId)).body.status).toBe('pending');
  });

  it('completed with an empty publicInputs array is an answer (a circuit may have none)', async () => {
    const url = await start();
    const { requestId } = await createRequest(url);
    expect((await callback(url, { requestId, status: 'completed', proof: '0x01', publicInputs: [] })).status).toBe(200);
  });

  it('error and cancelled need no proof', async () => {
    const url = await start();
    const a = await createRequest(url);
    const b = await createRequest(url);
    expect((await callback(url, { requestId: a.requestId, status: 'error', errorCode: 'E2007', error: 'x' })).status).toBe(200);
    expect((await callback(url, { requestId: b.requestId, status: 'cancelled', error: 'user cancelled' })).status).toBe(200);
  });

  it("the shipped app's completed answer, every field it sends, is accepted", async () => {
    const url = await start();
    const { requestId } = await createRequest(url);
    const results = await dappSocket(url, requestId);
    const answer = {
      requestId,
      circuit: 'coinbase_attestation',
      status: 'completed',
      proof: `0x${'ab'.repeat(8000)}`,
      publicInputs: Array.from({ length: 4 }, (_, i) => `0x${String(i).padStart(64, '0')}`),
      numPublicInputs: 4,
      verificationType: 'off-chain',
      verificationResult: false,
      verifierAddress: '0x1234567890abcdef1234567890abcdef12345678',
      chainId: 8453,
      nullifier: `0x${'00'.repeat(32)}`,
      startedAt: Date.now() - 5000,
      completedAt: Date.now(),
      inputs: { scope: 'myapp.com' },
    };
    expect((await callback(url, answer)).status).toBe(200);
    await new Promise((r) => setTimeout(r, 200));
    expect(results[0]).toMatchObject({ status: 'completed', circuit: 'coinbase_attestation', chainId: 8453 });
  });
});

describe('callback rate limit', () => {
  it('60 callbacks a minute per caller; the 61st is 429 with Retry-After; another caller and the request endpoint are unaffected', async () => {
    const url = await start();
    const ip = freshIp();
    for (let i = 0; i < 60; i++) {
      // Unknown ids: cheap, and still counted -- the limit runs before any lookup.
      expect((await callback(url, { requestId: `unknown-${i}`, status: 'cancelled' }, ip)).status).toBe(404);
    }
    const limited = await callback(url, { requestId: 'unknown-x', status: 'cancelled' }, ip);
    expect(limited.status).toBe(429);
    expect(Number(limited.retryAfter)).toBeGreaterThan(0);
    expect(Number(limited.retryAfter)).toBeLessThanOrEqual(60);
    expect((await callback(url, { requestId: 'unknown-y', status: 'cancelled' }, freshIp())).status).toBe(404);
    // A malformed body is counted too, so it cannot be used to probe for free.
    expect((await callback(url, { status: 'completed' }, ip)).status).toBe(429);
    const reqRes = await fetch(`${url}/api/v1/proof/request`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': ip }, body: '{}',
    });
    expect(reqRes.status).toBe(401);
  });
});

describe('deep-link callback URL', () => {
  it('is RELAY_EXTERNAL_URL whatever Host, X-Forwarded-Host and X-Forwarded-Proto the caller sends', async () => {
    const url = await start();
    const plain = await createRequest(url);
    expect(decodeDeepLink(plain.deepLink).callbackUrl).toBe(CALLBACK_URL);

    const body = await signedBody(url);
    const res = await fetch(`${url}/api/v1/proof/request`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': freshIp(),
        Host: 'evil.example',
        'X-Forwarded-Host': 'evil.example',
        'X-Forwarded-Proto': 'http',
      },
      body: JSON.stringify(body),
    });
    expect(res.status).toBe(201);
    const link = ((await res.json()) as { deepLink: string }).deepLink;
    expect(decodeDeepLink(link).callbackUrl).toBe(CALLBACK_URL);
    expect(JSON.stringify(decodeDeepLink(link))).not.toContain('evil.example');
  });

  it('the Socket.IO proof:request path uses the same URL', async () => {
    const url = await start();
    const body = await signedBody(url);
    const socket = connectSocket(`${url}/proof`, { path: '/socket.io', transports: ['websocket'], forceNew: true, extraHeaders: { Host: 'evil.example' } });
    sockets.push(socket);
    const status = await new Promise<Record<string, unknown>>((resolve, reject) => {
      socket.once('connect_error', reject);
      socket.once('proof:error', (e) => reject(new Error(JSON.stringify(e))));
      socket.once('proof:status', resolve);
      socket.on('connect', () => socket.emit('proof:request', body));
    });
    expect(decodeDeepLink(status.deepLink as string).callbackUrl).toBe(CALLBACK_URL);
  });
});
