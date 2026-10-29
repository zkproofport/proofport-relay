/**
 * E2E: the six relay defects fixed on 2026-10-27, against the two real relay
 * containers on one Redis (relay :4001, relay-b :4011). Real HTTP and real
 * Socket.IO; nothing mocked.
 *
 * Run: `scripts/test-relay.sh e2e`. Every proof request and callback here goes
 * out under a fresh X-Forwarded-For address of its own (the relay trusts one
 * hop locally, src/clientIp.ts), so this file shares no rate-limit bucket with
 * the other E2E files or with a previous run.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { createHash } from 'crypto';
import { ethers } from 'ethers';

function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required. Run scripts/test-relay.sh e2e.`);
  return v;
}

const A = required('RELAY_URL');
const B = required('RELAY_B_URL');
const PROOF = { proof: '0xdead', publicInputs: ['0x01'] };
const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');
const appHash = (inputs: Record<string, unknown>) => sha256(JSON.stringify(inputs, Object.keys(inputs).sort()));

const run = `${Math.floor(Math.random() * 256)}`;
let ipCounter = 0;
const freshIp = () => `198.19.${run}.${(++ipCounter % 254) + 1}`;

const wallet = ethers.Wallet.createRandom();

beforeAll(async () => {
  for (const url of [A, B]) {
    const res = await fetch(`${url}/health`);
    if (!res.ok) throw new Error(`${url} not healthy: ${res.status}`);
  }
});

async function signedBody(url: string, extra: Record<string, unknown> = {}) {
  const ch = await (await fetch(`${url}/api/v1/challenge`, { headers: { 'X-Forwarded-For': freshIp() } })).json() as { requestId: string; challenge: string };
  const signature = await wallet.signMessage(ch.challenge);
  return { requestId: ch.requestId, challenge: ch.challenge, signature, circuitId: 'coinbase_attestation', inputs: { scope: 'hardening-e2e.example' }, ...extra };
}

async function postRequest(url: string, body: Record<string, unknown>, headers: Record<string, string> = {}) {
  const res = await fetch(`${url}/api/v1/proof/request`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': freshIp(), ...headers },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() as Record<string, unknown> };
}

async function createRequest(url: string, extra: Record<string, unknown> = {}) {
  const res = await postRequest(url, await signedBody(url, extra));
  expect(res.status).toBe(201);
  return { requestId: res.body.requestId as string, deepLink: res.body.deepLink as string };
}

async function callback(url: string, body: Record<string, unknown>, ip = freshIp()) {
  const res = await fetch(`${url}/api/v1/proof/callback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': ip },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() as Record<string, unknown> };
}

async function poll(url: string, requestId: string) {
  return await (await fetch(`${url}/api/v1/proof/${requestId}`)).json() as Record<string, unknown>;
}

const decode = (deepLink: string) => JSON.parse(Buffer.from(new URL(deepLink).searchParams.get('data')!, 'base64url').toString('utf8')) as Record<string, unknown>;

describe('inputs hash on the containers', () => {
  it('nested inputs: inputsHash is what a shipped app computes, inputsHashV2 covers the nested action', async () => {
    const inputs = { scope: 'hardening-e2e.example', action: { kind: 'transfer', value: '7', to: '0x2222222222222222222222222222222222222222' } };
    const { requestId, deepLink } = await createRequest(B, { inputs });
    const polled = await poll(A, requestId);
    expect(polled.inputsHash).toBe(appHash(decode(deepLink).inputs as Record<string, unknown>));
    expect(polled.inputsHashV2).toBe(sha256('{"action":{"kind":"transfer","to":"0x2222222222222222222222222222222222222222","value":"7"},"scope":"hardening-e2e.example"}'));
  });
});

describe('session and nonce claim across the two containers', () => {
  it('one session posted 10 times at once to both containers: exactly one 201', async () => {
    const body = await signedBody(A);
    const results = await Promise.all(Array.from({ length: 10 }, (_, i) => postRequest(i % 2 ? B : A, body)));
    expect(results.filter((r) => r.status === 201)).toHaveLength(1);
    expect(results.filter((r) => r.status === 409)).toHaveLength(9);
  });

  it('one nonce on 10 sessions at once across both containers: exactly one 201', async () => {
    const nonce = `e2e-${run}-${Date.now()}`;
    const bodies = await Promise.all(Array.from({ length: 10 }, (_, i) => signedBody(i % 2 ? B : A, { nonce })));
    const results = await Promise.all(bodies.map((body, i) => postRequest(i % 2 ? B : A, body)));
    expect(results.filter((r) => r.status === 201)).toHaveLength(1);
    expect(results.filter((r) => r.status === 409 && r.body.error === 'Duplicate nonce (replay detected)')).toHaveLength(9);
  });
});

describe('callback contract on the containers', () => {
  it('an answer naming another circuit is refused; the right one is then delivered under the requested circuit', async () => {
    const { requestId } = await createRequest(B);
    const wrong = await callback(A, { requestId, status: 'completed', circuit: 'oidc_domain_attestation', ...PROOF });
    expect(wrong.status).toBe(400);
    expect((await poll(B, requestId)).status).toBe('pending');
    expect((await callback(B, { requestId, status: 'completed', circuit: 'coinbase_attestation', ...PROOF })).status).toBe(200);
    expect(await poll(A, requestId)).toMatchObject({ status: 'completed', circuit: 'coinbase_attestation', proof: '0xdead' });
  });

  it('a completed answer without a proof is refused and the request stays open', async () => {
    const { requestId } = await createRequest(B);
    const r = await callback(A, { requestId, status: 'completed', circuit: 'coinbase_attestation' });
    expect(r).toEqual({ status: 400, body: { error: 'a completed answer must carry proof and publicInputs' } });
    expect((await poll(A, requestId)).status).toBe('pending');
  });

  it('a mistyped field is refused', async () => {
    const { requestId } = await createRequest(B);
    expect((await callback(A, { requestId, status: 'completed', ...PROOF, chainId: '8453' })).body).toEqual({ error: 'chainId must be a positive integer' });
    expect((await callback(A, { requestId, status: 'completed', proof: '0x01', publicInputs: [1] })).body).toEqual({ error: 'publicInputs must be an array of strings' });
  });

  it('60 callbacks a minute per caller on one container; the 61st is 429 with Retry-After', async () => {
    const ip = freshIp();
    for (let i = 0; i < 60; i++) {
      expect((await callback(A, { requestId: `e2e-unknown-${i}`, status: 'cancelled' }, ip)).status).toBe(404);
    }
    const res = await fetch(`${A}/api/v1/proof/callback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': ip },
      body: JSON.stringify({ requestId: 'e2e-unknown-x', status: 'cancelled' }),
    });
    expect(res.status).toBe(429);
    expect(Number(res.headers.get('retry-after'))).toBeGreaterThan(0);
    // The other container keeps its own window (per instance, like every limit here).
    expect((await callback(B, { requestId: 'e2e-unknown-y', status: 'cancelled' }, ip)).status).toBe(404);
  });
});

describe('deep-link callback URL on the containers', () => {
  it("comes from the container's RELAY_EXTERNAL_URL, never from a Host header the caller sends", async () => {
    for (const url of [A, B]) {
      const plain = decode((await createRequest(url)).deepLink).callbackUrl as string;
      expect(plain).toMatch(/^https?:\/\/[^/]+\/api\/v1\/proof\/callback$/);
      const hostile = await postRequest(url, await signedBody(url), { Host: 'evil.example', 'X-Forwarded-Host': 'evil.example', 'X-Forwarded-Proto': 'https' });
      expect(hostile.status).toBe(201);
      const link = decode(hostile.body.deepLink as string);
      expect(link.callbackUrl).toBe(plain);
      expect(String(link.callbackUrl)).not.toContain('evil.example');
    }
  });
});
