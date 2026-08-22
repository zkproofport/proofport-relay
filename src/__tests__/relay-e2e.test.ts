/**
 * E2E tests for relay challenge-signature auth flow.
 * These tests hit real running Docker containers via HTTP.
 *
 * Prerequisites:
 *   ./scripts/dev.sh   (starts redis + relay containers)
 *
 * Run:
 *   npx vitest run src/__tests__/relay-e2e.test.ts
 *
 * NOTE: POST /api/v1/proof/request is rate limited to 10 per minute per IP
 * (RATE_LIMITS.request in src/index.ts) and this suite makes exactly 10 of
 * them — there is no headroom. Two runs inside the same minute will 429, and
 * any new test that posts a proof request must either replace an existing one
 * or come with a raised limit. `expectCreated()` reports a 429 as such instead
 * of leaving a bare "expected 429 to be 201".
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { ethers } from 'ethers';
import { createHash } from 'crypto';

const RELAY_URL = process.env.RELAY_URL || 'http://localhost:4001';

interface ChallengeData {
  /** Session id issued with the challenge; every proof request must echo it back. */
  requestId: string;
  challenge: string;
  expiresAt: number;
}

interface RequestData {
  requestId: string;
  deepLink: string;
  status: string;
  pollUrl: string;
}

interface PollData {
  requestId: string;
  status: string;
  inputsHash?: string;
  proof?: string;
  publicInputs?: string[];
  circuit?: string;
  error?: string;
}

interface ErrorData {
  error: string;
}

function computeInputsHash(inputs: Record<string, unknown>): string {
  const canonical = JSON.stringify(inputs, Object.keys(inputs).sort());
  return createHash('sha256').update(canonical).digest('hex');
}

async function getChallenge(): Promise<ChallengeData> {
  const res = await fetch(`${RELAY_URL}/api/v1/challenge`);
  return res.json() as Promise<ChallengeData>;
}

/** Asserts a 201, turning a rate-limit response into an actionable message. */
async function expectCreated(res: Response): Promise<RequestData> {
  if (res.status === 429) {
    throw new Error(
      'Relay returned 429: POST /api/v1/proof/request is capped at 10/min per IP. ' +
        'Wait for the window to reset before re-running this suite.',
    );
  }
  expect(res.status).toBe(201);
  return res.json() as Promise<RequestData>;
}

describe('Relay E2E: Challenge-Signature Auth Flow', () => {
  let wallet: ethers.HDNodeWallet;

  beforeAll(async () => {
    const res = await fetch(`${RELAY_URL}/health`);
    if (!res.ok) throw new Error(`Relay not healthy: ${res.status}`);
    wallet = ethers.Wallet.createRandom();
  });

  describe('GET /api/v1/challenge', () => {
    it('returns a 32-byte hex challenge with expiresAt', async () => {
      const res = await fetch(`${RELAY_URL}/api/v1/challenge`);
      expect(res.ok).toBe(true);
      const data = await res.json() as ChallengeData;
      expect(data.challenge).toMatch(/^0x[a-f0-9]{64}$/);
      expect(data.expiresAt).toBeGreaterThan(Date.now());
    });
  });

  describe('Full proof request lifecycle', () => {
    it('creates a proof request with challenge+signature and polls it', async () => {
      const { requestId, challenge } = await getChallenge();
      const signature = await wallet.signMessage(challenge);
      const inputs = { scope: '0xabc', countryList: ['US', 'KR'] };

      const requestRes = await fetch(`${RELAY_URL}/api/v1/proof/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ requestId, circuitId: 'coinbase_attestation', inputs, challenge, signature, returnScheme: 'MyDapp://' }),
      });

      const requestData = await expectCreated(requestRes);
      expect(requestData.requestId).toBe(requestId);

      // returnScheme rides inside the base64url deep-link payload, normalised.
      const encoded = new URL(requestData.deepLink).searchParams.get('data')!;
      const decoded = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf-8'));
      expect(decoded.returnScheme).toBe('mydapp://');
      expect(requestData.deepLink).toContain('zkproofport://');
      expect(requestData.status).toBe('pending');
      expect(requestData.pollUrl).toBe(`/api/v1/proof/${requestData.requestId}`);

      const pollRes = await fetch(`${RELAY_URL}/api/v1/proof/${requestData.requestId}`);
      expect(pollRes.ok).toBe(true);
      const pollData = await pollRes.json() as PollData;
      expect(pollData.status).toBe('pending');
      expect(pollData.requestId).toBe(requestData.requestId);

      const expectedHash = computeInputsHash(inputs);
      expect(pollData.inputsHash).toBe(expectedHash);
    });

    it('rejects proof request without challenge', async () => {
      const res = await fetch(`${RELAY_URL}/api/v1/proof/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ circuitId: 'coinbase_attestation', inputs: { scope: '0xabc' } }),
      });
      expect(res.status).toBe(401);
      const data = await res.json() as ErrorData;
      expect(data.error).toContain('requestId and challenge are required');
    });

    it('rejects proof request with invalid signature', async () => {
      const { requestId, challenge } = await getChallenge();
      const res = await fetch(`${RELAY_URL}/api/v1/proof/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          requestId,
          circuitId: 'coinbase_attestation',
          inputs: { scope: '0xabc' },
          challenge,
          signature: '0xinvalidsignature',
        }),
      });
      expect(res.status).toBe(401);
    });

    it('rejects a reused session (one-time use)', async () => {
      const { requestId, challenge } = await getChallenge();
      const signature = await wallet.signMessage(challenge);
      // Carries the exact value proofport-app-demo sends in production
      // (`window.location.origin` on demo.zkproofport.app). Asserted on this
      // request rather than in its own test because the suite has no headroom
      // under the 10/min POST cap — see the file header.
      const body = JSON.stringify({ requestId, circuitId: 'coinbase_attestation', inputs: { scope: '0xabc' }, challenge, signature, returnScheme: 'https://demo.zkproofport.app' });

      const res1 = await fetch(`${RELAY_URL}/api/v1/proof/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      });
      const created = await expectCreated(res1);

      // The https-origin form survives the relay untouched, all the way into
      // the base64url deep-link payload the app will parse.
      const demoEncoded = new URL(created.deepLink).searchParams.get('data')!;
      const demoDecoded = JSON.parse(Buffer.from(demoEncoded, 'base64url').toString('utf-8'));
      expect(demoDecoded.returnScheme).toBe('https://demo.zkproofport.app');

      // The session flips pending -> claimed on first use, so the replay is a
      // 409, not the 401 the pre-session challenge flow used to return.
      const res2 = await fetch(`${RELAY_URL}/api/v1/proof/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      });
      expect(res2.status).toBe(409);
      const data = await res2.json() as ErrorData;
      expect(data.error).toContain('Session already used');
    });
  });

  describe('Return scheme', () => {
    it('rejects a URL-shaped returnScheme with 400', async () => {
      const { requestId, challenge } = await getChallenge();
      const signature = await wallet.signMessage(challenge);

      const res = await fetch(`${RELAY_URL}/api/v1/proof/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          requestId,
          circuitId: 'coinbase_attestation',
          inputs: { scope: '0xabc' },
          challenge,
          signature,
          returnScheme: 'https://evil.example.com/pay?amount=1000',
        }),
      });

      expect(res.status).toBe(400);
      const data = await res.json() as ErrorData;
      expect(data.error).toContain('returnScheme');
    });
  });

  describe('Proof callback', () => {
    it('accepts callback and updates poll status to completed', async () => {
      const { requestId, challenge } = await getChallenge();
      const signature = await wallet.signMessage(challenge);

      const requestRes = await fetch(`${RELAY_URL}/api/v1/proof/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ requestId, circuitId: 'coinbase_attestation', inputs: { scope: '0xabc' }, challenge, signature }),
      });
      await expectCreated(requestRes);

      const callbackRes = await fetch(`${RELAY_URL}/api/v1/proof/callback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          requestId,
          status: 'completed',
          proof: '0xdeadbeef',
          publicInputs: ['0x1', '0x2'],
          verifierAddress: '0x1234567890abcdef1234567890abcdef12345678',
          chainId: 84532,
          circuit: 'coinbase_attestation',
        }),
      });
      expect(callbackRes.ok).toBe(true);

      const pollRes = await fetch(`${RELAY_URL}/api/v1/proof/${requestId}`);
      const pollData = await pollRes.json() as PollData;
      expect(pollData.status).toBe('completed');
      expect(pollData.proof).toBe('0xdeadbeef');
      expect(pollData.publicInputs).toEqual(['0x1', '0x2']);
      expect(pollData.circuit).toBe('coinbase_attestation');
    });

    it('rejects callback for unknown requestId', async () => {
      const res = await fetch(`${RELAY_URL}/api/v1/proof/callback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ requestId: 'nonexistent-request-id', status: 'completed' }),
      });
      expect(res.status).toBe(404);
    });
  });

  describe('Nonce replay protection', () => {
    it('rejects duplicate nonce', async () => {
      const nonce = `test-nonce-${Date.now()}`;

      const { requestId: id1, challenge: ch1 } = await getChallenge();
      const sig1 = await wallet.signMessage(ch1);
      const res1 = await fetch(`${RELAY_URL}/api/v1/proof/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ requestId: id1, circuitId: 'coinbase_attestation', inputs: { scope: '0xabc' }, challenge: ch1, signature: sig1, nonce }),
      });
      await expectCreated(res1);

      const { requestId: id2, challenge: ch2 } = await getChallenge();
      const sig2 = await wallet.signMessage(ch2);
      const res2 = await fetch(`${RELAY_URL}/api/v1/proof/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ requestId: id2, circuitId: 'coinbase_attestation', inputs: { scope: '0xabc' }, challenge: ch2, signature: sig2, nonce }),
      });
      expect(res2.status).toBe(409);
      const data = await res2.json() as ErrorData;
      expect(data.error).toContain('Duplicate nonce');
    });
  });

  describe('Deep link integrity (inputsHash)', () => {
    it('returns matching inputsHash for canonical JSON with sorted keys', async () => {
      const { requestId, challenge } = await getChallenge();
      const signature = await wallet.signMessage(challenge);
      const inputs = { zeta: 'last', alpha: 'first', middle: 'mid' };

      const requestRes = await fetch(`${RELAY_URL}/api/v1/proof/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ requestId, circuitId: 'coinbase_attestation', inputs, challenge, signature }),
      });
      await expectCreated(requestRes);

      const pollRes = await fetch(`${RELAY_URL}/api/v1/proof/${requestId}`);
      const pollData = await pollRes.json() as PollData;

      const expectedHash = computeInputsHash(inputs);
      expect(pollData.inputsHash).toBe(expectedHash);
    });
  });

  describe('Poll unknown requestId', () => {
    it('returns 404', async () => {
      const res = await fetch(`${RELAY_URL}/api/v1/proof/unknown-id-12345`);
      expect(res.status).toBe(404);
    });
  });
});
