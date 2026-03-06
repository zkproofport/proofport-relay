/**
 * E2E tests for relay challenge-signature auth flow.
 * These tests hit real running Docker containers via HTTP.
 *
 * Prerequisites:
 *   ./scripts/dev.sh   (starts redis + relay containers)
 *
 * Run:
 *   npx vitest run src/__tests__/relay-e2e.test.ts
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { ethers } from 'ethers';
import { createHash } from 'crypto';

const RELAY_URL = process.env.RELAY_URL || 'http://localhost:4001';

interface ChallengeData {
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
      const { challenge } = await getChallenge();
      const signature = await wallet.signMessage(challenge);
      const inputs = { scope: '0xabc', countryList: ['US', 'KR'] };

      const requestRes = await fetch(`${RELAY_URL}/api/v1/proof/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ circuitId: 'coinbase_attestation', inputs, challenge, signature }),
      });

      expect(requestRes.status).toBe(201);
      const requestData = await requestRes.json() as RequestData;
      expect(requestData.requestId).toBeDefined();
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
      expect(data.error).toContain('challenge and signature are required');
    });

    it('rejects proof request with invalid signature', async () => {
      const { challenge } = await getChallenge();
      const res = await fetch(`${RELAY_URL}/api/v1/proof/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          circuitId: 'coinbase_attestation',
          inputs: { scope: '0xabc' },
          challenge,
          signature: '0xinvalidsignature',
        }),
      });
      expect(res.status).toBe(401);
    });

    it('rejects reused challenge (one-time use)', async () => {
      const { challenge } = await getChallenge();
      const signature = await wallet.signMessage(challenge);

      const res1 = await fetch(`${RELAY_URL}/api/v1/proof/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ circuitId: 'coinbase_attestation', inputs: { scope: '0xabc' }, challenge, signature }),
      });
      expect(res1.status).toBe(201);

      const res2 = await fetch(`${RELAY_URL}/api/v1/proof/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ circuitId: 'coinbase_attestation', inputs: { scope: '0xabc' }, challenge, signature }),
      });
      expect(res2.status).toBe(401);
      const data = await res2.json() as ErrorData;
      expect(data.error).toContain('expired');
    });
  });

  describe('Proof callback', () => {
    it('accepts callback and updates poll status to completed', async () => {
      const { challenge } = await getChallenge();
      const signature = await wallet.signMessage(challenge);

      const requestRes = await fetch(`${RELAY_URL}/api/v1/proof/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ circuitId: 'coinbase_attestation', inputs: { scope: '0xabc' }, challenge, signature }),
      });
      const { requestId } = await requestRes.json() as RequestData;

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

      const { challenge: ch1 } = await getChallenge();
      const sig1 = await wallet.signMessage(ch1);
      const res1 = await fetch(`${RELAY_URL}/api/v1/proof/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ circuitId: 'coinbase_attestation', inputs: { scope: '0xabc' }, challenge: ch1, signature: sig1, nonce }),
      });
      expect(res1.status).toBe(201);

      const { challenge: ch2 } = await getChallenge();
      const sig2 = await wallet.signMessage(ch2);
      const res2 = await fetch(`${RELAY_URL}/api/v1/proof/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ circuitId: 'coinbase_attestation', inputs: { scope: '0xabc' }, challenge: ch2, signature: sig2, nonce }),
      });
      expect(res2.status).toBe(409);
      const data = await res2.json() as ErrorData;
      expect(data.error).toContain('Duplicate nonce');
    });
  });

  describe('Deep link integrity (inputsHash)', () => {
    it('returns matching inputsHash for canonical JSON with sorted keys', async () => {
      const { challenge } = await getChallenge();
      const signature = await wallet.signMessage(challenge);
      const inputs = { zeta: 'last', alpha: 'first', middle: 'mid' };

      const requestRes = await fetch(`${RELAY_URL}/api/v1/proof/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ circuitId: 'coinbase_attestation', inputs, challenge, signature }),
      });
      expect(requestRes.status).toBe(201);
      const { requestId } = await requestRes.json() as RequestData;

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
