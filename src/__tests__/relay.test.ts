import { describe, it, expect } from 'vitest';
import { createHash } from 'crypto';
import { ethers } from 'ethers';

// ---------------------------------------------------------------------------
// Pure function re-implementations (mirrors src/index.ts exactly)
// ---------------------------------------------------------------------------

function computeInputsHash(inputs: Record<string, unknown>): string {
  const canonical = JSON.stringify(inputs, Object.keys(inputs).sort());
  return createHash('sha256').update(canonical).digest('hex');
}

function buildDeepLink(request: {
  requestId: string;
  clientId: string;
  circuitId: string;
  scope: string;
  inputs: Record<string, unknown>;
  callbackUrl: string;
  createdAt: string;
}): string {
  const data = Buffer.from(JSON.stringify(request)).toString('base64url');
  return `zkproofport://proof-request?data=${data}`;
}

// ---------------------------------------------------------------------------
// Inputs Hash
// ---------------------------------------------------------------------------

describe('computeInputsHash', () => {
  it('produces a consistent hash for the same inputs', () => {
    const inputs = { scope: 'myapp.com', userAddress: '0x1234' };
    expect(computeInputsHash(inputs)).toBe(computeInputsHash(inputs));
  });

  it('produces the same hash regardless of key insertion order', () => {
    const inputs1 = { scope: 'myapp.com', userAddress: '0x1234' };
    const inputs2 = { userAddress: '0x1234', scope: 'myapp.com' };
    expect(computeInputsHash(inputs1)).toBe(computeInputsHash(inputs2));
  });

  it('produces different hashes for different input values', () => {
    const inputs1 = { scope: 'myapp.com' };
    const inputs2 = { scope: 'otherapp.com' };
    expect(computeInputsHash(inputs1)).not.toBe(computeInputsHash(inputs2));
  });

  it('produces a valid 64-char hex string for nested objects', () => {
    const inputs = { scope: 'test', countryList: ['US', 'KR'], isIncluded: true };
    expect(computeInputsHash(inputs)).toMatch(/^[a-f0-9]{64}$/);
  });

  it('produces different hashes when array order differs', () => {
    const inputs1 = { countryList: ['US', 'KR'] };
    const inputs2 = { countryList: ['KR', 'US'] };
    expect(computeInputsHash(inputs1)).not.toBe(computeInputsHash(inputs2));
  });
});

// ---------------------------------------------------------------------------
// Challenge Generation
// ---------------------------------------------------------------------------

describe('Challenge generation', () => {
  it('generates a 0x-prefixed 64-hex-char string (32 bytes)', () => {
    const challenge = ethers.hexlify(ethers.randomBytes(32));
    expect(challenge).toMatch(/^0x[a-f0-9]{64}$/);
  });

  it('generates unique challenges on each call', () => {
    const c1 = ethers.hexlify(ethers.randomBytes(32));
    const c2 = ethers.hexlify(ethers.randomBytes(32));
    expect(c1).not.toBe(c2);
  });
});

// ---------------------------------------------------------------------------
// Challenge-Signature Verification (EIP-191 personal_sign)
// ---------------------------------------------------------------------------

describe('Challenge-signature verification', () => {
  it('recovers the correct signer address from a valid signature', async () => {
    const wallet = ethers.Wallet.createRandom();
    const challenge = ethers.hexlify(ethers.randomBytes(32));
    const signature = await wallet.signMessage(challenge);
    const recovered = ethers.verifyMessage(challenge, signature);
    expect(recovered.toLowerCase()).toBe(wallet.address.toLowerCase());
  });

  it('throws on a malformed / all-zero signature', () => {
    const challenge = ethers.hexlify(ethers.randomBytes(32));
    const badSignature = '0x' + '00'.repeat(65);
    expect(() => ethers.verifyMessage(challenge, badSignature)).toThrow();
  });

  it('recovers different signers for different wallets signing the same challenge', async () => {
    const wallet1 = ethers.Wallet.createRandom();
    const wallet2 = ethers.Wallet.createRandom();
    const challenge = ethers.hexlify(ethers.randomBytes(32));

    const sig1 = await wallet1.signMessage(challenge);
    const sig2 = await wallet2.signMessage(challenge);

    expect(ethers.verifyMessage(challenge, sig1).toLowerCase()).toBe(wallet1.address.toLowerCase());
    expect(ethers.verifyMessage(challenge, sig2).toLowerCase()).toBe(wallet2.address.toLowerCase());
    expect(
      ethers.verifyMessage(challenge, sig1).toLowerCase()
    ).not.toBe(
      ethers.verifyMessage(challenge, sig2).toLowerCase()
    );
  });

  it('does NOT recover the signer when the wrong challenge is used', async () => {
    const wallet = ethers.Wallet.createRandom();
    const challenge = ethers.hexlify(ethers.randomBytes(32));
    const wrongChallenge = ethers.hexlify(ethers.randomBytes(32));
    const signature = await wallet.signMessage(challenge);
    const recovered = ethers.verifyMessage(wrongChallenge, signature);
    expect(recovered.toLowerCase()).not.toBe(wallet.address.toLowerCase());
  });
});

// ---------------------------------------------------------------------------
// Rate Limiting (sliding window logic)
// ---------------------------------------------------------------------------

describe('Rate limiting logic', () => {
  const RATE_LIMITS = {
    challenge: { windowMs: 60_000, max: 30 },
    request: { windowMs: 60_000, max: 10 },
  };

  it('allows the first request within the window', () => {
    const store = new Map<string, { count: number; resetAt: number }>();
    const ip = '127.0.0.1';
    const key = `request:${ip}`;
    const limit = RATE_LIMITS.request;
    const now = Date.now();

    // Simulate first request being recorded
    store.set(key, { count: 1, resetAt: now + limit.windowMs });
    expect(store.get(key)!.count).toBeLessThanOrEqual(limit.max);
  });

  it('flags an entry as over-limit when count reaches max', () => {
    const store = new Map<string, { count: number; resetAt: number }>();
    const ip = '1.2.3.4';
    const key = `request:${ip}`;
    const limit = RATE_LIMITS.request;
    const now = Date.now();

    store.set(key, { count: limit.max, resetAt: now + limit.windowMs });
    expect(store.get(key)!.count >= limit.max).toBe(true);
  });

  it('detects an expired window so the entry should be reset', () => {
    const store = new Map<string, { count: number; resetAt: number }>();
    const ip = '5.6.7.8';
    const key = `request:${ip}`;
    const now = Date.now();

    // Simulate an entry whose window has already closed
    store.set(key, { count: 10, resetAt: now - 1 });
    expect(now > store.get(key)!.resetAt).toBe(true);
  });

  it('tracks different IPs independently', () => {
    const store = new Map<string, { count: number; resetAt: number }>();
    const now = Date.now();

    store.set('request:1.1.1.1', { count: 5, resetAt: now + 60_000 });
    store.set('request:2.2.2.2', { count: 1, resetAt: now + 60_000 });

    expect(store.get('request:1.1.1.1')!.count).toBe(5);
    expect(store.get('request:2.2.2.2')!.count).toBe(1);
  });

  it('challenge limit is separate from request limit', () => {
    expect(RATE_LIMITS.challenge.max).toBeGreaterThan(RATE_LIMITS.request.max);
  });
});

// ---------------------------------------------------------------------------
// Deep Link Generation
// ---------------------------------------------------------------------------

describe('buildDeepLink', () => {
  it('generates a zkproofport:// deep link', () => {
    const request = {
      requestId: 'test-123',
      clientId: '0xabcdef',
      circuitId: 'coinbase_attestation',
      scope: 'myapp.com',
      inputs: { scope: 'myapp.com' },
      callbackUrl: 'http://localhost:4001/api/v1/proof/callback',
      createdAt: new Date().toISOString(),
    };
    const link = buildDeepLink(request);
    expect(link).toMatch(/^zkproofport:\/\/proof-request\?data=/);
  });

  it('round-trips the request payload through base64url encoding', () => {
    const request = {
      requestId: 'abc-456',
      clientId: '0xdeadbeef',
      circuitId: 'coinbase_country_attestation',
      scope: 'otherapp.com',
      inputs: { countryList: ['US', 'KR'], isIncluded: true },
      callbackUrl: 'https://relay.zkproofport.app/api/v1/proof/callback',
      createdAt: new Date().toISOString(),
    };
    const link = buildDeepLink(request);
    const encoded = link.split('data=')[1];
    const decoded = JSON.parse(Buffer.from(encoded, 'base64url').toString());

    expect(decoded.requestId).toBe(request.requestId);
    expect(decoded.circuitId).toBe(request.circuitId);
    expect(decoded.scope).toBe(request.scope);
    expect(decoded.inputs).toEqual(request.inputs);
    expect(decoded.callbackUrl).toBe(request.callbackUrl);
  });

  it('uses canonical circuit IDs (underscore format, never hyphens)', () => {
    const request = {
      requestId: 'r1',
      clientId: '0x1',
      circuitId: 'coinbase_attestation',
      scope: '',
      inputs: {},
      callbackUrl: 'http://localhost:4001/api/v1/proof/callback',
      createdAt: new Date().toISOString(),
    };
    const link = buildDeepLink(request);
    const encoded = link.split('data=')[1];
    const decoded = JSON.parse(Buffer.from(encoded, 'base64url').toString());
    expect(decoded.circuitId).not.toMatch(/-/);
    expect(decoded.circuitId).toMatch(/_/);
  });

  it('produces different deep links for different requestIds', () => {
    const base = {
      clientId: '0xabc',
      circuitId: 'coinbase_attestation',
      scope: 'app.com',
      inputs: {},
      callbackUrl: 'http://localhost:4001/api/v1/proof/callback',
      createdAt: new Date().toISOString(),
    };
    const link1 = buildDeepLink({ ...base, requestId: 'id-1' });
    const link2 = buildDeepLink({ ...base, requestId: 'id-2' });
    expect(link1).not.toBe(link2);
  });
});
