/**
 * The callback's `signerVariant` field, checked without Redis: field checks
 * run before the request is looked up, so an invalid value is a 400 whatever
 * the request id. Storing and returning a valid one is covered against real
 * Redis in relay-hardening.integration.test.ts.
 */
import { describe, it, expect, afterEach } from 'vitest';
import type { AddressInfo } from 'net';
import type Redis from 'ioredis';
import { createRelay } from '../app';
import { EDGES } from '../edge';
import { describeBody } from '../mask';
import { SIGNER_VARIANTS } from '../types';

const throwingRedis = new Proxy({}, {
  get(_t, prop) {
    if (prop === 'then') return undefined;
    return () => { throw new Error(`redis.${String(prop)} called in a test that must not reach Redis`); };
  },
}) as unknown as Redis;

const closers: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const c of closers.splice(0)) await c();
});

async function start(): Promise<string> {
  const relay = createRelay({
    redis: throwingRedis,
    stats: { record() {} },
    statsToken: 'k'.repeat(64),
    statsAuth: { lockedFor: async () => 0, recordFailure: async () => 1 },
    adapter: null,
    edge: EDGES.local,
    relayExternalUrl: 'https://relay.example.test',
    deadlineMs: 3_600_000,
    sweepIntervalMs: 3_600_000,
    playIntegrity: { enabled: false, missing: ['PLAY_INTEGRITY_DECRYPTION_KEY', 'PLAY_INTEGRITY_VERIFICATION_KEY'] },
  });
  await new Promise<void>((resolve) => relay.httpServer.listen(0, '127.0.0.1', resolve));
  closers.push(() => relay.close());
  return `http://127.0.0.1:${(relay.httpServer.address() as AddressInfo).port}`;
}

const MESSAGE = 'signerVariant must be one of standard, android, android_factory';

describe('callback signerVariant', () => {
  it('the allowed values are exactly the three the SDK names', () => {
    expect([...SIGNER_VARIANTS]).toEqual(['standard', 'android', 'android_factory']);
  });

  it.each([
    ['unknown word', 'ios'],
    ['hyphenated', 'android-factory'],
    ['upper case', 'Android'],
    ['padded', ' android'],
    ['empty', ''],
    ['null', null],
    ['number', 1],
    ['array', ['android']],
    ['object', { variant: 'android' }],
    ['HTML', '<script>alert(1)</script>'],
    ['Korean', '안드로이드'],
    ['very long', 'a'.repeat(100_000)],
  ])('%s -> 400 naming the allowed values, before any lookup', async (_name, signerVariant) => {
    const url = await start();
    const res = await fetch(`${url}/api/v1/proof/callback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ requestId: 'r-1', status: 'completed', proof: '0x01', publicInputs: [], signerVariant }),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: MESSAGE });
  });

  it('is logged as an envelope field', () => {
    expect(describeBody({ requestId: 'r', signerVariant: 'android_factory', proof: '0xdead' })).toContain('signerVariant=android_factory');
  });
});
