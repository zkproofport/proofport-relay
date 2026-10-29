import { describe, expect, it } from 'vitest';
import { REQUEST_DEADLINE_MS, SWEEP_INTERVAL_MS } from '../app';
import { RESULT_TTL_SECONDS, STATUS_TTL_SECONDS } from '../lifecycle';

/**
 * The SDK's default wait in `waitForProof()` / `waitForResult()`
 * (`proofport-app-sdk/src/ProofportSDK.ts`). The relay does not depend on the
 * SDK, so the number is written here; the SDK has its own test pinning it.
 */
const SDK_DEFAULT_WAIT_MS = 600_000;

/** The client's poll interval plus a cross-instance publish, rounded up. */
const DELIVERY_MARGIN_MS = 10_000;

describe('request deadline', () => {
  it('is 540 s', () => {
    expect(REQUEST_DEADLINE_MS).toBe(540_000);
  });

  it('answers the dApp before the SDK stops waiting', () => {
    expect(REQUEST_DEADLINE_MS + SWEEP_INTERVAL_MS + DELIVERY_MARGIN_MS).toBeLessThan(SDK_DEFAULT_WAIT_MS);
  });

  it('expires a request while Redis still holds its status and meta', () => {
    // The sweep reads both; the latest it runs is one interval after the deadline.
    expect(REQUEST_DEADLINE_MS + SWEEP_INTERVAL_MS).toBeLessThan(STATUS_TTL_SECONDS * 1000);
  });

  it('keeps the terminal answer readable after it is written', () => {
    // Both are counted from the moment the answer is written, not from creation.
    expect(RESULT_TTL_SECONDS).toBeGreaterThan(0);
    expect(STATUS_TTL_SECONDS).toBeGreaterThanOrEqual(RESULT_TTL_SECONDS);
  });
});
