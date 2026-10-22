import { describe, it, expect } from 'vitest';
import { CIRCUIT_NEEDS_WALLET_SIGNATURE } from '@zkproofport-app/core/circuits';
// From the policy module, not the server entry. Importing the entry boots the
// relay, which demands REDIS_URL and refuses to load -- so this file failed for
// a reason that had nothing to do with what it checks.
import { SIGNATURE_POLICY } from '../signaturePolicy';

/**
 * The relay decides for itself whether a circuit needs a wallet signature, and
 * this proves its answer is the same as the SDK's. The record is read from
 * `@zkproofport-app/core`, which the SDK re-exports unchanged, so the relay no
 * longer installs the SDK (and its off-chain verifier) just for these ids.
 *
 * Both declare the policy, deliberately. The relay is a security boundary: an
 * auth rule that a published npm package can flip is not a rule, so it does not
 * import the SDK's record — it writes its own and is checked against it here.
 * The SDK's copy exists so a dapp gets "Signer not set" locally instead of a
 * relay 401 two round trips later.
 *
 * Before this existed, both were typed-out arrays and the SDK's had missed a
 * circuit the relay's had. Nothing noticed.
 */
describe('the relay and the SDK agree on which circuits need a signature', () => {
  it('names the same circuits', () => {
    expect(Object.keys(SIGNATURE_POLICY).sort()).toEqual(
      Object.keys(CIRCUIT_NEEDS_WALLET_SIGNATURE).sort(),
    );
  });

  it('gives the same answer for each of them', () => {
    expect({ ...SIGNATURE_POLICY }).toEqual({ ...CIRCUIT_NEEDS_WALLET_SIGNATURE });
  });
});
