import { describe, it, expect } from 'vitest';
import { CIRCUIT_NEEDS_WALLET_SIGNATURE } from '@zkproofport-app/sdk/circuits';
import { SIGNATURE_POLICY } from '../index';

/**
 * The relay decides for itself whether a circuit needs a wallet signature, and
 * this proves its answer is the same as the SDK's.
 *
 * Both declare the policy, deliberately. The relay is a security boundary: an
 * auth rule that a published npm package can flip is not a rule, so it does not
 * import the SDK's record — it writes its own and is checked against it here.
 * The SDK's copy exists so a dapp gets "Signer not set" locally instead of a
 * relay 401 two round trips later.
 *
 * Before this existed, both were typed-out arrays and the SDK's had missed
 * `arc_eligibility` while the relay's had it. Nothing noticed.
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
