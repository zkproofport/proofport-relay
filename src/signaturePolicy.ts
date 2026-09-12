import type { CircuitId } from '@zkproofport-app/sdk/circuits';

/**
 * Whether a circuit's request must arrive with a wallet signature.
 *
 * ENVELOPE information -- who sent this -- not proof content. The relay still
 * never looks inside `inputs`; see the inspection-scope rule in
 * .claude/agents/relay-dev.md.
 *
 * Keyed by the SDK's `CircuitId`, and that is the load-bearing part. The two
 * arrays this replaced were typed out by hand with no dependency on the SDK at
 * all, so a circuit added to the SDK reached the check below, matched neither
 * array and was refused -- correct, but silent, and nobody learned that a
 * decision was waiting. As a `Record<CircuitId, boolean>` a new circuit is a
 * COMPILE error here until somebody decides which it is. The decision stays a
 * person's: guessing it wrong either demands a signature nobody can produce,
 * or forwards an unauthenticated request.
 */
export const SIGNATURE_POLICY = {
  coinbase_attestation: true,
  coinbase_country_attestation: true,
  // Same Coinbase-attested wallet; the signature is over an EIP-712 action
  // instead of signal_hash, which changes nothing the relay can see.
  arc_eligibility: true,
  // The signature is inside the OIDC identity token, checked by the prover.
  oidc_domain_attestation: false,
  // Web2 (OmniOne CX) flows with no wallet binding at all.
  mdl_kr_ownership: false,
  mdl_kr_age: false,
  mdl_kr_region: false,
  giwa_attestation: false,
  // `satisfies` and not an annotation: an annotation on the const would be
  // checked THROUGH Object.freeze(), which is a generic call and so swallows
  // excess-property checking. That version compiled cleanly against an SDK
  // with no `arc_eligibility` at all -- a guard that looked like it bit and
  // did not. `satisfies` checks both directions on the literal: a circuit the
  // SDK added and nobody classified, and a key naming a circuit the installed
  // SDK has never heard of.
} satisfies Record<CircuitId, boolean>;

/** The frozen view the request path reads. */
export const NEEDS_WALLET_SIGNATURE: Readonly<Record<CircuitId, boolean>> =
  Object.freeze(SIGNATURE_POLICY);
