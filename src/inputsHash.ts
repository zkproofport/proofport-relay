import { createHash } from 'crypto';

/**
 * Hashes of a request's `inputs`, returned by GET /api/v1/proof/:requestId so
 * the app can check that the deep link it opened carries the inputs the dApp
 * sent to the relay. The relay never READS the inputs: it serialises them.
 *
 * Two hashes are published, side by side:
 *
 *   inputsHash    LEGACY. sha256 of `JSON.stringify(inputs, Object.keys(inputs).sort())`.
 *                 An array replacer is an allowlist applied at EVERY depth,
 *                 so a nested object keeps only the keys that also appear at
 *                 the top level: `{a: {x: 1}}` and `{a: {x: 2}}` hash the
 *                 same, and `giwa_attestation` / `dojang_playground`'s
 *                 `inputs.action` is not covered at all. It stays, byte for
 *                 byte, because every shipped app (app-v1.4.0 and earlier,
 *                 src/utils/deeplink.ts `validateRequestWithRelay`) recomputes
 *                 exactly this and refuses the request as tampered when it
 *                 differs. Changing it would make those apps refuse every
 *                 request whose inputs contain a nested object.
 *
 *   inputsHashV2  sha256 of the canonical JSON: object keys sorted (default
 *                 string order, UTF-16 code units) at every depth, arrays in
 *                 their given order, no whitespace, numbers and strings as
 *                 JSON.stringify writes them -- the ordering and number form
 *                 of RFC 8785 (JCS) for any value that came out of JSON.parse.
 *                 This is the one an app should check. Same algorithm as
 *                 kproof-server's src/relay/inputsHash.ts.
 *
 * For inputs with no nested object the two serialisations are identical, so
 * the two hashes are equal; they differ exactly when nesting exists.
 *
 * Depth is capped: a 1 MB body of nested arrays is enough to overflow any
 * recursive serialiser's stack. A structural cap is envelope protection, not
 * a judgement about any circuit's fields.
 */
export const MAX_INPUTS_DEPTH = 32;

export class InputsTooDeepError extends Error {
  constructor() {
    super(`inputs are nested more than ${MAX_INPUTS_DEPTH} levels deep`);
    this.name = 'InputsTooDeepError';
  }
}

/** A value JSON cannot carry. Unreachable from a parsed JSON body; kept so a direct caller fails loudly. */
export class InputsNotJsonError extends TypeError {
  constructor(what: string) {
    super(`inputs contain ${what}`);
    this.name = 'InputsNotJsonError';
  }
}

export function canonicalJson(value: unknown, depth = 0): string {
  if (depth > MAX_INPUTS_DEPTH) throw new InputsTooDeepError();
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new InputsNotJsonError('a non-finite number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item, depth + 1)).join(',')}]`;
  }
  if (typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(record[k], depth + 1)}`).join(',')}}`;
  }
  throw new InputsNotJsonError(`a value JSON cannot carry (${typeof value})`);
}

function sha256Hex(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}

/** The canonical hash. Throws InputsTooDeepError / InputsNotJsonError on input it cannot serialise. */
export function computeInputsHashV2(inputs: Record<string, unknown>): string {
  return sha256Hex(canonicalJson(inputs));
}

/**
 * The hash shipped apps recompute. Do not "fix" it: see the file comment.
 * Call computeInputsHashV2 first, which enforces the depth cap this one lacks.
 */
export function computeLegacyInputsHash(inputs: Record<string, unknown>): string {
  return sha256Hex(JSON.stringify(inputs, Object.keys(inputs).sort()));
}

export interface InputsHashes {
  legacy: string;
  v2: string;
}

export function computeInputsHashes(inputs: Record<string, unknown>): InputsHashes {
  const v2 = computeInputsHashV2(inputs);
  return { legacy: computeLegacyInputsHash(inputs), v2 };
}
