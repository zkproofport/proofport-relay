import { describe, it, expect } from 'vitest';
import { createHash } from 'crypto';
import {
  canonicalJson,
  computeInputsHashes,
  computeInputsHashV2,
  computeLegacyInputsHash,
  InputsNotJsonError,
  InputsTooDeepError,
  MAX_INPUTS_DEPTH,
} from '../inputsHash';

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

/**
 * What every shipped app computes (proofport-app src/utils/deeplink.ts,
 * validateRequestWithRelay, identical in app-v1.3.0 through main on
 * 2026-10-27). Written out here, not imported, so a change to the relay's
 * legacy hash cannot quietly change the expectation with it.
 */
const appHash = (inputs: Record<string, unknown>) => sha256(JSON.stringify(inputs, Object.keys(inputs).sort()));

function nested(depth: number): unknown {
  let v: unknown = 1;
  for (let i = 0; i < depth; i++) v = [v];
  return v;
}

/** The giwa_attestation shape: the action is a nested object. */
const giwa = (value: string) => ({
  scope: 'dapp.example',
  userAddress: '0x1111111111111111111111111111111111111111',
  action: { kind: 'transfer', to: '0x2222222222222222222222222222222222222222', value, chainId: 91342 },
});

describe('legacy inputsHash: byte-for-byte what shipped apps compute', () => {
  it.each([
    ['flat', { scope: 'myapp.com', userAddress: '0x1234' }],
    ['country', { scope: 's', countryList: ['US', 'KR'], isIncluded: true }],
    ['nested action', giwa('1')],
    ['empty', {}],
    ['UTF-8', { scope: '홍길동 🪪 Ωmega\n\t' }],
  ])('%s', (_name, inputs) => {
    expect(computeLegacyInputsHash(inputs)).toBe(appHash(inputs));
    expect(computeInputsHashes(inputs).legacy).toBe(appHash(inputs));
  });

  it('pinned vector: a change to the legacy algorithm fails here, not on a phone', () => {
    expect(computeLegacyInputsHash({ scope: 'myapp.com', userAddress: '0x1234' }))
      .toBe(sha256('{"scope":"myapp.com","userAddress":"0x1234"}'));
    // The defect, preserved on purpose: the nested action is reduced to the
    // keys that also exist at the top level -- none here.
    expect(computeLegacyInputsHash(giwa('1'))).toBe(sha256(
      '{"action":{},"scope":"dapp.example","userAddress":"0x1111111111111111111111111111111111111111"}',
    ));
  });

  it('records the defect: two different nested actions hash the same', () => {
    expect(computeLegacyInputsHash(giwa('1'))).toBe(computeLegacyInputsHash(giwa('1000000')));
  });
});

describe('inputsHashV2: canonical at every depth', () => {
  it('matches an independently written canonical string', () => {
    const inputs = { scope: 'demo.example', b: [3, 1, { z: true, a: null }], a: { y: '나이', x: 1.5 } };
    const expected = '{"a":{"x":1.5,"y":"나이"},"b":[3,1,{"a":null,"z":true}],"scope":"demo.example"}';
    expect(canonicalJson(inputs)).toBe(expected);
    expect(computeInputsHashV2(inputs)).toBe(sha256(expected));
  });

  it('a change inside a nested object changes it (the defect this fixes)', () => {
    expect(computeInputsHashV2(giwa('1'))).not.toBe(computeInputsHashV2(giwa('1000000')));
    expect(computeInputsHashV2({ a: { x: 1 } })).not.toBe(computeInputsHashV2({ a: { x: 2 } }));
    // An object inside an array, too.
    expect(computeInputsHashV2({ list: [{ x: 1 }] })).not.toBe(computeInputsHashV2({ list: [{ x: 2 }] }));
  });

  it('equals the legacy hash whenever no object is nested, so flat requests cannot disagree', () => {
    for (const inputs of [{}, { scope: 's' }, { scope: 's', countryList: ['KR', 'US'], isIncluded: false, n: 0, z: null }]) {
      expect(computeInputsHashV2(inputs)).toBe(computeLegacyInputsHash(inputs));
    }
    expect(computeInputsHashV2(giwa('1'))).not.toBe(computeLegacyInputsHash(giwa('1')));
  });

  it('is independent of key order at every depth', () => {
    expect(computeInputsHashV2({ a: 1, b: { c: 2, d: [{ e: 1, f: 2 }] } }))
      .toBe(computeInputsHashV2({ b: { d: [{ f: 2, e: 1 }], c: 2 }, a: 1 }));
  });

  it('depends on array order', () => {
    expect(computeInputsHashV2({ list: ['KR', 'US'] })).not.toBe(computeInputsHashV2({ list: ['US', 'KR'] }));
  });

  it('keeps UTF-8 exact: Korean, emoji, mixed scripts, newline and tab', () => {
    const v = { name: '홍길동 🪪 Ωmega', note: 'line1\nline2\tend' };
    expect(JSON.parse(canonicalJson(v))).toEqual(v);
    expect(computeInputsHashV2(v)).not.toBe(computeInputsHashV2({ ...v, name: '홍길동 🪪 Omega' }));
  });

  it('sorts keys by UTF-16 code unit, as Array.prototype.sort does', () => {
    expect(canonicalJson({ b: 1, B: 2, '가': 3, a: 4, '🪪': 5 })).toBe('{"B":2,"a":4,"b":1,"가":3,"🪪":5}');
  });

  it('hostile strings are serialised, never interpreted', () => {
    const v = { scope: '%_\\\'; DROP TABLE x;-- <script>alert(1)</script>\u0000\u001f' };
    expect(JSON.parse(canonicalJson(v))).toEqual(v);
  });

  it('an empty object hashes as "{}"', () => {
    expect(computeInputsHashV2({})).toBe(sha256('{}'));
  });

  it(`accepts exactly ${MAX_INPUTS_DEPTH} levels of nesting under the top object and refuses one more`, () => {
    expect(() => canonicalJson({ v: nested(MAX_INPUTS_DEPTH - 1) })).not.toThrow();
    expect(() => canonicalJson({ v: nested(MAX_INPUTS_DEPTH) })).toThrow(InputsTooDeepError);
  });

  it('refuses a body of 200 000 nested arrays without overflowing the stack, and before the legacy hash runs', () => {
    const deep = JSON.parse('['.repeat(200_000) + ']'.repeat(200_000));
    expect(() => computeInputsHashes({ deep })).toThrow(InputsTooDeepError);
  });

  it('refuses values JSON cannot carry (unreachable from a parsed body)', () => {
    expect(() => canonicalJson({ n: Number.NaN })).toThrow(InputsNotJsonError);
    expect(() => canonicalJson({ n: Number.POSITIVE_INFINITY })).toThrow(InputsNotJsonError);
    expect(() => canonicalJson({ u: undefined as unknown as string })).toThrow(InputsNotJsonError);
    expect(() => canonicalJson({ f: (() => 1) as unknown as string })).toThrow(InputsNotJsonError);
  });

  it('treats "__proto__" as an ordinary key when it arrives from JSON', () => {
    const v = JSON.parse('{"__proto__":{"x":1},"a":2}');
    expect(canonicalJson(v)).toBe('{"__proto__":{"x":1},"a":2}');
  });

  it('a 900 KB flat input hashes (the body limit is 1 MB)', () => {
    const big = { scope: 'x'.repeat(900_000) };
    expect(computeInputsHashV2(big)).toBe(sha256(JSON.stringify(big)));
  });
});
