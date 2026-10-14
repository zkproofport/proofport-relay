import { describe, it, expect } from 'vitest';
import { describeBody, describeDeepLink, maskHex, maskIp, scrubError, scrubText } from '../mask';

const ADDRESS = '0x52908400098527886E0F7030069857D2E4169EE7';
const NULLIFIER = '0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8';

describe('maskIp', () => {
  it('keeps the first two IPv4 octets', () => {
    expect(maskIp('203.0.113.45')).toBe('203.0.x.x');
  });
  it('masks an IPv4-mapped IPv6 address as IPv4', () => {
    expect(maskIp('::ffff:198.51.100.7')).toBe('::ffff:198.51.x.x');
  });
  it('keeps the first three IPv6 groups, expanding ::', () => {
    expect(maskIp('2001:db8:85a3::8a2e:370:7334')).toBe('2001:db8:85a3:x:x:x:x:x');
    expect(maskIp('2001:0db8:85a3:0000:0000:8a2e:0370:7334')).toBe('2001:0db8:85a3:x:x:x:x:x');
  });
  it('masks loopback IPv6 without printing it raw', () => {
    expect(maskIp('::1')).toBe('0:0:0:x:x:x:x:x');
  });
  it('answers unknown for a missing IP, separately for undefined, null and empty', () => {
    expect(maskIp(undefined)).toBe('unknown');
    expect(maskIp(null)).toBe('unknown');
    expect(maskIp('')).toBe('unknown');
  });
});

describe('maskHex', () => {
  it('masks an address to 0x + 4 … 4', () => {
    expect(maskHex(ADDRESS)).toBe('0x5290…9EE7');
  });
  it('masks a 32-byte nullifier the same way', () => {
    expect(maskHex(NULLIFIER)).toBe('0x1c8a…eac8');
  });
  it('masks a bare sha256 digest', () => {
    expect(maskHex('a'.repeat(30) + 'b'.repeat(34))).toBe('aaaa…bbbb');
  });
  it('leaves short or non-hex values alone', () => {
    expect(maskHex('0xdeadbeef')).toBe('0xdeadbeef');
    expect(maskHex('coinbase_attestation')).toBe('coinbase_attestation');
    expect(maskHex(undefined)).toBe('undefined');
    expect(maskHex(null)).toBe('null');
  });
});

describe('scrubText', () => {
  it('masks an address, a hash, an IPv4 and an IPv6 inside one sentence', () => {
    const text = `wallet ${ADDRESS} nullifier ${NULLIFIER} from 203.0.113.45 and 2001:db8:85a3::8a2e:370:7334`;
    const out = scrubText(text);
    expect(out).toBe('wallet 0x5290…9EE7 nullifier 0x1c8a…eac8 from 203.0.x.x and 2001:db8:85a3:x:x:x:x:x');
  });
  it('masks the IPv4 part of a mapped address in text', () => {
    expect(scrubText('peer ::ffff:198.51.100.7 closed')).toBe('peer ::ffff:198.51.x.x closed');
  });
  it('masks an e-mail local part', () => {
    expect(scrubText('token for alice.smith@example.com expired')).toBe('token for a***@example.com expired');
  });
  it('does not mangle times, dates, UUIDs or circuit ids', () => {
    const text = '2026-10-14T13:21:03.000Z requestId=6f1c2b8e-1a2b-4c3d-9e8f-0123456789ab circuit=coinbase_attestation E2007';
    expect(scrubText(text)).toBe(text);
  });
  it('survives control characters, Korean and emoji around a hex value', () => {
    expect(scrubText(`증명 실패 🙁\t${ADDRESS}\n`)).toBe('증명 실패 🙁\t0x5290…9EE7\n');
  });
  it('masks every occurrence, not just the first', () => {
    expect(scrubText(`${ADDRESS},${ADDRESS}`)).toBe('0x5290…9EE7,0x5290…9EE7');
  });
});

describe('scrubError', () => {
  it('scrubs the message and stack of an Error', () => {
    const out = scrubError(new Error(`connect ECONNREFUSED 10.20.30.40:6379 for ${ADDRESS}`));
    expect(out).toContain('10.20.x.x');
    expect(out).toContain('0x5290…9EE7');
    expect(out).not.toContain('10.20.30.40');
    expect(out).not.toContain(ADDRESS);
  });
  it('handles thrown non-errors', () => {
    expect(scrubError({ ip: '203.0.113.45' })).toBe('{"ip":"203.0.x.x"}');
    expect(scrubError('plain')).toBe('plain');
  });
});

describe('describeBody', () => {
  it('lists key names and envelope fields, never inputs, proof data or signatures', () => {
    const out = describeBody({
      requestId: 'r-1',
      circuit: 'coinbase_attestation',
      status: 'error',
      errorCode: 'E2007',
      chainId: 8453,
      verifierAddress: '0x1234567890abcdef1234567890abcdef12345678',
      inputs: { userAddress: ADDRESS, scope: 'secret-scope' },
      publicInputs: [NULLIFIER],
      nullifier: NULLIFIER,
      signature: '0x' + 'ab'.repeat(65),
      error: `failed for ${ADDRESS}`,
    });
    expect(out).toContain('keys=[requestId,circuit,status,errorCode,chainId,verifierAddress,inputs,publicInputs,nullifier,signature,error]');
    expect(out).toContain('requestId=r-1');
    expect(out).toContain('errorCode=E2007');
    expect(out).toContain('verifierAddress=0x1234567890abcdef1234567890abcdef12345678');
    expect(out).toContain('error=failed for 0x5290…9EE7');
    expect(out).not.toContain(ADDRESS);
    expect(out).not.toContain(NULLIFIER);
    expect(out).not.toContain('secret-scope');
    expect(out).not.toContain('abab');
  });
  it('scrubs an envelope field that smuggles personal data', () => {
    expect(describeBody({ dappName: `pay ${ADDRESS}` })).toContain('dappName=pay 0x5290…9EE7');
  });
  it('prints an object-valued envelope field as its type only', () => {
    expect(describeBody({ circuit: { nested: ADDRESS } })).toContain('circuit=<object>');
  });
  it('describes non-object bodies without printing them', () => {
    expect(describeBody(undefined)).toBe('body=<undefined>');
    expect(describeBody(null)).toBe('body=<object>');
    expect(describeBody([1, 2])).toBe('body=<array>');
    expect(describeBody('x')).toBe('body=<string>');
  });
});

describe('describeDeepLink', () => {
  it('replaces the payload with its length', () => {
    const data = Buffer.from(JSON.stringify({ inputs: { userAddress: ADDRESS } })).toString('base64url');
    const out = describeDeepLink(`zkproofport://proof-request?data=${data}`);
    expect(out).toBe(`zkproofport://proof-request?data=<${data.length} chars>`);
    expect(out).not.toContain(data);
  });
  it('leaves a link without a query alone', () => {
    expect(describeDeepLink('zkproofport://proof-request')).toBe('zkproofport://proof-request');
  });
});
