/**
 * POST /api/v1/play-integrity/decrypt over real HTTP, in process.
 *
 * Tokens are built with `jose` (a devDependency only), not with the relay's
 * own code, so a decryption that merely agrees with itself cannot pass: the
 * relay has to open what an independent JOSE implementation produced, the way
 * it has to open what Google produces.
 *
 * Redis is never reached by this route; the relay gets a stub that throws.
 */
import { describe, it, expect, afterEach, beforeAll, vi } from 'vitest';
import type { AddressInfo } from 'net';
import { generateKeyPairSync, randomBytes, sign as cryptoSign, verify as cryptoVerify, KeyObject } from 'crypto';
import type Redis from 'ioredis';
import { createRelay, Relay, PLAY_INTEGRITY_BODY_LIMIT } from '../app';
import { EDGES } from '../edge';
import {
  decryptPlayIntegrityToken,
  PlayIntegrityConfig,
  playIntegrityConfigFromEnv,
  PLAY_INTEGRITY_DECRYPTION_KEY_ENV,
  PLAY_INTEGRITY_VERIFICATION_KEY_ENV,
} from '../playIntegrity';

// Dynamic import: jose is ESM-only and this file compiles as CommonJS.
const loadJose = () => import('jose');
let jose: Awaited<ReturnType<typeof loadJose>>;
beforeAll(async () => {
  jose = await loadJose();
});

const throwingRedis = new Proxy({}, {
  get(_t, prop) {
    if (prop === 'then') return undefined;
    return () => { throw new Error(`redis.${String(prop)} called in a test that must not reach Redis`); };
  },
}) as unknown as Redis;

const AES_KEY = randomBytes(32);
const { privateKey: GOOGLE_SIGNING_KEY, publicKey: GOOGLE_VERIFICATION_KEY } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const { privateKey: OTHER_SIGNING_KEY } = generateKeyPairSync('ec', { namedCurve: 'P-256' });

const KEYS = { decryptionKey: AES_KEY, verificationKey: GOOGLE_VERIFICATION_KEY };
const ENABLED: PlayIntegrityConfig = { enabled: true, ...KEYS };

/** Distinctive values, so the log test can search for them. */
const NONCE = 'bm9uY2UtYm91bmQtdG8tdGhlLXN0YXRlbWVudC1kaWdlc3Q';
const PACKAGE = 'com.masselabs.zkproofport';
const CERT_DIGEST = 'q1w2e3r4t5y6u7i8o9p0asdfghjklzxcvbnmQWERTYU';

/** The classic verdict shape (developer.android.com/google/play/integrity/verdicts). */
function verdict(nonce = NONCE) {
  return {
    requestDetails: { requestPackageName: PACKAGE, nonce, timestampMillis: '1761638400000' },
    appIntegrity: {
      appRecognitionVerdict: 'PLAY_RECOGNIZED',
      packageName: PACKAGE,
      certificateSha256Digest: [CERT_DIGEST],
      versionCode: '42',
    },
    deviceIntegrity: { deviceRecognitionVerdict: ['MEETS_DEVICE_INTEGRITY'] },
    accountDetails: { appLicensingVerdict: 'LICENSED' },
    environmentDetails: { appAccessRiskVerdict: { appsDetected: ['KNOWN_INSTALLED'] } },
  };
}

async function sign(payload: unknown, key: KeyObject = GOOGLE_SIGNING_KEY, alg = 'ES256'): Promise<string> {
  return new jose.CompactSign(new TextEncoder().encode(JSON.stringify(payload))).setProtectedHeader({ alg }).sign(key);
}

async function encrypt(
  plaintext: string,
  key: Uint8Array = AES_KEY,
  header: { alg: string; enc: string; [k: string]: unknown } = { alg: 'A256KW', enc: 'A256GCM' },
): Promise<string> {
  return new jose.CompactEncrypt(new TextEncoder().encode(plaintext)).setProtectedHeader(header).encrypt(key);
}

/** Flips one bit inside a base64url segment and re-encodes it canonically. */
function flipSegment(token: string, index: number): string {
  const parts = token.split('.');
  const bytes = Buffer.from(parts[index], 'base64url');
  bytes[Math.floor(bytes.length / 2)] ^= 0x01;
  parts[index] = bytes.toString('base64url');
  return parts.join('.');
}

const closers: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const c of closers.splice(0)) await c();
  vi.restoreAllMocks();
});

async function startRelay(playIntegrity: PlayIntegrityConfig = ENABLED): Promise<string> {
  const relay: Relay = createRelay({
    redis: throwingRedis,
    stats: { record() {} },
    statsToken: 'k'.repeat(64),
    statsAuth: { lockedFor: async () => 0, recordFailure: async () => 1 },
    adapter: null,
    edge: EDGES.local,
    relayExternalUrl: 'https://relay.example.test',
    deadlineMs: 3_600_000,
    sweepIntervalMs: 3_600_000,
    playIntegrity,
  });
  await new Promise<void>((resolve) => relay.httpServer.listen(0, '127.0.0.1', resolve));
  closers.push(() => relay.close());
  return `http://127.0.0.1:${(relay.httpServer.address() as AddressInfo).port}/api/v1/play-integrity/decrypt`;
}

async function post(url: string, body: unknown, raw?: string): Promise<{ status: number; json: Record<string, unknown>; headers: Headers }> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: raw ?? JSON.stringify(body),
  });
  return { status: res.status, json: (await res.json()) as Record<string, unknown>, headers: res.headers };
}

describe('POST /api/v1/play-integrity/decrypt: success', () => {
  it('returns the three JWS segments exactly as signed, and they re-verify with the public key', async () => {
    const url = await startRelay();
    const jws = await sign(verdict());
    const res = await post(url, { token: await encrypt(jws) });

    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('no-store');
    const [h, p, s] = jws.split('.');
    expect(res.json).toEqual({ protectedHeader: h, payload: p, signature: s });

    // The app rebuilds the signing input from these segments; it must verify.
    const signingInput = Buffer.from(`${res.json.protectedHeader}.${res.json.payload}`, 'ascii');
    const signature = Buffer.from(res.json.signature as string, 'base64url');
    expect(signature).toHaveLength(64);
    expect(cryptoVerify('sha256', signingInput, { key: GOOGLE_VERIFICATION_KEY, dsaEncoding: 'ieee-p1363' }, signature)).toBe(true);
    const independent = await jose.compactVerify(`${h}.${p}.${s}`, GOOGLE_VERIFICATION_KEY);
    expect(JSON.parse(new TextDecoder().decode(independent.payload))).toEqual(verdict());
    expect(JSON.parse(Buffer.from(res.json.protectedHeader as string, 'base64url').toString())).toEqual({ alg: 'ES256' });
  });

  it('keeps extra JWE header fields (cty, kid) and a large verdict', async () => {
    const url = await startRelay();
    const big = { ...verdict(), padding: 'x'.repeat(4000) };
    const jws = await sign(big);
    const res = await post(url, { token: await encrypt(jws, AES_KEY, { alg: 'A256KW', enc: 'A256GCM', cty: 'JWT', kid: 'k1' }) });
    expect(res.status).toBe(200);
    expect(`${res.json.protectedHeader}.${res.json.payload}.${res.json.signature}`).toBe(jws);
  });

  it('handles UTF-8 inside the verdict without re-encoding it', async () => {
    const url = await startRelay();
    const jws = await sign(verdict('논스-🔐-ñ\n\t'));
    const res = await post(url, { token: await encrypt(jws) });
    expect(res.status).toBe(200);
    expect(`${res.json.protectedHeader}.${res.json.payload}.${res.json.signature}`).toBe(jws);
  });
});

describe('POST /api/v1/play-integrity/decrypt: refused tokens', () => {
  it('wrong AES key -> 400 key_unwrap_failed', async () => {
    const url = await startRelay();
    const res = await post(url, { token: await encrypt(await sign(verdict()), randomBytes(32)) });
    expect(res).toMatchObject({ status: 400, json: { reason: 'key_unwrap_failed' } });
  });

  it('tampered encrypted key -> 400 key_unwrap_failed', async () => {
    const url = await startRelay();
    const res = await post(url, { token: flipSegment(await encrypt(await sign(verdict())), 1) });
    expect(res).toMatchObject({ status: 400, json: { reason: 'key_unwrap_failed' } });
  });

  it.each([
    ['ciphertext', 3],
    ['authentication tag', 4],
    ['IV', 2],
  ])('tampered %s -> 400 decrypt_failed', async (_name, index) => {
    const url = await startRelay();
    const res = await post(url, { token: flipSegment(await encrypt(await sign(verdict())), index) });
    expect(res).toMatchObject({ status: 400, json: { reason: 'decrypt_failed' } });
  });

  it('a protected header changed after encryption fails authentication (it is the AAD) -> decrypt_failed', async () => {
    const url = await startRelay();
    const parts = (await encrypt(await sign(verdict()))).split('.');
    parts[0] = Buffer.from(JSON.stringify({ alg: 'A256KW', enc: 'A256GCM', kid: 'swapped' })).toString('base64url');
    const res = await post(url, { token: parts.join('.') });
    expect(res).toMatchObject({ status: 400, json: { reason: 'decrypt_failed' } });
  });

  it('tampered JWS signature -> 422 signature_invalid', async () => {
    const url = await startRelay();
    const res = await post(url, { token: await encrypt(flipSegment(await sign(verdict()), 2)) });
    expect(res).toMatchObject({ status: 422, json: { reason: 'signature_invalid' } });
  });

  it('tampered JWS payload (signature unchanged) -> 422 signature_invalid', async () => {
    const url = await startRelay();
    const parts = (await sign(verdict())).split('.');
    parts[1] = Buffer.from(JSON.stringify(verdict('another-nonce'))).toString('base64url');
    const res = await post(url, { token: await encrypt(parts.join('.')) });
    expect(res).toMatchObject({ status: 422, json: { reason: 'signature_invalid' } });
  });

  it('JWS signed by another P-256 key -> 422 signature_invalid', async () => {
    const url = await startRelay();
    const res = await post(url, { token: await encrypt(await sign(verdict(), OTHER_SIGNING_KEY)) });
    expect(res).toMatchObject({ status: 422, json: { reason: 'signature_invalid' } });
  });

  it('ES256 signature that is not 64 bytes (DER-shaped) -> 422 signature_invalid', async () => {
    const url = await startRelay();
    const [h, p] = (await sign(verdict())).split('.');
    const der = Buffer.from(cryptoSign('sha256', Buffer.from(`${h}.${p}`), GOOGLE_SIGNING_KEY)).toString('base64url');
    const res = await post(url, { token: await encrypt(`${h}.${p}.${der}`) });
    expect(res).toMatchObject({ status: 422, json: { reason: 'signature_invalid' } });
  });

  it.each([
    ['alg A128KW', { alg: 'A128KW', enc: 'A256GCM' }, 16],
    ['enc A128GCM', { alg: 'A256KW', enc: 'A128GCM' }, 32],
    ['enc A256CBC-HS512', { alg: 'A256KW', enc: 'A256CBC-HS512' }, 32],
    ['alg dir', { alg: 'dir', enc: 'A256GCM' }, 32],
  ])('JWE %s -> 400 jwe_unsupported', async (_name, header, keyBytes) => {
    const url = await startRelay();
    const res = await post(url, { token: await encrypt(await sign(verdict()), randomBytes(keyBytes), header) });
    expect(res).toMatchObject({ status: 400, json: { reason: 'jwe_unsupported' } });
  });

  it.each([
    ['zip', { zip: 'DEF' }],
    ['crit', { crit: ['exp'], exp: 1 }],
  ])('JWE header with %s -> 400 jwe_unsupported', async (_name, extra) => {
    const url = await startRelay();
    const parts = (await encrypt(await sign(verdict()))).split('.');
    parts[0] = Buffer.from(JSON.stringify({ alg: 'A256KW', enc: 'A256GCM', ...extra })).toString('base64url');
    const res = await post(url, { token: parts.join('.') });
    expect(res).toMatchObject({ status: 400, json: { reason: 'jwe_unsupported' } });
  });

  it('JWS signed with ES384 -> 400 jws_unsupported', async () => {
    const url = await startRelay();
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-384' });
    const res = await post(url, { token: await encrypt(await sign(verdict(), privateKey, 'ES384')) });
    expect(res).toMatchObject({ status: 400, json: { reason: 'jws_unsupported' } });
  });

  it('JWS signed with HS256 -> 400 jws_unsupported', async () => {
    const url = await startRelay();
    const jws = await new jose.CompactSign(new TextEncoder().encode('{}')).setProtectedHeader({ alg: 'HS256' }).sign(randomBytes(32));
    const res = await post(url, { token: await encrypt(jws) });
    expect(res).toMatchObject({ status: 400, json: { reason: 'jws_unsupported' } });
  });

  it('JWS alg none -> 400 jws_unsupported', async () => {
    const url = await startRelay();
    const h = Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url');
    const p = Buffer.from(JSON.stringify(verdict())).toString('base64url');
    const res = await post(url, { token: await encrypt(`${h}.${p}.${Buffer.alloc(64).toString('base64url')}`) });
    expect(res).toMatchObject({ status: 400, json: { reason: 'jws_unsupported' } });
  });

  it.each([
    ['plain JSON', JSON.stringify(verdict())],
    ['two segments', 'eyJhbGciOiJFUzI1NiJ9.e30'],
    ['four segments', 'a.b.c.d'],
    ['header not JSON', `${Buffer.from('not json').toString('base64url')}.e30.${Buffer.alloc(64).toString('base64url')}`],
    ['header a JSON array', `${Buffer.from('[1]').toString('base64url')}.e30.${Buffer.alloc(64).toString('base64url')}`],
    ['empty signature', 'eyJhbGciOiJFUzI1NiJ9.e30.'],
    ['padded base64', 'eyJhbGciOiJFUzI1NiJ9.e30=.AAAA'],
    ['empty string', ''],
  ])('a JWE whose plaintext is not a compact JWS (%s) -> 400 not_a_jws', async (_name, plaintext) => {
    const url = await startRelay();
    const res = await post(url, { token: await encrypt(plaintext) });
    expect(res).toMatchObject({ status: 400, json: { reason: 'not_a_jws' } });
  });

  it.each([
    ['garbage', 'not-a-token'],
    ['a JWS, not a JWE', 'eyJhbGciOiJFUzI1NiJ9.e30.AAAA'],
    ['five empty segments', '....'],
    ['six segments', 'a.b.c.d.e.f'],
    ['non-base64url characters', 'eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0.a+b/.AAAA.AAAA.AAAA'],
    ['standard base64 padding', 'eyJhbGciOiJBMjU2S1cifQ==.AAAA.AAAA.AAAA.AAAA'],
    ['header not JSON', `${Buffer.from('{alg').toString('base64url')}.AAAA.AAAA.AAAA.AAAA`],
    ['SQL-shaped', "' OR 1=1 --.a.b.c.d"],
    ['HTML', '<script>alert(1)</script>'],
    ['control characters', '\u0000.\u0001.\u0002.\u0003.\u0004'],
    ['Korean and emoji', '토큰.🔐.a.b.c'],
    ['whitespace only', '   '],
  ])('non-JWE input (%s) -> 400 token_malformed', async (_name, token) => {
    const url = await startRelay();
    const res = await post(url, { token });
    expect(res).toMatchObject({ status: 400, json: { reason: 'token_malformed' } });
  });

  it('a JWE with wrong segment lengths (short IV) -> 400 token_malformed', async () => {
    const url = await startRelay();
    const parts = (await encrypt(await sign(verdict()))).split('.');
    parts[2] = Buffer.alloc(8).toString('base64url');
    const res = await post(url, { token: parts.join('.') });
    expect(res).toMatchObject({ status: 400, json: { reason: 'token_malformed' } });
  });
});

describe('POST /api/v1/play-integrity/decrypt: request shape', () => {
  it.each([
    ['empty object', {}],
    ['null token', { token: null }],
    ['empty string token', { token: '' }],
    ['a JSON array body', [1, 2]],
  ])('%s -> 400 token_missing', async (_name, body) => {
    const url = await startRelay();
    const res = await post(url, body);
    expect(res).toMatchObject({ status: 400, json: { reason: 'token_missing', error: 'token is required' } });
  });

  it.each([
    ['number', 42],
    ['object', { a: 1 }],
    ['array', ['x.y.z.w.v']],
    ['boolean', true],
  ])('token as %s -> 400 token_not_string', async (_name, token) => {
    const url = await startRelay();
    const res = await post(url, { token });
    expect(res).toMatchObject({ status: 400, json: { reason: 'token_not_string' } });
  });

  it(`a body over ${PLAY_INTEGRITY_BODY_LIMIT} -> 413 body_too_large, decryption never runs`, async () => {
    const url = await startRelay();
    const res = await post(url, { token: 'A'.repeat(17 * 1024) });
    expect(res).toMatchObject({ status: 413, json: { reason: 'body_too_large' } });
  });

  it('a body just under the cap is parsed (and refused on its content, not its size)', async () => {
    const url = await startRelay();
    const res = await post(url, { token: 'A'.repeat(16 * 1024 - 20) });
    expect(res).toMatchObject({ status: 400, json: { reason: 'token_malformed' } });
  });

  it('malformed JSON -> 400 body_malformed', async () => {
    const url = await startRelay();
    const res = await post(url, undefined, '{"token": "abc');
    expect(res).toMatchObject({ status: 400, json: { reason: 'body_malformed' } });
  });

  it('the endpoint answers any origin (it is called from the app, not a dApp page) with CORS headers', async () => {
    const url = await startRelay();
    const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: 'https://x.example' }, body: '{}' });
    expect(res.headers.get('access-control-allow-origin')).toBe('*');
  });
});

describe('POST /api/v1/play-integrity/decrypt: keys absent', () => {
  it.each([
    [[PLAY_INTEGRITY_DECRYPTION_KEY_ENV]],
    [[PLAY_INTEGRITY_VERIFICATION_KEY_ENV]],
    [[PLAY_INTEGRITY_DECRYPTION_KEY_ENV, PLAY_INTEGRITY_VERIFICATION_KEY_ENV]],
  ])('missing %j -> 503 not_configured naming the variable, even for a valid token', async (missing) => {
    const url = await startRelay({ enabled: false, missing });
    const res = await post(url, { token: await encrypt(await sign(verdict())) });
    expect(res.status).toBe(503);
    expect(res.json.reason).toBe('not_configured');
    expect(res.json.missing).toEqual(missing);
    for (const name of missing) expect(res.json.error).toContain(name);
  });

  it('the rest of the relay still answers', async () => {
    const url = await startRelay({ enabled: false, missing: [PLAY_INTEGRITY_DECRYPTION_KEY_ENV] });
    const health = await fetch(url.replace('/api/v1/play-integrity/decrypt', '/health'));
    expect(health.status).toBe(200);
  });
});

describe('POST /api/v1/play-integrity/decrypt: rate limit', () => {
  it('30 requests per minute per caller; the 31st is 429 with Retry-After; another caller is unaffected', async () => {
    const url = await startRelay();
    const send = (ip: string) => fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': ip }, body: '{}' });
    for (let i = 0; i < 30; i++) expect((await send('198.51.100.7')).status).toBe(400);
    const limited = await send('198.51.100.7');
    expect(limited.status).toBe(429);
    expect(Number(limited.headers.get('retry-after'))).toBeGreaterThan(0);
    expect((await send('198.51.100.8')).status).toBe(400);
  });

  it('oversized bodies count against the limit too (the limiter runs before the parser)', async () => {
    const url = await startRelay();
    const big = JSON.stringify({ token: 'A'.repeat(17 * 1024) });
    const send = () => fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': '198.51.100.9' }, body: big });
    for (let i = 0; i < 30; i++) expect((await send()).status).toBe(413);
    expect((await send()).status).toBe(429);
  });
});

describe('POST /api/v1/play-integrity/decrypt: logs', () => {
  it('never contain the token, any JWS segment, the nonce, or a verdict value', async () => {
    const lines: string[] = [];
    const capture = (...args: unknown[]) => { lines.push(args.map(String).join(' ')); };
    for (const level of ['log', 'error', 'warn', 'info', 'debug'] as const) vi.spyOn(console, level).mockImplementation(capture);

    const url = await startRelay();
    const jws = await sign(verdict());
    const token = await encrypt(jws);
    const otherJws = await sign(verdict(), OTHER_SIGNING_KEY);
    const tokens = [
      token,
      await encrypt(otherJws),
      await encrypt(jws, randomBytes(32)),
      flipSegment(token, 3),
    ];
    const statuses = [];
    for (const t of tokens) statuses.push((await post(url, { token: t })).status);
    statuses.push((await post(url, undefined, `{"token": "${token}`)).status);
    statuses.push((await post(url, { token: token + 'x'.repeat(17 * 1024) })).status);
    expect(statuses).toEqual([200, 422, 400, 400, 400, 413]);

    const text = lines.join('\n');
    expect(text).toContain('[Relay PlayIntegrity]');
    expect(text).toContain('outcome=ok');
    expect(text).toContain('outcome=signature_invalid');
    const secrets = [
      ...tokens.flatMap((t) => t.split('.')),
      ...jws.split('.'),
      ...otherJws.split('.'),
      NONCE,
      PACKAGE,
      CERT_DIGEST,
      'PLAY_RECOGNIZED',
      'MEETS_DEVICE_INTEGRITY',
      AES_KEY.toString('base64'),
    ].filter((s) => s.length >= 8);
    for (const secret of secrets) expect(text).not.toContain(secret);
    // The caller's address is masked.
    expect(text).not.toMatch(/127\.0\.0\.1/);
  });
});

describe('decryptPlayIntegrityToken (direct)', () => {
  it('returns segments that join back into the original JWS', async () => {
    const jws = await sign(verdict());
    const out = decryptPlayIntegrityToken(await encrypt(jws), KEYS);
    expect(`${out.protectedHeader}.${out.payload}.${out.signature}`).toBe(jws);
  });
});

describe('playIntegrityConfigFromEnv', () => {
  const aes = AES_KEY.toString('base64');
  const spki = (GOOGLE_VERIFICATION_KEY.export({ format: 'der', type: 'spki' }) as Buffer).toString('base64');

  it('both present and well-formed -> enabled, and the parsed keys decrypt a token', async () => {
    const config = playIntegrityConfigFromEnv({ [PLAY_INTEGRITY_DECRYPTION_KEY_ENV]: aes, [PLAY_INTEGRITY_VERIFICATION_KEY_ENV]: spki });
    expect(config.enabled).toBe(true);
    if (!config.enabled) throw new Error('unreachable');
    const jws = await sign(verdict());
    expect(decryptPlayIntegrityToken(await encrypt(jws), config).signature).toBe(jws.split('.')[2]);
  });

  it('surrounding whitespace (a secret written with echo) is ignored', () => {
    const config = playIntegrityConfigFromEnv({ [PLAY_INTEGRITY_DECRYPTION_KEY_ENV]: ` ${aes}\n`, [PLAY_INTEGRITY_VERIFICATION_KEY_ENV]: `${spki}\n` });
    expect(config.enabled).toBe(true);
  });

  it.each([
    ['both unset', {}, [PLAY_INTEGRITY_DECRYPTION_KEY_ENV, PLAY_INTEGRITY_VERIFICATION_KEY_ENV]],
    ['decryption unset', { [PLAY_INTEGRITY_VERIFICATION_KEY_ENV]: 'SPKI' }, [PLAY_INTEGRITY_DECRYPTION_KEY_ENV]],
    ['verification unset', { [PLAY_INTEGRITY_DECRYPTION_KEY_ENV]: 'AES' }, [PLAY_INTEGRITY_VERIFICATION_KEY_ENV]],
    ['both blank', { [PLAY_INTEGRITY_DECRYPTION_KEY_ENV]: '', [PLAY_INTEGRITY_VERIFICATION_KEY_ENV]: ' \n' }, [PLAY_INTEGRITY_DECRYPTION_KEY_ENV, PLAY_INTEGRITY_VERIFICATION_KEY_ENV]],
  ])('%s -> disabled, naming exactly what is missing', (_name, env, missing) => {
    const resolved = Object.fromEntries(Object.entries(env).map(([k, v]) => [k, v === 'AES' ? aes : v === 'SPKI' ? spki : v]));
    expect(playIntegrityConfigFromEnv(resolved)).toEqual({ enabled: false, missing });
  });

  const rsaSpki = (generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ format: 'der', type: 'spki' }) as Buffer).toString('base64');
  const p384Spki = (generateKeyPairSync('ec', { namedCurve: 'P-384' }).publicKey.export({ format: 'der', type: 'spki' }) as Buffer).toString('base64');

  it.each([
    ['AES key of 16 bytes', { d: randomBytes(16).toString('base64') }, /32 bytes/],
    ['AES key of 33 bytes', { d: randomBytes(33).toString('base64') }, /32 bytes/],
    ['AES key in base64url', { d: Buffer.alloc(32, 0xfb).toString('base64url') }, /standard base64/],
    ['AES key not base64', { d: 'not base64!' }, /standard base64/],
    ['verification key not DER', { v: Buffer.from('hello').toString('base64') }, /SubjectPublicKeyInfo/],
    ['verification key RSA', { v: rsaSpki }, /EC P-256/],
    ['verification key P-384', { v: p384Spki }, /EC P-256/],
  ])('%s -> throws at startup (no default key, no silent disable)', (_name, over, message) => {
    const env = {
      [PLAY_INTEGRITY_DECRYPTION_KEY_ENV]: (over as { d?: string }).d ?? aes,
      [PLAY_INTEGRITY_VERIFICATION_KEY_ENV]: (over as { v?: string }).v ?? spki,
    };
    expect(() => playIntegrityConfigFromEnv(env)).toThrow(message);
  });

  it('a malformed key throws even while its partner is missing', () => {
    expect(() => playIntegrityConfigFromEnv({ [PLAY_INTEGRITY_DECRYPTION_KEY_ENV]: randomBytes(16).toString('base64') })).toThrow(/32 bytes/);
  });

  it('error messages never quote the key value', () => {
    const bad = randomBytes(16).toString('base64');
    try {
      playIntegrityConfigFromEnv({ [PLAY_INTEGRITY_DECRYPTION_KEY_ENV]: bad, [PLAY_INTEGRITY_VERIFICATION_KEY_ENV]: spki });
      throw new Error('expected a throw');
    } catch (err) {
      expect((err as Error).message).not.toContain(bad);
    }
  });
});
