import { describe, it, expect } from 'vitest';
import { validateReturnScheme, MAX_RETURN_SCHEME_LENGTH } from '../returnScheme';

/**
 * Edge-case matrix for the `returnScheme` envelope field.
 * Row numbers refer to the matrix planned before implementation.
 */

// --- Row 1: absent / not set -------------------------------------------------
describe('returnScheme — absent (matrix row 1, 11)', () => {
  it('rejects undefined', () => {
    const r = validateReturnScheme(undefined);
    expect(r.valid).toBe(false);
    expect(r.normalized).toBeUndefined();
  });

  it('rejects null, distinctly from undefined', () => {
    expect(validateReturnScheme(null).valid).toBe(false);
  });

  it('rejects non-string types', () => {
    for (const v of [0, 1, true, false, {}, [], ['mydapp://']]) {
      expect(validateReturnScheme(v).valid).toBe(false);
    }
  });
});

// --- Rows 2-5, 13: boundary values -------------------------------------------
describe('returnScheme — boundaries (matrix rows 2-5, 13)', () => {
  it('accepts a 1-character scheme', () => {
    expect(validateReturnScheme('a://')).toEqual({ valid: true, normalized: 'a://' });
  });

  it('accepts a value exactly at the length cap', () => {
    const scheme = 'a'.repeat(MAX_RETURN_SCHEME_LENGTH - 3) + '://';
    expect(scheme.length).toBe(MAX_RETURN_SCHEME_LENGTH);
    expect(validateReturnScheme(scheme).valid).toBe(true);
  });

  it('rejects a value one character over the cap', () => {
    const scheme = 'a'.repeat(MAX_RETURN_SCHEME_LENGTH - 2) + '://';
    expect(scheme.length).toBe(MAX_RETURN_SCHEME_LENGTH + 1);
    const r = validateReturnScheme(scheme);
    expect(r.valid).toBe(false);
    expect(r.error).toMatch(/at most/);
  });

  it('rejects a value at 2x the cap', () => {
    expect(validateReturnScheme('a'.repeat(MAX_RETURN_SCHEME_LENGTH * 2) + '://').valid).toBe(false);
  });

  it('rejects a 100k-character value quickly (length checked before regex)', () => {
    const huge = 'a'.repeat(100_000) + '://';
    const started = Date.now();
    expect(validateReturnScheme(huge).valid).toBe(false);
    expect(Date.now() - started).toBeLessThan(100);
  });
});

// --- Rows 9, 10: empty / whitespace ------------------------------------------
describe('returnScheme — empty and whitespace (matrix rows 9, 10)', () => {
  it('rejects the empty string', () => {
    const r = validateReturnScheme('');
    expect(r.valid).toBe(false);
    expect(r.error).toMatch(/empty/);
  });

  it('rejects whitespace-only values, each shape separately', () => {
    for (const v of ['   ', '\t', '\n', ' \t\n ']) {
      expect(validateReturnScheme(v).valid).toBe(false);
    }
  });

  it('rejects a valid scheme with surrounding whitespace rather than trimming it', () => {
    expect(validateReturnScheme('  mydapp://  ').valid).toBe(false);
    expect(validateReturnScheme('mydapp:// ').valid).toBe(false);
  });
});

// --- Row 6: hostile schemes ---------------------------------------------------
describe('returnScheme — denied schemes (matrix row 6)', () => {
  const denied = [
    'javascript://',
    'data://',
    'file://',
    'about://',
    'blob://',
    'content://',
    'intent://',
    'http://',
    'tel://',
    'sms://',
    'mailto://',
    'facetime://',
    'ftp://',
    'jar://',
    'vbscript://',
  ];

  it.each(denied)('rejects %s', (value) => {
    expect(validateReturnScheme(value).valid).toBe(false);
  });

  it('rejects denied schemes regardless of case', () => {
    expect(validateReturnScheme('JavaScript://').valid).toBe(false);
    expect(validateReturnScheme('FILE://').valid).toBe(false);
    expect(validateReturnScheme('HtTp://').valid).toBe(false);
  });
});

// --- Row 7: hostile shape (paths, queries, fragments, userinfo) ---------------
describe('returnScheme — shape (matrix row 7)', () => {
  const rejected = [
    'mydapp://x',
    'mydapp://host/path',
    'mydapp://?a=1',
    'mydapp://#frag',
    'mydapp://a?b=1#c',
    'https://evil.example.com/pay?amount=1000',
    'https://evil.example.com/',
    'https://evil.example.com#frag',
    'https://evil.example.com?next=x',
    'https://user:pass@evil.example.com',
    'https://evil.example.com:99999999',
  ];

  it.each(rejected)('rejects %s', (value) => {
    expect(validateReturnScheme(value).valid).toBe(false);
  });

  it('accepts a bare https origin', () => {
    expect(validateReturnScheme('https://myapp.com')).toEqual({
      valid: true,
      normalized: 'https://myapp.com',
    });
  });

  it('accepts an https origin with a port', () => {
    expect(validateReturnScheme('https://myapp.com:8443').valid).toBe(true);
  });

  it('rejects an https origin with no dot (not a public host shape)', () => {
    expect(validateReturnScheme('https://localhost').valid).toBe(false);
  });
});

// --- Row 8: hostile characters -----------------------------------------------
describe('returnScheme — hostile characters (matrix row 8)', () => {
  const rejected = [
    'mydapp://\n',
    'my\ndapp://',
    'mydapp\t://',
    'mydapp://\u0000',
    'my dapp://',
    'mydapp://%0Ajavascript:alert(1)',
    '<script>://',
    "mydapp'://",
    'mydapp"://',
    'my%dapp://',
    'my_dapp://',
    'my/dapp://',
    'my\\dapp://',
    '1mydapp://',
  ];

  it.each(rejected)('rejects %j', (value) => {
    expect(validateReturnScheme(value).valid).toBe(false);
  });

  it('accepts the RFC 3986 scheme character set', () => {
    expect(validateReturnScheme('my-dapp.v2+alpha://').valid).toBe(true);
  });
});

// --- Row 12: UTF-8 ------------------------------------------------------------
describe('returnScheme — UTF-8 (matrix row 12)', () => {
  const rejected = [
    '앱://',
    '🚀://',
    'mydapp://한글',
    'myapp앱://',
    'https://한글.com',
    'mydapp://🚀',
  ];

  it.each(rejected)('rejects %s', (value) => {
    expect(validateReturnScheme(value).valid).toBe(false);
  });
});

// --- Row 19: non-scheme junk --------------------------------------------------
describe('returnScheme — junk (matrix row 19)', () => {
  const rejected = ['notaurl', 'mydapp:/', 'mydapp:', '://', '//mydapp', '/', 'mydapp', 'mydapp:///'];

  it.each(rejected)('rejects %s', (value) => {
    expect(validateReturnScheme(value).valid).toBe(false);
  });
});

// --- Normalization + Row 17 round trip ---------------------------------------
describe('returnScheme — normalization and deep-link round trip (matrix row 17)', () => {
  it('lowercases the accepted value', () => {
    expect(validateReturnScheme('MyDapp://').normalized).toBe('mydapp://');
    expect(validateReturnScheme('HTTPS://MyApp.COM').normalized).toBe('https://myapp.com');
  });

  it('survives the base64url deep-link encoding unchanged', () => {
    // Mirrors buildDeepLink() in src/index.ts.
    const request = {
      requestId: 'req-1',
      circuitId: 'coinbase_attestation',
      scope: 'myapp.com',
      inputs: { scope: 'myapp.com' },
      callbackUrl: 'https://relay.zkproofport.app/api/v1/proof/callback',
      returnScheme: validateReturnScheme('MyDapp://').normalized,
      createdAt: new Date().toISOString(),
    };
    const data = Buffer.from(JSON.stringify(request)).toString('base64url');
    const deepLink = `zkproofport://proof-request?data=${data}`;

    const encoded = new URL(deepLink).searchParams.get('data')!;
    const decoded = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf-8'));
    expect(decoded.returnScheme).toBe('mydapp://');
  });

  it('omits the field entirely when it was never supplied (matrix row 1)', () => {
    const request: Record<string, unknown> = {
      requestId: 'req-1',
      circuitId: 'coinbase_attestation',
      createdAt: new Date().toISOString(),
    };
    const data = Buffer.from(JSON.stringify(request)).toString('base64url');
    const decoded = JSON.parse(Buffer.from(data, 'base64url').toString('utf-8'));
    expect('returnScheme' in decoded).toBe(false);
  });
});

// --- Chain: the values proofport-app-demo can actually produce ---------------
/**
 * The demo derives its return target from `window.location.origin`
 * (`proofport-app-demo/lib/returnScheme.ts`), so the exact strings it can emit
 * are fixed by the environments it is deployed to. They are asserted against
 * the authority here so a tightening of the validator cannot silently turn the
 * demo's requests into 400s. The counterpart assertions — that the demo really
 * produces these strings and nothing else — live in
 * `proofport-app-demo/__tests__/returnScheme.test.ts`.
 */
describe('returnScheme — proofport-app-demo origins', () => {
  const accepted = [
    'https://demo.zkproofport.app',        // production
    'https://stg-demo.zkproofport.app',    // staging
  ];

  it.each(accepted)('accepts the demo origin %s unchanged', (origin) => {
    const r = validateReturnScheme(origin);
    expect(r.valid).toBe(true);
    expect(r.normalized).toBe(origin);
  });

  it('carries the production origin through the deep-link encoding', () => {
    // Mirrors buildDeepLink() in src/index.ts.
    const request = {
      requestId: 'req-demo-1',
      circuitId: 'coinbase_attestation',
      scope: 'zkproofport:demo',
      inputs: { scope: 'zkproofport:demo' },
      callbackUrl: 'https://relay.zkproofport.app/api/v1/proof/callback',
      dappName: 'ZKProofport Demo',
      returnScheme: validateReturnScheme('https://demo.zkproofport.app').normalized,
      createdAt: new Date().toISOString(),
    };
    const data = Buffer.from(JSON.stringify(request)).toString('base64url');
    const decoded = JSON.parse(
      Buffer.from(new URL(`zkproofport://proof-request?data=${data}`).searchParams.get('data')!, 'base64url').toString('utf-8'),
    );
    expect(decoded.returnScheme).toBe('https://demo.zkproofport.app');
  });

  it('rejects the local dev origins, which is why the demo omits the field there', () => {
    // http is denied outright, and `localhost` has no dot even over https.
    for (const origin of ['http://localhost:3300', 'http://192.168.0.10:3300', 'https://localhost:3300']) {
      expect(validateReturnScheme(origin).valid).toBe(false);
    }
  });
});
