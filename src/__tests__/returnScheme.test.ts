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

});

// --- The https origin form, removed ------------------------------------------
/**
 * A bare https origin used to be accepted as a second form. It is not any more.
 *
 * Opening one does not return the user to the page that made the request: the
 * OS hands the URL to the browser, which opens a NEW tab on a freshly loaded
 * page, while the tab the user actually started from keeps its state and stays
 * in the background. The round trip the field exists to complete is exactly
 * what an https origin destroyed. The field brings an APP forward, so it now
 * takes a scheme or it takes nothing.
 *
 * These assertions are the regression guard. Reintroduce an origin branch and
 * every case here fails.
 */
describe('returnScheme — the https origin form is gone', () => {
  const rejected = [
    'https://myapp.com',              // the plain form that used to pass
    'https://myapp.com:8443',         // ...and with a port
    'https://demo.zkproofport.app',   // the exact value the demo used to send
    'https://stg-demo.zkproofport.app',
    'https://a.b.c.example.com',
    'HTTPS://MyApp.COM',              // case-insensitively too
    'https://localhost',              // never matched the origin shape anyway
  ];

  it.each(rejected)('rejects the https origin %s', (value) => {
    const r = validateReturnScheme(value);
    expect(r.valid).toBe(false);
    expect(r.normalized).toBeUndefined();
  });

  it('explains the scheme-only rule when handed a URL-shaped value', () => {
    expect(validateReturnScheme('https://myapp.com').error).toMatch(/bare custom scheme/);
  });

  /**
   * The back door the shape rule alone leaves open: `https://` and `http://`
   * have no host, so they are shaped exactly like a bare custom scheme and
   * sail through BARE_SCHEME_RE. Only the denied list stops them. A browser
   * pointed at nowhere is not a return target, and allowing it would re-open
   * the URL-shaped door this change just closed.
   */
  it.each(['https://', 'http://', 'HTTPS://', 'HtTp://'])(
    'rejects the host-less browser scheme %s as denied, not as valid',
    (value) => {
      const r = validateReturnScheme(value);
      expect(r.valid).toBe(false);
      expect(r.error).toMatch(/not allowed/);
    },
  );

  it('still accepts the scheme form the field is actually for', () => {
    expect(validateReturnScheme('mydapp://')).toEqual({
      valid: true,
      normalized: 'mydapp://',
    });
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
    expect(validateReturnScheme('My-Dapp.V2+Alpha://').normalized).toBe('my-dapp.v2+alpha://');
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

// --- Chain: the values a requester can actually produce ---------------------
/**
 * The demo used to derive an https origin from `window.location.origin` and
 * send it here. That is gone: `proofport-app-demo/lib/returnScheme.ts` was
 * deleted along with the https form, because a web page has no app to hand
 * control back to and the origin it could name was the wrong answer anyway.
 *
 * What can reach this validator now:
 *   - a native integrator's own registered scheme;
 *   - `googlechrome://`, which the SDK fills in by itself when the requesting
 *     page is running in Chrome for iOS (`CriOS` in the user agent). Bare, that
 *     scheme foregrounds Chrome WITHOUT navigating, so the user lands back on
 *     the tab they were already reading.
 * Everything else sends nothing at all.
 *
 * These are asserted against the authority so a tightening of the validator
 * cannot silently turn a live request into a 400.
 */
describe('returnScheme — the values a requester can actually produce', () => {
  const accepted = [
    'googlechrome://',   // what the SDK sends for Chrome on iOS
    'mydapp://',         // a native integrator's own scheme
    'zkproofport://',    // our own, i.e. an app calling us back
  ];

  it.each(accepted)('accepts %s unchanged', (value) => {
    const r = validateReturnScheme(value);
    expect(r.valid).toBe(true);
    expect(r.normalized).toBe(value);
  });

  it('carries googlechrome:// through the deep-link encoding', () => {
    // Mirrors buildDeepLink() in src/index.ts.
    const request = {
      requestId: 'req-demo-1',
      circuitId: 'coinbase_attestation',
      scope: 'zkproofport:demo',
      inputs: { scope: 'zkproofport:demo' },
      callbackUrl: 'https://relay.zkproofport.app/api/v1/proof/callback',
      dappName: 'ZKProofport Demo',
      returnScheme: validateReturnScheme('googlechrome://').normalized,
      createdAt: new Date().toISOString(),
    };
    const data = Buffer.from(JSON.stringify(request)).toString('base64url');
    const decoded = JSON.parse(
      Buffer.from(new URL(`zkproofport://proof-request?data=${data}`).searchParams.get('data')!, 'base64url').toString('utf-8'),
    );
    expect(decoded.returnScheme).toBe('googlechrome://');
  });

  it('rejects every origin the demo used to send, local and deployed alike', () => {
    for (const origin of [
      'https://demo.zkproofport.app',
      'https://stg-demo.zkproofport.app',
      'http://localhost:3300',
      'http://192.168.0.10:3300',
      'https://localhost:3300',
    ]) {
      expect(validateReturnScheme(origin).valid).toBe(false);
    }
  });
});
