import { describe, it, expect } from 'vitest';
import { countryLabel, decodeLabel, MARKERS, originLabel, SCOPE_MAX_CHARS, scopeLabel } from '../labels';

describe('originLabel', () => {
  it('keeps the host, with a non-default port, and drops scheme, path and query', () => {
    expect(originLabel('https://dojangscan.com')).toBe('v:dojangscan.com');
    expect(originLabel('https://dojangscan.com/a/b?c=d#e')).toBe('v:dojangscan.com');
    expect(originLabel('http://localhost:3000')).toBe('v:localhost%3A3000');
    expect(originLabel('https://demo.zkproofport.app:443')).toBe('v:demo.zkproofport.app');
  });

  it('one site is one label: case folded, IDN as punycode', () => {
    expect(originLabel('https://DojangScan.COM')).toBe('v:dojangscan.com');
    const idn = originLabel('https://도장.com');
    expect(idn).toMatch(/^v:xn--[a-z0-9]+\.com$/);
    expect(originLabel(`https://${idn.slice(2)}`)).toBe(idn);
  });

  it('missing, empty and the literal "null" (file://, sandboxed frames) are "none", each separately', () => {
    expect(originLabel(undefined)).toBe(MARKERS.none);
    expect(originLabel(null)).toBe(MARKERS.none);
    expect(originLabel('')).toBe(MARKERS.none);
    expect(originLabel('null')).toBe(MARKERS.none);
  });

  it('anything that is not an http(s) origin is "invalid", never its raw text', () => {
    for (const bad of ['chrome-extension://abc', 'file:///etc/passwd', 'javascript:alert(1)', 'not a url', '%', '<script>', ['https://a.com'], 42]) {
      expect(originLabel(bad)).toBe(MARKERS.invalid);
    }
  });

  it('a host name of exactly 253 characters is kept, 254 is "too-long", whatever the port', () => {
    const name = (len: number) => `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(len - 63 * 3 - 3)}`;
    expect(name(253)).toHaveLength(253);
    expect(originLabel(`https://${name(253)}`)).toBe(`v:${name(253)}`);
    expect(originLabel(`https://${name(253)}:8443`)).toBe(`v:${name(253)}%3A8443`);
    expect(originLabel(`https://${name(254)}`)).toBe(MARKERS.tooLong);
  });
});

describe('scopeLabel', () => {
  it('counts the scope as given, encoded so | and : cannot break the stats field', () => {
    expect(scopeLabel('myapp.com')).toBe('v:myapp.com');
    expect(scopeLabel('a|b:c')).toBe('v:a%7Cb%3Ac');
    expect(decodeLabel(scopeLabel('a|b:c')!)).toEqual({ value: 'a|b:c', marker: null });
  });

  it('Korean, emoji, newlines and tabs round-trip unchanged', () => {
    for (const s of ['도장스캔', '🛡️ zk', 'line1\nline2', 'a\tb', "' OR 1=1 --", '%_\\']) {
      expect(decodeLabel(scopeLabel(s)!)).toEqual({ value: s, marker: null });
    }
  });

  it('undefined, null, empty and whitespace-only are "none", each separately', () => {
    expect(scopeLabel(undefined)).toBe(MARKERS.none);
    expect(scopeLabel(null)).toBe(MARKERS.none);
    expect(scopeLabel('')).toBe(MARKERS.none);
    expect(scopeLabel('   \n\t')).toBe(MARKERS.none);
  });

  it('a non-string is "invalid"', () => {
    for (const bad of [1, true, {}, ['a']]) expect(scopeLabel(bad)).toBe(MARKERS.invalid);
  });

  it('exactly the maximum is kept, one more code point is "too-long" (counted in code points, not UTF-16 units)', () => {
    expect(scopeLabel('a'.repeat(SCOPE_MAX_CHARS))).toBe(`v:${'a'.repeat(SCOPE_MAX_CHARS)}`);
    expect(scopeLabel('a'.repeat(SCOPE_MAX_CHARS + 1))).toBe(MARKERS.tooLong);
    expect(scopeLabel('😀'.repeat(SCOPE_MAX_CHARS)).startsWith('v:')).toBe(true);
    expect(scopeLabel('x'.repeat(1_000_000))).toBe(MARKERS.tooLong);
  });

  it('a scope spelled like a marker stays a value', () => {
    expect(decodeLabel(scopeLabel('m:none')!)).toEqual({ value: 'm:none', marker: null });
    expect(decodeLabel(scopeLabel('(none)')!)).toEqual({ value: '(none)', marker: null });
  });
});

describe('countryLabel', () => {
  it('a two-letter upper-case region code is kept', () => {
    expect(countryLabel('KR')).toBe('v:KR');
    expect(countryLabel('US')).toBe('v:US');
  });
  it('empty (the load balancer could not place the caller) is "unknown"; missing is "none"', () => {
    expect(countryLabel('')).toBe(MARKERS.unknown);
    expect(countryLabel(undefined)).toBe(MARKERS.none);
  });
  it('anything else is "invalid": lower case, three letters, two values, script', () => {
    for (const bad of ['kr', 'KOR', 'KR,US', 'KR ', '<b>', ['KR'], 'K']) expect(countryLabel(bad)).toBe(MARKERS.invalid);
  });
});

describe('decodeLabel', () => {
  it('reads every marker back by name', () => {
    for (const [name, label] of Object.entries(MARKERS)) expect(decodeLabel(label)).toEqual({ value: null, marker: name });
  });
  it('refuses labels it never writes', () => {
    for (const bad of ['', 'm:nope', 'x:abc', 'v:%E0%A4%A', 'dojangscan.com']) expect(decodeLabel(bad)).toBeNull();
  });
});
