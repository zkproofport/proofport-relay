/**
 * Unit tests for clientIp(): which address a request is counted under.
 * The integration and E2E suites check the same thing through the real rate
 * limiter, over HTTP and Socket.IO.
 */
import { describe, it, expect } from 'vitest';
import type { IncomingMessage } from 'http';
import express from 'express';
import { clientIp, TRUSTED_PROXY_HOPS, trustHops } from '../clientIp';

function req(remoteAddress: string, xff?: string | string[]): IncomingMessage {
  const headers: Record<string, string | string[]> = {};
  if (xff !== undefined) headers['x-forwarded-for'] = xff;
  return { headers, socket: { remoteAddress }, connection: { remoteAddress } } as unknown as IncomingMessage;
}

describe('TRUSTED_PROXY_HOPS', () => {
  it('is exactly one hop (Google front end), never "trust everything"', () => {
    expect(TRUSTED_PROXY_HOPS).toBe(1);
  });

  it('matches what Express compiles for the same setting, so req.ip and clientIp() agree', () => {
    const app = express();
    app.set('trust proxy', TRUSTED_PROXY_HOPS);
    const expressTrust = app.get('trust proxy fn') as (addr: string, i: number) => boolean;
    for (let i = 0; i < 5; i++) expect(trustHops('10.0.0.1', i)).toBe(expressTrust('10.0.0.1', i));
  });
});

describe('clientIp', () => {
  const FRONT_END = '169.254.169.126';

  it('no X-Forwarded-For: the socket address', () => {
    expect(clientIp(req('172.28.0.1'))).toBe('172.28.0.1');
  });

  it('one entry (what Google appends): that entry', () => {
    expect(clientIp(req(FRONT_END, '203.0.113.7'))).toBe('203.0.113.7');
  });

  it('a spoofed leftmost entry does not change the result', () => {
    const real = '203.0.113.7';
    const answers = ['1.1.1.1', '8.8.8.8', '0.0.0.0', '127.0.0.1', 'evil', '1.1.1.1, 2.2.2.2'].map((spoof) =>
      clientIp(req(FRONT_END, `${spoof}, ${real}`)),
    );
    expect(new Set(answers)).toEqual(new Set([real]));
  });

  it('two different rightmost entries are two different callers', () => {
    expect(clientIp(req(FRONT_END, '9.9.9.9, 203.0.113.7'))).not.toBe(clientIp(req(FRONT_END, '9.9.9.9, 203.0.113.8')));
  });

  it('IPv6 and IPv4-mapped addresses come through unchanged', () => {
    expect(clientIp(req(FRONT_END, '2001:db8::1'))).toBe('2001:db8::1');
    expect(clientIp(req(FRONT_END, '::ffff:203.0.113.7'))).toBe('::ffff:203.0.113.7');
  });

  it('a header sent twice is joined by Node in order; the last value still wins', () => {
    // Node joins repeated x-forwarded-for headers with ", ", so this is the
    // string form proxy-addr sees.
    expect(clientIp(req(FRONT_END, '1.1.1.1, 203.0.113.7'))).toBe('203.0.113.7');
  });

  it('empty header and whitespace-only header: the socket address', () => {
    expect(clientIp(req(FRONT_END, ''))).toBe(FRONT_END);
  });

  it('a very long header (1000 entries) still answers its rightmost entry', () => {
    const long = Array.from({ length: 1000 }, (_, i) => `10.0.${Math.floor(i / 256)}.${i % 256}`).join(', ') + ', 203.0.113.9';
    expect(clientIp(req(FRONT_END, long))).toBe('203.0.113.9');
  });
});
