/**
 * Unit tests for clientIpReader(): which address a request is counted under.
 * The integration and E2E suites check the same thing through the real rate
 * limiter, over HTTP and Socket.IO.
 */
import { describe, it, expect } from 'vitest';
import type { IncomingMessage } from 'http';
import express from 'express';
import { clientIpReader, trustHops } from '../clientIp';
import { EDGES, edgeFor } from '../edge';

function req(remoteAddress: string, xff?: string | string[]): IncomingMessage {
  const headers: Record<string, string | string[]> = {};
  if (xff !== undefined) headers['x-forwarded-for'] = xff;
  return { headers, socket: { remoteAddress }, connection: { remoteAddress } } as unknown as IncomingMessage;
}

const clientIp = clientIpReader(EDGES['cloud-run-domain'].proxyHops);

describe('edges', () => {
  it('a Cloud Run domain mapping is one hop, a load balancer in front of it two, never "trust everything"', () => {
    expect(EDGES['cloud-run-domain'].proxyHops).toBe(1);
    expect(EDGES['load-balancer'].proxyHops).toBe(2);
    expect(EDGES.local.proxyHops).toBe(1);
  });

  it('only a front end of ours that writes the country header has one', () => {
    expect(EDGES['cloud-run-domain'].regionHeader).toBeNull();
    expect(EDGES['load-balancer'].regionHeader).toBe('x-relay-client-region');
  });

  it('a missing or unknown RELAY_EDGE is an error naming the known ones, never a default', () => {
    expect(() => edgeFor(undefined)).toThrow(/RELAY_EDGE environment variable is required.*cloud-run-domain, load-balancer, local/);
    expect(() => edgeFor('')).toThrow(/required/);
    expect(() => edgeFor('loadbalancer')).toThrow(/Unknown RELAY_EDGE 'loadbalancer'/);
    expect(() => edgeFor('toString')).toThrow(/Unknown RELAY_EDGE/);
    expect(() => edgeFor('__proto__')).toThrow(/Unknown RELAY_EDGE/);
  });

  it('every edge matches what Express compiles for the same hop count, so req.ip and clientIp() agree', () => {
    for (const edge of Object.values(EDGES)) {
      const app = express();
      app.set('trust proxy', edge.proxyHops);
      const expressTrust = app.get('trust proxy fn') as (addr: string, i: number) => boolean;
      const ours = trustHops(edge.proxyHops);
      for (let i = 0; i < 5; i++) expect(ours('10.0.0.1', i)).toBe(expressTrust('10.0.0.1', i));
    }
  });

  it('refuses a hop count that would trust nothing or everything', () => {
    for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) expect(() => trustHops(bad)).toThrow(/positive integer/);
  });
});

describe('clientIp behind a load balancer (two hops)', () => {
  const viaLb = clientIpReader(EDGES['load-balancer'].proxyHops);
  const FRONT_END = '169.254.169.126';
  const LB = '35.191.0.1';

  it('`<client>,<lb>`: the client', () => {
    expect(viaLb(req(FRONT_END, `203.0.113.7, ${LB}`))).toBe('203.0.113.7');
  });

  it('a spoofed leftmost entry does not change the result', () => {
    const answers = ['1.1.1.1', 'evil', '1.1.1.1, 2.2.2.2'].map((spoof) => viaLb(req(FRONT_END, `${spoof}, 203.0.113.7, ${LB}`)));
    expect(new Set(answers)).toEqual(new Set(['203.0.113.7']));
  });

  it('is never the load balancer itself', () => {
    expect(viaLb(req(FRONT_END, `203.0.113.7, ${LB}`))).not.toBe(LB);
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
