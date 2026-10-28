import { describe, it, expect } from 'vitest';
import { parseRelayExternalUrl } from '../externalUrl';
import { EDGES } from '../edge';
import { createRelay } from '../app';
import { createStatsRecorder } from '../stats';
import type Redis from 'ioredis';

describe('RELAY_EXTERNAL_URL', () => {
  it.each([
    ['https://relay.zkproofport.app', EDGES['load-balancer']],
    ['https://stg-relay.zkproofport.app', EDGES['load-balancer']],
    ['https://relay.zkproofport.app', EDGES['cloud-run-domain']],
    ['http://192.168.0.10:4001', EDGES.local],
    ['https://relay.example:8443', EDGES.local],
  ])('accepts %s', (value, edge) => {
    expect(parseRelayExternalUrl(value, edge)).toBe(value);
  });

  it('missing, empty and whitespace-only are each an error naming the variable', () => {
    for (const value of [undefined, '', '   ', '\t\n']) {
      expect(() => parseRelayExternalUrl(value, EDGES.local)).toThrow(/RELAY_EXTERNAL_URL environment variable is required/);
    }
  });

  it('refuses surrounding whitespace rather than trimming it', () => {
    expect(() => parseRelayExternalUrl(' https://relay.zkproofport.app', EDGES.local)).toThrow(/whitespace/);
  });

  it('refuses http behind every real front end; allows it only for local Docker', () => {
    expect(() => parseRelayExternalUrl('http://relay.zkproofport.app', EDGES['load-balancer'])).toThrow(/must be https/);
    expect(() => parseRelayExternalUrl('http://relay.zkproofport.app', EDGES['cloud-run-domain'])).toThrow(/must be https/);
    expect(parseRelayExternalUrl('http://relay.zkproofport.app', EDGES.local)).toBe('http://relay.zkproofport.app');
  });

  it.each([
    'relay.zkproofport.app',
    '/api',
    'ftp://relay.zkproofport.app',
    'javascript:alert(1)',
    'zkproofport://relay',
  ])('refuses %s as not an http(s) URL', (value) => {
    expect(() => parseRelayExternalUrl(value, EDGES.local)).toThrow(/absolute http\(s\) URL/);
  });

  it.each([
    'https://relay.zkproofport.app/',
    'https://relay.zkproofport.app/api/v1',
    'https://relay.zkproofport.app?x=1',
    'https://relay.zkproofport.app?',
    'https://relay.zkproofport.app#frag',
    'https://relay.zkproofport.app#',
    'https://Relay.ZKProofport.app',
    'https://relay.zkproofport.app:443',
  ])('refuses %s as not exactly an origin', (value) => {
    expect(() => parseRelayExternalUrl(value, EDGES.local)).toThrow(/exactly an origin/);
  });

  it('refuses credentials in the URL', () => {
    expect(() => parseRelayExternalUrl('https://user:pass@relay.zkproofport.app', EDGES.local)).toThrow(/credentials/);
  });

  it('every edge row says whether http is allowed; only local allows it', () => {
    expect(Object.entries(EDGES).map(([name, e]) => [name, e.httpsOnly])).toEqual([
      ['cloud-run-domain', true],
      ['load-balancer', true],
      ['local', false],
    ]);
  });

  it('createRelay refuses to start without one (no Host-header fallback)', () => {
    const base = {
      redis: {} as Redis,
      stats: createStatsRecorder({} as Redis),
      statsToken: 't'.repeat(64),
      adapter: null,
      edge: EDGES.local,
      deadlineMs: 1000,
      sweepIntervalMs: 1000,
      playIntegrity: { enabled: false as const, missing: ['PLAY_INTEGRITY_DECRYPTION_KEY', 'PLAY_INTEGRITY_VERIFICATION_KEY'] },
    };
    expect(() => createRelay({ ...base, relayExternalUrl: '' })).toThrow(/RELAY_EXTERNAL_URL environment variable is required/);
    expect(() => createRelay({ ...base, relayExternalUrl: 'https://relay.example/' })).toThrow(/exactly an origin/);
  });
});
