/**
 * The admin page over real HTTP, in process: status, content types, every
 * security header, no inline script or style, CORS kept off the page and the
 * stats API, and the stats route failing closed when its lockout store fails.
 *
 * Redis is not touched by any route exercised here, so the relay gets a stub
 * that throws if anything does reach it.
 */
import { describe, it, expect, afterEach } from 'vitest';
import type { AddressInfo } from 'net';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import path from 'path';
import express from 'express';
import type Redis from 'ioredis';
import { createRelay, Relay } from '../app';
import { ADMIN_ASSETS, ADMIN_DIR, ADMIN_SECURITY_HEADERS, loadAdminAssets, mountAdmin } from '../admin';
import type { StatsAuthGuard } from '../statsAuth';

const TOKEN = 'k'.repeat(64);
const EXPECTED_CSP =
  "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

const throwingRedis = new Proxy({}, {
  get(_t, prop) {
    if (prop === 'then') return undefined;
    return () => { throw new Error(`redis.${String(prop)} called in a test that must not reach Redis`); };
  },
}) as unknown as Redis;

const closers: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const c of closers.splice(0)) await c();
});

async function startRelay(opts: { statsAuth?: StatsAuthGuard } = {}): Promise<{ relay: Relay; url: string }> {
  const relay = createRelay({
    redis: throwingRedis,
    stats: { record() {} },
    statsToken: TOKEN,
    statsAuth: opts.statsAuth ?? { lockedFor: async () => 0, recordFailure: async () => 1 },
    adapter: null,
    relayExternalUrl: '',
    port: 0,
    deadlineMs: 3_600_000,
    sweepIntervalMs: 3_600_000,
  });
  await new Promise<void>((resolve) => relay.httpServer.listen(0, '127.0.0.1', resolve));
  closers.push(() => relay.close());
  return { relay, url: `http://127.0.0.1:${(relay.httpServer.address() as AddressInfo).port}` };
}

function expectSecurityHeaders(res: Response) {
  expect(res.headers.get('content-security-policy')).toBe(EXPECTED_CSP);
  expect(res.headers.get('x-frame-options')).toBe('DENY');
  expect(res.headers.get('referrer-policy')).toBe('no-referrer');
  expect(res.headers.get('cache-control')).toBe('no-store');
  expect(res.headers.get('x-robots-tag')).toBe('noindex');
  expect(res.headers.get('x-content-type-options')).toBe('nosniff');
  expect(res.headers.get('access-control-allow-origin')).toBeNull();
}

describe('admin page and assets', () => {
  const cases: Array<[string, RegExp]> = [
    ['/admin', /^text\/html; charset=utf-8$/],
    ['/admin/', /^text\/html; charset=utf-8$/],
    ['/admin/admin.css', /^text\/css; charset=utf-8$/],
    ['/admin/app.mjs', /^text\/javascript; charset=utf-8$/],
    ['/admin/core.mjs', /^text\/javascript; charset=utf-8$/],
  ];

  it.each(cases)('%s: 200, content type, every security header (inside the full relay, after helmet)', async (p, type) => {
    const { url } = await startRelay();
    const res = await fetch(`${url}${p}`, { headers: { Origin: 'https://evil.example' } });
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toMatch(type);
    expectSecurityHeaders(res);
    expect((await res.arrayBuffer()).byteLength).toBeGreaterThan(0);
  });

  it('the exact header set is what the task asked for', () => {
    expect(ADMIN_SECURITY_HEADERS['Content-Security-Policy']).toBe(EXPECTED_CSP);
  });

  it.each(['/admin/nope.js', '/admin/core.d.mts', '/admin/index.html', '/admin/..%2fpackage.json', '/admin/app.mjs/x', '/admin/%00'])(
    '%s: 404, still with the security headers, never a file outside the list',
    async (p) => {
      const { url } = await startRelay();
      const res = await fetch(`${url}${p}`);
      expect(res.status).toBe(404);
      expectSecurityHeaders(res);
    },
  );

  it('a dot-dot path never reaches a file: the client resolves it out of /admin and the relay has no such route', async () => {
    const { url } = await startRelay();
    for (const p of ['/admin/%2e%2e/package.json', '/admin/../package.json', '/admin/../src/index.ts']) {
      const res = await fetch(`${url}${p}`);
      expect(res.status).toBe(404);
      expect(await res.text()).not.toMatch(/proofport-relay|RELAY_STATS_TOKEN/);
    }
  });

  it('the HTML has no inline script, inline style, style attribute or event handler', () => {
    const html = readFileSync(path.join(ADMIN_DIR, 'index.html'), 'utf8');
    const scripts = html.match(/<script\b[^>]*>/gi) ?? [];
    expect(scripts.length).toBeGreaterThan(0);
    for (const tag of scripts) expect(tag).toMatch(/\ssrc="\/admin\/[a-z]+\.mjs"/);
    expect(html).not.toMatch(/<script\b[^>]*>[^<\s]/i);
    expect(html).not.toMatch(/<style\b/i);
    expect(html).not.toMatch(/\sstyle\s*=/i);
    expect(html).not.toMatch(/\son[a-z]+\s*=/i);
    expect(html).not.toMatch(/javascript:/i);
    expect(html).not.toMatch(/https?:\/\//i); // nothing from another origin
  });

  it('the token input has no name, so a form submitted without the script carries nothing', () => {
    const html = readFileSync(path.join(ADMIN_DIR, 'index.html'), 'utf8');
    const input = /<input id="token-input"[^>]*>/.exec(html)?.[0];
    expect(input).toBeDefined();
    expect(input).not.toMatch(/\sname=/);
    expect(input).toMatch(/type="password"/);
  });

  it('the scripts never write data with innerHTML / outerHTML / insertAdjacentHTML / document.write', () => {
    for (const f of ['app.mjs', 'core.mjs']) {
      const src = readFileSync(path.join(ADMIN_DIR, f), 'utf8').replace(/^\s*\/\/.*$/gm, '');
      expect(src).not.toMatch(/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/);
    }
  });

  it('the token goes to sessionStorage only -- no localStorage, cookie or URL', () => {
    const src = readFileSync(path.join(ADMIN_DIR, 'app.mjs'), 'utf8');
    expect(src).toMatch(/sessionStorage\.setItem/);
    expect(src).not.toMatch(/localStorage|document\.cookie|history\.(push|replace)State|location\.(href|search|hash)\s*=/);
  });

  it('a missing asset stops startup with the file named, instead of a 404 later', () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'relay-admin-'));
    try {
      for (const { file } of Object.values(ADMIN_ASSETS)) writeFileSync(path.join(dir, file), 'x');
      expect(() => loadAdminAssets(dir)).not.toThrow();
      rmSync(path.join(dir, 'app.mjs'));
      expect(() => loadAdminAssets(dir)).toThrow(/app\.mjs/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('mountAdmin alone (no helmet) still sends every header', async () => {
    const app = express();
    mountAdmin(app);
    const server = app.listen(0, '127.0.0.1');
    await new Promise((r) => server.once('listening', r));
    closers.push(() => new Promise((r) => server.close(() => r())));
    const res = await fetch(`http://127.0.0.1:${(server.address() as AddressInfo).port}/admin`);
    expect(res.status).toBe(200);
    for (const [k, v] of Object.entries(ADMIN_SECURITY_HEADERS)) expect(res.headers.get(k)).toBe(v);
  });
});

describe('CORS on the admin page and the stats API', () => {
  it.each(['https://evil.example', 'https://demo.zkproofport.app'])('%s gets no CORS headers on /api/v1/stats or /admin', async (from) => {
    const { url } = await startRelay();
    const preflight = await fetch(`${url}/api/v1/stats?from=2026-10-14&to=2026-10-14`, {
      method: 'OPTIONS',
      headers: { Origin: from, 'Access-Control-Request-Method': 'GET', 'Access-Control-Request-Headers': 'authorization' },
    });
    expect(preflight.headers.get('access-control-allow-origin')).toBeNull();
    expect(preflight.headers.get('access-control-allow-headers')).toBeNull();
    const get = await fetch(`${url}/api/v1/stats?from=2026-10-14&to=2026-10-14`, { headers: { Origin: from, Authorization: `Bearer ${TOKEN}` } }).catch(() => null);
    // The stub Redis throws on read, so the body is a 500; the header is what matters.
    expect(get?.headers.get('access-control-allow-origin')).toBeNull();
    const upper = await fetch(`${url}/API/V1/STATS`, { method: 'OPTIONS', headers: { Origin: from, 'Access-Control-Request-Method': 'GET' } });
    expect(upper.headers.get('access-control-allow-origin')).toBeNull();
  });

  // Any dApp's page, including one nobody registered and a developer's localhost.
  it.each(['https://dapp.example', 'https://dojangscan.com', 'http://localhost:3000', 'null'])(
    'the public API answers a browser on %s (the SDK calls it cross-origin)',
    async (from) => {
      const { url } = await startRelay();
      const calls: Array<[string, string, string?]> = [
        ['/api/v1/challenge', 'GET'],
        ['/api/v1/proof/request', 'POST', 'content-type'],
        ['/api/v1/proof/00000000-0000-4000-8000-000000000000', 'GET'],
      ];
      for (const [path, method, headers] of calls) {
        const preflight = await fetch(`${url}${path}`, {
          method: 'OPTIONS',
          headers: {
            Origin: from,
            'Access-Control-Request-Method': method,
            ...(headers ? { 'Access-Control-Request-Headers': headers } : {}),
          },
        });
        expect(preflight.status).toBe(204);
        expect(preflight.headers.get('access-control-allow-origin')).toBe('*');
        expect(preflight.headers.get('access-control-allow-methods')).toContain(method);
        // No cookie may ride along: a credentialed CORS answer would need the exact origin.
        expect(preflight.headers.get('access-control-allow-credentials')).toBeNull();
      }
      const socket = await fetch(`${url}/socket.io/?EIO=4&transport=polling`, { headers: { Origin: from } });
      expect(socket.headers.get('access-control-allow-origin')).toBe('*');
    },
  );
});

describe('GET /api/v1/stats auth (lockout store stubbed)', () => {
  it('the lockout store failing answers 500, never the stats', async () => {
    const { url } = await startRelay({ statsAuth: { lockedFor: async () => { throw new Error('redis down'); }, recordFailure: async () => 1 } });
    const res = await fetch(`${url}/api/v1/stats?from=2026-10-14&to=2026-10-14`, { headers: { Authorization: `Bearer ${TOKEN}` } });
    expect(res.status).toBe(500);
    expect(res.headers.get('cache-control')).toBe('no-store');
  });

  it('recording a failure failing answers 500, not 401 -- and never 200', async () => {
    const { url } = await startRelay({ statsAuth: { lockedFor: async () => 0, recordFailure: async () => { throw new Error('redis down'); } } });
    const res = await fetch(`${url}/api/v1/stats?from=2026-10-14&to=2026-10-14`, { headers: { Authorization: 'Bearer wrong' } });
    expect(res.status).toBe(500);
  });

  it('locked out: 429 with Retry-After, before the token is even compared', async () => {
    let recorded = 0;
    const { url } = await startRelay({ statsAuth: { lockedFor: async () => 321, recordFailure: async () => ++recorded } });
    const res = await fetch(`${url}/api/v1/stats?from=2026-10-14&to=2026-10-14`, { headers: { Authorization: `Bearer ${TOKEN}` } });
    expect(res.status).toBe(429);
    expect(res.headers.get('retry-after')).toBe('321');
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(recorded).toBe(0);
  });

  it('every wrong-token shape is a 401 that is counted, with WWW-Authenticate and no-store', async () => {
    const seen: string[] = [];
    const { url } = await startRelay({ statsAuth: { lockedFor: async () => 0, recordFailure: async (ip) => { seen.push(ip); return seen.length; } } });
    const shapes: Array<Record<string, string>> = [
      {},
      { Authorization: '' },
      { Authorization: 'Bearer' },
      { Authorization: 'Bearer ' },
      { Authorization: `Basic ${TOKEN}` },
      { Authorization: `bearer ${TOKEN}` },
      // (A trailing space is not a case: HTTP strips it from header values, on
      // the client and the server, so `Bearer <token> ` IS the token.)
      { Authorization: `Bearer ${TOKEN.slice(1)}` },
      { Authorization: `Bearer ${TOKEN}x` },
      { Authorization: `Bearer ${'k'.repeat(10_000)}` },
      { Authorization: "Bearer ' OR 1=1 --" },
      { Authorization: 'Bearer %' },
    ];
    for (const headers of shapes) {
      const res = await fetch(`${url}/api/v1/stats?from=2026-10-14&to=2026-10-14`, { headers });
      expect(res.status, JSON.stringify(headers).slice(0, 80)).toBe(401);
      expect(res.headers.get('www-authenticate')).toBe('Bearer');
      expect(res.headers.get('cache-control')).toBe('no-store');
    }
    expect(seen).toHaveLength(shapes.length);
    expect(new Set(seen)).toEqual(new Set(['127.0.0.1']));
  });

  it('the failure is counted under the corrected address (rightmost X-Forwarded-For), not a spoofed one', async () => {
    const seen: string[] = [];
    const { url } = await startRelay({ statsAuth: { lockedFor: async () => 0, recordFailure: async (ip) => { seen.push(ip); return 1; } } });
    for (const spoof of ['1.1.1.1', '2.2.2.2']) {
      await fetch(`${url}/api/v1/stats?from=2026-10-14&to=2026-10-14`, { headers: { 'X-Forwarded-For': `${spoof}, 198.51.100.4` } });
    }
    expect(seen).toEqual(['198.51.100.4', '198.51.100.4']);
  });
});
