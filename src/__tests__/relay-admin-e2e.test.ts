/**
 * E2E over HTTP against the running relay container (:4001): the caller's
 * address under trust proxy = one hop, the admin page's headers, CORS on the
 * stats API, and the wrong-token lockout.
 *
 * Locally there is no Google front end, so these requests send the
 * X-Forwarded-For entry that front end would append. Each run uses fresh
 * addresses from 198.18.0.0/15 (reserved for benchmarking), so it has its own
 * buckets and never spends the budget of the other E2E files, which call
 * without the header and are counted under Docker's gateway address.
 *
 * Run: `scripts/test-relay.sh e2e`.
 */
import { describe, it, expect, beforeAll } from 'vitest';

function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required. Run scripts/test-relay.sh e2e.`);
  return v;
}

const A = required('RELAY_URL');
const TOKEN = required('RELAY_STATS_TOKEN');
const CSP =
  "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

const runOctet = Math.floor(Math.random() * 200);
let next = 1;
/** A caller address nobody else uses this run. */
function freshIp(): string {
  const n = next++;
  return `198.19.${runOctet}.${n}`;
}

beforeAll(async () => {
  const res = await fetch(`${A}/health`);
  if (!res.ok) throw new Error(`${A} not healthy: ${res.status}`);
});

async function hitRequest(xff: string): Promise<number> {
  const res = await fetch(`${A}/api/v1/proof/request`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': xff },
    body: '{}',
  });
  return res.status;
}

describe('caller address on the container', () => {
  it('a spoofed leftmost entry does not change the bucket', async () => {
    const real = freshIp();
    const statuses: number[] = [];
    for (let i = 0; i < 11; i++) statuses.push(await hitRequest(`10.0.0.${i}, ${real}`));
    expect(statuses.slice(0, 10)).toEqual(Array(10).fill(401));
    expect(statuses[10]).toBe(429);
  });

  it('two different rightmost entries get separate buckets', async () => {
    const one = freshIp();
    const two = freshIp();
    for (let i = 0; i < 10; i++) await hitRequest(one);
    expect(await hitRequest(one)).toBe(429);
    expect(await hitRequest(two)).toBe(401);
  });
});

describe('/admin on the container', () => {
  it.each([
    ['/admin', 'text/html; charset=utf-8'],
    ['/admin/admin.css', 'text/css; charset=utf-8'],
    ['/admin/app.mjs', 'text/javascript; charset=utf-8'],
    ['/admin/core.mjs', 'text/javascript; charset=utf-8'],
  ])('%s: 200, %s, every security header, no CORS', async (p, type) => {
    const res = await fetch(`${A}${p}`, { headers: { Origin: 'https://evil.example' } });
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toBe(type);
    expect(res.headers.get('content-security-policy')).toBe(CSP);
    expect(res.headers.get('x-frame-options')).toBe('DENY');
    expect(res.headers.get('referrer-policy')).toBe('no-referrer');
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(res.headers.get('x-robots-tag')).toBe('noindex');
    expect(res.headers.get('access-control-allow-origin')).toBeNull();
  });

  it('the served HTML loads only same-origin module scripts, with no inline script or style', async () => {
    const html = await (await fetch(`${A}/admin`)).text();
    for (const tag of html.match(/<script\b[^>]*>/gi) ?? []) expect(tag).toMatch(/src="\/admin\/[a-z]+\.mjs"/);
    expect(html).not.toMatch(/<style\b|\sstyle\s*=|\son[a-z]+\s*=/i);
  });
});

describe('GET /api/v1/stats on the container: CORS and lockout', () => {
  it('no CORS headers for another origin, on the preflight or the call, even though the public API allows any origin', async () => {
    const pre = await fetch(`${A}/api/v1/stats?from=2026-10-14&to=2026-10-14`, {
      method: 'OPTIONS',
      headers: { Origin: 'https://evil.example', 'Access-Control-Request-Method': 'GET', 'Access-Control-Request-Headers': 'authorization' },
    });
    expect(pre.headers.get('access-control-allow-origin')).toBeNull();
    const get = await fetch(`${A}/api/v1/stats?from=2026-10-14&to=2026-10-14`, {
      headers: { Origin: 'https://evil.example', Authorization: `Bearer ${TOKEN}`, 'X-Forwarded-For': freshIp() },
    });
    expect(get.status).toBe(200);
    expect(get.headers.get('access-control-allow-origin')).toBeNull();
    expect(get.headers.get('cache-control')).toBe('no-store');
    // The public API keeps its CORS.
    const ch = await fetch(`${A}/api/v1/challenge`, { method: 'OPTIONS', headers: { Origin: 'https://dapp.example', 'Access-Control-Request-Method': 'GET' } });
    expect(ch.headers.get('access-control-allow-origin')).toBe('*');
  });

  it('10 wrong tokens, then 429 with Retry-After -- also for the right token -- while another caller is unaffected', async () => {
    const ip = freshIp();
    const call = (token: string, xff = ip) =>
      fetch(`${A}/api/v1/stats?from=2026-10-14&to=2026-10-14`, { headers: { Authorization: `Bearer ${token}`, 'X-Forwarded-For': xff } });
    for (let i = 0; i < 10; i++) expect((await call(`wrong-${i}`)).status).toBe(401);
    const locked = await call('wrong-again');
    expect(locked.status).toBe(429);
    const ra = Number(locked.headers.get('retry-after'));
    expect(ra).toBeGreaterThan(0);
    expect(ra).toBeLessThanOrEqual(900);
    expect((await call(TOKEN)).status).toBe(429);
    expect((await call(TOKEN, freshIp())).status).toBe(200);
  });
});
