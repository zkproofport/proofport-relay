/**
 * E2E in a real (headless) browser against the running relay container:
 * log in to /admin with the dev stats token, see real counts after creating
 * requests and outcomes, wrong token, empty range, hostile data rendered as
 * text, token storage, logout.
 *
 * Headless Chromium through playwright-core; nothing touches the host's screen
 * or cursor. The browser binary comes from Playwright's cache: install it once
 * with `npx playwright-core install chromium-headless-shell` in proofport-relay.
 *
 * The browser sends an X-Forwarded-For entry of its own (as Google's front end
 * would append) so its wrong-token attempts land in a bucket nobody else uses.
 *
 * Screenshots go to RELAY_E2E_SCREENSHOT_DIR (scripts/test-relay.sh makes a
 * temporary directory and prints it). Run: `scripts/test-relay.sh e2e`.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import path from 'path';
import { mkdirSync } from 'fs';
import Redis from 'ioredis';
import { chromium, Browser, BrowserContext, Page } from 'playwright-core';

function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required. Run scripts/test-relay.sh e2e.`);
  return v;
}

const A = required('RELAY_URL');
const TOKEN = required('RELAY_STATS_TOKEN');
const REDIS_E2E_URL = required('REDIS_E2E_URL');
const SHOTS = required('RELAY_E2E_SCREENSHOT_DIR');
const CIRCUIT = 'mdl_kr_ownership';
const BROWSER_IP = `198.19.250.${Math.floor(Math.random() * 250) + 1}`;
const API_IP = `198.19.251.${Math.floor(Math.random() * 250) + 1}`;
const XSS_DAY = '2001-01-01';
const XSS_CIRCUIT = '<img src=x onerror="window.__xss=1">';

let browser: Browser;
let redis: Redis;
const today = new Date().toISOString().slice(0, 10);

async function createRequest(): Promise<string> {
  const h = { 'X-Forwarded-For': API_IP };
  const ch = await (await fetch(`${A}/api/v1/challenge`, { headers: h })).json() as { requestId: string; challenge: string };
  const res = await fetch(`${A}/api/v1/proof/request`, {
    method: 'POST',
    headers: { ...h, 'Content-Type': 'application/json' },
    body: JSON.stringify({ requestId: ch.requestId, challenge: ch.challenge, circuitId: CIRCUIT, inputs: { scope: 'admin-e2e.example' } }),
  });
  expect(res.status).toBe(201);
  return ch.requestId;
}

async function callback(body: Record<string, unknown>) {
  const res = await fetch(`${A}/api/v1/proof/callback`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  expect(res.status).toBe(200);
}

async function apiCounts(circuit: string, day: string) {
  const res = await fetch(`${A}/api/v1/stats?from=${day}&to=${day}`, { headers: { Authorization: `Bearer ${TOKEN}`, 'X-Forwarded-For': API_IP } });
  expect(res.status).toBe(200);
  const body = await res.json() as { totals: { circuits: Record<string, { requested: number; completed: number; cancelled: number; expired: number; error: { total: number; byCode: Record<string, number> } }> } };
  return body.totals.circuits[circuit];
}

async function newPage(): Promise<{ context: BrowserContext; page: Page; cspErrors: string[]; pageErrors: string[] }> {
  const context = await browser.newContext({ extraHTTPHeaders: { 'X-Forwarded-For': BROWSER_IP } });
  const page = await context.newPage();
  const cspErrors: string[] = [];
  const pageErrors: string[] = [];
  page.on('console', (m) => {
    if (m.type() === 'error' && /Content Security Policy|Refused to/i.test(m.text())) cspErrors.push(m.text());
  });
  page.on('pageerror', (e) => pageErrors.push(String(e)));
  return { context, page, cspErrors, pageErrors };
}

async function shot(page: Page, name: string) {
  const file = path.join(SHOTS, `${name}.png`);
  await page.screenshot({ path: file, fullPage: true });
  console.log(`[admin-browser-e2e] screenshot ${file}`);
}

async function login(page: Page, token: string) {
  await page.goto(`${A}/admin`);
  await page.locator('#login-view').waitFor({ state: 'visible' });
  await page.fill('#token-input', token);
  await page.click('#login-button');
}

beforeAll(async () => {
  mkdirSync(SHOTS, { recursive: true });
  redis = new Redis(REDIS_E2E_URL);
  browser = await chromium.launch({ headless: true });
});

afterAll(async () => {
  await redis.del(`relay:stats:${XSS_DAY}`);
  await redis.quit();
  await browser?.close();
});

describe('admin dashboard in a browser', () => {
  it('wrong token: error shown, still on the login view, nothing stored', async () => {
    const { context, page, cspErrors, pageErrors } = await newPage();
    await login(page, 'f'.repeat(64));
    await page.locator('#login-error').waitFor({ state: 'visible' });
    expect(await page.textContent('#login-error')).toBe('토큰이 올바르지 않습니다.');
    expect(await page.isVisible('#dashboard-view')).toBe(false);
    expect(await page.evaluate(() => sessionStorage.length)).toBe(0);
    await shot(page, '01-wrong-token');

    // A token an HTTP header cannot carry is refused in the page, not sent.
    await page.fill('#token-input', '토큰');
    await page.click('#login-button');
    expect(await page.textContent('#login-error')).toMatch(/영문/);
    expect(cspErrors).toEqual([]);
    expect(pageErrors).toEqual([]);
    await context.close();
  });

  it('logs in with the dev token and shows the real counts after requests and outcomes', async () => {
    const done = await createRequest();
    const failed = await createRequest();
    const cancelled = await createRequest();
    await callback({ requestId: done, status: 'completed', proof: '0x01', publicInputs: [], circuit: CIRCUIT });
    await callback({ requestId: failed, status: 'error', error: 'no attestation', errorCode: 'E2005', circuit: CIRCUIT });
    await callback({ requestId: cancelled, status: 'cancelled', circuit: CIRCUIT });
    // Counting is fire-and-forget; give it a moment, then take the API's numbers as the truth.
    await new Promise((r) => setTimeout(r, 300));
    const expected = await apiCounts(CIRCUIT, today);
    expect(expected.requested).toBeGreaterThanOrEqual(3);
    expect(expected.error.byCode.E2005).toBeGreaterThanOrEqual(1);

    const { context, page, cspErrors, pageErrors } = await newPage();
    await login(page, TOKEN);
    await page.locator('#dashboard-view').waitFor({ state: 'visible' });
    await page.locator('#content').waitFor({ state: 'visible' });

    expect(await page.textContent('#range-label')).toContain('UTC');
    expect(await page.getAttribute('.preset[data-days="7"]', 'aria-pressed')).toBe('true');
    expect(await page.inputValue('#to-input')).toBe(today);

    const row = page.locator('#circuit-table tbody tr', { has: page.locator('td:first-child', { hasText: new RegExp(`^${CIRCUIT}$`) }) });
    // The 7-day range holds more than today; compare with the API over the same range.
    const from = await page.inputValue('#from-input');
    const week = await (await fetch(`${A}/api/v1/stats?from=${from}&to=${today}`, { headers: { Authorization: `Bearer ${TOKEN}`, 'X-Forwarded-For': API_IP } })).json() as { totals: { circuits: Record<string, { requested: number; completed: number; cancelled: number; expired: number; error: { total: number } }> } };
    const w = week.totals.circuits[CIRCUIT];
    const cells = (await row.locator('td').allTextContents()).map((t) => t.replace(/,/g, ''));
    expect(cells.slice(0, 6)).toEqual([CIRCUIT, String(w.requested), String(w.completed), String(w.error.total), String(w.cancelled), String(w.expired)]);
    expect(cells[6]).toBe(`${((w.completed / w.requested) * 100).toFixed(1)}%`);

    const errRow = page.locator('#error-table tbody tr', { hasText: 'E2005' }).first();
    expect(await errRow.textContent()).toContain('Attestation Not Found');

    const todayRow = page.locator('#day-table tbody tr', { has: page.locator('td:first-child', { hasText: today }) });
    expect(await todayRow.count()).toBe(1);
    expect(await page.locator('#chart svg rect').count()).toBeGreaterThan(0);

    // Token storage: this tab's sessionStorage only.
    expect(await page.evaluate(() => Object.keys(sessionStorage))).toEqual(['relay-admin-stats-token']);
    expect(await page.evaluate(() => localStorage.length)).toBe(0);
    expect(await context.cookies()).toEqual([]);
    expect(page.url()).toBe(`${A}/admin`);
    expect(page.url()).not.toContain(TOKEN);
    await shot(page, '02-dashboard');

    // Presets: 30 days asks the API for 30 days.
    const [resp30] = await Promise.all([
      page.waitForResponse((r) => r.url().includes('/api/v1/stats')),
      page.click('.preset[data-days="30"]'),
    ]);
    expect(resp30.status()).toBe(200);
    expect(await page.getAttribute('.preset[data-days="30"]', 'aria-pressed')).toBe('true');
    const from30 = await page.inputValue('#from-input');
    expect(resp30.url()).toContain(`from=${from30}&to=${today}`);
    expect((Date.parse(today) - Date.parse(from30)) / 86_400_000 + 1).toBe(30);

    // Filter to the circuit: tiles show its numbers.
    await page.selectOption('#circuit-select', CIRCUIT);
    expect(Number((await page.textContent('#tile-requested'))!.replace(/,/g, ''))).toBeGreaterThanOrEqual(3);
    await shot(page, '03-dashboard-30d-filtered');

    // A reload stays logged in (same tab).
    await page.reload();
    await page.locator('#content').waitFor({ state: 'visible' });

    expect(cspErrors).toEqual([]);
    expect(pageErrors).toEqual([]);
    await context.close();
  });

  it('an empty range shows an explicit no-data state; a range over 400 days is refused in the page', async () => {
    const { context, page } = await newPage();
    await login(page, TOKEN);
    await page.locator('#dashboard-view').waitFor({ state: 'visible' });
    await page.fill('#from-input', '2000-01-01');
    await page.fill('#to-input', '2000-01-07');
    await page.click('#range-form button[type="submit"]');
    await page.locator('#empty-state').waitFor({ state: 'visible' });
    expect(await page.isVisible('#content')).toBe(false);
    expect(await page.textContent('#range-label')).toContain('2000-01-01 ~ 2000-01-07');
    await shot(page, '04-empty-range');

    await page.fill('#from-input', '2000-01-01');
    await page.fill('#to-input', '2001-12-31');
    await page.click('#range-form button[type="submit"]');
    await page.locator('#dashboard-error').waitFor({ state: 'visible' });
    expect(await page.textContent('#dashboard-error')).toMatch(/최대 400일/);
    await context.close();
  });

  it('a hostile circuit name in the data is shown as text and never runs', async () => {
    await redis.hset(`relay:stats:${XSS_DAY}`, `${XSS_CIRCUIT}|requested`, '2', `${XSS_CIRCUIT}|error|E2005`, '1');
    await redis.expire(`relay:stats:${XSS_DAY}`, 600);
    const { context, page, pageErrors } = await newPage();
    await login(page, TOKEN);
    await page.locator('#dashboard-view').waitFor({ state: 'visible' });
    await page.locator('#content').waitFor({ state: 'visible' }); // the default range has loaded
    await page.fill('#from-input', XSS_DAY);
    await page.fill('#to-input', XSS_DAY);
    // Wait for THIS range's answer: #content is already visible from the default range.
    const [res] = await Promise.all([
      page.waitForResponse((r) => r.url().includes(`from=${XSS_DAY}&to=${XSS_DAY}`)),
      page.click('#range-form button[type="submit"]'),
    ]);
    expect(res.status()).toBe(200);
    await expect.poll(async () => page.textContent('#range-label')).toMatch(new RegExp(`^${XSS_DAY} ~`));
    expect(await page.textContent('#circuit-table tbody tr td:first-child')).toBe(XSS_CIRCUIT);
    expect(await page.locator('img').count()).toBe(0);
    expect(await page.evaluate(() => (globalThis as unknown as { __xss?: number }).__xss)).toBeUndefined();
    expect(await page.locator('#circuit-select option', { hasText: XSS_CIRCUIT }).count()).toBe(1);
    await shot(page, '05-hostile-name-as-text');
    expect(pageErrors).toEqual([]);
    await context.close();
  });

  it('logout returns to the login view and forgets the token; a new tab starts logged out', async () => {
    const { context, page } = await newPage();
    await login(page, TOKEN);
    await page.locator('#dashboard-view').waitFor({ state: 'visible' });
    await page.click('#logout-button');
    await page.locator('#login-view').waitFor({ state: 'visible' });
    expect(await page.isVisible('#dashboard-view')).toBe(false);
    expect(await page.evaluate(() => sessionStorage.length)).toBe(0);
    await page.reload();
    await page.locator('#login-view').waitFor({ state: 'visible' });
    await shot(page, '06-after-logout');
    await context.close();

    const fresh = await newPage();
    await fresh.page.goto(`${A}/admin`);
    await fresh.page.locator('#login-view').waitFor({ state: 'visible' });
    expect(await fresh.page.isVisible('#dashboard-view')).toBe(false);
    await fresh.context.close();
  });

  it('a stored token that stopped working (rotated) sends the page back to login with a message', async () => {
    const { context, page } = await newPage();
    await page.goto(`${A}/admin`);
    await page.evaluate(() => sessionStorage.setItem('relay-admin-stats-token', 'e'.repeat(64)));
    await page.reload();
    await page.locator('#login-view').waitFor({ state: 'visible' });
    await page.locator('#login-error').waitFor({ state: 'visible' });
    expect(await page.textContent('#login-error')).toMatch(/다시 로그인/);
    expect(await page.evaluate(() => sessionStorage.length)).toBe(0);
    await context.close();
  });
});
