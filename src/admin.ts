import { readFileSync } from 'fs';
import path from 'path';
import type { Express, NextFunction, Request, Response } from 'express';

/**
 * The admin dashboard: one page at /admin that logs in with the stats token
 * and draws GET /api/v1/stats. Plain HTML, CSS and ES modules, served from
 * memory; no framework, no build step, nothing loaded from another origin.
 *
 * The files live in src/admin/ and are copied to dist/admin/ by `npm run build`
 * (tsc copies only TypeScript). They are read once at startup: a relay built
 * without them refuses to start rather than answering /admin with a 404.
 */
export const ADMIN_DIR = path.join(__dirname, 'admin');

/** Published path -> file name and content type. Nothing else under /admin is served. */
export const ADMIN_ASSETS: Record<string, { file: string; type: string }> = {
  '/admin': { file: 'index.html', type: 'text/html; charset=utf-8' },
  '/admin/admin.css': { file: 'admin.css', type: 'text/css; charset=utf-8' },
  '/admin/app.mjs': { file: 'app.mjs', type: 'text/javascript; charset=utf-8' },
  '/admin/core.mjs': { file: 'core.mjs', type: 'text/javascript; charset=utf-8' },
  // Country shapes for the map, built by scripts/build-world-map.mjs.
  '/admin/world.json': { file: 'world.json', type: 'application/json; charset=utf-8' },
};

/**
 * Every value here is load-bearing:
 *   CSP          no inline script or style, no other origin; the page can only
 *                fetch its own origin (the stats API) and cannot be framed
 *   frame        X-Frame-Options for browsers that ignore frame-ancestors
 *   referrer     the page URL never leaves in a Referer header
 *   no-store     a token-gated page and its data are never cached
 *   noindex      the page is not for search engines
 */
export const ADMIN_SECURITY_HEADERS: Record<string, string> = {
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
  'X-Robots-Tag': 'noindex',
};

export function applyAdminSecurityHeaders(res: Response): void {
  for (const [name, value] of Object.entries(ADMIN_SECURITY_HEADERS)) res.setHeader(name, value);
}

export function loadAdminAssets(dir: string = ADMIN_DIR): Map<string, { body: Buffer; type: string }> {
  const loaded = new Map<string, { body: Buffer; type: string }>();
  for (const [route, { file, type }] of Object.entries(ADMIN_ASSETS)) {
    const full = path.join(dir, file);
    let body: Buffer;
    try {
      body = readFileSync(full);
    } catch (err) {
      throw new Error(`Admin page asset missing: ${full} (${(err as Error).message}). Build with \`npm run build\`, which copies src/admin to dist/admin.`);
    }
    loaded.set(route, { body, type });
  }
  return loaded;
}

export function mountAdmin(app: Express, assets = loadAdminAssets()): void {
  // Headers first, for every path under /admin -- a 404 there gets them too.
  app.use('/admin', (_req: Request, res: Response, next: NextFunction) => {
    applyAdminSecurityHeaders(res);
    next();
  });
  for (const [route, asset] of assets) {
    app.get(route, (_req: Request, res: Response) => {
      res.setHeader('Content-Type', asset.type);
      res.send(asset.body);
    });
  }
  app.use('/admin', (_req: Request, res: Response) => {
    res.status(404).json({ error: 'Not found' });
  });
}
