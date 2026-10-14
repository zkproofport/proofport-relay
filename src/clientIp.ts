import type { IncomingMessage } from 'http';
import proxyaddr from 'proxy-addr';

/**
 * How many proxies in front of the relay append to X-Forwarded-For.
 *
 * The relay's hostnames (relay.zkproofport.app, stg-relay.zkproofport.app) are
 * Cloud Run domain mappings: they resolve to ghs.googlehosted.com and answer
 * with `server: Google Frontend`, with no CDN or load balancer of ours in
 * between. Google's front end is therefore the ONE hop, and it APPENDS the
 * address it accepted the connection from as the rightmost X-Forwarded-For
 * entry. Everything to the left of that entry was written by the client and
 * can be anything.
 *
 * Without this setting Express reports the socket peer, which on Cloud Run is
 * the front end's internal address (169.254.169.126 on 200 of 200 production
 * log lines over 7 days), so every per-IP limit was one bucket shared by every
 * caller in the world.
 *
 * Never `true`: that trusts every hop and takes the LEFTMOST entry, which the
 * client writes itself, so anyone could pick their own rate-limit bucket.
 *
 * Change this only when the path in front of the relay changes:
 *   - an external Application Load Balancer (serverless NEG) in front of Cloud
 *     Run appends `<client>,<lb>`: 2 hops
 *   - Cloudflare proxying (orange cloud) adds its own hop and its own header:
 *     revisit entirely, do not just bump the number
 * and prove it on staging: the masked `from IP` log line must show the caller's
 * own /16, not 169.254.x.x and not a value you put in X-Forwarded-For.
 *
 * Locally there is no front end. A request reaching the container carries no
 * X-Forwarded-For unless the caller adds one, so the address is the socket
 * peer: Docker's port-forwarding gateway as seen inside the container, which
 * is the same for every local caller. A local caller who DOES send the header
 * is believed for its rightmost entry; the E2E tests rely on that to stand in
 * for Google's front end and give each test its own bucket.
 */
export const TRUSTED_PROXY_HOPS = 1;

/**
 * The trust function Express builds for a numeric `trust proxy` (utils.js
 * `compileTrust`): the first N hops counted from the socket are trusted.
 */
export const trustHops = (_addr: string, i: number): boolean => i < TRUSTED_PROXY_HOPS;

/**
 * The caller's address, computed exactly the way Express computes `req.ip`
 * under `app.set('trust proxy', TRUSTED_PROXY_HOPS)`.
 *
 * One function for every reader: the HTTP rate limiter, the stats-auth
 * lockout, and Socket.IO connections (whose `socket.request` is a plain
 * IncomingMessage that Express never sees). Reading `req.ip` in one place and
 * the socket peer in another would put the same caller in two buckets.
 */
export function clientIp(req: IncomingMessage): string {
  return proxyaddr(req, trustHops);
}
