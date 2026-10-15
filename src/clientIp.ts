import type { IncomingMessage } from 'http';
import proxyaddr from 'proxy-addr';

/**
 * The caller's address, given how many proxies in front of the relay append
 * to X-Forwarded-For (`proxyHops`, from the edge row in edge.ts).
 *
 * Each front end of ours APPENDS the address it accepted the connection from
 * as the rightmost X-Forwarded-For entry. Everything to the left of the entries
 * our own hops wrote was written by the client and can be anything.
 *
 *   Cloud Run domain mapping   Google's front end is the one hop: 1.
 *   load balancer + Cloud Run  `<client>,<lb>`: 2.
 *
 * Without trusting the front end Express reports the socket peer, which on
 * Cloud Run is the front end's internal address (169.254.169.126 on 200 of 200
 * production log lines over 7 days), so every per-IP limit was one bucket
 * shared by every caller in the world.
 *
 * Never `true`: that trusts every hop and takes the LEFTMOST entry, which the
 * client writes itself, so anyone could pick their own rate-limit bucket.
 *
 * When the edge changes, prove it on staging: the masked `from IP` log line
 * must show the caller's own /16, not 169.254.x.x, not the load balancer's
 * address and not a value you put in X-Forwarded-For.
 *
 * Locally there is no front end. A request reaching the container carries no
 * X-Forwarded-For unless the caller adds one, so the address is the socket
 * peer: Docker's port-forwarding gateway as seen inside the container, which
 * is the same for every local caller. A local caller who DOES send the header
 * is believed for its rightmost entry; the E2E tests rely on that to stand in
 * for Google's front end and give each test its own bucket.
 */

/**
 * The trust function Express builds for a numeric `trust proxy` (utils.js
 * `compileTrust`): the first N hops counted from the socket are trusted.
 */
export function trustHops(proxyHops: number): (addr: string, i: number) => boolean {
  if (!Number.isInteger(proxyHops) || proxyHops < 1) {
    throw new Error(`proxyHops must be a positive integer, got ${proxyHops}`);
  }
  return (_addr, i) => i < proxyHops;
}

/**
 * One reader for every caller of the relay: the HTTP rate limiter, the
 * stats-auth lockout, and Socket.IO connections (whose `socket.request` is a
 * plain IncomingMessage that Express never sees). Reading `req.ip` in one
 * place and the socket peer in another would put the same caller in two
 * buckets.
 */
export function clientIpReader(proxyHops: number): (req: IncomingMessage) => string {
  const trust = trustHops(proxyHops);
  return (req) => proxyaddr(req, trust);
}
