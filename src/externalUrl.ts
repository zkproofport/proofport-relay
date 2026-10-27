import type { Edge } from './edge';

/**
 * The relay's public origin, from RELAY_EXTERNAL_URL. Every deep link carries
 * `<this>/api/v1/proof/callback` as the URL the app posts the proof to.
 *
 * Required in every environment, with no fallback. Until 2026-10-27 an empty
 * value made the relay build that URL from the incoming request's Host header
 * (and protocol), so whoever sent the request chose where the phone would post
 * its proof; outside production/staging an empty value was allowed. The app's
 * trusted-host list was the only thing standing between that and a proof
 * posted to an attacker's server.
 *
 * Exactly an origin (scheme, lower-case host, non-default port): no path,
 * query, fragment, credentials or trailing slash, so the callback path is
 * appended exactly once. https unless the edge row allows
 * plain http (`local`, edge.ts).
 */
export function parseRelayExternalUrl(value: string | undefined, edge: Edge): string {
  const name = 'RELAY_EXTERNAL_URL';
  if (value === undefined || value.trim() === '') {
    throw new Error(`${name} environment variable is required (the relay's public origin, e.g. https://relay.zkproofport.app)`);
  }
  if (value !== value.trim()) {
    throw new Error(`${name} must not have leading or trailing whitespace`);
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute http(s) URL, got '${value}'`);
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error(`${name} must be an absolute http(s) URL, got protocol '${url.protocol}'`);
  }
  if (edge.httpsOnly && url.protocol !== 'https:') {
    throw new Error(`${name} must be https behind this edge (the app posts proofs to it), got '${value}'`);
  }
  if (url.username || url.password) {
    throw new Error(`${name} must not carry credentials`);
  }
  // Comparing with the parsed origin also catches a bare `?` or `#`, an
  // upper-case host and a default port written out, which URL normalises.
  if (value !== url.origin) {
    throw new Error(`${name} must be exactly an origin such as '${url.origin}' (no path, query, fragment or trailing slash), got '${value}'`);
  }
  return value;
}
