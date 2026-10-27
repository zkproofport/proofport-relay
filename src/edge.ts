/**
 * What sits between the internet and this relay, set by `RELAY_EDGE`.
 *
 * It decides two things that must change together, so they live in one row:
 *
 *   proxyHops      how many X-Forwarded-For entries, counted from the right,
 *                  were written by our own front ends (see clientIp.ts)
 *   regionHeader   the header a front end of ours writes with the caller's
 *                  country, or null when nothing trustworthy writes one
 *   httpsOnly      whether RELAY_EXTERNAL_URL (the callback URL put in every
 *                  deep link) must be https. True behind any real front end:
 *                  the app posts the proof there. Only `local` allows http,
 *                  for a phone on the same LAN as a developer's Docker.
 *
 * Rows:
 *   cloud-run-domain  Cloud Run domain mapping (`ghs.googlehosted.com`). Google's
 *                     front end is the one hop and adds no country.
 *   load-balancer     external Application Load Balancer with a serverless NEG
 *                     in front of Cloud Run: `<client>,<lb>`, two hops. The
 *                     backend service adds `X-Relay-Client-Region:
 *                     {client_region}` and overwrites any header of that name
 *                     the client sent (scripts/relay-edge.sh). Cloud Run
 *                     ingress is limited to the load balancer, so no request
 *                     reaches the relay without passing it.
 *   local             Docker on a developer machine. No front end; a caller that
 *                     sends the headers is believed, which the tests rely on.
 *
 * There is no default. A relay that guessed its edge would either let callers
 * pick their own rate-limit bucket or count every caller as one.
 */

export const REGION_HEADER = 'x-relay-client-region';

export interface Edge {
  proxyHops: number;
  regionHeader: string | null;
  httpsOnly: boolean;
}

export const EDGES = {
  'cloud-run-domain': { proxyHops: 1, regionHeader: null, httpsOnly: true },
  'load-balancer': { proxyHops: 2, regionHeader: REGION_HEADER, httpsOnly: true },
  local: { proxyHops: 1, regionHeader: REGION_HEADER, httpsOnly: false },
} as const satisfies Record<string, Edge>;

export type EdgeName = keyof typeof EDGES;

export function edgeFor(name: string | undefined): Edge {
  if (!name) {
    throw new Error(`RELAY_EDGE environment variable is required. Known: ${Object.keys(EDGES).join(', ')}.`);
  }
  if (!Object.prototype.hasOwnProperty.call(EDGES, name)) {
    throw new Error(`Unknown RELAY_EDGE '${name}'. Known: ${Object.keys(EDGES).join(', ')}.`);
  }
  return EDGES[name as EdgeName];
}
