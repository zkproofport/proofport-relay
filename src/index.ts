import dotenv from 'dotenv';
import Redis from 'ioredis';
import { createAdapter } from '@socket.io/redis-adapter';
import { createRelay, REQUEST_DEADLINE_MS, SWEEP_INTERVAL_MS } from './app';
import { createStatsRecorder } from './stats';
import { edgeFor } from './edge';
import { parseRelayExternalUrl } from './externalUrl';
import { scrubError, scrubText } from './mask';

dotenv.config();

// ---------------------------------------------------------------------------
// Config. Every value that decides behaviour is required; PORT is the one
// value with a default, per the project rule on non-critical settings.
// ---------------------------------------------------------------------------
const PORT = parseInt(process.env.PORT || '4001', 10);

const REDIS_URL = process.env.REDIS_URL;
if (!REDIS_URL) throw new Error('REDIS_URL environment variable is required');

/**
 * Bearer token for GET /api/v1/stats. Required in every environment: a relay
 * that started without one would either expose its statistics or have an
 * endpoint nobody can call, and neither should happen quietly.
 * Locally `scripts/dev.sh` generates one into `.env.development`; deployed
 * environments get it from Google Secret Manager (relay-stats-token-<env>),
 * mounted by .github/workflows/deploy.yml with --set-secrets.
 */
const RELAY_STATS_TOKEN = process.env.RELAY_STATS_TOKEN;
if (!RELAY_STATS_TOKEN) throw new Error('RELAY_STATS_TOKEN environment variable is required');
if (RELAY_STATS_TOKEN.length < 32) {
  throw new Error(`RELAY_STATS_TOKEN must be at least 32 characters (got ${RELAY_STATS_TOKEN.length}); generate one with: openssl rand -hex 32`);
}

/** What sits in front of the relay; see edge.ts. Required, no default. */
const EDGE = edgeFor(process.env.RELAY_EDGE);

/**
 * The relay's public origin, put in every deep link as the callback URL.
 * Required everywhere (externalUrl.ts): it used to fall back to the request's
 * Host header, which let the caller choose where the app posts its proof.
 */
const RELAY_EXTERNAL_URL = parseRelayExternalUrl(process.env.RELAY_EXTERNAL_URL, EDGE);

function connect(name: string): Redis {
  const client = new Redis(REDIS_URL!, {
    maxRetriesPerRequest: 3,
    retryStrategy(times) {
      if (times > 5) return null;
      return Math.min(times * 500, 3000);
    },
    lazyConnect: true,
  });
  client.on('error', (err) => console.error(`[Redis:${name}] Connection error: ${scrubText(err.message)}`));
  return client;
}

async function main() {
  const redis = connect('state');
  // The Socket.IO Redis adapter needs its own publisher and a dedicated
  // subscriber connection (a subscribed connection cannot run other commands).
  const pub = connect('adapter-pub');
  const sub = connect('adapter-sub');
  await Promise.all([redis.connect(), pub.connect(), sub.connect()]);
  console.log('[Redis] Connected (state, adapter-pub, adapter-sub)');

  const relay = createRelay({
    redis,
    stats: createStatsRecorder(redis),
    statsToken: RELAY_STATS_TOKEN!,
    // Without an adapter an emit only reaches sockets on THIS instance. Cloud
    // Run runs up to 20, and the app's callback lands on any of them.
    adapter: createAdapter(pub, sub),
    edge: EDGE,
    relayExternalUrl: RELAY_EXTERNAL_URL,
    deadlineMs: REQUEST_DEADLINE_MS,
    sweepIntervalMs: SWEEP_INTERVAL_MS,
  });

  relay.httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`[Relay] Server running on port ${PORT}`);
    console.log(`[Relay] Socket.IO namespace: /proof (Redis adapter)`);
    console.log(`[Relay] Edge: RELAY_EDGE=${process.env.RELAY_EDGE} (proxy hops ${EDGE.proxyHops}, country header ${EDGE.regionHeader ?? 'none'})`);
    console.log(`[Relay] Request deadline ${REQUEST_DEADLINE_MS}ms, sweep every ${SWEEP_INTERVAL_MS}ms`);
  });
}

main().catch((err) => {
  console.error(`[Relay] Fatal error: ${scrubError(err)}`);
  process.exit(1);
});
