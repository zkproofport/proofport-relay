import { defineConfig } from 'vitest/config';

/**
 * The E2E suite, which needs a relay actually listening on :4001.
 *
 * Start the stack first (`/dev-start`, or `./scripts/dev.sh` from the repo
 * root -- never `docker compose` directly, which loses the LAN IP the relay
 * puts in its callback URLs). Running this against nothing gives ECONNREFUSED,
 * which is the truth and not a relay defect.
 */
export default defineConfig({
  test: {
    include: ['src/**/*-e2e.test.ts'],
    exclude: ['**/node_modules/**', 'dist/**'],
    testTimeout: 30_000,
    // One file at a time. Every file talks to the same relay and Redis, and
    // the per-day statistics are global: relay-lifecycle-e2e asserts that one
    // request moved `oidc_domain_attestation`'s count by exactly 1, while
    // admin-browser-e2e creates three requests for the same circuit on the
    // same day. Run in parallel, the delta read 4 (2026-10-23).
    fileParallelism: false,
  },
});
