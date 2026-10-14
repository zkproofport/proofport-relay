import { defineConfig } from 'vitest/config';

/**
 * Integration suite: real relay instances created in-process (`createRelay`),
 * real Redis, real HTTP and real Socket.IO clients over ephemeral ports. No
 * mocks. It is not E2E -- the relay runs inside the test process, not in its
 * container -- so it lives here and not under the E2E config.
 *
 * Needs REDIS_TEST_URL naming a non-zero database, which the suite FLUSHES.
 * `scripts/test-relay.sh integration` passes the dev stack's Redis, DB 15.
 */
export default defineConfig({
  test: {
    include: ['src/**/*.integration.test.ts'],
    exclude: ['**/node_modules/**', 'dist/**'],
    testTimeout: 30_000,
    hookTimeout: 30_000,
    fileParallelism: false,
  },
});
