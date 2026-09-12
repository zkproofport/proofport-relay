import { defineConfig } from 'vitest/config';

/**
 * The relay had no vitest config at all, so `npm test` scanned `dist/` too.
 *
 * `tsc` compiles `src/__tests__/*.ts` into `dist/__tests__/*.js` as CommonJS,
 * and vitest cannot load a CommonJS file that `require('vitest')`. A build left
 * over from any earlier day turned four suites red with an error about module
 * formats — nothing to do with the relay, and indistinguishable at a glance
 * from a real failure. Found 2026-09-11 against leftovers dated 2026-09-09.
 *
 * `dist/` is gitignored, so this never showed up in CI; only a person running
 * the tests after a build saw it.
 */
/**
 * The E2E suite is excluded from the default run for a second reason.
 *
 * It talks to a relay on :4001 over HTTP -- correctly, per the project rule
 * that E2E means real containers -- so `npm test` with nothing running failed
 * with ECONNREFUSED and looked exactly like a broken relay. It has its own
 * script now: `npm run test:e2e`, after `/dev-start`.
 */
export default defineConfig({
  test: {
    include: ['src/**/*.{test,spec}.ts'],
    exclude: ['**/node_modules/**', 'dist/**', 'src/**/*-e2e.test.ts'],
  },
});
