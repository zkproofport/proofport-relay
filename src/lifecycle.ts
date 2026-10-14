import type Redis from 'ioredis';
import type { ProofResult, ProofStatus, RequestMeta, TerminalStatus } from './types';

/**
 * Redis-backed request lifecycle: status, buffered result, deadline, and the
 * one-way door into a terminal state.
 *
 * Cloud Run runs up to 20 relay instances with no shared memory, and any of
 * them can restart at any time. So nothing here relies on an in-process timer
 * or map: the deadline lives in a Redis sorted set, every instance sweeps it,
 * and the move into a terminal state is a single Lua script that only one
 * caller can win. Whoever wins emits the result and counts it; everyone else
 * gets a 409 naming why (`expired` or `already_answered`).
 */

export const STATUS_TTL_SECONDS = 600;
export const RESULT_TTL_SECONDS = 300;
/**
 * How long the one-way terminal record outlives everything else: 7 days.
 *
 * The app re-sends an answer that did not get through when it was killed, on
 * its next launches (up to three). That can be hours or days after the
 * request, long after the 10-minute status is gone. While this record exists
 * such a callback gets 409 with the reason -- `expired` or `already_answered`
 * -- instead of a 404 that reads as "never existed". It is one short string
 * per request; after 7 days the request is forgotten and the answer is 404.
 */
export const TERMINAL_TTL_SECONDS = 7 * 24 * 60 * 60;
export const DEADLINES_KEY = 'proof:deadlines';

export function statusKey(requestId: string) { return `proof:status:${requestId}`; }
export function resultKey(requestId: string) { return `proof:result:${requestId}`; }
export function terminalKey(requestId: string) { return `proof:terminal:${requestId}`; }
export function metaKey(requestId: string) { return `proof:meta:${requestId}`; }

/**
 * KEYS: terminal, result, status, deadlines
 * ARGV: outcome, resultJson, statusJson, resultTtl, statusTtl, requestId, terminalTtl
 *
 * The SET NX on the terminal key is the arbiter. Callback, sweep and lazy
 * expiry all come through here, so a completed proof racing its own timeout
 * resolves to exactly one of the two. The terminal key carries its own,
 * longer TTL (TERMINAL_TTL_SECONDS) so a late re-send still gets a 409 naming
 * why after the status has aged out.
 */
const FINALIZE_LUA = `
if not redis.call('SET', KEYS[1], ARGV[1], 'NX', 'EX', ARGV[7]) then
  return 0
end
redis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[4])
redis.call('SET', KEYS[3], ARGV[3], 'EX', ARGV[5])
redis.call('ZREM', KEYS[4], ARGV[6])
return 1
`;

/**
 * KEYS: terminal, status
 * ARGV: statusJson, statusTtl
 * An intermediate status ("generating") must never overwrite a terminal one.
 */
const INTERMEDIATE_LUA = `
if redis.call('EXISTS', KEYS[1]) == 1 then
  return 0
end
redis.call('SET', KEYS[2], ARGV[1], 'EX', ARGV[2])
return 1
`;

export class Lifecycle {
  constructor(private readonly redis: Redis, private readonly deadlineMs: number) {}

  async getStatus(requestId: string): Promise<ProofStatus | null> {
    const raw = await this.redis.get(statusKey(requestId));
    return raw ? (JSON.parse(raw) as ProofStatus) : null;
  }

  async getResult(requestId: string): Promise<ProofResult | null> {
    const raw = await this.redis.get(resultKey(requestId));
    return raw ? (JSON.parse(raw) as ProofResult) : null;
  }

  async getMeta(requestId: string): Promise<RequestMeta | null> {
    const raw = await this.redis.get(metaKey(requestId));
    return raw ? (JSON.parse(raw) as RequestMeta) : null;
  }

  /** The terminal status a request already reached, or null while it is open. */
  async terminalOf(requestId: string): Promise<TerminalStatus | null> {
    return (await this.redis.get(terminalKey(requestId))) as TerminalStatus | null;
  }

  /** Records a new pending request and starts its deadline. */
  async open(status: ProofStatus, circuitId: string, now: number): Promise<RequestMeta> {
    const meta: RequestMeta = { circuitId, deadlineAt: now + this.deadlineMs };
    await this.redis
      .multi()
      .set(statusKey(status.requestId), JSON.stringify(status), 'EX', STATUS_TTL_SECONDS)
      .set(metaKey(status.requestId), JSON.stringify(meta), 'EX', STATUS_TTL_SECONDS)
      .zadd(DEADLINES_KEY, meta.deadlineAt, status.requestId)
      .exec();
    return meta;
  }

  /** False when the request is already terminal; the status was left alone. */
  async setIntermediate(requestId: string, status: ProofStatus['status']): Promise<boolean> {
    const current = await this.getStatus(requestId);
    if (!current) return false;
    const next: ProofStatus = { ...current, status, updatedAt: new Date().toISOString() };
    const won = await this.redis.eval(
      INTERMEDIATE_LUA, 2, terminalKey(requestId), statusKey(requestId),
      JSON.stringify(next), STATUS_TTL_SECONDS,
    );
    return won === 1;
  }

  /**
   * Moves a request into a terminal state. True for the single caller that
   * did it; false for everyone after.
   */
  async finalize(result: ProofResult): Promise<boolean> {
    const current = await this.getStatus(result.requestId);
    const now = new Date().toISOString();
    const next: ProofStatus = {
      ...(current ?? { requestId: result.requestId, createdAt: now }),
      requestId: result.requestId,
      status: result.status,
      proof: result.proof,
      publicInputs: result.publicInputs,
      error: result.error,
      errorCode: result.errorCode,
      verifierAddress: result.verifierAddress,
      chainId: result.chainId,
      circuit: result.circuit,
      updatedAt: now,
    } as ProofStatus;
    const won = await this.redis.eval(
      FINALIZE_LUA, 4,
      terminalKey(result.requestId), resultKey(result.requestId), statusKey(result.requestId), DEADLINES_KEY,
      result.status, JSON.stringify(result), JSON.stringify(next),
      RESULT_TTL_SECONDS, STATUS_TTL_SECONDS, result.requestId, TERMINAL_TTL_SECONDS,
    );
    return won === 1;
  }

  /** Request ids whose deadline has passed, oldest first. */
  async due(now: number, limit: number): Promise<string[]> {
    return this.redis.zrangebyscore(DEADLINES_KEY, '-inf', now, 'LIMIT', 0, limit);
  }

  async forgetDeadline(requestId: string): Promise<void> {
    await this.redis.zrem(DEADLINES_KEY, requestId);
  }

  /** Test and operator hook: the deadline as stored. */
  async deadlineOf(requestId: string): Promise<number | null> {
    const score = await this.redis.zscore(DEADLINES_KEY, requestId);
    return score === null ? null : Number(score);
  }
}
