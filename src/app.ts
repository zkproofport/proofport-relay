import express, { NextFunction, Request, Response } from 'express';
import { createServer, Server as HttpServer } from 'http';
import { Server, ServerOptions, Socket } from 'socket.io';
import cors from 'cors';
import helmet from 'helmet';
import { v4 as uuidv4 } from 'uuid';
import type Redis from 'ioredis';
import { ethers } from 'ethers';
import { isCircuitId, ALL_CIRCUIT_IDS } from '@zkproofport-app/core/circuits';
import type { ProofRequest, ProofResult, ProofSession, ProofStatus, RequestMeta, SignerVariant, TerminalStatus } from './types';
import { APP_TERMINAL_STATUSES, INTERMEDIATE_STATUSES, SIGNER_VARIANTS, TERMINAL_STATUSES } from './types';
import { validateReturnScheme } from './returnScheme';
import { NEEDS_WALLET_SIGNATURE } from './signaturePolicy';
import { Lifecycle, STATUS_TTL_SECONDS } from './lifecycle';
import { describeBody, describeDeepLink, maskHex, maskIp, scrubError, scrubText } from './mask';
import { bearerMatches, checkRange, ERROR_CODE_RE, readStats, StatsRecorder, TerminalOutcome } from './stats';
import { clientIpReader } from './clientIp';
import type { Edge } from './edge';
import { countryLabel, originLabel, scopeLabel } from './labels';
import { createStatsAuthGuard, STATS_AUTH_MAX_FAILURES, StatsAuthGuard } from './statsAuth';
import { mountAdmin } from './admin';
import { computeInputsHashes, InputsNotJsonError, InputsTooDeepError } from './inputsHash';
import { parseRelayExternalUrl } from './externalUrl';
import { decryptPlayIntegrityToken, PlayIntegrityConfig, PlayIntegrityError, PlayIntegrityReason, playIntegrityMessage } from './playIntegrity';

/**
 * How long the relay waits for the app before it answers the dApp itself.
 *
 * The SDK's `waitForProof()` / `waitForResult()` give up after 300 000 ms by
 * default. The relay's own answer has to reach the dApp BEFORE that, or the
 * dApp sees its own "timed out" error instead of a result it can branch on.
 * 280 s leaves 20 s for the sweep interval (5 s), the cross-instance publish
 * and the client's own poll interval (2 s), with margin. A user generating a
 * proof on a phone finishes well inside this; a request still open at 280 s
 * has been abandoned.
 */
export const REQUEST_DEADLINE_MS = 280_000;

/** How often each instance looks for requests past their deadline. */
export const SWEEP_INTERVAL_MS = 5_000;

/** Most requests expired by one instance in one sweep; the rest wait 5 s. */
const SWEEP_BATCH = 100;

/**
 * The longest app error message forwarded to the dApp. The message is free
 * text written for a person; 1000 characters is several paragraphs, and the
 * cap keeps a misbehaving client from parking megabytes in Redis per request.
 * Longer messages are cut at this many characters (code points), not refused,
 * so the dApp still gets its answer.
 */
export const ERROR_MESSAGE_MAX_CHARS = 1000;

export const EXPIRED_MESSAGE = 'The request timed out before the app answered';
export const ALREADY_ANSWERED_MESSAGE = 'This request has already been answered';

const NONCE_TTL = 600;
const SESSION_TTL = 600;
const SESSION_KEY_PREFIX = 'session:';

/** Longest `nonce` accepted. It becomes part of a Redis key. */
export const NONCE_MAX_CHARS = 256;

/**
 * Claims a challenge session and, when one was sent, its nonce, in ONE
 * atomic step. Until 2026-10-27 both were read, then written: two requests
 * arriving together with the same session (or the same nonce) could both read
 * "unused" and both be accepted.
 *
 * KEYS: session, claim, nonce (the nonce key only when a nonce was sent)
 * ARGV: claimTtl, nonceTtl
 * Returns: 'ok' | 'missing' | 'used' | 'nonce'
 *
 * The claim lives in its own key so the script never re-encodes the session
 * JSON (cjson would rewrite numbers inside `inputs`). A session whose JSON
 * already says something other than `pending` counts as used too: that is how
 * a relay before this change marked a claim, and both kinds of instance run
 * side by side during a rollout. Nothing is written unless every check passes,
 * so a duplicate nonce no longer burns the session and a used session no
 * longer burns the nonce.
 */
const CLAIM_LUA = `
local session = redis.call('GET', KEYS[1])
if not session then
  return 'missing'
end
if redis.call('EXISTS', KEYS[2]) == 1 then
  return 'used'
end
local ok, decoded = pcall(cjson.decode, session)
if not ok or type(decoded) ~= 'table' or decoded['status'] ~= 'pending' then
  return 'used'
end
if KEYS[3] and redis.call('EXISTS', KEYS[3]) == 1 then
  return 'nonce'
end
redis.call('SET', KEYS[2], '1', 'EX', ARGV[1])
if KEYS[3] then
  redis.call('SET', KEYS[3], '1', 'EX', ARGV[2])
end
return 'ok'
`;

const RATE_LIMITS = {
  challenge: { windowMs: 60_000, max: 30 },
  /** Shared by POST /api/v1/proof/request and the Socket.IO `proof:request` event. */
  request: { windowMs: 60_000, max: 10 },
  /**
   * POST /api/v1/proof/callback. Unlimited until 2026-10-27. The app sends one
   * answer per request (current builds send no `generating`) and re-sends an
   * undelivered one on up to three later launches, so 60 a minute leaves room
   * for many phones behind one carrier NAT. The current app treats a 429 on
   * its answer as final (relayAnswer.ts), so keep this well above what a
   * shared address legitimately sends. Same per-instance fixed window as the
   * other limits; Cloud Armor's 600/min per IP sits in front in production.
   */
  callback: { windowMs: 60_000, max: 60 },
  /** Authenticated stats reads. Wrong tokens are limited separately (statsAuth.ts). */
  stats: { windowMs: 60_000, max: 60 },
  /**
   * POST /api/v1/play-integrity/decrypt. The app sends one token per proof it
   * is about to generate; 30 a minute leaves room for many phones behind one
   * carrier NAT while keeping the AES and ECDSA work per address bounded.
   */
  playIntegrity: { windowMs: 60_000, max: 30 },
};

/**
 * Body cap for POST /api/v1/play-integrity/decrypt. A classic Play Integrity
 * token is a compact JWE of a signed verdict, a few kilobytes; 16 KB leaves
 * headroom for the optional verdict fields without letting anyone park a
 * megabyte per request on the decryption path. Larger bodies get 413.
 */
export const PLAY_INTEGRITY_BODY_LIMIT = '16kb';

/**
 * Paths no other origin may call from a browser: the admin page and the
 * stats API it reads. They get no CORS headers at all, though every other
 * path allows any origin, so a cross-origin `fetch` -- with or without the token -- is blocked
 * by the browser, and a preflight for the Authorization header is refused.
 * The page itself is same-origin and needs no CORS.
 */
/**
 * Every other path is called from whatever page a dApp runs on, and nobody can
 * list those in advance, so any origin may call it. The origin was never what
 * protected the relay: CORS binds browsers only, a server calls it with or
 * without a header, and a request is authenticated by its challenge and
 * signature. An allowlist stopped one kind of caller: a dApp using the SDK from
 * a browser, which is the normal integration (dojangscan.com, 2026-10-15).
 * No credentials are sent or accepted, so `*` exposes no cookie.
 */
const PUBLIC_CORS_ORIGIN = '*';

const SAME_ORIGIN_ONLY = [/^\/api\/v1\/stats(\/|$)/i, /^\/admin(\/|$)/i];

export interface RelayOptions {
  /** Request state: sessions, statuses, results, deadlines. */
  redis: Redis;
  stats: StatsRecorder;
  /** Bearer token for GET /api/v1/stats. */
  statsToken: string;
  /** Wrong-token lockout for the stats API. Defaults to one on `redis`. */
  statsAuth?: StatsAuthGuard;
  /** Socket.IO adapter. The Redis adapter in every deployment; null only for a single in-process test instance. */
  adapter: ServerOptions['adapter'] | null;
  /** What sits in front of the relay (edge.ts): proxy hops and the country header. */
  edge: Edge;
  /**
   * The relay's public origin (RELAY_EXTERNAL_URL). Required: every deep link
   * tells the app to post its proof to `<this>/api/v1/proof/callback`, and
   * nothing a caller sends may choose that address. See externalUrl.ts.
   */
  relayExternalUrl: string;
  deadlineMs: number;
  sweepIntervalMs: number;
  /**
   * Keys for POST /api/v1/play-integrity/decrypt (playIntegrity.ts). Required
   * so every caller decides; `{ enabled: false, missing }` turns the endpoint
   * into a 503 naming the missing variables and leaves everything else alone.
   */
  playIntegrity: PlayIntegrityConfig;
}

export interface Relay {
  app: express.Express;
  httpServer: HttpServer;
  io: Server;
  lifecycle: Lifecycle;
  /** Expires every request past its deadline that this instance wins. */
  sweep(): Promise<number>;
  close(): Promise<void>;
}

function isOneOf<T extends string>(list: readonly T[], value: unknown): value is T {
  return typeof value === 'string' && (list as readonly string[]).includes(value);
}

/** Which statistics bucket a terminal status lands in. `failed` is the old name for `error`. */
const STATS_OUTCOME: Record<TerminalStatus, TerminalOutcome> = {
  completed: 'completed',
  error: 'error',
  failed: 'error',
  cancelled: 'cancelled',
  expired: 'expired',
};

function capErrorMessage(message: string): string {
  const chars = Array.from(message);
  return chars.length > ERROR_MESSAGE_MAX_CHARS ? chars.slice(0, ERROR_MESSAGE_MAX_CHARS).join('') : message;
}

export function createRelay(options: RelayOptions): Relay {
  const { redis, stats, statsToken } = options;
  if (!statsToken) throw new Error('statsToken is required');
  const statsAuth = options.statsAuth ?? createStatsAuthGuard(redis);
  const lifecycle = new Lifecycle(redis, options.deadlineMs);
  const callbackUrl = `${parseRelayExternalUrl(options.relayExternalUrl, options.edge)}/api/v1/proof/callback`;

  const app = express();
  const httpServer = createServer(app);

  // See clientIp.ts and edge.ts: the hops our own front ends add, never `true`.
  // Set so `req.ip` and `req.protocol` agree with clientIp(); the relay's own
  // code reads clientIp() so HTTP and Socket.IO share one definition.
  const { edge } = options;
  const clientIp = clientIpReader(edge.proxyHops);
  app.set('trust proxy', edge.proxyHops);

  app.use(helmet());
  const corsMiddleware = cors({ origin: PUBLIC_CORS_ORIGIN });
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (SAME_ORIGIN_ONLY.some((re) => re.test(req.path))) return next();
    corsMiddleware(req, res, next);
  });
  // Mounted before the general JSON parser so its own, much smaller body cap
  // applies (a parsed body is not parsed again).
  app.use('/api/v1/play-integrity', playIntegrityRouter());
  app.use(express.json({ limit: '1mb' }));

  const io = new Server(httpServer, {
    cors: { origin: PUBLIC_CORS_ORIGIN, methods: ['GET', 'POST'] },
    path: '/socket.io',
    ...(options.adapter ? { adapter: options.adapter } : {}),
  });
  const proofNs = io.of('/proof');
  const room = (requestId: string) => `request:${requestId}`;

  // -------------------------------------------------------------------------
  // Rate limiting (in-memory fixed window, per instance). Keyed by the
  // caller's address from clientIp() -- the same for HTTP and Socket.IO; only
  // the log line is masked.
  // -------------------------------------------------------------------------
  const rateLimitStore = new Map<string, { count: number; resetAt: number }>();

  /** Counts one hit. Null when allowed; otherwise seconds until the window resets. */
  function consume(type: keyof typeof RATE_LIMITS, ip: string): number | null {
    const key = `${type}:${ip}`;
    const limit = RATE_LIMITS[type];
    const now = Date.now();
    const entry = rateLimitStore.get(key);
    if (!entry || now > entry.resetAt) {
      rateLimitStore.set(key, { count: 1, resetAt: now + limit.windowMs });
      return null;
    }
    if (entry.count >= limit.max) {
      console.log(`[Relay RateLimit] Rejected: type=${type}, ip=${maskIp(ip)}, count=${entry.count}, max=${limit.max}, resetsAt=${new Date(entry.resetAt).toISOString()}`);
      return Math.max(1, Math.ceil((entry.resetAt - now) / 1000));
    }
    entry.count++;
    return null;
  }

  function rateLimit(type: keyof typeof RATE_LIMITS) {
    return (req: Request, res: Response, next: NextFunction) => {
      const retryAfter = consume(type, clientIp(req));
      if (retryAfter === null) return next();
      res.setHeader('Retry-After', String(retryAfter));
      res.status(429).json({ error: 'Too many requests. Please try again later.' });
    };
  }

  const rateLimitCleanup = setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of rateLimitStore) {
      if (now > entry.resetAt) rateLimitStore.delete(key);
    }
  }, 300_000);
  rateLimitCleanup.unref();

  // -------------------------------------------------------------------------
  // Play Integrity token decryption (playIntegrity.ts)
  //
  // Nothing from the token, the decrypted header, payload or signature, the
  // nonce or any verdict field reaches a log line: only the caller's masked
  // address, the body's key names, the token's length and the outcome.
  // -------------------------------------------------------------------------
  function playIntegrityRouter(): express.Router {
    const router = express.Router();
    const config = options.playIntegrity;
    const log = (req: Request, outcome: string, detail: string) =>
      console.log(`[Relay PlayIntegrity] POST /api/v1/play-integrity/decrypt from IP: ${maskIp(clientIp(req))}, outcome=${outcome}${detail}`);
    const refuse = (req: Request, res: Response, status: number, reason: PlayIntegrityReason, detail: string) => {
      log(req, reason, detail);
      res.status(status).json({ error: playIntegrityMessage(reason), reason });
    };

    router.use(rateLimit('playIntegrity'));
    router.use(express.json({ limit: PLAY_INTEGRITY_BODY_LIMIT }));

    router.post('/decrypt', (req: Request, res: Response) => {
      res.setHeader('Cache-Control', 'no-store');
      if (!config.enabled) {
        log(req, 'not_configured', `, missing=${config.missing.join(',')}`);
        res.status(503).json({
          error: `Play Integrity token decryption is not configured on this relay: ${config.missing.join(' and ')} not set`,
          reason: 'not_configured',
          missing: config.missing,
        });
        return;
      }
      // describeBody prints key names and envelope fields only; `token` is
      // neither, so its value never appears.
      const body = req.body as unknown;
      const summary = `, ${describeBody(body)}`;
      const token = body && typeof body === 'object' && !Array.isArray(body) ? (body as Record<string, unknown>).token : undefined;
      if (token === undefined || token === null || token === '') return refuse(req, res, 400, 'token_missing', summary);
      if (typeof token !== 'string') return refuse(req, res, 400, 'token_not_string', summary);
      const detail = `${summary}, tokenChars=${token.length}`;
      try {
        const jws = decryptPlayIntegrityToken(token, config);
        log(req, 'ok', `${detail}, headerChars=${jws.protectedHeader.length}, payloadChars=${jws.payload.length}`);
        res.json(jws);
      } catch (err) {
        if (err instanceof PlayIntegrityError) {
          // A signature that does not verify is a well-formed token the relay
          // will not vouch for: 422, so the app can tell it from a broken one.
          return refuse(req, res, err.reason === 'signature_invalid' ? 422 : 400, err.reason, detail);
        }
        // Name only: an unexpected crypto error's message is not ours to vet.
        console.error(`[Relay PlayIntegrity] Unexpected error (${err instanceof Error ? err.name : typeof err})${detail}`);
        res.status(500).json({ error: 'Internal server error' });
      }
    });

    // Body-parser errors on this path. Its SyntaxError quotes the body it could
    // not parse, so only the error type is logged, never the message.
    router.use((err: unknown, req: Request, res: Response, next: NextFunction) => {
      if (res.headersSent) return next(err);
      const status = (err as { status?: number })?.status;
      const type = (err as { type?: unknown })?.type;
      log(req, `body_error_${status}`, `, type=${typeof type === 'string' ? type : 'unknown'}`);
      if (status === 413) {
        res.status(413).json({ error: `Request body too large (limit ${PLAY_INTEGRITY_BODY_LIMIT})`, reason: 'body_too_large' });
        return;
      }
      if (typeof status === 'number' && status >= 400 && status < 500) {
        res.status(status).json({ error: 'Malformed request body', reason: 'body_malformed' });
        return;
      }
      res.status(500).json({ error: 'Internal server error' });
    });
    return router;
  }

  // -------------------------------------------------------------------------
  // Sessions
  // -------------------------------------------------------------------------
  const sessionKey = (requestId: string) => `${SESSION_KEY_PREFIX}${requestId}`;
  const claimKey = (requestId: string) => `${SESSION_KEY_PREFIX}claimed:${requestId}`;
  const inputsHashKey = (requestId: string) => `proof:inputsHash:${requestId}`;
  const inputsHashV2Key = (requestId: string) => `proof:inputsHashV2:${requestId}`;
  const nonceKey = (nonce: string) => `proof:nonce:${nonce}`;

  async function createSession(ip: string): Promise<ProofSession> {
    const requestId = uuidv4();
    const challenge = ethers.hexlify(ethers.randomBytes(32));
    const now = new Date();
    const session: ProofSession = {
      requestId,
      challenge,
      status: 'pending',
      ip,
      createdAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + SESSION_TTL * 1000).toISOString(),
    };
    await redis.set(sessionKey(requestId), JSON.stringify(session), 'EX', SESSION_TTL);
    console.log(`[Relay Session] Created: requestId=${requestId}, challenge=${maskHex(challenge)}, ip=${maskIp(ip)}`);
    return session;
  }

  async function getSession(requestId: string): Promise<ProofSession | null> {
    const data = await redis.get(sessionKey(requestId));
    return data ? (JSON.parse(data) as ProofSession) : null;
  }

  async function updateSession(requestId: string, updates: Partial<ProofSession>): Promise<void> {
    const session = await getSession(requestId);
    if (!session) return;
    const ttl = Math.max(1, Math.floor((new Date(session.expiresAt).getTime() - Date.now()) / 1000));
    await redis.set(sessionKey(requestId), JSON.stringify({ ...session, ...updates }), 'EX', ttl);
  }

  function verifyWalletSignature(challenge: string, signature: string): { valid: boolean; signerAddress?: string; error?: string } {
    try {
      const signerAddress = ethers.verifyMessage(challenge, signature);
      console.log(`[Relay Auth] Wallet signature verified: signerAddress=${maskHex(signerAddress)}`);
      return { valid: true, signerAddress };
    } catch (err) {
      console.log(`[Relay Auth] Wallet signature verification failed: ${scrubError(err)}`);
      return { valid: false, error: 'Invalid signature' };
    }
  }

  /** One atomic claim of the session and nonce (CLAIM_LUA). */
  async function claimSession(requestId: string, nonce: string | undefined): Promise<'ok' | 'missing' | 'used' | 'nonce'> {
    const keys = [sessionKey(requestId), claimKey(requestId), ...(nonce !== undefined ? [nonceKey(nonce)] : [])];
    const outcome = await redis.eval(CLAIM_LUA, keys.length, ...keys, SESSION_TTL, NONCE_TTL);
    if (outcome === 'ok' || outcome === 'missing' || outcome === 'used' || outcome === 'nonce') return outcome;
    throw new Error(`Unexpected session claim outcome '${String(outcome)}'`);
  }

  function buildDeepLink(request: ProofRequest): string {
    const data = Buffer.from(JSON.stringify(request)).toString('base64url');
    const deepLink = `zkproofport://proof-request?data=${data}`;
    console.log(`[Relay DeepLink] buildDeepLink: requestId=${request.requestId}, ${describeDeepLink(deepLink)}`);
    return deepLink;
  }

  // -------------------------------------------------------------------------
  // Terminal outcomes
  // -------------------------------------------------------------------------

  /** Emits the result to every dApp socket in the room, on every instance. */
  function deliver(result: ProofResult): void {
    const r = room(result.requestId);
    const localSockets = proofNs.adapter.rooms.get(r)?.size ?? 0;
    console.log(`[Relay Deliver] proof:result requestId=${result.requestId}, status=${result.status}, localSockets=${localSockets}`);
    proofNs.to(r).emit('proof:result', result);
  }

  /**
   * `country` is the label of where the app's callback came from; absent for
   * outcomes the relay produced itself (expiry), where no phone answered.
   */
  function countOutcome(meta: RequestMeta | null, result: ProofResult, country?: string): void {
    if (!meta) {
      // A request opened by a relay version that did not record its circuit.
      // Its `requested` was never counted either, so skipping keeps the two consistent.
      console.log(`[Relay Stats] Not counted: no recorded circuit for requestId=${result.requestId}`);
      return;
    }
    const outcome = STATS_OUTCOME[result.status];
    stats.record(meta.circuitId, outcome, outcome === 'error' ? result.errorCode : undefined, undefined, {
      ...meta.labels,
      ...(country !== undefined && { country }),
    });
  }

  /** Expires one request if this caller wins it. True when it did. */
  async function expire(requestId: string, knownMeta?: RequestMeta | null): Promise<boolean> {
    const meta = knownMeta === undefined ? await lifecycle.getMeta(requestId) : knownMeta;
    const status = await lifecycle.getStatus(requestId);
    if (!status) {
      // Nothing left to answer; the request aged out of Redis entirely.
      await lifecycle.forgetDeadline(requestId);
      return false;
    }
    const result: ProofResult = {
      requestId,
      status: 'expired',
      error: EXPIRED_MESSAGE,
      ...(meta && { circuit: meta.circuitId }),
      completedAt: new Date().toISOString(),
    };
    const won = await lifecycle.finalize(result);
    if (!won) return false;
    console.log(`[Relay Expiry] Expired: requestId=${requestId}, circuit=${meta?.circuitId}, deadlineAt=${meta ? new Date(meta.deadlineAt).toISOString() : 'unknown'}`);
    deliver(result);
    countOutcome(meta, result);
    return true;
  }

  /** Lazy expiry: whoever touches a request past its deadline expires it. */
  async function expireIfDue(requestId: string): Promise<void> {
    const meta = await lifecycle.getMeta(requestId);
    if (!meta || meta.deadlineAt > Date.now()) return;
    if (await lifecycle.terminalOf(requestId)) return;
    await expire(requestId, meta);
  }

  let sweeping = false;
  async function sweep(): Promise<number> {
    if (sweeping) return 0;
    sweeping = true;
    let expired = 0;
    try {
      const due = await lifecycle.due(Date.now(), SWEEP_BATCH);
      for (const requestId of due) {
        try {
          if (await expire(requestId)) expired++;
        } catch (err) {
          console.error(`[Relay Expiry] Failed to expire requestId=${requestId}: ${scrubError(err)}`);
        }
      }
    } finally {
      sweeping = false;
    }
    return expired;
  }

  const sweepTimer = setInterval(() => {
    sweep().catch((err) => console.error(`[Relay Expiry] Sweep failed: ${scrubError(err)}`));
  }, options.sweepIntervalMs);
  sweepTimer.unref();

  // -------------------------------------------------------------------------
  // Proof request processing
  // -------------------------------------------------------------------------
  async function processProofRequest(body: {
    requestId?: string;
    circuitId?: string;
    scope?: string;
    inputs?: Record<string, unknown>;
    nonce?: string;
    challenge?: string;
    signature?: string;
    dappName?: string;
    dappIcon?: string;
    message?: string;
    returnScheme?: string;
  }, origin: unknown): Promise<{ ok: true; requestId: string; deepLink: string; status: ProofStatus } | { ok: false; error: string; code: number }> {
    const { requestId: reqId, circuitId, scope, inputs, nonce, challenge, signature } = body;

    console.log(`[Relay] processProofRequest: requestId=${reqId}, circuitId=${circuitId}, challenge=${maskHex(challenge)}, signature=${maskHex(signature)}`);

    if (!reqId || !challenge) {
      return { ok: false, error: 'requestId and challenge are required', code: 401 };
    }

    const session = await getSession(reqId);
    if (!session) {
      console.log(`[Relay] processProofRequest rejected: session not found — requestId=${reqId}`);
      return { ok: false, error: 'Invalid or expired session', code: 401 };
    }
    // Whether the session is still unused is decided only by the atomic claim
    // below (CLAIM_LUA), never by this read.
    if (session.challenge !== challenge) {
      console.log(`[Relay] processProofRequest rejected: challenge mismatch — requestId=${reqId}`);
      return { ok: false, error: 'Challenge mismatch', code: 401 };
    }

    if (!circuitId || typeof circuitId !== 'string') {
      return { ok: false, error: 'circuitId is required', code: 400 };
    }
    if (!inputs || typeof inputs !== 'object') {
      return { ok: false, error: 'inputs object is required', code: 400 };
    }
    // Absent, null and '' mean "no nonce", as before. Anything else must be a
    // string: `${nonce}` of any object is "[object Object]", so every object
    // nonce would have collided with every other.
    let claimNonce: string | undefined;
    if (nonce !== undefined && nonce !== null && nonce !== '') {
      if (typeof nonce !== 'string') return { ok: false, error: 'nonce must be a string', code: 400 };
      if (Array.from(nonce).length > NONCE_MAX_CHARS) {
        return { ok: false, error: `nonce must be at most ${NONCE_MAX_CHARS} characters`, code: 400 };
      }
      claimNonce = nonce;
    }

    // Envelope-level: where control goes back to when the app is done. A bad
    // value is rejected here rather than silently dropped so the integrator gets
    // a 400 instead of a feature that quietly never fires.
    let returnScheme: string | undefined;
    if (body.returnScheme !== undefined && body.returnScheme !== null) {
      const returnSchemeCheck = validateReturnScheme(body.returnScheme);
      if (!returnSchemeCheck.valid) {
        console.log(`[Relay] processProofRequest rejected: invalid returnScheme — requestId=${reqId}, value=${scrubText(String(body.returnScheme))}, error=${returnSchemeCheck.error}`);
        return { ok: false, error: returnSchemeCheck.error!, code: 400 };
      }
      returnScheme = returnSchemeCheck.normalized;
    }

    // An id in neither list has never been configured here. Refusing beats
    // forwarding it with no authentication and no record of the decision.
    if (!isCircuitId(circuitId)) {
      return {
        ok: false,
        error: `unknown circuit '${circuitId}' -- this relay has no signature policy for it. Known: ${ALL_CIRCUIT_IDS.join(', ')}`,
        code: 400,
      };
    }

    if (NEEDS_WALLET_SIGNATURE[circuitId]) {
      if (!signature) {
        return { ok: false, error: 'signature is required for this circuit', code: 401 };
      }
      const sigResult = verifyWalletSignature(challenge, signature);
      if (!sigResult.valid) {
        return { ok: false, error: sigResult.error!, code: 401 };
      }
    }

    // Before the claim, so inputs the relay cannot serialise are a 400 that
    // leaves the session usable.
    let hashes: { legacy: string; v2: string };
    try {
      hashes = computeInputsHashes(inputs);
    } catch (err) {
      if (err instanceof InputsTooDeepError || err instanceof InputsNotJsonError) {
        return { ok: false, error: err.message, code: 400 };
      }
      throw err;
    }
    // Key names only: the values are the user's proof inputs.
    console.log(`[Relay Hash] requestId=${reqId}, keys=${JSON.stringify(Object.keys(inputs).sort())}, inputsHash=${maskHex(hashes.legacy)}, inputsHashV2=${maskHex(hashes.v2)}`);

    const claim = await claimSession(reqId, claimNonce);
    if (claim !== 'ok') {
      console.log(`[Relay] processProofRequest rejected: claim=${claim}, requestId=${reqId}${claim === 'nonce' ? `, nonce=${scrubText(claimNonce!)}` : ''}`);
      if (claim === 'missing') return { ok: false, error: 'Invalid or expired session', code: 401 };
      if (claim === 'nonce') return { ok: false, error: 'Duplicate nonce (replay detected)', code: 409 };
      return { ok: false, error: 'Session already used (replay detected)', code: 409 };
    }
    // Informational now; kept so an instance from before CLAIM_LUA, during a
    // rollout, also sees the session as used.
    await updateSession(reqId, { status: 'claimed', circuitId, inputs });

    const requestId = reqId;
    const nowMs = Date.now();
    const now = new Date(nowMs).toISOString();

    const relayCallbackUrl = callbackUrl;
    console.log(`[Relay] processProofRequest: requestId=${requestId}, callbackUrl=${relayCallbackUrl}`);

    const proofRequest: ProofRequest = {
      requestId,
      circuitId,
      scope: scope || '',
      inputs,
      callbackUrl: relayCallbackUrl,
      ...(body.dappName && { dappName: body.dappName }),
      ...(body.dappIcon && { dappIcon: body.dappIcon }),
      ...(body.message && { message: body.message }),
      ...(returnScheme && { returnScheme }),
      createdAt: now,
    };
    console.log(`[Relay] ProofRequest object: ${describeBody(proofRequest)}`);

    await redis.set(inputsHashKey(requestId), hashes.legacy, 'EX', STATUS_TTL_SECONDS);
    await redis.set(inputsHashV2Key(requestId), hashes.v2, 'EX', STATUS_TTL_SECONDS);

    const deepLink = buildDeepLink(proofRequest);
    const status: ProofStatus = { requestId, status: 'pending', deepLink, createdAt: now, updatedAt: now };
    // Envelope only: the page that asked (browser Origin header) and the
    // top-level scope field. Nothing inside `inputs` is read.
    const labels = { origin: originLabel(origin), scope: scopeLabel(scope) };
    const meta = await lifecycle.open(status, circuitId, nowMs, labels);
    console.log(`[Relay] Status stored: requestId=${requestId}, status=pending, ttl=${STATUS_TTL_SECONDS}s, deadlineAt=${new Date(meta.deadlineAt).toISOString()}`);

    stats.record(circuitId, 'requested', undefined, undefined, labels);

    proofNs.to(room(requestId)).emit('proof:status', { requestId, status: 'pending' });
    console.log(`[Relay] Proof request created successfully: requestId=${requestId}, circuitId=${circuitId}, inputsHash=${maskHex(hashes.legacy)}, inputsHashV2=${maskHex(hashes.v2)}`);

    return { ok: true, requestId, deepLink, status };
  }

  // -------------------------------------------------------------------------
  // REST
  // -------------------------------------------------------------------------
  app.get('/api/v1/challenge', rateLimit('challenge'), async (req: Request, res: Response) => {
    try {
      const ip = clientIp(req);
      console.log(`[Relay Challenge] GET /api/v1/challenge from IP: ${maskIp(ip)}`);
      const session = await createSession(ip);
      res.json({ requestId: session.requestId, challenge: session.challenge, expiresAt: new Date(session.expiresAt).getTime() });
    } catch (err) {
      console.error(`[Relay Challenge] Generation error: ${scrubError(err)}`);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.post('/api/v1/proof/request', rateLimit('request'), async (req: Request, res: Response) => {
    try {
      console.log(`[Relay REST] POST /api/v1/proof/request from IP: ${maskIp(clientIp(req))}, ${describeBody(req.body)}`);

      const result = await processProofRequest(req.body || {}, req.headers.origin);
      if (!result.ok) {
        console.log(`[Relay REST] POST /api/v1/proof/request failed: code=${result.code}, error=${scrubText(result.error)}`);
        res.status(result.code).json({ error: result.error });
        return;
      }
      const response = {
        requestId: result.requestId,
        deepLink: result.deepLink,
        status: result.status.status,
        pollUrl: `/api/v1/proof/${result.requestId}`,
      };
      console.log(`[Relay REST] POST /api/v1/proof/request success: requestId=${response.requestId}, status=${response.status}, ${describeDeepLink(response.deepLink)}`);
      res.status(201).json(response);
    } catch (err) {
      console.error(`[Relay REST] Proof request error: ${scrubError(err)}`);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.get('/api/v1/proof/:requestId', async (req: Request, res: Response) => {
    try {
      const requestId = req.params.requestId as string;
      console.log(`[Relay Poll] GET /api/v1/proof/${requestId} from IP: ${maskIp(clientIp(req))}`);
      await expireIfDue(requestId);
      const status = await lifecycle.getStatus(requestId);
      if (!status) {
        console.log(`[Relay Poll] Request ${requestId} not found or expired (no status in Redis)`);
        res.status(404).json({ error: 'Request not found or expired' });
        return;
      }

      if (isOneOf(TERMINAL_STATUSES, status.status)) {
        const result = await lifecycle.getResult(requestId);
        if (result) {
          status.proof = result.proof;
          status.publicInputs = result.publicInputs;
          status.error = result.error;
          status.errorCode = result.errorCode;
          status.verifierAddress = result.verifierAddress;
          status.chainId = result.chainId;
          status.circuit = result.circuit;
          status.signerVariant = result.signerVariant;
        }
      }

      // Both hashes; see inputsHash.ts for which client reads which. A request
      // opened by a relay before inputsHashV2 existed has only the legacy one.
      const [inputsHash, inputsHashV2] = await redis.mget(inputsHashKey(requestId), inputsHashV2Key(requestId));
      if (inputsHash) status.inputsHash = inputsHash;
      if (inputsHashV2) status.inputsHashV2 = inputsHashV2;

      console.log(`[Relay Poll] Response for ${requestId}: status=${status.status}, errorCode=${status.errorCode}, hasProof=${Boolean(status.proof)}, inputsHash=${maskHex(status.inputsHash)}, inputsHashV2=${maskHex(status.inputsHashV2)}`);
      res.json(status);
    } catch (err) {
      console.error(`[Relay Poll] Error: ${scrubError(err)}`);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  /**
   * Types of the optional callback fields, and the one rule about content the
   * relay can check without reading a proof: a `completed` answer carries one.
   * Until 2026-10-27 any of these could be any JSON value and a `completed`
   * answer with no proof was delivered to the dApp as a result. Envelope only:
   * the proof and public inputs are forwarded, never interpreted.
   */
  function callbackFieldError(body: Record<string, unknown>): string | null {
    const { errorCode, error, proof, publicInputs, verifierAddress, chainId, circuit, status, signerVariant } = body;
    if (errorCode !== undefined && (typeof errorCode !== 'string' || !ERROR_CODE_RE.test(errorCode))) {
      return 'errorCode must look like E2007 (E followed by four digits)';
    }
    if (error !== undefined && typeof error !== 'string') return 'error must be a string';
    if (proof !== undefined && typeof proof !== 'string') return 'proof must be a string';
    if (publicInputs !== undefined && !(Array.isArray(publicInputs) && publicInputs.every((p) => typeof p === 'string'))) {
      return 'publicInputs must be an array of strings';
    }
    if (verifierAddress !== undefined && typeof verifierAddress !== 'string') return 'verifierAddress must be a string';
    if (chainId !== undefined && !(typeof chainId === 'number' && Number.isSafeInteger(chainId) && chainId > 0)) {
      return 'chainId must be a positive integer';
    }
    if (circuit !== undefined && typeof circuit !== 'string') return 'circuit must be a string';
    // Which verifier the dApp should use. A word from a closed list, carried
    // unchanged; the relay never checks it against the proof.
    if (signerVariant !== undefined && !isOneOf(SIGNER_VARIANTS, signerVariant)) {
      return `signerVariant must be one of ${SIGNER_VARIANTS.join(', ')}`;
    }
    if (status === 'completed' && (typeof proof !== 'string' || proof.length === 0 || !Array.isArray(publicInputs))) {
      return 'a completed answer must carry proof and publicInputs';
    }
    return null;
  }

  // Callback writes rely on possession of a live requestId, which only the
  // deep link carries. Status/results are transport state, not authorization:
  // consumers must cryptographically verify the ZK proof and its public inputs.
  app.post('/api/v1/proof/callback', rateLimit('callback'), async (req: Request, res: Response) => {
    const body = (req.body && typeof req.body === 'object' ? req.body : {}) as Record<string, unknown>;
    console.log(`[Relay Callback] <<<< RECEIVED from app. IP: ${maskIp(clientIp(req))}, ${describeBody(body)}`);
    try {
      const { requestId, status, errorCode } = body;

      if (typeof requestId !== 'string' || !requestId || typeof status !== 'string' || !status) {
        res.status(400).json({ error: 'requestId and status are required' });
        return;
      }
      const isTerminal = isOneOf(APP_TERMINAL_STATUSES, status);
      if (!isTerminal && !isOneOf(INTERMEDIATE_STATUSES, status)) {
        console.log(`[Relay Callback] Rejected: unknown status=${scrubText(status)} for requestId=${requestId}`);
        res.status(400).json({
          error: `Unknown status '${status}'. Known: ${[...APP_TERMINAL_STATUSES, ...INTERMEDIATE_STATUSES].join(', ')}`,
        });
        return;
      }
      const fieldError = callbackFieldError(body);
      if (fieldError) {
        console.log(`[Relay Callback] Rejected: requestId=${requestId}, status=${status}: ${fieldError}`);
        res.status(400).json({ error: fieldError });
        return;
      }

      // The terminal record outlives the status (TERMINAL_TTL_SECONDS), so a
      // re-sent answer days later still learns why it was refused.
      const finishedEarlier = await lifecycle.terminalOf(requestId);
      if (finishedEarlier) {
        console.log(`[Relay Callback] Rejected: requestId=${requestId} already ${finishedEarlier}, incoming status=${status}`);
        res.status(409).json(alreadyFinished(finishedEarlier));
        return;
      }

      const meta = await lifecycle.getMeta(requestId);
      if (!meta || !(await lifecycle.getStatus(requestId))) {
        console.log(`[Relay Callback] Rejected: unknown requestId=${requestId} (not found in Redis — expired or never created)`);
        res.status(404).json({ error: 'Unknown or expired requestId' });
        return;
      }
      // The circuit is part of what the dApp asked for. An answer naming
      // another circuit is not an answer to this request. Until 2026-10-27 the
      // relay logged the mismatch and delivered it anyway. The app echoes the
      // request's own canonical id, so only a tampered or foreign answer differs.
      if (body.circuit !== undefined && body.circuit !== meta.circuitId) {
        console.log(`[Relay Callback] Rejected: circuit mismatch requestId=${requestId}, requested=${meta.circuitId}, callback=${scrubText(String(body.circuit))}`);
        res.status(400).json({ error: `circuit '${String(body.circuit)}' does not match the request's circuit '${meta.circuitId}'` });
        return;
      }

      await expireIfDue(requestId);
      const already = await lifecycle.terminalOf(requestId);
      if (already) {
        console.log(`[Relay Callback] Rejected: requestId=${requestId} already ${already}, incoming status=${status}`);
        res.status(409).json(alreadyFinished(already));
        return;
      }

      if (!isTerminal) {
        const applied = await lifecycle.setIntermediate(requestId, status as ProofStatus['status']);
        if (!applied) {
          const finished = await lifecycle.terminalOf(requestId);
          res.status(409).json(alreadyFinished(finished));
          return;
        }
        proofNs.to(room(requestId)).emit('proof:status', { requestId, status });
        console.log(`[Relay Callback] Intermediate status update: requestId=${requestId}, status=${status}`);
        res.json({ received: true });
        return;
      }

      const isError = status === 'error' || status === 'failed';
      // Every field was type-checked above (callbackFieldError). The circuit is
      // the one recorded at creation, whether or not the app named it.
      const proofResult: ProofResult = {
        requestId,
        status: status as TerminalStatus,
        proof: body.proof as string | undefined,
        publicInputs: body.publicInputs as string[] | undefined,
        error: typeof body.error === 'string' ? capErrorMessage(body.error) : undefined,
        ...(isError && typeof errorCode === 'string' && { errorCode }),
        verifierAddress: body.verifierAddress as string | undefined,
        chainId: body.chainId as number | undefined,
        circuit: meta.circuitId,
        ...(body.signerVariant !== undefined && { signerVariant: body.signerVariant as SignerVariant }),
        completedAt: new Date().toISOString(),
      };

      const won = await lifecycle.finalize(proofResult);
      if (!won) {
        const finished = await lifecycle.terminalOf(requestId);
        console.log(`[Relay Callback] Lost the race: requestId=${requestId} already ${finished}`);
        res.status(409).json(alreadyFinished(finished));
        return;
      }

      deliver(proofResult);
      // Where the answer came from, as our own front end resolved it. With no
      // such front end (edge.ts) there is nothing trustworthy to read.
      const country = edge.regionHeader ? countryLabel(req.headers[edge.regionHeader]) : undefined;
      countOutcome(meta, proofResult, country);

      res.json({ received: true });
      console.log(`[Relay Callback] Successfully processed: requestId=${requestId}, status=${status}, errorCode=${proofResult.errorCode}, circuit=${scrubText(proofResult.circuit)}, chainId=${proofResult.chainId}, signerVariant=${proofResult.signerVariant}`);
    } catch (err) {
      console.error(`[Relay Callback] Error: ${scrubError(err)}`);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  /**
   * The 409 body for a callback on a request that already ended. Stable on
   * purpose: the app branches on `reason` (and falls back to the wording).
   *   expired           the relay timed the request out before the app answered
   *   already_answered  another terminal answer was taken first
   */
  function alreadyFinished(terminal: TerminalStatus | null): { error: string; reason: 'expired' | 'already_answered' } {
    if (terminal === 'expired') return { error: EXPIRED_MESSAGE, reason: 'expired' };
    return { error: ALREADY_ANSWERED_MESSAGE, reason: 'already_answered' };
  }

  /**
   * Statistics. Bearer-protected; authentication is checked before the query
   * is validated, so an unauthenticated caller learns nothing about the API.
   *
   * Order: lockout (statsAuth.ts, shared across instances via Redis) -> token
   * (constant-time) -> per-instance limit on successful reads -> query.
   * Same-origin only: SAME_ORIGIN_ONLY keeps CORS headers off this path.
   */
  app.get('/api/v1/stats', async (req: Request, res: Response) => {
    res.setHeader('Cache-Control', 'no-store');
    const ip = clientIp(req);
    try {
      const lockedFor = await statsAuth.lockedFor(ip);
      if (lockedFor > 0) {
        console.log(`[Relay Stats] Locked out: IP ${maskIp(ip)} for ${lockedFor}s more`);
        res.setHeader('Retry-After', String(lockedFor));
        res.status(429).json({ error: 'Too many failed attempts. Try again later.', retryAfterSeconds: lockedFor });
        return;
      }
      if (!bearerMatches(req.get('authorization'), statsToken)) {
        const failures = await statsAuth.recordFailure(ip);
        console.log(`[Relay Stats] Rejected: missing or wrong bearer token from IP: ${maskIp(ip)}, failures=${failures}/${STATS_AUTH_MAX_FAILURES}`);
        res.setHeader('WWW-Authenticate', 'Bearer');
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }
    } catch (err) {
      console.error(`[Relay Stats] Auth check failed: ${scrubError(err)}`);
      res.status(500).json({ error: 'Internal server error' });
      return;
    }
    const retryAfter = consume('stats', ip);
    if (retryAfter !== null) {
      res.setHeader('Retry-After', String(retryAfter));
      res.status(429).json({ error: 'Too many requests. Please try again later.' });
      return;
    }
    const range = checkRange(req.query.from, req.query.to);
    if (!range.ok) {
      res.status(400).json({ error: range.error });
      return;
    }
    try {
      res.json(await readStats(redis, range.days));
    } catch (err) {
      console.error(`[Relay Stats] Read failed: ${scrubError(err)}`);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.get('/health', (_req: Request, res: Response) => {
    res.json({ status: 'ok', service: 'proofport-relay', timestamp: new Date().toISOString() });
  });

  mountAdmin(app);

  // body-parser's SyntaxError quotes the start of the body it could not parse,
  // and Express's default handler prints that stack. Scrub it here.
  app.use((err: unknown, req: Request, res: Response, next: NextFunction) => {
    if (res.headersSent) return next(err);
    const status = (err as { status?: number; statusCode?: number })?.status ?? (err as { statusCode?: number })?.statusCode ?? 500;
    console.error(`[Relay] ${req.method} ${req.path} failed (${status}): ${scrubError(err)}`);
    let message = 'Internal server error';
    if (status === 400) message = 'Malformed request body';
    if (status === 413) message = 'Request body too large';
    res.status(status).json({ error: message });
  });

  // -------------------------------------------------------------------------
  // Socket.IO /proof namespace (no JWT middleware — open connections)
  // -------------------------------------------------------------------------
  proofNs.on('connection', (socket: Socket) => {
    // The handshake request, read the same way as HTTP (clientIp.ts), so a
    // caller has one rate-limit bucket whichever transport it uses.
    const ip = clientIp(socket.request);
    console.log(`[Socket.IO] Client connected: ${socket.id}, ip=${maskIp(ip)}`);

    socket.on('proof:request', async (data: Parameters<typeof processProofRequest>[0]) => {
      console.log(`[Socket.IO] proof:request from ${socket.id}: ${describeBody(data)}`);
      // Same budget as POST /api/v1/proof/request. Until 2026-10-14 this event
      // had no limit at all, so the HTTP limit could be sidestepped here.
      if (consume('request', ip) !== null) {
        socket.emit('proof:error', { error: 'Too many requests. Please try again later.', code: 429 });
        return;
      }
      try {
        const result = await processProofRequest(data || {}, socket.handshake.headers.origin);
        if (!result.ok) {
          console.log(`[Socket.IO] proof:request failed for ${socket.id}: code=${result.code}, error=${scrubText(result.error)}`);
          socket.emit('proof:error', { error: result.error, code: result.code });
          return;
        }
        socket.join(room(result.requestId));
        console.log(`[Socket.IO] Socket ${socket.id} joined room request:${result.requestId}, ${describeDeepLink(result.deepLink)}`);
        socket.emit('proof:status', { requestId: result.requestId, status: 'pending', deepLink: result.deepLink });
      } catch (err) {
        console.error(`[Socket.IO] proof:request error: ${scrubError(err)}`);
        socket.emit('proof:error', { error: 'Internal server error' });
      }
    });

    socket.on('proof:subscribe', async (data: { requestId?: unknown }) => {
      const requestId = data && typeof data.requestId === 'string' ? data.requestId : undefined;
      console.log(`[Socket.IO] proof:subscribe from ${socket.id}: requestId=${requestId ?? 'none'}`);
      if (!requestId) {
        socket.emit('proof:error', { error: 'requestId is required' });
        return;
      }
      try {
        await expireIfDue(requestId);
        socket.join(room(requestId));

        const buffered = await lifecycle.getResult(requestId);
        if (buffered) {
          console.log(`[Socket.IO] Replaying buffered result for ${requestId} (status=${buffered.status})`);
          socket.emit('proof:result', buffered);
          return;
        }
        const status = await lifecycle.getStatus(requestId);
        if (status) {
          socket.emit('proof:status', { requestId, status: status.status, deepLink: status.deepLink });
        } else {
          console.log(`[Socket.IO] Request not found: ${requestId}`);
          socket.emit('proof:error', { error: 'Request not found or expired', requestId });
        }
      } catch (err) {
        console.error(`[Socket.IO] proof:subscribe error: ${scrubError(err)}`);
        socket.emit('proof:error', { error: 'Internal server error', requestId });
      }
    });

    socket.on('disconnect', (reason: string) => {
      console.log(`[Socket.IO] Client disconnected: ${socket.id} (${reason})`);
    });
  });

  return {
    app,
    httpServer,
    io,
    lifecycle,
    sweep,
    async close() {
      clearInterval(sweepTimer);
      clearInterval(rateLimitCleanup);
      await new Promise<void>((resolve) => io.close(() => resolve()));
      if (httpServer.listening) await new Promise<void>((resolve) => httpServer.close(() => resolve()));
    },
  };
}
