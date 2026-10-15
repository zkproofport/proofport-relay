import express, { NextFunction, Request, Response } from 'express';
import { createServer, Server as HttpServer } from 'http';
import { Server, ServerOptions, Socket } from 'socket.io';
import cors from 'cors';
import helmet from 'helmet';
import { v4 as uuidv4 } from 'uuid';
import { createHash } from 'crypto';
import type Redis from 'ioredis';
import { ethers } from 'ethers';
import { isCircuitId, ALL_CIRCUIT_IDS } from '@zkproofport-app/sdk/circuits';
import type { ProofRequest, ProofResult, ProofSession, ProofStatus, RequestMeta, TerminalStatus } from './types';
import { APP_TERMINAL_STATUSES, INTERMEDIATE_STATUSES, TERMINAL_STATUSES } from './types';
import { validateReturnScheme } from './returnScheme';
import { NEEDS_WALLET_SIGNATURE } from './signaturePolicy';
import { Lifecycle, STATUS_TTL_SECONDS } from './lifecycle';
import { describeBody, describeDeepLink, maskHex, maskIp, scrubError, scrubText } from './mask';
import { bearerMatches, checkRange, ERROR_CODE_RE, readStats, StatsRecorder, TerminalOutcome } from './stats';
import { clientIp, TRUSTED_PROXY_HOPS } from './clientIp';
import { createStatsAuthGuard, STATS_AUTH_MAX_FAILURES, StatsAuthGuard } from './statsAuth';
import { mountAdmin } from './admin';

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

const RATE_LIMITS = {
  challenge: { windowMs: 60_000, max: 30 },
  /** Shared by POST /api/v1/proof/request and the Socket.IO `proof:request` event. */
  request: { windowMs: 60_000, max: 10 },
  /** Authenticated stats reads. Wrong tokens are limited separately (statsAuth.ts). */
  stats: { windowMs: 60_000, max: 60 },
};

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
  /** Public base URL the app posts callbacks to; empty means "derive from the request". */
  relayExternalUrl: string;
  port: number;
  deadlineMs: number;
  sweepIntervalMs: number;
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

  const app = express();
  const httpServer = createServer(app);

  // See clientIp.ts: exactly one hop (Google's front end), never `true`.
  // Set so `req.ip` and `req.protocol` agree with clientIp(); the relay's own
  // code reads clientIp() so HTTP and Socket.IO share one definition.
  app.set('trust proxy', TRUSTED_PROXY_HOPS);

  app.use(helmet());
  const corsMiddleware = cors({ origin: PUBLIC_CORS_ORIGIN });
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (SAME_ORIGIN_ONLY.some((re) => re.test(req.path))) return next();
    corsMiddleware(req, res, next);
  });
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
  // Sessions
  // -------------------------------------------------------------------------
  const sessionKey = (requestId: string) => `${SESSION_KEY_PREFIX}${requestId}`;
  const inputsHashKey = (requestId: string) => `proof:inputsHash:${requestId}`;
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

  // Known limitation: the replacer filters nested keys (e.g. giwa_attestation.action).
  // Use recursive stable canonicalization before treating this hash as tamper-evident
  // integrity protection for nested requests; it is not an action-bound circuit's
  // exact-action authorization boundary -- the proof is.
  function computeInputsHash(inputs: Record<string, unknown>): string {
    const sortedKeys = Object.keys(inputs).sort();
    const hash = createHash('sha256').update(JSON.stringify(inputs, sortedKeys)).digest('hex');
    // The canonical JSON is the user's proof inputs; only its key names are logged.
    console.log(`[Relay Hash] computeInputsHash: sortedKeys=${JSON.stringify(sortedKeys)}, hash=${maskHex(hash)}`);
    return hash;
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

  function countOutcome(meta: RequestMeta | null, result: ProofResult): void {
    if (!meta) {
      // A request opened by a relay version that did not record its circuit.
      // Its `requested` was never counted either, so skipping keeps the two consistent.
      console.log(`[Relay Stats] Not counted: no recorded circuit for requestId=${result.requestId}`);
      return;
    }
    const outcome = STATS_OUTCOME[result.status];
    stats.record(meta.circuitId, outcome, outcome === 'error' ? result.errorCode : undefined);
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
  }, relayBaseUrl?: string): Promise<{ ok: true; requestId: string; deepLink: string; status: ProofStatus } | { ok: false; error: string; code: number }> {
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
    if (session.status !== 'pending') {
      console.log(`[Relay] processProofRequest rejected: session already used — requestId=${reqId}, status=${session.status}`);
      return { ok: false, error: 'Session already used (replay detected)', code: 409 };
    }
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

    await updateSession(reqId, { status: 'claimed', circuitId, inputs });

    if (nonce) {
      const seen = await redis.get(nonceKey(nonce));
      if (seen) {
        console.log(`[Relay] processProofRequest rejected: duplicate nonce=${scrubText(nonce)}`);
        return { ok: false, error: 'Duplicate nonce (replay detected)', code: 409 };
      }
      await redis.set(nonceKey(nonce), '1', 'EX', NONCE_TTL);
    }

    const requestId = reqId;
    const nowMs = Date.now();
    const now = new Date(nowMs).toISOString();

    const relayCallbackUrl = `${options.relayExternalUrl || relayBaseUrl || `http://localhost:${options.port}`}/api/v1/proof/callback`;
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

    const inputsHash = computeInputsHash(inputs);
    await redis.set(inputsHashKey(requestId), inputsHash, 'EX', STATUS_TTL_SECONDS);

    const deepLink = buildDeepLink(proofRequest);
    const status: ProofStatus = { requestId, status: 'pending', deepLink, createdAt: now, updatedAt: now };
    const meta = await lifecycle.open(status, circuitId, nowMs);
    console.log(`[Relay] Status stored: requestId=${requestId}, status=pending, ttl=${STATUS_TTL_SECONDS}s, deadlineAt=${new Date(meta.deadlineAt).toISOString()}`);

    stats.record(circuitId, 'requested');

    proofNs.to(room(requestId)).emit('proof:status', { requestId, status: 'pending' });
    console.log(`[Relay] Proof request created successfully: requestId=${requestId}, circuitId=${circuitId}, inputsHash=${maskHex(inputsHash)}`);

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
      const relayBaseUrl = `${req.protocol}://${req.get('host')}`;
      console.log(`[Relay REST] POST /api/v1/proof/request from IP: ${maskIp(clientIp(req))}, relayBaseUrl=${relayBaseUrl}, ${describeBody(req.body)}`);

      const result = await processProofRequest(req.body || {}, relayBaseUrl);
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
        }
      }

      const inputsHash = await redis.get(inputsHashKey(requestId));
      if (inputsHash) status.inputsHash = inputsHash;

      console.log(`[Relay Poll] Response for ${requestId}: status=${status.status}, errorCode=${status.errorCode}, hasProof=${Boolean(status.proof)}, inputsHash=${maskHex(status.inputsHash)}`);
      res.json(status);
    } catch (err) {
      console.error(`[Relay Poll] Error: ${scrubError(err)}`);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // Callback writes currently rely on possession of a live requestId.
  // Status/results are transport state, not authorization. Production hardening
  // requires per-session capability/signature authentication (or equivalent);
  // consumers must cryptographically verify the ZK proof and expected public inputs.
  app.post('/api/v1/proof/callback', async (req: Request, res: Response) => {
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
      if (errorCode !== undefined && (typeof errorCode !== 'string' || !ERROR_CODE_RE.test(errorCode))) {
        res.status(400).json({ error: 'errorCode must look like E2007 (E followed by four digits)' });
        return;
      }
      if (body.error !== undefined && typeof body.error !== 'string') {
        res.status(400).json({ error: 'error must be a string' });
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

      if (!(await lifecycle.getStatus(requestId))) {
        console.log(`[Relay Callback] Rejected: unknown requestId=${requestId} (not found in Redis — expired or never created)`);
        res.status(404).json({ error: 'Unknown or expired requestId' });
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
      const proofResult: ProofResult = {
        requestId,
        status: status as TerminalStatus,
        proof: body.proof as string | undefined,
        publicInputs: body.publicInputs as string[] | undefined,
        error: typeof body.error === 'string' ? capErrorMessage(body.error) : undefined,
        ...(isError && typeof errorCode === 'string' && { errorCode }),
        verifierAddress: body.verifierAddress as string | undefined,
        chainId: body.chainId as number | undefined,
        circuit: body.circuit as string | undefined,
        completedAt: new Date().toISOString(),
      };

      const won = await lifecycle.finalize(proofResult);
      if (!won) {
        const finished = await lifecycle.terminalOf(requestId);
        console.log(`[Relay Callback] Lost the race: requestId=${requestId} already ${finished}`);
        res.status(409).json(alreadyFinished(finished));
        return;
      }

      const meta = await lifecycle.getMeta(requestId);
      if (meta && proofResult.circuit !== undefined && proofResult.circuit !== meta.circuitId) {
        console.log(`[Relay Callback] Circuit mismatch: requestId=${requestId}, requested=${meta.circuitId}, callback=${scrubText(proofResult.circuit)}; stats use the requested circuit`);
      }
      deliver(proofResult);
      countOutcome(meta, proofResult);

      res.json({ received: true });
      console.log(`[Relay Callback] Successfully processed: requestId=${requestId}, status=${status}, errorCode=${proofResult.errorCode}, circuit=${scrubText(proofResult.circuit)}, chainId=${proofResult.chainId}`);
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
        const result = await processProofRequest(data || {});
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
