import express, { Request, Response } from 'express';
import { createServer } from 'http';
import { Server, Socket } from 'socket.io';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import { v4 as uuidv4 } from 'uuid';
import { createHash } from 'crypto';
import { initRedis, cacheSet, cacheGet } from './redis';
import type { ProofRequest, ProofResult, ProofStatus, ProofSession } from './types';
import { ethers } from 'ethers';

dotenv.config();

// ---------------------------------------------------------------------------
// Log masking — protect sensitive data in server logs
// ---------------------------------------------------------------------------
const SENSITIVE_KEYS = new Set(['proof', 'signature', 'challenge', 'publicInputs']);

/** Mask a hex string: show first 10 + last 6 chars */
function maskHex(value: string | undefined | null): string {
  if (!value) return String(value);
  if (value.length <= 20) return value;
  return `${value.slice(0, 10)}...${value.slice(-6)}`;
}

/** Mask publicInputs array: show count only */
function maskPublicInputs(arr: string[] | undefined | null): string {
  if (!arr) return String(arr);
  return `[${arr.length} items]`;
}

/** Redact sensitive fields from an object for logging */
function safeStringify(obj: Record<string, unknown>): string {
  const redacted: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    if (key === 'proof' && typeof value === 'string') {
      redacted[key] = maskHex(value);
    } else if (key === 'publicInputs' && Array.isArray(value)) {
      redacted[key] = `[${value.length} items]`;
    } else if (SENSITIVE_KEYS.has(key) && typeof value === 'string') {
      redacted[key] = maskHex(value);
    } else {
      redacted[key] = value;
    }
  }
  return JSON.stringify(redacted);
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const PORT = parseInt(process.env.PORT || '4001', 10);
const nodeEnv = process.env.NODE_ENV || 'development';
if ((nodeEnv === 'production' || nodeEnv === 'staging') && !process.env.CORS_ORIGIN) {
  throw new Error('CORS_ORIGIN environment variable is required in production/staging');
}
const CORS_ORIGIN: string | string[] = process.env.CORS_ORIGIN
  ? (process.env.CORS_ORIGIN === '*' ? '*' : process.env.CORS_ORIGIN.split(',').map(s => s.trim()))
  : '*';

const RESULT_TTL = 300; // 5 minutes
const STATUS_TTL = 600; // 10 minutes
const NONCE_TTL = 600;  // 10 minutes (replay prevention)
// CHALLENGE_TTL replaced by SESSION_TTL in session management

if ((nodeEnv === 'production' || nodeEnv === 'staging') && !process.env.RELAY_EXTERNAL_URL) {
  throw new Error('RELAY_EXTERNAL_URL environment variable is required in production/staging');
}
const RELAY_EXTERNAL_URL = process.env.RELAY_EXTERNAL_URL || '';

// ---------------------------------------------------------------------------
// Express + HTTP
// ---------------------------------------------------------------------------
const app = express();
const httpServer = createServer(app);

app.use(helmet());
app.use(cors({ origin: CORS_ORIGIN }));
app.use(express.json({ limit: '1mb' }));

// ---------------------------------------------------------------------------
// Socket.IO
// ---------------------------------------------------------------------------
const io = new Server(httpServer, {
  cors: { origin: CORS_ORIGIN, methods: ['GET', 'POST'] },
  path: '/socket.io',
});

const proofNs = io.of('/proof');

// ---------------------------------------------------------------------------
// Rate limiting (in-memory sliding window)
// ---------------------------------------------------------------------------
const RATE_LIMITS = {
  challenge: { windowMs: 60_000, max: 30 },   // 30 challenges per minute per IP
  request: { windowMs: 60_000, max: 10 },      // 10 proof requests per minute per IP
};

const rateLimitStore = new Map<string, { count: number; resetAt: number }>();

function rateLimit(type: keyof typeof RATE_LIMITS) {
  return (req: Request, res: Response, next: Function) => {
    const ip = req.ip || 'unknown';
    const key = `${type}:${ip}`;
    const limit = RATE_LIMITS[type];
    const now = Date.now();

    const entry = rateLimitStore.get(key);
    if (!entry || now > entry.resetAt) {
      rateLimitStore.set(key, { count: 1, resetAt: now + limit.windowMs });
      return next();
    }

    if (entry.count >= limit.max) {
      console.log(`[Relay RateLimit] Rejected: type=${type}, ip=${ip}, count=${entry.count}, max=${limit.max}, resetsAt=${new Date(entry.resetAt).toISOString()}`);
      res.status(429).json({ error: 'Too many requests. Please try again later.' });
      return;
    }

    entry.count++;
    next();
  };
}

// Periodic cleanup (every 5 minutes)
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitStore) {
    if (now > entry.resetAt) rateLimitStore.delete(key);
  }
}, 300_000);

// ---------------------------------------------------------------------------
// Session management (Redis-backed)
// ---------------------------------------------------------------------------
const SESSION_KEY_PREFIX = 'session:';
const SESSION_TTL = 600; // 10 minutes

function sessionKey(requestId: string) { return `${SESSION_KEY_PREFIX}${requestId}`; }

async function createSession(ip: string): Promise<ProofSession> {
  const requestId = uuidv4();
  const challengeBytes = ethers.randomBytes(32);
  const challenge = ethers.hexlify(challengeBytes);
  const now = new Date();

  const session: ProofSession = {
    requestId,
    challenge,
    status: 'pending',
    ip,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + SESSION_TTL * 1000).toISOString(),
  };

  await cacheSet(sessionKey(requestId), JSON.stringify(session), SESSION_TTL);
  console.log(`[Relay Session] Created: requestId=${requestId}, challenge=${maskHex(challenge)}, ip=${ip}`);
  return session;
}

async function getSession(requestId: string): Promise<ProofSession | null> {
  const data = await cacheGet(sessionKey(requestId));
  if (!data) return null;
  return JSON.parse(data) as ProofSession;
}

async function updateSession(requestId: string, updates: Partial<ProofSession>): Promise<void> {
  const session = await getSession(requestId);
  if (!session) return;
  const updated = { ...session, ...updates };
  const ttl = Math.max(1, Math.floor((new Date(session.expiresAt).getTime() - Date.now()) / 1000));
  await cacheSet(sessionKey(requestId), JSON.stringify(updated), ttl > 0 ? ttl : SESSION_TTL);
}

/**
 * Verify challenge-signature for circuits that require wallet signing (e.g., Coinbase).
 * Returns the recovered signer address for use as circuit input.
 */
async function verifyWalletSignature(challenge: string, signature: string): Promise<{ valid: boolean; signerAddress?: string; error?: string }> {
  if (!signature) {
    return { valid: false, error: 'signature is required for this circuit' };
  }
  try {
    const signerAddress = ethers.verifyMessage(challenge, signature);
    console.log(`[Relay Auth] Wallet signature verified: signerAddress=${signerAddress}`);
    return { valid: true, signerAddress };
  } catch (err: any) {
    console.log(`[Relay Auth] Wallet signature verification failed: ${err.message}`);
    return { valid: false, error: 'Invalid signature' };
  }
}

// ---------------------------------------------------------------------------
// Inputs hash
// ---------------------------------------------------------------------------
function computeInputsHash(inputs: Record<string, unknown>): string {
  const sortedKeys = Object.keys(inputs).sort();
  const canonical = JSON.stringify(inputs, sortedKeys);
  const hash = createHash('sha256').update(canonical).digest('hex');
  console.log(`[Relay Hash] computeInputsHash: sortedKeys=${JSON.stringify(sortedKeys)}, canonical=${canonical}, hash=${hash}`);
  return hash;
}

function inputsHashKey(requestId: string) { return `proof:inputsHash:${requestId}`; }

// ---------------------------------------------------------------------------
// Deep link generation
// ---------------------------------------------------------------------------
function buildDeepLink(request: ProofRequest): string {
  const jsonPayload = JSON.stringify(request);
  const data = Buffer.from(jsonPayload).toString('base64url');
  const deepLink = `zkproofport://proof-request?data=${data}`;
  console.log(`[Relay DeepLink] buildDeepLink: requestId=${request.requestId}, jsonPayload=${jsonPayload}, base64url=${data}, deepLink=${deepLink}`);
  return deepLink;
}

// ---------------------------------------------------------------------------
// Status helpers
// ---------------------------------------------------------------------------
function statusKey(requestId: string) {
  return `proof:status:${requestId}`;
}
function resultKey(requestId: string) {
  return `proof:result:${requestId}`;
}
function nonceKey(nonce: string) {
  return `proof:nonce:${nonce}`;
}

async function setStatus(requestId: string, status: Partial<ProofStatus>): Promise<void> {
  const existing = await cacheGet(statusKey(requestId));
  const current: ProofStatus = existing
    ? JSON.parse(existing)
    : { requestId, status: 'pending', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() };

  const updated: ProofStatus = {
    ...current,
    ...status,
    requestId,
    updatedAt: new Date().toISOString(),
  };
  await cacheSet(statusKey(requestId), JSON.stringify(updated), STATUS_TTL);
}

async function getStatus(requestId: string): Promise<ProofStatus | null> {
  const raw = await cacheGet(statusKey(requestId));
  return raw ? JSON.parse(raw) : null;
}

// ---------------------------------------------------------------------------
// Core proof request processing
// ---------------------------------------------------------------------------
// Circuits that require wallet signature (used as circuit input for on-chain verification)
const WALLET_SIGNATURE_CIRCUITS = ['coinbase_attestation', 'coinbase_country_attestation'];

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
}, relayBaseUrl?: string): Promise<{ ok: true; requestId: string; deepLink: string; status: ProofStatus } | { ok: false; error: string; code: number }> {
  const { requestId: reqId, circuitId, scope, inputs, nonce, challenge, signature } = body;

  console.log(`[Relay] processProofRequest: requestId=${reqId}, circuitId=${circuitId}, challenge=${maskHex(challenge)}, signature=${maskHex(signature)}`);

  // Session-based authentication: verify requestId + challenge
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

  // Validate required fields
  if (!circuitId || typeof circuitId !== 'string') {
    return { ok: false, error: 'circuitId is required', code: 400 };
  }
  if (!inputs || typeof inputs !== 'object') {
    return { ok: false, error: 'inputs object is required', code: 400 };
  }

  // Wallet signature required for Coinbase circuits (used as circuit input)
  if (WALLET_SIGNATURE_CIRCUITS.includes(circuitId)) {
    if (!signature) {
      return { ok: false, error: 'signature is required for this circuit', code: 401 };
    }
    const sigResult = await verifyWalletSignature(challenge, signature);
    if (!sigResult.valid) {
      return { ok: false, error: sigResult.error!, code: 401 };
    }
    console.log(`[Relay] Wallet signature verified for ${circuitId}: ${sigResult.signerAddress}`);
  }

  // Mark session as claimed (prevents replay)
  await updateSession(reqId, { status: 'claimed', circuitId, inputs });

  // Replay prevention via nonce (additional layer)
  if (nonce) {
    const seen = await cacheGet(nonceKey(nonce));
    if (seen) {
      console.log(`[Relay] processProofRequest rejected: duplicate nonce=${nonce}`);
      return { ok: false, error: 'Duplicate nonce (replay detected)', code: 409 };
    }
    await cacheSet(nonceKey(nonce), '1', NONCE_TTL);
  }

  const requestId = reqId;
  const now = new Date().toISOString();
  const effectiveScope = scope || '';

  const relayCallbackUrl = `${RELAY_EXTERNAL_URL || relayBaseUrl || `http://localhost:${PORT}`}/api/v1/proof/callback`;
  console.log(`[Relay] processProofRequest: requestId=${requestId}, callbackUrl=${relayCallbackUrl}`);

  const proofRequest: ProofRequest = {
    requestId,
    circuitId,
    scope: effectiveScope,
    inputs,
    callbackUrl: relayCallbackUrl,
    ...(body.dappName && { dappName: body.dappName }),
    ...(body.dappIcon && { dappIcon: body.dappIcon }),
    ...(body.message && { message: body.message }),
    createdAt: now,
  };
  console.log(`[Relay] ProofRequest object: ${safeStringify(proofRequest as unknown as Record<string, unknown>)}`);

  // Compute and store inputs hash for deep link integrity verification
  const inputsHash = computeInputsHash(inputs);
  await cacheSet(inputsHashKey(requestId), inputsHash, STATUS_TTL);

  // Set initial status
  const deepLink = buildDeepLink(proofRequest);
  const status: ProofStatus = {
    requestId,
    status: 'pending',
    deepLink,
    createdAt: now,
    updatedAt: now,
  };
  await cacheSet(statusKey(requestId), JSON.stringify(status), STATUS_TTL);
  console.log(`[Relay] Status stored: requestId=${requestId}, status=pending, ttl=${STATUS_TTL}s`);

  proofNs.to(`request:${requestId}`).emit('proof:status', { requestId, status: 'pending' });

  console.log(`[Relay] Proof request created successfully: requestId=${requestId}, circuitId=${circuitId}, inputsHash=${inputsHash}`);

  return { ok: true, requestId, deepLink: status.deepLink!, status };
}

// ---------------------------------------------------------------------------
// REST: GET /api/v1/challenge
// ---------------------------------------------------------------------------
app.get('/api/v1/challenge', rateLimit('challenge'), async (req: Request, res: Response) => {
  try {
    const ip = req.ip || 'unknown';
    console.log(`[Relay Challenge] GET /api/v1/challenge from IP: ${ip}`);

    const session = await createSession(ip);
    const expiresAt = new Date(session.expiresAt).getTime();

    console.log(`[Relay Challenge] Generated: requestId=${session.requestId}, challenge=${maskHex(session.challenge)}, ip=${ip}`);

    res.json({ requestId: session.requestId, challenge: session.challenge, expiresAt });
  } catch (err: any) {
    console.error('[Relay Challenge] Generation error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ---------------------------------------------------------------------------
// REST: POST /api/v1/proof/request
// ---------------------------------------------------------------------------
app.post('/api/v1/proof/request', rateLimit('request'), async (req: Request, res: Response) => {
  try {
    const relayBaseUrl = `${req.protocol}://${req.get('host')}`;
    console.log(`[Relay REST] POST /api/v1/proof/request from IP: ${req.ip}, relayBaseUrl=${relayBaseUrl}, body=${safeStringify(req.body || {})}`);

    const result = await processProofRequest(req.body, relayBaseUrl);
    if (!result.ok) {
      console.log(`[Relay REST] POST /api/v1/proof/request failed: code=${result.code}, error=${result.error}`);
      res.status(result.code).json({ error: result.error });
      return;
    }

    const response = {
      requestId: result.requestId,
      deepLink: result.deepLink,
      status: result.status.status,
      pollUrl: `/api/v1/proof/${result.requestId}`,
    };
    console.log(`[Relay REST] POST /api/v1/proof/request success: ${JSON.stringify(response)}`);
    res.status(201).json(response);
  } catch (err: any) {
    console.error('[Relay REST] Proof request error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ---------------------------------------------------------------------------
// REST: GET /api/v1/proof/:requestId
// ---------------------------------------------------------------------------
app.get('/api/v1/proof/:requestId', async (req: Request, res: Response) => {
  try {
    const requestId = req.params.requestId as string;
    console.log(`[Relay Poll] GET /api/v1/proof/${requestId} from IP: ${req.ip}`);
    const status = await getStatus(requestId);
    if (!status) {
      console.log(`[Relay Poll] Request ${requestId} not found or expired (no status in Redis)`);
      res.status(404).json({ error: 'Request not found or expired' });
      return;
    }

    console.log(`[Relay Poll] Status found for ${requestId}: status=${status.status}, createdAt=${status.createdAt}, updatedAt=${status.updatedAt}`);

    // If completed, attach buffered result
    if (status.status === 'completed' || status.status === 'failed') {
      const raw = await cacheGet(resultKey(requestId));
      if (raw) {
        const result: ProofResult = JSON.parse(raw);
        status.proof = result.proof;
        status.publicInputs = result.publicInputs;
        status.error = result.error;
        status.verifierAddress = result.verifierAddress;
        status.chainId = result.chainId;
        status.circuit = result.circuit;
        console.log(`[Relay Poll] Attached buffered result for ${requestId}: proof=${maskHex(result.proof)}, publicInputs=${maskPublicInputs(result.publicInputs)}, verifierAddress=${result.verifierAddress}, chainId=${result.chainId}, circuit=${result.circuit}, error=${result.error}`);
      } else {
        console.log(`[Relay Poll] No buffered result found for ${requestId} (result expired from Redis)`);
      }
    }

    // Attach inputsHash if available
    const inputsHash = await cacheGet(inputsHashKey(requestId));
    if (inputsHash) {
      status.inputsHash = inputsHash;
      console.log(`[Relay Poll] InputsHash for ${requestId}: ${inputsHash}`);
    } else {
      console.log(`[Relay Poll] No inputsHash found for ${requestId} (expired from Redis)`);
    }

    console.log(`[Relay Poll] Full response for ${requestId}: ${safeStringify(status as unknown as Record<string, unknown>)}`);
    res.json(status);
  } catch (err: any) {
    console.error('[Relay Poll] Error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ---------------------------------------------------------------------------
// REST: POST /api/v1/proof/callback  (ZKProofport app posts result here)
// ---------------------------------------------------------------------------
app.post('/api/v1/proof/callback', async (req: Request, res: Response) => {
  console.log(`[Relay Callback] <<<< RECEIVED from app. IP: ${req.ip}, body=${safeStringify(req.body || {})}`);
  try {
    const { requestId, status, proof, publicInputs, error, verifierAddress, chainId, circuit } = req.body as {
      requestId?: string;
      status?: string;
      proof?: string;
      publicInputs?: string[];
      error?: string;
      verifierAddress?: string;
      chainId?: number;
      circuit?: string;
    };

    console.log(`[Relay Callback] Parsed fields: requestId=${requestId}, status=${status}, circuit=${circuit}, proof=${maskHex(proof)}, publicInputs=${maskPublicInputs(publicInputs)}, verifierAddress=${verifierAddress}, chainId=${chainId}, error=${error}`);

    if (!requestId || !status) {
      console.log(`[Relay Callback] Rejected: missing required fields — requestId=${requestId}, status=${status}`);
      res.status(400).json({ error: 'requestId and status are required' });
      return;
    }

    // Validate requestId was created by this relay (exists in Redis)
    const existingStatus = await getStatus(requestId);
    if (!existingStatus) {
      console.log(`[Relay Callback] Rejected: unknown requestId=${requestId} (not found in Redis — expired or never created)`);
      res.status(404).json({ error: 'Unknown or expired requestId' });
      return;
    }
    console.log(`[Relay Callback] Existing status for ${requestId}: ${JSON.stringify(existingStatus)}`);

    if (status !== 'completed' && status !== 'failed' && status !== 'error') {
      // Intermediate status update (e.g. "generating")
      await setStatus(requestId, { status: status as ProofStatus['status'] });
      proofNs.to(`request:${requestId}`).emit('proof:status', { requestId, status });
      console.log(`[Relay Callback] Intermediate status update: requestId=${requestId}, status=${status}`);
      res.json({ received: true });
      return;
    }

    const proofResult: ProofResult = {
      requestId,
      status,
      proof,
      publicInputs,
      error,
      verifierAddress,
      chainId,
      circuit,
      completedAt: new Date().toISOString(),
    };
    console.log(`[Relay Callback] ProofResult object: ${safeStringify(proofResult as unknown as Record<string, unknown>)}`);

    // Buffer result in Redis for reconnection
    await cacheSet(resultKey(requestId), JSON.stringify(proofResult), RESULT_TTL);
    console.log(`[Relay Callback] Result buffered in Redis: requestId=${requestId}, ttl=${RESULT_TTL}s`);

    // Update status
    await setStatus(requestId, { status: status as ProofStatus['status'], proof, publicInputs, error });

    // Emit via Socket.IO
    const room = `request:${requestId}`;
    const sockets = await proofNs.in(room).fetchSockets();
    console.log(`[Relay Callback] Socket.IO emit: room=${room}, connectedSockets=${sockets.length}, socketIds=${sockets.map(s => s.id).join(',')}`);
    proofNs.to(room).emit('proof:result', proofResult);

    res.json({ received: true });
    console.log(`[Relay Callback] Successfully processed: requestId=${requestId}, status=${status}, circuit=${circuit}, verifierAddress=${verifierAddress}, chainId=${chainId}`);
  } catch (err: any) {
    console.error('[Relay Callback] Error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------
app.get('/health', (_req: Request, res: Response) => {
  res.json({
    status: 'ok',
    service: 'proofport-relay',
    timestamp: new Date().toISOString(),
  });
});

// ---------------------------------------------------------------------------
// Socket.IO /proof namespace (no JWT middleware — open connections)
// ---------------------------------------------------------------------------
proofNs.on('connection', (socket: Socket) => {
  console.log(`[Socket.IO] Client connected: ${socket.id}`);

  // proof:request via Socket.IO - require challenge+signature in data
  socket.on('proof:request', async (data: {
    circuitId?: string;
    scope?: string;
    inputs?: Record<string, unknown>;
    nonce?: string;
    challenge?: string;
    signature?: string;
  }) => {
    console.log(`[Socket.IO] proof:request from ${socket.id}: ${safeStringify(data as unknown as Record<string, unknown>)}`);
    try {
      const result = await processProofRequest(data);
      if (!result.ok) {
        console.log(`[Socket.IO] proof:request failed for ${socket.id}: code=${result.code}, error=${result.error}`);
        socket.emit('proof:error', { error: result.error, code: result.code });
        return;
      }

      socket.join(`request:${result.requestId}`);
      console.log(`[Socket.IO] Socket ${socket.id} joined room request:${result.requestId}, deepLink=${result.deepLink}`);

      socket.emit('proof:status', {
        requestId: result.requestId,
        status: 'pending',
        deepLink: result.deepLink,
      });
    } catch (err: any) {
      console.error('[Socket.IO] proof:request error:', err);
      socket.emit('proof:error', { error: 'Internal server error' });
    }
  });

  // Allow client to subscribe to an existing request (e.g. after reconnect)
  socket.on('proof:subscribe', async (data: { requestId?: string }) => {
    console.log(`[Socket.IO] proof:subscribe from ${socket.id}: requestId=${data.requestId || 'none'}`);
    if (!data.requestId) {
      socket.emit('proof:error', { error: 'requestId is required' });
      return;
    }

    socket.join(`request:${data.requestId}`);

    // If there is a buffered result, replay it
    const buffered = await cacheGet(resultKey(data.requestId));
    if (buffered) {
      const result: ProofResult = JSON.parse(buffered);
      console.log(`[Socket.IO] Replaying buffered result for ${data.requestId} (status=${result.status})`);
      socket.emit('proof:result', result);
      return;
    }

    // Otherwise send current status
    const status = await getStatus(data.requestId);
    if (status) {
      console.log(`[Socket.IO] Current status for ${data.requestId}: ${status.status}`);
      socket.emit('proof:status', {
        requestId: data.requestId,
        status: status.status,
        deepLink: status.deepLink,
      });
    } else {
      console.log(`[Socket.IO] Request not found: ${data.requestId}`);
      socket.emit('proof:error', { error: 'Request not found or expired', requestId: data.requestId });
    }
  });

  socket.on('disconnect', (reason: string) => {
    console.log(`[Socket.IO] Client disconnected: ${socket.id} (${reason})`);
  });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
async function main() {
  await initRedis();

  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`[Relay] Server running on port ${PORT}`);
    console.log(`[Relay] Health: http://0.0.0.0:${PORT}/health`);
    console.log(`[Relay] Socket.IO namespace: /proof`);
  });
}

main().catch((err) => {
  console.error('[Relay] Fatal error:', err);
  process.exit(1);
});
