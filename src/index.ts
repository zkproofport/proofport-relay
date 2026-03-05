import express, { Request, Response } from 'express';
import { createServer } from 'http';
import { Server, Socket } from 'socket.io';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import { v4 as uuidv4 } from 'uuid';
import { createHash } from 'crypto';
import { initRedis, cacheSet, cacheGet, cacheDel } from './redis';
import type { ProofRequest, ProofResult, ProofStatus } from './types';
import { ethers } from 'ethers';

dotenv.config();

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
const CHALLENGE_TTL = 120; // 2 minutes

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
// Challenge-signature auth
// ---------------------------------------------------------------------------
function challengeKey(challenge: string) { return `challenge:${challenge}`; }

async function verifyChallenge(challenge: string, signature: string): Promise<{ valid: boolean; signerAddress?: string; error?: string }> {
  if (!challenge || !signature) {
    return { valid: false, error: 'challenge and signature are required' };
  }

  // Check challenge exists in Redis (prevents replay)
  const stored = await cacheGet(challengeKey(challenge));
  if (!stored) {
    return { valid: false, error: 'Invalid or expired challenge' };
  }

  try {
    // Recover signer address from EIP-191 personal_sign
    const signerAddress = ethers.verifyMessage(challenge, signature);

    // Delete challenge from Redis (one-time use)
    await cacheDel(challengeKey(challenge));

    return { valid: true, signerAddress };
  } catch (err: any) {
    return { valid: false, error: 'Invalid signature' };
  }
}

// ---------------------------------------------------------------------------
// Inputs hash
// ---------------------------------------------------------------------------
function computeInputsHash(inputs: Record<string, unknown>): string {
  const canonical = JSON.stringify(inputs, Object.keys(inputs).sort());
  return createHash('sha256').update(canonical).digest('hex');
}

function inputsHashKey(requestId: string) { return `proof:inputsHash:${requestId}`; }

// ---------------------------------------------------------------------------
// Deep link generation
// ---------------------------------------------------------------------------
function buildDeepLink(request: ProofRequest): string {
  const data = Buffer.from(JSON.stringify(request)).toString('base64url');
  return `zkproofport://proof-request?data=${data}`;
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
async function processProofRequest(body: {
  circuitId?: string;
  scope?: string;
  inputs?: Record<string, unknown>;
  nonce?: string;
  challenge?: string;
  signature?: string;
}, relayBaseUrl?: string): Promise<{ ok: true; requestId: string; deepLink: string; status: ProofStatus } | { ok: false; error: string; code: number }> {
  const { circuitId, scope, inputs, nonce, challenge, signature } = body;

  console.log(`[Relay] processProofRequest: circuitId=${circuitId}, scope=${scope || 'none'}, inputKeys=${inputs ? Object.keys(inputs).join(',') : 'none'}, nonce=${nonce || 'none'}`);

  // Verify challenge-signature
  if (!challenge || !signature) {
    return { ok: false, error: 'challenge and signature are required', code: 401 };
  }

  const challengeResult = await verifyChallenge(challenge, signature);
  if (!challengeResult.valid) {
    console.log(`[Relay] Challenge verification failed: ${challengeResult.error}`);
    return { ok: false, error: challengeResult.error!, code: 401 };
  }

  const signerAddress = challengeResult.signerAddress!;
  console.log(`[Relay] Challenge verified, signer: ${signerAddress}`);

  // Validate required fields
  if (!circuitId || typeof circuitId !== 'string') {
    return { ok: false, error: 'circuitId is required', code: 400 };
  }
  if (!inputs || typeof inputs !== 'object') {
    return { ok: false, error: 'inputs object is required', code: 400 };
  }

  // Replay prevention via nonce
  if (nonce) {
    const seen = await cacheGet(nonceKey(nonce));
    if (seen) {
      return { ok: false, error: 'Duplicate nonce (replay detected)', code: 409 };
    }
    await cacheSet(nonceKey(nonce), '1', NONCE_TTL);
  }

  const requestId = uuidv4();
  const now = new Date().toISOString();
  const effectiveScope = scope || '';

  const relayCallbackUrl = `${RELAY_EXTERNAL_URL || relayBaseUrl || `http://localhost:${PORT}`}/api/v1/proof/callback`;

  const proofRequest: ProofRequest = {
    requestId,
    clientId: signerAddress,
    circuitId,
    scope: effectiveScope,
    inputs,
    callbackUrl: relayCallbackUrl,
    createdAt: now,
  };

  // Compute and store inputs hash for deep link integrity verification
  const inputsHash = computeInputsHash(inputs);
  await cacheSet(inputsHashKey(requestId), inputsHash, STATUS_TTL);

  // Set initial status
  const status: ProofStatus = {
    requestId,
    status: 'pending',
    deepLink: buildDeepLink(proofRequest),
    createdAt: now,
    updatedAt: now,
  };
  await cacheSet(statusKey(requestId), JSON.stringify(status), STATUS_TTL);

  proofNs.to(`request:${requestId}`).emit('proof:status', { requestId, status: 'pending' });

  console.log(`[Relay] Proof request created: ${requestId} (signer=${signerAddress}, circuit=${circuitId})`);

  return { ok: true, requestId, deepLink: status.deepLink!, status };
}

// ---------------------------------------------------------------------------
// REST: GET /api/v1/challenge
// ---------------------------------------------------------------------------
app.get('/api/v1/challenge', rateLimit('challenge'), async (req: Request, res: Response) => {
  try {
    // Generate random 32-byte challenge
    const challengeBytes = ethers.randomBytes(32);
    const challenge = ethers.hexlify(challengeBytes);

    // Store in Redis with TTL
    await cacheSet(challengeKey(challenge), JSON.stringify({
      createdAt: Date.now(),
      ip: req.ip,
    }), CHALLENGE_TTL);

    res.json({
      challenge,
      expiresAt: Date.now() + (CHALLENGE_TTL * 1000),
    });
  } catch (err: any) {
    console.error('[REST] Challenge generation error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ---------------------------------------------------------------------------
// REST: POST /api/v1/proof/request
// ---------------------------------------------------------------------------
app.post('/api/v1/proof/request', rateLimit('request'), async (req: Request, res: Response) => {
  try {
    const relayBaseUrl = `${req.protocol}://${req.get('host')}`;
    const result = await processProofRequest(req.body, relayBaseUrl);
    if (!result.ok) {
      res.status(result.code).json({ error: result.error });
      return;
    }
    res.status(201).json({
      requestId: result.requestId,
      deepLink: result.deepLink,
      status: result.status.status,
      pollUrl: `/api/v1/proof/${result.requestId}`,
    });
  } catch (err: any) {
    console.error('[REST] Proof request error:', err);
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
      console.log(`[Relay Poll] Request ${requestId} not found or expired`);
      res.status(404).json({ error: 'Request not found or expired' });
      return;
    }

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
        status.nullifier = result.nullifier;
        status.circuit = result.circuit;
      }
    }

    // Attach inputsHash if available
    const inputsHash = await cacheGet(inputsHashKey(requestId));
    if (inputsHash) {
      status.inputsHash = inputsHash;
    }

    console.log(`[Relay Poll] Response for ${requestId}: status=${status.status}`);
    res.json(status);
  } catch (err: any) {
    console.error('[REST] Poll error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ---------------------------------------------------------------------------
// REST: POST /api/v1/proof/callback  (ZKProofport app posts result here)
// ---------------------------------------------------------------------------
app.post('/api/v1/proof/callback', async (req: Request, res: Response) => {
  console.log(`[Relay Callback] <<<< RECEIVED from app. IP: ${req.ip}`);
  const { proof: _proof, publicInputs: _pi, ...bodyWithoutProof } = req.body || {};
  console.log(`[Relay Callback] Body (excluding proof/publicInputs):`, JSON.stringify(bodyWithoutProof));
  console.log(`[Relay Callback] hasProof: ${!!_proof}, publicInputs: ${_pi?.length ?? 0} items`);
  try {
    const { requestId, status, proof, publicInputs, error, verifierAddress, chainId, nullifier, circuit } = req.body as {
      requestId?: string;
      status?: string;
      proof?: string;
      publicInputs?: string[];
      error?: string;
      verifierAddress?: string;
      chainId?: number;
      nullifier?: string;
      circuit?: string;
    };

    if (!requestId || !status) {
      res.status(400).json({ error: 'requestId and status are required' });
      return;
    }

    // Validate requestId was created by this relay (exists in Redis)
    const existingStatus = await getStatus(requestId);
    if (!existingStatus) {
      console.log(`[Relay Callback] Rejected: unknown requestId ${requestId}`);
      res.status(404).json({ error: 'Unknown or expired requestId' });
      return;
    }

    if (status !== 'completed' && status !== 'failed' && status !== 'error') {
      // Intermediate status update (e.g. "generating")
      await setStatus(requestId, { status: status as ProofStatus['status'] });
      proofNs.to(`request:${requestId}`).emit('proof:status', { requestId, status });
      console.log(`[Relay Callback] Intermediate status update: ${requestId} -> ${status}`);
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
      nullifier,
      circuit,
      completedAt: new Date().toISOString(),
    };

    // Buffer result in Redis for reconnection
    await cacheSet(resultKey(requestId), JSON.stringify(proofResult), RESULT_TTL);

    // Update status
    await setStatus(requestId, { status: status as ProofStatus['status'], proof, publicInputs, error });

    // Emit via Socket.IO
    const room = `request:${requestId}`;
    const sockets = await proofNs.in(room).fetchSockets();
    console.log(`[Socket.IO] Emitting proof:result to room=${room}, sockets=${sockets.length}`);
    proofNs.to(room).emit('proof:result', proofResult);

    console.log(`[Relay] Proof result received: ${requestId} (status=${status})`);
    res.json({ received: true });
    console.log(`[Relay Callback] Successfully processed callback for ${requestId} (status=${status}, circuit=${circuit || 'unknown'})`);
  } catch (err: any) {
    console.error('[REST] Callback error:', err);
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
    try {
      const result = await processProofRequest(data);
      if (!result.ok) {
        socket.emit('proof:error', { error: result.error, code: result.code });
        return;
      }

      socket.join(`request:${result.requestId}`);

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
