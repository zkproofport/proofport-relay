import express, { Request, Response } from 'express';
import { createServer } from 'http';
import { Server, Socket } from 'socket.io';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import { v4 as uuidv4 } from 'uuid';
import jwt from 'jsonwebtoken';
import { initRedis, cacheSet, cacheGet, cacheSetNX } from './redis';
import type { PlanInfo, ProofRequest, ProofResult, ProofStatus, Tier } from './types';
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
if ((nodeEnv === 'production' || nodeEnv === 'staging') && !process.env.API_URL) {
  throw new Error('API_URL environment variable is required in production/staging');
}
const BACKEND_URL = process.env.API_URL || 'http://localhost:4000';
if (!process.env.INTERNAL_API_KEY) throw new Error('INTERNAL_API_KEY environment variable is required');
const INTERNAL_KEY: string = process.env.INTERNAL_API_KEY;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error('JWT_SECRET environment variable is required');

const FREE_SCOPE = 'proofport:default:noop';
const RESULT_TTL = 300; // 5 minutes
const STATUS_TTL = 600; // 10 minutes
const NONCE_TTL = 600;  // 10 minutes (replay prevention)
if ((nodeEnv === 'production' || nodeEnv === 'staging') && !process.env.RELAY_EXTERNAL_URL) {
  throw new Error('RELAY_EXTERNAL_URL environment variable is required in production/staging');
}
const RELAY_EXTERNAL_URL = process.env.RELAY_EXTERNAL_URL || '';

// On-chain nullifier registration (Plan 2)
const RELAY_PRIVATE_KEY = process.env.RELAY_PRIVATE_KEY || '';
const NULLIFIER_REGISTRY_ADDRESS = process.env.NULLIFIER_REGISTRY_ADDRESS || '';
const CHAIN_RPC_URL = process.env.CHAIN_RPC_URL;
if (!CHAIN_RPC_URL) throw new Error('CHAIN_RPC_URL environment variable is required');

const NULLIFIER_REGISTRY_ABI = [
  'function verifyAndRegister(bytes32 _circuitId, bytes calldata _proof, bytes32[] calldata _publicInputs) external returns (uint8 status, bytes32 nullifier, bytes32 scope)',
  'function isNullifierRegistered(bytes32 _nullifier) external view returns (bool)',
  'function getNullifierInfo(bytes32 _nullifier) external view returns (uint64 registeredAt, bytes32 scope, bytes32 circuitId)',
];

const VERIFY_STATUS_NAMES: Record<number, string> = {
  0: 'verified_and_registered',
  1: 'already_registered',
  2: 'expired_and_reregistered',
  3: 'verification_failed',
  4: 'circuit_not_found',
};

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
// JWT verification
// ---------------------------------------------------------------------------
interface ClientJwtPayload {
  sub: string;      // clientId
  type: 'client';
  dappId: string;
  customerId: string;
  tier: string;
}

function verifyClientToken(token: string): ClientJwtPayload | null {
  try {
    const decoded = jwt.verify(token, JWT_SECRET as string) as unknown as ClientJwtPayload;
    if (decoded.type !== 'client') return null;
    return decoded;
  } catch (err) {
    return null;
  }
}

function extractBearerToken(req: Request): string | null {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return null;
  return auth.slice(7);
}

// ---------------------------------------------------------------------------
// Backend API client
// ---------------------------------------------------------------------------
async function getPlan(clientId: string): Promise<PlanInfo> {
  const res = await fetch(`${BACKEND_URL}/internal/plan/${clientId}`, {
    headers: { 'x-internal-key': INTERNAL_KEY },
  });
  if (!res.ok) throw new Error(`Plan lookup failed (${res.status})`);
  return res.json() as Promise<PlanInfo>;
}

async function deductCredit(clientId: string, creditType: 'free' | 'paid' | 'auto' = 'auto', referenceId?: string): Promise<boolean> {
  try {
    const res = await fetch(`${BACKEND_URL}/internal/credits/deduct`, {
      method: 'POST',
      headers: {
        'x-internal-key': INTERNAL_KEY,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ clientId, amount: 1, creditType, referenceId }),
    });
    return res.ok;
  } catch (err) {
    console.error('[Backend] Credit deduction failed:', err);
    return false;
  }
}

async function logUsage(
  clientId: string,
  circuit: string,
  requestId: string,
  creditType?: string,
  status = 'success',
  onChainData?: { nullifier?: string; txHash?: string; onChainStatus?: string }
): Promise<void> {
  try {
    await fetch(`${BACKEND_URL}/internal/usage`, {
      method: 'POST',
      headers: {
        'x-internal-key': INTERNAL_KEY,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ clientId, circuit, requestId, creditsUsed: 1, status, creditType, ...onChainData }),
    });
  } catch (err) {
    console.error('[Backend] Usage logging failed:', err);
  }
}

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
function tierKey(requestId: string) {
  return `proof:tier:${requestId}`;
}
function clientKey(requestId: string) {
  return `proof:client:${requestId}`;
}
function circuitKey(requestId: string) {
  return `proof:circuit:${requestId}`;
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
// Nullifier extraction from public inputs (mirrors SDK verifier.ts)
// ---------------------------------------------------------------------------
function extractBytes32FromFields(publicInputs: string[], startIndex: number): string {
  if (publicInputs.length <= startIndex + 31) return '0x' + '00'.repeat(32);
  const fields = publicInputs.slice(startIndex, startIndex + 32);
  const bytes = fields.map(f => {
    const byte = BigInt(f) & 0xFFn;
    return byte.toString(16).padStart(2, '0');
  }).join('');
  return '0x' + bytes;
}

function extractNullifierFromPublicInputs(publicInputs: string[], circuit?: string): string {
  const start = circuit === 'coinbase_country_attestation' ? 118 : 96;
  return extractBytes32FromFields(publicInputs, start);
}

function extractScopeFromPublicInputs(publicInputs: string[], circuit?: string): string {
  const start = circuit === 'coinbase_country_attestation' ? 86 : 64;
  return extractBytes32FromFields(publicInputs, start);
}

// ---------------------------------------------------------------------------
// On-chain nullifier registration (Plan 2)
// ---------------------------------------------------------------------------
async function registerNullifierOnChain(
  circuitId: string,
  proof: string,
  publicInputs: string[]
): Promise<{
  status: string;
  nullifier: string;
  scope: string;
  txHash?: string;
  error?: string;
}> {
  if (!RELAY_PRIVATE_KEY || !NULLIFIER_REGISTRY_ADDRESS) {
    return { status: 'failed', nullifier: '', scope: '', error: 'Relay signer or registry not configured' };
  }

  try {
    const provider = new ethers.JsonRpcProvider(CHAIN_RPC_URL);
    const signer = new ethers.Wallet(RELAY_PRIVATE_KEY, provider);
    const registry = new ethers.Contract(NULLIFIER_REGISTRY_ADDRESS, NULLIFIER_REGISTRY_ABI, signer);

    // Convert circuitId string to bytes32
    const circuitIdBytes = ethers.encodeBytes32String(circuitId.length <= 31 ? circuitId : '');
    // If circuitId is already hex, use it directly
    const circuitIdHex = circuitId.startsWith('0x') ? circuitId : circuitIdBytes;

    // Ensure proof has 0x prefix
    const proofHex = proof.startsWith('0x') ? proof : '0x' + proof;

    // Ensure public inputs are bytes32
    const publicInputsHex = publicInputs.map(input => {
      const hex = input.startsWith('0x') ? input : '0x' + input;
      return ethers.zeroPadValue(hex, 32);
    });

    // First, use staticCall to get return values without sending transaction
    const [statusCode, nullifierBytes, scopeBytes] = await registry.verifyAndRegister.staticCall(
      circuitIdHex,
      proofHex,
      publicInputsHex
    );
    const statusNum = Number(statusCode);
    const statusName = VERIFY_STATUS_NAMES[statusNum] || 'unknown';

    // Convert bytes32 return values to hex strings
    const nullifier = nullifierBytes as string;
    const scope = scopeBytes as string;

    // Check status and decide whether to send actual transaction
    if (statusNum === 1) {
      // ALREADY_REGISTERED - no transaction needed
      return {
        status: statusName,
        nullifier,
        scope,
      };
    } else if (statusNum === 3) {
      // VERIFICATION_FAILED
      return {
        status: statusName,
        nullifier,
        scope,
        error: 'Proof verification failed',
      };
    } else if (statusNum === 4) {
      // CIRCUIT_NOT_FOUND
      return {
        status: statusName,
        nullifier,
        scope,
        error: 'Circuit not found in registry',
      };
    } else if (statusNum === 0 || statusNum === 2) {
      // VERIFIED_AND_REGISTERED or EXPIRED_AND_REREGISTERED - send actual transaction
      // Noir proof verification is gas-intensive; set explicit high gas limit
      const tx = await registry.verifyAndRegister(circuitIdHex, proofHex, publicInputsHex, { gasLimit: 10_000_000 });
      const receipt = await tx.wait();

      return {
        status: statusName,
        nullifier,
        scope,
        txHash: receipt.hash,
      };
    } else {
      // Unknown status
      return {
        status: statusName,
        nullifier,
        scope,
        error: `Unknown status code: ${statusNum}`,
      };
    }
  } catch (err: any) {
    console.error('[Relay] On-chain registration failed:', err.message);

    // Try to extract nullifier/scope for error response
    const nullifier = extractNullifierFromPublicInputs(publicInputs, circuitId);
    const scope = extractScopeFromPublicInputs(publicInputs, circuitId);

    return {
      status: 'failed',
      nullifier,
      scope,
      error: err.message,
    };
  }
}

// ---------------------------------------------------------------------------
// Core proof request processing
// ---------------------------------------------------------------------------
async function processProofRequest(body: {
  clientId?: string;
  circuitId?: string;
  scope?: string;
  inputs?: Record<string, unknown>;
  nonce?: string;
}, relayBaseUrl?: string): Promise<{ ok: true; requestId: string; deepLink: string; status: ProofStatus } | { ok: false; error: string; code: number }> {
  const { clientId, circuitId, scope, inputs, nonce } = body;

  console.log(`[Relay] processProofRequest: clientId=${clientId}, circuitId=${circuitId}, scope=${scope || 'none'}, inputKeys=${inputs ? Object.keys(inputs).join(',') : 'none'}, nonce=${nonce || 'none'}`);

  // Validate required fields
  if (!clientId || typeof clientId !== 'string') {
    console.log('[Relay] Rejected: clientId is required');
    return { ok: false, error: 'clientId is required', code: 400 };
  }
  if (!circuitId || typeof circuitId !== 'string') {
    console.log('[Relay] Rejected: circuitId is required');
    return { ok: false, error: 'circuitId is required', code: 400 };
  }
  if (!inputs || typeof inputs !== 'object') {
    console.log('[Relay] Rejected: inputs object is required');
    return { ok: false, error: 'inputs object is required', code: 400 };
  }

  // Replay prevention via nonce
  if (nonce) {
    const seen = await cacheGet(nonceKey(nonce));
    if (seen) {
      console.log(`[Relay] Rejected: duplicate nonce ${nonce}`);
      return { ok: false, error: 'Duplicate nonce (replay detected)', code: 409 };
    }
    await cacheSet(nonceKey(nonce), '1', NONCE_TTL);
  }

  // Validate client and get plan
  let plan: PlanInfo;
  try {
    plan = await getPlan(clientId);
  } catch (err: any) {
    console.error('[Relay] Plan lookup failed:', err.message);
    return { ok: false, error: 'Invalid or unknown clientId', code: 403 };
  }

  const tier: Tier = plan.tier || 'free';

  // Free tier: check credits and deduct immediately (success or failure)
  if (tier === 'free') {
    const totalCredits = (plan.freeCredits ?? 0) + (plan.paidCredits ?? 0);
    if (totalCredits <= 0) {
      console.log(`[Relay] Rejected: insufficient credits for ${clientId}`);
      return { ok: false, error: 'Insufficient credits. Purchase more at the dashboard.', code: 402 };
    }
  }

  // Credit tier: check balance (deduction happens on completion)
  if (tier === 'credit') {
    const totalCredits = (plan.freeCredits ?? 0) + (plan.paidCredits ?? 0);
    if (totalCredits <= 0) {
      console.log(`[Relay] Rejected: insufficient credits for ${clientId} (credit tier)`);
      return { ok: false, error: 'Insufficient credits', code: 402 };
    }
  }


  // Scope injection: free tier gets noop scope
  const effectiveScope = tier === 'free' ? FREE_SCOPE : (scope || FREE_SCOPE);

  const requestId = uuidv4();
  const now = new Date().toISOString();

  // Deep link callbackUrl always points to the relay so the app sends results here.
  const relayCallbackUrl = `${RELAY_EXTERNAL_URL || relayBaseUrl || `http://localhost:${PORT}`}/api/v1/proof/callback`;

  const proofRequest: ProofRequest = {
    requestId,
    clientId,
    circuitId,
    scope: effectiveScope,
    inputs,
    callbackUrl: relayCallbackUrl,
    createdAt: now,
  };

  // Store metadata for credit deduction
  await cacheSet(tierKey(requestId), tier, STATUS_TTL);
  await cacheSet(clientKey(requestId), clientId, STATUS_TTL);
  await cacheSet(circuitKey(requestId), circuitId, STATUS_TTL);

  // Set initial status
  const status: ProofStatus = {
    requestId,
    status: 'pending',
    deepLink: buildDeepLink(proofRequest),
    createdAt: now,
    updatedAt: now,
  };
  await cacheSet(statusKey(requestId), JSON.stringify(status), STATUS_TTL);

  // Emit to Socket.IO room for any listeners
  proofNs.to(`request:${requestId}`).emit('proof:status', { requestId, status: 'pending' });

  console.log(`[Relay] Proof request created: ${requestId} (tier=${tier}, circuit=${circuitId})`);
  console.log(`[Relay] Deep link callbackUrl: ${relayCallbackUrl}`);
  console.log(`[Relay] Deep link data keys: ${Object.keys(proofRequest).join(', ')}`);

  // Free tier: deduct 1 credit immediately at request time
  if (tier === 'free') {
    const ok = await deductCredit(clientId, 'auto', requestId);
    if (!ok) {
      console.warn(`[Relay] Free tier credit deduction failed for ${clientId}, request ${requestId}`);
    }
    logUsage(clientId, circuitId, requestId, 'free', 'requested');
  }

  return { ok: true, requestId, deepLink: status.deepLink!, status };
}

// ---------------------------------------------------------------------------
// REST: POST /api/v1/proof/request
// ---------------------------------------------------------------------------
app.post('/api/v1/proof/request', async (req: Request, res: Response) => {
  try {
    const bearerToken = extractBearerToken(req);
    if (!bearerToken) {
      console.log('[REST] No Authorization header — JWT required');
      res.status(401).json({ error: 'Authorization header with Bearer token is required' });
      return;
    }

    const payload = verifyClientToken(bearerToken);
    if (!payload) {
      console.log('[REST] JWT verification failed');
      res.status(401).json({ error: 'Invalid or expired token' });
      return;
    }

    const clientId = payload.sub;
    console.log(`[REST] JWT authenticated: clientId=${clientId}, dappId=${payload.dappId}, tier=${payload.tier}`);

    const relayBaseUrl = `${req.protocol}://${req.get('host')}`;
    const result = await processProofRequest({ ...req.body, clientId }, relayBaseUrl);
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

    // Check if plan2 needs on-chain registration first
    const tierForOnChain = await cacheGet(tierKey(requestId));
    const circuitForOnChain = await cacheGet(circuitKey(requestId));
    const needsOnChain = tierForOnChain === 'plan2' && !!circuitForOnChain && status === 'completed' && !!proof && !!publicInputs;

    // Update status — for plan2, delay 'completed' until after on-chain registration
    if (needsOnChain) {
      await setStatus(requestId, { status: 'generating' as ProofStatus['status'] });
    } else {
      await setStatus(requestId, { status, proof, publicInputs, error });
    }

    // Credit deduction on completion (logging deferred until after nullifier extraction)
    if (status === 'completed') {
      const tier = await cacheGet(tierKey(requestId));
      const cid = await cacheGet(clientKey(requestId));
      if (cid && tier === 'credit') {
        const ok = await deductCredit(cid, 'paid', requestId);
        if (!ok) {
          console.warn(`[Relay] Paid credit deduction failed for client ${cid}, request ${requestId}`);
        }
      }
    } else if (status === 'failed') {
      const tier = await cacheGet(tierKey(requestId));
      const cid = await cacheGet(clientKey(requestId));
      const circuit = await cacheGet(circuitKey(requestId));
      if (cid) {
        const creditType = tier === 'credit' ? 'paid' : (tier || 'free');
        logUsage(cid, circuit || '', requestId, creditType, 'failed');
      }
    }

    // Extract nullifier/scope for paid tiers
    let nullifierInfo: { nullifier?: string; scope?: string; onChainStatus?: string; txHash?: string } = {};
    if (status === 'completed' && proof && publicInputs) {
      const circuit = await cacheGet(circuitKey(requestId));
      if (circuit) {
        nullifierInfo.nullifier = extractNullifierFromPublicInputs(publicInputs, circuit);
        nullifierInfo.scope = extractScopeFromPublicInputs(publicInputs, circuit);
      }

      // Plan 2: Auto on-chain registration (with lock to prevent duplicates)
      const tier = await cacheGet(tierKey(requestId));
      if (tier === 'plan2' && circuit) {
        const lockKey = `onchain:lock:${requestId}`;
        const acquired = await cacheSetNX(lockKey, '1', 300);
        if (!acquired) {
          console.log(`[Relay] Plan 2: On-chain registration already in progress for ${requestId}, skipping`);
          await setStatus(requestId, { status: 'completed' as ProofStatus['status'] });
        } else {
          console.log(`[Relay] Plan 2: Registering nullifier on-chain for ${requestId}`);
          const onChainResult = await registerNullifierOnChain(circuit, proof, publicInputs);
          nullifierInfo.onChainStatus = onChainResult.status;
          nullifierInfo.txHash = onChainResult.txHash;
          if (onChainResult.error) {
            console.warn(`[Relay] On-chain registration: ${onChainResult.status} - ${onChainResult.error}`);
          } else {
            console.log(`[Relay] On-chain registration: ${onChainResult.status} txHash=${onChainResult.txHash}`);
          }

          // Set completed with on-chain result atomically (was 'generating' until now)
          await setStatus(requestId, {
            status: 'completed' as ProofStatus['status'],
            onChainStatus: onChainResult.status,
            txHash: onChainResult.txHash,
            nullifier: nullifierInfo.nullifier,
          });

          // Log plan2 usage with on-chain data
          const cidForLog = await cacheGet(clientKey(requestId));
          if (cidForLog) {
            logUsage(cidForLog, circuit, requestId, 'plan2', 'completed', {
              nullifier: nullifierInfo.nullifier,
              txHash: nullifierInfo.txHash,
              onChainStatus: nullifierInfo.onChainStatus,
            });
          }
        }
      }

      // Log completed usage for non-plan2 tiers (with nullifier)
      if (tier !== 'plan2') {
        const cid = await cacheGet(clientKey(requestId));
        if (cid) {
          const creditType = tier === 'credit' ? 'paid' : (tier || 'free');
          logUsage(cid, circuit || '', requestId, creditType, 'completed', {
            nullifier: nullifierInfo.nullifier,
          });
        }
      }
    }

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
// REST: GET /api/v1/nullifier/:hash (Plan 2 nullifier query)
// ---------------------------------------------------------------------------
app.get('/api/v1/nullifier/:hash', async (req: Request, res: Response) => {
  try {
    const hash = req.params.hash as string;
    console.log(`[Relay] GET /api/v1/nullifier/${hash} from IP: ${req.ip}`);
    if (!hash || !hash.startsWith('0x')) {
      res.status(400).json({ error: 'Invalid nullifier hash (must start with 0x)' });
      return;
    }

    if (!NULLIFIER_REGISTRY_ADDRESS) {
      res.status(503).json({ error: 'Nullifier registry not configured' });
      return;
    }

    const provider = new ethers.JsonRpcProvider(CHAIN_RPC_URL);
    const registry = new ethers.Contract(NULLIFIER_REGISTRY_ADDRESS, NULLIFIER_REGISTRY_ABI, provider);

    const [registeredAt, scope, circuitId] = await registry.getNullifierInfo(hash);
    const registered = BigInt(registeredAt) > 0n;

    console.log(`[Relay] Nullifier ${hash}: registered=${registered}`);
    res.json({
      registered,
      registeredAt: registered ? Number(registeredAt) : null,
      scope: registered ? scope : null,
      circuitId: registered ? circuitId : null,
    });
  } catch (err: any) {
    console.error('[REST] Nullifier query error:', err);
    res.status(500).json({ error: 'Failed to query nullifier registry' });
  }
});

// ---------------------------------------------------------------------------
// REST: POST /api/v1/auth/token (proxy to backend API)
// ---------------------------------------------------------------------------
app.post('/api/v1/auth/token', async (req: Request, res: Response) => {
  try {
    const { client_id, api_key } = req.body as { client_id?: string; api_key?: string };

    if (!client_id || !api_key) {
      res.status(400).json({ error: 'client_id and api_key are required' });
      return;
    }

    console.log(`[Relay Auth] Token request for client_id=${client_id}`);

    const response = await fetch(`${BACKEND_URL}/api/auth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id, api_key }),
    });

    const data = await response.json() as any;

    if (!response.ok) {
      console.log(`[Relay Auth] Backend rejected: ${response.status} ${data.error || ''}`);
      res.status(response.status).json(data);
      return;
    }

    console.log(`[Relay Auth] Token issued for client_id=${client_id}`);
    res.json(data);
  } catch (err: any) {
    console.error('[Relay Auth] Proxy error:', err.message);
    res.status(502).json({ error: 'Authentication service unavailable' });
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
// Socket.IO /proof namespace
// ---------------------------------------------------------------------------

// Auth middleware: validate JWT token
proofNs.use(async (socket: Socket, next) => {
  const token = socket.handshake.auth?.token as string | undefined;

  if (!token) {
    console.warn(`[Socket.IO] Connection rejected: no JWT token (socket=${socket.id})`);
    return next(new Error('Authentication error: JWT token required'));
  }

  const payload = verifyClientToken(token);
  if (!payload) {
    console.warn(`[Socket.IO] Connection rejected: invalid/expired JWT (socket=${socket.id})`);
    return next(new Error('Authentication error: invalid or expired token'));
  }

  const clientId = payload.sub;
  console.log(`[Socket.IO] JWT authenticated: clientId=${clientId}, dappId=${payload.dappId}`);

  try {
    const plan = await getPlan(clientId);
    // Attach plan to socket data for later use
    (socket as any).plan = plan;
    (socket as any).clientId = clientId;
    next();
  } catch (err: any) {
    console.error('[Socket.IO] Auth failed:', err.message);
    return next(new Error('Authentication error: invalid clientId'));
  }
});

proofNs.on('connection', (socket: Socket) => {
  const clientId = (socket as any).clientId as string;
  const plan = (socket as any).plan as PlanInfo;
  console.log(`[Socket.IO] Client connected: ${socket.id} (client=${clientId}, tier=${plan.tier})`);

  // Handle proof request from dApp SDK
  socket.on('proof:request', async (data: {
    circuitId?: string;
    scope?: string;
    inputs?: Record<string, unknown>;
    nonce?: string;
  }) => {
    try {
      const result = await processProofRequest({
        clientId,
        ...data,
      });

      if (!result.ok) {
        socket.emit('proof:error', { error: result.error, code: result.code });
        return;
      }

      // Join the request room for status updates
      socket.join(`request:${result.requestId}`);

      // Send back the request acknowledgment
      socket.emit('proof:status', {
        requestId: result.requestId,
        status: 'pending',
        deepLink: result.deepLink,
      });

      console.log(`[Socket.IO] Proof request from ${clientId}: ${result.requestId}`);
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
