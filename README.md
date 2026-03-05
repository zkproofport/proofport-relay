# proofport-relay

Express + Socket.IO relay server for real-time proof request sessions between dApps and the Proofport mobile app. The relay bridges web applications via the SDK and the mobile proof generator, managing proof request lifecycles with real-time status updates.

## Overview

Proofport Relay is the communication hub of the Proofport zero-knowledge proof infrastructure. It:

- Manages proof request sessions with unique request IDs
- Provides REST and WebSocket (Socket.IO) APIs for real-time bidirectional communication
- Authenticates requests via challenge-signature (EIP-191) instead of JWT
- Applies IP-based rate limiting to challenge and proof request endpoints
- Computes and stores SHA256 inputs hash for integrity verification
- Implements replay prevention via nonce tracking
- Generates deep links for mobile app invocation

## Architecture

```
+-----------------+          +------------------+          +------------------+
|  dApp SDK       |          |  Proofport Relay |          |  Proofport App   |
|  (Web/REST)     |<-------->|   Express +      |<-------->|   (Mobile)       |
|                 |          |   Socket.IO      |          |                  |
+-----------------+          +------------------+          +------------------+
                                     |
                                     v
                           +------------------+
                           |  Redis Cache     |
                           +------------------+
```

### Flow

1. **Challenge**: SDK requests a challenge via `GET /api/v1/challenge`
2. **Sign**: SDK signs the challenge with the user's wallet (EIP-191 personal_sign)
3. **Request**: SDK creates a proof request via `POST /api/v1/proof/request` or Socket.IO `proof:request` event, including `challenge` + `signature`
4. **Verify**: Relay recovers signer address via `ecrecover`, uses it as `clientId`
5. **Session**: Relay generates unique `requestId`, computes inputs hash, stores metadata
6. **Deep Link**: Relay generates a base64-encoded deep link (`zkproofport://proof-request?data=...`) for mobile app invocation
7. **Status**: Mobile app performs proof generation, posting intermediate and final status updates via `POST /api/v1/proof/callback`
8. **Delivery**: Relay broadcasts to connected clients via Socket.IO
9. **Polling**: Clients can poll `GET /api/v1/proof/:requestId` until completion (includes `inputsHash`)

## Quick Start

### Installation

```bash
npm install
```

### Development

```bash
npm run dev
```

Server runs on `http://0.0.0.0:4001` with hot reload via `tsx`.

### Production Build

```bash
npm run build
npm start
```

Compiled output is in `dist/`.

### Type Checking

```bash
npx tsc --noEmit
```

## Configuration

Environment variables (see `.env.example`):

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `4001` | Server port |
| `CORS_ORIGIN` | `*` | CORS allowed origins |
| `REDIS_URL` | (required) | Redis connection string |
| `RELAY_EXTERNAL_URL` | (required for production) | External relay URL for deep link callbacks |
| `NODE_ENV` | `development` | Environment mode |

## API Reference

### Authentication

**Challenge-Signature Authentication (EIP-191)** replaces JWT. The flow:

1. SDK calls `GET /api/v1/challenge` to obtain a random 32-byte hex challenge
2. SDK signs the challenge with the user's wallet via `personal_sign` (EIP-191)
3. SDK includes `challenge` and `signature` in the proof request body
4. Relay recovers the signer address via `ethers.verifyMessage()` and uses it as the client identity
5. Each challenge is single-use and expires after 2 minutes

### REST Endpoints

#### GET /api/v1/challenge
Request a random challenge for wallet signature authentication.

**Rate limit:** 30 requests per minute per IP.

**Response (200):**
```json
{
  "challenge": "0xa1b2c3d4e5f6...",
  "expiresAt": 1709654400000
}
```

#### POST /api/v1/proof/request
Create a new proof request session.

**Rate limit:** 10 requests per minute per IP.

**Request:**
```bash
curl -X POST http://relay:4001/api/v1/proof/request \
  -H "Content-Type: application/json" \
  -d '{
    "circuitId": "coinbase_attestation",
    "scope": "proofport:kyc",
    "inputs": {
      "account": "0x1234...",
      "signalHash": "0x5678...",
      "attesterRoot": "0x9abc..."
    },
    "nonce": "unique_idempotency_key",
    "challenge": "0xa1b2c3d4e5f6...",
    "signature": "0xdeadbeef..."
  }'
```

**Response (201):**
```json
{
  "requestId": "550e8400-e29b-41d4-a716-446655440000",
  "deepLink": "zkproofport://proof-request?data=eyJy...",
  "status": "pending",
  "pollUrl": "/api/v1/proof/550e8400-e29b-41d4-a716-446655440000"
}
```

**Status Codes:**
- `201`: Request created successfully
- `400`: Missing required fields or invalid inputs
- `401`: Missing or invalid challenge/signature
- `409`: Duplicate nonce (replay detected)
- `429`: Rate limit exceeded
- `500`: Internal server error

#### GET /api/v1/proof/:requestId
Poll proof request status.

**Response:**
```json
{
  "requestId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending",
  "deepLink": "zkproofport://proof-request?data=eyJy...",
  "inputsHash": "a1b2c3d4e5f6789...",
  "createdAt": "2025-02-01T10:00:00.000Z",
  "updatedAt": "2025-02-01T10:00:00.000Z"
}
```

After completion:
```json
{
  "requestId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "proof": "0x1234...",
  "publicInputs": ["0x5678...", "0x9abc..."],
  "inputsHash": "a1b2c3d4e5f6789...",
  "deepLink": "zkproofport://proof-request?data=eyJy...",
  "createdAt": "2025-02-01T10:00:00.000Z",
  "updatedAt": "2025-02-01T10:00:10.000Z"
}
```

**Status Codes:**
- `200`: Status retrieved
- `404`: Request not found or expired (TTL: 10 minutes)
- `500`: Internal server error

#### POST /api/v1/proof/callback
Receive proof completion callback from mobile app.

**Request (Intermediate Status):**
```json
{
  "requestId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "generating"
}
```

**Request (Final Status - Success):**
```json
{
  "requestId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "proof": "0x1234567890abcdef...",
  "publicInputs": ["0x5678...", "0x9abc..."]
}
```

**Request (Final Status - Failure):**
```json
{
  "requestId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "failed",
  "error": "Invalid inputs"
}
```

**Response:**
```json
{
  "received": true
}
```

**Status Codes:**
- `200`: Callback received
- `400`: Missing requestId or status
- `404`: Unknown or expired requestId
- `500`: Internal server error

**Behavior:**
- Intermediate statuses (`generating`, `verifying`) update status only
- Final statuses (`completed`, `failed`) store result and broadcast via Socket.IO
- Result buffered in Redis for 5 minutes (client reconnection tolerance)

#### GET /health
Health check endpoint.

**Response:**
```json
{
  "status": "ok",
  "service": "proofport-relay",
  "timestamp": "2025-02-01T10:00:00.000Z"
}
```

### WebSocket Events (Socket.IO /proof namespace)

**Connection (open, no auth middleware):**
```javascript
const socket = io('http://relay:4001', {
  path: '/socket.io',
  namespace: '/proof'
});
```

Socket.IO connections are open. Authentication happens per-request via challenge+signature in the `proof:request` event data.

#### Event: proof:request
Client initiates proof request (requires challenge+signature).

**Send:**
```javascript
socket.emit('proof:request', {
  circuitId: 'coinbase_attestation',
  scope: 'proofport:kyc',
  inputs: { account: '0x...', signalHash: '0x...' },
  nonce: 'unique_idempotency_key',
  challenge: '0xa1b2c3d4e5f6...',
  signature: '0xdeadbeef...'
});
```

**Receive (success):**
```javascript
socket.on('proof:status', (data) => {
  // { requestId: '550e8400-...', status: 'pending', deepLink: 'zkproofport://...' }
});
```

**Receive (error):**
```javascript
socket.on('proof:error', (data) => {
  // { error: 'Invalid or expired challenge', code: 401 }
});
```

#### Event: proof:subscribe
Subscribe to existing proof request (for reconnection).

**Send:**
```javascript
socket.emit('proof:subscribe', {
  requestId: '550e8400-e29b-41d4-a716-446655440000'
});
```

**Receive (if completed, buffered result):**
```javascript
socket.on('proof:result', (result) => {
  // { requestId, status: 'completed', proof, publicInputs, completedAt }
});
```

**Receive (if still pending):**
```javascript
socket.on('proof:status', (data) => {
  // { requestId, status: 'generating', deepLink }
});
```

**Receive (if expired):**
```javascript
socket.on('proof:error', (data) => {
  // { error: 'Request not found or expired', requestId }
});
```

#### Event: proof:status (Server -> Client)
Real-time status update for active request.

#### Event: proof:result (Server -> Client)
Final proof result broadcast.

## Rate Limiting

IP-based in-memory sliding window rate limiting:

| Endpoint | Limit | Window |
|----------|-------|--------|
| `GET /api/v1/challenge` | 30 requests | 1 minute per IP |
| `POST /api/v1/proof/request` | 10 requests | 1 minute per IP |

Exceeding limits returns HTTP 429.

## Storage

### Redis (Primary)

All session data cached in Redis with TTL:

| Key Pattern | TTL | Purpose |
|-------------|-----|---------|
| `proof:status:{requestId}` | 10 min | Current proof status |
| `proof:result:{requestId}` | 5 min | Proof result (for reconnection) |
| `proof:nonce:{nonce}` | 10 min | Nonce seen flag (replay prevention) |
| `proof:inputsHash:{requestId}` | 10 min | SHA256 hash of proof inputs |
| `challenge:{challenge}` | 2 min | Challenge for signature auth |

## Deep Link Format

Deep links encode the entire proof request as base64-encoded JSON:

```
zkproofport://proof-request?data=eyJyZXF1ZXN0SWQiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAi...
```

**Decoded:**
```json
{
  "requestId": "550e8400-e29b-41d4-a716-446655440000",
  "clientId": "0x1234567890abcdef...",
  "circuitId": "coinbase_attestation",
  "scope": "proofport:kyc",
  "inputs": { "account": "0x...", "signalHash": "0x..." },
  "callbackUrl": "http://relay:4001/api/v1/proof/callback",
  "createdAt": "2025-02-01T10:00:00.000Z"
}
```

Mobile app decodes and extracts fields for proof generation.

## Integration Guide

### Backend (dApp SDK)

**REST Example with Challenge-Signature Auth:**
```javascript
// Step 1: Get challenge
const challengeRes = await fetch('http://relay:4001/api/v1/challenge');
const { challenge, expiresAt } = await challengeRes.json();

// Step 2: Sign challenge with wallet (EIP-191)
const signature = await wallet.signMessage(challenge);

// Step 3: Create proof request
const response = await fetch('http://relay:4001/api/v1/proof/request', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    circuitId: 'coinbase_attestation',
    scope: 'proofport:kyc',
    inputs: {
      account: userAddress,
      signalHash: challengeHash,
      attesterRoot: merkleRoot
    },
    nonce: UUID(),
    challenge,
    signature
  })
});

const { requestId, deepLink, status, pollUrl } = await response.json();

// Step 4: Poll for result (includes inputsHash for integrity check)
const pollRes = await fetch(`http://relay:4001${pollUrl}`);
const result = await pollRes.json();
console.log('Inputs hash:', result.inputsHash);
```

**Socket.IO Example:**
```javascript
const socket = io('http://relay:4001', { namespace: '/proof' });

// Get challenge first
const { challenge } = await (await fetch('http://relay:4001/api/v1/challenge')).json();
const signature = await wallet.signMessage(challenge);

socket.on('connect', () => {
  socket.emit('proof:request', {
    circuitId: 'coinbase_attestation',
    scope: 'proofport:kyc',
    inputs: { account: userAddress, signalHash: challengeHash },
    nonce: UUID(),
    challenge,
    signature
  });
});

socket.on('proof:status', (data) => {
  console.log(`Status: ${data.status}, Deep link: ${data.deepLink}`);
});

socket.on('proof:result', (result) => {
  if (result.status === 'completed') {
    console.log(`Proof received: ${result.proof}`);
  } else {
    console.error(`Proof failed: ${result.error}`);
  }
});

socket.on('proof:error', (err) => {
  console.error(`Error: ${err.error} (code: ${err.code})`);
});
```

### Mobile App (Proof Generation)

Mobile app receives deep link and:

1. Decodes the proof request
2. Reads `circuitId`, `inputs`, and other parameters
3. Generates proof via mopro (Noir circuit execution)
4. Posts result to `POST /api/v1/proof/callback`:

```javascript
const result = {
  requestId: decodedLink.requestId,
  status: 'completed',
  proof: hexEncodedProof,
  publicInputs: [publicInput1, publicInput2]
};

await fetch('http://relay:4001/api/v1/proof/callback', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(result)
});
```

## Debugging

### Health Check

```bash
curl http://0.0.0.0:4001/health
```

### View Status

```bash
curl http://0.0.0.0:4001/api/v1/proof/{requestId}
```

### Logs

Development logs to stdout. Production should use structured logging (JSON).

**Log Prefixes:**
- `[Relay]` - Core request handling
- `[REST]` - HTTP endpoint errors
- `[Socket.IO]` - WebSocket events
- `[Redis]` - Redis connection state
- `[Relay Callback]` - Callback processing
- `[Relay Poll]` - Status polling

## Docker

**Build:**
```bash
docker build -t proofport-relay .
```

**Run:**
```bash
docker run -p 4001:4001 \
  -e REDIS_URL=redis://redis:6379 \
  proofport-relay
```

**Docker Compose:**
```yaml
services:
  relay:
    image: proofport-relay
    ports:
      - '4001:4001'
    environment:
      REDIS_URL: redis://redis:6379
    depends_on:
      - redis

  redis:
    image: redis:7-alpine
    ports:
      - '6379:6379'
```

## TypeScript Types

Key types exported from `src/types.ts`:

```typescript
interface ChallengeResponse {
  challenge: string;  // hex-encoded 32 random bytes
  expiresAt: number;  // unix timestamp ms
}

interface ProofRequest {
  requestId: string;
  clientId: string;
  circuitId: string;
  scope: string;
  inputs: Record<string, unknown>;
  inputsHash?: string;
  callbackUrl?: string;
  createdAt: string;
}

interface ProofStatus {
  requestId: string;
  status: 'pending' | 'generating' | 'completed' | 'failed' | 'error' | 'expired';
  proof?: string;
  publicInputs?: string[];
  error?: string;
  deepLink?: string;
  inputsHash?: string;
  createdAt: string;
  updatedAt: string;
}

interface ProofResult {
  requestId: string;
  status: 'completed' | 'failed' | 'error';
  proof?: string;
  publicInputs?: string[];
  error?: string;
  completedAt: string;
}
```

## Error Handling

**Common Errors:**

| Scenario | HTTP Status | Error Message |
|----------|-------------|---------------|
| Missing challenge/signature | 401 | `challenge and signature are required` |
| Invalid/expired challenge | 401 | `Invalid or expired challenge` |
| Invalid signature | 401 | `Invalid signature` |
| Missing circuitId | 400 | `circuitId is required` |
| Missing inputs | 400 | `inputs object is required` |
| Replay detected | 409 | `Duplicate nonce (replay detected)` |
| Request expired | 404 | `Request not found or expired` |
| Rate limit exceeded | 429 | `Too many requests. Please try again later.` |

## Performance

**Throughput:**
- REST: 100+ requests/second per instance (Redis-backed)
- Socket.IO: 500+ concurrent connections per instance

**Latency:**
- Challenge generation: <10ms
- Request creation: <50ms (Redis)
- Status polling: <20ms (cached)

**Resource Usage (per instance):**
- CPU: 1-2 cores typical, 4 cores recommended
- Memory: 100-200 MB baseline, +1MB per 1000 concurrent connections
- Redis: <100MB for typical workload (auto-expiring TTL)

## Development

**File Structure:**
```
src/
+-- index.ts      # Express server, REST endpoints, Socket.IO handlers
+-- types.ts      # TypeScript interfaces
+-- redis.ts      # Redis wrapper
```

**Scripts:**
- `npm run dev` - Development with hot reload
- `npm run build` - Compile TypeScript
- `npm start` - Production server
- `npx tsc --noEmit` - Type checking

## License

MIT
