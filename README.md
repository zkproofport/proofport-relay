# proofport-relay

Express + Socket.IO relay server for real-time proof request sessions between dApps and the Proofport mobile app. The relay bridges web applications via the SDK and the mobile proof generator, managing proof request lifecycles with real-time status updates.

## Overview

Proofport Relay is the communication hub of the Proofport zero-knowledge proof infrastructure. It:

- Manages proof request sessions with unique request IDs
- Provides REST and WebSocket (Socket.IO) APIs for real-time bidirectional communication
- Handles tier-based rate limiting and credit deduction
- Supports callback webhooks for proof delivery
- Implements replay prevention via nonce tracking
- Falls back to in-memory storage when Redis is unavailable
- Generates deep links for mobile app invocation

## Architecture

```
┌─────────────────┐          ┌──────────────────┐          ┌──────────────────┐
│  dApp SDK       │          │  Proofport Relay │          │  Proofport App   │
│  (Web/REST)     │◄────────►│   Express +      │◄────────►│   (Mobile)       │
│                 │          │   Socket.IO      │          │                  │
└─────────────────┘          └──────────────────┘          └──────────────────┘
                                     │
                                     ▼
                           ┌──────────────────┐
                           │  Redis Cache     │
                           │  (w/ fallback)   │
                           └──────────────────┘
```

### Flow

1. **Request**: dApp SDK creates a proof request via `POST /api/v1/proof/request` or Socket.IO `proof:request` event
2. **Session**: Relay generates unique `requestId` and stores metadata (clientId, tier, callbackUrl)
3. **Deep Link**: Relay generates a base64-encoded deep link (`zkproofport://proof-request?data=...`) for mobile app invocation
4. **Status**: Mobile app performs proof generation, posting intermediate and final status updates via `POST /api/v1/proof/callback`
5. **Delivery**: Relay broadcasts to connected clients via Socket.IO and retries webhook callbacks
6. **Polling**: Clients can poll `GET /api/v1/proof/:requestId` until completion

## Quick Start

### Installation

```bash
npm install
```

### Development

```bash
npm run dev
```

Server runs on `http://0.0.0.0:3100` with hot reload via `tsx`.

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
| `PORT` | `3100` | Server port |
| `CORS_ORIGIN` | `*` | CORS allowed origins |
| `REDIS_URL` | `redis://172.28.0.21:6379` | Redis connection string |
| `BACKEND_API_URL` | `http://172.28.0.11:3200` | Backend API for plan/credit validation |
| `BACKEND_API_KEY` | `dev-internal-api-key` | API key for backend authentication |
| `JWT_SECRET` | (required) | JWT secret for token verification (REQUIRED for authentication) |
| `NODE_ENV` | `development` | Environment mode |

## API Reference

### Authentication

**JWT Token Authentication is REQUIRED.** All requests must include `Authorization: Bearer <token>` header with a valid JWT token from the API server. The token payload must contain `{ sub: clientId, type: 'client', dappId, customerId, tier }`. The `clientId` is extracted from the token's `sub` field.

**Important:** The `clientId` field in the request body (REST) or connection auth (Socket.IO) is ignored. Client identity is always determined from the JWT token.

### REST Endpoints

#### POST /api/v1/proof/request
Create a new proof request session.

**Request (with JWT token):**
```bash
curl -X POST http://relay:4001/api/v1/proof/request \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{
    "circuitId": "coinbase_attestation",
    "scope": "proofport:kyc",
    "inputs": {
      "account": "0x1234...",
      "signalHash": "0x5678...",
      "attesterRoot": "0x9abc..."
    },
    "callbackUrl": "https://myapp.com/webhook/proof",
    "nonce": "unique_idempotency_key"
  }'
```

**Note:** The `clientId` field in the request body is optional and ignored. Client identity is always extracted from the JWT token's `sub` field.

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
- `401`: Invalid or expired JWT token
- `402`: Insufficient credits (credit tier)
- `403`: Invalid or unknown clientId
- `409`: Duplicate nonce (replay detected)
- `500`: Internal server error

**Notes:**
- Free tier clients must provide `callbackUrl`
- Credit tier clients checked for available credits
- Nonce prevents duplicate requests (optional but recommended)
- Default scope is `proofport:default:noop` for free tier

#### GET /api/v1/proof/:requestId
Poll proof request status.

**Response:**
```json
{
  "requestId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending",
  "deepLink": "zkproofport://proof-request?data=eyJy...",
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
  "deepLink": "zkproofport://proof-request?data=eyJy...",
  "createdAt": "2025-02-01T10:00:00.000Z",
  "updatedAt": "2025-02-01T10:00:10.000Z"
}
```

**Status Codes:**
- `200`: Status retrieved
- `404`: Request not found or expired (TTL: 10 minutes)
- `500`: Internal server error

**Polling Intervals:**
- Free tier: 2-3 seconds (backend rate limit)
- Credit/Unlimited: 1-2 seconds

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
- `500`: Internal server error

**Behavior:**
- Intermediate statuses (`generating`, `verifying`) update status only
- Final statuses (`completed`, `failed`) trigger credit deduction, webhook delivery, and Socket.IO broadcast
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

**Connection (with JWT token):**
```javascript
const socket = io('http://relay:4001', {
  path: '/socket.io',
  namespace: '/proof',
  auth: {
    token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
  }
});
```

**Authentication:**
- Clients MUST provide `token` (JWT) in connection auth
- JWT token is verified; `clientId` is extracted from token's `sub` field
- Free tier clients cannot use Socket.IO (REST only)
- Invalid or missing token rejects connection

#### Event: proof:request
Client initiates proof request.

**Send:**
```javascript
socket.emit('proof:request', {
  circuitId: 'coinbase_attestation',
  scope: 'proofport:kyc',
  inputs: { account: '0x...', signalHash: '0x...' },
  callbackUrl: 'https://myapp.com/webhook/proof',
  nonce: 'unique_idempotency_key'
});
```

**Receive (success):**
```javascript
socket.on('proof:status', (data) => {
  console.log(data);
  // {
  //   requestId: '550e8400-...',
  //   status: 'pending',
  //   deepLink: 'zkproofport://...'
  // }
});
```

**Receive (error):**
```javascript
socket.on('proof:error', (data) => {
  console.error(data);
  // { error: 'Insufficient credits', code: 402 }
});
```

**Notes:**
- Client automatically joins room `request:{requestId}` after creation
- Room used for all subsequent status updates

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
  console.log(result);
  // {
  //   requestId: '550e8400-...',
  //   status: 'completed',
  //   proof: '0x1234...',
  //   publicInputs: ['0x5678...'],
  //   completedAt: '2025-02-01T10:00:10.000Z'
  // }
});
```

**Receive (if still pending):**
```javascript
socket.on('proof:status', (data) => {
  console.log(data);
  // { requestId: '550e8400-...', status: 'generating', deepLink: '...' }
});
```

**Receive (if expired):**
```javascript
socket.on('proof:error', (data) => {
  console.error(data);
  // { error: 'Request not found or expired', requestId: '550e8400-...' }
});
```

#### Event: proof:status (Server -> Client)
Real-time status update for active request.

**Broadcast (intermediate):**
```javascript
socket.on('proof:status', (data) => {
  // { requestId: '550e8400-...', status: 'verifying' }
});
```

**Broadcast (completion):**
```javascript
socket.on('proof:result', (result) => {
  // {
  //   requestId: '550e8400-...',
  //   status: 'completed',
  //   proof: '0x1234...',
  //   publicInputs: [...],
  //   completedAt: '2025-02-01T10:00:10.000Z'
  // }
});
```

## Tier System

| Tier | Rate Limit | Session TTL | Credit Deduction | Scope Control | Callback |
|------|-----------|-------------|------------------|---------------|----------|
| `free` | Backend enforced | 10 min | None | Forced `proofport:default:noop` | Required |
| `credit` | 100 req/min | 10 min | 1 per completion | User-provided | Optional |
| `unlimited` | Unlimited | 10 min | None | User-provided | Optional |

**Tier Behavior:**

- **Free**: Must provide `callbackUrl` (Socket.IO denied). Cannot use custom scope. No credits deducted.
- **Credit**: Can use Socket.IO and REST. Uses custom scope. 1 credit deducted on successful proof completion.
- **Unlimited**: Can use Socket.IO and REST. Uses custom scope. No credit deduction.

**Client Plan Validation:**
Relay calls backend `GET /internal/plan/{clientId}` to validate tier and check credit balance.

## Storage

### Redis (Primary)

All session data cached in Redis with TTL:

| Key Pattern | TTL | Purpose |
|-------------|-----|---------|
| `proof:status:{requestId}` | 10 min | Current proof status |
| `proof:result:{requestId}` | 5 min | Proof result (for reconnection) |
| `proof:callback:{requestId}` | 10 min | Callback URL |
| `proof:tier:{requestId}` | 10 min | Client tier (for credit deduction) |
| `proof:client:{requestId}` | 10 min | ClientId (for credit deduction) |
| `proof:nonce:{nonce}` | 10 min | Nonce seen flag (replay prevention) |

### In-Memory Fallback

If Redis unavailable:
- Uses JavaScript `Map` for session data
- Automatic expiration via TTL tracking
- Full feature parity with Redis
- No data persistence (resets on restart)

## Webhook Callback Delivery

Relay sends proof results to registered `callbackUrl` with automatic retries.

**Payload:**
```json
{
  "requestId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "proof": "0x1234...",
  "publicInputs": ["0x5678...", "0x9abc..."],
  "error": null
}
```

**Retry Strategy:**
- Maximum 3 attempts
- Exponential backoff: 1s, 2s, 4s (500ms base)
- 10-second timeout per request
- Fire-and-forget (no error on final failure)

**Errors:**
Failed callback attempts logged but don't block proof completion. Client can always poll `GET /api/v1/proof/:requestId`.

## Deep Link Format

Deep links encode the entire proof request as base64-encoded JSON:

```
zkproofport://proof-request?data=eyJyZXF1ZXN0SWQiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJjbGllbnRJZCI6ImNsaWVudF8xMjMiLCJjaXJjdWl0SWQiOiJjb2luYmFzZV9hdHRlc3RhdGlvbiIsInNjb3BlIjoicHJvb2Zwb3J0Omtv...
```

**Decoded:**
```json
{
  "requestId": "550e8400-e29b-41d4-a716-446655440000",
  "clientId": "client_123",
  "circuitId": "coinbase_attestation",
  "scope": "proofport:kyc",
  "inputs": { "account": "0x...", "signalHash": "0x..." },
  "callbackUrl": "https://myapp.com/webhook/proof",
  "createdAt": "2025-02-01T10:00:00.000Z"
}
```

Mobile app decodes and extracts fields for proof generation.

## Integration Guide

### Backend (dApp SDK)

**REST Example with JWT Token (Recommended):**
```javascript
// First, obtain JWT token from API server
const authResponse = await fetch('http://api:4000/api/auth/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'x-api-key': 'your_api_key'
  },
  body: JSON.stringify({
    dappId: 'your_dapp_id',
    customerId: 'your_customer_id'
  })
});

const { token } = await authResponse.json();

// Use token for relay requests
const response = await fetch('http://relay:4001/api/v1/proof/request', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`
  },
  body: JSON.stringify({
    circuitId: 'coinbase_attestation',
    scope: 'proofport:kyc',
    inputs: {
      account: userAddress,
      signalHash: challengeHash,
      attesterRoot: merkleRoot
    },
    callbackUrl: 'https://myapp.com/webhook/proof',
    nonce: UUID() // Prevent duplicate submissions
  })
});

const { requestId, deepLink, status, pollUrl } = await response.json();

// Store requestId in session
// Display QR code with deepLink
// Poll pollUrl every 2 seconds
```


**Socket.IO Example with JWT Token (Recommended):**
```javascript
// First, obtain JWT token from API server (same as REST example above)
const { token } = await authResponse.json();

const socket = io('http://relay:4001', {
  namespace: '/proof',
  auth: { token }
});

socket.on('connect', () => {
  socket.emit('proof:request', {
    circuitId: 'coinbase_attestation',
    scope: 'proofport:kyc',
    inputs: { account: userAddress, signalHash: challengeHash },
    nonce: UUID()
  });
});

socket.on('proof:status', (data) => {
  if (data.status === 'pending') {
    console.log(`Proof generation started. Deep link: ${data.deepLink}`);
  } else if (data.status === 'generating') {
    console.log('Proof generation in progress...');
  }
});

socket.on('proof:result', (result) => {
  if (result.status === 'completed') {
    console.log(`Proof received: ${result.proof}`);
    // Submit proof to smart contract
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

await fetch('http://relay:3100/api/v1/proof/callback', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(result)
});
```

### Webhook Consumer (dApp Backend)

Receives callbacks at registered `callbackUrl`:

```javascript
app.post('/webhook/proof', (req, res) => {
  const { requestId, status, proof, publicInputs, error } = req.body;

  if (status === 'completed') {
    // Verify proof on-chain or use for downstream logic
    submitProofToContract(proof, publicInputs);
  } else {
    // Handle failure
    logProofError(requestId, error);
  }

  res.json({ received: true });
});
```

## Debugging

### Health Check

```bash
curl http://0.0.0.0:3100/health
```

### View Status

```bash
curl http://0.0.0.0:3100/api/v1/proof/{requestId}
```

### Logs

Development logs to stdout. Production should use structured logging (JSON).

**Log Prefixes:**
- `[Relay]` - Core request handling
- `[REST]` - HTTP endpoint errors
- `[Socket.IO]` - WebSocket events
- `[Redis]` - Redis connection state
- `[Callback]` - Webhook delivery
- `[Backend]` - Backend API calls

## Docker

**Build:**
```bash
docker build -t proofport-relay .
```

**Run:**
```bash
docker run -p 3100:3100 \
  -e REDIS_URL=redis://redis:6379 \
  -e BACKEND_API_URL=http://backend:3200 \
  -e BACKEND_API_KEY=secret \
  proofport-relay
```

**Docker Compose:**
```yaml
version: '3.8'
services:
  relay:
    image: proofport-relay
    ports:
      - '3100:3100'
    environment:
      REDIS_URL: redis://redis:6379
      BACKEND_API_URL: http://backend:3200
      BACKEND_API_KEY: ${BACKEND_API_KEY}
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
type Tier = 'free' | 'credit' | 'unlimited';

interface PlanInfo {
  clientId: string;
  tier: Tier;
  credits?: number;
  scope?: string;
  callbackUrl?: string;
}

interface ProofRequest {
  requestId: string;
  clientId: string;
  circuitId: string;
  scope: string;
  inputs: Record<string, unknown>;
  callbackUrl?: string;
  createdAt: string;
}

interface ProofStatus {
  requestId: string;
  status: 'pending' | 'generating' | 'completed' | 'failed' | 'expired';
  proof?: string;
  publicInputs?: string[];
  error?: string;
  deepLink?: string;
  createdAt: string;
  updatedAt: string;
}

interface ProofResult {
  requestId: string;
  status: 'completed' | 'failed';
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
| Missing JWT token | 401 | `Authorization header required` |
| Invalid JWT token | 401 | `Invalid or expired JWT token` |
| Missing circuitId | 400 | `circuitId is required` |
| Missing inputs | 400 | `inputs object is required` |
| Invalid clientId | 403 | `Invalid or unknown clientId` |
| Insufficient credits | 402 | `Insufficient credits` |
| Free tier without callback | 400 | `callbackUrl is required for free tier` |
| Replay detected | 409 | `Duplicate nonce (replay detected)` |
| Request expired | 404 | `Request not found or expired` |
| Free tier on Socket.IO | Error | `Free tier must use REST API with callbackUrl` |
| Missing Socket.IO token | Error | `Authentication error: JWT token required` |

## Performance

**Throughput:**
- REST: 100+ requests/second per instance (Redis-backed)
- Socket.IO: 500+ concurrent connections per instance
- Callback delivery: 50+ concurrent webhooks

**Latency:**
- Request creation: <50ms (Redis)
- Status polling: <20ms (cached)
- Callback delivery: <100ms (with retries)

**Resource Usage (per instance):**
- CPU: 1-2 cores typical, 4 cores recommended
- Memory: 100-200 MB baseline, +1MB per 1000 concurrent connections
- Redis: <100MB for typical workload (auto-expiring TTL)

## Development

**File Structure:**
```
src/
├── index.ts      # Express server, REST endpoints, Socket.IO handlers
├── types.ts      # TypeScript interfaces
└── redis.ts      # Redis wrapper with in-memory fallback
```

**Scripts:**
- `npm run dev` - Development with hot reload
- `npm run build` - Compile TypeScript
- `npm start` - Production server
- `npx tsc --noEmit` - Type checking

**Linting & Formatting:**
Not included. Add ESLint/Prettier as needed:
```bash
npm install --save-dev eslint prettier typescript-eslint
```

## License

MIT
