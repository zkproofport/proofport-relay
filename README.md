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

### Tests

```bash
./scripts/test-relay.sh unit          # from the repo root; no services
./scripts/test-relay.sh integration   # in-process relays on the dev Redis, DB 15 (flushed)
./scripts/test-relay.sh e2e           # relay :4001 + test-only relay-b :4011 on one Redis, and /admin in headless Chromium
./scripts/test-relay.sh image         # builds Dockerfile.prod and checks the admin page's files load from it
./scripts/test-relay.sh all           # all four
```

The admin browser test needs Playwright's headless Chromium once: `npx playwright-core install chromium-headless-shell` (in `proofport-relay`). Screenshots go to a temporary directory the script prints.

### Type Checking

```bash
npx tsc --noEmit
```

## Configuration

Environment variables (see `.env.example`):

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `4001` | Server port |
| `CORS_ORIGIN` | `*` | CORS allowed origins for the public API. Never applied to `/admin` or `/api/v1/stats`, which send no CORS headers at all |
| `REDIS_URL` | (required) | Redis connection string |
| `RELAY_EXTERNAL_URL` | (required for production) | External relay URL for deep link callbacks |
| `RELAY_STATS_TOKEN` | (required, ≥ 32 chars) | Bearer token for `GET /api/v1/stats`. The relay refuses to start without it. Locally `scripts/dev.sh` generates one into `.env.development`; deployed environments read the Google Secret Manager secrets `relay-stats-token-staging` / `relay-stats-token-production` (mounted by `deploy.yml` with `--set-secrets`; GitHub secrets are write-only, so the token could never be read back to call the API) |
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
    "signature": "0xdeadbeef...",
    "returnScheme": "mydapp://"
  }'
```

**`returnScheme` (optional)** — which app the ZKProofport app should bring back
to the foreground once it has finished. Envelope-level data: it says *which app*,
never *which URL*, and the proof result is still delivered over the relay as
usual. One form is accepted, nothing else:

| Form | Example |
|------|---------|
| bare custom scheme | `mydapp://`, `googlechrome://`, `firefox://` |

Normalised to lowercase and stored on the request, so it travels inside the
base64url deep-link payload.

**An https origin is NOT accepted.** `https://myapp.com` used to be a second
accepted form and now returns `400`. Opening one returns nobody anywhere: the
OS hands the URL to the browser, which opens a *new tab* on a freshly loaded
page while the tab the user started in — and every bit of state in it — is left
behind. A native app therefore sends its own registered scheme, and a web
requester sends nothing at all. When the field is absent the ZKProofport app
either backgrounds itself (Android, so the browser resumes untouched) or tells
the user the proof was delivered and to switch back themselves (iOS). The two
browser exceptions are Chrome and Firefox for iOS: the SDK fills in
`googlechrome://` or `firefox://` by itself, because opening either scheme bare
foregrounds that browser without navigating.

Rejected with `400`: empty/whitespace values, anything over 128 characters,
anything carrying a host, path, query string, fragment or userinfo, and the
`http:`, `https:`, `file:`, `data:`, `javascript:`, `intent:`, `tel:`, `sms:`,
`mailto:` families. Note `https:` and `http:` are denied as schemes too — with
no host they are shaped exactly like a bare custom scheme, so the shape rule
alone would let `https://` through.

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
- `400`: Missing required fields, invalid inputs, or malformed `returnScheme`
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

`status` is `pending`, `generating`, or a terminal status: `completed`, `error`, `failed` (older apps' name for `error`), `cancelled`, `expired`. A terminal response carries the buffered result (`proof`, `publicInputs`, `error`, `errorCode`, `verifierAddress`, `chainId`, `circuit`) while it is kept (5 minutes).

A poll of a request past its deadline expires it on the spot (see [Request deadline](#request-deadline)).

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
  "circuit": "coinbase_attestation",
  "status": "error",
  "errorCode": "E2007",
  "error": "Proof generation failed"
}
```

**Request (Final Status - Declined by the user):**
```json
{ "requestId": "550e8400-e29b-41d4-a716-446655440000", "circuit": "coinbase_attestation", "status": "cancelled" }
```

| Field | Rule |
|-------|------|
| `status` | `completed`, `error`, `cancelled` (terminal); `failed` is accepted as the older name for `error`; `generating` is the one intermediate status. Anything else, including `expired` (which only the relay writes), is 400 |
| `errorCode` | Optional, `^E\d{4}$` (the app's ErrorModal codes). Malformed or non-string is 400. Stored and counted only on `error`/`failed` |
| `error` | Optional string forwarded to the dApp. Cut to 1000 characters (code points). Never used as a statistics key. Non-string is 400 |

**Response:**
```json
{
  "received": true
}
```

**Status Codes:**
- `200`: Callback received
- `400`: Missing/invalid requestId or status, malformed errorCode, non-string error, malformed JSON
- `404`: Unknown or expired requestId
- `409`: The request already has a terminal status. Nothing changes: no second result, no second emit, no second count. Body is stable: `reason: "expired"` after a relay timeout, `reason: "already_answered"` otherwise. The terminal record is kept 7 days, so an answer the app re-sends on a later launch gets this 409 rather than 404
- `500`: Internal server error

**Behavior:**
- The intermediate status (`generating`) updates status only, and never overwrites a terminal one
- A terminal status is taken exactly once (an atomic Redis script decides the winner): the result is buffered, the status set, `proof:result` emitted to every instance's sockets, and the outcome counted
- Result buffered in Redis for 5 minutes (client reconnection tolerance)
- Statistics use the circuit recorded when the request was created, not the `circuit` the callback claims

#### GET /api/v1/stats
Per-circuit request statistics, per UTC day. `Authorization: Bearer <RELAY_STATS_TOKEN>` is required (401 otherwise, checked before anything else). The comparison is constant-time.

- **Same origin only.** No CORS headers, whatever `CORS_ORIGIN` says: a browser on another origin cannot call it, token or not. The admin page (`/admin`) is same-origin.
- **Wrong-token lockout.** 10 wrong or missing tokens from one caller within 15 minutes, and every stats call from that caller answers **429** with `Retry-After` until the window ends -- the right token included. Counted in Redis (`relay:stats-auth-fail:<sha256 of the address>`, 15-minute TTL), so it holds across all Cloud Run instances; the address itself is never stored.
- **Read limit.** 60 successful calls per minute per caller per instance, then 429.
- Responses carry `Cache-Control: no-store`. If the lockout store (Redis) fails, the answer is 500, never the data.

`GET /api/v1/stats?from=2026-10-01&to=2026-10-14` — both required, `YYYY-MM-DD` (UTC), real calendar dates, `from <= to`, at most 400 days inclusive (400 otherwise).

```json
{
  "from": "2026-10-01",
  "to": "2026-10-14",
  "days": [
    { "date": "2026-10-01", "circuits": {
      "coinbase_attestation": {
        "requested": 12, "completed": 9,
        "error": { "total": 1, "byCode": { "E2007": 1 } },
        "cancelled": 1, "expired": 1, "abandoned": 2
      } } }
  ],
  "totals": { "circuits": { "coinbase_attestation": { "...": "same shape" } }, "all": { "...": "same shape" } },
  "unrecognized": {}
}
```

- Only dApp → relay requests are counted (app-internal proofs never reach the relay).
- `abandoned` = `cancelled` + `expired`: the user never answered.
- `error.byCode.none` counts errors that arrived without an `errorCode`.
- An event counts on the UTC day it happened: a request at 23:59 that expires at 00:03 is `requested` on one day and `expired` on the next.
- Stored as Redis hashes `relay:stats:YYYY-MM-DD` (fields `<circuit>|requested`, `<circuit>|completed`, `<circuit>|error|<code or none>`, `<circuit>|cancelled`, `<circuit>|expired`), 400-day TTL. No IP, wallet, requestId, scope or nullifier is stored.
- Counting is fire-and-forget: a Redis error while counting is logged and dropped, never failing or delaying the proof path.

#### Request deadline

The relay answers the dApp itself when the app has not answered within **280 s** (`REQUEST_DEADLINE_MS` in `src/app.ts`), 20 s before the SDK's default 300 s wait gives up. The result is `{ "status": "expired", "error": "The request timed out before the app answered" }`, delivered over `proof:result` and polling like any other terminal status, and counted as `expired`. A late app callback gets 409 `{ "error": "The request timed out before the app answered", "reason": "expired" }`.

Deadlines live in the Redis sorted set `proof:deadlines`, not in process memory: every instance sweeps it every 5 s, the atomic terminal script lets exactly one instance win each expiry, and a poll, subscribe or callback that touches an overdue request expires it on the spot.

#### GET /admin
Admin dashboard for the statistics above: log in with the stats token, pick a range (last 7 / 30 / 90 days, or any range up to 400 days), and read per-circuit totals (requested, completed, error, cancelled, expired, success rate = completed / requested, `—` when nothing was requested), errors by code with the app's label for known `E` codes, a per-day chart and a per-day table. All dates are UTC days. An empty range says so.

- **The token.** Get it with `./scripts/relay-stats-token.sh <staging|production>` from the repository root (add `--copy` to put it on the clipboard instead of printing it). It reads the Google Secret Manager secret `relay-stats-token-<env>` in project `masselabs-zkproofport`; you need `gcloud auth login` as an account allowed to read it. Locally the token is `RELAY_STATS_TOKEN` in `.env.development`.
- **Rotation.** Add a new secret version (`openssl rand -hex 32 | tr -d '\n' | gcloud secrets versions add relay-stats-token-<env> --project masselabs-zkproofport --data-file=-`), then redeploy the relay (`deploy.yml`, service `relay`) -- Cloud Run reads `:latest` at deploy time. A page still holding the old token returns to the login view on its next call.
- **Where the token lives in the browser.** `sessionStorage` of that tab only: gone when the tab closes, never in the URL, a cookie or `localStorage`. *로그아웃* clears it.
- **What is served.** `GET /admin` (HTML), `/admin/admin.css`, `/admin/app.mjs`, `/admin/core.mjs` -- read from `src/admin/` (copied to `dist/admin/` by `npm run build`) once at startup; a relay built without them refuses to start. Anything else under `/admin` is 404. No external CDN, framework or build step.
- **Headers** on all of them: `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` (no inline script or style), `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `X-Robots-Tag: noindex`. Every value from the API is written with `textContent`, never `innerHTML`.

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
Terminal result broadcast, sent exactly once per request (and replayed to a late `proof:subscribe`): `status` is `completed`, `error`, `failed`, `cancelled` or `expired`.

Socket.IO uses the Redis adapter (`@socket.io/redis-adapter`) on the same Redis, so an emit from the instance that received the app's callback reaches a dApp socket connected to any other instance. Polling transport still needs sticky sessions (`--session-affinity` on Cloud Run); the SDK connects with WebSocket first.

## Rate Limiting

Per caller address, in memory, per instance, fixed 1-minute windows:

| Endpoint | Limit | Window |
|----------|-------|--------|
| `GET /api/v1/challenge` | 30 requests | 1 minute per IP |
| `POST /api/v1/proof/request` and Socket.IO `proof:request` (one shared budget) | 10 requests | 1 minute per IP |
| `GET /api/v1/stats` (authenticated) | 60 requests | 1 minute per IP |
| `GET /api/v1/stats` wrong token | 10 failures, then locked | 15 minutes per IP, across all instances (Redis) |

Exceeding limits returns HTTP 429 with `Retry-After` (a socket gets `proof:error` with `code: 429`).

**Which address.** `app.set('trust proxy', 1)` (`TRUSTED_PROXY_HOPS` in `src/clientIp.ts`): the relay's hostnames are Cloud Run domain mappings, and Google's front end appends the caller's address as the rightmost `X-Forwarded-For` entry; that entry is the caller, everything to its left is whatever the client wrote. `clientIp()` computes it the way Express computes `req.ip`, and HTTP routes and Socket.IO handshakes both use it. Before this, every request read the front end's own address (`169.254.169.126`), so each limit was one bucket for everyone. Never set it to `true` (that trusts the client-written leftmost entry). If a load balancer or CDN is ever put in front, the hop count changes -- see the comment on `TRUSTED_PROXY_HOPS`. Locally there is no front end: a request without the header is counted under Docker's gateway address, and one with it under its rightmost entry.

## Storage

### Redis (Primary)

All session data cached in Redis with TTL:

| Key Pattern | TTL | Purpose |
|-------------|-----|---------|
| `proof:status:{requestId}` | 10 min | Current proof status |
| `proof:result:{requestId}` | 5 min | Proof result (for reconnection) |
| `proof:nonce:{nonce}` | 10 min | Nonce seen flag (replay prevention) |
| `proof:inputsHash:{requestId}` | 10 min | SHA256 hash of proof inputs |
| `session:{requestId}` | 10 min | Challenge session |
| `proof:meta:{requestId}` | 10 min | Circuit as requested and the deadline (relay-internal) |
| `proof:terminal:{requestId}` | 7 days | The terminal status taken; makes the terminal transition one-way |
| `proof:deadlines` | — | Sorted set of open requests by deadline (ms) |
| `relay:stats:{YYYY-MM-DD}` | 400 days | Per-circuit counters (see `GET /api/v1/stats`) |
| `relay:stats-auth-fail:{sha256(ip)}` | 15 min | Wrong stats tokens from one caller (lockout at 10) |

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

**Personal data is masked in every log line** by `src/mask.ts`: IPs (`203.0.x.x`, IPv6 first three groups), addresses, hashes and nullifiers (`0x1234…abcd`), e-mail local parts; request and callback bodies are logged as key names plus envelope fields only (`requestId`, `circuit`, `status`, `errorCode`, `dappName`, `chainId`, `verifierAddress`, `returnScheme`); deep links without their payload; free-text errors through the scrubber. Rate limiting still uses the real IP in memory. Masking is not truncation — non-personal values are logged in full.

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
  status: 'pending' | 'generating' | 'completed' | 'failed' | 'error' | 'cancelled' | 'expired';
  proof?: string;
  publicInputs?: string[];
  error?: string;
  errorCode?: string;
  deepLink?: string;
  inputsHash?: string;
  createdAt: string;
  updatedAt: string;
}

interface ProofResult {
  requestId: string;
  status: 'completed' | 'failed' | 'error' | 'cancelled' | 'expired';
  proof?: string;
  publicInputs?: string[];
  error?: string;
  errorCode?: string;
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
| Second terminal callback | 409 | `{ "error": "This request has already been answered", "reason": "already_answered" }` |
| Callback after the relay timed the request out | 409 | `{ "error": "The request timed out before the app answered", "reason": "expired" }` |
| Malformed `errorCode` | 400 | `errorCode must look like E2007 (E followed by four digits)` |
| Stats without / with wrong token | 401 | `Unauthorized` |
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
