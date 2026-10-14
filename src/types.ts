export interface ChallengeResponse {
  requestId: string;  // session identifier
  challenge: string;  // hex-encoded 32 random bytes
  expiresAt: number;  // unix timestamp ms
}

export interface ProofRequest {
  requestId: string;
  circuitId: string;
  scope: string;
  inputs: Record<string, unknown>;
  inputsHash?: string;
  callbackUrl?: string;
  dappName?: string;
  dappIcon?: string;
  message?: string;
  /**
   * Optional app to bring back to the foreground once ZKProofport is done —
   * a bare custom scheme (`mydapp://`). Not a URL: no host, path, query or
   * fragment, and an https origin is NOT accepted (opening one lands the user
   * in a new browser tab, abandoning the page that made the request). A web
   * requester therefore has nothing valid to send and omits the field, which
   * means no auto-switch.
   * Validated by `validateReturnScheme()` before it ever reaches a deep link.
   */
  returnScheme?: string;
  createdAt: string;
}

/**
 * The states a request can end in. Once one is reached it never changes.
 *
 * `completed`, `error`, `cancelled` come from the app; `failed` is the older
 * name for `error`, still accepted from apps that send it. `expired` is
 * written by the relay itself when the app has not answered by the deadline.
 */
export const TERMINAL_STATUSES = ['completed', 'error', 'failed', 'cancelled', 'expired'] as const;
export type TerminalStatus = typeof TERMINAL_STATUSES[number];

/** Terminal statuses the APP may send. `expired` belongs to the relay. */
export const APP_TERMINAL_STATUSES = ['completed', 'error', 'failed', 'cancelled'] as const;

/** Non-terminal statuses the app may report while it works. */
export const INTERMEDIATE_STATUSES = ['generating'] as const;

export interface ProofResult {
  requestId: string;
  status: TerminalStatus;
  proof?: string;
  publicInputs?: string[];
  error?: string;
  /** The app's ErrorModal code (`E2007`), when the app sent one. */
  errorCode?: string;
  verifierAddress?: string;
  chainId?: number;
  circuit?: string;
  completedAt: string;
}

/** What the relay remembers about a request for itself; never sent to anyone. */
export interface RequestMeta {
  /** The circuit as validated at creation. Stats use this, not the callback's claim. */
  circuitId: string;
  /** Unix ms after which the relay answers the dApp with `expired`. */
  deadlineAt: number;
}

export interface ProofStatus {
  requestId: string;
  status: 'pending' | typeof INTERMEDIATE_STATUSES[number] | TerminalStatus;
  proof?: string;
  publicInputs?: string[];
  error?: string;
  errorCode?: string;
  verifierAddress?: string;
  chainId?: number;
  circuit?: string;
  deepLink?: string;
  inputsHash?: string;
  createdAt: string;
  updatedAt: string;
}

/**
 * Session data stored in Redis for each proof request.
 * Created at challenge time, updated through the request lifecycle.
 */
export interface ProofSession {
  requestId: string;
  challenge: string;
  status: 'pending' | 'claimed' | 'completed' | 'failed' | 'expired';
  ip: string;
  circuitId?: string;
  inputs?: Record<string, unknown>;
  createdAt: string;
  expiresAt: string;
}
