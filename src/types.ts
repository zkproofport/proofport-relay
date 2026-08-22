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
   * a bare custom scheme (`mydapp://`) or an https origin (`https://myapp.com`).
   * Not a URL: no path, query or fragment. Omitted means no auto-switch.
   * Validated by `validateReturnScheme()` before it ever reaches a deep link.
   */
  returnScheme?: string;
  createdAt: string;
}

export interface ProofResult {
  requestId: string;
  status: 'completed' | 'failed' | 'error';
  proof?: string;
  publicInputs?: string[];
  error?: string;
  verifierAddress?: string;
  chainId?: number;
  circuit?: string;
  completedAt: string;
}

export interface ProofStatus {
  requestId: string;
  status: 'pending' | 'generating' | 'completed' | 'failed' | 'error' | 'expired';
  proof?: string;
  publicInputs?: string[];
  error?: string;
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
