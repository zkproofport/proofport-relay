export interface ChallengeResponse {
  challenge: string;  // hex-encoded 32 random bytes
  expiresAt: number;  // unix timestamp ms
}

export interface ProofRequest {
  requestId: string;
  clientId: string;
  circuitId: string;
  scope: string;
  inputs: Record<string, unknown>;
  inputsHash?: string;
  callbackUrl?: string;
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
