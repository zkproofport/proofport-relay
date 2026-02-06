export type Tier = 'free' | 'credit' | 'plan1' | 'plan2';

export interface PlanInfo {
  clientId: string;
  tier: Tier;
  credits?: number;
  freeCredits?: number;
  paidCredits?: number;
  scope?: string;
  callbackUrl?: string;
}

export interface ProofRequest {
  requestId: string;
  clientId: string;
  circuitId: string;
  scope: string;
  inputs: Record<string, unknown>;
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
  nullifier?: string;
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
  nullifier?: string;
  circuit?: string;
  deepLink?: string;
  onChainStatus?: string;
  txHash?: string;
  createdAt: string;
  updatedAt: string;
}

export interface CallbackPayload {
  requestId: string;
  status: 'completed' | 'failed' | 'error';
  proof?: string;
  publicInputs?: string[];
  error?: string;
  verifierAddress?: string;
  chainId?: number;
  nullifier?: string;
  scope?: string;
  circuit?: string;
  onChainStatus?: string;
  txHash?: string;
}
