/**
 * Solcrypt CLI Configuration
 */

import { type Address, createSolanaRpc } from "@solana/kit";
import { createRpc, Rpc as LightRpc } from "@lightprotocol/stateless.js";

// ============================================================================
// Program Constants
// ============================================================================

export const SYSTEM_PROGRAM_ADDRESS = "11111111111111111111111111111111" as Address;
export const THREAD_STATE_PENDING = 0;
export const THREAD_STATE_ACCEPTED = 1;

// ============================================================================
// RPC Configuration
// ============================================================================

export interface RpcConfig {
    rpcUrl: string;
}

export function createRpcClients(config: RpcConfig) {
    const rpc = createSolanaRpc(config.rpcUrl);
    const lightRpc = createRpc(config.rpcUrl, config.rpcUrl);
    return { rpc, lightRpc };
}

export type SolanaRpc = ReturnType<typeof createSolanaRpc>;
export type { LightRpc };
