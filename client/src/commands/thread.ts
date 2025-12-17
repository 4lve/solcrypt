/**
 * Thread management commands (accept/remove)
 */

import type { KeyPairSigner } from "@solana/kit";
import type { SolanaRpc } from "../config.js";
import { sendTransaction } from "../transaction.js";
import {
    getAcceptThreadDataInstructionAsync,
    getRemoveThreadDataInstructionAsync,
} from "../generated/instructions/index.js";

/**
 * Accepts a pending thread (chat request).
 */
export async function acceptThread(
    rpc: SolanaRpc,
    signer: KeyPairSigner,
    threadId: Uint8Array
): Promise<string> {
    const instruction = await getAcceptThreadDataInstructionAsync({
        signer,
        threadId: Array.from(threadId),
    });

    return await sendTransaction(rpc, signer, instruction);
}

/**
 * Removes a thread from the user's list.
 */
export async function removeThread(
    rpc: SolanaRpc,
    signer: KeyPairSigner,
    threadId: Uint8Array
): Promise<string> {
    const instruction = await getRemoveThreadDataInstructionAsync({
        signer,
        threadId: Array.from(threadId),
    });

    return await sendTransaction(rpc, signer, instruction);
}

/**
 * Parses a thread ID from hex string to bytes.
 */
export function parseThreadId(threadIdHex: string): Uint8Array {
    if (threadIdHex.length !== 64) {
        throw new Error("Thread ID must be 64 hex characters (32 bytes)");
    }
    return new Uint8Array(Buffer.from(threadIdHex, "hex"));
}
