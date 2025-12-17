/**
 * Fetch chats (threads) command
 */

import type { Address } from "@solana/kit";
import type { SolanaRpc } from "../config.js";
import { THREAD_STATE_PENDING, THREAD_STATE_ACCEPTED } from "../config.js";
import { getUserPda, fetchUserAccount } from "./init.js";
import type { ThreadEntry } from "../generated/types/index.js";

export interface ChatInfo {
    threadId: string;
    state: "pending" | "accepted";
    threadIdBytes: number[];
}

/**
 * Fetches all chats for a user.
 */
export async function fetchAllChats(
    rpc: SolanaRpc,
    userAddress: Address
): Promise<ChatInfo[]> {
    const pda = await getUserPda(userAddress);
    const account = await fetchUserAccount(rpc, pda);

    if (!account) {
        return [];
    }

    return account.threads.map((thread: ThreadEntry) => ({
        threadId: Buffer.from(thread.threadId).toString("hex"),
        state: thread.state === THREAD_STATE_ACCEPTED ? "accepted" : "pending",
        threadIdBytes: thread.threadId,
    }));
}

/**
 * Fetches only accepted chats for a user.
 */
export async function fetchAcceptedChats(
    rpc: SolanaRpc,
    userAddress: Address
): Promise<ChatInfo[]> {
    const chats = await fetchAllChats(rpc, userAddress);
    return chats.filter((chat) => chat.state === "accepted");
}

/**
 * Fetches only pending chats for a user.
 */
export async function fetchPendingChats(
    rpc: SolanaRpc,
    userAddress: Address
): Promise<ChatInfo[]> {
    const chats = await fetchAllChats(rpc, userAddress);
    return chats.filter((chat) => chat.state === "pending");
}

/**
 * Gets user account info including X25519 public key.
 */
export async function getUserInfo(
    rpc: SolanaRpc,
    userAddress: Address
): Promise<{ x25519Pubkey: Uint8Array; threadCount: number } | null> {
    const pda = await getUserPda(userAddress);
    const account = await fetchUserAccount(rpc, pda);

    if (!account) {
        return null;
    }

    return {
        x25519Pubkey: new Uint8Array(account.x25519Pubkey),
        threadCount: account.threads.length,
    };
}
