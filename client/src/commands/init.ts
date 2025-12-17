/**
 * Initialize user account command
 */

import type { KeyPairSigner, Address } from "@solana/kit";
import type { SolanaRpc } from "../config.js";
import { SYSTEM_PROGRAM_ADDRESS } from "../config.js";
import { sendTransaction } from "../transaction.js";
import { getSecretKeyBytes } from "../keypair.js";
import { deriveX25519Keypair } from "../crypto.js";
import { getInitUserDataInstructionAsync } from "../generated/instructions/index.js";
import { findUserAccountPda } from "../generated/pdas/index.js";
import { getUserAccountDecoder, type UserAccount } from "../generated/accounts/index.js";

/**
 * Gets the user account PDA for a given public key.
 */
export async function getUserPda(user: Address): Promise<Address> {
    const [pda] = await findUserAccountPda({ userPubkey: user });
    return pda;
}

/**
 * Fetches a user account from chain.
 */
export async function fetchUserAccount(
    rpc: SolanaRpc,
    userPda: Address
): Promise<UserAccount | null> {
    const response = await rpc.getAccountInfo(userPda, { encoding: "base64" }).send();
    if (!response.value) return null;

    const data = Buffer.from(response.value.data[0], "base64");
    const decoder = getUserAccountDecoder();
    return decoder.decode(data);
}

/**
 * Initializes a user account with the derived X25519 public key.
 */
export async function initUserAccount(
    rpc: SolanaRpc,
    signer: KeyPairSigner
): Promise<{ signature: string; pda: Address; x25519Pubkey: Uint8Array }> {
    // Derive X25519 keypair from signer
    const secretKey = await getSecretKeyBytes(signer);
    const x25519Keypair = deriveX25519Keypair(secretKey);

    // Build instruction
    const instruction = await getInitUserDataInstructionAsync({
        signer,
        systemProgram: SYSTEM_PROGRAM_ADDRESS,
        x25519Pubkey: Array.from(x25519Keypair.public),
    });

    // Send transaction
    const signature = await sendTransaction(rpc, signer, instruction);
    const pda = await getUserPda(signer.address);

    return { signature, pda, x25519Pubkey: x25519Keypair.public };
}
