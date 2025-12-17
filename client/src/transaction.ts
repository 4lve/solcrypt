/**
 * Transaction utilities
 */

import {
    type KeyPairSigner,
    type Instruction,
    pipe,
    createTransactionMessage,
    setTransactionMessageFeePayer,
    setTransactionMessageLifetimeUsingBlockhash,
    appendTransactionMessageInstruction,
    signTransactionMessageWithSigners,
    getSignatureFromTransaction,
    sendTransactionWithoutConfirmingFactory,
    lamports,
    type Address,
} from "@solana/kit";

import type { SolanaRpc } from "./config.js";

/**
 * Sends a transaction and waits for confirmation.
 */
export async function sendTransaction(
    rpc: SolanaRpc,
    signer: KeyPairSigner,
    instruction: Instruction
): Promise<string> {
    const { value: latestBlockhash } = await rpc.getLatestBlockhash().send();

    const transactionMessage = pipe(
        createTransactionMessage({ version: 0 }),
        (msg) => setTransactionMessageFeePayer(signer.address, msg),
        (msg) => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, msg),
        (msg) => appendTransactionMessageInstruction(instruction, msg)
    );

    const signedTx = await signTransactionMessageWithSigners(transactionMessage);
    const signature = getSignatureFromTransaction(signedTx);

    // Send transaction
    const sendTx = sendTransactionWithoutConfirmingFactory({ rpc });
    await sendTx(signedTx, { skipPreflight: false, commitment: "confirmed" });

    // Wait for confirmation by polling
    let confirmed = false;
    for (let i = 0; i < 30; i++) {
        const { value: statuses } = await rpc.getSignatureStatuses([signature]).send();
        if (
            statuses[0]?.confirmationStatus === "confirmed" ||
            statuses[0]?.confirmationStatus === "finalized"
        ) {
            confirmed = true;
            break;
        }
        await new Promise((resolve) => setTimeout(resolve, 500));
    }

    if (!confirmed) {
        throw new Error(`Transaction ${signature} not confirmed`);
    }

    return signature;
}

/**
 * Requests an airdrop (for local testing).
 */
export async function requestAirdrop(
    rpc: SolanaRpc,
    targetAddress: Address,
    amount: bigint
): Promise<void> {
    // Use any to bypass the cluster type checking for local validator
    await (rpc as any).requestAirdrop(targetAddress, lamports(amount)).send();
    // Wait for confirmation
    await new Promise((resolve) => setTimeout(resolve, 2000));
}
