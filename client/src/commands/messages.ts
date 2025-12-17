/**
 * Message loading and sending commands
 */

import {
    type Address,
    type KeyPairSigner,
    type Instruction,
    AccountRole,
    type AccountMeta,
} from "@solana/kit";
import { PublicKey } from "@solana/web3.js";
import {
    bn,
    deriveAddress,
    defaultTestStateTreeAccounts,
    PackedAccounts,
    SystemAccountMetaConfig,
} from "@lightprotocol/stateless.js";

import type { SolanaRpc, LightRpc } from "../config.js";
import { SYSTEM_PROGRAM_ADDRESS } from "../config.js";
import { sendTransaction } from "../transaction.js";
import { getSecretKeyBytes } from "../keypair.js";
import {
    deriveX25519Keypair,
    deriveAesKey,
    computeThreadId,
    encryptMessage,
    decryptMessage,
    encodeTextMessage,
    decodeTextMessage,
    generateNonce,
} from "../crypto.js";
import { getUserInfo } from "./chats.js";
import { getSendDmMessageDataInstructionAsync } from "../generated/instructions/index.js";
import { getMsgV1Decoder } from "../generated/types/index.js";
import { SOLCRYPT_PROGRAM_ADDRESS } from "../generated/programs/index.js";

export interface Message {
    sender: string;
    recipient: string;
    threadId: string;
    timestamp: bigint;
    content: string;
    iv: Uint8Array;
    ciphertext: Uint8Array;
}

export interface DecryptedMessage extends Message {
    decryptedContent: string;
}

/**
 * Sends an encrypted DM message.
 */
export async function sendMessage(
    rpc: SolanaRpc,
    lightRpc: LightRpc,
    signer: KeyPairSigner,
    recipientAddress: Address,
    messageText: string
): Promise<{ signature: string; messageAddress: number[] }> {
    // Get recipient's X25519 public key
    const recipientInfo = await getUserInfo(rpc, recipientAddress);
    if (!recipientInfo) {
        throw new Error("Recipient has not initialized their account");
    }

    // Derive our X25519 keypair
    const secretKey = await getSecretKeyBytes(signer);
    const ourX25519 = deriveX25519Keypair(secretKey);

    // Derive shared AES key
    const aesKey = deriveAesKey(ourX25519.secret, recipientInfo.x25519Pubkey);

    // Compute thread ID
    const threadId = computeThreadId(signer.address, recipientAddress);

    // Encode and encrypt message
    const plaintext = encodeTextMessage(messageText);
    const { iv, ciphertext } = encryptMessage(aesKey, plaintext);
    const nonce = generateNonce();

    // Get tree accounts from Light SDK
    const treeAccounts = defaultTestStateTreeAccounts();

    // Derive message address
    const addressSeeds = new Uint8Array([...Buffer.from("msg"), ...threadId, ...nonce]);
    const messageAddress = deriveAddress(addressSeeds, treeAccounts.addressTree);

    // Get validity proof from Light RPC
    const proof = await lightRpc.getValidityProofV0(undefined, [
        {
            address: bn(messageAddress.toBytes()),
            tree: treeAccounts.addressTree,
            queue: treeAccounts.addressQueue,
        },
    ]);

    const proofData = proof.compressedProof;
    const rootIndex = proof.rootIndices?.[0] ?? 0;

    // Use PackedAccounts helper from Light SDK
    const packedAccounts = new PackedAccounts();

    // Add Light System accounts
    const systemAccountConfig = SystemAccountMetaConfig.new(
        new PublicKey(SOLCRYPT_PROGRAM_ADDRESS)
    );
    packedAccounts.addSystemAccounts(systemAccountConfig);

    // Get indices for tree accounts
    const addressMerkleTreePubkeyIndex = packedAccounts.insertOrGet(treeAccounts.addressTree);
    const addressQueuePubkeyIndex = packedAccounts.insertOrGet(treeAccounts.addressQueue);
    const outputStateTreeIndex = packedAccounts.insertOrGet(treeAccounts.merkleTree);

    // Convert to account metas
    const { remainingAccounts: lightRemainingAccounts } = packedAccounts.toAccountMetas();

    // Convert web3.js v1 account metas to @solana/kit format
    const remainingAccounts: AccountMeta[] = lightRemainingAccounts.map((acc) => ({
        address: acc.pubkey.toBase58() as Address,
        role: acc.isWritable
            ? acc.isSigner
                ? AccountRole.WRITABLE_SIGNER
                : AccountRole.WRITABLE
            : acc.isSigner
                ? AccountRole.READONLY_SIGNER
                : AccountRole.READONLY,
    }));

    // Build base instruction
    const baseInstruction = await getSendDmMessageDataInstructionAsync({
        signer,
        systemProgram: SYSTEM_PROGRAM_ADDRESS,
        proof: proofData
            ? {
                a: Array.from(proofData.a),
                b: Array.from(proofData.b),
                c: Array.from(proofData.c),
            }
            : null,
        addressTreeInfo: {
            addressMerkleTreePubkeyIndex,
            addressQueuePubkeyIndex,
            rootIndex,
        },
        outputStateTreeIndex,
        threadId: Array.from(threadId),
        recipient: recipientAddress,
        iv: Array.from(iv),
        ciphertext: Array.from(ciphertext),
        nonce: Array.from(nonce),
    });

    // Create instruction with remaining accounts
    const instruction: Instruction = {
        ...baseInstruction,
        accounts: [...baseInstruction.accounts, ...remainingAccounts],
    };

    // Send transaction
    const signature = await sendTransaction(rpc, signer, instruction);

    return { signature, messageAddress: Array.from(messageAddress.toBytes()) };
}

/**
 * Loads messages for a thread between two users.
 * Note: This requires indexing compressed accounts which may need additional RPC support.
 */
export async function loadMessages(
    lightRpc: LightRpc,
    rpc: SolanaRpc,
    signer: KeyPairSigner,
    otherUserAddress: Address
): Promise<DecryptedMessage[]> {
    // Get other user's X25519 public key
    const otherUserInfo = await getUserInfo(rpc, otherUserAddress);
    if (!otherUserInfo) {
        throw new Error("Other user has not initialized their account");
    }

    // Derive our X25519 keypair
    const secretKey = await getSecretKeyBytes(signer);
    const ourX25519 = deriveX25519Keypair(secretKey);

    // Derive shared AES key
    const aesKey = deriveAesKey(ourX25519.secret, otherUserInfo.x25519Pubkey);

    // Compute thread ID
    const threadId = computeThreadId(signer.address, otherUserAddress);
    const threadIdHex = Buffer.from(threadId).toString("hex");

    // Get compressed accounts by owner (our program)
    // Filter for messages in this thread
    const accounts = await lightRpc.getCompressedAccountsByOwner(
        new PublicKey(SOLCRYPT_PROGRAM_ADDRESS)
    );

    const messages: DecryptedMessage[] = [];
    const msgDecoder = getMsgV1Decoder();

    for (const account of accounts.items) {
        if (!account.data?.data) continue;

        try {
            const msgData = msgDecoder.decode(Buffer.from(account.data.data));

            // Check if this message belongs to our thread
            const msgThreadIdHex = Buffer.from(msgData.threadId).toString("hex");
            if (msgThreadIdHex !== threadIdHex) continue;

            // Decrypt the message
            const decrypted = decryptMessage(
                aesKey,
                Uint8Array.from(msgData.iv),
                Uint8Array.from(msgData.ciphertext)
            );
            const decryptedText = decodeTextMessage(decrypted);

            messages.push({
                sender: msgData.sender,
                recipient: msgData.recipient,
                threadId: msgThreadIdHex,
                timestamp: msgData.timestamp,
                content: decryptedText,
                decryptedContent: decryptedText,
                iv: Uint8Array.from(msgData.iv),
                ciphertext: Uint8Array.from(msgData.ciphertext),
            });
        } catch {
            // Skip messages that can't be decoded (different format or not a message)
            continue;
        }
    }

    // Sort by timestamp
    messages.sort((a, b) => Number(a.timestamp - b.timestamp));

    return messages;
}
