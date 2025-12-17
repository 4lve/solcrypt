/**
 * Solcrypt TypeScript Test Suite
 *
 * This test mirrors the Rust test suite in program/tests/test.rs
 * Tests E2EE DM messaging using ZK Compression on Solana.
 */

// @ts-ignore - noble packages have proper ESM exports
import { sha256 } from "@noble/hashes/sha256";
// @ts-ignore - noble packages have proper ESM exports
import { x25519, ed25519 } from "@noble/curves/ed25519";
// @ts-ignore - noble packages have proper ESM exports
import { gcm } from "@noble/ciphers/aes";
// @ts-ignore - noble packages have proper ESM exports
import { randomBytes } from "@noble/ciphers/webcrypto";

import {
    type Address,
    createSolanaRpc,
    generateKeyPairSigner,
    type KeyPairSigner,
    getAddressEncoder,
    pipe,
    createTransactionMessage,
    setTransactionMessageFeePayer,
    setTransactionMessageLifetimeUsingBlockhash,
    appendTransactionMessageInstruction,
    signTransactionMessageWithSigners,
    lamports,
    type Instruction,
    getSignatureFromTransaction,
    sendTransactionWithoutConfirmingFactory,
    AccountRole,
    type AccountMeta,
} from "@solana/kit";

import {
    Rpc as LightRpc,
    createRpc,
    defaultTestStateTreeAccounts,
    deriveAddress,
    bn,
    PackedAccounts,
    SystemAccountMetaConfig,
} from "@lightprotocol/stateless.js";
import { PublicKey } from "@solana/web3.js";

// Import generated encoders and types
import {
    getInitUserDataInstructionAsync,
    getAddThreadDataInstructionAsync,
    getAcceptThreadDataInstructionAsync,
    getRemoveThreadDataInstructionAsync,
    getSendDmMessageDataInstructionAsync,
} from "./generated/instructions";
import { getMsgV1Decoder } from "./generated/types";
import { getUserAccountDecoder, type UserAccount } from "./generated/accounts";
import { findUserAccountPda } from "./generated/pdas";
import { SOLCRYPT_PROGRAM_ADDRESS } from "./generated/programs";

// ============================================================================
// Program Constants
// ============================================================================

const SYSTEM_PROGRAM_ADDRESS = "11111111111111111111111111111111" as Address;
const THREAD_STATE_PENDING = 0;
const THREAD_STATE_ACCEPTED = 1;


// ============================================================================
// Cryptographic Primitives
// ============================================================================

/**
 * Derives an X25519 keypair from a Solana keypair.
 */
function deriveX25519Keypair(secretKey: Uint8Array): { secret: Uint8Array; public: Uint8Array } {
    const message = new TextEncoder().encode("solcrypt-x25519-key-derivation-v1");
    const signature = ed25519.sign(message, secretKey.slice(0, 32));
    const seed = sha256(signature);
    const publicKey = x25519.getPublicKey(seed);
    return { secret: seed, public: publicKey };
}

/**
 * Computes the thread ID for a DM conversation between two parties.
 * thread_id = SHA256(min(a, b) || max(a, b) || "dm-v1")
 */
function computeThreadId(a: Address, b: Address): Uint8Array {
    const aBytes = getAddressEncoder().encode(a);
    const bBytes = getAddressEncoder().encode(b);

    // Compare bytes to determine order
    let isASmaller = false;
    for (let i = 0; i < 32; i++) {
        if (aBytes[i]! < bBytes[i]!) {
            isASmaller = true;
            break;
        } else if (aBytes[i]! > bBytes[i]!) {
            isASmaller = false;
            break;
        }
    }

    const first = isASmaller ? aBytes : bBytes;
    const second = isASmaller ? bBytes : aBytes;
    const dmTag = new TextEncoder().encode("dm-v1");

    const combined = new Uint8Array(64 + dmTag.length);
    combined.set(first, 0);
    combined.set(second, 32);
    combined.set(dmTag, 64);

    return sha256(combined);
}

/**
 * Derives AES-256 key from X25519 shared secret.
 */
function deriveAesKey(ourSecret: Uint8Array, theirPublic: Uint8Array): Uint8Array {
    const sharedSecret = x25519.getSharedSecret(ourSecret, theirPublic);
    return sha256(sharedSecret);
}

/**
 * Encrypts a message using AES-256-GCM.
 */
function encryptMessage(
    aesKey: Uint8Array,
    plaintext: Uint8Array
): { iv: Uint8Array; ciphertext: Uint8Array } {
    const iv = randomBytes(12);
    const cipher = gcm(aesKey, iv);
    const ciphertext = cipher.encrypt(plaintext);
    return { iv, ciphertext };
}

/**
 * Decrypts a message using AES-256-GCM.
 */
function decryptMessage(aesKey: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    const cipher = gcm(aesKey, iv);
    return cipher.decrypt(ciphertext);
}

/**
 * Encode a text message for the protocol (Message::Text variant).
 */
function encodeTextMessage(text: string): Uint8Array {
    const textBytes = new TextEncoder().encode(text);
    // Format: discriminator (1 byte) + length (4 bytes LE) + text
    const result = new Uint8Array(1 + 4 + textBytes.length);
    result[0] = 0; // Message::Text discriminator
    new DataView(result.buffer).setUint32(1, textBytes.length, true);
    result.set(textBytes, 5);
    return result;
}

/**
 * Decode a text message from the protocol.
 */
function decodeTextMessage(data: Uint8Array): string {
    if (data[0] !== 0) {
        throw new Error(`Unknown message type: ${data[0]}`);
    }
    const length = new DataView(data.buffer, data.byteOffset).getUint32(1, true);
    return new TextDecoder().decode(data.slice(5, 5 + length));
}

// ============================================================================
// PDA Helpers
// ============================================================================

async function getUserPda(user: Address): Promise<Address> {
    const [pda] = await findUserAccountPda({ userPubkey: user });
    return pda;
}

// ============================================================================
// Instruction Builders (using generated async helpers)
// ============================================================================

async function createInitUserInstruction(
    signer: KeyPairSigner,
    x25519Pubkey: Uint8Array
): Promise<Instruction> {
    return await getInitUserDataInstructionAsync(
        {
            signer,
            systemProgram: SYSTEM_PROGRAM_ADDRESS,
            x25519Pubkey: Array.from(x25519Pubkey),
        },
    );
}

async function createAddThreadInstruction(
    signer: KeyPairSigner,
    threadId: Uint8Array,
    state: number
): Promise<Instruction> {
    return await getAddThreadDataInstructionAsync(
        {
            signer,
            systemProgram: SYSTEM_PROGRAM_ADDRESS,
            threadId: Array.from(threadId),
            state,
        },
    );
}

async function createAcceptThreadInstruction(
    signer: KeyPairSigner,
    threadId: Uint8Array
): Promise<Instruction> {
    return await getAcceptThreadDataInstructionAsync(
        {
            signer,
            threadId: Array.from(threadId),
        },
    );
}

async function createRemoveThreadInstruction(
    signer: KeyPairSigner,
    threadId: Uint8Array
): Promise<Instruction> {
    return await getRemoveThreadDataInstructionAsync(
        {
            signer,
            threadId: Array.from(threadId),
        },
    );
}

// ============================================================================
// Transaction Helpers
// ============================================================================

async function sendTransaction(
    rpc: ReturnType<typeof createSolanaRpc>,
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
        if (statuses[0]?.confirmationStatus === "confirmed" || statuses[0]?.confirmationStatus === "finalized") {
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

async function fetchUserAccount(
    rpc: ReturnType<typeof createSolanaRpc>,
    userPda: Address
): Promise<UserAccount | null> {
    const response = await rpc.getAccountInfo(userPda, { encoding: "base64" }).send();
    if (!response.value) return null;

    const data = Buffer.from(response.value.data[0], "base64");
    const decoder = getUserAccountDecoder();
    return decoder.decode(data);
}

async function requestAirdrop(
    rpc: ReturnType<typeof createSolanaRpc>,
    targetAddress: Address,
    amount: bigint
): Promise<void> {
    // Use any to bypass the cluster type checking for local validator
    const signature = await (rpc as any).requestAirdrop(targetAddress, lamports(amount)).send();
    // Wait for confirmation
    await new Promise((resolve) => setTimeout(resolve, 2000));
}

// ============================================================================
// Send DM Message (uses Light Protocol SDK PackedAccounts + @solana/kit)
// ============================================================================

async function sendDmMessage(
    rpc: ReturnType<typeof createSolanaRpc>,
    lightRpc: LightRpc,
    signer: KeyPairSigner,
    recipientAddress: Address,
    threadId: Uint8Array,
    iv: Uint8Array,
    ciphertext: Uint8Array,
    nonce: Uint8Array
): Promise<{ signature: string; messageAddress: number[] }> {
    // Get tree accounts from Light SDK
    const treeAccounts = defaultTestStateTreeAccounts();

    // Derive message address
    const addressSeeds = new Uint8Array([...Buffer.from("msg"), ...threadId, ...nonce]);
    const messageAddress = deriveAddress(addressSeeds, treeAccounts.addressTree);

    // Get validity proof from Light RPC
    const proof = await lightRpc.getValidityProofV0(undefined, [
        { address: bn(messageAddress.toBytes()), tree: treeAccounts.addressTree, queue: treeAccounts.addressQueue },
    ]);

    const proofData = proof.compressedProof;
    const rootIndex = proof.rootIndices?.[0] ?? 0;

    // Use PackedAccounts helper from Light SDK
    const packedAccounts = new PackedAccounts();

    // Add Light System accounts (uses our program ID for CPI signer derivation)
    const systemAccountConfig = SystemAccountMetaConfig.new(new PublicKey(SOLCRYPT_PROGRAM_ADDRESS));
    packedAccounts.addSystemAccounts(systemAccountConfig);

    // Get indices for tree accounts by inserting them
    const addressMerkleTreePubkeyIndex = packedAccounts.insertOrGet(treeAccounts.addressTree);
    const addressQueuePubkeyIndex = packedAccounts.insertOrGet(treeAccounts.addressQueue);
    const outputStateTreeIndex = packedAccounts.insertOrGet(treeAccounts.merkleTree);

    // Convert to account metas (Light SDK returns web3.js v1 format)
    const { remainingAccounts: lightRemainingAccounts } = packedAccounts.toAccountMetas();

    // Convert web3.js v1 account metas to @solana/kit format
    const remainingAccounts: AccountMeta[] = lightRemainingAccounts.map((acc) => ({
        address: acc.pubkey.toBase58() as Address,
        role: acc.isWritable
            ? (acc.isSigner ? AccountRole.WRITABLE_SIGNER : AccountRole.WRITABLE)
            : (acc.isSigner ? AccountRole.READONLY_SIGNER : AccountRole.READONLY),
    }));

    // Build base instruction using generated helper
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
            rootIndex: rootIndex,
        },
        outputStateTreeIndex,
        threadId: Array.from(threadId),
        recipient: recipientAddress,
        iv: Array.from(iv),
        ciphertext: Array.from(ciphertext),
        nonce: Array.from(nonce),
    });

    // Create instruction with base accounts + remaining accounts
    const instruction: Instruction = {
        ...baseInstruction,
        accounts: [...baseInstruction.accounts, ...remainingAccounts],
    };

    // Send using @solana/kit
    const signature = await sendTransaction(rpc, signer, instruction);

    return { signature, messageAddress: Array.from(messageAddress.toBytes()) };
}

// ============================================================================
// Test Utilities
// ============================================================================

function assert(condition: boolean, message: string): asserts condition {
    if (!condition) throw new Error(`Assertion failed: ${message}`);
}

function assertDefined<T>(value: T | null | undefined, message: string): asserts value is T {
    if (value === null || value === undefined) throw new Error(`Assertion failed: ${message}`);
}

function assertArrayEqual(a: number[], b: number[] | Uint8Array, message: string): void {
    const bArray = Array.from(b);
    assert(a.length === bArray.length && a.every((v, i) => v === bArray[i]), message);
}

// ============================================================================
// Main Test
// ============================================================================

async function main() {
    console.log("🔐 Solcrypt E2EE DM Test Suite\n");

    const RPC_URL = process.env.RPC_URL || "http://127.0.0.1:8899";

    // Create @solana/kit RPC
    const rpc = createSolanaRpc(RPC_URL);

    // Create Light Protocol RPC
    const lightRpc = createRpc(RPC_URL, RPC_URL);

    // Generate keypairs using @solana/kit
    const payer = await generateKeyPairSigner();
    const recipient = await generateKeyPairSigner();
    const thirdUser = await generateKeyPairSigner();

    // Fund accounts
    console.log("Funding test accounts...");
    try {
        await requestAirdrop(rpc, payer.address, 10n * 1_000_000_000n);
        await requestAirdrop(rpc, recipient.address, 10n * 1_000_000_000n);
        console.log("  ✓ Accounts funded\n");
    } catch (err) {
        console.error("Failed to fund accounts. Is the test validator running?");
        console.error("Run: light test-validator (requires Light Protocol CLI)");
        throw err;
    }

    // Get secret keys for X25519 derivation
    const payerSecretKey = new Uint8Array(await crypto.subtle.exportKey("raw", payer.keyPair.privateKey));
    const recipientSecretKey = new Uint8Array(await crypto.subtle.exportKey("raw", recipient.keyPair.privateKey));

    // Derive X25519 keypairs
    console.log("Deriving X25519 keypairs from Solana signatures...");
    const senderX25519 = deriveX25519Keypair(payerSecretKey);
    const recipientX25519 = deriveX25519Keypair(recipientSecretKey);

    const senderAesKey = deriveAesKey(senderX25519.secret, recipientX25519.public);
    const recipientAesKey = deriveAesKey(recipientX25519.secret, senderX25519.public);
    assertArrayEqual(Array.from(senderAesKey), recipientAesKey, "Shared secrets must match!");
    console.log("  ✓ X25519 key exchange verified\n");

    // Test 1a: Initialize sender
    console.log("Test 1a: Initialize sender's UserAccount...");
    const senderPda = await getUserPda(payer.address);
    const initSenderIx = await createInitUserInstruction(payer, senderX25519.public);
    await sendTransaction(rpc, payer, initSenderIx);

    const senderAccount = await fetchUserAccount(rpc, senderPda);
    assertDefined(senderAccount, "Sender account should exist");
    assertArrayEqual(senderAccount.x25519Pubkey, senderX25519.public, "X25519 pubkey mismatch");
    assert(senderAccount.threads.length === 0, "Threads should be empty");
    console.log("  ✓ Sender UserAccount created\n");

    // Test 1b: Initialize recipient
    console.log("Test 1b: Initialize recipient's UserAccount...");
    const recipientPda = await getUserPda(recipient.address);
    const initRecipientIx = await createInitUserInstruction(recipient, recipientX25519.public);
    await sendTransaction(rpc, recipient, initRecipientIx);

    const recipientAccount = await fetchUserAccount(rpc, recipientPda);
    assertDefined(recipientAccount, "Recipient account should exist");
    assertArrayEqual(recipientAccount.x25519Pubkey, recipientX25519.public, "Recipient X25519 pubkey mismatch");
    console.log("  ✓ Recipient UserAccount created\n");

    // Test 2: Send encrypted DM
    console.log("Test 2: Send encrypted DM message...");
    const threadId = computeThreadId(payer.address, recipient.address);
    const nonce = randomBytes(32);
    const messageText = "Hello from Solcrypt! This is an E2EE message.";
    const plaintext = encodeTextMessage(messageText);
    console.log(`  Message: "${messageText}"`);
    console.log(`  Serialized size: ${plaintext.length} bytes`);

    const { iv, ciphertext } = encryptMessage(senderAesKey, plaintext);
    console.log(`  Ciphertext size: ${ciphertext.length} bytes (includes 16-byte auth tag)`);

    const { signature: sendSig, messageAddress } = await sendDmMessage(
        rpc,
        lightRpc,
        payer,
        recipient.address,
        threadId,
        iv,
        ciphertext,
        nonce
    );
    console.log(`  TX: ${sendSig}`);

    // Verify compressed message
    const compressedMsg = await lightRpc.getCompressedAccount(bn(messageAddress));
    assert(compressedMsg !== null, "Compressed message should exist");

    if (compressedMsg?.data?.data) {
        const msgDecoder = getMsgV1Decoder();
        const msgData = msgDecoder.decode(Buffer.from(compressedMsg.data.data));
        assertArrayEqual(msgData.threadId, threadId, "Thread ID mismatch");

        const decrypted = decryptMessage(
            recipientAesKey,
            Uint8Array.from(msgData.iv),
            Uint8Array.from(msgData.ciphertext)
        );
        const decryptedText = decodeTextMessage(decrypted);
        assert(decryptedText === messageText, `Decrypted message mismatch`);
        console.log("  ✓ Message encrypted and stored on-chain");
        console.log(`  ✓ Recipient decrypted: "${decryptedText}"`);
    }

    // Verify threads
    const senderAccountAfter = await fetchUserAccount(rpc, senderPda);
    assertDefined(senderAccountAfter, "Sender account should exist");
    assert(senderAccountAfter.threads.length === 1, "Sender should have 1 thread");
    const senderThread = senderAccountAfter.threads[0];
    assertDefined(senderThread, "Sender thread should exist");
    assert(senderThread.state === THREAD_STATE_ACCEPTED, "Sender thread should be ACCEPTED");
    console.log("  ✓ Thread auto-added to sender (ACCEPTED)");

    const recipientAccountAfter = await fetchUserAccount(rpc, recipientPda);
    assertDefined(recipientAccountAfter, "Recipient account should exist");
    assert(recipientAccountAfter.threads.length === 1, "Recipient should have 1 thread");
    const recipientThread = recipientAccountAfter.threads[0];
    assertDefined(recipientThread, "Recipient thread should exist");
    assert(recipientThread.state === THREAD_STATE_PENDING, "Recipient thread should be PENDING");
    console.log("  ✓ Thread auto-added to recipient (PENDING)\n");

    // Test 3: Accept thread
    console.log("Test 3: Recipient accepts thread...");
    const acceptIx = await createAcceptThreadInstruction(recipient, threadId);
    await sendTransaction(rpc, recipient, acceptIx);

    const recipientAccepted = await fetchUserAccount(rpc, recipientPda);
    assertDefined(recipientAccepted, "Recipient account should exist");
    const acceptedThread = recipientAccepted.threads[0];
    assertDefined(acceptedThread, "Accepted thread should exist");
    assert(acceptedThread.state === THREAD_STATE_ACCEPTED, "Thread should be ACCEPTED");
    console.log("  ✓ Recipient accepted the DM request\n");

    // Test 4: Add manual thread
    console.log("Test 4: Add thread manually...");
    const manualThreadId = computeThreadId(payer.address, thirdUser.address);
    const addThreadIx = await createAddThreadInstruction(payer, manualThreadId, THREAD_STATE_PENDING);
    await sendTransaction(rpc, payer, addThreadIx);

    const senderWithManual = await fetchUserAccount(rpc, senderPda);
    assertDefined(senderWithManual, "Sender account should exist");
    assert(senderWithManual.threads.length === 2, "Sender should have 2 threads");
    console.log("  ✓ Manual thread added\n");

    // Test 5: Accept manual thread
    console.log("Test 5: Accept manual thread...");
    const acceptManualIx = await createAcceptThreadInstruction(payer, manualThreadId);
    await sendTransaction(rpc, payer, acceptManualIx);

    const senderManualAccepted = await fetchUserAccount(rpc, senderPda);
    assertDefined(senderManualAccepted, "Sender account should exist");
    const manualThread = senderManualAccepted.threads[1];
    assertDefined(manualThread, "Manual thread should exist");
    assert(manualThread.state === THREAD_STATE_ACCEPTED, "Manual thread should be ACCEPTED");
    console.log("  ✓ Manual thread accepted\n");

    // Test 6: Remove thread
    console.log("Test 6: Remove thread...");
    const removeIx = await createRemoveThreadInstruction(payer, manualThreadId);
    await sendTransaction(rpc, payer, removeIx);

    const senderFinal = await fetchUserAccount(rpc, senderPda);
    assertDefined(senderFinal, "Sender account should exist");
    assert(senderFinal.threads.length === 1, "Sender should have 1 thread");
    console.log("  ✓ Thread removed\n");

    console.log("✅ All tests passed! E2EE messaging verified.");
}

main().catch((err) => {
    console.error("\n❌ Test failed:", err);
    process.exit(1);
});
