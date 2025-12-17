/**
 * Solcrypt Cryptographic Primitives
 *
 * Provides X25519 key exchange and AES-256-GCM encryption for E2EE messaging.
 */

// @ts-ignore - noble packages have proper ESM exports
import { sha256 } from "@noble/hashes/sha256";
// @ts-ignore - noble packages have proper ESM exports
import { x25519, ed25519 } from "@noble/curves/ed25519";
// @ts-ignore - noble packages have proper ESM exports
import { gcm } from "@noble/ciphers/aes";
// @ts-ignore - noble packages have proper ESM exports
import { randomBytes } from "@noble/ciphers/webcrypto";

import { type Address, getAddressEncoder } from "@solana/kit";

// ============================================================================
// X25519 Key Derivation
// ============================================================================

export interface X25519Keypair {
    secret: Uint8Array;
    public: Uint8Array;
}

/**
 * Derives an X25519 keypair from a Solana Ed25519 secret key.
 * Uses a deterministic derivation scheme.
 */
export function deriveX25519Keypair(secretKey: Uint8Array): X25519Keypair {
    const message = new TextEncoder().encode("solcrypt-x25519-key-derivation-v1");
    const signature = ed25519.sign(message, secretKey.slice(0, 32));
    const seed = sha256(signature);
    const publicKey = x25519.getPublicKey(seed);
    return { secret: seed, public: publicKey };
}

/**
 * Derives AES-256 key from X25519 shared secret.
 */
export function deriveAesKey(ourSecret: Uint8Array, theirPublic: Uint8Array): Uint8Array {
    const sharedSecret = x25519.getSharedSecret(ourSecret, theirPublic);
    return sha256(sharedSecret);
}

// ============================================================================
// Thread ID Computation
// ============================================================================

/**
 * Computes the thread ID for a DM conversation between two parties.
 * thread_id = SHA256(min(a, b) || max(a, b) || "dm-v1")
 */
export function computeThreadId(a: Address, b: Address): Uint8Array {
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

// ============================================================================
// AES-256-GCM Encryption
// ============================================================================

export interface EncryptedMessage {
    iv: Uint8Array;
    ciphertext: Uint8Array;
}

/**
 * Encrypts a message using AES-256-GCM.
 */
export function encryptMessage(aesKey: Uint8Array, plaintext: Uint8Array): EncryptedMessage {
    const iv = randomBytes(12);
    const cipher = gcm(aesKey, iv);
    const ciphertext = cipher.encrypt(plaintext);
    return { iv, ciphertext };
}

/**
 * Decrypts a message using AES-256-GCM.
 */
export function decryptMessage(
    aesKey: Uint8Array,
    iv: Uint8Array,
    ciphertext: Uint8Array
): Uint8Array {
    const cipher = gcm(aesKey, iv);
    return cipher.decrypt(ciphertext);
}

// ============================================================================
// Message Encoding
// ============================================================================

/**
 * Encodes a text message for the protocol (Message::Text variant).
 */
export function encodeTextMessage(text: string): Uint8Array {
    const textBytes = new TextEncoder().encode(text);
    // Format: discriminator (1 byte) + length (4 bytes LE) + text
    const result = new Uint8Array(1 + 4 + textBytes.length);
    result[0] = 0; // Message::Text discriminator
    new DataView(result.buffer).setUint32(1, textBytes.length, true);
    result.set(textBytes, 5);
    return result;
}

/**
 * Decodes a text message from the protocol.
 */
export function decodeTextMessage(data: Uint8Array): string {
    if (data[0] !== 0) {
        throw new Error(`Unknown message type: ${data[0]}`);
    }
    const length = new DataView(data.buffer, data.byteOffset).getUint32(1, true);
    return new TextDecoder().decode(data.slice(5, 5 + length));
}

/**
 * Generates a random nonce for message addressing.
 */
export function generateNonce(): Uint8Array {
    return randomBytes(32);
}
