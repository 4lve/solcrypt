/**
 * Keypair loading utilities
 */

import { readFileSync } from "fs";
import {
    type KeyPairSigner,
    createKeyPairFromBytes,
    createSignerFromKeyPair,
} from "@solana/kit";

/**
 * Loads a KeyPairSigner from a Solana CLI-style JSON keypair file.
 * The file should contain a JSON array of 64 bytes (secret key).
 */
export async function loadKeypairFromFile(path: string): Promise<KeyPairSigner> {
    const fileContent = readFileSync(path, "utf-8");
    const secretKeyArray: number[] = JSON.parse(fileContent);

    if (!Array.isArray(secretKeyArray) || secretKeyArray.length !== 64) {
        throw new Error(
            `Invalid keypair file: expected array of 64 bytes, got ${secretKeyArray.length}`
        );
    }

    const secretKeyBytes = new Uint8Array(secretKeyArray);
    const keyPair = await createKeyPairFromBytes(secretKeyBytes);
    return await createSignerFromKeyPair(keyPair);
}

/**
 * Gets the raw secret key bytes from a KeyPairSigner.
 * Used for X25519 key derivation.
 */
export async function getSecretKeyBytes(signer: KeyPairSigner): Promise<Uint8Array> {
    return new Uint8Array(
        await crypto.subtle.exportKey("raw", signer.keyPair.privateKey)
    );
}
