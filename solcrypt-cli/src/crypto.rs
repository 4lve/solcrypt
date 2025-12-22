//! Cryptographic primitives for Solcrypt E2EE messaging.
//!
//! This module provides:
//! - X25519 keypair derivation from Solana signatures
//! - Thread ID computation for DM conversations
//! - AES-256-GCM encryption/decryption
//! - Message content protocol types

use aes_gcm::{
    aead::{Aead, OsRng},
    Aes256Gcm, KeyInit, Nonce,
};
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use solana_sdk::{pubkey::Pubkey, signature::Keypair, signer::Signer};
use solcrypt_program::ClientSideMessage;
use wincode::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

/// Derives an X25519 keypair from a Solana keypair.
///
/// Process:
/// 1. Sign a domain-specific message with the Solana keypair
/// 2. Hash the signature with SHA256 to get a 32-byte seed
/// 3. Use the seed to create an X25519 secret key
pub fn derive_x25519_keypair(solana_keypair: &Keypair) -> (X25519SecretKey, X25519PublicKey) {
    // Sign a domain-specific message to derive the X25519 seed
    let message = b"solcrypt-x25519-key-derivation-v1";
    let signature = solana_keypair.sign_message(message);

    // Hash the signature to get a 32-byte seed
    let mut hasher = Sha256::new();
    hasher.update(signature.as_ref());
    let seed: [u8; 32] = hasher.finalize().into();

    // Create X25519 keypair from seed
    let secret = X25519SecretKey::from(seed);
    let public = X25519PublicKey::from(&secret);

    (secret, public)
}

/// Computes the thread ID for a DM conversation between two parties.
///
/// thread_id = SHA256(min(a, b) || max(a, b) || "dm-v1")
///
/// This ensures both parties compute the same thread ID regardless of
/// who initiates the conversation.
pub fn compute_thread_id(a: &Pubkey, b: &Pubkey) -> [u8; 32] {
    let a_bytes = a.to_bytes();
    let b_bytes = b.to_bytes();

    // Order deterministically
    let (first, second) = if a_bytes < b_bytes {
        (&a_bytes, &b_bytes)
    } else {
        (&b_bytes, &a_bytes)
    };

    // SHA256(first || second || "dm-v1")
    let mut hasher = Sha256::new();
    hasher.update(first);
    hasher.update(second);
    hasher.update(b"dm-v1");
    hasher.finalize().into()
}

/// Derives a shared AES-256 key using X25519 Diffie-Hellman.
pub fn derive_aes_key(our_secret: &X25519SecretKey, their_public: &X25519PublicKey) -> [u8; 32] {
    let shared_secret = our_secret.diffie_hellman(their_public);

    // Hash the shared secret to derive the AES key
    let mut hasher = Sha256::new();
    hasher.update(shared_secret.as_bytes());
    hasher.finalize().into()
}

/// Encrypts a message using AES-256-GCM.
/// Returns (iv, ciphertext).
pub fn encrypt_message(aes_key: &[u8; 32], plaintext: &[u8]) -> Result<([u8; 12], Vec<u8>)> {
    use aes_gcm::aead::rand_core::RngCore;

    let cipher =
        Aes256Gcm::new_from_slice(aes_key).context("Failed to create AES-256-GCM cipher")?;

    // Generate random IV
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let nonce = Nonce::from_slice(&iv);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    Ok((iv, ciphertext))
}

/// Decrypts a message using AES-256-GCM.
pub fn decrypt_message(aes_key: &[u8; 32], iv: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher =
        Aes256Gcm::new_from_slice(aes_key).context("Failed to create AES-256-GCM cipher")?;
    let nonce = Nonce::from_slice(iv);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))
}

/// Generate a random nonce for message address derivation
pub fn random_nonce() -> [u8; 32] {
    use aes_gcm::aead::rand_core::RngCore;
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

pub trait ClientSideMessageExt {
    fn text(content: impl Into<String>) -> Self;
    fn encrypt(&self, aes_key: &[u8; 32]) -> Result<([u8; 12], Vec<u8>)>;
    fn decrypt(aes_key: &[u8; 32], iv: &[u8; 12], ciphertext: &[u8]) -> Result<ClientSideMessage>;
    fn display_text(&self) -> &str;
}

impl ClientSideMessageExt for ClientSideMessage {
    /// Create a text message
    fn text(content: impl Into<String>) -> Self {
        ClientSideMessage::Text(content.into())
    }

    /// Serialize and encrypt the message
    fn encrypt(&self, aes_key: &[u8; 32]) -> Result<([u8; 12], Vec<u8>)> {
        let plaintext =
            ClientSideMessage::serialize(self).context("Failed to serialize message")?;
        encrypt_message(aes_key, &plaintext)
    }

    /// Decrypt and deserialize a message
    fn decrypt(aes_key: &[u8; 32], iv: &[u8; 12], ciphertext: &[u8]) -> Result<Self> {
        let plaintext = decrypt_message(aes_key, iv, ciphertext)?;
        ClientSideMessage::deserialize(plaintext.as_slice())
            .context("Failed to deserialize message")
    }

    /// Get the display text for this message
    fn display_text(&self) -> &str {
        match self {
            ClientSideMessage::Text(s) => s,
            ClientSideMessage::Image(url) => url,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thread_id_is_symmetric() {
        let a = Pubkey::new_unique();
        let b = Pubkey::new_unique();

        let thread_id_ab = compute_thread_id(&a, &b);
        let thread_id_ba = compute_thread_id(&b, &a);

        assert_eq!(thread_id_ab, thread_id_ba);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let message = ClientSideMessage::text("Hello, World!");

        let (iv, ciphertext) = message.encrypt(&key).unwrap();
        let decrypted = ClientSideMessage::decrypt(&key, &iv, &ciphertext).unwrap();

        assert_eq!(message, decrypted);
    }
}
