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

/// Generate a random group ID
pub fn random_group_id() -> [u8; 32] {
    random_nonce()
}

/// Generate a random AES-256 key for group encryption
pub fn generate_group_aes_key() -> [u8; 32] {
    use aes_gcm::aead::rand_core::RngCore;
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Encrypt a 32-byte AES key using AES-256-GCM key wrapping.
/// Uses X25519 ECDH to derive a wrapping key, then AES-GCM to encrypt.
///
/// Layout of 48-byte output:
/// - Bytes 0-47: AES-GCM ciphertext (32 bytes) + auth tag (16 bytes) = 48 bytes
///
/// The nonce is derived deterministically from the shared secret (no need to store it).
pub fn encrypt_group_key_for_member(
    group_aes_key: &[u8; 32],
    our_secret: &X25519SecretKey,
    their_public: &X25519PublicKey,
) -> [u8; 48] {
    // Derive shared secret via X25519 ECDH
    let shared_secret = our_secret.diffie_hellman(their_public);

    // Derive wrapping key (32 bytes for AES-256)
    let mut key_hasher = Sha256::new();
    key_hasher.update(shared_secret.as_bytes());
    key_hasher.update(b"solcrypt-group-key-wrap-v1-key");
    let wrapping_key: [u8; 32] = key_hasher.finalize().into();

    // Derive nonce deterministically (12 bytes for AES-GCM)
    // This is safe because we use a unique wrapping_key per recipient
    let mut nonce_hasher = Sha256::new();
    nonce_hasher.update(shared_secret.as_bytes());
    nonce_hasher.update(b"solcrypt-group-key-wrap-v1-nonce");
    let nonce_hash: [u8; 32] = nonce_hasher.finalize().into();
    let nonce: [u8; 12] = nonce_hash[..12].try_into().unwrap();

    // Encrypt using AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&wrapping_key).expect("Invalid key length");
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), group_aes_key.as_ref())
        .expect("AES-GCM encryption failed");

    // ciphertext = 32 bytes plaintext + 16 bytes auth tag = 48 bytes exactly
    let mut result = [0u8; 48];
    result.copy_from_slice(&ciphertext);
    result
}

/// Decrypt a 48-byte encrypted group key using AES-256-GCM.
pub fn decrypt_group_key(
    encrypted_key: &[u8; 48],
    our_secret: &X25519SecretKey,
    their_public: &X25519PublicKey,
) -> Result<[u8; 32]> {
    // Derive shared secret via X25519 ECDH
    let shared_secret = our_secret.diffie_hellman(their_public);

    // Derive wrapping key (same as encryption)
    let mut key_hasher = Sha256::new();
    key_hasher.update(shared_secret.as_bytes());
    key_hasher.update(b"solcrypt-group-key-wrap-v1-key");
    let wrapping_key: [u8; 32] = key_hasher.finalize().into();

    // Derive nonce deterministically (same as encryption)
    let mut nonce_hasher = Sha256::new();
    nonce_hasher.update(shared_secret.as_bytes());
    nonce_hasher.update(b"solcrypt-group-key-wrap-v1-nonce");
    let nonce_hash: [u8; 32] = nonce_hasher.finalize().into();
    let nonce: [u8; 12] = nonce_hash[..12].try_into().unwrap();

    // Decrypt using AES-256-GCM (authenticates and decrypts)
    let cipher = Aes256Gcm::new_from_slice(&wrapping_key).context("Invalid key length")?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), encrypted_key.as_ref())
        .map_err(|_| {
            anyhow::anyhow!("Group key decryption failed - invalid key or tampered data")
        })?;

    let mut aes_key = [0u8; 32];
    aes_key.copy_from_slice(&plaintext);
    Ok(aes_key)
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
