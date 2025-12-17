# Solcrypt

**End-to-End Encrypted Messaging on Solana with ZK-Compressed Accounts**

Solcrypt is a Solana program that enables cost-efficient, fully on-chain end-to-end encrypted (E2EE) messaging using zero-knowledge compressed accounts. Messages are stored on-chain but remain private through client-side encryption, while leveraging ZK compression to minimize storage costs.

## 🎯 Overview

Solcrypt combines:
- **E2EE Security**: X25519 key exchange + AES-256-GCM encryption
- **ZK Compression**: Light Protocol for ultra-low-cost on-chain storage
- **On-Chain Everything**: All messages stored on-chain (encrypted)
- **Client-Driven Indexing**: No shared write locks, scalable architecture

## 🏗️ Architecture

### Account Types

#### 1. `MsgV1` (ZK-Compressed Account)
Encrypted DM messages stored as compressed account leaves:
- **ZK-Verified Fields** (in Merkle leaf hash):
  - `thread_id`: SHA256(min(sender, recipient) || max(sender, recipient) || "dm-v1")
  - `sender`: Message origin (proven via ZK)
- **Stored Fields** (not hashed, for indexing/decryption):
  - `recipient`: For client-side filtering
  - `unix_timestamp`: Message ordering
  - `iv`: AES-GCM initialization vector (12 bytes)
  - `ciphertext`: Encrypted message content (AES-256-GCM)

#### 2. `UserAccount` (PDA)
Regular PDA account storing user metadata:
- `x25519_pubkey`: Public key for E2EE key derivation
- `threads`: List of `ThreadEntry` (thread_id + state)
- **PDA Seeds**: `["user", user_pubkey]`

### Thread Management

Threads have two states for anti-spam:
- **`PENDING` (0)**: DM request not yet accepted
- **`ACCEPTED` (1)**: Active conversation

When Alice sends the first DM to Bob:
- Thread automatically added to Alice's list as `ACCEPTED`
- Thread automatically added to Bob's list as `PENDING`
- Bob can accept via `AcceptThread` instruction

## 🔐 Cryptography

### Key Derivation Flow

1. **X25519 Keypair from Solana Signature**:
   ```
   message = "solcrypt-x25519-key-derivation-v1"
   signature = sign(message, solana_keypair)
   seed = SHA256(signature)
   x25519_secret = X25519SecretKey::from(seed)
   x25519_public = X25519PublicKey::from(x25519_secret)
   ```

2. **Shared Secret (Diffie-Hellman)**:
   ```
   shared_secret = x25519_dh(alice_secret, bob_public)
   aes_key = SHA256(shared_secret)
   ```

3. **Message Encryption**:
   ```
   iv = random_12_bytes()
   ciphertext = AES256_GCM.encrypt(aes_key, iv, plaintext)
   ```

[Add contribution guidelines]

## 📚 References

- [Light Protocol](https://www.zkcompression.com/) - ZK-compressed accounts
- [X25519](https://datatracker.ietf.org/doc/html/rfc7748) - Elliptic curve Diffie-Hellman
- [AES-GCM](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) - Authenticated encryption
