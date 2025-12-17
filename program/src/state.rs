use borsh::{BorshDeserialize, BorshSerialize};
use codama::{CodamaAccount, CodamaType};
use light_sdk_pinocchio::{LightDiscriminator, LightHasher};
use pinocchio::pubkey::Pubkey;

// ============================================================================
// Account Structures
// ============================================================================

/// Encrypted DM message stored as a ZK-compressed account leaf.
///
/// Hash strategy: Minimal - only `thread_id` and `sender` are included in the
/// Merkle leaf hash. This proves message origin while reducing ZK circuit overhead.
#[derive(
    Debug,
    Default,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    LightDiscriminator,
    LightHasher,
    CodamaAccount,
    CodamaType,
)]
pub struct MsgV1 {
    /// Thread ID: sha256(min(sender,recipient) || max(sender,recipient) || "dm-v1")
    /// ZK verified - included in leaf hash
    #[hash]
    pub thread_id: [u8; 32],
    /// Sender's public key - ZK verified (proves message origin)
    #[hash]
    pub sender: Pubkey,
    /// Recipient's public key - stored but not in leaf hash
    #[skip]
    pub recipient: Pubkey,
    /// Solana unix timestamp when message was created (for ordering)
    #[skip]
    pub unix_timestamp: i64,
    /// AES-GCM initialization vector (12 bytes)
    #[skip]
    pub iv: [u8; 12],
    /// Encrypted message content
    #[skip]
    pub ciphertext: Vec<u8>,
}

/// Entry in a user's thread list with acceptance state for anti-spam.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, CodamaType)]
pub struct ThreadEntry {
    /// Thread state: 0 = pending, 1 = accepted
    pub state: u8,
    /// Thread ID
    pub thread_id: [u8; 32],
}

impl ThreadEntry {
    pub const SIZE: usize = 1 + 32; // state + thread_id
}

/// User account PDA storing X25519 public key and thread list.
///
/// PDA seeds: ["user", user_pubkey]
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, CodamaAccount)]
#[codama(discriminator(field = "discriminator"))]
#[codama(seed(type = string, value = "user"))]
#[codama(seed(name = "user_pubkey", type = public_key))]
pub struct UserAccount {
    /// Discriminator
    #[codama(default_value = 0)]
    pub discriminator: u8,
    /// X25519 public key for Diffie-Hellman key exchange (set once at init)
    pub x25519_pubkey: [u8; 32],
    /// List of thread entries (thread_id + acceptance state)
    pub threads: Vec<ThreadEntry>,
}

impl UserAccount {
    pub const BASE_SIZE: usize = 1 + 32 + 4; // bump + x25519_pubkey + vec length prefix

    pub fn size_for_threads(count: usize) -> usize {
        Self::BASE_SIZE + (count * ThreadEntry::SIZE)
    }
}
