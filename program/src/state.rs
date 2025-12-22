use codama::{CodamaAccount, CodamaType};
use light_sdk_pinocchio::{LightDiscriminator, LightHasher};
use pinocchio::pubkey::Pubkey;
use wincode::containers;
use wincode::{
    ReadResult, SchemaRead, SchemaWrite, WriteResult,
    error::{pointer_sized_decode_error, preallocation_size_limit},
    io::{Reader, Writer},
    len::SeqLen,
};

#[derive(Debug, Clone, SchemaWrite, SchemaRead, CodamaType, Default)]
#[wincode(tag_encoding = "u8")]
#[repr(u8)]
pub enum AccountDiscriminator {
    #[default]
    UserAccount = 0,
    MsgV1 = 1,
}

/// 327 680 * ThreadEntry::SIZE is the max we can fit in a 10 MiB Solana account.
pub struct BincodeLen<const MAX_SIZE: usize = 327_680>;

impl<const MAX_SIZE: usize> SeqLen for BincodeLen<MAX_SIZE> {
    #[inline(always)]
    fn read<'de, T>(reader: &mut impl Reader<'de>) -> ReadResult<usize> {
        let len = u32::get(reader)
            .and_then(|len| usize::try_from(len).map_err(|_| pointer_sized_decode_error()))?;
        let needed = len
            .checked_mul(size_of::<T>())
            .ok_or_else(|| preallocation_size_limit(usize::MAX, MAX_SIZE))?;
        if needed > MAX_SIZE {
            return Err(preallocation_size_limit(needed, MAX_SIZE));
        }
        Ok(len)
    }

    #[inline(always)]
    fn write(writer: &mut impl Writer, len: usize) -> WriteResult<()> {
        u32::write(writer, &(len as u32))
    }

    #[inline(always)]
    fn write_bytes_needed(_len: usize) -> WriteResult<usize> {
        Ok(size_of::<u32>())
    }
}

// ============================================================================
// Account Structures
// ============================================================================

/// Encrypted DM message stored as a ZK-compressed account leaf.
///
/// Hash strategy: Minimal - only `thread_id` and `sender` are included in the
/// Merkle leaf hash. This proves message origin while reducing ZK circuit overhead.
#[derive(
    Debug, Default, Clone, SchemaWrite, SchemaRead, LightDiscriminator, LightHasher, CodamaAccount,
)]
#[codama(discriminator(field = "discriminator"))]
pub struct MsgV1 {
    /// Discriminator
    #[skip]
    #[codama(default_value = 1)]
    pub discriminator: AccountDiscriminator,
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
#[derive(Debug, Clone, SchemaWrite, SchemaRead, CodamaType)]
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
#[derive(Debug, Clone, SchemaWrite, SchemaRead, CodamaAccount)]
#[codama(discriminator(field = "discriminator"))]
#[codama(seed(type = string, value = "user"))]
#[codama(seed(name = "user_pubkey", type = public_key))]
pub struct UserAccount {
    /// Discriminator
    #[codama(default_value = 0)]
    pub discriminator: AccountDiscriminator,
    /// X25519 public key for Diffie-Hellman key exchange (set once at init)
    pub x25519_pubkey: [u8; 32],
    /// List of thread entries (thread_id + acceptance state)
    #[wincode(with = "containers::Vec<_, BincodeLen>")]
    pub threads: Vec<ThreadEntry>,
}

impl UserAccount {
    // discriminator (1) + x25519_pubkey (32) + Vec length prefix
    pub const BASE_SIZE: usize = 1 + 32 + 4;

    pub fn size_for_threads(count: usize) -> usize {
        Self::BASE_SIZE + (count * ThreadEntry::SIZE)
    }
}
