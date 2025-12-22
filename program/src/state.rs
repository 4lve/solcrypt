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
    GroupAccount = 2,
    GroupKeyV1 = 3,
    GroupMsgV1 = 4,
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
///
/// State is a bitfield:
/// - Bit 0: accepted (0=pending, 1=accepted)
/// - Bit 1: thread type (0=DM, 1=Group)
#[derive(Debug, Clone, SchemaWrite, SchemaRead, CodamaType)]
pub struct ThreadEntry {
    /// Thread state bitflags (see constants for values)
    pub state: u8,
    /// Thread ID
    pub thread_id: [u8; 32],
}

impl ThreadEntry {
    pub const SIZE: usize = 1 + 32; // state + thread_id

    /// Returns true if the thread is accepted
    #[inline]
    pub fn is_accepted(&self) -> bool {
        self.state & 0b01 != 0
    }

    /// Returns true if this is a group thread
    #[inline]
    pub fn is_group(&self) -> bool {
        self.state & 0b10 != 0
    }
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

// ============================================================================
// Group Chat Account Structures
// ============================================================================

/// Group metadata PDA - lightweight, fixed-size.
///
/// PDA seeds: ["group", group_id]
#[derive(Debug, Clone, SchemaWrite, SchemaRead, CodamaAccount)]
#[codama(discriminator(field = "discriminator"))]
#[codama(seed(type = string, value = "group"))]
#[codama(seed(name = "group_id", type = bytes))]
pub struct GroupAccount {
    /// Discriminator
    #[codama(default_value = 2)]
    pub discriminator: AccountDiscriminator,
    /// Group ID (client-generated random 32 bytes)
    pub group_id: [u8; 32],
    /// Group owner's public key
    pub owner: Pubkey,
    /// Current key version (incremented on rotation)
    pub current_key_version: u32,
}

impl GroupAccount {
    // discriminator (1) + group_id (32) + owner (32) + current_key_version (4)
    pub const SIZE: usize = 1 + 32 + 32 + 4;
}

/// Encrypted group key for a member, stored as ZK-compressed account.
///
/// One per member per key version. Enables historical key lookup for
/// decrypting old messages after key rotation.
///
/// Address derivation: ["group-key", group_id, member, key_version.to_le_bytes()]
#[derive(Debug, Clone, SchemaWrite, SchemaRead, LightDiscriminator, LightHasher, CodamaAccount)]
#[codama(discriminator(field = "discriminator"))]
pub struct GroupKeyV1 {
    /// Discriminator
    #[skip]
    #[codama(default_value = 3)]
    pub discriminator: AccountDiscriminator,
    /// Group ID - ZK verified
    #[hash]
    pub group_id: [u8; 32],
    /// Member's public key - ZK verified
    #[hash]
    pub member: Pubkey,
    /// Key version - ZK verified
    #[hash]
    pub key_version: u32,
    /// Member role: 0=member, 1=admin, 2=owner - ZK verified (prevents spoofing)
    #[hash]
    pub role: u8,
    /// AES-256 key encrypted with member's X25519 pubkey (NaCl box: 32 key + 16 tag)
    #[skip]
    pub encrypted_aes_key: [u8; 48],
}

impl Default for GroupKeyV1 {
    fn default() -> Self {
        Self {
            discriminator: AccountDiscriminator::default(),
            group_id: [0u8; 32],
            member: Pubkey::default(),
            key_version: 0,
            role: 0,
            encrypted_aes_key: [0u8; 48],
        }
    }
}

/// Encrypted group message stored as ZK-compressed account.
///
/// Address derivation: ["group-msg", group_id, nonce]
#[derive(
    Debug, Default, Clone, SchemaWrite, SchemaRead, LightDiscriminator, LightHasher, CodamaAccount,
)]
#[codama(discriminator(field = "discriminator"))]
pub struct GroupMsgV1 {
    /// Discriminator
    #[skip]
    #[codama(default_value = 4)]
    pub discriminator: AccountDiscriminator,
    /// Group ID - ZK verified
    #[hash]
    pub group_id: [u8; 32],
    /// Sender's public key - ZK verified (proves message origin)
    #[hash]
    pub sender: Pubkey,
    /// Key version used for encryption (for decryption lookup)
    #[skip]
    pub key_version: u32,
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
