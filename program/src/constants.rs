use light_macros::pubkey_array;
use light_sdk_pinocchio::{cpi::CpiSigner, derive_light_cpi_signer};
use pinocchio::pubkey::Pubkey;

// ============================================================================
// Program Constants
// ============================================================================

pub const ID: Pubkey = pubkey_array!("AESxu6qe2Mo5Ue8KJo33Di5UT5dW5CmJQwxqHh8dNK6y");
pub const LIGHT_CPI_SIGNER: CpiSigner =
    derive_light_cpi_signer!("AESxu6qe2Mo5Ue8KJo33Di5UT5dW5CmJQwxqHh8dNK6y");

/// Seed for UserAccount PDA derivation
pub const USER_SEED: &[u8] = b"user";

/// Seed for GroupAccount PDA derivation
pub const GROUP_SEED: &[u8] = b"group";

/// Seed for GroupKeyV1 compressed account address derivation
pub const GROUP_KEY_SEED: &[u8] = b"group-key";

/// Seed for GroupMsgV1 compressed account address derivation
pub const GROUP_MSG_SEED: &[u8] = b"group-msg";

/// Initial thread capacity for new UserAccount
pub const INITIAL_THREAD_CAPACITY: usize = 0;

// ============================================================================
// Thread State Bitflags
// ============================================================================
//
// Bit 0: accepted (0=pending, 1=accepted)
// Bit 1: thread type (0=DM, 1=Group)

/// DM thread, pending (not yet accepted by recipient)
pub const THREAD_STATE_PENDING: u8 = 0b00;
/// DM thread, accepted (active conversation)
pub const THREAD_STATE_ACCEPTED: u8 = 0b01;
/// Group thread, pending (not yet accepted by member)
pub const THREAD_STATE_GROUP_PENDING: u8 = 0b10;
/// Group thread, accepted (active group member)
pub const THREAD_STATE_GROUP_ACCEPTED: u8 = 0b11;

/// Bitflag for accepted state
pub const THREAD_FLAG_ACCEPTED: u8 = 0b01;
/// Bitflag for group thread type
pub const THREAD_FLAG_GROUP: u8 = 0b10;

// ============================================================================
// Group Member Roles
// ============================================================================

/// Regular group member - can send messages and leave
pub const ROLE_MEMBER: u8 = 0;
/// Group admin - can invite and remove non-admins
pub const ROLE_ADMIN: u8 = 1;
/// Group owner - full control, can manage admins and rotate keys
pub const ROLE_OWNER: u8 = 2;
