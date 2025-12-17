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

/// Initial thread capacity for new UserAccount
pub const INITIAL_THREAD_CAPACITY: usize = 0;

// ============================================================================
// Thread States
// ============================================================================

/// Thread state: pending (not yet accepted by recipient)
pub const THREAD_STATE_PENDING: u8 = 0;
/// Thread state: accepted (active conversation)
pub const THREAD_STATE_ACCEPTED: u8 = 1;
