use borsh::{BorshDeserialize, BorshSerialize};
use codama::CodamaInstruction;
use light_sdk_pinocchio::error::LightSdkError;
use pinocchio::pubkey::Pubkey;

use crate::types::{PackedAddressTreeInfoCodama, ValidityProofCodama};

// ============================================================================
// Instruction Types
// ============================================================================

#[repr(u8)]
pub enum InstructionType {
    SendDmMessage = 0,
    InitUser = 1,
    AddThread = 2,
    AcceptThread = 3,
    RemoveThread = 4,
}

impl TryFrom<u8> for InstructionType {
    type Error = LightSdkError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(InstructionType::SendDmMessage),
            1 => Ok(InstructionType::InitUser),
            2 => Ok(InstructionType::AddThread),
            3 => Ok(InstructionType::AcceptThread),
            4 => Ok(InstructionType::RemoveThread),
            _ => panic!("Invalid instruction discriminator."),
        }
    }
}

// ============================================================================
// Instruction Data Structures
// ============================================================================

/// Instruction data for sending a DM message (creates compressed MsgV1 leaf)
#[derive(BorshSerialize, BorshDeserialize, CodamaInstruction)]
#[codama(discriminator(field = "discriminator"))]
#[codama(account(name = "signer", signer, writable))]
#[codama(account(name = "sender_user_account", writable, default_value = pda(
    name = "user_account",
    seeds = [
        seed("user_pubkey", account("signer")),
    ],
)))]
#[codama(account(name = "recipient_user_account", writable, default_value = pda(
    name = "user_account",
    seeds = [
        seed("user_pubkey", argument("recipient")),
    ],
)))]
#[codama(account(name = "system_program"))]
pub struct SendDmMessageData {
    #[codama(default_value = 0)]
    pub discriminator: u8,
    /// ZK validity proof
    pub proof: ValidityProofCodama,
    /// Address tree info for the new message
    pub address_tree_info: PackedAddressTreeInfoCodama,
    /// Output state tree index
    pub output_state_tree_index: u8,
    /// Thread ID (sha256 of participants)
    pub thread_id: [u8; 32],
    /// Message recipient pubkey (for deriving their PDA)
    pub recipient: Pubkey,
    /// AES-GCM initialization vector
    pub iv: [u8; 12],
    /// Encrypted message content
    pub ciphertext: Vec<u8>,
    /// Nonce for unique address derivation
    /// MUST be all zeros for the first message in a thread, non-zero for subsequent messages
    pub nonce: [u8; 32],
}

/// Instruction data for initializing a user account PDA
#[derive(BorshSerialize, BorshDeserialize, CodamaInstruction)]
#[codama(discriminator(field = "discriminator"))]
#[codama(account(name = "signer", signer, writable))]
#[codama(account(name = "user_account", writable, default_value = pda(
    name = "user_account",
    seeds = [
        seed("user_pubkey", account("signer")),
    ],
)))]
#[codama(account(name = "system_program"))]
pub struct InitUserData {
    #[codama(default_value = 1)]
    pub discriminator: u8,
    /// X25519 public key for E2EE key derivation
    pub x25519_pubkey: [u8; 32],
}

/// Instruction data for adding a thread to user's thread list
#[derive(BorshSerialize, BorshDeserialize, CodamaInstruction)]
#[codama(discriminator(field = "discriminator"))]
#[codama(account(name = "signer", signer))]
#[codama(account(name = "user_account", writable, default_value = pda(
    name = "user_account",
    seeds = [
        seed("user_pubkey", account("signer")),
    ],
)))]
#[codama(account(name = "system_program"))]
pub struct AddThreadData {
    #[codama(default_value = 2)]
    pub discriminator: u8,
    /// Thread ID to add
    pub thread_id: [u8; 32],
    /// Initial state (0 = pending, 1 = accepted)
    pub state: u8,
}

/// Instruction data for accepting a pending thread
#[derive(BorshSerialize, BorshDeserialize, CodamaInstruction)]
#[codama(discriminator(field = "discriminator"))]
#[codama(account(name = "signer", signer))]
#[codama(account(name = "user_account", writable, default_value = pda(
    name = "user_account",
    seeds = [
        seed("user_pubkey", account("signer")),
    ],
)))]
pub struct AcceptThreadData {
    #[codama(default_value = 3)]
    pub discriminator: u8,
    /// Thread ID to accept
    pub thread_id: [u8; 32],
}

/// Instruction data for removing a thread from user's thread list
#[derive(BorshSerialize, BorshDeserialize, CodamaInstruction)]
#[codama(discriminator(field = "discriminator"))]
#[codama(account(name = "signer", signer))]
#[codama(account(name = "user_account", writable, default_value = pda(
    name = "user_account",
    seeds = [
        seed("user_pubkey", account("signer")),
    ],
)))]
pub struct RemoveThreadData {
    #[codama(default_value = 4)]
    pub discriminator: u8,
    /// Thread ID to remove
    pub thread_id: [u8; 32],
}
