use codama::{CodamaInstruction, CodamaType};
use light_sdk_pinocchio::error::LightSdkError;
use pinocchio::pubkey::Pubkey;
use wincode::{SchemaRead, SchemaWrite};

use crate::types::{CompressedAccountMetaCodama, PackedAddressTreeInfoCodama, ValidityProofCodama};

// ============================================================================
// Instruction Types
// ============================================================================

#[derive(Debug, Clone, SchemaWrite, SchemaRead, CodamaType, Default)]
#[wincode(tag_encoding = "u8")]
#[repr(u8)]
pub enum InstructionType {
    #[default]
    SendDmMessage = 0,
    InitUser = 1,
    AddThread = 2,
    AcceptThread = 3,
    RemoveThread = 4,
    // Group chat instructions
    CreateGroup = 5,
    InviteToGroup = 6,
    AcceptGroupInvite = 7,
    RemoveFromGroup = 8,
    LeaveGroup = 9,
    SetMemberRole = 10,
    RotateGroupKey = 11,
    SendGroupMessage = 12,
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
            5 => Ok(InstructionType::CreateGroup),
            6 => Ok(InstructionType::InviteToGroup),
            7 => Ok(InstructionType::AcceptGroupInvite),
            8 => Ok(InstructionType::RemoveFromGroup),
            9 => Ok(InstructionType::LeaveGroup),
            10 => Ok(InstructionType::SetMemberRole),
            11 => Ok(InstructionType::RotateGroupKey),
            12 => Ok(InstructionType::SendGroupMessage),
            _ => panic!("Invalid instruction discriminator."),
        }
    }
}

// ============================================================================
// Instruction Data Structures
// ============================================================================

/// Instruction data for sending a DM message (creates compressed MsgV1 leaf)
#[derive(SchemaWrite, SchemaRead, CodamaInstruction)]
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
    pub discriminator: InstructionType,
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
#[derive(SchemaWrite, SchemaRead, CodamaInstruction)]
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
    pub discriminator: InstructionType,
    /// X25519 public key for E2EE key derivation
    pub x25519_pubkey: [u8; 32],
}

/// Instruction data for adding a thread to user's thread list
#[derive(SchemaWrite, SchemaRead, CodamaInstruction)]
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
    pub discriminator: InstructionType,
    /// Thread ID to add
    pub thread_id: [u8; 32],
    /// Initial state (0 = pending, 1 = accepted)
    pub state: u8,
}

/// Instruction data for accepting a pending thread
#[derive(SchemaWrite, SchemaRead, CodamaInstruction)]
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
    pub discriminator: InstructionType,
    /// Thread ID to accept
    pub thread_id: [u8; 32],
}

/// Instruction data for removing a thread from user's thread list
#[derive(SchemaWrite, SchemaRead, CodamaInstruction)]
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
    pub discriminator: InstructionType,
    /// Thread ID to remove
    pub thread_id: [u8; 32],
}

// ============================================================================
// Group Chat Instruction Data Structures
// ============================================================================

/// Instruction data for creating a new group
#[derive(SchemaWrite, SchemaRead, CodamaInstruction)]
#[codama(discriminator(field = "discriminator"))]
#[codama(account(name = "signer", signer, writable))]
#[codama(account(name = "user_account", writable, default_value = pda(
    name = "user_account",
    seeds = [
        seed("user_pubkey", account("signer")),
    ],
)))]
#[codama(account(name = "group_account", writable, default_value = pda(
    name = "group_account",
    seeds = [
        seed("group_id", argument("group_id")),
    ],
)))]
#[codama(account(name = "system_program"))]
pub struct CreateGroupData {
    #[codama(default_value = 5)]
    pub discriminator: InstructionType,
    /// ZK validity proof for creating GroupKeyV1
    pub proof: ValidityProofCodama,
    /// Address tree info for the owner's GroupKeyV1
    pub address_tree_info: PackedAddressTreeInfoCodama,
    /// Output state tree index
    pub output_state_tree_index: u8,
    /// Group ID (client-generated random 32 bytes)
    pub group_id: [u8; 32],
    /// Owner's encrypted AES key (NaCl box encrypted)
    pub encrypted_aes_key: [u8; 48],
}

/// Instruction data for inviting a member to a group
#[derive(SchemaWrite, SchemaRead, CodamaInstruction)]
#[codama(discriminator(field = "discriminator"))]
#[codama(account(name = "signer", signer, writable))]
#[codama(account(name = "group_account", default_value = pda(
    name = "group_account",
    seeds = [
        seed("group_id", argument("group_id")),
    ],
)))]
#[codama(account(name = "invitee_user_account", writable, default_value = pda(
    name = "user_account",
    seeds = [
        seed("user_pubkey", argument("invitee")),
    ],
)))]
#[codama(account(name = "system_program"))]
pub struct InviteToGroupData {
    #[codama(default_value = 6)]
    pub discriminator: InstructionType,
    /// ZK validity proof for reading inviter's GroupKeyV1 and creating invitee's GroupKeyV1
    pub proof: ValidityProofCodama,
    /// Compressed account meta for inviter's GroupKeyV1 (for role verification)
    pub inviter_account_meta: CompressedAccountMetaCodama,
    /// Inviter's current GroupKeyV1 data (role is hashed for verification)
    pub inviter_key_version: u32,
    pub inviter_role: u8,
    pub inviter_encrypted_aes_key: [u8; 48],
    /// Address tree info for the new member's GroupKeyV1
    pub invitee_address_tree_info: PackedAddressTreeInfoCodama,
    /// Output state tree index
    pub output_state_tree_index: u8,
    /// Group ID
    pub group_id: [u8; 32],
    /// Invitee's public key
    pub invitee: Pubkey,
    /// Invitee's encrypted AES key (NaCl box encrypted with their X25519 pubkey)
    pub encrypted_aes_key: [u8; 48],
}

/// Instruction data for accepting a group invitation
#[derive(SchemaWrite, SchemaRead, CodamaInstruction)]
#[codama(discriminator(field = "discriminator"))]
#[codama(account(name = "signer", signer))]
#[codama(account(name = "user_account", writable, default_value = pda(
    name = "user_account",
    seeds = [
        seed("user_pubkey", account("signer")),
    ],
)))]
pub struct AcceptGroupInviteData {
    #[codama(default_value = 7)]
    pub discriminator: InstructionType,
    /// Group ID to accept invitation for
    pub group_id: [u8; 32],
}

/// Instruction data for removing a member from a group (admin/owner action)
#[derive(SchemaWrite, SchemaRead, CodamaInstruction)]
#[codama(discriminator(field = "discriminator"))]
#[codama(account(name = "signer", signer, writable))]
#[codama(account(name = "group_account", default_value = pda(
    name = "group_account",
    seeds = [
        seed("group_id", argument("group_id")),
    ],
)))]
#[codama(account(name = "target_user_account", writable, default_value = pda(
    name = "user_account",
    seeds = [
        seed("user_pubkey", argument("target")),
    ],
)))]
pub struct RemoveFromGroupData {
    #[codama(default_value = 8)]
    pub discriminator: InstructionType,
    /// ZK validity proof for reading signer's GroupKeyV1 and closing target's GroupKeyV1
    pub proof: ValidityProofCodama,
    /// Compressed account meta for signer's GroupKeyV1 (for role verification)
    pub signer_account_meta: CompressedAccountMetaCodama,
    /// Signer's current GroupKeyV1 data
    pub signer_key_version: u32,
    pub signer_role: u8,
    pub signer_encrypted_aes_key: [u8; 48],
    /// Compressed account meta for target's GroupKeyV1 (to close)
    pub target_account_meta: CompressedAccountMetaCodama,
    /// Target's current GroupKeyV1 data (needed to verify hash before closing)
    pub target_key_version: u32,
    pub target_role: u8,
    pub target_encrypted_aes_key: [u8; 48],
    /// Group ID
    pub group_id: [u8; 32],
    /// Target member to remove
    pub target: Pubkey,
}

/// Instruction data for leaving a group (self action)
#[derive(SchemaWrite, SchemaRead, CodamaInstruction)]
#[codama(discriminator(field = "discriminator"))]
#[codama(account(name = "signer", signer))]
#[codama(account(name = "user_account", writable, default_value = pda(
    name = "user_account",
    seeds = [
        seed("user_pubkey", account("signer")),
    ],
)))]
#[codama(account(name = "group_account", default_value = pda(
    name = "group_account",
    seeds = [
        seed("group_id", argument("group_id")),
    ],
)))]
pub struct LeaveGroupData {
    #[codama(default_value = 9)]
    pub discriminator: InstructionType,
    /// ZK validity proof for closing signer's GroupKeyV1
    pub proof: ValidityProofCodama,
    /// Compressed account meta for signer's GroupKeyV1 (to close)
    pub account_meta: CompressedAccountMetaCodama,
    /// Signer's current GroupKeyV1 data (needed to verify hash before closing)
    pub key_version: u32,
    pub role: u8,
    pub encrypted_aes_key: [u8; 48],
    /// Group ID
    pub group_id: [u8; 32],
}

/// Instruction data for changing a member's role (owner only)
#[derive(SchemaWrite, SchemaRead, CodamaInstruction)]
#[codama(discriminator(field = "discriminator"))]
#[codama(account(name = "signer", signer))]
#[codama(account(name = "group_account", default_value = pda(
    name = "group_account",
    seeds = [
        seed("group_id", argument("group_id")),
    ],
)))]
pub struct SetMemberRoleData {
    #[codama(default_value = 10)]
    pub discriminator: InstructionType,
    /// ZK validity proof for updating target's GroupKeyV1
    pub proof: ValidityProofCodama,
    /// Compressed account meta for target's GroupKeyV1
    pub account_meta: CompressedAccountMetaCodama,
    /// Target's current GroupKeyV1 data (needed to verify hash before updating)
    pub current_key_version: u32,
    pub current_role: u8,
    pub encrypted_aes_key: [u8; 48],
    /// Group ID
    pub group_id: [u8; 32],
    /// Target member pubkey
    pub target: Pubkey,
    /// New role (0=member, 1=admin)
    pub new_role: u8,
}

/// Entry for a single member's new encrypted key during rotation
#[derive(Debug, Clone, SchemaWrite, SchemaRead, CodamaType)]
pub struct RotationKeyEntry {
    /// Member's public key
    pub member: Pubkey,
    /// Member's role (preserved from previous key)
    pub role: u8,
    /// New encrypted AES key for this member
    pub encrypted_aes_key: [u8; 48],
}

/// Instruction data for rotating the group key (owner only)
#[derive(SchemaWrite, SchemaRead, CodamaInstruction)]
#[codama(discriminator(field = "discriminator"))]
#[codama(account(name = "signer", signer, writable))]
#[codama(account(name = "group_account", writable, default_value = pda(
    name = "group_account",
    seeds = [
        seed("group_id", argument("group_id")),
    ],
)))]
#[codama(account(name = "system_program"))]
pub struct RotateGroupKeyData {
    #[codama(default_value = 11)]
    pub discriminator: InstructionType,
    /// ZK validity proof for creating new GroupKeyV1 accounts
    pub proof: ValidityProofCodama,
    /// Output state tree index for all new GroupKeyV1 accounts
    pub output_state_tree_index: u8,
    /// Group ID
    pub group_id: [u8; 32],
    /// New encrypted keys for all accepted members (includes role)
    pub new_keys: Vec<RotationKeyEntry>,
    /// Address tree infos for each new GroupKeyV1 (same order as new_keys)
    pub address_tree_infos: Vec<PackedAddressTreeInfoCodama>,
}

/// Instruction data for sending a message to a group
#[derive(SchemaWrite, SchemaRead, CodamaInstruction)]
#[codama(discriminator(field = "discriminator"))]
#[codama(account(name = "signer", signer, writable))]
#[codama(account(name = "group_account", default_value = pda(
    name = "group_account",
    seeds = [
        seed("group_id", argument("group_id")),
    ],
)))]
#[codama(account(name = "system_program"))]
pub struct SendGroupMessageData {
    #[codama(default_value = 12)]
    pub discriminator: InstructionType,
    /// ZK validity proof for verifying sender's GroupKeyV1 and creating GroupMsgV1
    pub proof: ValidityProofCodama,
    /// Compressed account meta for sender's GroupKeyV1 (for membership verification)
    pub sender_key_account_meta: CompressedAccountMetaCodama,
    /// Sender's current GroupKeyV1 data (proves membership at current key_version)
    pub sender_key_version: u32,
    pub sender_role: u8,
    pub sender_encrypted_aes_key: [u8; 48],
    /// Address tree info for the new message
    pub message_address_tree_info: PackedAddressTreeInfoCodama,
    /// Output state tree index
    pub output_state_tree_index: u8,
    /// Group ID
    pub group_id: [u8; 32],
    /// AES-GCM initialization vector
    pub iv: [u8; 12],
    /// Encrypted message content
    pub ciphertext: Vec<u8>,
    /// Nonce for unique address derivation (0 for first message)
    pub nonce: [u8; 32],
}
