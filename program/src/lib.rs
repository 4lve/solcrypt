#![allow(unexpected_cfgs)]

use borsh::{BorshDeserialize, BorshSerialize};
use codama::{CodamaAccount, CodamaErrors, CodamaInstruction, CodamaType};
use light_macros::pubkey_array;
use light_sdk_pinocchio::{
    LightAccount, LightDiscriminator, LightHasher,
    address::v1::derive_address,
    cpi::{
        CpiAccountsConfig, CpiSigner, InvokeLightSystemProgram, LightCpiInstruction,
        v1::{CpiAccounts, LightSystemProgramCpi},
    },
    derive_light_cpi_signer,
    error::LightSdkError,
    instruction::{PackedAddressTreeInfo, ValidityProof},
};
use pinocchio::{
    ProgramResult,
    account_info::AccountInfo,
    entrypoint,
    instruction::Signer,
    program_error::ProgramError,
    pubkey::Pubkey,
    seeds,
    sysvars::{Sysvar, clock::Clock},
};
use pinocchio_system::instructions::{CreateAccount, Transfer};

// ============================================================================
// Program Constants
// ============================================================================

pub const ID: Pubkey = pubkey_array!("GRLu2hKaAiMbxpkAM1HeXzks9YeGuz18SEgXEizVvPqX");
pub const LIGHT_CPI_SIGNER: CpiSigner =
    derive_light_cpi_signer!("GRLu2hKaAiMbxpkAM1HeXzks9YeGuz18SEgXEizVvPqX");

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

entrypoint!(process_instruction);

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
#[codama(account(name = "signer", signer, writable))]
#[codama(account(name = "sender_user_account", writable))]
#[codama(account(name = "recipient_user_account", writable))]
#[codama(account(name = "system_program"))]
pub struct SendDmMessageData {
    /// ZK validity proof
    pub proof: ValidityProof,
    /// Address tree info for the new message
    pub address_tree_info: PackedAddressTreeInfo,
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
    /// Random nonce for unique address derivation
    pub nonce: [u8; 32],
}

/// Instruction data for initializing a user account PDA
#[derive(BorshSerialize, BorshDeserialize, CodamaInstruction)]
#[codama(account(name = "signer", signer, writable))]
#[codama(account(name = "user_account", writable))]
#[codama(account(name = "system_program"))]
pub struct InitUserData {
    /// X25519 public key for E2EE key derivation
    pub x25519_pubkey: [u8; 32],
}

/// Instruction data for adding a thread to user's thread list
#[derive(BorshSerialize, BorshDeserialize, CodamaInstruction)]
#[codama(account(name = "signer", signer))]
#[codama(account(name = "user_account", writable))]
#[codama(account(name = "system_program"))]
pub struct AddThreadData {
    /// Thread ID to add
    pub thread_id: [u8; 32],
    /// Initial state (0 = pending, 1 = accepted)
    pub state: u8,
}

/// Instruction data for accepting a pending thread
#[derive(BorshSerialize, BorshDeserialize, CodamaInstruction)]
#[codama(account(name = "signer", signer))]
#[codama(account(name = "user_account", writable))]
pub struct AcceptThreadData {
    /// Thread ID to accept
    pub thread_id: [u8; 32],
}

/// Instruction data for removing a thread from user's thread list
#[derive(BorshSerialize, BorshDeserialize, CodamaInstruction)]
#[codama(account(name = "signer", signer))]
#[codama(account(name = "user_account", writable))]
pub struct RemoveThreadData {
    /// Thread ID to remove
    pub thread_id: [u8; 32],
}

// ============================================================================
// Error Definitions
// ============================================================================

#[derive(Debug, Clone, CodamaErrors)]
pub enum SolcryptError {
    #[codama(error("The provided signer does not match the expected authority"))]
    Unauthorized,
    #[codama(error("Thread already exists in the user's thread list"))]
    ThreadAlreadyExists,
    #[codama(error("Thread not found in the user's thread list"))]
    ThreadNotFound,
    #[codama(error("Thread has already been accepted"))]
    ThreadAlreadyAccepted,
    #[codama(error("Message ciphertext exceeds maximum allowed size"))]
    MessageTooLarge,
    #[codama(error("PDA derivation does not match expected address"))]
    InvalidPda,
    #[codama(error("User account already initialized"))]
    UserAlreadyInitialized,
    #[codama(error("Sender has not initialized their user account"))]
    UserNotInitialized,
    #[codama(error("Recipient has not initialized their user account"))]
    RecipientNotInitialized,
}

impl From<SolcryptError> for ProgramError {
    fn from(e: SolcryptError) -> Self {
        match e {
            SolcryptError::Unauthorized => ProgramError::Custom(1),
            SolcryptError::ThreadAlreadyExists => ProgramError::Custom(2),
            SolcryptError::ThreadNotFound => ProgramError::Custom(3),
            SolcryptError::ThreadAlreadyAccepted => ProgramError::Custom(4),
            SolcryptError::MessageTooLarge => ProgramError::Custom(5),
            SolcryptError::InvalidPda => ProgramError::Custom(6),
            SolcryptError::UserAlreadyInitialized => ProgramError::Custom(7),
            SolcryptError::UserNotInitialized => ProgramError::Custom(8),
            SolcryptError::RecipientNotInitialized => ProgramError::Custom(9),
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn to_custom_error<E: Into<u64>>(e: E) -> ProgramError {
    ProgramError::Custom(u64::from(e.into()) as u32)
}

fn to_custom_error_u32<E: Into<u32>>(e: E) -> ProgramError {
    ProgramError::Custom(u32::from(e.into()))
}

/// Derives the UserAccount PDA address
pub fn get_user_pda(user: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
    pinocchio::pubkey::find_program_address(&[USER_SEED, user.as_ref()], program_id)
}

/// Helper to add a thread to a UserAccount PDA.
/// Handles resize if needed. Skips if thread already exists (idempotent).
fn add_thread_to_user_account(
    payer: &AccountInfo,
    user_pda: &AccountInfo,
    user_pubkey: &Pubkey,
    bump: u8,
    thread_id: [u8; 32],
    state: u8,
) -> ProgramResult {
    // Deserialize current account data
    let data = user_pda.try_borrow_data()?;
    let mut user_account =
        UserAccount::deserialize(&mut &data[..]).map_err(|_| ProgramError::InvalidAccountData)?;
    drop(data);

    // Skip if thread already exists (idempotent)
    if user_account
        .threads
        .iter()
        .any(|t| t.thread_id == thread_id)
    {
        return Ok(());
    }

    // Add new thread entry
    user_account.threads.push(ThreadEntry { state, thread_id });

    // Check if resize is needed
    let required_size = UserAccount::size_for_threads(user_account.threads.len());
    let current_size = user_pda.data_len();

    if required_size > current_size {
        // Need to reallocate - add capacity for more threads
        let new_size =
            UserAccount::size_for_threads(user_account.threads.len() + INITIAL_THREAD_CAPACITY);
        let rent = pinocchio::sysvars::rent::Rent::get()?;
        let new_rent = rent.minimum_balance(new_size);
        let current_lamports = user_pda.lamports();

        if new_rent > current_lamports {
            // Transfer additional lamports from payer
            let diff = new_rent - current_lamports;
            Transfer {
                from: payer,
                to: user_pda,
                lamports: diff,
            }
            .invoke()?;
        }

        // Resize the account using invoke_signed with PDA seeds
        let bump_slice = [bump];
        let signer_seeds = seeds!(USER_SEED, user_pubkey.as_ref(), &bump_slice);
        user_pda.resize(new_size)?;
        // Note: resize doesn't need invoke_signed, the program owns the account
        let _ = signer_seeds; // silence unused warning
    }

    // Serialize and write updated data
    let mut data = user_pda.try_borrow_mut_data()?;
    user_account
        .serialize(&mut &mut data[..])
        .map_err(|_| ProgramError::InvalidAccountData)?;

    Ok(())
}

// ============================================================================
// Entrypoint & Instruction Routing
// ============================================================================

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if program_id != &Pubkey::from(crate::ID) {
        return Err(ProgramError::IncorrectProgramId);
    }
    if instruction_data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let discriminator = InstructionType::try_from(instruction_data[0])
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    match discriminator {
        InstructionType::SendDmMessage => {
            let ix_data = SendDmMessageData::try_from_slice(&instruction_data[1..])
                .map_err(|_| ProgramError::InvalidInstructionData)?;
            send_dm_message(accounts, ix_data)
        }
        InstructionType::InitUser => {
            let ix_data = InitUserData::try_from_slice(&instruction_data[1..])
                .map_err(|_| ProgramError::InvalidInstructionData)?;
            init_user(accounts, ix_data)
        }
        InstructionType::AddThread => {
            let ix_data = AddThreadData::try_from_slice(&instruction_data[1..])
                .map_err(|_| ProgramError::InvalidInstructionData)?;
            add_thread(accounts, ix_data)
        }
        InstructionType::AcceptThread => {
            let ix_data = AcceptThreadData::try_from_slice(&instruction_data[1..])
                .map_err(|_| ProgramError::InvalidInstructionData)?;
            accept_thread(accounts, ix_data)
        }
        InstructionType::RemoveThread => {
            let ix_data = RemoveThreadData::try_from_slice(&instruction_data[1..])
                .map_err(|_| ProgramError::InvalidInstructionData)?;
            remove_thread(accounts, ix_data)
        }
    }
}

// ============================================================================
// Instruction Handlers
// ============================================================================

/// Creates a new encrypted DM message as a ZK-compressed account leaf.
/// Also adds the thread to both sender's and recipient's UserAccount PDAs.
pub fn send_dm_message(
    accounts: &[AccountInfo],
    instruction_data: SendDmMessageData,
) -> ProgramResult {
    let signer = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let sender_user_pda = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    let recipient_user_pda = accounts.get(2).ok_or(ProgramError::NotEnoughAccountKeys)?;
    let _system_program = accounts.get(3).ok_or(ProgramError::NotEnoughAccountKeys)?;

    let program_id = Pubkey::from(ID);

    // Verify sender's PDA
    let (expected_sender_pda, sender_bump) = get_user_pda(signer.key(), &program_id);
    if sender_user_pda.key() != &expected_sender_pda {
        return Err(SolcryptError::InvalidPda.into());
    }
    if sender_user_pda.data_is_empty() {
        return Err(SolcryptError::UserNotInitialized.into());
    }

    // Verify recipient's PDA
    let recipient_pubkey: Pubkey = instruction_data.recipient;
    let (expected_recipient_pda, recipient_bump) = get_user_pda(&recipient_pubkey, &program_id);
    if recipient_user_pda.key() != &expected_recipient_pda {
        return Err(SolcryptError::InvalidPda.into());
    }
    if recipient_user_pda.data_is_empty() {
        return Err(SolcryptError::RecipientNotInitialized.into());
    }

    // Get current timestamp for message ordering
    let clock = Clock::get()?;
    let unix_timestamp = clock.unix_timestamp;

    // Setup CPI accounts for Light Protocol (accounts after system_program)
    let config = CpiAccountsConfig::new(LIGHT_CPI_SIGNER);
    let cpi_accounts = CpiAccounts::try_new_with_config(signer, &accounts[4..], config)
        .map_err(to_custom_error_u32)?;

    // Get the address tree pubkey for address derivation
    let tree_pubkey = cpi_accounts
        .get_tree_account_info(
            instruction_data
                .address_tree_info
                .address_merkle_tree_pubkey_index as usize,
        )
        .map_err(to_custom_error_u32)?
        .key();

    // Derive unique address for this message using thread_id + nonce
    let (address, address_seed) = derive_address(
        &[b"msg", &instruction_data.thread_id, &instruction_data.nonce],
        &tree_pubkey,
        &program_id,
    );

    let new_address_params = instruction_data
        .address_tree_info
        .into_new_address_params_packed(address_seed);

    // Create the new message account
    let mut msg = LightAccount::<MsgV1>::new_init(
        &program_id,
        Some(address),
        instruction_data.output_state_tree_index,
    );

    // Populate message fields
    msg.thread_id = instruction_data.thread_id;
    msg.sender = *signer.key();
    msg.recipient = instruction_data.recipient;
    msg.unix_timestamp = unix_timestamp;
    msg.iv = instruction_data.iv;
    msg.ciphertext = instruction_data.ciphertext.clone();

    // Execute CPI to create the compressed account
    LightSystemProgramCpi::new_cpi(LIGHT_CPI_SIGNER, instruction_data.proof)
        .with_light_account(msg)
        .map_err(to_custom_error)?
        .with_new_addresses(&[new_address_params])
        .invoke(cpi_accounts)?;

    // Add thread to sender's UserAccount (state = ACCEPTED)
    add_thread_to_user_account(
        signer,
        sender_user_pda,
        signer.key(),
        sender_bump,
        instruction_data.thread_id,
        THREAD_STATE_ACCEPTED,
    )?;

    // Add thread to recipient's UserAccount (state = PENDING)
    add_thread_to_user_account(
        signer,
        recipient_user_pda,
        &recipient_pubkey,
        recipient_bump,
        instruction_data.thread_id,
        THREAD_STATE_PENDING,
    )?;

    Ok(())
}

/// Initializes a new UserAccount PDA with X25519 public key.
pub fn init_user(accounts: &[AccountInfo], instruction_data: InitUserData) -> ProgramResult {
    let signer = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let user_account_info = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    let _system_program = accounts.get(2).ok_or(ProgramError::NotEnoughAccountKeys)?;

    // Verify PDA derivation
    let program_id = Pubkey::from(ID);
    let (expected_pda, bump) = get_user_pda(signer.key(), &program_id);

    if user_account_info.key() != &expected_pda {
        return Err(SolcryptError::InvalidPda.into());
    }

    // Check if already initialized (has data)
    if !user_account_info.data_is_empty() {
        return Err(SolcryptError::UserAlreadyInitialized.into());
    }

    // Calculate required space
    let space = UserAccount::size_for_threads(INITIAL_THREAD_CAPACITY);

    // Calculate rent
    let rent_lamports = pinocchio::sysvars::rent::Rent::get()?.minimum_balance(space);

    // Create the PDA account via CPI to system program
    let bump_slice = [bump];
    let signer_seeds = seeds!(USER_SEED, signer.key().as_ref(), &bump_slice);
    CreateAccount {
        from: signer,
        to: user_account_info,
        lamports: rent_lamports,
        space: space as u64,
        owner: &program_id,
    }
    .invoke_signed(&[Signer::from(&signer_seeds)])?;

    // Initialize account data
    let user_account = UserAccount {
        discriminator: 0,
        x25519_pubkey: instruction_data.x25519_pubkey,
        threads: Vec::new(),
    };

    // Serialize and write to account
    let mut data = user_account_info.try_borrow_mut_data()?;
    user_account
        .serialize(&mut &mut data[..])
        .map_err(|_| ProgramError::InvalidAccountData)?;

    Ok(())
}

/// Adds a thread entry to the user's thread list.
pub fn add_thread(accounts: &[AccountInfo], instruction_data: AddThreadData) -> ProgramResult {
    let signer = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let user_account_info = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    let _system_program = accounts.get(2).ok_or(ProgramError::NotEnoughAccountKeys)?;

    // Verify PDA ownership
    let program_id = Pubkey::from(ID);
    let (expected_pda, _bump) = get_user_pda(signer.key(), &program_id);

    if user_account_info.key() != &expected_pda {
        return Err(SolcryptError::InvalidPda.into());
    }

    // Deserialize current account data (use deserialize to allow extra allocated space)
    let data = user_account_info.try_borrow_data()?;
    let mut user_account =
        UserAccount::deserialize(&mut &data[..]).map_err(|_| ProgramError::InvalidAccountData)?;
    drop(data);

    // Check for duplicate thread
    if user_account
        .threads
        .iter()
        .any(|t| t.thread_id == instruction_data.thread_id)
    {
        return Err(SolcryptError::ThreadAlreadyExists.into());
    }

    // Add new thread entry
    user_account.threads.push(ThreadEntry {
        state: instruction_data.state,
        thread_id: instruction_data.thread_id,
    });

    // Check if resize is needed
    let required_size = UserAccount::size_for_threads(user_account.threads.len());
    let current_size = user_account_info.data_len();

    if required_size > current_size {
        // Need to reallocate - add capacity for more threads
        let new_size =
            UserAccount::size_for_threads(user_account.threads.len() + INITIAL_THREAD_CAPACITY);
        let rent = pinocchio::sysvars::rent::Rent::get()?;
        let new_rent = rent.minimum_balance(new_size);
        let current_lamports = user_account_info.lamports();

        if new_rent > current_lamports {
            // Transfer additional lamports from signer
            let diff = new_rent - current_lamports;
            Transfer {
                from: signer,
                to: user_account_info,
                lamports: diff,
            }
            .invoke()?;
        }

        // Resize the account
        user_account_info.resize(new_size)?;
    }

    // Serialize and write updated data
    let mut data = user_account_info.try_borrow_mut_data()?;
    user_account
        .serialize(&mut &mut data[..])
        .map_err(|_| ProgramError::InvalidAccountData)?;

    Ok(())
}

/// Accepts a pending thread (changes state from 0 to 1).
pub fn accept_thread(
    accounts: &[AccountInfo],
    instruction_data: AcceptThreadData,
) -> ProgramResult {
    let signer = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let user_account_info = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;

    // Verify PDA ownership
    let program_id = Pubkey::from(ID);
    let (expected_pda, _bump) = get_user_pda(signer.key(), &program_id);

    if user_account_info.key() != &expected_pda {
        return Err(SolcryptError::InvalidPda.into());
    }

    // Deserialize current account data (use deserialize to allow extra allocated space)
    let data = user_account_info.try_borrow_data()?;
    let mut user_account =
        UserAccount::deserialize(&mut &data[..]).map_err(|_| ProgramError::InvalidAccountData)?;
    drop(data);

    // Find and update the thread
    let thread = user_account
        .threads
        .iter_mut()
        .find(|t| t.thread_id == instruction_data.thread_id)
        .ok_or(SolcryptError::ThreadNotFound)?;

    if thread.state == THREAD_STATE_ACCEPTED {
        return Err(SolcryptError::ThreadAlreadyAccepted.into());
    }

    thread.state = THREAD_STATE_ACCEPTED;

    // Serialize and write updated data
    let mut data = user_account_info.try_borrow_mut_data()?;
    user_account
        .serialize(&mut &mut data[..])
        .map_err(|_| ProgramError::InvalidAccountData)?;

    Ok(())
}

/// Removes a thread from the user's thread list.
pub fn remove_thread(
    accounts: &[AccountInfo],
    instruction_data: RemoveThreadData,
) -> ProgramResult {
    let signer = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let user_account_info = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;

    // Verify PDA ownership
    let program_id = Pubkey::from(ID);
    let (expected_pda, _bump) = get_user_pda(signer.key(), &program_id);

    if user_account_info.key() != &expected_pda {
        return Err(SolcryptError::InvalidPda.into());
    }

    // Deserialize current account data (use deserialize to allow extra allocated space)
    let data = user_account_info.try_borrow_data()?;
    let mut user_account =
        UserAccount::deserialize(&mut &data[..]).map_err(|_| ProgramError::InvalidAccountData)?;
    drop(data);

    // Find and remove the thread
    let original_len = user_account.threads.len();
    user_account
        .threads
        .retain(|t| t.thread_id != instruction_data.thread_id);

    if user_account.threads.len() == original_len {
        return Err(SolcryptError::ThreadNotFound.into());
    }

    // Serialize and write updated data
    let mut data = user_account_info.try_borrow_mut_data()?;
    user_account
        .serialize(&mut &mut data[..])
        .map_err(|_| ProgramError::InvalidAccountData)?;

    Ok(())
}
