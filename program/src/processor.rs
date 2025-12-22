use crate::{
    constants::{
        GROUP_KEY_SEED, GROUP_MSG_SEED, GROUP_SEED, ID, INITIAL_THREAD_CAPACITY, LIGHT_CPI_SIGNER,
        ROLE_ADMIN, ROLE_MEMBER, ROLE_OWNER, THREAD_FLAG_ACCEPTED, THREAD_STATE_ACCEPTED,
        THREAD_STATE_GROUP_ACCEPTED, THREAD_STATE_GROUP_PENDING, THREAD_STATE_PENDING, USER_SEED,
    },
    error::SolcryptError,
    instruction::{
        AcceptGroupInviteData, AcceptThreadData, AddThreadData, CreateGroupData, InitUserData,
        InviteToGroupData, LeaveGroupData, RemoveFromGroupData, RemoveThreadData,
        RotateGroupKeyData, SendDmMessageData, SendGroupMessageData, SetMemberRoleData,
    },
    state::{GroupAccount, GroupKeyV1, GroupMsgV1, MsgV1, ThreadEntry, UserAccount},
};
use light_sdk_pinocchio::{
    LightAccount,
    address::v1::derive_address,
    cpi::{
        CpiAccountsConfig, InvokeLightSystemProgram, LightCpiInstruction,
        v1::{CpiAccounts, LightSystemProgramCpi},
    },
    instruction::{PackedAddressTreeInfo, account_meta::CompressedAccountMeta},
};
use pinocchio::{
    ProgramResult,
    account_info::AccountInfo,
    instruction::Signer,
    seeds,
    sysvars::{Sysvar, clock::Clock},
};
use pinocchio::{program_error::ProgramError, pubkey::Pubkey};
use pinocchio_system::instructions::{CreateAccount, Transfer};
use wincode::{Deserialize, Serialize};

// ============================================================================
// Helper Functions
// ============================================================================

pub fn to_custom_error<E: Into<u64>>(e: E) -> ProgramError {
    ProgramError::Custom(e.into() as u32)
}

pub fn to_custom_error_u32<E: Into<u32>>(e: E) -> ProgramError {
    ProgramError::Custom(e.into())
}

/// Derives the UserAccount PDA address
pub fn get_user_pda(user: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
    pinocchio::pubkey::find_program_address(&[USER_SEED, user.as_ref()], program_id)
}

/// Derives the GroupAccount PDA address
pub fn get_group_pda(group_id: &[u8; 32], program_id: &Pubkey) -> (Pubkey, u8) {
    pinocchio::pubkey::find_program_address(&[GROUP_SEED, group_id], program_id)
}

/// Helper to add a thread to a UserAccount PDA.
/// Handles resize if needed. Skips if thread already exists (idempotent).
#[cfg(feature = "bpf-entrypoint")]
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
        UserAccount::deserialize(&data[..]).map_err(|_| ProgramError::InvalidAccountData)?;
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
    UserAccount::serialize_into(&mut &mut data[..], &user_account)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    Ok(())
}

// ============================================================================
// Instruction Handlers
// ============================================================================

/// Creates a new encrypted DM message as a ZK-compressed account leaf.
/// Also adds the thread to both sender's and recipient's UserAccount PDAs.
///
/// ## Nonce Validation
/// The first message in a thread MUST use nonce=0 (all zeros). This enables
/// O(1) client-side lookup of the first message by deriving its address
/// deterministically. Subsequent messages must use non-zero nonces to avoid
/// address collisions.
#[inline(never)]
#[cfg(feature = "bpf-entrypoint")]
pub fn send_dm_message(
    accounts: &[AccountInfo],
    instruction_data: Box<SendDmMessageData>,
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

    // Check if this is the first message in the thread (thread doesn't exist in sender's account)
    let sender_data = sender_user_pda.try_borrow_data()?;
    let sender_account =
        UserAccount::deserialize(&sender_data[..]).map_err(|_| ProgramError::InvalidAccountData)?;
    let is_first_message = !sender_account
        .threads
        .iter()
        .any(|t| t.thread_id == instruction_data.thread_id);
    drop(sender_data);

    // Validate nonce based on whether this is the first message
    let nonce_is_zero = instruction_data.nonce.iter().all(|&b| b == 0);
    if is_first_message && !nonce_is_zero {
        return Err(SolcryptError::FirstMessageMustUseNonceZero.into());
    }
    if !is_first_message && nonce_is_zero {
        return Err(SolcryptError::SubsequentMessageCannotUseNonceZero.into());
    }

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
        tree_pubkey,
        &program_id,
    );

    let new_address_params = PackedAddressTreeInfo::from(instruction_data.address_tree_info)
        .into_new_address_params_packed(address_seed);

    // Create the new message account
    let mut msg = LightAccount::<MsgV1>::new_init(
        &program_id,
        Some(address),
        instruction_data.output_state_tree_index,
    );

    // Populate message fields
    msg.discriminator = crate::AccountDiscriminator::MsgV1;
    msg.thread_id = instruction_data.thread_id;
    msg.sender = *signer.key();
    msg.recipient = instruction_data.recipient;
    msg.unix_timestamp = unix_timestamp;
    msg.iv = instruction_data.iv;
    msg.ciphertext = instruction_data.ciphertext.clone();

    // Execute CPI to create the compressed account
    LightSystemProgramCpi::new_cpi(LIGHT_CPI_SIGNER, instruction_data.proof.into())
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
#[inline(never)]
#[cfg(feature = "bpf-entrypoint")]
pub fn init_user(accounts: &[AccountInfo], instruction_data: Box<InitUserData>) -> ProgramResult {
    use crate::AccountDiscriminator;

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
        discriminator: AccountDiscriminator::UserAccount,
        x25519_pubkey: instruction_data.x25519_pubkey,
        threads: Vec::new(),
    };

    // Serialize and write to account
    let mut data = user_account_info.try_borrow_mut_data()?;
    UserAccount::serialize_into(&mut &mut data[..], &user_account)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    Ok(())
}

/// Adds a thread entry to the user's thread list.
#[inline(never)]
#[cfg(feature = "bpf-entrypoint")]
pub fn add_thread(accounts: &[AccountInfo], instruction_data: Box<AddThreadData>) -> ProgramResult {
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
        UserAccount::deserialize(&data[..]).map_err(|_| ProgramError::InvalidAccountData)?;
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
    UserAccount::serialize_into(&mut &mut data[..], &user_account)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    Ok(())
}

/// Accepts a pending thread (changes state from 0 to 1).
#[inline(never)]
#[cfg(feature = "bpf-entrypoint")]
pub fn accept_thread(
    accounts: &[AccountInfo],
    instruction_data: Box<AcceptThreadData>,
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
        UserAccount::deserialize(&data[..]).map_err(|_| ProgramError::InvalidAccountData)?;
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
    UserAccount::serialize_into(&mut &mut data[..], &user_account)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    Ok(())
}

/// Removes a thread from the user's thread list.
#[inline(never)]
#[cfg(feature = "bpf-entrypoint")]
pub fn remove_thread(
    accounts: &[AccountInfo],
    instruction_data: Box<RemoveThreadData>,
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
        UserAccount::deserialize(&data[..]).map_err(|_| ProgramError::InvalidAccountData)?;
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
    UserAccount::serialize_into(&mut &mut data[..], &user_account)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    Ok(())
}

// ============================================================================
// Group Chat Instruction Handlers
// ============================================================================

/// Creates a new group with the signer as owner.
/// Creates GroupAccount PDA and owner's GroupKeyV1 compressed account.
#[inline(never)]
#[cfg(feature = "bpf-entrypoint")]
pub fn create_group(
    accounts: &[AccountInfo],
    instruction_data: Box<CreateGroupData>,
) -> ProgramResult {
    use crate::AccountDiscriminator;

    let signer = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let user_account_info = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    let group_account_info = accounts.get(2).ok_or(ProgramError::NotEnoughAccountKeys)?;
    let _system_program = accounts.get(3).ok_or(ProgramError::NotEnoughAccountKeys)?;

    let program_id = Pubkey::from(ID);

    // Verify user's PDA exists
    let (expected_user_pda, user_bump) = get_user_pda(signer.key(), &program_id);
    if user_account_info.key() != &expected_user_pda {
        return Err(SolcryptError::InvalidPda.into());
    }
    if user_account_info.data_is_empty() {
        return Err(SolcryptError::UserNotInitialized.into());
    }

    // Verify group PDA derivation
    let (expected_group_pda, group_bump) = get_group_pda(&instruction_data.group_id, &program_id);
    if group_account_info.key() != &expected_group_pda {
        return Err(SolcryptError::InvalidPda.into());
    }

    // Check if group already exists
    if !group_account_info.data_is_empty() {
        return Err(SolcryptError::GroupAlreadyExists.into());
    }

    // Create the GroupAccount PDA
    let space = GroupAccount::SIZE;
    let rent_lamports = pinocchio::sysvars::rent::Rent::get()?.minimum_balance(space);
    let group_bump_slice = [group_bump];
    let group_signer_seeds = seeds!(
        GROUP_SEED,
        instruction_data.group_id.as_ref(),
        &group_bump_slice
    );
    CreateAccount {
        from: signer,
        to: group_account_info,
        lamports: rent_lamports,
        space: space as u64,
        owner: &program_id,
    }
    .invoke_signed(&[Signer::from(&group_signer_seeds)])?;

    // Initialize GroupAccount data
    let group_account = GroupAccount {
        discriminator: AccountDiscriminator::GroupAccount,
        group_id: instruction_data.group_id,
        owner: *signer.key(),
        current_key_version: 1,
    };
    let mut data = group_account_info.try_borrow_mut_data()?;
    GroupAccount::serialize_into(&mut &mut data[..], &group_account)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    drop(data);

    // Setup CPI accounts for Light Protocol
    let config = CpiAccountsConfig::new(LIGHT_CPI_SIGNER);
    let cpi_accounts = CpiAccounts::try_new_with_config(signer, &accounts[4..], config)
        .map_err(to_custom_error_u32)?;

    // Get address tree pubkey
    let tree_pubkey = cpi_accounts
        .get_tree_account_info(
            instruction_data
                .address_tree_info
                .address_merkle_tree_pubkey_index as usize,
        )
        .map_err(to_custom_error_u32)?
        .key();

    // Derive address for owner's GroupKeyV1
    let key_version_bytes = 1u32.to_le_bytes();
    let (address, address_seed) = derive_address(
        &[
            GROUP_KEY_SEED,
            &instruction_data.group_id,
            signer.key().as_ref(),
            &key_version_bytes,
        ],
        tree_pubkey,
        &program_id,
    );

    let new_address_params = PackedAddressTreeInfo::from(instruction_data.address_tree_info)
        .into_new_address_params_packed(address_seed);

    // Create owner's GroupKeyV1
    let mut group_key = LightAccount::<GroupKeyV1>::new_init(
        &program_id,
        Some(address),
        instruction_data.output_state_tree_index,
    );
    group_key.discriminator = crate::AccountDiscriminator::GroupKeyV1;
    group_key.group_id = instruction_data.group_id;
    group_key.member = *signer.key();
    group_key.key_version = 1;
    group_key.role = ROLE_OWNER;
    group_key.encrypted_aes_key = instruction_data.encrypted_aes_key;

    // Execute CPI to create compressed account
    LightSystemProgramCpi::new_cpi(LIGHT_CPI_SIGNER, instruction_data.proof.into())
        .with_light_account(group_key)
        .map_err(to_custom_error)?
        .with_new_addresses(&[new_address_params])
        .invoke(cpi_accounts)?;

    // Add group thread to owner's UserAccount
    add_thread_to_user_account(
        signer,
        user_account_info,
        signer.key(),
        user_bump,
        instruction_data.group_id,
        THREAD_STATE_GROUP_ACCEPTED,
    )?;

    Ok(())
}

/// Invites a member to a group. Only owner or admin can invite.
#[inline(never)]
#[cfg(feature = "bpf-entrypoint")]
pub fn invite_to_group(
    accounts: &[AccountInfo],
    instruction_data: Box<InviteToGroupData>,
) -> ProgramResult {
    let signer = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let group_account_info = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    let invitee_user_account = accounts.get(2).ok_or(ProgramError::NotEnoughAccountKeys)?;
    let _system_program = accounts.get(3).ok_or(ProgramError::NotEnoughAccountKeys)?;

    let program_id = Pubkey::from(ID);

    // Verify group PDA
    let (expected_group_pda, _) = get_group_pda(&instruction_data.group_id, &program_id);
    if group_account_info.key() != &expected_group_pda {
        return Err(SolcryptError::InvalidPda.into());
    }

    // Read group account to get current key version
    let group_data = group_account_info.try_borrow_data()?;
    let group_account =
        GroupAccount::deserialize(&group_data[..]).map_err(|_| ProgramError::InvalidAccountData)?;
    let current_key_version = group_account.current_key_version;
    drop(group_data);

    // Verify inviter's role (must be admin or owner)
    // The inviter_role is verified through hash: if they lie about role, the hash won't match
    if instruction_data.inviter_role < ROLE_ADMIN {
        return Err(SolcryptError::NotGroupAdmin.into());
    }

    // Verify key version matches current
    if instruction_data.inviter_key_version != current_key_version {
        return Err(SolcryptError::KeyVersionMismatch.into());
    }

    // Verify invitee's user account exists
    let (expected_invitee_pda, invitee_bump) = get_user_pda(&instruction_data.invitee, &program_id);
    if invitee_user_account.key() != &expected_invitee_pda {
        return Err(SolcryptError::InvalidPda.into());
    }
    if invitee_user_account.data_is_empty() {
        return Err(SolcryptError::RecipientNotInitialized.into());
    }

    // Setup CPI accounts
    let config = CpiAccountsConfig::new(LIGHT_CPI_SIGNER);
    let cpi_accounts = CpiAccounts::try_new_with_config(signer, &accounts[4..], config)
        .map_err(to_custom_error_u32)?;

    // Get address tree pubkey for invitee's key
    let tree_pubkey = cpi_accounts
        .get_tree_account_info(
            instruction_data
                .invitee_address_tree_info
                .address_merkle_tree_pubkey_index as usize,
        )
        .map_err(to_custom_error_u32)?
        .key();

    // Reconstruct inviter's GroupKeyV1 for hash verification (proves they have valid role)
    let inviter_key = GroupKeyV1 {
        discriminator: crate::AccountDiscriminator::GroupKeyV1,
        group_id: instruction_data.group_id,
        member: *signer.key(),
        key_version: instruction_data.inviter_key_version,
        role: instruction_data.inviter_role,
        encrypted_aes_key: instruction_data.inviter_encrypted_aes_key,
    };

    // Read the inviter's account (hash is verified via ZK proof)
    let _inviter_account = LightAccount::<GroupKeyV1>::new_mut(
        &program_id,
        &CompressedAccountMeta::from(instruction_data.inviter_account_meta),
        inviter_key,
    )
    .map_err(to_custom_error)?;

    // Derive address for invitee's GroupKeyV1
    let key_version_bytes = current_key_version.to_le_bytes();
    let (address, address_seed) = derive_address(
        &[
            GROUP_KEY_SEED,
            &instruction_data.group_id,
            instruction_data.invitee.as_ref(),
            &key_version_bytes,
        ],
        tree_pubkey,
        &program_id,
    );

    let new_address_params =
        PackedAddressTreeInfo::from(instruction_data.invitee_address_tree_info)
            .into_new_address_params_packed(address_seed);

    // Create invitee's GroupKeyV1
    let mut group_key = LightAccount::<GroupKeyV1>::new_init(
        &program_id,
        Some(address),
        instruction_data.output_state_tree_index,
    );
    group_key.discriminator = crate::AccountDiscriminator::GroupKeyV1;
    group_key.group_id = instruction_data.group_id;
    group_key.member = instruction_data.invitee;
    group_key.key_version = current_key_version;
    group_key.role = ROLE_MEMBER;
    group_key.encrypted_aes_key = instruction_data.encrypted_aes_key;

    // Execute CPI - inviter's hash verification + create invitee's key
    LightSystemProgramCpi::new_cpi(LIGHT_CPI_SIGNER, instruction_data.proof.into())
        .with_light_account(_inviter_account)
        .map_err(to_custom_error)?
        .with_light_account(group_key)
        .map_err(to_custom_error)?
        .with_new_addresses(&[new_address_params])
        .invoke(cpi_accounts)?;

    // Add pending group thread to invitee's UserAccount
    add_thread_to_user_account(
        signer,
        invitee_user_account,
        &instruction_data.invitee,
        invitee_bump,
        instruction_data.group_id,
        THREAD_STATE_GROUP_PENDING,
    )?;

    Ok(())
}

/// Accepts a group invitation (updates ThreadEntry state).
#[inline(never)]
#[cfg(feature = "bpf-entrypoint")]
pub fn accept_group_invite(
    accounts: &[AccountInfo],
    instruction_data: Box<AcceptGroupInviteData>,
) -> ProgramResult {
    let signer = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let user_account_info = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;

    let program_id = Pubkey::from(ID);

    // Verify PDA ownership
    let (expected_pda, _bump) = get_user_pda(signer.key(), &program_id);
    if user_account_info.key() != &expected_pda {
        return Err(SolcryptError::InvalidPda.into());
    }

    // Deserialize user account
    let data = user_account_info.try_borrow_data()?;
    let mut user_account =
        UserAccount::deserialize(&data[..]).map_err(|_| ProgramError::InvalidAccountData)?;
    drop(data);

    // Find the pending group thread
    let thread = user_account
        .threads
        .iter_mut()
        .find(|t| t.thread_id == instruction_data.group_id && t.is_group() && !t.is_accepted())
        .ok_or(SolcryptError::InvitationNotFound)?;

    // Accept the invitation by setting the accepted bit
    thread.state |= THREAD_FLAG_ACCEPTED;

    // Serialize and write updated data
    let mut data = user_account_info.try_borrow_mut_data()?;
    UserAccount::serialize_into(&mut &mut data[..], &user_account)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    Ok(())
}

/// Removes a member from the group. Owner can remove anyone, admin can remove members.
#[inline(never)]
#[cfg(feature = "bpf-entrypoint")]
pub fn remove_from_group(
    accounts: &[AccountInfo],
    instruction_data: Box<RemoveFromGroupData>,
) -> ProgramResult {
    let signer = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let group_account_info = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    let target_user_account = accounts.get(2).ok_or(ProgramError::NotEnoughAccountKeys)?;

    let program_id = Pubkey::from(ID);

    // Verify group PDA
    let (expected_group_pda, _) = get_group_pda(&instruction_data.group_id, &program_id);
    if group_account_info.key() != &expected_group_pda {
        return Err(SolcryptError::InvalidPda.into());
    }

    // Read group account to get current key version
    let group_data = group_account_info.try_borrow_data()?;
    let group_account =
        GroupAccount::deserialize(&group_data[..]).map_err(|_| ProgramError::InvalidAccountData)?;
    let current_key_version = group_account.current_key_version;
    drop(group_data);

    // Verify signer's role (must be admin or owner)
    if instruction_data.signer_role < ROLE_ADMIN {
        return Err(SolcryptError::NotGroupAdmin.into());
    }

    // Verify signer can remove target (must have higher role, unless owner)
    if instruction_data.signer_role != ROLE_OWNER
        && instruction_data.signer_role <= instruction_data.target_role
    {
        return Err(SolcryptError::CannotRemoveHigherRole.into());
    }

    // Verify key versions match current
    if instruction_data.signer_key_version != current_key_version
        || instruction_data.target_key_version != current_key_version
    {
        return Err(SolcryptError::KeyVersionMismatch.into());
    }

    // Verify target's user account
    let (expected_target_pda, _) = get_user_pda(&instruction_data.target, &program_id);
    if target_user_account.key() != &expected_target_pda {
        return Err(SolcryptError::InvalidPda.into());
    }

    // Setup CPI accounts
    let config = CpiAccountsConfig::new(LIGHT_CPI_SIGNER);
    let cpi_accounts = CpiAccounts::try_new_with_config(signer, &accounts[3..], config)
        .map_err(to_custom_error_u32)?;

    // Reconstruct signer's GroupKeyV1 for hash verification
    let signer_key = GroupKeyV1 {
        discriminator: crate::AccountDiscriminator::GroupKeyV1,
        group_id: instruction_data.group_id,
        member: *signer.key(),
        key_version: instruction_data.signer_key_version,
        role: instruction_data.signer_role,
        encrypted_aes_key: instruction_data.signer_encrypted_aes_key,
    };

    // Read signer's account (hash is verified via ZK proof)
    let signer_account = LightAccount::<GroupKeyV1>::new_mut(
        &program_id,
        &CompressedAccountMeta::from(instruction_data.signer_account_meta),
        signer_key,
    )
    .map_err(to_custom_error)?;

    // Reconstruct target's GroupKeyV1 for closing
    let target_key = GroupKeyV1 {
        discriminator: crate::AccountDiscriminator::GroupKeyV1,
        group_id: instruction_data.group_id,
        member: instruction_data.target,
        key_version: instruction_data.target_key_version,
        role: instruction_data.target_role,
        encrypted_aes_key: instruction_data.target_encrypted_aes_key,
    };

    // Close target's GroupKeyV1 account
    let target_account = LightAccount::<GroupKeyV1>::new_close(
        &program_id,
        &CompressedAccountMeta::from(instruction_data.target_account_meta),
        target_key,
    )
    .map_err(to_custom_error)?;

    // Execute CPI - verify signer, close target
    LightSystemProgramCpi::new_cpi(LIGHT_CPI_SIGNER, instruction_data.proof.into())
        .with_light_account(signer_account)
        .map_err(to_custom_error)?
        .with_light_account(target_account)
        .map_err(to_custom_error)?
        .invoke(cpi_accounts)?;

    // Remove thread from target's UserAccount
    let data = target_user_account.try_borrow_data()?;
    let mut target_account_data =
        UserAccount::deserialize(&data[..]).map_err(|_| ProgramError::InvalidAccountData)?;
    drop(data);

    target_account_data
        .threads
        .retain(|t| t.thread_id != instruction_data.group_id);

    let mut data = target_user_account.try_borrow_mut_data()?;
    UserAccount::serialize_into(&mut &mut data[..], &target_account_data)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    Ok(())
}

/// Member voluntarily leaves the group. Owner cannot leave.
#[inline(never)]
#[cfg(feature = "bpf-entrypoint")]
pub fn leave_group(
    accounts: &[AccountInfo],
    instruction_data: Box<LeaveGroupData>,
) -> ProgramResult {
    let signer = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let user_account_info = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    let group_account_info = accounts.get(2).ok_or(ProgramError::NotEnoughAccountKeys)?;

    let program_id = Pubkey::from(ID);

    // Verify user's PDA
    let (expected_user_pda, _) = get_user_pda(signer.key(), &program_id);
    if user_account_info.key() != &expected_user_pda {
        return Err(SolcryptError::InvalidPda.into());
    }

    // Verify group PDA
    let (expected_group_pda, _) = get_group_pda(&instruction_data.group_id, &program_id);
    if group_account_info.key() != &expected_group_pda {
        return Err(SolcryptError::InvalidPda.into());
    }

    // Check that signer is not the owner (also verified via role in instruction data)
    let group_data = group_account_info.try_borrow_data()?;
    let group_account =
        GroupAccount::deserialize(&group_data[..]).map_err(|_| ProgramError::InvalidAccountData)?;
    if &group_account.owner == signer.key() {
        return Err(SolcryptError::OwnerCannotLeave.into());
    }
    let current_key_version = group_account.current_key_version;
    drop(group_data);

    // Verify the role from instruction data isn't owner (double check)
    if instruction_data.role == ROLE_OWNER {
        return Err(SolcryptError::OwnerCannotLeave.into());
    }

    // Verify key version matches current
    if instruction_data.key_version != current_key_version {
        return Err(SolcryptError::KeyVersionMismatch.into());
    }

    // Setup CPI accounts
    let config = CpiAccountsConfig::new(LIGHT_CPI_SIGNER);
    let cpi_accounts = CpiAccounts::try_new_with_config(signer, &accounts[3..], config)
        .map_err(to_custom_error_u32)?;

    // Reconstruct signer's GroupKeyV1 for closing
    let signer_key = GroupKeyV1 {
        discriminator: crate::AccountDiscriminator::GroupKeyV1,
        group_id: instruction_data.group_id,
        member: *signer.key(),
        key_version: instruction_data.key_version,
        role: instruction_data.role,
        encrypted_aes_key: instruction_data.encrypted_aes_key,
    };

    // Close signer's GroupKeyV1 account
    let signer_account = LightAccount::<GroupKeyV1>::new_close(
        &program_id,
        &CompressedAccountMeta::from(instruction_data.account_meta),
        signer_key,
    )
    .map_err(to_custom_error)?;

    // Execute CPI to close signer's GroupKeyV1
    LightSystemProgramCpi::new_cpi(LIGHT_CPI_SIGNER, instruction_data.proof.into())
        .with_light_account(signer_account)
        .map_err(to_custom_error)?
        .invoke(cpi_accounts)?;

    // Remove thread from signer's UserAccount
    let data = user_account_info.try_borrow_data()?;
    let mut user_account =
        UserAccount::deserialize(&data[..]).map_err(|_| ProgramError::InvalidAccountData)?;
    drop(data);

    user_account
        .threads
        .retain(|t| t.thread_id != instruction_data.group_id);

    let mut data = user_account_info.try_borrow_mut_data()?;
    UserAccount::serialize_into(&mut &mut data[..], &user_account)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    Ok(())
}

/// Sets a member's role. Only owner can call this.
#[inline(never)]
#[cfg(feature = "bpf-entrypoint")]
pub fn set_member_role(
    accounts: &[AccountInfo],
    instruction_data: Box<SetMemberRoleData>,
) -> ProgramResult {
    let signer = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let group_account_info = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;

    let program_id = Pubkey::from(ID);

    // Verify group PDA
    let (expected_group_pda, _) = get_group_pda(&instruction_data.group_id, &program_id);
    if group_account_info.key() != &expected_group_pda {
        return Err(SolcryptError::InvalidPda.into());
    }

    // Verify signer is owner
    let group_data = group_account_info.try_borrow_data()?;
    let group_account =
        GroupAccount::deserialize(&group_data[..]).map_err(|_| ProgramError::InvalidAccountData)?;
    if &group_account.owner != signer.key() {
        return Err(SolcryptError::NotGroupOwner.into());
    }
    let current_key_version = group_account.current_key_version;
    drop(group_data);

    // Verify key version matches current
    if instruction_data.current_key_version != current_key_version {
        return Err(SolcryptError::KeyVersionMismatch.into());
    }

    // Validate new role (can only set to MEMBER or ADMIN, not OWNER)
    if instruction_data.new_role != ROLE_MEMBER && instruction_data.new_role != ROLE_ADMIN {
        return Err(SolcryptError::InvalidRole.into());
    }

    // Setup CPI accounts
    let config = CpiAccountsConfig::new(LIGHT_CPI_SIGNER);
    let cpi_accounts = CpiAccounts::try_new_with_config(signer, &accounts[2..], config)
        .map_err(to_custom_error_u32)?;

    // Reconstruct target's current GroupKeyV1 for hash verification
    let current_key = GroupKeyV1 {
        discriminator: crate::AccountDiscriminator::GroupKeyV1,
        group_id: instruction_data.group_id,
        member: instruction_data.target,
        key_version: instruction_data.current_key_version,
        role: instruction_data.current_role,
        encrypted_aes_key: instruction_data.encrypted_aes_key,
    };

    // Update target's GroupKeyV1 with new role
    let mut target_account = LightAccount::<GroupKeyV1>::new_mut(
        &program_id,
        &CompressedAccountMeta::from(instruction_data.account_meta),
        current_key,
    )
    .map_err(to_custom_error)?;

    // Set the new role
    target_account.role = instruction_data.new_role;

    // Execute CPI to update the account
    LightSystemProgramCpi::new_cpi(LIGHT_CPI_SIGNER, instruction_data.proof.into())
        .with_light_account(target_account)
        .map_err(to_custom_error)?
        .invoke(cpi_accounts)?;

    Ok(())
}

/// Rotates the group key. Only owner can call this.
/// Creates new GroupKeyV1 accounts for all accepted members with new key version.
#[inline(never)]
#[cfg(feature = "bpf-entrypoint")]
pub fn rotate_group_key(
    accounts: &[AccountInfo],
    instruction_data: Box<RotateGroupKeyData>,
) -> ProgramResult {
    let signer = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let group_account_info = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    let _system_program = accounts.get(2).ok_or(ProgramError::NotEnoughAccountKeys)?;

    let program_id = Pubkey::from(ID);

    // Verify group PDA
    let (expected_group_pda, _) = get_group_pda(&instruction_data.group_id, &program_id);
    if group_account_info.key() != &expected_group_pda {
        return Err(SolcryptError::InvalidPda.into());
    }

    // Verify signer is owner and increment key version
    let mut group_data = group_account_info.try_borrow_mut_data()?;
    let mut group_account =
        GroupAccount::deserialize(&group_data[..]).map_err(|_| ProgramError::InvalidAccountData)?;
    if &group_account.owner != signer.key() {
        return Err(SolcryptError::NotGroupOwner.into());
    }
    group_account.current_key_version += 1;
    let new_key_version = group_account.current_key_version;
    GroupAccount::serialize_into(&mut &mut group_data[..], &group_account)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    drop(group_data);

    // Setup CPI accounts
    let config = CpiAccountsConfig::new(LIGHT_CPI_SIGNER);
    let cpi_accounts = CpiAccounts::try_new_with_config(signer, &accounts[3..], config)
        .map_err(to_custom_error_u32)?;

    // Build the CPI instruction with all new GroupKeyV1 accounts
    let mut cpi_instruction =
        LightSystemProgramCpi::new_cpi(LIGHT_CPI_SIGNER, instruction_data.proof.into());

    let key_version_bytes = new_key_version.to_le_bytes();

    for (i, key_entry) in instruction_data.new_keys.iter().enumerate() {
        let address_tree_info = instruction_data
            .address_tree_infos
            .get(i)
            .ok_or(ProgramError::InvalidInstructionData)?;

        let tree_pubkey = cpi_accounts
            .get_tree_account_info(address_tree_info.address_merkle_tree_pubkey_index as usize)
            .map_err(to_custom_error_u32)?
            .key();

        let (address, address_seed) = derive_address(
            &[
                GROUP_KEY_SEED,
                &instruction_data.group_id,
                key_entry.member.as_ref(),
                &key_version_bytes,
            ],
            tree_pubkey,
            &program_id,
        );

        let new_address_params = PackedAddressTreeInfo::from(address_tree_info.clone())
            .into_new_address_params_packed(address_seed);

        let mut group_key = LightAccount::<GroupKeyV1>::new_init(
            &program_id,
            Some(address),
            instruction_data.output_state_tree_index,
        );
        group_key.discriminator = crate::AccountDiscriminator::GroupKeyV1;
        group_key.group_id = instruction_data.group_id;
        group_key.member = key_entry.member;
        group_key.key_version = new_key_version;
        // Preserve role from previous key (passed in from client who read it from ZK account)
        group_key.role = key_entry.role;
        group_key.encrypted_aes_key = key_entry.encrypted_aes_key;

        cpi_instruction = cpi_instruction
            .with_light_account(group_key)
            .map_err(to_custom_error)?
            .with_new_addresses(&[new_address_params]);
    }

    cpi_instruction.invoke(cpi_accounts)?;

    Ok(())
}

/// Sends a message to a group.
#[inline(never)]
#[cfg(feature = "bpf-entrypoint")]
pub fn send_group_message(
    accounts: &[AccountInfo],
    instruction_data: Box<SendGroupMessageData>,
) -> ProgramResult {
    let signer = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let group_account_info = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    let _system_program = accounts.get(2).ok_or(ProgramError::NotEnoughAccountKeys)?;

    let program_id = Pubkey::from(ID);

    // Verify group PDA
    let (expected_group_pda, _) = get_group_pda(&instruction_data.group_id, &program_id);
    if group_account_info.key() != &expected_group_pda {
        return Err(SolcryptError::InvalidPda.into());
    }

    // Get current key version from group account
    let group_data = group_account_info.try_borrow_data()?;
    let group_account =
        GroupAccount::deserialize(&group_data[..]).map_err(|_| ProgramError::InvalidAccountData)?;
    let current_key_version = group_account.current_key_version;
    drop(group_data);

    // Verify sender's key version matches current (proves membership)
    if instruction_data.sender_key_version != current_key_version {
        return Err(SolcryptError::KeyVersionMismatch.into());
    }

    // Get current timestamp
    let clock = Clock::get()?;
    let unix_timestamp = clock.unix_timestamp;

    // Setup CPI accounts
    let config = CpiAccountsConfig::new(LIGHT_CPI_SIGNER);
    let cpi_accounts = CpiAccounts::try_new_with_config(signer, &accounts[3..], config)
        .map_err(to_custom_error_u32)?;

    // Reconstruct sender's GroupKeyV1 for hash verification (proves membership)
    let sender_key = GroupKeyV1 {
        discriminator: crate::AccountDiscriminator::GroupKeyV1,
        group_id: instruction_data.group_id,
        member: *signer.key(),
        key_version: instruction_data.sender_key_version,
        role: instruction_data.sender_role,
        encrypted_aes_key: instruction_data.sender_encrypted_aes_key,
    };

    // Read sender's account (hash is verified via ZK proof, proves membership)
    let sender_account = LightAccount::<GroupKeyV1>::new_mut(
        &program_id,
        &CompressedAccountMeta::from(instruction_data.sender_key_account_meta),
        sender_key,
    )
    .map_err(to_custom_error)?;

    // Get address tree pubkey for message
    let tree_pubkey = cpi_accounts
        .get_tree_account_info(
            instruction_data
                .message_address_tree_info
                .address_merkle_tree_pubkey_index as usize,
        )
        .map_err(to_custom_error_u32)?
        .key();

    // Derive address for the message
    let (address, address_seed) = derive_address(
        &[
            GROUP_MSG_SEED,
            &instruction_data.group_id,
            &instruction_data.nonce,
        ],
        tree_pubkey,
        &program_id,
    );

    let new_address_params =
        PackedAddressTreeInfo::from(instruction_data.message_address_tree_info)
            .into_new_address_params_packed(address_seed);

    // Create the message
    let mut msg = LightAccount::<GroupMsgV1>::new_init(
        &program_id,
        Some(address),
        instruction_data.output_state_tree_index,
    );
    msg.discriminator = crate::AccountDiscriminator::GroupMsgV1;
    msg.group_id = instruction_data.group_id;
    msg.sender = *signer.key();
    msg.key_version = current_key_version;
    msg.unix_timestamp = unix_timestamp;
    msg.iv = instruction_data.iv;
    msg.ciphertext = instruction_data.ciphertext.clone();

    // Execute CPI - verify sender's membership + create message
    LightSystemProgramCpi::new_cpi(LIGHT_CPI_SIGNER, instruction_data.proof.into())
        .with_light_account(sender_account)
        .map_err(to_custom_error)?
        .with_light_account(msg)
        .map_err(to_custom_error)?
        .with_new_addresses(&[new_address_params])
        .invoke(cpi_accounts)?;

    Ok(())
}
