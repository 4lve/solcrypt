use pinocchio::{
    program_error::ProgramError,
    pubkey::Pubkey,
};

use crate::constants::USER_SEED;

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
