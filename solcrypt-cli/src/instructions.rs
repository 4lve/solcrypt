//! Transaction builders for Solcrypt program instructions.
//!
//! Provides instruction building for:
//! - InitUser: Initialize user account with X25519 public key
//! - SendDmMessage: Send an encrypted DM message
//! - AcceptThread: Accept a pending thread/chat request

use anyhow::{Context, Result};
use light_client::{
    indexer::{AddressWithTree, Indexer, TreeInfo},
    rpc::Rpc,
};
use light_sdk::{
    address::v1::derive_address,
    instruction::{PackedAccounts, SystemAccountMetaConfig},
};
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signer::Signer,
    transaction::Transaction,
};
use solcrypt_program::{
    AcceptGroupInviteData, AcceptThreadData, AddThreadData, CreateGroupData, InitUserData,
    InstructionType, InviteToGroupData, RemoveThreadData, SendDmMessageData, SendGroupMessageData,
    GROUP_KEY_SEED,
};
use wincode::Serialize;

use crate::client::SolcryptClient;
use crate::crypto::random_nonce;

/// System program ID
const SYSTEM_PROGRAM_ID: Pubkey = solana_sdk::pubkey!("11111111111111111111111111111111");

/// Build an InitUser instruction
pub fn build_init_user_instruction(
    signer: &Pubkey,
    x25519_pubkey: [u8; 32],
) -> Result<Instruction> {
    let (user_pda, _bump) = SolcryptClient::get_user_pda(signer);

    let instruction_data = InitUserData {
        discriminator: InstructionType::InitUser,
        x25519_pubkey,
    };
    let data =
        InitUserData::serialize(&instruction_data).context("Failed to serialize InitUserData")?;

    let accounts = vec![
        AccountMeta::new(*signer, true),
        AccountMeta::new(user_pda, false),
        AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
    ];

    Ok(Instruction {
        program_id: solcrypt_program::ID.into(),
        accounts,
        data,
    })
}

/// Build an AcceptThread instruction
pub fn build_accept_thread_instruction(
    signer: &Pubkey,
    thread_id: [u8; 32],
) -> Result<Instruction> {
    let (user_pda, _bump) = SolcryptClient::get_user_pda(signer);

    let instruction_data = AcceptThreadData {
        discriminator: InstructionType::AcceptThread,
        thread_id,
    };
    let data = AcceptThreadData::serialize(&instruction_data)
        .context("Failed to serialize AcceptThreadData")?;

    let accounts = vec![
        AccountMeta::new(*signer, true),
        AccountMeta::new(user_pda, false),
    ];

    Ok(Instruction {
        program_id: solcrypt_program::ID.into(),
        accounts,
        data,
    })
}

/// Build a RemoveThread instruction
pub fn build_remove_thread_instruction(
    signer: &Pubkey,
    thread_id: [u8; 32],
) -> Result<Instruction> {
    let (user_pda, _bump) = SolcryptClient::get_user_pda(signer);

    let instruction_data = RemoveThreadData {
        discriminator: InstructionType::RemoveThread,
        thread_id,
    };
    let data = RemoveThreadData::serialize(&instruction_data)
        .context("Failed to serialize RemoveThreadData")?;

    let accounts = vec![
        AccountMeta::new(*signer, true),
        AccountMeta::new(user_pda, false),
    ];

    Ok(Instruction {
        program_id: solcrypt_program::ID.into(),
        accounts,
        data,
    })
}

/// Build an AddThread instruction
pub fn build_add_thread_instruction(
    signer: &Pubkey,
    thread_id: [u8; 32],
    state: u8,
) -> Result<Instruction> {
    let (user_pda, _bump) = SolcryptClient::get_user_pda(signer);

    let instruction_data = AddThreadData {
        discriminator: InstructionType::AddThread,
        thread_id,
        state,
    };
    let data =
        AddThreadData::serialize(&instruction_data).context("Failed to serialize AddThreadData")?;

    let accounts = vec![
        AccountMeta::new(*signer, true),
        AccountMeta::new(user_pda, false),
        AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
    ];

    Ok(Instruction {
        program_id: solcrypt_program::ID.into(),
        accounts,
        data,
    })
}

/// Build a SendDmMessage instruction
/// This is more complex as it involves Light Protocol ZK compression
pub async fn build_send_dm_message_instruction(
    client: &mut SolcryptClient,
    recipient: &Pubkey,
    thread_id: [u8; 32],
    iv: [u8; 12],
    ciphertext: Vec<u8>,
) -> Result<Instruction> {
    let signer = client.payer.pubkey();

    // Get user PDAs
    let (sender_user_pda, _) = SolcryptClient::get_user_pda(&signer);
    let (recipient_user_pda, _) = SolcryptClient::get_user_pda(recipient);

    // Get tree info from client
    let address_tree_info: TreeInfo = client.rpc.get_address_tree_v1();
    let state_tree_info = client
        .rpc
        .get_random_state_tree_info()
        .map_err(|e| anyhow::anyhow!("Failed to get state tree info: {:?}", e))?;

    let address_tree_pubkey = address_tree_info.tree;
    let merkle_tree_pubkey = state_tree_info.tree;

    // Check if this is the first message in the thread
    // (thread doesn't exist in sender's account yet)
    let sender_account = client.get_user_account(&signer).await?;
    let is_first_message = match sender_account {
        Some(account) => !account.threads.iter().any(|t| t.thread_id == thread_id),
        None => {
            anyhow::bail!("Sender user account not initialized");
        }
    };

    // Use nonce=0 for first message, random nonce for subsequent messages
    let nonce = if is_first_message {
        [0u8; 32]
    } else {
        random_nonce()
    };

    // Derive the message address
    let (msg_address, _) = derive_address(
        &[b"msg", &thread_id, &nonce],
        &address_tree_pubkey,
        &solcrypt_program::ID.into(),
    );

    // Setup packed accounts for Light Protocol
    let system_account_meta_config = SystemAccountMetaConfig::new(solcrypt_program::ID.into());
    let mut packed_accounts = PackedAccounts::default();
    packed_accounts.add_pre_accounts_signer(signer);
    packed_accounts
        .add_system_accounts(system_account_meta_config)
        .map_err(|e| anyhow::anyhow!("Failed to add system accounts: {:?}", e))?;

    // Get validity proof for the new address
    let rpc_result = client
        .rpc
        .get_validity_proof(
            vec![],
            vec![AddressWithTree {
                address: msg_address,
                tree: address_tree_pubkey,
            }],
            None,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get validity proof: {:?}", e))?;

    let output_merkle_tree_index = packed_accounts.insert_or_get(merkle_tree_pubkey);
    let packed_address_tree_info = rpc_result
        .value
        .pack_tree_infos(&mut packed_accounts)
        .address_trees[0];
    let (light_accounts, _, _) = packed_accounts.to_account_metas();

    // Build instruction data
    let instruction_data = SendDmMessageData {
        discriminator: InstructionType::SendDmMessage,
        proof: rpc_result.value.proof.into(),
        address_tree_info: packed_address_tree_info.into(),
        output_state_tree_index: output_merkle_tree_index,
        thread_id,
        recipient: recipient.to_bytes(),
        iv,
        ciphertext,
        nonce,
    };
    let data = SendDmMessageData::serialize(&instruction_data)
        .context("Failed to serialize SendDmMessageData")?;

    // Build account list:
    // [0] = signer (from light_accounts[0])
    // [1] = sender_user_pda
    // [2] = recipient_user_pda
    // [3] = system_program
    // [4..] = Light Protocol accounts (light_accounts[1..])
    let mut accounts = vec![
        light_accounts[0].clone(), // signer
        AccountMeta::new(sender_user_pda, false),
        AccountMeta::new(recipient_user_pda, false),
        AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
    ];
    accounts.extend(light_accounts[1..].iter().cloned());

    Ok(Instruction {
        program_id: solcrypt_program::ID.into(),
        accounts,
        data,
    })
}

/// Create and sign a transaction for initializing a user account
pub async fn create_init_user_transaction(
    client: &mut SolcryptClient,
    x25519_pubkey: [u8; 32],
) -> Result<Transaction> {
    let instruction = build_init_user_instruction(&client.payer.pubkey(), x25519_pubkey)?;
    let blockhash = client.get_recent_blockhash().await?;

    let transaction = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&client.payer.pubkey()),
        &[&client.payer],
        blockhash,
    );

    Ok(transaction)
}

/// Create and sign a transaction for sending a DM message
pub async fn create_send_dm_message_transaction(
    client: &mut SolcryptClient,
    recipient: &Pubkey,
    thread_id: [u8; 32],
    iv: [u8; 12],
    ciphertext: Vec<u8>,
) -> Result<Transaction> {
    let instruction =
        build_send_dm_message_instruction(client, recipient, thread_id, iv, ciphertext).await?;

    // Add compute budget instruction for complex ZK operations
    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_000_000);

    let blockhash = client.get_recent_blockhash().await?;

    let transaction = Transaction::new_signed_with_payer(
        &[compute_budget_ix, instruction],
        Some(&client.payer.pubkey()),
        &[&client.payer],
        blockhash,
    );

    Ok(transaction)
}

/// Create and sign a transaction for accepting a thread
pub async fn create_accept_thread_transaction(
    client: &mut SolcryptClient,
    thread_id: [u8; 32],
) -> Result<Transaction> {
    let instruction = build_accept_thread_instruction(&client.payer.pubkey(), thread_id)?;
    let blockhash = client.get_recent_blockhash().await?;

    let transaction = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&client.payer.pubkey()),
        &[&client.payer],
        blockhash,
    );

    Ok(transaction)
}

// ============================================================================
// Group Chat Transaction Builders
// ============================================================================

/// Build a CreateGroup instruction
pub async fn build_create_group_instruction(
    client: &mut SolcryptClient,
    group_id: [u8; 32],
    encrypted_aes_key: [u8; 48],
) -> Result<Instruction> {
    let signer = client.payer.pubkey();
    let (user_pda, _) = SolcryptClient::get_user_pda(&signer);
    let (group_pda, _) = SolcryptClient::get_group_pda(&group_id);

    // Get tree info
    let address_tree_info: TreeInfo = client.rpc.get_address_tree_v1();
    let state_tree_info = client
        .rpc
        .get_random_state_tree_info()
        .map_err(|e| anyhow::anyhow!("Failed to get state tree info: {:?}", e))?;

    let address_tree_pubkey = address_tree_info.tree;
    let merkle_tree_pubkey = state_tree_info.tree;

    // Derive the owner's GroupKeyV1 address (key_version = 1 for new group)
    let key_version_bytes = 1u32.to_le_bytes();
    let (owner_key_address, _) = derive_address(
        &[
            GROUP_KEY_SEED,
            &group_id,
            signer.as_ref(),
            &key_version_bytes,
        ],
        &address_tree_pubkey,
        &solcrypt_program::ID.into(),
    );

    // Setup packed accounts
    let system_account_meta_config = SystemAccountMetaConfig::new(solcrypt_program::ID.into());
    let mut packed_accounts = PackedAccounts::default();
    packed_accounts.add_pre_accounts_signer(signer);
    packed_accounts
        .add_system_accounts(system_account_meta_config)
        .map_err(|e| anyhow::anyhow!("Failed to add system accounts: {:?}", e))?;

    // Get validity proof for the new address
    let rpc_result = client
        .rpc
        .get_validity_proof(
            vec![],
            vec![AddressWithTree {
                address: owner_key_address,
                tree: address_tree_pubkey,
            }],
            None,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get validity proof: {:?}", e))?;

    let output_merkle_tree_index = packed_accounts.insert_or_get(merkle_tree_pubkey);
    let packed_address_tree_info = rpc_result
        .value
        .pack_tree_infos(&mut packed_accounts)
        .address_trees[0];
    let (light_accounts, _, _) = packed_accounts.to_account_metas();

    // Build instruction data
    let instruction_data = CreateGroupData {
        discriminator: InstructionType::CreateGroup,
        proof: rpc_result.value.proof.into(),
        address_tree_info: packed_address_tree_info.into(),
        output_state_tree_index: output_merkle_tree_index,
        group_id,
        encrypted_aes_key,
    };
    let data = CreateGroupData::serialize(&instruction_data)
        .context("Failed to serialize CreateGroupData")?;

    // Build account list
    let mut accounts = vec![
        light_accounts[0].clone(), // signer
        AccountMeta::new(user_pda, false),
        AccountMeta::new(group_pda, false),
        AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
    ];
    accounts.extend(light_accounts[1..].iter().cloned());

    Ok(Instruction {
        program_id: solcrypt_program::ID.into(),
        accounts,
        data,
    })
}

/// Create and sign a transaction for creating a group
pub async fn create_create_group_transaction(
    client: &mut SolcryptClient,
    group_id: [u8; 32],
    encrypted_aes_key: [u8; 48],
) -> Result<Transaction> {
    let instruction = build_create_group_instruction(client, group_id, encrypted_aes_key).await?;
    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_000_000);
    let blockhash = client.get_recent_blockhash().await?;

    let transaction = Transaction::new_signed_with_payer(
        &[compute_budget_ix, instruction],
        Some(&client.payer.pubkey()),
        &[&client.payer],
        blockhash,
    );

    Ok(transaction)
}

/// Build an AcceptGroupInvite instruction
pub fn build_accept_group_invite_instruction(
    signer: &Pubkey,
    group_id: [u8; 32],
) -> Result<Instruction> {
    let (user_pda, _) = SolcryptClient::get_user_pda(signer);

    let instruction_data = AcceptGroupInviteData {
        discriminator: InstructionType::AcceptGroupInvite,
        group_id,
    };
    let data = AcceptGroupInviteData::serialize(&instruction_data)
        .context("Failed to serialize AcceptGroupInviteData")?;

    let accounts = vec![
        AccountMeta::new(*signer, true),
        AccountMeta::new(user_pda, false),
    ];

    Ok(Instruction {
        program_id: solcrypt_program::ID.into(),
        accounts,
        data,
    })
}

/// Create and sign a transaction for accepting a group invite
pub async fn create_accept_group_invite_transaction(
    client: &mut SolcryptClient,
    group_id: [u8; 32],
) -> Result<Transaction> {
    let instruction = build_accept_group_invite_instruction(&client.payer.pubkey(), group_id)?;
    let blockhash = client.get_recent_blockhash().await?;

    let transaction = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&client.payer.pubkey()),
        &[&client.payer],
        blockhash,
    );

    Ok(transaction)
}

/// Build an InviteToGroup instruction
/// Invites a new member to the group by creating their GroupKeyV1 with the encrypted AES key
pub async fn build_invite_to_group_instruction(
    client: &mut SolcryptClient,
    group_id: [u8; 32],
    invitee: &Pubkey,
    invitee_encrypted_aes_key: [u8; 48],
) -> Result<Instruction> {
    let signer = client.payer.pubkey();
    let (group_pda, _) = SolcryptClient::get_group_pda(&group_id);
    let (invitee_user_pda, _) = SolcryptClient::get_user_pda(invitee);

    // Get tree info
    let address_tree_info: TreeInfo = client.rpc.get_address_tree_v1();
    let state_tree_info = client
        .rpc
        .get_random_state_tree_info()
        .map_err(|e| anyhow::anyhow!("Failed to get state tree info: {:?}", e))?;

    let address_tree_pubkey = address_tree_info.tree;
    let merkle_tree_pubkey = state_tree_info.tree;

    // Get the group account to find the current key version
    let group_account = client
        .get_group_account(&group_id)
        .await?
        .context("Group not found")?;

    // Get inviter's GroupKeyV1 with hash for ZK proof
    let (inviter_key, inviter_key_address, inviter_key_hash) = client
        .get_my_group_key_with_hash(&group_id)
        .await?
        .context("You are not a member of this group")?;

    // Derive the invitee's GroupKeyV1 address
    let key_version_bytes = group_account.current_key_version.to_le_bytes();
    let (invitee_key_address, _) = derive_address(
        &[
            GROUP_KEY_SEED,
            &group_id,
            invitee.as_ref(),
            &key_version_bytes,
        ],
        &address_tree_pubkey,
        &solcrypt_program::ID.into(),
    );

    // Setup packed accounts
    let system_account_meta_config = SystemAccountMetaConfig::new(solcrypt_program::ID.into());
    let mut packed_accounts = PackedAccounts::default();
    packed_accounts.add_pre_accounts_signer(signer);
    packed_accounts
        .add_system_accounts(system_account_meta_config)
        .map_err(|e| anyhow::anyhow!("Failed to add system accounts: {:?}", e))?;

    // Get validity proof for:
    // 1. Existing inviter's GroupKeyV1 (hash) - proves membership and role
    // 2. New invitee's GroupKeyV1 address - proves uniqueness
    let rpc_result = client
        .rpc
        .get_validity_proof(
            vec![inviter_key_hash], // Existing account hash
            vec![AddressWithTree {
                address: invitee_key_address,
                tree: address_tree_pubkey,
            }],
            None,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get validity proof: {:?}", e))?;

    let output_merkle_tree_index = packed_accounts.insert_or_get(merkle_tree_pubkey);

    let packed_tree_infos = rpc_result.value.pack_tree_infos(&mut packed_accounts);

    // Get the packed account info for inviter's GroupKeyV1
    let state_trees = packed_tree_infos
        .state_trees
        .as_ref()
        .context("No state trees in proof result")?;
    let inviter_key_tree_info = state_trees
        .packed_tree_infos
        .first()
        .context("State trees list is empty")?
        .clone();

    let invitee_address_tree_info = packed_tree_infos.address_trees[0];

    let (light_accounts, _, _) = packed_accounts.to_account_metas();

    // Build the inviter key account meta
    use solcrypt_program::CompressedAccountMetaCodama;

    let inviter_account_meta = CompressedAccountMetaCodama {
        tree_info: inviter_key_tree_info.into(),
        address: inviter_key_address,
        output_state_tree_index: output_merkle_tree_index,
    };

    // Build instruction data
    let instruction_data = InviteToGroupData {
        discriminator: InstructionType::InviteToGroup,
        proof: rpc_result.value.proof.into(),
        inviter_account_meta,
        inviter_key_version: inviter_key.key_version,
        inviter_role: inviter_key.role,
        inviter_encrypted_aes_key: inviter_key.encrypted_aes_key,
        invitee_address_tree_info: invitee_address_tree_info.into(),
        output_state_tree_index: output_merkle_tree_index,
        group_id,
        invitee: invitee.to_bytes().into(),
        encrypted_aes_key: invitee_encrypted_aes_key,
    };
    let data = InviteToGroupData::serialize(&instruction_data)
        .context("Failed to serialize InviteToGroupData")?;

    // Build account list
    let mut accounts = vec![
        light_accounts[0].clone(), // signer
        AccountMeta::new_readonly(group_pda, false),
        AccountMeta::new(invitee_user_pda, false),
        AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
    ];
    accounts.extend(light_accounts[1..].iter().cloned());

    Ok(Instruction {
        program_id: solcrypt_program::ID.into(),
        accounts,
        data,
    })
}

/// Create and sign a transaction for inviting a member to a group
pub async fn create_invite_to_group_transaction(
    client: &mut SolcryptClient,
    group_id: [u8; 32],
    invitee: &Pubkey,
    invitee_encrypted_aes_key: [u8; 48],
) -> Result<Transaction> {
    let instruction =
        build_invite_to_group_instruction(client, group_id, invitee, invitee_encrypted_aes_key)
            .await?;

    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_000_000);
    let blockhash = client.get_recent_blockhash().await?;

    let transaction = Transaction::new_signed_with_payer(
        &[compute_budget_ix, instruction],
        Some(&client.payer.pubkey()),
        &[&client.payer],
        blockhash,
    );

    Ok(transaction)
}

/// Build a SendGroupMessage instruction with membership verification.
/// The sender's GroupKeyV1 is included in the ZK proof to verify they are a group member.
pub async fn build_send_group_message_instruction(
    client: &mut SolcryptClient,
    group_id: [u8; 32],
    sender_key_version: u32,
    sender_role: u8,
    sender_encrypted_aes_key: [u8; 48],
    iv: [u8; 12],
    ciphertext: Vec<u8>,
) -> Result<Instruction> {
    let signer = client.payer.pubkey();
    let (group_pda, _) = SolcryptClient::get_group_pda(&group_id);

    // Get tree info
    let address_tree_info: TreeInfo = client.rpc.get_address_tree_v1();
    let state_tree_info = client
        .rpc
        .get_random_state_tree_info()
        .map_err(|e| anyhow::anyhow!("Failed to get state tree info: {:?}", e))?;

    let address_tree_pubkey = address_tree_info.tree;
    let merkle_tree_pubkey = state_tree_info.tree;

    // Generate random nonce for message
    let nonce = random_nonce();

    // Derive the message address
    let (msg_address, _) = derive_address(
        &[b"group-msg", &group_id, &nonce],
        &address_tree_pubkey,
        &solcrypt_program::ID.into(),
    );

    // Get the sender's GroupKeyV1 hash for membership verification
    let (group_key, key_address, key_hash) = client
        .get_my_group_key_with_hash(&group_id)
        .await?
        .context("You are not a member of this group")?;

    // Setup packed accounts
    let system_account_meta_config = SystemAccountMetaConfig::new(solcrypt_program::ID.into());
    let mut packed_accounts = PackedAccounts::default();
    packed_accounts.add_pre_accounts_signer(signer);
    packed_accounts
        .add_system_accounts(system_account_meta_config)
        .map_err(|e| anyhow::anyhow!("Failed to add system accounts: {:?}", e))?;

    // Get validity proof for:
    // 1. Existing sender's GroupKeyV1 (hash) - proves membership
    // 2. New message address - proves uniqueness
    let rpc_result = client
        .rpc
        .get_validity_proof(
            vec![key_hash], // Existing account hash for membership verification
            vec![AddressWithTree {
                address: msg_address,
                tree: address_tree_pubkey,
            }],
            None,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get validity proof: {:?}", e))?;

    let output_merkle_tree_index = packed_accounts.insert_or_get(merkle_tree_pubkey);

    let packed_tree_infos = rpc_result.value.pack_tree_infos(&mut packed_accounts);

    // Get the packed account info for sender's GroupKeyV1
    let state_trees = packed_tree_infos
        .state_trees
        .as_ref()
        .context("No state trees in proof result")?;
    let sender_key_tree_info = state_trees
        .packed_tree_infos
        .first()
        .context("State trees list is empty")?
        .clone();

    let message_address_tree_info = packed_tree_infos.address_trees[0];

    let (light_accounts, _, _) = packed_accounts.to_account_metas();

    // Build the sender key account meta with proper tree info
    use solcrypt_program::CompressedAccountMetaCodama;

    let sender_key_account_meta = CompressedAccountMetaCodama {
        tree_info: sender_key_tree_info.into(),
        address: key_address,
        output_state_tree_index: output_merkle_tree_index,
    };

    // Build instruction data with real membership proof
    let instruction_data = SendGroupMessageData {
        discriminator: InstructionType::SendGroupMessage,
        proof: rpc_result.value.proof.into(),
        sender_key_account_meta,
        sender_key_version: group_key.key_version,
        sender_role: group_key.role,
        sender_encrypted_aes_key: group_key.encrypted_aes_key,
        message_address_tree_info: message_address_tree_info.into(),
        output_state_tree_index: output_merkle_tree_index,
        group_id,
        iv,
        ciphertext,
        nonce,
    };
    let data = SendGroupMessageData::serialize(&instruction_data)
        .context("Failed to serialize SendGroupMessageData")?;

    // Build account list
    let mut accounts = vec![
        light_accounts[0].clone(), // signer
        AccountMeta::new_readonly(group_pda, false),
        AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
    ];
    accounts.extend(light_accounts[1..].iter().cloned());

    Ok(Instruction {
        program_id: solcrypt_program::ID.into(),
        accounts,
        data,
    })
}

/// Create and sign a transaction for sending a group message
pub async fn create_send_group_message_transaction(
    client: &mut SolcryptClient,
    group_id: [u8; 32],
    sender_key_version: u32,
    sender_role: u8,
    sender_encrypted_aes_key: [u8; 48],
    iv: [u8; 12],
    ciphertext: Vec<u8>,
) -> Result<Transaction> {
    let instruction = build_send_group_message_instruction(
        client,
        group_id,
        sender_key_version,
        sender_role,
        sender_encrypted_aes_key,
        iv,
        ciphertext,
    )
    .await?;

    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_000_000);
    let blockhash = client.get_recent_blockhash().await?;

    let transaction = Transaction::new_signed_with_payer(
        &[compute_budget_ix, instruction],
        Some(&client.payer.pubkey()),
        &[&client.payer],
        blockhash,
    );

    Ok(transaction)
}

// ============================================================================
// GROUP MANAGEMENT INSTRUCTIONS
// ============================================================================

/// Build a RemoveFromGroup instruction - admin removes a member
pub async fn build_remove_from_group_instruction(
    client: &mut SolcryptClient,
    group_id: [u8; 32],
    target: &Pubkey,
) -> Result<Instruction> {
    use solcrypt_program::{CompressedAccountMetaCodama, RemoveFromGroupData};

    let signer = client.payer.pubkey();
    let (user_pda, _) = SolcryptClient::get_user_pda(&signer);
    let (group_pda, _) = SolcryptClient::get_group_pda(&group_id);
    let (target_user_pda, _) = SolcryptClient::get_user_pda(target);

    // Get tree info
    let state_tree_info = client
        .rpc
        .get_random_state_tree_info()
        .map_err(|e| anyhow::anyhow!("Failed to get state tree info: {:?}", e))?;
    let merkle_tree_pubkey = state_tree_info.tree;

    // Get signer's GroupKeyV1 with hash for ZK proof (proves role)
    let (signer_key, signer_key_address, signer_key_hash) = client
        .get_my_group_key_with_hash(&group_id)
        .await?
        .context("You are not a member of this group")?;

    // Get target's GroupKeyV1 with hash for closing
    let (target_key, target_key_address, target_key_hash) = client
        .get_member_group_key_with_hash(&group_id, target)
        .await?
        .context("Target is not a member of this group")?;

    // Setup packed accounts
    let system_account_meta_config = SystemAccountMetaConfig::new(solcrypt_program::ID.into());
    let mut packed_accounts = PackedAccounts::default();
    packed_accounts.add_pre_accounts_signer(signer);
    packed_accounts
        .add_system_accounts(system_account_meta_config)
        .map_err(|e| anyhow::anyhow!("Failed to add system accounts: {:?}", e))?;

    // Get validity proof for both accounts
    let rpc_result = client
        .rpc
        .get_validity_proof(vec![signer_key_hash, target_key_hash], vec![], None)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get validity proof: {:?}", e))?;

    let output_merkle_tree_index = packed_accounts.insert_or_get(merkle_tree_pubkey);
    let packed_tree_infos = rpc_result.value.pack_tree_infos(&mut packed_accounts);

    let state_trees = packed_tree_infos
        .state_trees
        .as_ref()
        .context("No state trees in proof result")?;

    let signer_key_tree_info = state_trees
        .packed_tree_infos
        .get(0)
        .context("Signer tree info missing")?
        .clone();

    let target_key_tree_info = state_trees
        .packed_tree_infos
        .get(1)
        .context("Target tree info missing")?
        .clone();

    let (light_accounts, _, _) = packed_accounts.to_account_metas();

    let signer_account_meta = CompressedAccountMetaCodama {
        tree_info: signer_key_tree_info.into(),
        address: signer_key_address,
        output_state_tree_index: output_merkle_tree_index,
    };

    let target_account_meta = CompressedAccountMetaCodama {
        tree_info: target_key_tree_info.into(),
        address: target_key_address,
        output_state_tree_index: output_merkle_tree_index,
    };

    let instruction_data = RemoveFromGroupData {
        discriminator: InstructionType::RemoveFromGroup,
        proof: rpc_result.value.proof.into(),
        signer_account_meta,
        signer_key_version: signer_key.key_version,
        signer_role: signer_key.role,
        signer_encrypted_aes_key: signer_key.encrypted_aes_key,
        target_account_meta,
        target_key_version: target_key.key_version,
        target_role: target_key.role,
        target_encrypted_aes_key: target_key.encrypted_aes_key,
        group_id,
        target: target.to_bytes().into(),
    };
    let data = RemoveFromGroupData::serialize(&instruction_data)
        .context("Failed to serialize RemoveFromGroupData")?;

    // Account order must match processor:
    // 0: signer
    // 1: group_account_info
    // 2: target_user_account
    // 3+: light system accounts
    let mut accounts = vec![
        light_accounts[0].clone(), // signer
        AccountMeta::new_readonly(group_pda, false),
        AccountMeta::new(target_user_pda, false),
    ];
    accounts.extend(light_accounts[1..].iter().cloned());

    Ok(Instruction {
        program_id: solcrypt_program::ID.into(),
        accounts,
        data,
    })
}

/// Create and sign a transaction for removing a member from a group
pub async fn create_remove_from_group_transaction(
    client: &mut SolcryptClient,
    group_id: [u8; 32],
    target: &Pubkey,
) -> Result<Transaction> {
    let instruction = build_remove_from_group_instruction(client, group_id, target).await?;

    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let blockhash = client.get_recent_blockhash().await?;

    let transaction = Transaction::new_signed_with_payer(
        &[compute_budget_ix, instruction],
        Some(&client.payer.pubkey()),
        &[&client.payer],
        blockhash,
    );

    Ok(transaction)
}

/// Build a LeaveGroup instruction - member voluntarily leaves
pub async fn build_leave_group_instruction(
    client: &mut SolcryptClient,
    group_id: [u8; 32],
) -> Result<Instruction> {
    use solcrypt_program::{CompressedAccountMetaCodama, LeaveGroupData};

    let signer = client.payer.pubkey();
    let (user_pda, _) = SolcryptClient::get_user_pda(&signer);
    let (group_pda, _) = SolcryptClient::get_group_pda(&group_id);

    // Get tree info
    let state_tree_info = client
        .rpc
        .get_random_state_tree_info()
        .map_err(|e| anyhow::anyhow!("Failed to get state tree info: {:?}", e))?;
    let merkle_tree_pubkey = state_tree_info.tree;

    // Get signer's GroupKeyV1 with hash for closing
    let (signer_key, signer_key_address, signer_key_hash) = client
        .get_my_group_key_with_hash(&group_id)
        .await?
        .context("You are not a member of this group")?;

    // Setup packed accounts
    let system_account_meta_config = SystemAccountMetaConfig::new(solcrypt_program::ID.into());
    let mut packed_accounts = PackedAccounts::default();
    packed_accounts.add_pre_accounts_signer(signer);
    packed_accounts
        .add_system_accounts(system_account_meta_config)
        .map_err(|e| anyhow::anyhow!("Failed to add system accounts: {:?}", e))?;

    // Get validity proof for closing the account
    let rpc_result = client
        .rpc
        .get_validity_proof(vec![signer_key_hash], vec![], None)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get validity proof: {:?}", e))?;

    let output_merkle_tree_index = packed_accounts.insert_or_get(merkle_tree_pubkey);
    let packed_tree_infos = rpc_result.value.pack_tree_infos(&mut packed_accounts);

    let state_trees = packed_tree_infos
        .state_trees
        .as_ref()
        .context("No state trees in proof result")?;

    let signer_key_tree_info = state_trees
        .packed_tree_infos
        .first()
        .context("State trees list is empty")?
        .clone();

    let (light_accounts, _, _) = packed_accounts.to_account_metas();

    let account_meta = CompressedAccountMetaCodama {
        tree_info: signer_key_tree_info.into(),
        address: signer_key_address,
        output_state_tree_index: output_merkle_tree_index,
    };

    let instruction_data = LeaveGroupData {
        discriminator: InstructionType::LeaveGroup,
        proof: rpc_result.value.proof.into(),
        account_meta,
        key_version: signer_key.key_version,
        role: signer_key.role,
        encrypted_aes_key: signer_key.encrypted_aes_key,
        group_id,
    };
    let data = LeaveGroupData::serialize(&instruction_data)
        .context("Failed to serialize LeaveGroupData")?;

    let mut accounts = vec![
        light_accounts[0].clone(), // signer
        AccountMeta::new(user_pda, false),
        AccountMeta::new_readonly(group_pda, false),
    ];
    accounts.extend(light_accounts[1..].iter().cloned());

    Ok(Instruction {
        program_id: solcrypt_program::ID.into(),
        accounts,
        data,
    })
}

/// Create and sign a transaction for leaving a group
pub async fn create_leave_group_transaction(
    client: &mut SolcryptClient,
    group_id: [u8; 32],
) -> Result<Transaction> {
    let instruction = build_leave_group_instruction(client, group_id).await?;

    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_000_000);
    let blockhash = client.get_recent_blockhash().await?;

    let transaction = Transaction::new_signed_with_payer(
        &[compute_budget_ix, instruction],
        Some(&client.payer.pubkey()),
        &[&client.payer],
        blockhash,
    );

    Ok(transaction)
}

/// Build a SetMemberRole instruction - owner promotes/demotes admins
pub async fn build_set_member_role_instruction(
    client: &mut SolcryptClient,
    group_id: [u8; 32],
    target: &Pubkey,
    new_role: u8,
) -> Result<Instruction> {
    use solcrypt_program::{CompressedAccountMetaCodama, SetMemberRoleData};

    let signer = client.payer.pubkey();
    let (group_pda, _) = SolcryptClient::get_group_pda(&group_id);

    // Get tree info
    let state_tree_info = client
        .rpc
        .get_random_state_tree_info()
        .map_err(|e| anyhow::anyhow!("Failed to get state tree info: {:?}", e))?;
    let merkle_tree_pubkey = state_tree_info.tree;

    // Get target's GroupKeyV1 with hash for updating
    let (target_key, target_key_address, target_key_hash) = client
        .get_member_group_key_with_hash(&group_id, target)
        .await?
        .context("Target is not a member of this group")?;

    // Setup packed accounts
    let system_account_meta_config = SystemAccountMetaConfig::new(solcrypt_program::ID.into());
    let mut packed_accounts = PackedAccounts::default();
    packed_accounts.add_pre_accounts_signer(signer);
    packed_accounts
        .add_system_accounts(system_account_meta_config)
        .map_err(|e| anyhow::anyhow!("Failed to add system accounts: {:?}", e))?;

    // Get validity proof for updating the account
    let rpc_result = client
        .rpc
        .get_validity_proof(vec![target_key_hash], vec![], None)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get validity proof: {:?}", e))?;

    let output_merkle_tree_index = packed_accounts.insert_or_get(merkle_tree_pubkey);
    let packed_tree_infos = rpc_result.value.pack_tree_infos(&mut packed_accounts);

    let state_trees = packed_tree_infos
        .state_trees
        .as_ref()
        .context("No state trees in proof result")?;

    let target_key_tree_info = state_trees
        .packed_tree_infos
        .first()
        .context("State trees list is empty")?
        .clone();

    let (light_accounts, _, _) = packed_accounts.to_account_metas();

    let account_meta = CompressedAccountMetaCodama {
        tree_info: target_key_tree_info.into(),
        address: target_key_address,
        output_state_tree_index: output_merkle_tree_index,
    };

    let instruction_data = SetMemberRoleData {
        discriminator: InstructionType::SetMemberRole,
        proof: rpc_result.value.proof.into(),
        account_meta,
        current_key_version: target_key.key_version,
        current_role: target_key.role,
        encrypted_aes_key: target_key.encrypted_aes_key,
        group_id,
        target: target.to_bytes().into(),
        new_role,
    };
    let data = SetMemberRoleData::serialize(&instruction_data)
        .context("Failed to serialize SetMemberRoleData")?;

    let mut accounts = vec![
        light_accounts[0].clone(), // signer
        AccountMeta::new_readonly(group_pda, false),
    ];
    accounts.extend(light_accounts[1..].iter().cloned());

    Ok(Instruction {
        program_id: solcrypt_program::ID.into(),
        accounts,
        data,
    })
}

/// Create and sign a transaction for setting a member's role
pub async fn create_set_member_role_transaction(
    client: &mut SolcryptClient,
    group_id: [u8; 32],
    target: &Pubkey,
    new_role: u8,
) -> Result<Transaction> {
    let instruction = build_set_member_role_instruction(client, group_id, target, new_role).await?;

    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_000_000);
    let blockhash = client.get_recent_blockhash().await?;

    let transaction = Transaction::new_signed_with_payer(
        &[compute_budget_ix, instruction],
        Some(&client.payer.pubkey()),
        &[&client.payer],
        blockhash,
    );

    Ok(transaction)
}

/// Build a RotateGroupKey instruction - owner rotates the encryption key
/// This creates new GroupKeyV1 accounts for all accepted members with the new key version
pub async fn build_rotate_group_key_instruction(
    client: &mut SolcryptClient,
    group_id: [u8; 32],
    new_encrypted_keys: Vec<(Pubkey, u8, [u8; 48])>, // (member, role, encrypted_aes_key)
) -> Result<Instruction> {
    use solcrypt_program::{PackedAddressTreeInfoCodama, RotateGroupKeyData, RotationKeyEntry};

    let signer = client.payer.pubkey();
    let (group_pda, _) = SolcryptClient::get_group_pda(&group_id);

    // Get current group account to determine new key version
    let group_account = client
        .get_group_account(&group_id)
        .await?
        .context("Group not found")?;
    let new_key_version = group_account.current_key_version + 1;

    // Get tree info
    let address_tree_info: TreeInfo = client.rpc.get_address_tree_v1();
    let state_tree_info = client
        .rpc
        .get_random_state_tree_info()
        .map_err(|e| anyhow::anyhow!("Failed to get state tree info: {:?}", e))?;

    let address_tree_pubkey = address_tree_info.tree;
    let merkle_tree_pubkey = state_tree_info.tree;

    // Derive addresses for all new GroupKeyV1 accounts
    let key_version_bytes = new_key_version.to_le_bytes();
    let mut new_addresses: Vec<AddressWithTree> = Vec::new();

    for (member, _, _) in &new_encrypted_keys {
        let (key_address, _) = derive_address(
            &[
                GROUP_KEY_SEED,
                &group_id,
                member.as_ref(),
                &key_version_bytes,
            ],
            &address_tree_pubkey,
            &solcrypt_program::ID.into(),
        );
        new_addresses.push(AddressWithTree {
            address: key_address,
            tree: address_tree_pubkey,
        });
    }

    // Setup packed accounts
    let system_account_meta_config = SystemAccountMetaConfig::new(solcrypt_program::ID.into());
    let mut packed_accounts = PackedAccounts::default();
    packed_accounts.add_pre_accounts_signer(signer);
    packed_accounts
        .add_system_accounts(system_account_meta_config)
        .map_err(|e| anyhow::anyhow!("Failed to add system accounts: {:?}", e))?;

    // Get validity proof for all new addresses
    let rpc_result = client
        .rpc
        .get_validity_proof(vec![], new_addresses, None)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get validity proof: {:?}", e))?;

    let output_merkle_tree_index = packed_accounts.insert_or_get(merkle_tree_pubkey);
    let packed_tree_infos = rpc_result.value.pack_tree_infos(&mut packed_accounts);

    let (light_accounts, _, _) = packed_accounts.to_account_metas();

    // Build rotation key entries and address tree infos
    let new_keys: Vec<RotationKeyEntry> = new_encrypted_keys
        .iter()
        .map(|(member, role, encrypted_aes_key)| RotationKeyEntry {
            member: member.to_bytes().into(),
            role: *role,
            encrypted_aes_key: *encrypted_aes_key,
        })
        .collect();

    let address_tree_infos: Vec<PackedAddressTreeInfoCodama> = packed_tree_infos
        .address_trees
        .iter()
        .map(|&info| info.into())
        .collect();

    let instruction_data = RotateGroupKeyData {
        discriminator: InstructionType::RotateGroupKey,
        proof: rpc_result.value.proof.into(),
        output_state_tree_index: output_merkle_tree_index,
        group_id,
        new_keys,
        address_tree_infos,
    };
    let data = RotateGroupKeyData::serialize(&instruction_data)
        .context("Failed to serialize RotateGroupKeyData")?;

    let mut accounts = vec![
        light_accounts[0].clone(), // signer
        AccountMeta::new(group_pda, false),
        AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
    ];
    accounts.extend(light_accounts[1..].iter().cloned());

    Ok(Instruction {
        program_id: solcrypt_program::ID.into(),
        accounts,
        data,
    })
}

/// Create and sign a transaction for rotating the group key
pub async fn create_rotate_group_key_transaction(
    client: &mut SolcryptClient,
    group_id: [u8; 32],
    new_encrypted_keys: Vec<(Pubkey, u8, [u8; 48])>,
) -> Result<Transaction> {
    let instruction =
        build_rotate_group_key_instruction(client, group_id, new_encrypted_keys).await?;

    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let blockhash = client.get_recent_blockhash().await?;

    let transaction = Transaction::new_signed_with_payer(
        &[compute_budget_ix, instruction],
        Some(&client.payer.pubkey()),
        &[&client.payer],
        blockhash,
    );

    Ok(transaction)
}
