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
    AcceptThreadData, AddThreadData, InitUserData, InstructionType, RemoveThreadData,
    SendDmMessageData,
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
